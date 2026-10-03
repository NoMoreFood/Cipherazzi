using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;
using Microsoft.Data.Sqlite;

namespace Cipherazzi.UiTests;

internal static class RefreshUi
{
    private static T Field<T>(object value, string name)
    {
        for (var type = value.GetType(); type is not null; type = type.BaseType)
            if (type.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic) is { } field)
                return (T)field.GetValue(value)!;
        throw new MissingFieldException(name);
    }

    private static async Task Until(Func<bool> condition)
    {
        var elapsed = Stopwatch.StartNew();
        while (!condition())
        {
            if (elapsed.Elapsed > TimeSpan.FromSeconds(45))
                throw new TimeoutException("The view did not finish refreshing.");
            await Task.Delay(20);
        }
    }

    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "refresh.db");
        using var writer = new SqliteConnection($"Data Source={path};Pooling=False");
        writer.Open();
        using (var original = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        {
            original.Open();
            original.BackupDatabase(writer);
        }
        using var command = writer.CreateCommand();
        command.CommandText = "SELECT count(*) FROM pragma_table_info('metadata') WHERE name='observation_revision'";
        if (Convert.ToInt64(command.ExecuteScalar()) == 0)
        {
            command.CommandText = "ALTER TABLE metadata ADD observation_revision INTEGER NOT NULL DEFAULT 0;" +
                "UPDATE metadata SET observation_revision=revision";
            command.ExecuteNonQuery();
        }
        var source = DatabaseSource.Sqlite(path);
        var settings = new ViewerSettings { Live = false, AnalyticsMinutes = 0, AnalyticsRefreshSeconds = 1 };
        using var window = new MainForm(source, null, settings)
        {
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000)
        };
        var checks = new List<string>();
        var exit = 0;
        void Check(bool condition, string message)
        {
            if (!condition)
                throw new InvalidOperationException(message);
            checks.Add(message);
        }
        window.Shown += async (_, _) =>
        {
            try
            {
                var grid = Field<DataGridView>(window, "grid");
                var live = Field<CheckBox>(window, "live");
                var tabs = Field<TabControl>(window, "tabs");
                var query = new Query("", "", false, PageCursor.Newest);
                await Until(() => grid.RowCount == 250 && !Field<bool>(window, "loading"));

                // Live health checks must preserve the loaded page, including after a durable heartbeat update.
                live.Checked = true;
                await Until(() => !Field<bool>(window, "loading"));
                var rows = Field<List<ConnectionRow>>(window, "rows");
                var stamp = Database.ReadStamp(source, default);
                command.CommandText = "UPDATE metadata SET revision=revision+1;" +
                    "UPDATE capture_sessions SET packets=packets+1,updated_us=@now," +
                    "change_revision=(SELECT revision FROM metadata)";
                command.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000);
                command.ExecuteNonQuery();
                command.Parameters.Clear();
                var refreshed = Field<DateTime>(window, "healthRefreshed");
                await Until(() => Field<DateTime>(window, "healthRefreshed") > refreshed);
                await Task.Delay(5500);
                Check(ReferenceEquals(rows, Field<List<ConnectionRow>>(window, "rows")) &&
                    Database.ReadStamp(source, default) == stamp,
                    "Repeated health checks and heartbeat-only revisions preserve the connection page");
                live.Checked = false;

                // Each inactive data set stays cached while readiness coverage can still change.
                tabs.SelectedIndex = 2;
                var analytics = Field<AnalyticsView>(window, "analytics");
                await Until(() => Field<AnalyticsSnapshot?>(analytics, "snapshot") is not null &&
                    !Field<bool>(analytics, "loading"));
                var snapshot = Field<AnalyticsSnapshot>(analytics, "snapshot");

                // Export destinations must preserve a journal even when it has a misleading extension.
                var protectedPath = Path.Combine(output, "journal.csv");
                File.Copy(path, protectedPath);
                var originalBytes = File.ReadAllBytes(protectedPath);
                var rejected = false;
                try { await AnalyticsView.ExportAsync(snapshot, protectedPath); }
                catch (ArgumentException) { rejected = true; }
                Check(rejected && File.ReadAllBytes(protectedPath).SequenceEqual(originalBytes),
                    "Analytics export preserves an existing capture journal");
                rejected = false;
                try { settings.Save(protectedPath); }
                catch (ArgumentException) { rejected = true; }
                Check(rejected && File.ReadAllBytes(protectedPath).SequenceEqual(originalBytes),
                    "Configuration export preserves an existing capture journal");
                foreach (var explicitOutput in new[] { false, true })
                {
                    var start = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "Cipherazzi.Viewer.exe"))
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden,
                        RedirectStandardError = true
                    };
                    start.ArgumentList.Add("--verify-ui");
                    start.ArgumentList.Add(protectedPath);
                    if (explicitOutput)
                        start.ArgumentList.Add(protectedPath);
                    using var process = Process.Start(start)!;
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                    var error = process.StandardError.ReadToEndAsync();
                    try { await process.WaitForExitAsync(timeout.Token); }
                    catch (OperationCanceledException)
                    {
                        process.Kill(entireProcessTree: true);
                        await process.WaitForExitAsync();
                        throw;
                    }
                    Check(process.ExitCode == 1 && (await error).Contains(explicitOutput ?
                        "separate from the capture journal" : "separate output image path", StringComparison.Ordinal) &&
                        File.ReadAllBytes(protectedPath).SequenceEqual(originalBytes),
                        explicitOutput ? "UI verification refuses to overwrite its journal with a screenshot" :
                            "UI verification requires a separate screenshot argument");
                }
                var exported = Path.Combine(output, "analytics.csv");
                await AnalyticsView.ExportAsync(snapshot with
                {
                    Breakdown = [new("=example,\"Δ\"", 1, 1.25, null)]
                }, exported);
                Check(File.ReadAllBytes(exported).Take(3).SequenceEqual(new byte[] { 0xef, 0xbb, 0xbf }) &&
                    File.ReadAllText(exported).Contains("\"'=example,\"\"Δ\"\"\"", StringComparison.Ordinal),
                    "Analytics export retains Unicode and spreadsheet-safe CSV escaping");
                await Task.Delay(1100);
                await analytics.RefreshAsync(source, query, false);
                Check(ReferenceEquals(snapshot, Field<AnalyticsSnapshot>(analytics, "snapshot")),
                    "Unchanged analytics skip aggregation");
                tabs.SelectedIndex = 3;
                var endpoints = Field<EndpointView>(window, "endpoints");
                await Until(() => !Field<bool>(endpoints, "loading"));
                var events = Field<List<EndpointRow>>(endpoints, "rows");
                await Task.Delay(2100);
                await endpoints.RefreshAsync(source, query, false);
                Check(ReferenceEquals(events, Field<List<EndpointRow>>(endpoints, "rows")),
                    "Unchanged endpoint pages skip decoding and grid replacement");
                tabs.SelectedIndex = 4;
                var readiness = Field<ReadinessView>(window, "readiness");
                await Until(() => readiness.Snapshot is not null && !Field<bool>(readiness, "loading"));
                var cohorts = readiness.Snapshot!.Rows;
                var packets = readiness.Snapshot.Coverage.Sum(row => row.Packets);
                command.CommandText = "UPDATE metadata SET revision=revision+1;" +
                    "UPDATE capture_sessions SET packets=packets+1 WHERE id=(SELECT id FROM capture_sessions LIMIT 1)";
                command.ExecuteNonQuery();
                await Task.Delay(1100);
                await readiness.RefreshAsync(source, query, false);
                Check(ReferenceEquals(cohorts, readiness.Snapshot!.Rows) &&
                    readiness.Snapshot.Coverage.Sum(row => row.Packets) == packets + 1,
                    "Readiness refreshes coverage without rebuilding unchanged cohorts");

                // Leaving an in-flight search cancels it without restarting the newly selected investigation.
                tabs.SelectedIndex = 0;
                await Until(() => !Field<bool>(window, "loading"));
                Field<TextBox>(window, "search").Text = "missing-refresh-regression.example";
                Field<System.Windows.Forms.Timer>(window, "debounce").Stop();
                Field<Button>(window, "refresh").PerformClick();
                var cancellation = Field<CancellationTokenSource>(window, "cancellation");
                tabs.SelectedIndex = 4;
                var generation = Field<int>(readiness, "generation");
                Check(cancellation.IsCancellationRequested, "Switching views cancels the connection search");
                await Until(() => Field<HashSet<Task>>(window, "operations").Count == 0);
                Check(Field<int>(readiness, "generation") == generation,
                    "The cancelled connection query does not restart readiness");

                // A rolling window expires observations even when the durable data revision stays unchanged.
                command.CommandText = "UPDATE connections SET sni='expiry.refresh.test',first_us=@first " +
                    "WHERE id=(SELECT min(id) FROM connections);" +
                    "UPDATE metadata SET revision=revision+1,observation_revision=revision+1";
                command.Parameters.AddWithValue("@first", DateTimeOffset.UtcNow.AddMinutes(-15).AddSeconds(5)
                    .ToUnixTimeMilliseconds() * 1000);
                command.ExecuteNonQuery();
                using var rolling = new AnalyticsView(new ViewerSettings
                { AnalyticsMinutes = 15, AnalyticsRefreshSeconds = 1 }, visual: false);
                var scoped = query with
                {
                    Conditions =
                    [new(ObservationField.ServerName, FilterComparison.Equals, "expiry.refresh.test")]
                };
                await rolling.RefreshAsync(source, scoped, true);
                Check(Field<AnalyticsSnapshot>(rolling, "snapshot").Total == 1,
                    "The rolling window initially includes the expiring observation");
                await Task.Delay(5100);
                await rolling.RefreshAsync(source, scoped, false);
                Check(Field<AnalyticsSnapshot>(rolling, "snapshot").Total == 0,
                    "Rolling-window expiration bypasses the unchanged-revision gate");

                // Replacing a journal can reuse its revision and row IDs without reusing its evidence.
                Field<TextBox>(window, "search").Clear();
                await Until(() => !Field<System.Windows.Forms.Timer>(window, "debounce").Enabled &&
                    Field<HashSet<Task>>(window, "operations").Count == 0);
                command.Parameters.Clear();
                command.CommandText = """
                    UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                    WITH RECURSIVE samples(n) AS (SELECT 0 UNION ALL SELECT n+1 FROM samples WHERE n<299)
                    INSERT INTO endpoint_events(id,run_id,timestamp_us,provider,kind,result,pid,peer,port,
                        protocol,cipher,certificate_id,detail_json,change_revision)
                    SELECT 'refresh-page-'||n,s.id,@now+n,'Refresh adapter','TLS','Completed',1234,'192.0.2.2',443,
                        'TLS 1.3','','','{}',(SELECT revision FROM metadata)
                    FROM (SELECT id FROM capture_sessions LIMIT 1) s CROSS JOIN samples;
                    """;
                command.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000);
                command.ExecuteNonQuery();
                tabs.SelectedIndex = 3;
                await Until(() => Field<List<EndpointRow>>(endpoints, "rows").Count == 250 &&
                    !Field<bool>(endpoints, "loading"));
                Field<Button>(endpoints, "next").PerformClick();
                Field<Button>(endpoints, "next").PerformClick();
                Check(Field<int>(endpoints, "page") == 1,
                    "Rapid pagination clicks cannot append a duplicate endpoint cursor");
                await Until(() => Field<int>(endpoints, "page") == 1 &&
                    !Field<bool>(endpoints, "loading") && Field<List<EndpointRow>>(endpoints, "rows").Count > 0);
                tabs.SelectedIndex = 0;
                await Until(() => grid.RowCount == 250 && !Field<bool>(window, "loading") &&
                    Field<HashSet<Task>>(window, "operations").Count == 0);
                var original = Database.Read(source, query, default);
                Check(Database.ReadIfChanged(source, query, default, original.Stamp) is null,
                    "An unchanged connection journal skips decoding");
                Field<Button>(window, "next").PerformClick();
                await Until(() => Field<int>(window, "page") == 1 && !Field<bool>(window, "loading") &&
                    Field<HashSet<Task>>(window, "operations").Count == 0);
                var replacement = Path.Combine(output, "replacement.db");
                using (var replaced = new SqliteConnection($"Data Source={replacement};Pooling=False"))
                {
                    replaced.Open();
                    writer.BackupDatabase(replaced);
                    using var replace = replaced.CreateCommand();
                    replace.CommandText = "UPDATE metadata SET database_id=lower(hex(randomblob(16)));" +
                        "UPDATE connections SET sni='replacement.refresh.test';" +
                        "UPDATE endpoint_events SET provider='Replacement adapter'," +
                        "timestamp_us=timestamp_us+1000000000";
                    replace.ExecuteNonQuery();
                }
                writer.Close();
                File.Move(path, Path.Combine(output, "unavailable.db"));
                await endpoints.RefreshAsync(source, query, true);
                Field<Button>(window, "refresh").PerformClick();
                await Until(() => !Field<bool>(window, "loading") &&
                    Field<HashSet<Task>>(window, "operations").Count == 0);
                Check(Field<int>(window, "page") == 1 && Field<int>(endpoints, "page") == 1 &&
                    Field<Label>(endpoints, "status").Text.StartsWith("Endpoint events unavailable."),
                    "Interrupted journal replacement leaves both historical views recoverable");
                File.Move(replacement, path, true);
                Check(Database.ReadStamp(source, default) is var replacedStamp &&
                    replacedStamp.Identity != original.Stamp.Identity &&
                    replacedStamp.Revision == original.Stamp.Revision,
                    "The replacement journal reuses the loaded observation revision");
                live.Checked = true;
                Field<Button>(window, "refresh").PerformClick();
                await Until(() => grid.RowCount == 250 && grid.Rows.Cast<DataGridViewRow>().All(row =>
                    row.Cells["Sni"].Value?.ToString()?.StartsWith("replacement.refresh.test") == true));
                live.Checked = false;
                Check(Database.ReadIfChanged(source, query, default, replacedStamp) is null,
                    "Live refresh loads a replacement journal and then resumes unchanged-revision caching");
                Check(Field<int>(window, "page") == 0 && !Field<Button>(window, "previous").Enabled,
                    "A replacement journal discards historical connection cursors after a failed query");
                await endpoints.RefreshAsync(source, query, true);
                Check(Field<int>(endpoints, "page") == 0 && !Field<Button>(endpoints, "previous").Enabled &&
                    Field<List<EndpointRow>>(endpoints, "rows") is { Count: 250 } replacementEvents &&
                    replacementEvents.All(row => row.Provider == "Replacement adapter"),
                    "A replacement journal discards historical endpoint cursors and loads its newest events");

                // Drilldown uses the original server name, including reports without ports and IPv6 addresses.
                using var evidence = new SqliteConnection($"Data Source={path};Pooling=False");
                evidence.Open();
                using var edit = evidence.CreateCommand();
                edit.CommandText = """
                    UPDATE connections SET sni=@sni,destination_address=@address,destination_port=@port,
                        tls_name='TLS 1.2',tls_version=771,crypto_json='{}',group_name='X25519',key_exchange='X25519'
                    WHERE id=(SELECT min(id) FROM connections);
                    UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                    """;
                using var drilldownReadiness = new ReadinessView(settings);
                using var drilldownPolicies = new PoliciesView(settings);
                var clicked = typeof(DataGridView).GetMethod("OnCellDoubleClick",
                    BindingFlags.Instance | BindingFlags.NonPublic)!;
                foreach (var (server, port) in new[]
                {
                    ("drilldown.example", 0), ("2001:db8::1", 0), ("2001:db8::1", 443)
                })
                {
                    edit.Parameters.Clear();
                    edit.Parameters.AddWithValue("@sni", server.Contains(':') ? "" : server);
                    edit.Parameters.AddWithValue("@address", server.Contains(':') ? server : "192.0.2.1");
                    edit.Parameters.AddWithValue("@port", port);
                    edit.ExecuteNonQuery();
                    var drilldownQuery = query with
                    {
                        Conditions = [new(ObservationField.ServerName, FilterComparison.Equals, server)]
                    };
                    foreach (var view in new InvestigationView[] { drilldownReadiness, drilldownPolicies })
                    {
                        await view.RefreshAsync(source, drilldownQuery, true);
                        if (view is PoliciesView)
                        {
                            var policyTable = Field<DataGridView>(view, "grid");
                            Check(policyTable.RowCount == 1, "The drilldown policy has an evaluated result");
                            policyTable.CurrentCell = policyTable.Rows[0].Cells[0];
                        }
                        var table = Field<DataGridView>(view, view is ReadinessView ? "grid" : "examples");
                        Check(table.RowCount == 1, $"{view.GetType().Name} loads the {server}:{port} observation");
                        string? filtered = null;
                        void Selected(string value) => filtered = value;
                        view.FilterRequested += Selected;
                        try { clicked.Invoke(table, [new DataGridViewCellEventArgs(0, 0)]); }
                        finally { view.FilterRequested -= Selected; }
                        Check(filtered == server,
                            $"{view.GetType().Name} drills into the complete server name for port {port}");
                    }
                }
            }
            catch (Exception error)
            {
                exit = 1;
                checks.Add(error.ToString());
            }
            finally
            {
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new { exit, checks },
                    new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine(string.Join(Environment.NewLine, checks));
                window.Close();
            }
        };
        Application.Run(window);
        return exit;
    }
}
