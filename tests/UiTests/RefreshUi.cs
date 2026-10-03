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
                await Until(() => Field<bool>(window, "loading"));
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
                tabs.SelectedIndex = 0;
                await Until(() => grid.RowCount == 250 && !Field<bool>(window, "loading") &&
                    Field<HashSet<Task>>(window, "operations").Count == 0);
                var original = Database.Read(source, query, default);
                Check(Database.ReadIfChanged(source, query, default, original.Stamp) is null,
                    "An unchanged connection journal skips decoding");
                var replacement = Path.Combine(output, "replacement.db");
                using (var replaced = new SqliteConnection($"Data Source={replacement};Pooling=False"))
                {
                    replaced.Open();
                    writer.BackupDatabase(replaced);
                    using var replace = replaced.CreateCommand();
                    replace.CommandText = "UPDATE metadata SET database_id=lower(hex(randomblob(16)));" +
                        "UPDATE connections SET sni='replacement.refresh.test'";
                    replace.ExecuteNonQuery();
                }
                writer.Close();
                File.Move(replacement, path, true);
                Check(Database.ReadStamp(source, default) is var replacedStamp &&
                    replacedStamp.Identity != original.Stamp.Identity &&
                    replacedStamp.Revision == original.Stamp.Revision,
                    "The replacement journal reuses the loaded observation revision");
                live.Checked = true;
                await Until(() => grid.RowCount == 250 && grid.Rows.Cast<DataGridViewRow>().All(row =>
                    row.Cells["Sni"].Value?.ToString()?.StartsWith("replacement.refresh.test") == true));
                live.Checked = false;
                Check(Database.ReadIfChanged(source, query, default, replacedStamp) is null,
                    "Live refresh loads a replacement journal and then resumes unchanged-revision caching");
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
