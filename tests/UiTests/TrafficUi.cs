using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;
using Microsoft.Data.Sqlite;

namespace Cipherazzi.UiTests;

internal static class TrafficUi
{
    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "traffic.db");
        using (var original = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);

            // A driver-marked local flow need not use localhost or matching IP addresses.
            var columns = new List<string>();
            using (var schema = copy.CreateCommand())
            {
                schema.CommandText = "PRAGMA table_info(connections)";
                using var reader = schema.ExecuteReader();
                while (reader.Read())
                    if (reader.GetString(1) != "id")
                        columns.Add(reader.GetString(1));
            }
            using var command = copy.CreateCommand();
            command.CommandText = $"INSERT INTO connections({string.Join(',', columns)}) SELECT " +
                string.Join(',', columns.Select(column => column switch
                {
                    "flow_id" => "10000",
                    "source_address" => "'10.30.0.1'",
                    "destination_address" => "'10.30.0.2'",
                    "crypto_json" => "json_set(crypto_json,'$.loopback',json('true'))",
                    _ => column
                })) + " FROM connections WHERE destination_port=3009";
            command.ExecuteNonQuery();
            command.CommandText = "UPDATE connections SET crypto_json=json_set(crypto_json,'$.http_hosts'," +
                "json_array('ordinary.http-monitor.test:3000','secondary.test')) WHERE destination_port=3001";
            command.ExecuteNonQuery();
            foreach (var (id, local, remote, protocol) in new[]
            {
                ("network", "10.20.0.1", "10.20.0.2", "TLS"), ("localhost", "::1", "::1", "TLS"),
                ("samehost", "192.0.2.1", "192.0.2.1", "TLS"), ("unknown", "", "", "TLS"),
                ("http", "10.20.0.1", "10.20.0.2", "HTTP")
            })
            {
                command.CommandText = """
                    INSERT INTO endpoint_events
                    SELECT @id,id,started_us,'Traffic fixture','TLS','Observed',0,@id,443,@protocol,'','',@json,1
                    FROM capture_sessions LIMIT 1
                    """;
                command.Parameters.Clear();
                command.Parameters.AddWithValue("@id", id);
                command.Parameters.AddWithValue("@protocol", protocol);
                command.Parameters.AddWithValue("@json", JsonSerializer.Serialize(new
                {
                    local = new { address = local, port = 40000 },
                    remote = new { address = remote, port = 443 },
                    role = "client",
                    transport = "TCP"
                }));
                command.ExecuteNonQuery();
            }
        }

        var source = DatabaseSource.Sqlite(path);
        var checks = new List<string>();
        void Check(bool condition, string message)
        {
            if (!condition)
                throw new InvalidOperationException(message);
            checks.Add(message);
        }
        Query Scope(bool http, bool loopback) => new("", "", false, PageCursor.Newest)
        { IncludeHttp = http, IncludeLoopback = loopback };
        var combinations = new[] { (true, true, 10, 5), (false, true,
            4, 4), (true, false, 5, 3), (false, false, 2, 2) };
        foreach (var (http, loopback, count, events) in combinations)
        {
            var query = Scope(http, loopback);
            Check(Database.Read(source, query, CancellationToken.None).Rows.Count == count,
                $"Connection filters compose for HTTP={http}, loopback={loopback}");
            Check(Insights.ReadAnalytics(source, query, 0, "Protocol", 20, CancellationToken.None).Total == count,
                "Analytics uses the traffic visibility scope");
            Check(ReportExport.Write(source, query, ReportKind.Connections,
                Path.Combine(output, $"connections-{http}-{loopback}.jsonl"), [], CancellationToken.None) == count,
                "Connection exports use the traffic visibility scope");
            Check(Insights.ReadEvents(source, query, long.MaxValue, "", 0, CancellationToken.None).Rows.Count == events,
                "Endpoint visibility handles local, remote, and unknown sockets");
            Check(ReportExport.Write(source, query, ReportKind.Endpoints,
                Path.Combine(output, $"endpoints-{http}-{loopback}.jsonl"), [], CancellationToken.None) == events,
                "Endpoint exports use the traffic visibility scope");
        }
        var hosts = Database.Read(source, Scope(true, true) with { Search = "ordinary.http-monitor.test" },
            CancellationToken.None);
        Check(hosts.Rows.Count == 4 && hosts.Rows.All(row => row.Value("Peer") == "ordinary.http-monitor.test:3000"),
            "HTTP hosts are visible and searchable without being stored as TLS SNI");
        Check(hosts.Rows.All(row => row.Value("Encryption") == "Unencrypted" &&
            row.Properties.Any(property => property.Category == "HTTP" && property.Value == "GET") &&
            row.Properties.All(property => property.Category is not "HTTP authentication" and not "Authentication")),
            "Ordinary HTTP details show metadata and unencrypted protection without authentication claims");
        Check(Database.Read(source, Scope(true, true) with
        {
            Conditions = [new(ObservationField.ServerName, FilterComparison.Equals, "ordinary.http-monitor.test:3000")]
        }, CancellationToken.None).Rows.Count == 4, "Server-name conditions match HTTP hosts");
        Check(Insights.ReadAnalytics(source, Scope(true, true), 0, "Server name", 20, CancellationToken.None)
            .Breakdown.Any(row => row.Name == "ordinary.http-monitor.test:3000" && row.Count == 4),
            "Server-name analytics groups HTTP hosts");

        // Every host on a reused connection participates in search and structured field conditions.
        var secondary = Scope(true, true) with { Search = "SECONDARY.test" };
        Check(Database.Read(source, secondary, CancellationToken.None).Rows.Count == 1 &&
            Insights.ReadAnalytics(source, secondary, 0, "Server name", 20, CancellationToken.None).Total == 1 &&
            ReportExport.Write(source, secondary, ReportKind.Connections,
                Path.Combine(output, "secondary-host.jsonl"), [], CancellationToken.None) == 1,
            "Secondary HTTP hosts match search, analytics, and exports");
        foreach (var (comparison, value, count) in new[]
        {
            (FilterComparison.Equals, "SECONDARY.test", 1), (FilterComparison.Contains, "CONDAR", 1),
            (FilterComparison.StartsWith, "SECOND", 1), (FilterComparison.NotEquals, "secondary.test", 9)
        })
            Check(Database.Read(source, Scope(true, true) with
            {
                Conditions = [new(ObservationField.ServerName, comparison, value)]
            }, CancellationToken.None).Rows.Count == count, "Secondary HTTP host condition: " + comparison);

        var settings = new ViewerSettings
        {
            Live = false,
            AnalyticsMinutes = 0,
            Theme = "Light",
            PersistencePath = Path.Combine(output, "Viewer.config"),
            SavedSearches = [new("Keep my search", InvestigationTarget.Connections, Scope(true, true))]
        };
        UiTheme.Select(settings.Theme);
        using var window = new MainForm(source, null, settings)
        {
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000)
        };
        var exit = 0;
        window.Shown += async (_, _) =>
        {
            try
            {
                var controls = Descendants(window).ToList();
                var grid = controls.OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
                var refresh = controls.OfType<Button>().Single(control => control.Text == "&Refresh");
                var options = controls.OfType<Button>().Single(control => control.Text == "&Options…");
                await Until(() => grid.RowCount == 10 && refresh.Enabled);
                void Configure(bool http, bool loopback, bool apply = true)
                {
                    Exception? failure = null;
                    using var automation = new System.Windows.Forms.Timer { Interval = 25 };
                    automation.Tick += (_, _) =>
                    {
                        if (Application.OpenForms.OfType<SettingsDialog>().FirstOrDefault() is not { } dialog)
                            return;
                        automation.Stop();
                        try
                        {
                            var children = Descendants(dialog).ToList();
                            children.OfType<CheckBox>().Single(control => control.AccessibleName == "Show HTTP traffic")
                                .Checked = http;
                            children.OfType<CheckBox>().Single(control =>
                                control.AccessibleName == "Show loopback traffic")
                                .Checked = loopback;
                            foreach (var theme in new[] { "Light", "Dark" })
                                foreach (var points in new[] { 9f, 12f })
                                {
                                    dialog.Font = new Font("Segoe UI", points);
                                    UiTheme.Apply(dialog, theme);
                                    dialog.ClientSize = new Size(650 * dialog.DeviceDpi / 96,
                                        650 * dialog.DeviceDpi / 96);
                                    dialog.PerformLayout();
                                    foreach (var control in children.Where(control => control.Visible &&
                                        control is Button or CheckBox or TextBox or ComboBox or NumericUpDown))
                                        Check(control.Parent!.ClientRectangle.Contains(control.Bounds),
                                            "Options controls fit at both tested text sizes");
                                    using var bitmap = new Bitmap(dialog.Width, dialog.Height);
                                    dialog.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
                                    bitmap.Save(Path.Combine(output, $"options-{theme}-{points}.png"));
                                }
                            children.OfType<Button>().Single(control => control.Text == (apply ? "&Apply" : "Cancel"))
                                .PerformClick();
                        }
                        catch (Exception error) { failure = error; dialog.Close(); }
                    };
                    automation.Start();
                    options.PerformClick();
                    if (failure is not null)
                        throw failure;
                }
                foreach (var (http, loopback, count, _) in combinations.Skip(1))
                {
                    Configure(http, loopback);
                    await Until(() => grid.RowCount == count && refresh.Enabled);
                    var saved = ViewerSettings.Load(settings.PersistencePath);
                    Check(saved.ShowHttp == http && saved.ShowLoopback == loopback && saved.SavedSearches.Count == 1,
                        "Applying traffic options refreshes results and preserves saved defaults and searches");
                }
                Configure(true, true, apply: false);
                Check(!settings.ShowHttp && !settings.ShowLoopback && grid.RowCount == 2,
                    "Cancel leaves traffic visibility unchanged");
                Configure(true, true);
                await Until(() => grid.RowCount == 10 && refresh.Enabled);
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                {
                    result = "passed",
                    checks = checks.Distinct(),
                    dpi = window.DeviceDpi
                }, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception error)
            {
                exit = 1;
                File.WriteAllText(Path.Combine(output, "failure.txt"), error.ToString());
            }
            finally { window.Close(); }
        };
        Application.Run(window);
        return exit;
    }

    private static IEnumerable<Control> Descendants(Control control) => control.Controls.Cast<Control>()
        .SelectMany(child => new[] { child }.Concat(Descendants(child)));

    private static async Task Until(Func<bool> ready)
    {
        var watch = Stopwatch.StartNew();
        while (!ready())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(15))
                throw new TimeoutException("The traffic view did not finish loading.");
            await Task.Delay(25);
        }
    }
}
