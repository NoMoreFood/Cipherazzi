using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;
using Microsoft.Data.Sqlite;

namespace Cipherazzi.UiTests;

internal static class MigrationUi
{
    public static int Run(string[] args, bool performance)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var remote = args[0] is "sqlserver" or "postgresql" ?
            DatabaseSource.FromEnvironment(args[0], "CIPHERAZZI_CONNECTION") : null;
        var path = remote is null ? Path.GetFullPath(args[0]) : "";
        if (!performance)
        {
            path = Path.Combine(output, "ui.db");
            using var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection();
            using var destination = new SqliteConnection($"Data Source={path}");
            source.Open();
            destination.Open();
            source.BackupDatabase(destination);
        }
        var settings = new ViewerSettings { Theme = "Dark", AnalyticsMinutes = 0, AnalyticsRefreshSeconds = 2,
            Live = false, PersistencePath = Path.Combine(output, "Viewer.config") };
        var checks = new List<string>();
        var measurements = new Dictionary<string, double>();
        var errors = new List<string>();
        Application.ThreadException += (_, e) => errors.Add(e.Exception.ToString());
        var startup = Stopwatch.StartNew();
        using var runner = new Form { ShowInTaskbar = false, StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000) };
        using var window = new MainForm(remote ?? DatabaseSource.Sqlite(path), null, settings)
        {
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000),
            ClientSize = new Size(1440, 900)
        };
        var exit = 0;
        using var heartbeat = new System.Windows.Forms.Timer { Interval = 20 };
        var lastTick = Stopwatch.GetTimestamp();
        var maximumGap = 0.0;
        heartbeat.Tick += (_, _) =>
        {
            maximumGap = Math.Max(maximumGap, Stopwatch.GetElapsedTime(lastTick).TotalMilliseconds);
            lastTick = Stopwatch.GetTimestamp();
        };
        window.Shown += async (_, _) =>
        {
            try
            {
                void Check(bool accepted, string text)
                {
                    if (!accepted) throw new InvalidOperationException(text);
                    checks.Add(text);
                }
                var controls = Descendants(window).ToList();
                var tabs = controls.OfType<TabControl>().Single(control => control.AccessibleName == "Workspace views");
                var refresh = controls.OfType<Button>().Single(control => control.Text == "&Refresh");
                var connections = controls.OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
                var readiness = controls.OfType<ReadinessView>().Single();
                var inventory = controls.OfType<DataGridView>().Single(control => control.Name == "CertificatesGrid");
                var uses = controls.OfType<DataGridView>().Single(control => control.Name == "CertificateUsesGrid");
                var policyGrid = controls.OfType<DataGridView>().Single(control => control.Name == "PolicyGrid");
                await Until(() => connections.RowCount > 0 && refresh.Enabled);
                measurements["startup_ms"] = startup.Elapsed.TotalMilliseconds;
                lastTick = Stopwatch.GetTimestamp();
                heartbeat.Start();

                // Exercise each investigation through its actual tab, loading, and selection workflow.
                var watch = Stopwatch.StartNew();
                tabs.SelectedIndex = 4;
                await Until(() => readiness.Snapshot is not null);
                measurements["readiness_ms"] = watch.Elapsed.TotalMilliseconds;
                var initial = readiness.Snapshot!;
                Check(initial.Total > 0 && initial.Rows.All(row => row.Counts.Values.All(count => count <= row.Total)),
                    "Readiness includes all observations with valid denominators");
                Save(window, Path.Combine(output, "readiness.png"));
                if (!performance)
                {
                    await readiness.SaveBaselineAsync(Path.Combine(output, "baseline.json"));
                    await readiness.ImportBaselineAsync(Path.Combine(output, "baseline.json"));
                    Check(controls.OfType<DataGridView>().Single(control => control.Name == "BaselineGrid").RowCount == 0,
                        "Baseline save and import preserve evidence without reporting changes");
                    var live = controls.OfType<CheckBox>().Single(control => control.Text == "&Live");
                    live.Checked = true;
                    await Until(() => !ReferenceEquals(initial, readiness.Snapshot));
                    var idle = readiness.Snapshot;
                    await Task.Delay(2800);
                    Check(ReferenceEquals(idle, readiness.Snapshot), "An unchanged journal does not repeat readiness scans");
                    using var writer = new SqliteConnection($"Data Source={path}");
                    writer.Open();
                    using var command = writer.CreateCommand();
                    command.CommandText = """
                        BEGIN IMMEDIATE;
                        UPDATE metadata SET revision=revision+1;
                        UPDATE connections SET crypto_json=json_set(crypto_json,'$.group_class','Classical',
                            '$.selected_group_id',29,'$.group_standardization','Assigned'),group_name='X25519',
                            change_revision=(SELECT revision FROM metadata) WHERE sni='case-1.migration.test';
                        COMMIT;
                        """;
                    watch.Restart();
                    command.ExecuteNonQuery();
                    await Until(() => readiness.Snapshot?.Rows.SingleOrDefault(row => row.Peer == "case-1.migration.test:443")
                        ?.ClassicalKeys > 0);
                    measurements["readiness_live_latency_ms"] = watch.Elapsed.TotalMilliseconds;
                    Check(controls.OfType<DataGridView>().Single(control => control.Name == "BaselineGrid").Rows
                        .Cast<DataGridViewRow>().Any(row => row.Cells["Change"].Value?.ToString()?.Contains("Classical") == true),
                        "Live evidence updates produce an observed baseline regression");
                    live.Checked = false;
                }
                watch.Restart();
                tabs.SelectedIndex = 5;
                await Until(() => inventory.RowCount > 0);
                var linked = inventory.Rows.Cast<DataGridViewRow>().First(row => Convert.ToInt64(row.Cells["Observations"].Value) > 0);
                inventory.CurrentCell = linked.Cells[0];
                await Until(() => uses.RowCount > 0);
                measurements["certificate_inventory_and_usage_ms"] = watch.Elapsed.TotalMilliseconds;
                Check(uses.Rows.Cast<DataGridViewRow>().All(row => Convert.ToInt32(row.Cells["Position"].Value) >= 1),
                    "Certificate usage exposes ordered chain positions");
                Save(window, Path.Combine(output, "certificates.png"));
                watch.Restart();
                tabs.SelectedIndex = 6;
                await Until(() => policyGrid.RowCount > 0);
                measurements["policies_ms"] = watch.Elapsed.TotalMilliseconds;
                if (!performance)
                {
                    var editor = controls.OfType<PropertyGrid>().Single(control => control.AccessibleName == "Cryptographic policy editor");
                    var candidate = (CryptoPolicy)editor.SelectedObject!;
                    candidate.Name = "Scoped UI policy";
                    candidate.ServerName = "case-1.migration.test";
                    candidate.RequirePostQuantumServerAuthentication = true;
                    controls.OfType<Button>().Single(control => control.Text == "Appl&y policies").PerformClick();
                    await Until(() => policyGrid.RowCount > 0 &&
                        policyGrid.Rows[0].Cells["Policy"].Value?.ToString() == "Scoped UI policy");
                    Check(Convert.ToInt64(policyGrid.Rows[0].Cells["Applicable"].Value) == 100 &&
                        Convert.ToInt64(policyGrid.Rows[0].Cells["Violations"].Value) == 100,
                        "Edited scoped policies persist and evaluate the intended observations");
                    Check(ViewerSettings.Load(settings.PersistencePath).ScopedPolicies.Single().Name == "Scoped UI policy",
                        "Applied policy configuration reloads correctly");
                }
                Save(window, Path.Combine(output, "policies.png"));
                Check(errors.Count == 0, "Investigation workflows raise no UI thread exceptions");
                Check(maximumGap < 1500, "Investigation views remain responsive while database work runs");

                // Closing immediately after starting a large read exercises cancellation and task draining.
                tabs.SelectedIndex = 4;
                refresh.PerformClick();
                await Task.Delay(30);
                watch.Restart();
                window.Close();
                await Until(() => window.IsDisposed, 10000);
                measurements["close_during_read_ms"] = watch.Elapsed.TotalMilliseconds;
            }
            catch (Exception error)
            {
                exit = 1;
                errors.Add(error.ToString());
                window.Close();
            }
            finally
            {
                heartbeat.Stop();
                measurements["maximum_ui_gap_ms"] = maximumGap;
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                {
                    mode = performance ? "performance" : "functional", checks, measurements, errors
                }, new JsonSerializerOptions { WriteIndented = true }));
                runner.Close();
            }
        };
        runner.Shown += (_, _) => window.Show(runner);
        Application.Run(runner);
        return exit;
    }

    private static IEnumerable<Control> Descendants(Control parent)
    {
        foreach (Control child in parent.Controls)
        {
            yield return child;
            foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }

    private static async Task Until(Func<bool> ready, int milliseconds = 120000)
    {
        var watch = Stopwatch.StartNew();
        while (!ready())
        {
            if (watch.ElapsedMilliseconds > milliseconds) throw new TimeoutException("UI workflow did not complete.");
            await Task.Delay(20);
        }
    }

    private static void Save(Control control, string path)
    {
        using var bitmap = new Bitmap(control.Width, control.Height);
        control.DrawToBitmap(bitmap, new Rectangle(Point.Empty, control.Size));
        bitmap.Save(path);
    }
}
