using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;
using Microsoft.Data.Sqlite;

namespace Cipherazzi.UiTests;

internal static class CertificateMetadataUi
{
    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "certificate-ui.db");

        // Isolate the real viewer workflow from its source journal.
        using (var original = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
        }
        var unreadable = args.Contains("--unreadable");
        var missingSubject = args.Contains("--missing-subject");
        string hash, subject;
        using (var connection = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT sha256," + (missingSubject ? "sha256" :
                "json_extract(metadata_json,'$.subject')") + " FROM certificates " +
                "ORDER BY sha256 LIMIT 1";
            using var reader = command.ExecuteReader();
            reader.Read();
            hash = reader.GetString(0);
            subject = reader.GetString(1);
        }
        var baseline = args.Contains("--baseline");
        var settings = new ViewerSettings { Live = false, Theme = "Dark",
            PersistencePath = Path.Combine(output, "Viewer.config") };
        UiTheme.Select(settings.Theme);
        using var window = new MainForm(DatabaseSource.Sqlite(path), null, settings)
        {
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000)
        };
        var checks = new List<string>();
        var samples = new List<object>();
        var watch = new Stopwatch();
        var lastTick = 0d;
        var pause = 0d;

        // Observe UI-thread stalls while the certificate view loads and renders metadata.
        using var pulse = new System.Windows.Forms.Timer { Interval = 25 };
        pulse.Tick += (_, _) =>
        {
            var elapsed = watch.Elapsed.TotalMilliseconds;
            pause = Math.Max(pause, elapsed - lastTick);
            lastTick = elapsed;
        };
        var exit = 0;
        window.Shown += async (_, _) =>
        {
            try
            {
                watch.Start();
                pulse.Start();
                var controls = Descendants(window).ToArray();
                var tabs = controls.OfType<TabControl>().Single(control =>
                    control.AccessibleName == "Workspace views");
                tabs.SelectedIndex = 5;
                var view = controls.OfType<CertificatesView>().Single();
                var grid = Descendants(view).OfType<DataGridView>().Single(control =>
                    control.Name == "CertificatesGrid");
                await Until(() => grid.RowCount > 0);
                var row = grid.Rows.Cast<DataGridViewRow>().Single(row =>
                    row.Cells["Sha256"].Value?.ToString() == hash);
                grid.CurrentCell = row.Cells["Subject"];
                var inspector = Descendants(view).OfType<PropertyInspector>().Single();
                await Until(() => inspector.Grid.SelectedObject is { } selected &&
                    TypeDescriptor.GetProperties(selected).Cast<PropertyDescriptor>().Any(property => missingSubject ?
                        property.DisplayName == "SHA-256" && property.GetValue(selected)?.ToString() == hash :
                        property.DisplayName == "Subject" && property.GetValue(selected)?.ToString() == subject));
                var ready = watch.Elapsed.TotalMilliseconds;
                var values = TypeDescriptor.GetProperties(inspector.Grid.SelectedObject!)
                    .Cast<PropertyDescriptor>().ToArray();
                if (row.Cells["Subject"].Value?.ToString() != subject || !baseline && values.Length > 512)
                    throw new InvalidOperationException("Certificate details lost their identity or display bounds.");
                checks.Add("Certificate metadata retains the recorded identity and readable fields");
                if (!baseline)
                {
                    if (!values.Any(property => property.DisplayName == "Metadata" &&
                        property.GetValue(inspector.Grid.SelectedObject)?.ToString() ==
                            (unreadable ? "Recorded certificate metadata could not be read" :
                                "Recorded certificate metadata exceeds the display limit")))
                        throw new InvalidOperationException("Truncated metadata needs an explicit display notice.");
                    checks.Add("Display limits remain explicit beside the readable certificate fields");
                }
                if (Descendants(view).OfType<Button>().Count(button => button.Visible && button.Enabled &&
                    (button.Text.Contains("Export certificate") ||
                        button.Text.Contains("Windows certificate viewer"))) != 2)
                    throw new InvalidOperationException("Certificate display limits disabled native viewing or export.");
                checks.Add("Original certificate viewing and export remain available");

                // Exercise the same inspector with normal and enlarged text.
                foreach (var points in baseline ? new[] { 9 } : [9, 12])
                {
                    window.Font = new Font("Segoe UI", points);
                    inspector.Grid.CollapseAllGridItems();
                    var root = inspector.Grid.SelectedGridItem;
                    while (root?.Parent is { } parent)
                        root = parent;
                    var category = root!.GridItems.Cast<GridItem>().Single(item => item.Label == "Certificate");
                    category.Expanded = true;
                    inspector.Grid.SelectedGridItem = category.GridItems.Cast<GridItem>()
                        .Single(item => item.Label == (baseline ? "Subject" : "Metadata"));
                    await Task.Delay(100);
                    samples.Add(new { font_points = points, properties = values.Length,
                        ready_ms = ready, maximum_ui_pause_ms = pause });
                    using var bitmap = new Bitmap(window.Width, window.Height);
                    window.DrawToBitmap(bitmap, new Rectangle(0, 0, window.Width, window.Height));
                    bitmap.Save(Path.Combine(output, "certificate-metadata-" + points + ".png"));
                }
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                { result = "passed", baseline, checks, dpi = window.DeviceDpi, samples },
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception error)
            {
                exit = 1;
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                { result = "failed", baseline, checks, samples, error = error.ToString() },
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            finally { pulse.Stop(); window.Close(); }
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
            if (watch.Elapsed > TimeSpan.FromSeconds(45))
                throw new TimeoutException("Certificate metadata UI did not reach the expected state.");
            await Task.Delay(25);
        }
    }
}
