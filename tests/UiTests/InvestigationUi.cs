using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;
using Microsoft.Data.Sqlite;

namespace Cipherazzi.UiTests;

internal static class InvestigationUi
{
    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "investigation-ui.db");
        using (var original = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
            using var command = copy.CreateCommand();
            command.CommandText = "PRAGMA journal_mode=DELETE";
            command.ExecuteNonQuery();
        }
        long first, last, total;
        using (var connection = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT min(first_us),max(first_us),count(*) FROM connections";
            using var reader = command.ExecuteReader();
            reader.Read();
            first = reader.GetInt64(0);
            last = reader.GetInt64(1);
            total = reader.GetInt64(2);
        }
        var settings = new ViewerSettings
        {
            Live = false, AnalyticsMinutes = 15, Theme = "Dark",
            PersistencePath = Path.Combine(output, "Viewer.config"),
            ScopedPolicies = [new CryptoPolicy { Name = "Investigation UI", RequirePostQuantumKeyExchange = false,
                RequireEndpointCompletion = false }]
        };
        UiTheme.Select(settings.Theme);
        using var window = new MainForm(DatabaseSource.Sqlite(path), null, settings)
        {
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
        };
        var checks = new List<string>();
        var exit = 0;
        void Check(bool condition, string text)
        {
            if (!condition)
                throw new InvalidOperationException(text);
            checks.Add(text);
        }
        window.Shown += async (_, _) =>
        {
            try
            {
                var controls = Descendants(window).ToList();
                var grid = controls.OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
                var refresh = controls.OfType<Button>().Single(control => control.Text == "&Refresh");
                var filter = controls.OfType<Button>().Single(control =>
                    control.AccessibleName == "Dates, field filters, and saved searches");
                var export = controls.OfType<Button>().Single(control => control.AccessibleName == "Export matching evidence");
                var tabs = controls.OfType<TabControl>().Single(control => control.AccessibleName == "Workspace views");
                await Until(() => grid.RowCount == 250 && refresh.Enabled);
                var scope = new Query("", "", false, PageCursor.Newest)
                {
                    FromUs = first, ToUs = last, Conditions =
                    [new(ObservationField.ServerName, FilterComparison.Equals, "case-1.migration.test"),
                     new(ObservationField.ClientProcess, FilterComparison.Contains, "client"),
                     new(ObservationField.ServerPort, FilterComparison.Equals, "443")]
                };
                void EditFilters(Action<FilterDialog> edit)
                {
                    Exception? failure = null;
                    using var automation = new System.Windows.Forms.Timer { Interval = 25 };
                    automation.Tick += (_, _) =>
                    {
                        if (Application.OpenForms.OfType<FilterDialog>().FirstOrDefault() is not { } dialog)
                            return;
                        automation.Stop();
                        try { edit(dialog); }
                        catch (Exception error) { failure = error; dialog.Close(); }
                    };
                    automation.Start();
                    filter.PerformClick();
                    if (failure is not null)
                        throw failure;
                }

                // Save from the real modal workflow, then cancel so the visible scope remains unchanged.
                EditFilters(dialog =>
                {
                    dialog.SetScope(new("", "", false, PageCursor.Newest));
                    var children = Descendants(dialog).ToList();
                    var conditions = children.OfType<DataGridView>().Single(control => control.Name == "FieldConditions");
                    children.OfType<Button>().Single(control => control.Text == "Add &condition").PerformClick();
                    conditions.Rows[0].Cells[0].Value = ObservationField.ServerPort;
                    conditions.Rows[0].Cells[2].Value = "443";
                    Check(dialog.ReadScope().Conditions.Single() is { Field: ObservationField.ServerPort,
                        Comparison: FilterComparison.Equals, Value: "443" },
                        "Native numeric field editing selects a valid equality comparison");
                    conditions.Rows[0].Cells[1].Value = FilterComparison.Observed;
                    Check(conditions.Rows[0].Cells[2].ReadOnly, "Value-free conditions hide editing of an irrelevant value");
                    children.OfType<Button>().Single(control => control.Text == "C&lear filters").PerformClick();
                    Check(!dialog.ReadScope().HasAdvancedFilters, "Clear filters resets date and field conditions together");
                    dialog.SetScope(scope);
                    Check(dialog.ReadScope().CacheKey == scope.CacheKey, "Native filter inputs preserve precise date bounds");
                    Descendants(dialog).OfType<TextBox>().Single(control => control.AccessibleName == "Saved search name")
                        .Text = "Migration investigation";
                    Descendants(dialog).OfType<Button>().Single(control => control.Text == "Sa&ve search").PerformClick();
                    Check(ViewerSettings.Load(settings.PersistencePath).SavedSearches.Single().Query.CacheKey == scope.CacheKey,
                        "Saved searches persist dates and every typed condition");
                    foreach (var points in new[] { 9, 12 })
                    {
                        dialog.Font = new Font("Segoe UI", points);
                        dialog.ClientSize = new Size(1100, 780);
                        Capture(dialog, "filters-" + points, output);
                    }
                    ((Button)dialog.CancelButton!).PerformClick();
                });
                Check(grid.RowCount == 250, "Cancelling the filter dialog preserves the current results");
                EditFilters(dialog =>
                {
                    var saved = Descendants(dialog).OfType<ComboBox>().Single(control => control.AccessibleName == "Saved searches");
                    saved.SelectedItem = settings.SavedSearches.Single();
                    Check(dialog.ReadScope().CacheKey == scope.CacheKey, "Loading a saved search restores its full scope");
                    ((Button)dialog.AcceptButton!).PerformClick();
                });
                Check(grid.RowCount == 0, "Applying named filters clears stale observations immediately");
                await Until(() => grid.RowCount == total / 10 && refresh.Enabled);
                Check(grid.Rows.Cast<DataGridViewRow>().All(row => row.Cells["Sni"].Value?.ToString() == "case-1.migration.test"),
                    "The connection grid displays only the intersection of saved conditions");
                Check(await window.ExportMatchingAsync(Path.Combine(output, "scoped-connections.jsonl"),
                    ReportKind.Connections) == total / 10, "Desktop connection export uses the active saved scope");

                tabs.SelectedIndex = 4;
                var readiness = controls.OfType<ReadinessView>().Single();
                await Until(() => readiness.Snapshot?.Total == total / 10);
                Check(Descendants(readiness).OfType<ComboBox>().Single(control =>
                    control.AccessibleName == "Investigation time window").Parent?.Visible == false,
                    "Explicit dates hide the inapplicable readiness preset");
                tabs.SelectedIndex = 6;
                var policies = controls.OfType<DataGridView>().Single(control => control.Name == "PolicyGrid");
                await Until(() => policies.RowCount == 1 && Convert.ToInt64(policies.Rows[0].Cells["Applicable"].Value) == total / 10);
                Check(await window.ExportMatchingAsync(Path.Combine(output, "scoped-policies.csv"), ReportKind.Policies) == total / 10,
                    "Desktop policy export uses explicit dates rather than its hidden relative preset");

                // Endpoint reports keep their own typed scope, including provider and endpoint role conditions.
                tabs.SelectedIndex = 3;
                var endpointScope = new Query("", "", false, PageCursor.Newest)
                {
                    FromUs = first, ToUs = last + 1000, Conditions =
                    [new(ObservationField.Provider, FilterComparison.Equals, "Investigation adapter"),
                     new(ObservationField.ServerProcess, FilterComparison.Contains, "endpoint-Δ")]
                };
                window.ApplyFilters(endpointScope, InvestigationTarget.Endpoints);
                var events = controls.OfType<DataGridView>().Single(control => control.AccessibleName == "Endpoint telemetry events");
                await Until(() => events.RowCount == 200);
                Check(await window.ExportMatchingAsync(Path.Combine(output, "scoped-endpoints.jsonl"), ReportKind.Endpoints) == 200,
                    "Desktop endpoint export respects provider and server-process conditions");
                tabs.SelectedIndex = 0;
                await Until(() => grid.RowCount == total / 10);
                Check(grid.RowCount == total / 10, "Endpoint filters do not replace the saved connection scope");
                window.ApplyFilters(new("", "", false, PageCursor.Newest), InvestigationTarget.Connections);
                await Until(() => grid.RowCount == 250 && refresh.Enabled);
                controls.OfType<Button>().Single(control => control.Visible && control.Text == "Ol&der").PerformClick();
                await Until(() => grid.RowCount == 250 && refresh.Enabled);
                Check(await window.ExportMatchingAsync(Path.Combine(output, "all-connections.csv"), ReportKind.Connections) == total,
                    "Bulk export includes all matching pages while an older page is displayed");

                // Interrupt a real locked-journal read through the visible cancellation command.
                using (var blocker = new SqliteConnection($"Data Source={path};Pooling=False"))
                {
                    blocker.Open();
                    using var command = blocker.CreateCommand();
                    command.CommandText = "BEGIN EXCLUSIVE; UPDATE metadata SET revision=revision";
                    command.ExecuteNonQuery();
                    var task = window.ExportMatchingAsync(Path.Combine(output, "interrupted.csv"), ReportKind.Connections);
                    await Until(() => export.Text.StartsWith("Cancel", StringComparison.Ordinal));
                    export.PerformClick();
                    Check(await task.WaitAsync(TimeSpan.FromSeconds(5)) is null &&
                        !File.Exists(Path.Combine(output, "interrupted.csv")),
                        "Cancelling a blocked desktop export leaves no partial report");
                    command.CommandText = "ROLLBACK";
                    command.ExecuteNonQuery();
                }
                Check(!Directory.EnumerateFiles(output, "*.tmp").Any(), "Desktop exports remove abandoned staging files");
                EditFilters(dialog =>
                {
                    var children = Descendants(dialog).ToList();
                    children.OfType<ComboBox>().Single(control => control.AccessibleName == "Saved searches")
                        .SelectedItem = settings.SavedSearches.Single();
                    children.OfType<Button>().Single(control => control.Text == "&Delete search").PerformClick();
                    Check(ViewerSettings.Load(settings.PersistencePath).SavedSearches.Count == 0,
                        "Deleting a saved search persists without changing the active query");
                    ((Button)dialog.CancelButton!).PerformClick();
                });
                tabs.SelectedIndex = 5;
                Check(!export.Visible && !filter.Visible, "Certificate view hides unrelated bulk-export and filter actions");
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                {
                    result = "passed", checks, dpi = window.DeviceDpi, text_sizes = new[] { 9, 12 }
                }, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception error)
            {
                exit = 1;
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                { result = "failed", checks, failure = error.ToString() }, new JsonSerializerOptions { WriteIndented = true }));
            }
            finally { window.Close(); }
        };
        Application.Run(window);
        return exit;
    }

    private static void Capture(Form window, string name, string output)
    {
        window.PerformLayout();
        foreach (var control in Descendants(window).Where(control => control.Visible &&
            control is Button or TextBox or ComboBox or CheckBox or DateTimePicker))
            if (!window.ClientRectangle.Contains(window.RectangleToClient(control.RectangleToScreen(control.ClientRectangle))))
                throw new InvalidOperationException("Filter control is clipped: " + control.AccessibleName);
        using var bitmap = new Bitmap(window.Width, window.Height);
        window.DrawToBitmap(bitmap, new Rectangle(0, 0, window.Width, window.Height));
        bitmap.Save(Path.Combine(output, name + ".png"));
    }

    private static IEnumerable<Control> Descendants(Control control) => control.Controls.Cast<Control>()
        .SelectMany(child => new[] { child }.Concat(Descendants(child)));

    private static async Task Until(Func<bool> ready)
    {
        var watch = Stopwatch.StartNew();
        while (!ready())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(12))
                throw new TimeoutException("Investigation UI did not reach the expected state.");
            await Task.Delay(25);
        }
    }
}
