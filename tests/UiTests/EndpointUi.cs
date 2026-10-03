using System.Diagnostics;
using System.Reflection;
using Cipherazzi.Data;
using Cipherazzi.Viewer;

namespace Cipherazzi.UiTests;

internal static class EndpointUi
{
    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var settings = new ViewerSettings { Live = false, AnalyticsMinutes = 0,
            PersistencePath = Path.Combine(output, "Viewer.config") };
        using var window = new MainForm(DatabaseSource.Sqlite(args[0]), null, settings)
        {
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
        };
        var exit = 0;
        window.Shown += async (_, _) =>
        {
            try
            {
                var controls = Descendants(window).ToList();
                var tabs = controls.OfType<TabControl>().Single(control => control.AccessibleName == "Workspace views");
                var readiness = controls.OfType<ReadinessView>().Single();
                tabs.SelectedIndex = 4;
                await Until(() => readiness.Snapshot is not null);
                if (readiness.Snapshot!.Total != 7 ||
                    readiness.Snapshot.Rows.Sum(row => row.Count("Evidence source", "Endpoint")) != 4)
                    throw new InvalidOperationException("The UI omitted endpoint readiness evidence.");
                foreach (var theme in new[] { "Light", "Dark" })
                {
                    settings.Theme = theme;
                    typeof(MainForm).GetMethod("ApplyTheme", BindingFlags.Instance | BindingFlags.NonPublic)!
                        .Invoke(window, null);
                    window.ClientSize = new Size(1000, 650);
                    foreach (var view in new[] { 4, 6 })
                    {
                        tabs.SelectedIndex = view;
                        var grid = controls.OfType<DataGridView>().Single(control =>
                            control.Name == (view == 4 ? "ReadinessGrid" : "PolicyGrid"));
                        await Until(() => grid.RowCount > 0 && !Descendants(tabs.SelectedTab!).OfType<Label>()
                            .Any(label => label.Text.StartsWith("Loading", StringComparison.Ordinal)));
                        window.PerformLayout();
                        using var bitmap = new Bitmap(window.Width, window.Height);
                        window.DrawToBitmap(bitmap, new Rectangle(Point.Empty, window.Size));
                        bitmap.Save(Path.Combine(output, theme + "-" + view + ".png"));
                    }
                }
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

    private static IEnumerable<Control> Descendants(Control control)
    {
        foreach (Control child in control.Controls)
        {
            yield return child;
            foreach (var descendant in Descendants(child))
                yield return descendant;
        }
    }

    private static async Task Until(Func<bool> condition)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(15))
                throw new TimeoutException("Endpoint UI did not finish loading.");
            await Task.Delay(20);
        }
    }
}
