using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;

namespace Cipherazzi.UiTests;

internal static class LayoutAudit
{
    private sealed record Frame(string Name, int Dpi, float FontPoints, Size ClientSize,
        List<string> Issues, object[] Controls);

    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var frames = new List<Frame>();
        var settings = new ViewerSettings { Theme = "Dark", AnalyticsMinutes = 0, Live = false,
            PersistencePath = Path.Combine(output, "Viewer.config") };
        UiTheme.Select(settings.Theme);
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
                var grid = controls.OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
                var refresh = controls.OfType<Button>().Single(control => control.Text == "&Refresh");
                var tabs = controls.OfType<TabControl>().Single(tabControl => tabControl.AccessibleName == "Workspace views");
                var search = controls.OfType<TextBox>().Single(control => control.PlaceholderText.Length > 0);
                await Until(() => grid.RowCount > 0 && refresh.Enabled);

                // Inspect actual rendered layouts across compact, full, and enlarged-text workspaces.
                foreach (var theme in new[] { "Light", "Dark" })
                {
                    ApplyTheme(window, theme);
                    foreach (var (name, font, size) in new[]
                    {
                        ("compact", 9f, new Size(1000, 650)),
                        ("full", 9f, new Size(1440, 900)),
                        ("text", 12f, new Size(1100, 750))
                    })
                    {
                        window.Font = new Font("Segoe UI", font);
                        window.ClientSize = size;
                        for (var index = 0; index < tabs.TabCount; ++index)
                        {
                            tabs.SelectedIndex = index;
                            await Task.Delay(550);
                            await Until(() => !Descendants(tabs.SelectedTab!).OfType<Label>().Any(control =>
                                control.Text.StartsWith("Aggregating") || control.Text.StartsWith("Loading")));
                            Require(!Descendants(tabs.SelectedTab!).OfType<Label>().Any(control =>
                                control.Text.StartsWith("View unavailable")), "A workspace view failed to load.");
                            if (index == 2)
                            {
                                var table = Descendants(tabs.SelectedTab!).OfType<DataGridView>().Single();
                                table.Sort(table.Columns["Count"]!, System.ComponentModel.ListSortDirection.Descending);
                            }
                            Capture(window, $"{theme.ToLowerInvariant()}-{name}-tab-{index}", output, frames);
                        }
                    }
                    tabs.SelectedIndex = 0;
                    foreach (var font in new[] { 9f, 12f })
                    {
                        using var options = new SettingsDialog(settings, grid)
                        {
                            Font = new Font("Segoe UI", font), ShowInTaskbar = false,
                            StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
                        };
                        options.Show(window);
                        options.Size = options.MinimumSize;
                        await Task.Delay(80);
                        var optionControls = Descendants(options).ToList();
                        var list = optionControls.OfType<CheckedListBox>().Single();
                        var up = optionControls.OfType<Button>().Single(control => control.Text == "Move &up");
                        var down = optionControls.OfType<Button>().Single(control => control.Text == "Move &down");
                        Require(!up.Enabled && down.Enabled, "Column movement does not reflect the first item.");
                        list.SelectedIndex = list.Items.Count - 1;
                        Require(up.Enabled && !down.Enabled, "Column movement does not reflect the last item.");
                        list.SelectedIndex = 0;
                        Capture(options, $"{theme.ToLowerInvariant()}-options-{font}", output, frames);
                        var longest = list.Items.Cast<object>().Select((item, index) => (item, index))
                            .MaxBy(value => TextRenderer.MeasureText(value.item.ToString(), list.Font).Width);
                        list.SelectedIndex = longest.index;
                        list.TopIndex = Math.Max(0, longest.index - 2);
                        Capture(options, $"{theme.ToLowerInvariant()}-columns-{font}", output, frames);
                        options.Close();

                        using var connection = new ConnectionDialog(null)
                        {
                            Font = new Font("Segoe UI", font), ShowInTaskbar = false,
                            StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
                        };
                        UiTheme.Apply(connection, theme);
                        connection.Show(window);
                        var provider = Descendants(connection).OfType<ComboBox>().Single();
                        for (var index = 0; index < provider.Items.Count; ++index)
                        {
                            provider.SelectedIndex = index;
                            await Task.Delay(80);
                            Capture(connection, $"{theme.ToLowerInvariant()}-connection-{font}-{index}",
                                output, frames);
                        }
                        var authentication = Descendants(connection).OfType<CheckBox>()
                            .Single(control => control.Text == "&Windows authentication");
                        provider.SelectedIndex = 1;
                        authentication.Checked = false;
                        await Task.Delay(80);
                        Capture(connection, $"{theme.ToLowerInvariant()}-connection-{font}-sql-login", output, frames);
                        provider.SelectedIndex = 0;
                        Descendants(connection).OfType<Button>().Single(control => control.Text == "&Connect")
                            .PerformClick();
                        await Task.Delay(80);
                        Capture(connection, $"{theme.ToLowerInvariant()}-connection-{font}-error", output, frames);
                        connection.Close();
                    }
                }

                // Capture empty search results and disconnected startup so status and help remain understandable.
                tabs.SelectedIndex = 0;
                window.Font = new Font("Segoe UI", 9);
                window.ClientSize = new Size(1000, 650);
                search.Text = "no-match-layout-audit";
                await Until(() => grid.RowCount == 0 && refresh.Enabled);
                await Task.Delay(400);
                Capture(window, "empty-filter", output, frames);
                using var disconnected = new MainForm(null, null, settings)
                {
                    ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
                };
                disconnected.Show(window);
                disconnected.ClientSize = new Size(1000, 650);
                await Task.Delay(80);
                var disconnectedControls = Descendants(disconnected).ToList();
                Require(!disconnectedControls.OfType<Button>().Single(control => control.Text == "&Refresh").Enabled &&
                    !disconnectedControls.OfType<CheckBox>().Single(control => control.Text == "&Live").Enabled,
                    "Disconnected startup offers database actions.");
                var inspector = disconnectedControls.OfType<PropertyInspector>().First();
                inspector.Grid.ContextMenuStrip!.Show(inspector.Grid, new Point(5, 5));
                Require(!inspector.Grid.ContextMenuStrip.Visible, "An empty inspector offers clipboard actions.");
                for (var index = 0; index < 7; ++index)
                {
                    Descendants(disconnected).OfType<TabControl>().Single(tabControl => tabControl.AccessibleName == "Workspace views").SelectedIndex = index;
                    Capture(disconnected, $"disconnected-tab-{index}", output, frames);
                }
                disconnected.Close();
                if (frames.Any(frame => frame.Issues.Count > 0))
                    exit = 1;
            }
            catch (Exception error)
            {
                exit = 1;
                File.WriteAllText(Path.Combine(output, "failure.txt"), error.ToString());
            }
            finally
            {
                File.WriteAllText(Path.Combine(output, "layout.json"), JsonSerializer.Serialize(new
                {
                    frames = frames.Count, issues = frames.Sum(frame => frame.Issues.Count), layouts = frames
                }, new JsonSerializerOptions { WriteIndented = true }));
                window.Close();
            }
        };
        Application.Run(window);
        return exit;
    }

    private static void ApplyTheme(MainForm window, string theme)
    {
        // Use the visible options workflow so handle recreation and native dark-mode rendering are exercised.
        using var automation = new System.Windows.Forms.Timer { Interval = 20 };
        automation.Tick += (_, _) =>
        {
            var dialog = Application.OpenForms.OfType<SettingsDialog>().FirstOrDefault();
            if (dialog is null)
                return;
            automation.Stop();
            var controls = Descendants(dialog).ToList();
            controls.OfType<ComboBox>().Single().SelectedItem = theme;
            controls.OfType<CheckBox>().Single().Checked = false;
            controls.OfType<Button>().Single(control => control.Text == "&Apply").PerformClick();
        };
        automation.Start();
        Descendants(window).OfType<Button>().Single(control => control.Text == "&Options…").PerformClick();
    }

    private static void Capture(Form form, string name, string output, List<Frame> frames)
    {
        form.PerformLayout();
        var controls = Descendants(form).Where(control => control.Visible && control is not Form).ToList();
        var issues = new List<string>();

        // Check visible access keys and native keyboard navigation through the dialog's action row.
        var keys = new HashSet<char>();
        foreach (var control in controls.Where(control => control.Enabled &&
            (control is ButtonBase button && button.UseMnemonic || control is Label label && label.UseMnemonic)))
        {
            var index = control.Text.IndexOf('&');
            if (index >= 0 && index < control.Text.Length - 1 &&
                !keys.Add(char.ToUpperInvariant(control.Text[index + 1])))
                issues.Add($"Duplicate access key: {control.Text}");
        }
        var actions = controls.OfType<FlowLayoutPanel>().SingleOrDefault(panel => panel.Controls.OfType<Button>()
            .Any(button => button.DialogResult == DialogResult.Cancel));
        if (actions is not null)
        {
            var ordered = actions.Controls.OfType<Button>().Where(button => button.Visible && button.Enabled)
                .OrderBy(button => button.Left).ToArray();
            for (var index = 0; index < ordered.Length - 1; ++index)
            {
                ordered[index].Select();
                if (!actions.SelectNextControl(ordered[index], true, true, false, false) ||
                    !ordered[index + 1].Focused)
                    issues.Add("Dialog actions are not navigable from left to right.");
            }
        }

        // Check input bounds, complete command labels, and label/input alignment at each actual text scale.
        foreach (var control in controls.Where(control => control is Button or TextBox or ComboBox or CheckBox or
            NumericUpDown || control is Label && control.Parent is TableLayoutPanel or FlowLayoutPanel))
        {
            var bounds = form.RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
            if (!form.ClientRectangle.Contains(bounds) || !control.Parent!.ClientRectangle.Contains(control.Bounds))
                issues.Add($"Clipped {control.GetType().Name}: {control.Text}");
            if (control is Button && control.ClientSize.Width < TextRenderer.MeasureText(control.Text, control.Font,
                Size.Empty, TextFormatFlags.SingleLine).Width + control.Padding.Horizontal + 4)
                issues.Add($"Command label too narrow: {control.Text}");
            if (control is CommandButton { Enabled: true, Text.Length: > 0 } button)
            {
                // Check painted text through startup and theme changes, including cached native button renderers.
                using var buttonImage = new Bitmap(button.Width, button.Height);
                button.DrawToBitmap(buttonImage, button.ClientRectangle);
                var ink = button.ForeColor.ToArgb();
                var visible = false;
                for (var y = 3; y < buttonImage.Height - 3 && !visible; ++y)
                    for (var x = 3; x < buttonImage.Width - 3 && !visible; ++x)
                        visible = buttonImage.GetPixel(x, y).ToArgb() == ink;
                if (!visible)
                    issues.Add($"Command label does not use its theme color: {button.Text}");
            }
            if (control is ComboBox combo && combo.Items.Count > 0 && combo.ClientSize.Width <
                combo.Items.Cast<object>().Max(item => TextRenderer.MeasureText(item.ToString(), combo.Font).Width) +
                SystemInformation.VerticalScrollBarWidth + 6)
                issues.Add($"Choice label too narrow: {combo.AccessibleName ?? combo.Text}");
            if (control is Label label && !label.AutoEllipsis && label.PreferredHeight > label.ClientSize.Height)
                issues.Add($"Label height too small: {label.Text}");
        }
        foreach (var table in controls.OfType<TableLayoutPanel>())
        {
            var children = table.Controls.Cast<Control>().Where(control => control.Visible).ToList();
            foreach (var label in children.OfType<Label>().Where(label => label.Text.Length > 0 &&
                table.GetColumnSpan(label) == 1))
            {
                var input = children.FirstOrDefault(control => table.GetRow(control) == table.GetRow(label) &&
                    table.GetColumn(control) == table.GetColumn(label) + 1 &&
                    control is TextBox or ComboBox or NumericUpDown);
                if (input is not null && Math.Abs(label.Top + label.Height / 2 - input.Top - input.Height / 2) > 3)
                    issues.Add($"Label/input vertical alignment: {label.Text}");
            }
        }
        frames.Add(new(name, form.DeviceDpi, form.Font.SizeInPoints, form.ClientSize, issues,
            controls.Where(control => control is Button or Label or TextBox or ComboBox or NumericUpDown or CheckBox)
                .Select(control => (object)new
                {
                    type = control.GetType().Name, control.Name, control.Text, control.AccessibleName,
                    control.TabIndex, control.TabStop, control.Bounds, preferred = control.PreferredSize,
                    font_points = control.Font.SizeInPoints, control.DeviceDpi
                }).ToArray()));
        using var bitmap = new Bitmap(form.Width, form.Height);
        form.DrawToBitmap(bitmap, new Rectangle(0, 0, bitmap.Width, bitmap.Height));
        bitmap.Save(Path.Combine(output, name + ".png"), System.Drawing.Imaging.ImageFormat.Png);
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
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
            if (watch.Elapsed > TimeSpan.FromSeconds(10))
                throw new TimeoutException("The view did not load during the layout audit.");
            await Task.Delay(20);
        }
    }
}
