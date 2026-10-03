using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Cipherazzi.Viewer;

internal class CommandButton : Button
{
    public CommandButton()
    {
        AutoSizeMode = AutoSizeMode.GrowAndShrink;

        // Initialize custom colors before the button inherits its parent's palette.
        BackColor = UiTheme.Surface;
        ForeColor = UiTheme.Foreground;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        if (Enabled || !UiTheme.Dark)
            return;

        // Retain a legible disabled label when the native flat button uses a light-theme text color.
        var bounds = ClientRectangle;
        bounds.Inflate(-2, -2);
        using var surface = new SolidBrush(BackColor);
        e.Graphics.FillRectangle(surface, bounds);
        var flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis;
        if (!ShowKeyboardCues)
            flags |= TextFormatFlags.HidePrefix;
        TextRenderer.DrawText(e.Graphics, Text, Font, bounds, UiTheme.Muted, flags);
    }
}

internal sealed class InputTextBox : TextBox
{
    public InputTextBox()
    {
        AutoSize = false;
        Height = PreferredHeight;
    }

    protected override void OnFontChanged(EventArgs e)
    {
        base.OnFontChanged(e);

        // Keep the height used by table layouts synchronized with the native edit control.
        Height = PreferredHeight;
    }

    protected override void OnDpiChangedAfterParent(EventArgs e)
    {
        base.OnDpiChangedAfterParent(e);
        Height = PreferredHeight;
    }
}

internal sealed class ChoiceBox : ComboBox
{
    public ChoiceBox()
    {
        DrawMode = DrawMode.OwnerDrawFixed;
        FlatStyle = FlatStyle.Flat;
    }

    public override Size GetPreferredSize(Size proposedSize)
    {
        // Include the drawn item's padding in the row height measured by native layouts.
        var size = base.GetPreferredSize(proposedSize);
        size.Height = PreferredHeight + Math.Max(0, ItemHeight - Font.Height);
        return size;
    }

    protected override void OnFontChanged(EventArgs e)
    {
        base.OnFontChanged(e);
        ItemHeight = Font.Height + 4 * DeviceDpi / 96;
    }

    protected override void OnDpiChangedAfterParent(EventArgs e)
    {
        base.OnDpiChangedAfterParent(e);
        ItemHeight = Font.Height + 4 * DeviceDpi / 96;
    }

    protected override void OnDrawItem(DrawItemEventArgs e)
    {
        // Paint both the selected value and dropdown items with the active palette.
        var selected = (e.State & DrawItemState.Selected) != 0 &&
            (e.State & DrawItemState.ComboBoxEdit) == 0;
        using var fill = new SolidBrush(selected ? UiTheme.Selection : UiTheme.Surface);
        e.Graphics.FillRectangle(fill, e.Bounds);
        var bounds = e.Bounds;
        bounds.Inflate(-3 * DeviceDpi / 96, 0);
        TextRenderer.DrawText(e.Graphics, e.Index >= 0 ? GetItemText(Items[e.Index]) : Text, Font, bounds,
            !Enabled ? UiTheme.Muted : selected && SystemInformation.HighContrast ? SystemColors.HighlightText :
                UiTheme.Foreground,
            TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        e.DrawFocusRectangle();
    }
}

internal sealed class WorkspaceTabs : TabControl
{
    public WorkspaceTabs()
    {
        // Keep native tab navigation and accessibility while painting a consistent workspace surface.
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
            ControlStyles.OptimizedDoubleBuffer, true);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        e.Graphics.Clear(UiTheme.Canvas);
        for (var index = 0; index < TabCount; ++index)
        {
            var bounds = GetTabRect(index);
            var selected = SelectedIndex == index;
            using var fill = new SolidBrush(selected ? UiTheme.Surface : UiTheme.Canvas);
            e.Graphics.FillRectangle(fill, bounds);
            var text = bounds;
            text.Inflate(-4, -2);
            TextRenderer.DrawText(e.Graphics, TabPages[index].Text, Font, text, UiTheme.Foreground,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
            if (selected)
            {
                using var accent = new Pen(UiTheme.Accent, 2 * DeviceDpi / 96f);
                e.Graphics.DrawLine(accent, bounds.Left + 3, bounds.Bottom - 2, bounds.Right - 3, bounds.Bottom - 2);
                if (Focused)
                    ControlPaint.DrawFocusRectangle(e.Graphics, text, UiTheme.Foreground, UiTheme.Surface);
            }
        }
    }
}

internal sealed class EmptyState : UserControl
{
    private readonly Label heading = new() { AutoSize = true, Anchor = AnchorStyles.None, UseMnemonic = false };
    private readonly Label message = new() { AutoSize = true, Anchor = AnchorStyles.None,
        TextAlign = ContentAlignment.TopCenter, UseMnemonic = false };
    private readonly CommandButton action = new() { AutoSize = true, Anchor = AnchorStyles.None, Visible = false };
    private Action? requested;
    private Font? headingFont;
    private Font? measuredFont;

    public EmptyState()
    {
        Dock = DockStyle.Fill;
        var content = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5 };
        content.ColumnStyles.Add(new(SizeType.Percent, 100));
        content.RowStyles.Add(new(SizeType.Percent, 50));
        content.RowStyles.Add(new(SizeType.AutoSize));
        content.RowStyles.Add(new(SizeType.AutoSize));
        content.RowStyles.Add(new(SizeType.AutoSize));
        content.RowStyles.Add(new(SizeType.Percent, 50));
        heading.Margin = new Padding(12, 6, 12, 6);
        message.Margin = new Padding(12, 0, 12, 8);
        action.Margin = new Padding(12, 0, 12, 6);
        content.Controls.Add(heading, 0, 1);
        content.Controls.Add(message, 0, 2);
        content.Controls.Add(action, 0, 3);
        Controls.Add(content);
        action.Click += (_, _) => requested?.Invoke();
        FontChanged += (_, _) => UpdateMetrics();
        SizeChanged += (_, _) => UpdateMetrics();
        DpiChangedAfterParent += (_, _) => UpdateMetrics();
        UpdateMetrics();
    }

    public void Set(string title, string explanation, string actionText = "", Action? callback = null)
    {
        heading.Text = title;
        message.Text = explanation;
        requested = callback;
        action.Text = actionText;
        action.Visible = callback is not null && actionText.Length > 0;
        AccessibleName = title;
        AccessibleDescription = explanation;
    }

    private void UpdateMetrics()
    {
        if (!Equals(measuredFont, Font))
        {
            var old = headingFont;
            measuredFont = Font;
            headingFont = new Font(Font, Font.Style | FontStyle.Bold);
            heading.Font = headingFont;
            old?.Dispose();
        }
        var width = Math.Max(1, Math.Min(Width - 32 * DeviceDpi / 96, 520 * DeviceDpi / 96));
        heading.MaximumSize = message.MaximumSize = new Size(width, 0);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            headingFont?.Dispose();
        base.Dispose(disposing);
    }
}

internal sealed class EvidenceCard : TableLayoutPanel
{
    private readonly Label heading = new() { AutoSize = true, Dock = DockStyle.Fill, UseMnemonic = false };
    private readonly Label value = new() { AutoSize = true, Dock = DockStyle.Fill, UseMnemonic = false };
    private readonly Label evidence = new() { AutoSize = true, Dock = DockStyle.Fill, UseMnemonic = false };
    private Font? headingFont;
    private Font? measuredFont;

    public EvidenceCard(string title)
    {
        Dock = DockStyle.Fill;
        AutoSize = true;
        ColumnCount = 1;
        RowCount = 3;
        Padding = new Padding(8, 6, 8, 6);
        Margin = new Padding(3, 3, 3, 6);
        ColumnStyles.Add(new(SizeType.Percent, 100));
        for (var index = 0; index < 3; ++index)
            RowStyles.Add(new(SizeType.AutoSize));
        heading.Text = title;
        Controls.Add(heading, 0, 0);
        Controls.Add(value, 0, 1);
        Controls.Add(evidence, 0, 2);
        FontChanged += (_, _) => UpdateMetrics();
        SizeChanged += (_, _) => UpdateMetrics();
        UpdateMetrics();
    }

    public void Set(string result, string coverage)
    {
        value.Text = result;
        evidence.Text = coverage;
        AccessibleName = heading.Text;
        AccessibleDescription = result + ". " + coverage;
    }

    private void UpdateMetrics()
    {
        if (!Equals(measuredFont, Font))
        {
            var old = headingFont;
            measuredFont = Font;
            headingFont = new Font(Font, Font.Style | FontStyle.Bold);
            heading.Font = headingFont;
            old?.Dispose();
        }
        var width = Math.Max(1, Width - Padding.Horizontal - 6);
        foreach (var label in new[] { heading, value, evidence })
            label.MaximumSize = new Size(width, 0);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            headingFont?.Dispose();
        base.Dispose(disposing);
    }
}

internal static class UiTheme
{
    public static bool Dark { get; private set; }
    public static Color Canvas => SystemInformation.HighContrast ? SystemColors.Control :
        Dark ? Color.FromArgb(20, 25, 34) : Color.FromArgb(245, 247, 250);
    public static Color Surface => SystemInformation.HighContrast ? SystemColors.Window :
        Dark ? Color.FromArgb(28, 35, 46) : Color.White;
    public static Color Foreground => SystemInformation.HighContrast ? SystemColors.WindowText :
        Dark ? Color.FromArgb(226, 232, 240) : Color.FromArgb(28, 42, 60);
    public static Color Muted => SystemInformation.HighContrast ? SystemColors.WindowText :
        Dark ? Color.FromArgb(161, 174, 194) : Color.FromArgb(87, 104, 124);
    public static Color Border => SystemInformation.HighContrast ? SystemColors.WindowText :
        Dark ? Color.FromArgb(56, 68, 85) : Color.FromArgb(222, 229, 237);
    public static Color Accent => SystemInformation.HighContrast ? SystemColors.Highlight :
        Dark ? Color.FromArgb(99, 179, 255) : Color.FromArgb(30, 105, 190);
    public static Color Selection => SystemInformation.HighContrast ? SystemColors.Highlight :
        Dark ? Color.FromArgb(39, 69, 104) : Color.FromArgb(218, 235, 254);
    public static Color Error => Dark ? Color.FromArgb(255, 160, 152) : Color.Firebrick;

    public static void Select(string theme)
    {
        var systemDark = Registry.GetValue(
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "AppsUseLightTheme", 1) is int value && value == 0;
        Dark = !SystemInformation.HighContrast && (theme == "Dark" || theme == "System" && systemDark);
        Application.SetColorMode(Dark ? SystemColorMode.Dark : SystemColorMode.Classic);
    }

    public static void Apply(Control root, string? theme = null)
    {
        if (theme is not null)
            Select(theme);
        root.SuspendLayout();
        root.BackColor = root is TextBoxBase or ListBox or ComboBox or NumericUpDown or EvidenceCard ||
            root.Parent is EvidenceCard ? Surface : Canvas;
        root.ForeColor = Foreground;
        if (root is Button button)
        {
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderColor = Border;
            button.BackColor = Surface;
            var spacing = button.DeviceDpi / 96f;
            button.Padding = new Padding((int)(4 * spacing), (int)spacing, (int)(4 * spacing), (int)spacing);
        }
        if (root is DataGridView grid)
        {
            grid.BackgroundColor = Surface;
            grid.GridColor = Border;
            grid.EnableHeadersVisualStyles = false;
            grid.DefaultCellStyle.BackColor = Surface;
            grid.DefaultCellStyle.ForeColor = Foreground;
            grid.DefaultCellStyle.SelectionBackColor = Selection;
            grid.DefaultCellStyle.SelectionForeColor = SystemInformation.HighContrast ?
                SystemColors.HighlightText : Foreground;
            grid.AlternatingRowsDefaultCellStyle.BackColor = SystemInformation.HighContrast ? Surface :
                Dark ? Color.FromArgb(31, 39, 51) :
                Color.FromArgb(248, 250, 253);
            grid.ColumnHeadersDefaultCellStyle.BackColor = SystemInformation.HighContrast ? Canvas :
                Dark ? Color.FromArgb(36, 46, 61) :
                Color.FromArgb(234, 239, 246);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Foreground;
            grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = grid.ColumnHeadersDefaultCellStyle.BackColor;
        }
        if (root is PropertyGrid properties)
        {
            properties.ViewBackColor = Surface;
            properties.ViewForeColor = Foreground;
            properties.HelpBackColor = Surface;
            properties.HelpForeColor = Foreground;
            properties.CategoryForeColor = Accent;
            properties.CategorySplitterColor = Border;
            properties.LineColor = Border;
            properties.CommandsBackColor = Surface;
            properties.CommandsForeColor = Foreground;
            properties.SelectedItemWithFocusBackColor = Selection;
            properties.SelectedItemWithFocusForeColor = SystemInformation.HighContrast ? SystemColors.HighlightText :
                Foreground;
        }
        foreach (Control child in root.Controls)
            Apply(child);
        if (root is Form form)
        {
            void Caption()
            {
                var dark = Dark ? 1 : 0;
                DwmSetWindowAttribute(form.Handle, 20, ref dark, sizeof(int));
            }
            if (form.IsHandleCreated)
                Caption();
            else
                form.HandleCreated += (_, _) => Caption();
        }
        root.ResumeLayout();
        root.Invalidate();
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(nint window, int attribute, ref int value, int size);
}
