using System.ComponentModel;
using System.Drawing.Drawing2D;

namespace Cipherazzi.Viewer;

internal sealed class MetricChart : Control
{
    private readonly ToolTip tooltip = new();
    private readonly List<(Rectangle Bounds, string Name, string Detail)> hits = [];
    private string hovered = "";
    private int selectedBar;
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    internal string Heading { get; set; } = "";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    internal List<AggregateRow> Bars { get; set; } = [];
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    internal List<TimelinePoint> Timeline { get; set; } = [];
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    internal bool TimeSeries { get; set; }
    public event Action<string>? ValueSelected;

    public MetricChart()
    {
        DoubleBuffered = true;
        Dock = DockStyle.Fill;
        Margin = new Padding(3);
        MinimumSize = new Size(220, 140);
        AccessibleRole = AccessibleRole.Chart;
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
        MouseMove += (_, e) =>
        {
            var hit = hits.Where(item => item.Bounds.Contains(e.Location))
                .OrderBy(item => Math.Abs(e.X - item.Bounds.Left - item.Bounds.Width / 2)).FirstOrDefault();
            if (hit.Detail == hovered)
                return;
            hovered = hit.Detail ?? "";
            tooltip.SetToolTip(this, hovered);
            Cursor = !TimeSeries && hit.Name is { Length: > 0 } ? Cursors.Hand : Cursors.Default;
        };
        MouseClick += (_, e) =>
        {
            var hit = hits.FirstOrDefault(item => item.Bounds.Contains(e.Location));
            if (!TimeSeries && hit.Name is { Length: > 0 } && hit.Name != "Not observed")
            {
                Focus();
                selectedBar = hits.FindIndex(item => item.Name == hit.Name);
                ValueSelected?.Invoke(hit.Name);
            }
        };
    }

    protected override bool IsInputKey(Keys keyData) => (keyData & Keys.KeyCode) is Keys.Up or Keys.Down or
        Keys.Home or Keys.End || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (TimeSeries || hits.Count == 0)
            return;

        // Offer the same category drilldown through the keyboard as through chart clicks.
        selectedBar = Math.Clamp(selectedBar, 0, hits.Count - 1);
        switch (e.KeyCode)
        {
            case Keys.Up: selectedBar = Math.Max(0, selectedBar - 1); break;
            case Keys.Down: selectedBar = Math.Min(hits.Count - 1, selectedBar + 1); break;
            case Keys.Home: selectedBar = 0; break;
            case Keys.End: selectedBar = hits.Count - 1; break;
            case Keys.Enter:
                if (hits[selectedBar].Name is { Length: > 0 } name && name != "Not observed")
                    ValueSelected?.Invoke(name);
                break;
            default: return;
        }
        e.Handled = e.SuppressKeyPress = true;
        AccessibleDescription = hits[selectedBar].Detail;
        Invalidate();
    }

    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var graphics = e.Graphics;
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        graphics.Clear(UiTheme.Surface);
        AccessibleName = Heading;
        hits.Clear();
        var scale = DeviceDpi / 96f;
        var pad = (int)(8 * scale);
        using var border = new Pen(UiTheme.Border);
        graphics.DrawRectangle(border, 0, 0, Width - 1, Height - 1);
        using var bold = new Font(Font, FontStyle.Bold);
        TextRenderer.DrawText(graphics, Heading, bold, new Rectangle(pad, pad, Width - pad * 2, Font.Height + 6),
            UiTheme.Foreground, TextFormatFlags.EndEllipsis);
        var area = new Rectangle(pad, pad * 2 + Font.Height, Width - pad * 2, Height - pad * 3 - Font.Height);
        if ((TimeSeries ? Timeline.Count : Bars.Count) == 0)
        {
            TextRenderer.DrawText(graphics, "No observations in this scope", Font, area, UiTheme.Muted,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak);
            return;
        }
        if (TimeSeries)
        {
            var max = Math.Max(1, Timeline.Max(point => point.Count));
            var first = Timeline[0].TimestampUs;
            var span = Math.Max(1, Timeline[^1].TimestampUs - first);
            var axisWidth = TextRenderer.MeasureText(max.ToString("N0"), Font).Width + (int)(12 * scale);
            var plot = new Rectangle(area.Left + axisWidth, area.Top + 6,
                Math.Max(10, area.Width - axisWidth - 10),
                Math.Max(10, area.Height - Font.Height * 2));
            var intervals = (int)Math.Min(max, Math.Clamp(plot.Height / (Font.Height + (int)(6 * scale)), 1, 3));
            var step = Math.Ceiling(max / (double)intervals);
            var axisMaximum = step * intervals;
            for (var line = 0; line <= intervals; ++line)
            {
                var y = plot.Bottom - plot.Height * line / intervals;
                graphics.DrawLine(border, plot.Left, y, plot.Right, y);
                TextRenderer.DrawText(graphics, (step * line).ToString("N0"), Font,
                    new Rectangle(area.Left, y - Font.Height / 2, axisWidth - 8, Font.Height), UiTheme.Muted,
                    TextFormatFlags.Right | TextFormatFlags.EndEllipsis);
            }
            var points = Timeline.Select(point => new PointF(
                plot.Left + (float)((point.TimestampUs - first) / (double)span) * plot.Width,
                plot.Bottom - (float)(point.Count / axisMaximum) * plot.Height)).ToArray();
            using var pen = new Pen(UiTheme.Accent, 2.5f * scale);
            if (points.Length > 1)
                graphics.DrawLines(pen, points);
            using var dot = new SolidBrush(UiTheme.Accent);
            for (var index = 0; index < points.Length; ++index)
            {
                var point = points[index];
                graphics.FillEllipse(dot, point.X - 3, point.Y - 3, 6, 6);
                var time = DateTimeOffset.FromUnixTimeMilliseconds(Timeline[index].TimestampUs / 1000).ToLocalTime();
                hits.Add((new((int)point.X - 8, plot.Top, 16, plot.Height), "",
                    $"{time:yyyy-MM-dd HH:mm:ss}: {Timeline[index].Count:N0} observations"));
            }
            var format = span < 3600000000 ? "HH:mm:ss" : "MM-dd HH:mm";
            var start = DateTimeOffset.FromUnixTimeMilliseconds(first / 1000).ToLocalTime().ToString(format);
            var end = DateTimeOffset.FromUnixTimeMilliseconds(Timeline[^1].TimestampUs / 1000)
                .ToLocalTime().ToString(format);
            TextRenderer.DrawText(graphics, start, Font, new Rectangle(plot.Left, plot.Bottom + 5,
                plot.Width / 2, Font.Height), UiTheme.Muted, TextFormatFlags.EndEllipsis);
            TextRenderer.DrawText(graphics, end, Font, new Rectangle(plot.Left + plot.Width / 2,
                plot.Bottom + 5, plot.Width / 2, Font.Height), UiTheme.Muted,
                TextFormatFlags.Right | TextFormatFlags.EndEllipsis);
            return;
        }
        var rowHeight = Font.Height + (int)(6 * scale);
        var maximumRows = Math.Max(1, area.Height / rowHeight);
        if (Bars.Count > maximumRows)
        {
            // Reserve a visible count when the panel cannot display every requested category.
            area.Height = Math.Max(rowHeight, area.Height - Font.Height - (int)(6 * scale));
            maximumRows = Math.Max(1, area.Height / rowHeight);
            TextRenderer.DrawText(graphics, $"{maximumRows:N0}/{Bars.Count:N0} categories shown", Font,
                new Rectangle(area.Left, area.Bottom + (int)(4 * scale), area.Width, Font.Height), UiTheme.Muted,
                TextFormatFlags.EndEllipsis);
        }
        var bars = Bars.Take(maximumRows).ToList();
        var largest = Math.Max(1, bars.Max(row => row.Count));
        var labelWidth = Math.Min((int)(230 * scale), area.Width * 52 / 100);
        var countWidth = Math.Max((int)(62 * scale), TextRenderer.MeasureText(largest.ToString("N0"), Font).Width + 8);
        foreach (var (row, index) in bars.Select((row, index) => (row, index)))
        {
            var y = area.Top + index * rowHeight;
            TextRenderer.DrawText(graphics, row.Name, Font,
                new Rectangle(area.Left, y, labelWidth - 8, rowHeight), UiTheme.Foreground,
                TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter);
            var width = Math.Max(2, (int)((area.Width - labelWidth - countWidth) * row.Count / (double)largest));
            using var fill = new SolidBrush(UiTheme.Accent);
            var barPadding = (int)(3 * scale);
            graphics.FillRectangle(fill, area.Left + labelWidth, y + barPadding, width, rowHeight - barPadding * 2);
            TextRenderer.DrawText(graphics, row.Count.ToString("N0"), Font,
                new Rectangle(area.Right - countWidth, y, countWidth, rowHeight), UiTheme.Muted,
                TextFormatFlags.Right | TextFormatFlags.VerticalCenter);
            hits.Add((new(area.Left, y, area.Width, rowHeight), row.Name,
                $"{row.Name}: {row.Count:N0} observations"));
            if (Focused && index == Math.Clamp(selectedBar, 0, bars.Count - 1))
                ControlPaint.DrawFocusRectangle(graphics, hits[^1].Bounds, UiTheme.Foreground, UiTheme.Surface);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            tooltip.Dispose();
        base.Dispose(disposing);
    }
}
