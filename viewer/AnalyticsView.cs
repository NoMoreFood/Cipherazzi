using System.Globalization;
using System.Text;

namespace Cipherazzi.Viewer;

internal sealed class AnalyticsView : UserControl
{
    private readonly ViewerSettings settings;
    private readonly ChoiceBox window = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = true };
    private readonly Label timeLabel = new() { Text = "&Time range", AutoSize = true, Anchor = AnchorStyles.Left };
    private readonly ChoiceBox dimension = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = true };
    private readonly Label scope = new() { Dock = DockStyle.Fill, AutoSize = true,
        TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(3, 3, 3, 0), UseMnemonic = false };
    private readonly Label summary = new() { Dock = DockStyle.Fill, AutoSize = true,
        TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(3, 4, 3, 6), UseMnemonic = false };
    private readonly MetricChart timeline = new() { Heading = "Observations over time", TimeSeries = true };
    private readonly MetricChart protocols = new() { Heading = "Observed protocols" };
    private readonly MetricChart groups = new() { Heading = "Key-exchange groups" };
    private readonly MetricChart distribution = new() { Heading = "Distribution" };
    private readonly ResultGrid grid = new() { Name = "AnalyticsGrid" };
    private readonly EmptyState empty = new();
    private readonly CommandButton export = new()
    {
        Text = "&Export CSV…", AutoSize = true, Enabled = false, Visible = false
    };
    private CancellationTokenSource? cancellation;
    private DateTime updated;
    private string context = "";
    private int generation;
    private bool loading;
    private AnalyticsSnapshot? snapshot;
    public event Action? RefreshRequested;
    public event Action<string>? FilterRequested;
    public event Action? ConnectRequested;
    public event Action? ClearFiltersRequested;

    public AnalyticsView(ViewerSettings settings, bool visual)
    {
        this.settings = settings;
        Dock = DockStyle.Fill;
        Padding = new Padding(3);
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, RowCount = 4, ColumnCount = 1, Margin = Padding.Empty
        };
        root.ColumnStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.RowStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        var tools = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 6 };
        tools.ColumnStyles.Add(new(SizeType.AutoSize));
        tools.ColumnStyles.Add(new(SizeType.AutoSize));
        tools.ColumnStyles.Add(new(SizeType.AutoSize));
        tools.ColumnStyles.Add(new(SizeType.AutoSize));
        tools.ColumnStyles.Add(new(SizeType.Percent, 100));
        tools.ColumnStyles.Add(new(SizeType.AutoSize));
        tools.Controls.Add(timeLabel, 0, 0);
        window.Items.AddRange(["Last 15 minutes", "Last hour", "Last 24 hours", "All observations"]);
        window.SelectedIndex = settings.AnalyticsMinutes switch { 15 => 0, 60 => 1, 1440 => 2, _ => 3 };
        if (settings.AnalyticsMinutes is not (0 or 15 or 60 or 1440))
        {
            window.Items.Add($"Last {settings.AnalyticsMinutes:N0} minutes");
            window.SelectedIndex = 4;
        }
        window.AccessibleName = "Analytics time window";
        window.Width = 175;
        dimension.Items.AddRange(Insights.Dimensions.Keys.Cast<object>().ToArray());
        dimension.SelectedItem = "Server name";
        dimension.AccessibleName = "Analytics grouping";
        tools.Controls.Add(window, 1, 0);
        window.Anchor = AnchorStyles.Left;
        tools.Controls.Add(new Label { Text = "&Group by", AutoSize = true, Anchor = AnchorStyles.Left,
            Margin = new Padding(8, 3, 3, 3) }, 2, 0);
        tools.Controls.Add(dimension, 3, 0);
        dimension.Anchor = AnchorStyles.Left;
        tools.Controls.Add(export, 5, 0);
        root.Controls.Add(tools, 0, 0);
        summary.Text = "No database connected.";
        root.Controls.Add(summary, 0, 1);
        root.Controls.Add(scope, 0, 3);
        var content = new Panel { Dock = DockStyle.Fill };
        root.Controls.Add(content, 0, 2);
        if (visual)
        {
            var charts = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
            charts.ColumnStyles.Add(new(SizeType.Percent, 50));
            charts.ColumnStyles.Add(new(SizeType.Percent, 50));
            charts.RowStyles.Add(new(SizeType.Percent, 45));
            charts.RowStyles.Add(new(SizeType.Percent, 55));
            charts.Controls.Add(timeline, 0, 0);
            charts.Controls.Add(protocols, 1, 0);
            charts.Controls.Add(groups, 0, 1);
            charts.Controls.Add(distribution, 1, 1);
            content.Controls.Add(charts);
        }
        else
        {
            ConfigureGrid(grid);
            foreach (var (name, caption, width, type) in new[]
            {
                ("Name", "Value", 330, typeof(string)), ("Count", "Observations", 100, typeof(long)),
                ("Percent", "Share (%)", 90, typeof(double)), ("Mean", "Mean hello (ms)", 145, typeof(double)),
                ("Maximum", "Max hello (ms)", 145, typeof(double))
            })
            {
                grid.Columns.Add(new DataGridViewTextBoxColumn { Name = name, HeaderText = caption, Width = width,
                    ValueType = type, SortMode = DataGridViewColumnSortMode.Automatic });
                if (type != typeof(string))
                {
                    grid.Columns[name]!.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
                    grid.Columns[name]!.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleRight;
                }
                if (type == typeof(double))
                    grid.Columns[name]!.DefaultCellStyle.Format = "N2";
                if (type == typeof(long))
                    grid.Columns[name]!.DefaultCellStyle.Format = "N0";
                if (name is "Mean" or "Maximum")
                    grid.Columns[name]!.ToolTipText =
                        "Observed complete ClientHello to ServerHello interval; excludes handshake completion.";
            }
            grid.CellDoubleClick += (_, e) =>
            {
                if (e.RowIndex >= 0 && grid.Rows[e.RowIndex].Cells[0].Value is string value && value != "Not observed")
                    FilterRequested?.Invoke(value);
            };
            content.Controls.Add(grid);
        }
        content.Controls.Add(empty);
        empty.BringToFront();
        empty.Set("Explore captured traffic", "Connect to a capture journal to inspect protocols and algorithms.",
            "Connect…", () => ConnectRequested?.Invoke());
        Controls.Add(root);
        foreach (var chart in new[] { protocols, groups, distribution })
            chart.ValueSelected += value => FilterRequested?.Invoke(value);
        window.SelectedIndexChanged += (_, _) => RefreshRequested?.Invoke();
        dimension.SelectedIndexChanged += (_, _) => RefreshRequested?.Invoke();
        export.Click += (_, _) => Export();

        // Size fixed-choice controls for their complete labels at the current text scale.
        void UpdateTextMetrics()
        {
            var padding = 32 * DeviceDpi / 96;
            window.MinimumSize = new Size(window.Items.Cast<string>()
                .Max(value => TextRenderer.MeasureText(value, Font).Width) + padding, 0);
            dimension.MinimumSize = new Size(dimension.Items.Cast<string>()
                .Max(value => TextRenderer.MeasureText(value, Font).Width) + padding, 0);
            window.Width = window.MinimumSize.Width;
            dimension.Width = dimension.MinimumSize.Width;
        }
        FontChanged += (_, _) => UpdateTextMetrics();
        DpiChangedAfterParent += (_, _) => UpdateTextMetrics();
        UpdateTextMetrics();
    }

    internal static void ConfigureGrid(DataGridView grid)
    {
        grid.Dock = DockStyle.Fill;
        grid.ReadOnly = true;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.AllowUserToResizeRows = false;
        grid.RowHeadersVisible = false;
        grid.MultiSelect = false;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.BorderStyle = BorderStyle.None;
        grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        grid.ColumnHeadersDefaultCellStyle.WrapMode = DataGridViewTriState.False;
        grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        // Keep compact rows readable when Windows text size or monitor DPI changes.
        void UpdateMetrics()
        {
            var spacing = Math.Max(1, grid.DeviceDpi / 96f);
            grid.ColumnHeadersHeight = grid.Font.Height + (int)(6 * spacing);
            grid.RowTemplate.Height = grid.Font.Height + (int)(4 * spacing);
            foreach (DataGridViewRow row in grid.Rows)
                row.Height = grid.RowTemplate.Height;
            foreach (DataGridViewColumn column in grid.Columns)
                column.MinimumWidth = TextRenderer.MeasureText(column.HeaderText, grid.Font).Width +
                    (int)((column.SortMode == DataGridViewColumnSortMode.Automatic ? 28 : 12) * spacing);
        }
        grid.FontChanged += (_, _) => UpdateMetrics();
        grid.DpiChangedAfterParent += (_, _) => UpdateMetrics();
        grid.ColumnAdded += (_, e) =>
        {
            e.Column.Width = e.Column.Width * grid.DeviceDpi / 96;
            UpdateMetrics();
        };
        UpdateMetrics();
    }

    public void Reset()
    {
        ++generation;
        cancellation?.Cancel();
        context = "";
        snapshot = null;
        updated = default;
        loading = false;
        export.Enabled = false;
        export.Visible = false;
        grid.Rows.Clear();
        timeline.Timeline = [];
        protocols.Bars = groups.Bars = distribution.Bars = [];
        scope.Text = "";
        summary.Text = "Loading analytics…";
        empty.Set("Loading analytics…", "Aggregating observations for the current filters and time range.");
        empty.Visible = true;
        Invalidate(true);
    }

    public void Pause()
    {
        ++generation;
        cancellation?.Cancel();
        loading = false;
        export.Enabled = snapshot?.Total > 0;
        export.Visible = snapshot?.Total > 0;
        scope.Text = "Viewer updates: paused";
    }

    public async Task RefreshAsync(DatabaseSource? source, Query query, bool force)
    {
        if (source is null || IsDisposed)
            return;
        window.Visible = timeLabel.Visible = !query.HasDateRange;
        var key = string.Join('\0', source.CacheKey, query.CacheKey,
            window.SelectedIndex, dimension.Text);
        if (context != key)
        {
            Reset();
            context = key;
        }
        if (!force && (loading || DateTime.UtcNow - updated < TimeSpan.FromSeconds(settings.AnalyticsRefreshSeconds)))
            return;
        cancellation?.Cancel();
        cancellation?.Dispose();
        cancellation = new();
        var token = cancellation.Token;
        var current = ++generation;
        loading = true;
        export.Enabled = false;
        scope.Text = "Aggregating filtered observations…";
        var minutes = window.SelectedIndex switch { 0 => 15, 1 => 60, 2 => 1440, 4 => settings.AnalyticsMinutes, _ => 0 };
        var since = minutes == 0 ? 0 : DateTimeOffset.UtcNow.AddMinutes(-minutes).ToUnixTimeMilliseconds() * 1000;
        var grouping = dimension.Text;
        try
        {
            var result = await Task.Run(() => Insights.ReadAnalytics(source, query, since, grouping,
                settings.TopGroups, token), token);
            if (IsDisposed || current != generation)
                return;
            snapshot = result;
            updated = DateTime.UtcNow;
            summary.Text = $"Observations: {result.Total:N0}  ·  TLS selections: {result.Selected:N0}  ·  " +
                $"Plaintext alerts: {result.Alerts:N0}  ·  Mean hello interval: " +
                (result.MeanHelloMs is { } mean ? $"{mean:N2} ms" : "Not observed");
            scope.Text = $"{(query.HasDateRange ? "Explicit dates" : window.Text)} · " +
                $"Top {settings.TopGroups} values · Refreshed {DateTime.Now:T}";
            timeline.Timeline = result.Timeline;
            protocols.Bars = result.Protocols;
            groups.Bars = result.Groups;
            distribution.Heading = grouping;
            distribution.Bars = result.Breakdown;
            grid.Rows.Clear();
            if (grid.Columns.Count != 0)
                foreach (var row in result.Breakdown)
                    grid.Rows.Add(row.Name, row.Count, result.Total == 0 ? 0 : row.Count * 100.0 / result.Total,
                        (object?)row.MeanHelloMs ?? DBNull.Value, (object?)row.MaximumHelloMs ?? DBNull.Value);
            export.Enabled = result.Total > 0;
            export.Visible = result.Total > 0;
            empty.Visible = result.Total == 0;
            empty.Set("No observations in this scope",
                "Widen the time range or clear the current search and protocol filters.",
                "Show all observations", () => { window.SelectedIndex = 3; ClearFiltersRequested?.Invoke(); });
            Invalidate(true);
        }
        catch (OperationCanceledException) {}
        catch (Exception error)
        {
            if (current == generation && !IsDisposed)
            {
                updated = DateTime.UtcNow;
                scope.Text = "Analytics unavailable; refresh to retry.";
                summary.Text = error.Message;
                empty.Set("Analytics unavailable", "Check the database connection and refresh to retry.",
                    "Refresh", () => RefreshRequested?.Invoke());
                empty.Visible = true;
            }
        }
        finally
        {
            if (current == generation)
                loading = false;
        }
    }

    private void Export()
    {
        if (snapshot is not { } data)
            return;
        using var dialog = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = "Cipherazzi-analytics.csv" };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        string Csv(string value)
        {
            if (value.Length > 0 && "=+-@\t\r".Contains(value[0]))
                value = "'" + value;
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
        try
        {
            using var writer = new StreamWriter(dialog.FileName, false, new UTF8Encoding(true));
            writer.WriteLine("Dimension,Value,Observations,Scope total,Mean hello ms,Maximum hello ms");
            foreach (var row in data.Breakdown)
                writer.WriteLine(string.Join(',', Csv(data.Dimension), Csv(row.Name), row.Count, data.Total,
                    row.MeanHelloMs?.ToString(CultureInfo.InvariantCulture) ?? "",
                    row.MaximumHelloMs?.ToString(CultureInfo.InvariantCulture) ?? ""));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, "The export could not be saved. " + error.Message, "Export analytics");
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            cancellation?.Cancel();
            cancellation?.Dispose();
            cancellation = null;
            foreach (var control in new Control[] { timeline, protocols, groups, distribution, grid })
                if (control.Parent is null)
                    control.Dispose();
        }
        base.Dispose(disposing);
    }
}
