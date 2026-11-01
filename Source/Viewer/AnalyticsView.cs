using System.Globalization;
using System.Text;

namespace Cipherazzi.Viewer;

internal sealed class AnalyticsView : InvestigationView
{
    private readonly ComboBox window;
    private readonly Label timeLabel = new() { Text = "&Time range", AutoSize = true, Anchor = AnchorStyles.Left };
    private readonly ChoiceBox dimension = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = true };
    private readonly Label summary = new()
    {
        Dock = DockStyle.Fill,
        AutoSize = true,
        TextAlign = ContentAlignment.MiddleLeft,
        Margin = new Padding(3, 4, 3, 6),
        UseMnemonic = false
    };
    private readonly MetricChart timeline = new() { Heading = "Observations over time", TimeSeries = true };
    private readonly MetricChart protocols = new() { Heading = "Observed protocols" };
    private readonly MetricChart groups = new() { Heading = "Key-exchange groups" };
    private readonly MetricChart distribution = new() { Heading = "Distribution" };
    private readonly ResultGrid grid = new() { Name = "AnalyticsGrid" };
    private readonly EmptyState empty = new();
    private readonly CommandButton export = new()
    {
        Text = "&Export CSV…",
        AutoSize = true,
        Enabled = false,
        Visible = false
    };
    private AnalyticsSnapshot? snapshot;
    private (int Minutes, bool Range, string Grouping, string Window) read;

    public AnalyticsView(ViewerSettings settings, bool visual) : base(settings)
    {
        Status.TextAlign = ContentAlignment.MiddleLeft;
        Status.Margin = new Padding(3, 3, 3, 0);
        Status.Text = "";
        window = WindowChoice();
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            RowCount = 4,
            ColumnCount = 1,
            Margin = Padding.Empty
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
        window.AccessibleName = "Analytics time window";
        dimension.Items.AddRange(Insights.Dimensions.Keys.Cast<object>().ToArray());
        dimension.SelectedItem = "Server name";
        dimension.AccessibleName = "Analytics grouping";
        tools.Controls.Add(window, 1, 0);
        window.Anchor = AnchorStyles.Left;
        tools.Controls.Add(new Label
        {
            Text = "&Group by",
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            Margin = new Padding(8, 3, 3, 3)
        }, 2, 0);
        tools.Controls.Add(dimension, 3, 0);
        dimension.Anchor = AnchorStyles.Left;
        tools.Controls.Add(export, 5, 0);
        root.Controls.Add(tools, 0, 0);
        summary.Text = "No database connected.";
        root.Controls.Add(summary, 0, 1);
        root.Controls.Add(Status, 0, 3);
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
                grid.Columns.Add(new DataGridViewTextBoxColumn
                {
                    Name = name,
                    HeaderText = caption,
                    Width = width,
                    ValueType = type,
                    SortMode = DataGridViewColumnSortMode.Automatic
                });
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
                    Filter(value);
            };
            content.Controls.Add(grid);
        }
        content.Controls.Add(empty);
        empty.BringToFront();
        empty.Set("Explore captured traffic", "Connect to a capture journal to inspect protocols and algorithms.",
            "Connect…", Connect);
        Controls.Add(root);
        foreach (var chart in new[] { protocols, groups, distribution })
            chart.ValueSelected += Filter;
        dimension.SelectedIndexChanged += (_, _) => RequestRefresh();
        export.Click += async (_, _) => await ExportAsync();

        // Size fixed-choice controls for their complete labels at the current text scale.
        FontChanged += (_, _) => dimension.FitItems();
        DpiChangedAfterParent += (_, _) => dimension.FitItems();
        dimension.FitItems();
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

    protected override string ScopeKey => window.SelectedIndex + "\0" + dimension.Text;

    protected override void ClearResult()
    {
        snapshot = null;
        export.Enabled = false;
        export.Visible = false;
        grid.Rows.Clear();
        timeline.Timeline = [];
        protocols.Bars = groups.Bars = distribution.Bars = [];
        summary.Text = "Loading analytics…";
        empty.Set("Loading analytics…", "Aggregating observations for the current filters and time range.");
        empty.Visible = true;
        Invalidate(true);
    }

    public override void Reset()
    {
        base.Reset();
        Status.Text = "";
    }

    public override void Pause()
    {
        base.Pause();
        export.Enabled = snapshot?.Total > 0;
        export.Visible = snapshot?.Total > 0;
        Status.Text = "Viewer updates: paused";
    }

    protected override void ShowLoading()
    {
        export.Enabled = false;
        Status.Text = "Aggregating filtered observations…";
    }

    protected override Func<DbConnection, CancellationToken, object> PrepareRead(DatabaseSource source, Query query)
    {
        window.Visible = timeLabel.Visible = !query.HasDateRange;
        var minutes = WindowMinutes(window);
        var since = Since(minutes);
        var grouping = dimension.Text;
        var top = Settings.TopGroups;
        read = (minutes, query.HasDateRange, grouping, window.Text);
        return (connection, token) => Insights.ReadAnalytics(source, query, since, grouping, top, token, connection);
    }

    // Aggregates stay valid until observations change or the rolling window loses its oldest observation.
    protected override DateTime NextTimedRefresh(object result)
    {
        var data = (AnalyticsSnapshot)result;
        var expiresMs = Math.Min(DateTimeOffset.MaxValue.ToUnixTimeMilliseconds(),
            data.FromUs / 1000 + read.Minutes * 60000L + 1);
        return read.Range || read.Minutes == 0 || data.Total == 0 ? DateTime.MaxValue :
            DateTimeOffset.FromUnixTimeMilliseconds(expiresMs).UtcDateTime;
    }

    protected override void ApplyResult(object value)
    {
        var result = (AnalyticsSnapshot)value;
        snapshot = result;
        summary.Text = $"Observations: {result.Total:N0}  ·  TLS selections: {result.Selected:N0}  ·  " +
            $"Plaintext alerts: {result.Alerts:N0}  ·  Mean hello interval: " +
            (result.MeanHelloMs is { } mean ? $"{mean:N2} ms" : "Not observed");
        Status.Text = $"{(read.Range ? "Explicit dates" : read.Window)} · " +
            $"Top {Settings.TopGroups} values · Refreshed {DateTime.Now:T}";
        timeline.Timeline = result.Timeline;
        protocols.Bars = result.Protocols;
        groups.Bars = result.Groups;
        distribution.Heading = read.Grouping;
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
            "Show all observations", () => { window.SelectedIndex = 3; ClearFilters(); });
        Invalidate(true);
    }

    protected override void ShowError(Exception error)
    {
        ClearResult();
        Status.Text = "Analytics unavailable; refresh to retry.";
        summary.Text = error.Message;
        empty.Set("Analytics unavailable", "Check the database connection and refresh to retry.",
            "Refresh", RequestRefresh);
        empty.Visible = true;
    }

    private async Task ExportAsync()
    {
        if (snapshot is not { } data)
            return;
        using var dialog = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = "Cipherazzi-analytics.csv" };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        try { await ExportAsync(data, dialog.FileName); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
        {
            if (!IsDisposed)
                MessageBox.Show(this, "The export could not be saved. " + error.Message, "Export analytics");
        }
    }

    internal static Task ExportAsync(AnalyticsSnapshot data, string path) => ExportFile.WriteAsync(path, (stream, _) =>
    {
        using var writer = new StreamWriter(stream, new UTF8Encoding(true), leaveOpen: true);
        writer.WriteLine("Dimension,Value,Observations,Scope total,Mean hello ms,Maximum hello ms");
        foreach (var row in data.Breakdown)
            writer.WriteLine(string.Join(',', ReportExport.Quote(data.Dimension, true),
                ReportExport.Quote(row.Name, true), row.Count, data.Total,
                row.MeanHelloMs?.ToString(CultureInfo.InvariantCulture) ?? "",
                row.MaximumHelloMs?.ToString(CultureInfo.InvariantCulture) ?? ""));
        return Task.CompletedTask;
    }, CancellationToken.None);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (var control in new Control[] { timeline, protocols, groups, distribution, grid })
                if (control.Parent is null)
                    control.Dispose();
        }
        base.Dispose(disposing);
    }
}
