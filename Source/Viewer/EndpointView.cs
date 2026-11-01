namespace Cipherazzi.Viewer;

internal sealed class EndpointView : InvestigationView
{
    private readonly ResultGrid grid = new() { Name = "EndpointGrid", AccessibleName = "Endpoint telemetry events" };
    private readonly PropertyInspector details = new();
    private readonly CommandButton previous = new() { Text = "&Newer", AutoSize = true, Enabled = false };
    private readonly CommandButton next = new() { Text = "Ol&der", AutoSize = true, Enabled = false };
    private readonly PageNavigator<(long Time, string Id)> pages = new((long.MaxValue, "\uffff"));
    private List<EndpointRow> rows = [];

    public EndpointView(ViewerSettings settings) : base(settings)
    {
        Status.AutoSize = false;
        Status.AutoEllipsis = true;
        Status.TextAlign = ContentAlignment.MiddleLeft;
        Status.Margin = new Padding(3);
        Status.Text = "No endpoint events loaded";
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        root.RowStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.ColumnStyles.Add(new(SizeType.Percent, 100));
        var toolbar = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 3 };
        toolbar.ColumnStyles.Add(new(SizeType.AutoSize));
        toolbar.ColumnStyles.Add(new(SizeType.AutoSize));
        toolbar.ColumnStyles.Add(new(SizeType.Percent, 100));
        toolbar.Controls.Add(previous, 0, 0);
        toolbar.Controls.Add(next, 1, 0);
        toolbar.Controls.Add(Status, 2, 0);
        root.Controls.Add(toolbar, 0, 1);
        AnalyticsView.ConfigureGrid(grid);
        foreach (var (name, caption, width) in new[]
        {
            ("Time", "Observed", 155), ("Provider", "Provider", 145), ("Kind", "Event", 160),
            ("Result", "Endpoint evidence", 280), ("Pid", "Emitting PID", 100), ("Peer", "Peer", 180),
            ("Protocol", "Protocol", 85), ("Cipher", "Cipher", 240), ("Certificate", "Certificate ID", 170)
        })
            grid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = name,
                HeaderText = caption,
                Width = width,
                SortMode = DataGridViewColumnSortMode.NotSortable
            });
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = 5,
            Size = new Size(1200, 600),
            SplitterDistance = 340,
            Panel1MinSize = 100,
            Panel2MinSize = 120
        };
        split.Panel1.Controls.Add(grid);
        split.Panel2.Controls.Add(details);
        root.Controls.Add(split, 0, 0);
        Controls.Add(root);
        grid.SetEmptyState("No endpoint reports loaded", "Connect to a capture with endpoint telemetry.",
            "Connect…", Connect);
        previous.Click += (_, _) =>
        {
            previous.Enabled = next.Enabled = false;
            pages.Newer();
            RequestRefresh();
        };
        next.Click += (_, _) =>
        {
            if (rows.Count == 0)
                return;
            previous.Enabled = next.Enabled = false;
            pages.Older((rows[^1].TimestampUs, rows[^1].Id));
            RequestRefresh();
        };
        grid.CurrentCellChanged += (_, _) => Selection();
        details.Clear("No endpoint event selected.");
    }

    protected override string ScopeKey => Settings.PageSize.ToString();
    protected override TimeSpan RefreshInterval => TimeSpan.FromSeconds(2);
    protected override bool HoldsPage => pages.Page > 0;
    protected override bool PagedByJournal => true;
    protected override DateTime NextTimedRefresh(object result) => DateTime.MaxValue;
    protected override void ShowLoading() => Status.Text = "Loading endpoint events…";

    private void Selection()
    {
        if (grid.CurrentRow is not { Index: >= 0 } selected || selected.Index >= rows.Count)
            return;
        var row = rows[selected.Index];
        details.Show(row.Id, row.Provider + " · " + row.Kind, row.Properties);
    }

    public override void Reset()
    {
        pages.Reset();
        base.Reset();
        Status.Text = "Loading endpoint events…";
    }

    protected override void ClearResult()
    {
        rows.Clear();
        grid.Rows.Clear();
        grid.SetEmptyState("Loading endpoint reports…", "Reading reported events from the connected database.");
        previous.Enabled = next.Enabled = false;
        details.Clear("Loading endpoint telemetry…");
    }

    protected override Func<DbConnection, CancellationToken, object> PrepareRead(DatabaseSource source, Query query)
    {
        var cursor = pages.Cursor;
        return (connection, token) => Insights.ReadEvents(source, query, cursor.Time, cursor.Id, 0, token, connection);
    }

    protected override void ApplyResult(object result)
    {
        var page = (EndpointPage)result;
        var selected = grid.CurrentRow is { Index: >= 0 } selection && selection.Index < rows.Count ?
            rows[selection.Index].Id : null;
        var first = grid.FirstDisplayedScrollingRowIndex;
        var firstId = first > 0 && first < rows.Count ? rows[first].Id : null;
        rows = page.Rows;
        grid.Rows.Clear();
        foreach (var row in rows)
            grid.Rows.Add(DateTimeOffset.FromUnixTimeMilliseconds(row.TimestampUs / 1000)
                .ToLocalTime().ToString("MM-dd HH:mm:ss.fff"), row.Provider, row.Kind, row.Result,
                row.Pid == "0" ? "Not supplied" : row.Pid, row.Peer, row.Protocol, row.Cipher, row.CertificateId);
        if (selected is not null && rows.FindIndex(row => row.Id == selected) is >= 0 and var index)
            grid.CurrentCell = grid.Rows[index].Cells[0];
        if (firstId is not null && rows.FindIndex(row => row.Id == firstId) is >= 0 and var visible)
            grid.FirstDisplayedScrollingRowIndex = visible;
        previous.Enabled = pages.Page > 0;
        next.Enabled = page.HasMore;
        Status.Text = $"{rows.Count:N0} events · page {pages.Page + 1} · " +
            "Provider reports; correlation shown in connection details";
        grid.SetEmptyState("No matching endpoint reports",
            "Clear the search filter. If no reports are recorded, inspect capture coverage and telemetry setup.",
            "Clear search", ClearFilters);
        if (rows.Count == 0)
            details.Clear("No matching endpoint events.");
        else
            Selection();
    }

    // Keep the current page and its rows so an interrupted journal can recover in place.
    protected override void ShowError(Exception error)
    {
        Status.Text = "Endpoint events unavailable. " + error.Message;
        grid.SetEmptyState("Endpoint reports unavailable", "Check the connection and refresh to retry.",
            "Refresh", RequestRefresh);
    }

    public override void Pause()
    {
        base.Pause();
        Status.Text = "Viewer updates: paused";
    }
}
