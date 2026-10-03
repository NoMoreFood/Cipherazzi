namespace Cipherazzi.Viewer;

internal sealed class EndpointView : UserControl
{
    private readonly ResultGrid grid = new() { Name = "EndpointGrid", AccessibleName = "Endpoint telemetry events" };
    private readonly PropertyInspector details = new();
    private readonly Label status = new() { Dock = DockStyle.Fill, AutoEllipsis = true,
        TextAlign = ContentAlignment.MiddleLeft, Text = "No endpoint events loaded", UseMnemonic = false };
    private readonly CommandButton previous = new() { Text = "&Newer", AutoSize = true, Enabled = false };
    private readonly CommandButton next = new() { Text = "Ol&der", AutoSize = true, Enabled = false };
    private readonly List<(long Time, string Id)> pages = [(long.MaxValue, "\uffff")];
    private List<EndpointRow> rows = [];
    private int page;
    private int generation;
    private bool loading;
    private string context = "";
    private DateTime updated;
    private CancellationTokenSource? cancellation;
    public event Action? RefreshRequested;
    public event Action? ConnectRequested;
    public event Action? ClearFiltersRequested;

    public EndpointView()
    {
        Dock = DockStyle.Fill;
        Padding = new Padding(3);
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
        toolbar.Controls.Add(status, 2, 0);
        root.Controls.Add(toolbar, 0, 1);
        AnalyticsView.ConfigureGrid(grid);
        foreach (var (name, caption, width) in new[]
        {
            ("Time", "Observed", 155), ("Provider", "Provider", 145), ("Kind", "Event", 160),
            ("Result", "Endpoint evidence", 280), ("Pid", "Emitting PID", 100), ("Peer", "Peer", 180),
            ("Protocol", "Protocol", 85), ("Cipher", "Cipher", 240), ("Certificate", "Certificate ID", 170)
        })
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = name, HeaderText = caption, Width = width,
                SortMode = DataGridViewColumnSortMode.NotSortable });
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterWidth = 5,
            Size = new Size(1200, 600), SplitterDistance = 340, Panel1MinSize = 100, Panel2MinSize = 120 };
        split.Panel1.Controls.Add(grid);
        split.Panel2.Controls.Add(details);
        root.Controls.Add(split, 0, 0);
        Controls.Add(root);
        grid.SetEmptyState("No endpoint reports loaded", "Connect to a capture with endpoint telemetry.",
            "Connect…", () => ConnectRequested?.Invoke());
        previous.Click += (_, _) =>
        {
            if (page > 0)
                --page;
            updated = default;
            RefreshRequested?.Invoke();
        };
        next.Click += (_, _) =>
        {
            if (rows.Count == 0)
                return;
            if (pages.Count > page + 1)
                pages.RemoveRange(page + 1, pages.Count - page - 1);
            pages.Add((rows[^1].TimestampUs, rows[^1].Id));
            ++page;
            updated = default;
            RefreshRequested?.Invoke();
        };
        grid.CurrentCellChanged += (_, _) => Selection();
        details.Clear("No endpoint event selected.");
    }

    private void Selection()
    {
        if (grid.CurrentRow is not { Index: >= 0 } selected || selected.Index >= rows.Count)
            return;
        var row = rows[selected.Index];
        details.Show(row.Id, row.Provider + " · " + row.Kind, row.Properties);
    }

    public void Reset()
    {
        ++generation;
        cancellation?.Cancel();
        loading = false;
        context = "";
        updated = default;
        page = 0;
        pages.Clear();
        pages.Add((long.MaxValue, "\uffff"));
        rows.Clear();
        grid.Rows.Clear();
        grid.SetEmptyState("Loading endpoint reports…", "Reading reported events from the connected database.");
        previous.Enabled = next.Enabled = false;
        details.Clear("Loading endpoint telemetry…");
    }

    public async Task RefreshAsync(DatabaseSource? source, string search, bool force)
        => await RefreshAsync(source, new Query(search, "", false, PageCursor.Newest), force);

    public async Task RefreshAsync(DatabaseSource? source, Query query, bool force)
    {
        if (source is null || IsDisposed)
            return;
        var key = source.CacheKey + '\0' + query.CacheKey;
        if (context != key)
        {
            Reset();
            context = key;
        }
        if (!force && (loading || page > 0 || DateTime.UtcNow - updated < TimeSpan.FromSeconds(2)))
            return;
        cancellation?.Cancel();
        cancellation?.Dispose();
        cancellation = new();
        var token = cancellation.Token;
        var current = ++generation;
        var cursor = pages[page];
        loading = true;
        status.Text = "Loading endpoint events…";
        try
        {
            var result = await Task.Run(() => Insights.ReadEvents(source, query, cursor.Time, cursor.Id, 0, token), token);
            if (current != generation || IsDisposed)
                return;
            var selected = grid.CurrentRow is { Index: >= 0 } selection && selection.Index < rows.Count ?
                rows[selection.Index].Id : null;
            var first = grid.FirstDisplayedScrollingRowIndex;
            var firstId = first > 0 && first < rows.Count ? rows[first].Id : null;
            rows = result;
            grid.Rows.Clear();
            foreach (var row in rows)
                grid.Rows.Add(DateTimeOffset.FromUnixTimeMilliseconds(row.TimestampUs / 1000)
                    .ToLocalTime().ToString("MM-dd HH:mm:ss.fff"), row.Provider, row.Kind, row.Result,
                    row.Pid == "0" ? "Not supplied" : row.Pid, row.Peer, row.Protocol, row.Cipher, row.CertificateId);
            if (selected is not null && rows.FindIndex(row => row.Id == selected) is >= 0 and var index)
                grid.CurrentCell = grid.Rows[index].Cells[0];
            if (firstId is not null && rows.FindIndex(row => row.Id == firstId) is >= 0 and var visible)
                grid.FirstDisplayedScrollingRowIndex = visible;
            previous.Enabled = page > 0;
            next.Enabled = rows.Count == 250;
            status.Text = $"{rows.Count:N0} events · page {page + 1} · " +
                "Provider reports; correlation shown in connection details";
            grid.SetEmptyState("No matching endpoint reports",
                "Clear the search filter. If no reports are recorded, inspect capture coverage and telemetry setup.",
                "Clear search", () => ClearFiltersRequested?.Invoke());
            if (rows.Count == 0)
            {
                details.Clear("No matching endpoint events.");
            }
            else
                Selection();
            updated = DateTime.UtcNow;
        }
        catch (OperationCanceledException) {}
        catch (Exception error)
        {
            if (current == generation && !IsDisposed)
            {
                updated = DateTime.UtcNow;
                status.Text = "Endpoint events unavailable. " + error.Message;
                grid.SetEmptyState("Endpoint reports unavailable", "Check the connection and refresh to retry.",
                    "Refresh", () => RefreshRequested?.Invoke());
            }
        }
        finally
        {
            if (current == generation)
                loading = false;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            cancellation?.Cancel();
            cancellation?.Dispose();
            cancellation = null;
        }
        base.Dispose(disposing);
    }

    public void Pause()
    {
        ++generation;
        cancellation?.Cancel();
        loading = false;
        status.Text = "Viewer updates: paused";
    }
}
