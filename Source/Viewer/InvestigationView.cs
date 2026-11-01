namespace Cipherazzi.Viewer;

internal abstract class InvestigationView : UserControl
{
    protected readonly ViewerSettings Settings;
    protected readonly Label Status = new()
    {
        AutoSize = true,
        Dock = DockStyle.Fill,
        UseMnemonic = false,
        Text = "Connect to a database.",
        Margin = new Padding(3, 4, 3, 3)
    };
    protected DatabaseSource? Source;
    private readonly CancellationTokenSource lifetime = new();
    protected CancellationToken ClosingToken => lifetime.Token;
    private CancellationTokenSource? cancellation;
    private readonly HashSet<Task> pending = [];
    private string context = "";
    private DateTime updated;
    private DateTime nextTimedRefresh;
    private (string Identity, long Revision)? stamp;
    private string identity = "";
    private int generation;
    private bool loading;
    public event Action? RefreshRequested;
    public event Action<string>? FilterRequested;
    public event Action? ConnectRequested;
    public event Action? ClearFiltersRequested;

    protected InvestigationView(ViewerSettings settings)
    {
        Settings = settings;
        Dock = DockStyle.Fill;
        Padding = new Padding(3);
    }

    protected void RequestRefresh() => RefreshRequested?.Invoke();
    protected void Filter(string value) => FilterRequested?.Invoke(value);
    protected void Connect() => ConnectRequested?.Invoke();
    protected void ClearFilters() => ClearFiltersRequested?.Invoke();
    protected abstract string ScopeKey { get; }
    protected abstract Func<DbConnection, CancellationToken, object> PrepareRead(DatabaseSource source, Query query);
    protected abstract void ApplyResult(object result);
    protected abstract void ClearResult();
    protected virtual Func<DbConnection, CancellationToken, object>? PrepareStatusRead(DatabaseSource source,
        Query query) => null;
    protected virtual void ApplyStatusResult(object result) { }
    protected virtual DateTime NextTimedRefresh(object result) => DateTime.UtcNow.AddMinutes(1);
    protected virtual TimeSpan RefreshInterval => TimeSpan.FromSeconds(Settings.AnalyticsRefreshSeconds);

    // A paged view keeps its current page until the user moves, and restarts when the journal is replaced.
    protected virtual bool HoldsPage => false;
    protected virtual bool PagedByJournal => false;
    protected virtual void ShowLoading() => Status.Text = "Loading…";

    protected virtual void ShowError(Exception error)
    {
        ClearResult();
        Status.Text = "View unavailable. " + error.Message;

        // Replace loading placeholders with a recovery action when an investigation cannot be read.
        var controls = new Stack<Control>();
        controls.Push(this);
        while (controls.TryPop(out var control))
        {
            if (control is ResultGrid grid)
                grid.SetEmptyState("View unavailable", "Check the database connection and refresh to retry.",
                    "Refresh", RequestRefresh);
            else
                foreach (Control child in control.Controls)
                    controls.Push(child);
        }
    }

    protected DateTime NextWindowExpiry(PqcSnapshot snapshot, int minutes) => minutes == 0 || snapshot.Rows.Count == 0 ?
        DateTime.MaxValue : DateTimeOffset.FromUnixTimeMilliseconds(snapshot.Rows.Min(row => row.FirstUs) / 1000)
            .UtcDateTime.AddMinutes(minutes).AddMilliseconds(1);

    public void SetSource(DatabaseSource source)
    {
        Source = source;
        Reset();
    }

    public virtual void Reset()
    {
        ++generation;
        cancellation?.Cancel();
        loading = false;
        context = "";
        updated = default;
        stamp = null;
        identity = "";
        ClearResult();
        Status.Text = Source is null ? "Connect to a database." : "Loading…";
    }

    public virtual void Pause()
    {
        ++generation;
        cancellation?.Cancel();
        loading = false;
        Status.Text = "Viewer updates: paused.";
    }

    public Task RefreshAsync(DatabaseSource? source, Query query,
        bool force) => TrackAsync(LoadAsync(source, query, force));

    private async Task LoadAsync(DatabaseSource? source, Query query, bool force)
    {
        if (source is null || IsDisposed)
            return;
        var key = string.Join('\0', source.CacheKey, source.Provider, query.CacheKey, ScopeKey);
        if (context != key)
        {
            Source = source;
            Reset();
            context = key;
        }
        if (!force && (loading || HoldsPage || DateTime.UtcNow - updated < RefreshInterval))
            return;
        cancellation?.Cancel();
        cancellation?.Dispose();
        cancellation = new();
        var token = cancellation.Token;
        var current = ++generation;
        loading = true;
        if (force || stamp is null)
            ShowLoading();
        try
        {
            // Reuse results until observations change or a timed boundary such as a rolling window passes.
            var known = !force && DateTime.UtcNow < nextTimedRefresh ? stamp : null;
            var read = PrepareRead(source, query);
            var readStatus = PrepareStatusRead(source, query);
            var (currentStamp, changed, result) = await Task.Run(() => Database.ReadIfChanged(source, known, token,
                connection => read(connection, token),
                readStatus is null ? null : connection => readStatus(connection, token)), token);
            if (current != generation || IsDisposed)
                return;
            if (identity.Length > 0 && identity != currentStamp.Identity)
            {
                // A replacement journal has independent identities, so paging restarts at its newest rows.
                if (PagedByJournal)
                {
                    Reset();
                    await LoadAsync(source, query, true);
                    return;
                }
                ClearResult();
            }
            identity = currentStamp.Identity;
            if (!changed)
            {
                if (result is not null)
                    ApplyStatusResult(result);
                updated = DateTime.UtcNow;
                return;
            }
            ApplyResult(result!);
            stamp = result is PqcSnapshot snapshot ? (currentStamp.Identity, snapshot.Revision) : currentStamp;
            nextTimedRefresh = NextTimedRefresh(result!);
            updated = DateTime.UtcNow;
        }
        catch (OperationCanceledException) { }
        catch (Exception error)
        {
            if (current == generation && !IsDisposed)
            {
                stamp = null;
                updated = DateTime.UtcNow;
                ShowError(error);
            }
        }
        finally
        {
            if (current == generation)
                loading = false;
        }
    }

    protected async Task TrackAsync(Task task)
    {
        pending.Add(task);
        try { await task; }
        finally { pending.Remove(task); }
    }

    public async Task DrainAsync()
    {
        lifetime.Cancel();
        Pause();
        while (pending.Count > 0)
        {
            try { await Task.WhenAll(pending.ToArray()); }
            catch (Exception) { }
        }
    }

    protected static FlowLayoutPanel Toolbar() => new()
    {
        AutoSize = true,
        Dock = DockStyle.Fill,
        WrapContents = true,
        Margin = Padding.Empty
    };

    protected static Control Choice(string label, Control control)
    {
        var group = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Margin = new Padding(0, 0, 8, 0) };
        group.ColumnStyles.Add(new(SizeType.AutoSize));
        group.ColumnStyles.Add(new(SizeType.AutoSize));
        group.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        control.Anchor = AnchorStyles.Left;
        group.Controls.Add(control, 1, 0);
        return group;
    }

    protected ComboBox WindowChoice()
    {
        var window = new ChoiceBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            AutoSize = true,
            AccessibleName = "Investigation time window"
        };
        window.Items.AddRange(["Last 15 minutes", "Last hour", "Last 24 hours", "All observations"]);
        window.SelectedIndex = Settings.AnalyticsMinutes switch { 15 => 0, 60 => 1, 1440 => 2, _ => 3 };
        if (Settings.AnalyticsMinutes is not (0 or 15 or 60 or 1440))
        {
            window.Items.Add($"Last {Settings.AnalyticsMinutes:N0} minutes");
            window.SelectedIndex = 4;
        }
        void Metrics() => window.FitItems();
        window.FontChanged += (_, _) => Metrics();
        window.DpiChangedAfterParent += (_, _) => Metrics();
        Metrics();
        window.SelectedIndexChanged += (_, _) => { Reset(); RequestRefresh(); };
        return window;
    }

    protected int WindowMinutes(ComboBox window) => window.SelectedIndex switch
    {
        0 => 15,
        1 => 60,
        2 => 1440,
        4 => Settings.AnalyticsMinutes,
        _ => 0
    };
    protected static long Since(int minutes) => minutes == 0 ? 0 :
        DateTimeOffset.UtcNow.AddMinutes(-minutes).ToUnixTimeMilliseconds() * 1000;
    protected static DataGridViewTextBoxColumn Column(string name, string caption, int width, bool numeric = false)
    {
        var column = new DataGridViewTextBoxColumn
        {
            Name = name,
            HeaderText = caption,
            Width = width,
            SortMode = DataGridViewColumnSortMode.Automatic
        };
        if (numeric)
        {
            column.ValueType = typeof(long);
            column.DefaultCellStyle.Alignment = column.HeaderCell.Style
                .Alignment = DataGridViewContentAlignment.MiddleRight;
            column.DefaultCellStyle.Format = "N0";
        }
        return column;
    }

    protected static DataGridViewCell FirstVisibleCell(DataGridViewRow row) => row.Cells.Cast<DataGridViewCell>()
        .Where(cell => cell.OwningColumn!.Visible).MinBy(cell => cell.OwningColumn!.DisplayIndex)!;

    protected void ConfigureColumns(ResultGrid grid)
    {
        // Persist each investigation grid independently; header menus keep advanced fields available.
        if (Settings.ViewColumns.TryGetValue(grid.Name, out var configured))
        {
            foreach (var setting in configured)
            {
                if (grid.Columns[setting.Name] is not { } column)
                    continue;
                column.Visible = setting.Visible;
                column.Width = setting.Width;
            }
            if (grid.Columns.Cast<DataGridViewColumn>().All(column => !column.Visible))
                grid.Columns[0].Visible = true;
        }
        var menu = new ContextMenuStrip();
        foreach (DataGridViewColumn column in grid.Columns)
        {
            var item = new ToolStripMenuItem(column.HeaderText) { CheckOnClick = true, Checked = column.Visible };
            item.Click += (_, _) =>
            {
                if (!item.Checked && grid.Columns.Cast<DataGridViewColumn>().Count(value => value.Visible) == 1)
                {
                    item.Checked = true;
                    return;
                }
                column.Visible = item.Checked;
                Settings.ViewColumns[grid.Name] = grid.Columns.Cast<DataGridViewColumn>().Select(value =>
                    new ColumnSetting(value.Name, value.Visible, Math.Clamp(value.Width, 60, 2000))).ToList();
                try { Settings.Save(Settings.PersistencePath); }
                catch (Exception error) when (
                    error is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException)
                { Status.Text = "Column settings could not be saved. " + error.Message; }
            };
            menu.Items.Add(item);
        }
        grid.ColumnHeaderMouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Right)
                menu.Show(Cursor.Position);
        };
        grid.Disposed += (_, _) => menu.Dispose();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            lifetime.Cancel();
            cancellation?.Cancel();
            cancellation?.Dispose();
            cancellation = null;
            lifetime.Dispose();
        }
        base.Dispose(disposing);
    }
}
