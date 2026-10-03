using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace Cipherazzi.Viewer;

internal sealed class MainForm : Form
{
    private readonly Icon applicationIcon = new(typeof(MainForm), "Cipherazzi.ico");
    private readonly ResultGrid grid = new();
    private readonly InputTextBox search = new();
    private readonly ChoiceBox protocol = new() { AutoSize = true };
    private readonly CheckBox incomplete = new() { Text = "Partial e&xchanges", AutoSize = true };
    private readonly CheckBox live = new() { Text = "&Live", Checked = true, AutoSize = true, Visible = false };
    private readonly CommandButton refresh = new() { Text = "&Refresh", AutoSize = true, Visible = false };
    private readonly CommandButton health = new() { Text = "Capture &health", AutoSize = true, Visible = false };
    private readonly CommandButton filterDialog = new() { Text = "&Filters…", AutoSize = true,
        AccessibleName = "Dates, field filters, and saved searches" };
    private readonly CommandButton report = new() { Text = "&Bulk export…", AutoSize = true, Visible = false,
        AccessibleName = "Export matching evidence" };
    private Query connectionScope = new("", "", false, PageCursor.Newest);
    private Query endpointScope = new("", "", false, PageCursor.Newest);
    private CancellationTokenSource? exportCancellation;
    private readonly TableLayoutPanel filters;
    private readonly TableLayoutPanel navigation;
    private readonly CommandButton previous = new() { Text = "&Newer", AutoSize = true, Enabled = false };
    private readonly CommandButton next = new() { Text = "Ol&der", AutoSize = true, Enabled = false };
    private readonly Label pageLabel = new()
    {
        AutoSize = true, Text = "No database connected", Anchor = AnchorStyles.Left, UseMnemonic = false
    };
    private readonly Label databaseLabel = new() { AutoEllipsis = true, Dock = DockStyle.Fill, UseMnemonic = false };
    private readonly PropertyInspector details = new();
    private readonly ToolTip hints = new() { AutoPopDelay = 15000 };
    private readonly ViewerSettings settings;
    private readonly WorkspaceTabs tabs = new()
    {
        Dock = DockStyle.Fill, AccessibleName = "Workspace views", ShowToolTips = true
    };
    private readonly AnalyticsView visualization;
    private readonly AnalyticsView analytics;
    private readonly EndpointView endpoints = new();
    private readonly ReadinessView readiness;
    private readonly CertificatesView certificates;
    private readonly PoliciesView policies;
    private CancellationTokenSource? detailCancellation;
    private string detailKey = "";
    private List<ObservationProperty> certificateProperties = [];
    private readonly Label status = new()
    {
        Dock = DockStyle.Bottom, AutoEllipsis = true, Height = 24,
        TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(8, 0, 8, 0), UseMnemonic = false
    };
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 250 };
    private readonly System.Windows.Forms.Timer debounce = new() { Interval = 350 };
    private readonly List<PageCursor> pages = [PageCursor.Newest];
    private readonly string? smokePath;
    private CancellationTokenSource? cancellation;
    private DatabaseSource? source;
    private FileSystemWatcher? journalWatcher;
    private readonly System.Windows.Forms.Timer journalDebounce = new() { Interval = 75 };
    private long revision = -1;
    private DateTime healthRefreshed;
    private bool applying;
    private string diagnostics = "No database connected.";
    private List<ConnectionRow> rows = [];
    private int generation;
    private int page;
    private bool loading;
    private readonly HashSet<Task> operations = [];
    private bool closing, closeReady;
    public int ExitCode { get; private set; }

    public MainForm(DatabaseSource? initialSource, string? smokePath, ViewerSettings? settings = null)
    {
        this.smokePath = smokePath;
        this.settings = settings ?? ViewerSettings.Load();
        visualization = new(this.settings, visual: true);
        analytics = new(this.settings, visual: false);
        readiness = new(this.settings);
        certificates = new(this.settings);
        policies = new(this.settings);
        live.Checked = this.settings.Live;
        timer.Interval = this.settings.PollMilliseconds;
        Text = "Cipherazzi — Network cryptography";
        Icon = applicationIcon;
        Font = new Font("Segoe UI", 9);
        AutoScaleDimensions = new SizeF(96, 96);
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(1440, 900);
        MinimumSize = new Size(1000, 650);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(246, 248, 251);
        KeyPreview = true;

        // Keep the command area measured by its contents and the results free to resize.
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            Padding = new Padding(8, 6, 8, 4)
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var commands = new TableLayoutPanel
        {
            AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 8, Margin = Padding.Empty
        };
        commands.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commands.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commands.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commands.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        commands.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commands.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commands.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        commands.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var open = new CommandButton { Text = "&Connect…", AutoSize = true };
        var configure = new CommandButton { Text = "&Options…", AutoSize = true };
        var help = new CommandButton { Text = "Help", AutoSize = true };
        commands.Controls.Add(open, 0, 0);
        commands.Controls.Add(refresh, 1, 0);
        live.Anchor = AnchorStyles.Left;
        live.Margin = new Padding(6, 3, 6, 3);
        commands.Controls.Add(live, 2, 0);
        databaseLabel.Text = "No database connected";
        databaseLabel.TextAlign = ContentAlignment.MiddleLeft;
        databaseLabel.Margin = new Padding(6, 3, 6, 3);
        commands.Controls.Add(databaseLabel, 3, 0);
        commands.Controls.Add(report, 4, 0);
        commands.Controls.Add(configure, 5, 0);
        commands.Controls.Add(health, 6, 0);
        commands.Controls.Add(help, 7, 0);
        root.Controls.Add(commands, 0, 0);

        filters = new TableLayoutPanel
        {
            AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 6, Margin = new Padding(0, 2, 0, 4)
        };
        filters.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        filters.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        filters.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        filters.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        filters.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        filters.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        filters.Controls.Add(new Label { Text = "&Search", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        search.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        search.PlaceholderText = "SNI, address, process, cipher, or group";
        search.AccessibleName = "Search SNI, IP address, or process name";
        search.MaxLength = 256;
        filters.Controls.Add(search, 1, 0);
        var protocolLabel = new Label
        {
            Text = "&Protocol", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(8, 3, 4, 3)
        };
        filters.Controls.Add(protocolLabel, 2, 0);
        protocol.DropDownStyle = ComboBoxStyle.DropDownList;
        protocol.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        protocol.MinimumSize = new Size(160, 0);
        protocol.AccessibleName = "Observed protocol";
        protocol.Items.AddRange(FilterDialog.ProtocolNames);
        protocol.SelectedIndex = 0;
        filters.Controls.Add(protocol, 3, 0);
        incomplete.Anchor = AnchorStyles.Left;
        incomplete.Margin = new Padding(8, 3, 3, 3);
        filters.Controls.Add(incomplete, 4, 0);
        filters.Controls.Add(filterDialog, 5, 0);
        root.Controls.Add(filters, 0, 1);

        // Bound the displayed rows and avoid measuring every cell during live refresh.
        grid.Dock = DockStyle.Fill;
        grid.Name = "ConnectionsGrid";
        grid.AccessibleName = "Observed connections";
        grid.AllowUserToOrderColumns = true;
        grid.ReadOnly = true;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.AllowUserToResizeRows = false;
        grid.MultiSelect = false;
        grid.RowHeadersVisible = false;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.AutoGenerateColumns = false;
        grid.VirtualMode = true;
        grid.CellValueNeeded += (_, e) =>
        {
            if (e.RowIndex < 0 || e.RowIndex >= rows.Count)
                return;
            var row = rows[e.RowIndex];
            e.Value = row.Value(grid.Columns[e.ColumnIndex].Name);
        };
        grid.BackgroundColor = Color.White;
        grid.BorderStyle = BorderStyle.None;
        grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        grid.GridColor = Color.FromArgb(230, 234, 240);
        grid.EnableHeadersVisualStyles = false;
        grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(231, 237, 245);
        grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(30, 49, 73);
        grid.ColumnHeadersDefaultCellStyle.WrapMode = DataGridViewTriState.False;
        grid.ColumnHeadersHeight = 24;
        grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        grid.RowTemplate.Height = 22;
        grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(217, 234, 252);
        grid.DefaultCellStyle.SelectionForeColor = Color.FromArgb(15, 38, 65);
        grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(248, 250, 253);
        foreach (var column in ColumnDefinitions.All)
        {
            grid.Columns.Add(new DataGridViewTextBoxColumn
            {
                CellTemplate = new ResultGrid.TextCell(),
                Name = column.Name, DataPropertyName = column.Name, HeaderText = column.Caption,
                Width = column.Width, MinimumWidth = 60, SortMode = DataGridViewColumnSortMode.NotSortable,
                ToolTipText = column.Description
            });
        }
        ApplyColumns();
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterWidth = 5,
            Size = new Size(1300, 600), SplitterDistance = 370,
            Panel1MinSize = 140, Panel2MinSize = 120
        };
        split.Panel1.Controls.Add(grid);
        details.AccessibleName = "Selected observation details";
        details.Clear("No observation selected.");
        split.Panel2.Controls.Add(details);
        foreach (var (caption, hint, view) in new (string, string, Control)[]
        {
            ("Connections", "Browse captured connections and inspect their cryptographic evidence.", split),
            ("Visualizations", "Explore charts of observed protocols and algorithms.", visualization),
            ("Analytics", "Compare counts of observed protocols, algorithms, and applications.", analytics),
            ("Endpoint telemetry", "Inspect cryptographic reports from applications and providers.", endpoints),
            ("PQC readiness", "Assess post-quantum cryptography use and compare migration baselines.", readiness),
            ("Certificates", "Inspect observed public certificates and their cryptographic properties.", certificates),
            ("Policies", "Evaluate captured observations against the enabled cryptographic policies.", policies)
        })
        {
            var tab = new TabPage(caption) { ToolTipText = hint, AccessibleDescription = hint };
            tab.Controls.Add(view);
            tabs.TabPages.Add(tab);
        }
        root.Controls.Add(tabs, 0, 2);
        navigation = new TableLayoutPanel
        {
            AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 3, Margin = Padding.Empty
        };
        navigation.ColumnStyles.Add(new(SizeType.AutoSize));
        navigation.ColumnStyles.Add(new(SizeType.AutoSize));
        navigation.ColumnStyles.Add(new(SizeType.Percent, 100));
        navigation.Controls.Add(previous, 0, 0);
        navigation.Controls.Add(next, 1, 0);
        pageLabel.Anchor = AnchorStyles.Left;
        pageLabel.Margin = new Padding(6, 0, 0, 0);
        navigation.Controls.Add(pageLabel, 2, 0);
        root.Controls.Add(navigation, 0, 3);
        navigation.Visible = false;
        status.Text = "Connect to a capture journal or server database.";
        details.Clear("Connect to a database to view observations.");
        refresh.Enabled = live.Enabled = health.Enabled = filters.Enabled = false;
        Controls.Add(root);
        Controls.Add(status);

        open.Click += (_, _) => OpenDatabase();
        filterDialog.Click += (_, _) => OpenFilters();
        report.Click += async (_, _) => await TrackAsync(ExportReportAsync());
        grid.SetEmptyState("Open a capture journal", "View an existing local journal or replicated server database. " +
            "Start the collector separately.", "Connect…", OpenDatabase);

        // Explain viewer commands and expose the same guidance to assistive tools.
        foreach (var (control, hint) in new (Control, string)[]
        {
            (open, "Open an existing capture journal or replicated server database (Ctrl+O). " +
                "Start the collector separately."),
            (refresh, "Reload the current view from the connected database (F5), including when Live is off."),
            (live, "Automatically update the current view as new observations arrive. " +
                "Clear to pause viewer updates; collection continues. Older connection pages stay paused."),
            (configure, "Choose the viewer theme, refresh interval, page size, and displayed connection columns."),
            (health, "Show collector status, capture losses, inspection limits, and retention."),
            (help, "Open Cipherazzi help on GitHub in your default browser (F1)."),
            (search, "Search observations in the current view (Ctrl+F). Press Escape to clear the search."),
            (protocol, "Filter observations by the observed protocol."),
            (incomplete, "Show only partial exchanges where the full negotiation was not observed."),
            (previous, "Show newer connections. Live updates resume on the newest page if enabled."),
            (next, "Show the next page of older connections. Live updates pause while browsing older pages.")
        })
        {
            hints.SetToolTip(control, hint);
            control.AccessibleDescription = hint;
        }
        configure.Click += async (_, _) =>
        {
            this.settings.Live = live.Checked;
            using var dialog = new SettingsDialog(this.settings, grid);
            if (dialog.ShowDialog(this) != DialogResult.OK)
                return;
            timer.Interval = this.settings.PollMilliseconds;
            ApplyColumns();
            ApplyTheme();
            ResetPages();
            readiness.Reset();
            certificates.Reset();
            policies.Reset();
            await RefreshWorkspaceAsync(clear: true);
        };
        var columnMenu = new ContextMenuStrip();
        columnMenu.Items.Add("Display &options…", null, (_, _) => configure.PerformClick());
        grid.ColumnHeaderMouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Right)
                columnMenu.Show(Cursor.Position);
        };
        refresh.Click += async (_, _) => await RefreshWorkspaceAsync();
        health.Click += (_, _) => ShowText("Capture health", diagnostics);
        details.CertificateRequested += async hash => await TrackAsync(OpenCertificateAsync(hash));
        help.Click += (_, _) =>
        {
            // Open product help in the configured browser.
            try
            {
                Process.Start(new ProcessStartInfo("https://github.com/NoMoreFood/Cipherazzi")
                {
                    UseShellExecute = true
                });
            }
            catch (Exception error)
            {
                status.ForeColor = UiTheme.Error;
                status.Text = "Help could not be opened. " + error.Message;
            }
        };
        tabs.SelectedIndexChanged += async (_, _) =>
        {
            if (tabs.SelectedIndex != 1) visualization.Pause();
            if (tabs.SelectedIndex != 2) analytics.Pause();
            if (tabs.SelectedIndex != 3) endpoints.Pause();
            if (tabs.SelectedIndex != 4) readiness.Pause();
            if (tabs.SelectedIndex != 5) certificates.Pause();
            if (tabs.SelectedIndex != 6) policies.Pause();
            navigation.Visible = source is not null && tabs.SelectedIndex == 0;
            protocol.Visible = protocolLabel.Visible = incomplete.Visible = tabs.SelectedIndex is not (3 or 5);
            filterDialog.Visible = tabs.SelectedIndex != 5;
            UpdateReportAction();
            search.PlaceholderText = tabs.SelectedIndex switch
            {
                3 => "Provider, event, peer, or cipher",
                5 => "Subject, issuer, SAN, fingerprint, computer, or application",
                _ => "SNI, address, process, cipher, or group"
            };
            await RefreshWorkspaceAsync(clear: true);
        };
        foreach (var view in new[] { visualization, analytics })
        {
            view.RefreshRequested += async () => await RefreshActiveViewAsync(true);
            view.ConnectRequested += OpenDatabase;
            view.ClearFiltersRequested += ClearFilters;
            view.FilterRequested += value =>
            {
                tabs.SelectedIndex = 0;
                search.Text = value;
            };
        }
        endpoints.RefreshRequested += async () => await RefreshActiveViewAsync(true);
        endpoints.ConnectRequested += OpenDatabase;
        endpoints.ClearFiltersRequested += ClearFilters;
        foreach (var view in new InvestigationView[] { readiness, certificates, policies })
        {
            view.RefreshRequested += async () => await RefreshActiveViewAsync(true);
            view.ConnectRequested += OpenDatabase;
            view.ClearFiltersRequested += ClearFilters;
            view.FilterRequested += value => { tabs.SelectedIndex = 0; search.Text = value; };
        }
        policies.PoliciesChanged += async () =>
        {
            readiness.Reset();
            await RefreshWorkspaceAsync(clear: true);
        };
        search.TextChanged += (_, _) => DebounceFilter();
        protocol.SelectedIndexChanged += (_, _) => DebounceFilter();
        incomplete.CheckedChanged += (_, _) => DebounceFilter();
        grid.CurrentCellChanged += (_, _) => ShowSelection();
        previous.Click += async (_, _) =>
        {
            if (page > 0)
                --page;
            await RefreshAsync(clear: true);
        };
        next.Click += async (_, _) =>
        {
            if (rows.Count == 0)
                return;
            var last = rows[^1];
            if (pages.Count > page + 1)
                pages.RemoveRange(page + 1, pages.Count - page - 1);
            pages.Add(new PageCursor(last.FirstUs, last.Id));
            ++page;
            await RefreshAsync(clear: true);
        };
        debounce.Tick += async (_, _) =>
        {
            debounce.Stop();
            ResetPages();
            await RefreshWorkspaceAsync(clear: true);
        };
        timer.Tick += async (_, _) =>
        {
            if (live.Checked && !loading && !debounce.Enabled)
            {
                if (tabs.SelectedIndex == 0 && page == 0)
                    await RefreshAsync(streaming: true);
                else if (tabs.SelectedIndex != 0)
                    await RefreshActiveViewAsync(false);
            }
        };
        journalDebounce.Tick += async (_, _) =>
        {
            journalDebounce.Stop();
            if (live.Checked && page == 0 && !loading && !debounce.Enabled)
                await RefreshWorkspaceAsync(streaming: true);
        };
        live.CheckedChanged += async (_, _) =>
        {
            if (!live.Checked)
            {
                ++generation;
                cancellation?.Cancel();
                loading = false;
                refresh.Enabled = true;
                visualization.Pause();
                analytics.Pause();
                endpoints.Pause();
                readiness.Pause();
                certificates.Pause();
                policies.Pause();
            }
            if (live.Checked && page == 0)
                await RefreshWorkspaceAsync();
            UpdatePageLabel();
        };
        KeyDown += async (_, e) =>
        {
            if (e.Control && e.KeyCode == Keys.O)
            {
                e.SuppressKeyPress = true;
                OpenDatabase();
            }
            else if (e.KeyCode == Keys.F1)
            {
                e.SuppressKeyPress = true;
                help.PerformClick();
            }
            else if (e.KeyCode == Keys.F5)
            {
                e.SuppressKeyPress = true;
                await RefreshWorkspaceAsync();
            }
        };
        FormClosing += async (_, e) =>
        {
            if (closeReady)
                return;
            e.Cancel = true;
            if (closing)
                return;
            closing = true;
            ++generation;
            timer.Stop();
            debounce.Stop();
            journalDebounce.Stop();
            journalWatcher?.Dispose();
            cancellation?.Cancel();
            detailCancellation?.Cancel();
            exportCancellation?.Cancel();
            visualization.Pause();
            analytics.Pause();
            endpoints.Pause();
            readiness.Pause();
            certificates.Pause();
            policies.Pause();
            Enabled = false;
            status.Text = "Closing…";

            // Keep the UI context alive until cancelled queries have finished their continuations.
            while (operations.Count != 0)
            {
                try { await Task.WhenAll(operations.ToArray()); }
                catch (Exception) {}
                await Task.Yield();
            }
            await Task.WhenAll(readiness.DrainAsync(), certificates.DrainAsync(), policies.DrainAsync());
            closeReady = true;
            Close();
        };
        SystemEvents.UserPreferenceChanged += OnSystemThemeChanged;
        FontChanged += (_, _) => UpdateTextMetrics();
        DpiChanged += (_, _) => UpdateTextMetrics();
        UpdateTextMetrics();
        UiTheme.Apply(this, this.settings.Theme);
        Shown += async (_, _) =>
        {
            var desktop = Screen.FromControl(this).WorkingArea;
            Size = new Size(Math.Min(Width, desktop.Width), Math.Min(Height, desktop.Height));
            if (initialSource is not null)
            {
                SetSource(initialSource);
                await RefreshAsync(clear: true);
            }
            if (smokePath is not null)
                await VerifyUiAsync();
            else
                timer.Start();
            if (this.settings.Warning is { } warning)
                status.Text = warning;
        };
        if (smokePath is not null)
        {
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            Location = new Point(-20000, -20000);
        }
    }

    protected override bool ProcessCmdKey(ref Message message, Keys keyData)
    {
        if (keyData == (Keys.Control | Keys.F) && search.Enabled && search.Visible)
        {
            search.Focus();
            search.SelectAll();
            return true;
        }
        if (keyData == Keys.Escape && search.ContainsFocus && search.TextLength > 0)
        {
            search.Clear();
            return true;
        }
        return base.ProcessCmdKey(ref message, keyData);
    }

    private void ResetPages()
    {
        page = 0;
        pages.Clear();
        pages.Add(PageCursor.Newest);
    }

    private void OnSystemThemeChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (settings.Theme == "System" && IsHandleCreated && !IsDisposed)
            BeginInvoke(ApplyTheme);
    }

    private void ApplyTheme()
    {
        var previousDark = UiTheme.Dark;
        UiTheme.Select(settings.Theme);
        if (previousDark != UiTheme.Dark && IsHandleCreated)
            RecreateHandle();
        UiTheme.Apply(this);
    }

    private void ApplyColumns()
    {
        grid.CurrentCell = null;
        foreach (var (column, index) in settings.Columns.Select((column, index) => (column, index)))
        {
            var item = grid.Columns[column.Name]!;
            item.Visible = column.Visible;
            item.Width = Math.Max(item.MinimumWidth, column.Width * DeviceDpi / 96);
            item.DisplayIndex = index;
        }
    }

    private Query CurrentQuery() => (tabs.SelectedIndex == 3 ? endpointScope : connectionScope) with
    {
        Search = search.Text.Trim(),
        Protocol = tabs.SelectedIndex == 3 ? endpointScope.Protocol : protocol.SelectedIndex == 0 ? "" : protocol.Text,
        Incomplete = tabs.SelectedIndex != 3 && incomplete.Checked, Before = pages[page], PageSize = settings.PageSize
    };

    private void OpenFilters()
    {
        var target = tabs.SelectedIndex == 3 ? InvestigationTarget.Endpoints : InvestigationTarget.Connections;
        try
        {
            using var dialog = new FilterDialog(settings, CurrentQuery(), target, Font);
            if (dialog.ShowDialog(this) == DialogResult.OK && dialog.SelectedQuery is { } query)
                ApplyFilters(query, target);
        }
        catch (Exception error) when (error is ArgumentException or InvalidDataException)
        { status.Text = "Filters could not be opened. " + error.Message; }
    }

    internal void ApplyFilters(Query query, InvestigationTarget target)
    {
        query.Validate(target);
        if (target == InvestigationTarget.Endpoints)
            endpointScope = query.CopyScope();
        else
        {
            connectionScope = query.CopyScope();
            if (query.Protocol.Length > 0 && !protocol.Items.Contains(query.Protocol))
                protocol.Items.Add(query.Protocol);
            protocol.SelectedItem = query.Protocol.Length == 0 ? FilterDialog.ProtocolNames[0] : query.Protocol;
            incomplete.Checked = query.Incomplete;
        }
        search.Text = query.Search;
        DebounceFilter();
        UpdateFilterHint();
    }

    private void UpdateFilterHint()
    {
        var query = CurrentQuery();
        var text = $"{query.Conditions.Count} field conditions" + (query.HasDateRange ? " · Explicit dates (UTC)" : "") +
            ". Set dates and field conditions, or load a saved search.";
        hints.SetToolTip(filterDialog, text);
        filterDialog.AccessibleDescription = text;
        filterDialog.Text = query.HasAdvancedFilters ? "&Filters… *" : "&Filters…";
    }

    private void UpdateReportAction()
    {
        report.Visible = exportCancellation is not null || source is not null && tabs.SelectedIndex is 0 or 3 or 6;
        report.Enabled = source is not null;
        report.Text = exportCancellation is null ? "&Bulk export…" : "Cancel &bulk export";
        UpdateFilterHint();
    }

    private async Task ExportReportAsync()
    {
        if (exportCancellation is not null)
        {
            exportCancellation.Cancel();
            return;
        }
        var kind = tabs.SelectedIndex switch { 3 => ReportKind.Endpoints, 6 => ReportKind.Policies, _ => ReportKind.Connections };
        using var dialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|JSON Lines (*.jsonl)|*.jsonl", DefaultExt = "csv",
            FileName = "Cipherazzi-" + kind.ToString().ToLowerInvariant() + ".csv",
            Title = "Export all matching " + kind.ToString().ToLowerInvariant()
        };
        if (dialog.ShowDialog(this) == DialogResult.OK)
            await ExportMatchingAsync(dialog.FileName, kind);
    }

    internal async Task<long?> ExportMatchingAsync(string path, ReportKind kind)
    {
        if (source is not { } selected || exportCancellation is not null)
            return null;
        var query = CurrentQuery().CopyScope();
        if (kind == ReportKind.Policies)
            query = policies.ExportQuery(query);
        var rules = settings.ScopedPolicies.Select(policy => policy.Clone()).ToArray();
        using var cancellation = new CancellationTokenSource();
        exportCancellation = cancellation;
        UpdateReportAction();
        status.ForeColor = UiTheme.Foreground;
        status.Text = "Exporting matching evidence…";
        try
        {
            var progress = new Progress<long>(count =>
            {
                if (!closing && ReferenceEquals(exportCancellation, cancellation))
                    status.Text = $"Exporting matching evidence… {count:N0} rows";
            });
            var count = await Task.Run(() => ReportExport.Write(selected, query, kind, path, rules,
                cancellation.Token, progress), cancellation.Token);
            if (!closing)
                status.Text = $"Exported {count:N0} rows to {Path.GetFileName(path)}.";
            return count;
        }
        catch (OperationCanceledException)
        {
            if (!closing)
                status.Text = "Export cancelled.";
            return null;
        }
        catch (Exception error)
        {
            if (!closing)
            {
                status.ForeColor = UiTheme.Error;
                status.Text = "Export could not be saved. " + error.Message;
            }
            return null;
        }
        finally
        {
            exportCancellation = null;
            if (!closing)
                UpdateReportAction();
        }
    }

    private void ClearFilters()
    {
        // Clear the active investigation's shared filters through the ordinary refresh path.
        search.Clear();
        if (tabs.SelectedIndex == 3)
            endpointScope = new("", "", false, PageCursor.Newest);
        else
            connectionScope = new("", "", false, PageCursor.Newest);
        protocol.SelectedIndex = 0;
        incomplete.Checked = false;
        DebounceFilter();
    }

    private async Task TrackAsync(Task operation)
    {
        operations.Add(operation);
        try { await operation; }
        finally { operations.Remove(operation); }
    }

    private Task RefreshActiveViewAsync(bool force) => closing ? Task.CompletedTask :
        TrackAsync(tabs.SelectedIndex switch
    {
        1 => visualization.RefreshAsync(source, CurrentQuery(), force),
        2 => analytics.RefreshAsync(source, CurrentQuery(), force),
        3 => endpoints.RefreshAsync(source, CurrentQuery(), force),
        4 => readiness.RefreshAsync(source, CurrentQuery(), force),
        5 => certificates.RefreshAsync(source, CurrentQuery(), force),
        6 => policies.RefreshAsync(source, CurrentQuery(), force),
        _ => Task.CompletedTask
    });

    private Task RefreshWorkspaceAsync(bool clear = false, bool streaming = false) => tabs.SelectedIndex == 0 ?
        RefreshAsync(clear, streaming) : RefreshActiveViewAsync(!streaming);

    private void UpdateTextMetrics()
    {
        // Keep native text and row heights usable as Windows text size or monitor DPI changes.
        var spacing = Math.Max(1, DeviceDpi / 96f);
        var protocolWidth = protocol.Items.Cast<object>().Max(item =>
            TextRenderer.MeasureText(item.ToString(), Font).Width) + (int)(32 * spacing);
        protocol.MinimumSize = new Size(protocolWidth, 0);
        protocol.Width = protocolWidth;
        grid.ColumnHeadersHeight = Font.Height + (int)(6 * spacing);
        grid.RowTemplate.Height = Font.Height + (int)(4 * spacing);
        foreach (DataGridViewColumn column in grid.Columns)
            column.MinimumWidth = Math.Max((int)(60 * spacing),
                TextRenderer.MeasureText(column.HeaderText, Font).Width + (int)(12 * spacing));
        grid.Columns["Time"]!.MinimumWidth = TextRenderer.MeasureText("00:00:00.000", Font).Width + (int)(8 * spacing);
        foreach (DataGridViewRow row in grid.Rows)
            row.Height = grid.RowTemplate.Height;
        status.Height = Font.Height + (int)(6 * spacing);
    }

    private void DebounceFilter()
    {
        // A changed filter invalidates in-flight results immediately, before the debounced query starts.
        ++generation;
        cancellation?.Cancel();
        loading = false;
        ResetPages();
        rows = [];
        grid.RowCount = 0;
        grid.SetEmptyState("Filtering connections…", "Updating observations for the selected filters.");
        previous.Enabled = next.Enabled = false;
        details.Clear("Filtering observations…");
        detailKey = "";
        detailCancellation?.Cancel();
        visualization.Reset();
        analytics.Reset();
        endpoints.Reset();
        readiness.Reset();
        certificates.Reset();
        policies.Reset();
        status.Text = "Filtering observations…";
        debounce.Stop();
        debounce.Start();
        UpdateFilterHint();
    }

    private void SetSource(DatabaseSource selected)
    {
        exportCancellation?.Cancel();
        source = selected;
        refresh.Visible = live.Visible = health.Visible = true;
        navigation.Visible = tabs.SelectedIndex == 0;
        refresh.Enabled = live.Enabled = health.Enabled = filters.Enabled = true;
        UpdateReportAction();
        visualization.Reset();
        analytics.Reset();
        endpoints.Reset();
        readiness.SetSource(selected);
        certificates.SetSource(selected);
        policies.SetSource(selected);
        detailKey = "";
        detailCancellation?.Cancel();
        databaseLabel.Text = selected.DisplayName;
        hints.SetToolTip(databaseLabel, selected.DisplayName);
        revision = -1;
        journalWatcher?.Dispose();
        journalWatcher = null;
        if (selected.Provider == DatabaseProvider.Sqlite)
        {
            // File notifications reduce local latency; the durable revision and timer recover missed notifications.
            journalWatcher = new FileSystemWatcher(Path.GetDirectoryName(selected.FilePath)!,
                Path.GetFileName(selected.FilePath) + "*")
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                SynchronizingObject = this, EnableRaisingEvents = true
            };
            FileSystemEventHandler changed = (_, _) =>
            {
                if (!IsDisposed && !journalDebounce.Enabled)
                    journalDebounce.Start();
            };
            journalWatcher.Changed += changed;
            journalWatcher.Created += changed;
        }
        ResetPages();
    }

    private async void OpenDatabase()
    {
        using var dialog = new ConnectionDialog(source) { Font = Font };
        UiTheme.Apply(dialog, settings.Theme);
        if (dialog.ShowDialog(this) != DialogResult.OK || dialog.Source is null)
            return;
        SetSource(dialog.Source);
        diagnostics = "Loading capture health…";
        await RefreshAsync(clear: true);
    }

    private ConnectionRow? SelectedRow => grid.CurrentRow is { Index: >= 0 } current && current.Index < rows.Count ?
        rows[current.Index] : null;

    private void UpdatePageLabel()
    {
        pageLabel.Text = $"Page {page + 1}  •  {rows.Count:N0} observations  •  " +
            (page > 0 ? "Viewer updates: historical page" : live.Checked ? "Viewer updates: live" :
                "Viewer updates: paused");
    }

    private Task RefreshAsync(bool clear = false, bool streaming = false) =>
        TrackAsync(LoadConnectionsAsync(clear, streaming));

    private async Task LoadConnectionsAsync(bool clear, bool streaming)
    {
        if (source is null || IsDisposed || closing)
            return;
        cancellation?.Cancel();
        cancellation?.Dispose();
        cancellation = new CancellationTokenSource();
        var token = cancellation.Token;
        var current = ++generation;
        loading = true;
        if (!streaming)
        {
            refresh.Enabled = previous.Enabled = next.Enabled = false;
            status.Text = "Loading observations…";
        }
        if (clear)
        {
            revision = -1;
            rows = [];
            grid.RowCount = 0;
            grid.SetEmptyState("Loading connections…", "Reading observations from the connected database.");
            details.Clear("Loading observations…");
            pageLabel.Text = "Loading…";
        }
        var query = CurrentQuery();
        var selectedSource = source;
        var knownRevision = streaming && DateTime.UtcNow - healthRefreshed < TimeSpan.FromSeconds(5) ? revision : -1;
        try
        {
            var snapshot = await Task.Run(() => Database.ReadIfChanged(selectedSource, query, token, knownRevision), token);
            if (current != generation || IsDisposed || snapshot is null || streaming && !live.Checked)
                return;

            // Apply a bounded window in place so selection and the reader's scroll position survive new arrivals.
            var selected = SelectedRow?.Id;
            var firstVisible = grid.FirstDisplayedScrollingRowIndex;
            var firstVisibleId = firstVisible > 0 && firstVisible < rows.Count ? rows[firstVisible].Id : (long?)null;
            var horizontalOffset = grid.HorizontalScrollingOffset;
            applying = true;
            rows = snapshot.Rows;
            foreach (var row in rows)
            {
                row.Values["Findings"] = string.Join("; ", ObservationDetails.Findings(row.Values, settings.Policy));
            }
            grid.RowCount = rows.Count;
            grid.SetEmptyState("No matching connections",
                "Clear filters or include partial exchanges to broaden the view.",
                "Clear filters", ClearFilters);
            if (selected is not null)
            {
                var index = rows.FindIndex(row => row.Id == selected);
                if (index >= 0)
                    grid.CurrentCell = grid.Rows[index].Cells[grid.CurrentCell?.ColumnIndex ??
                        grid.Columns.GetFirstColumn(DataGridViewElementStates.Visible)!.Index];
                else
                    grid.CurrentCell = null;
            }
            if (rows.Count != 0)
            {
                var index = firstVisibleId is null ? 0 : rows.FindIndex(row => row.Id == firstVisibleId);
                grid.FirstDisplayedScrollingRowIndex = Math.Max(0, index);
            }
            grid.HorizontalScrollingOffset = horizontalOffset;
            grid.Invalidate();
            applying = false;
            ShowSelection();
            revision = snapshot.Revision;
            healthRefreshed = DateTime.UtcNow;
            status.ForeColor = UiTheme.Foreground;
            status.Text = snapshot.Health.Replace("Latest session:", "Capture session:", StringComparison.Ordinal) +
                $" · Checked {DateTime.Now:T}";
            hints.SetToolTip(status, status.Text);
            diagnostics = snapshot.Diagnostics;
            next.Enabled = snapshot.HasMore;
            previous.Enabled = page > 0;
            UpdatePageLabel();
            await RefreshActiveViewAsync(!streaming);
        }
        catch (OperationCanceledException) {}
        catch (Exception error)
        {
            if (current != generation || IsDisposed)
                return;
            revision = -1;
            status.ForeColor = UiTheme.Error;
            status.Text = streaming ? "Database query failed · retrying…" : "Database query failed. Refresh to retry.";
            diagnostics = error.Message;
            if (clear)
            {
                details.Clear(error.Message);
                pageLabel.Text = "No observations";
                grid.SetEmptyState("Connections unavailable", "Check the database connection and refresh to retry.",
                    "Refresh", () => refresh.PerformClick());
            }
        }
        finally
        {
            if (current == generation && !IsDisposed)
            {
                applying = false;
                loading = false;
                refresh.Enabled = true;
            }
        }
    }

    private async void ShowSelection() => await TrackAsync(LoadSelectionAsync());

    private async Task LoadSelectionAsync()
    {
        if (applying || closing)
            return;
        if (SelectedRow is not { } row)
        {
            detailKey = "";
            detailCancellation?.Cancel();
            details.Clear(rows.Count == 0 ? "No matching observations." : "No observation selected.");
            return;
        }
        var key = source?.DisplayName + row.Id + string.Join('|', row.Certificates);
        var title = (row.Sni == "—" ? row.Destination : row.Sni) + " · " + row.Tls;

        // Summarize recorded algorithms and outcomes without inferring success from visible negotiation messages.
        var findings = row.Value("Findings");
        var authentication = row.Value("EndpointSignature");
        if (authentication is "" or "Not observed")
            authentication = row.Value("Protocol") == "SSH" ? row.Value("Authentication") : row.Value("Signature");
        if (authentication is "" or "Encrypted")
            authentication = "Not observed";
        string Evidence(string name) => row.Value(name) is { Length: > 0 } value ? value : "Not observed";
        var cipher = row.Value("Cipher") is "" or "Not observed" or "—" ? Evidence("Encryption") : row.Value("Cipher");
        var overview = "Protocol / algorithm findings: " + (findings.Length == 0 ? "None" : findings) +
            $"\nCipher: {cipher} · Keys: {Evidence("Group")} ({Evidence("GroupClass")})" +
            $"\nHandshake auth: {authentication} · Endpoint: {Evidence("Confirmation")}";
        if (row.Value("Protocol") == "Unknown")
            title += " · " + row.State;
        if (key == detailKey)
        {
            details.Show(row.Id.ToString(), title,
                [.. row.Properties, .. certificateProperties], row.Certificates, overview);
            return;
        }
        detailKey = key;
        certificateProperties = [];
        detailCancellation?.Cancel();
        detailCancellation?.Dispose();
        detailCancellation = new();
        var token = detailCancellation.Token;
        details.Show(row.Id.ToString(), title, row.Properties, summary: overview);
        if (row.Certificates.Length == 0 || source is null)
            return;
        var selectedSource = source;
        try
        {
            var properties = await Task.Run(() => Insights.ReadCertificates(selectedSource, row.Certificates, token), token);
            if (IsDisposed || key != detailKey || token.IsCancellationRequested || SelectedRow?.Id != row.Id)
                return;
            certificateProperties = properties;
            details.Show(row.Id.ToString(), title,
                [.. SelectedRow.Properties, .. properties], row.Certificates, overview);
        }
        catch (OperationCanceledException) {}
        catch (Exception error)
        {
            if (!IsDisposed && key == detailKey && !token.IsCancellationRequested)
                details.Show(row.Id.ToString(), row.Sni, [.. row.Properties,
                    new("Certificates", "Read status", error.Message)]);
        }
    }

    private async Task OpenCertificateAsync(string hash)
    {
        if (details.CertificateBusy || SelectedRow is not { } row || source is not { } selectedSource)
            return;
        details.CertificateBusy = true;
        status.Text = "Loading public certificate data…";
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            detailCancellation?.Token ?? CancellationToken.None);
        cancellation.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            // Read and validate the linked certificate without blocking selection or collection.
            var der = await Task.Run(() => CertificateInventory.ReadDer(selectedSource, hash, cancellation.Token),
                cancellation.Token);
            if (closing || IsDisposed || source != selectedSource || SelectedRow?.Id != row.Id ||
                cancellation.IsCancellationRequested)
                return;
            using var certificate = X509CertificateLoader.LoadCertificate(der);
            X509Certificate2UI.DisplayCertificate(certificate, Handle);
            if (!closing && !IsDisposed && source == selectedSource)
                status.Text = "Public certificate opened.";
        }
        catch (OperationCanceledException) {}
        catch (Exception error)
        {
            if (!closing && !IsDisposed && source == selectedSource && SelectedRow?.Id == row.Id)
                status.Text = "Certificate could not be opened. " + error.Message;
        }
        finally
        {
            if (!IsDisposed)
                details.CertificateBusy = false;
        }
    }

    private void ShowText(string title, string text)
    {
        using var dialog = new Form
        {
            Text = title, Font = Font, ClientSize = new Size(820, 510), MinimumSize = new Size(600, 360),
            StartPosition = FormStartPosition.CenterParent, Padding = new Padding(16),
            MinimizeBox = false, MaximizeBox = false
        };
        dialog.Controls.Add(new TextBox
        {
            Text = text.ReplaceLineEndings(), Multiline = true, ReadOnly = true, Dock = DockStyle.Fill,
            ScrollBars = ScrollBars.Vertical, BackColor = SystemColors.Window
        });
        UiTheme.Apply(dialog, settings.Theme);
        dialog.ShowDialog(this);
    }

    private async Task VerifyUiAsync()
    {
        try
        {
            void SaveLayout(string path)
            {
                PerformLayout();
                foreach (var control in new Control[]
                {
                    search, protocol, incomplete, live, refresh, previous, next, pageLabel,
                    databaseLabel, status, grid, details
                })
                {
                    var bounds = RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
                    if (!ClientRectangle.Contains(bounds))
                        throw new InvalidOperationException($"The {control.GetType().Name} layout exceeds the window.");
                }
                using var bitmap = new Bitmap(Width, Height);
                DrawToBitmap(bitmap, new Rectangle(0, 0, Width, Height));
                bitmap.Save(path, System.Drawing.Imaging.ImageFormat.Png);
            }
            void ResizeWithinDesktop(Size desired)
            {
                var desktop = Screen.FromControl(this).WorkingArea;
                ClientSize = new Size(Math.Min(desired.Width, desktop.Width - Width + ClientSize.Width),
                    Math.Min(desired.Height, desktop.Height - Height + ClientSize.Height));
            }
            if (rows.Count == 0)
                throw new InvalidOperationException("The UI verification database must contain observations.");
            if (next.Enabled)
            {
                var firstPage = rows.Select(row => row.Id).ToHashSet();
                next.PerformClick();
                for (var attempt = 0; loading && attempt < 200; ++attempt)
                    await Task.Delay(25);
                if (loading || page != 1 || rows.Count == 0 || rows.Any(row => firstPage.Contains(row.Id)))
                    throw new InvalidOperationException("Older-page navigation failed.");
                previous.PerformClick();
                for (var attempt = 0; loading && attempt < 200; ++attempt)
                    await Task.Delay(25);
                if (loading || page != 0 || !rows.Select(row => row.Id).ToHashSet().SetEquals(firstPage))
                    throw new InvalidOperationException("Newer-page navigation failed.");
            }
            // Exercise layout and an actual filtered database refresh before rendering the form.
            search.Text = "no-match-cipherazzi-ui-test";
            debounce.Stop();
            await RefreshAsync(clear: true);
            if (rows.Count != 0)
                throw new InvalidOperationException("Search did not clear the displayed observations.");
            search.Clear();
            debounce.Stop();
            await RefreshAsync(clear: true);
            var certificateRow = rows.FindIndex(row => row.Certificates.Length != 0);
            if (certificateRow >= 0)
            {
                grid.CurrentCell = grid.Rows[certificateRow].Cells[grid.Columns.Cast<DataGridViewColumn>()
                    .First(column => column.Visible).Index];
                for (var attempt = 0; certificateProperties.Count == 0 && attempt < 200; ++attempt)
                    await Task.Delay(25);
                if (certificateProperties.Count == 0)
                    throw new InvalidOperationException("The selected certificate properties were not loaded.");
            }
            SaveLayout(smokePath!);
            File.WriteAllText(smokePath! + ".txt", $"Rows: {rows.Count}\n{status.Text}\n{details.Summary}");
            ResizeWithinDesktop(new Size(1000, 650));
            await RefreshAsync();
            SaveLayout(smokePath! + ".compact.png");
            Font = new Font("Segoe UI", 12);
            ResizeWithinDesktop(new Size(1600, 1050));
            await RefreshAsync();
            SaveLayout(smokePath! + ".text.png");
            Font = new Font("Segoe UI", 9);
            settings.Theme = "Dark";
            ApplyTheme();
            SaveLayout(smokePath! + ".dark.png");
            foreach (var index in new[] { 1, 2, 3 })
            {
                tabs.SelectedIndex = index;
                await RefreshActiveViewAsync(true);
                using var bitmap = new Bitmap(Width, Height);
                DrawToBitmap(bitmap, new Rectangle(0, 0, Width, Height));
                bitmap.Save(smokePath! + $".tab-{index}.png", System.Drawing.Imaging.ImageFormat.Png);
            }
        }
        catch (Exception error)
        {
            ExitCode = 1;
            File.WriteAllText(smokePath! + ".txt", error.ToString());
        }
        finally { Close(); }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            timer.Dispose();
            debounce.Dispose();
            journalDebounce.Dispose();
            hints.Dispose();
            journalWatcher?.Dispose();
            cancellation?.Cancel();
            cancellation?.Dispose();
            cancellation = null;
            detailCancellation?.Cancel();
            detailCancellation?.Dispose();
            detailCancellation = null;
            SystemEvents.UserPreferenceChanged -= OnSystemThemeChanged;
        }
        base.Dispose(disposing);
        if (disposing)
            applicationIcon.Dispose();
    }
}
