namespace Cipherazzi.Viewer;

internal sealed class ReadinessView : InvestigationView
{
    private readonly ComboBox window;
    private readonly ChoiceBox dimension = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = true };
    private readonly NumericUpDown samples = new() { Minimum = 1, Maximum = 1000000, Width = 85, AutoSize = true };
    private readonly Label summary = new() { AutoSize = true, Dock = DockStyle.Fill, UseMnemonic = false,
        Margin = new Padding(3, 5, 3, 6), Text = "TLS readiness is based on observed traffic and reported endpoint results." };
    private readonly EvidenceCard keyEvidence = new("Key establishment");
    private readonly EvidenceCard authEvidence = new("Handshake authentication");
    private readonly EvidenceCard completionEvidence = new("Endpoint completion");
    private readonly ResultGrid grid = new() { Name = "ReadinessGrid", AccessibleName = "PQC readiness by observed cohort" };
    private readonly ResultGrid coverage = new() { Name = "CoverageGrid", AccessibleName = "Capture coverage by computer" };
    private readonly ResultGrid changes = new() { Name = "BaselineGrid", AccessibleName = "Changes from migration baseline" };
    private readonly PropertyInspector details = new();
    private readonly CommandButton capture = new() { Text = "Capture &baseline…", AutoSize = true, Enabled = false };
    private readonly Label baselineLabel = new() { AutoSize = true, Dock = DockStyle.Fill, UseMnemonic = false,
        Text = "No baseline loaded. Changes describe observations; they do not establish an attack." };
    private MigrationBaseline? baseline;
    private bool fixedRange;
    private int BaselineMinutes => fixedRange ? 0 : WindowMinutes(window);
    public PqcSnapshot? Snapshot { get; private set; }
    protected override string ScopeKey => window.SelectedIndex + "\0" + dimension.Text;

    public ReadinessView(ViewerSettings settings) : base(settings)
    {
        window = WindowChoice();
        dimension.Items.AddRange(PqcInsights.Dimensions);
        dimension.SelectedIndex = 0;
        dimension.AccessibleName = "Readiness grouping";
        samples.Value = settings.BaselineMinimumSamples;
        samples.AccessibleName = "Minimum observations in each baseline cohort";
        var load = new CommandButton { Text = "Lo&ad baseline…", AutoSize = true };
        var tools = Toolbar();
        tools.Controls.Add(Choice("&Time range", window));
        tools.Controls.Add(Choice("&Group by", dimension));
        tools.Controls.Add(capture);
        tools.Controls.Add(load);
        tools.Controls.Add(Choice("&Min. samples", samples));
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5 };
        root.ColumnStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.RowStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.Controls.Add(tools, 0, 0);
        root.Controls.Add(summary, 0, 1);
        var metrics = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 3,
            Margin = Padding.Empty };
        for (var index = 0; index < 3; ++index)
            metrics.ColumnStyles.Add(new(SizeType.Percent, 100f / 3));
        metrics.Controls.Add(keyEvidence, 0, 0);
        metrics.Controls.Add(authEvidence, 1, 0);
        metrics.Controls.Add(completionEvidence, 2, 0);
        root.Controls.Add(metrics, 0, 2);
        root.Controls.Add(Status, 0, 4);
        foreach (var table in new[] { grid, coverage, changes })
            AnalyticsView.ConfigureGrid(table);
        foreach (var column in new[]
        {
            Column("Computer", "Computer", 125), Column("Application", "Application", 170),
            Column("Peer", "Server", 170), Column("Transport", "Transport", 80),
            Column("Total", "Observations", 100, true), Column("PqKey", "PQ keys %", 90),
            Column("PqAuth", "PQ auth %", 90), Column("Complete", "Completed %", 105),
            Column("UnknownKey", "Unknown keys %", 130), Column("UnknownAuth", "Unknown auth %", 135),
            Column("Classical", "Classical keys", 130, true), Column("ChainPq", "PQ chain signatures %", 180)
        })
            grid.Columns.Add(column);
        foreach (var name in new[] { "Computer", "Transport", "Classical", "ChainPq" })
            grid.Columns[name]!.Visible = false;
        foreach (var name in new[] { "PqKey", "PqAuth", "Complete", "UnknownKey", "UnknownAuth", "ChainPq" })
        {
            grid.Columns[name]!.ValueType = typeof(double);
            grid.Columns[name]!.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
            grid.Columns[name]!.DefaultCellStyle.Format = "N1";
        }
        grid.Columns["PqKey"]!.ToolTipText = "PQ and hybrid key establishment as a percentage of all observations.";
        grid.Columns["PqAuth"]!.ToolTipText = "Observed PQ server handshake signatures; certificate signatures are assessed separately.";
        foreach (var column in new[]
        {
            Column("Computer", "Computer", 160), Column("Sessions", "Sessions", 95, true),
            Column("Packets", "Packets", 130, true), Column("Losses", "Losses / errors", 140, true),
            Column("Truncated", "Truncated", 120, true), Column("Limits", "Inspection limits", 150, true),
            Column("Updated", "Last heartbeat", 220), Column("Status", "Scope", 300)
        })
            coverage.Columns.Add(column);
        foreach (var column in new[]
        {
            Column("Computer", "Computer", 140), Column("Application", "Application", 230),
            Column("Peer", "Server", 180), Column("Change", "Observed change", 380),
            Column("Before", "Baseline samples", 150, true), Column("After", "Current samples", 150, true),
            Column("FirstPercent", "Before %", 105), Column("LastPercent", "After %", 105)
        })
            changes.Columns.Add(column);
        foreach (var table in new[] { grid, coverage, changes })
            ConfigureColumns(table);
        foreach (DataGridViewColumn column in grid.Columns)
            column.FillWeight = column.Width;
        grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal,
            SplitterWidth = 5, Size = new Size(1200, 600), SplitterDistance = 355, Panel1MinSize = 100, Panel2MinSize = 120 };
        split.Panel1.Controls.Add(grid);
        split.Panel2.Controls.Add(details);
        details.Clear("Select a cohort to inspect evidence counts and gaps.");
        var views = new WorkspaceTabs { Dock = DockStyle.Fill };
        foreach (var (name, control) in new (string, Control)[] { ("Readiness", split), ("Capture coverage", coverage) })
        {
            var tab = new TabPage(name);
            tab.Controls.Add(control);
            views.TabPages.Add(tab);
        }
        var baselinePage = new TabPage("Baseline changes");
        var baselineRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        baselineRoot.ColumnStyles.Add(new(SizeType.Percent, 100));
        baselineRoot.RowStyles.Add(new(SizeType.AutoSize));
        baselineRoot.RowStyles.Add(new(SizeType.Percent, 100));
        baselineRoot.Controls.Add(baselineLabel, 0, 0);
        baselineRoot.Controls.Add(changes, 0, 1);
        baselinePage.Controls.Add(baselineRoot);
        views.TabPages.Add(baselinePage);
        root.Controls.Add(views, 0, 3);
        Controls.Add(root);
        dimension.SelectedIndexChanged += (_, _) => { Reset(); RequestRefresh(); };
        void Metrics() => dimension.Width = dimension.Items.Cast<object>().Max(item =>
            TextRenderer.MeasureText(item.ToString(), dimension.Font).Width) + 32 * dimension.DeviceDpi / 96;
        dimension.FontChanged += (_, _) => Metrics();
        dimension.DpiChangedAfterParent += (_, _) => Metrics();
        Metrics();
        grid.CurrentCellChanged += (_, _) => Selection();
        samples.ValueChanged += (_, _) => UpdateComparison();
        capture.Click += async (_, _) => await TrackAsync(CaptureBaselineAsync());
        load.Click += async (_, _) => await TrackAsync(LoadBaselineAsync());
        grid.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && grid.Rows[e.RowIndex].Tag is ReadinessRow row && row.Peer.Length > 0)
                Filter(row.Peer[..row.Peer.LastIndexOf(':')]);
        };
        ClearResult();
    }

    protected override Func<CancellationToken, object> PrepareRead(DatabaseSource source, Query query)
    {
        fixedRange = query.HasDateRange;
        window.Parent!.Visible = !fixedRange;
        var minutes = WindowMinutes(window);
        var group = dimension.Text;
        var policies = Settings.ScopedPolicies.Select(policy => policy.Clone()).ToArray();
        var since = Since(minutes);
        return token => PqcInsights.Read(source, query, since, long.MaxValue, group, policies, token);
    }

    protected override DateTime NextTimedRefresh(object result) => fixedRange ? DateTime.MaxValue :
        NextWindowExpiry((PqcSnapshot)result, WindowMinutes(window));

    protected override void ApplyResult(object result)
    {
        Snapshot = (PqcSnapshot)result;
        grid.Columns["Computer"]!.Visible = dimension.Text == "Collector computer" ||
            Settings.ViewColumns.GetValueOrDefault(grid.Name)?.Any(column => column.Name == "Computer" && column.Visible) == true;
        grid.Columns["Application"]!.Visible = dimension.Text.EndsWith("application") &&
            Settings.ViewColumns.GetValueOrDefault(grid.Name)?.Any(column => column.Name == "Application" && !column.Visible) != true;
        grid.Columns["Peer"]!.Visible = dimension.Text != "Collector computer" &&
            Settings.ViewColumns.GetValueOrDefault(grid.Name)?.Any(column => column.Name == "Peer" && !column.Visible) != true;
        var selected = (grid.CurrentRow?.Tag as ReadinessRow)?.Key;
        grid.Rows.Clear();
        foreach (var row in Snapshot.Rows.Take(1000))
        {
            double Share(long count) => count * 100.0 / Math.Max(1, row.Total);
            var index = grid.Rows.Add(row.Computer, row.Application, row.Peer, row.Transport, row.Total, Share(row.PqKeys),
                Share(row.PqAuth), Share(row.Complete), Share(row.UnknownKeys), Share(row.UnknownAuth), row.ClassicalKeys,
                Share(row.Count("Presented server-chain signatures", "Post-quantum")));
            grid.Rows[index].Tag = row;
            if (row.Key == selected)
                grid.CurrentCell = FirstVisibleCell(grid.Rows[index]);
        }
        coverage.Rows.Clear();
        foreach (var row in Snapshot.Coverage)
            coverage.Rows.Add(row.Computer, row.Sessions, row.Packets, row.Losses, row.Truncated, row.InspectionLimits,
                CertificateInventory.At(row.LastUpdatedUs), row.Status);
        var total = Snapshot.Total;
        var completed = Snapshot.Rows.Sum(row => row.Complete);
        var failures = Snapshot.Rows.Sum(row => row.Failures);
        var unknownKeys = Snapshot.Rows.Sum(row => row.UnknownKeys);
        var unknownAuth = Snapshot.Rows.Sum(row => row.UnknownAuth);
        summary.Text = $"{total:N0} observations · {Snapshot.Rows.Count:N0} cohorts · " +
            "Unknown evidence remains in each percentage.";

        // Present key establishment, authentication, and completion as independent evidence dimensions.
        keyEvidence.Set($"PQ / hybrid: {Percent(Snapshot.Rows.Sum(row => row.PqKeys), total)}",
            $"Unknown: {Percent(unknownKeys, total)} · {unknownKeys:N0}/{total:N0}");
        authEvidence.Set($"Post-quantum: {Percent(Snapshot.Rows.Sum(row => row.PqAuth), total)}",
            $"Unknown: {Percent(unknownAuth, total)} · {unknownAuth:N0}/{total:N0}");
        completionEvidence.Set($"Completed: {Percent(completed, total)} · Failed: {Percent(failures, total)}",
            $"Unconfirmed / conflicting: {Percent(total - completed - failures, total)}");
        grid.SetEmptyState("No readiness observations", "Widen the time range or clear the current filters.",
            "Show all observations", () => { window.SelectedIndex = 3; ClearFilters(); });
        coverage.SetEmptyState("No capture coverage recorded", "Choose a journal with recorded capture-session health.",
            "Connect…", Connect);
        Status.Text = $"Showing {Math.Min(1000, Snapshot.Rows.Count):N0} cohorts. " +
            "Counts include unmatched endpoint reports; presented chains do not establish trust or include every trust anchor.";
        capture.Enabled = Snapshot.Total > 0;
        Selection();
        UpdateComparison();
    }

    private static string Percent(long count, long total) => total == 0 ? "—" : $"{count * 100.0 / total:N1}%";

    private void Selection()
    {
        if (grid.CurrentRow?.Tag is not ReadinessRow row)
            return;
        var values = new List<ObservationProperty>
        {
            new("Cohort", "Computer", row.Computer), new("Cohort", "Application", row.Application),
            new("Cohort", "Server", row.Peer), new("Cohort", "Transport", row.Transport),
            new("Cohort", "Observations", row.Total.ToString("N0")),
            new("Cohort", "First observed", CertificateInventory.At(row.FirstUs)),
            new("Cohort", "Last observed", CertificateInventory.At(row.LastUs))
        };
        foreach (var (key, count) in row.Counts.OrderBy(item => item.Key))
        {
            var separator = key.IndexOf(": ", StringComparison.Ordinal);
            values.Add(new(key[..separator], key[(separator + 2)..], $"{count:N0} ({Percent(count, row.Total)})",
                "Count among observations in this cohort. Unknown evidence is retained in the denominator."));
        }
        details.Show(row.Key, row.Computer + " · " + row.Application + " · " + row.Peer, values, summary:
            $"Key evidence unknown: {Percent(row.UnknownKeys, row.Total)} · Auth evidence unknown: " +
            $"{Percent(row.UnknownAuth, row.Total)}\n" +
            $"PQ / hybrid keys: {Percent(row.PqKeys, row.Total)} · PQ auth: {Percent(row.PqAuth, row.Total)}\n" +
            $"Endpoint completed: {Percent(row.Complete, row.Total)} · " +
            $"Endpoint failed: {Percent(row.Failures, row.Total)}");
    }

    private async Task CaptureBaselineAsync()
    {
        if (Snapshot is not { Total: > 0 })
            return;
        using var dialog = new SaveFileDialog { Filter = "Migration baseline (*.json)|*.json", FileName = "Cipherazzi-baseline.json" };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        await SaveBaselineAsync(dialog.FileName);
    }

    internal async Task SaveBaselineAsync(string path)
    {
        if (Snapshot is not { Total: > 0 } snapshot)
            return;
        try
        {
            var candidate = MigrationBaseline.Capture(snapshot, BaselineMinutes);
            Status.Text = "Saving migration baseline…";
            await candidate.SaveAsync(path, ClosingToken);
            if (IsDisposed || ClosingToken.IsCancellationRequested)
                return;
            baseline = candidate;
            Status.Text = "Migration baseline saved.";
            UpdateComparison();
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException)
        { if (!IsDisposed) Status.Text = "Baseline could not be saved. " + error.Message; }
        catch (OperationCanceledException) {}
    }

    private async Task LoadBaselineAsync()
    {
        using var dialog = new OpenFileDialog { Filter = "Migration baseline (*.json)|*.json" };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        await ImportBaselineAsync(dialog.FileName);
    }

    internal async Task ImportBaselineAsync(string path)
    {
        try
        {
            Status.Text = "Loading migration baseline…";
            var candidate = await MigrationBaseline.LoadAsync(path, ClosingToken);
            if (IsDisposed || ClosingToken.IsCancellationRequested)
                return;
            baseline = candidate;
            Status.Text = "Migration baseline loaded.";
            UpdateComparison();
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or
            System.Text.Json.JsonException)
        { if (!IsDisposed) Status.Text = "Baseline could not be loaded. " + error.Message; }
        catch (OperationCanceledException) {}
    }

    private void UpdateComparison()
    {
        changes.Rows.Clear();
        if (baseline is null || Snapshot is null)
        {
            baselineLabel.Text = baseline is null ? "No baseline loaded." : "Waiting for current observations.";
            changes.SetEmptyState(baseline is null ? "No baseline loaded" : "Waiting for current observations",
                "Load a saved baseline or capture one from the current readiness observations.",
                "Load baseline…", () => _ = TrackAsync(LoadBaselineAsync()));
            return;
        }
        try
        {
            var comparison = baseline.Compare(Snapshot, BaselineMinutes, (int)samples.Value);
            foreach (var row in comparison.Take(1000))
                changes.Rows.Add(row.Computer, row.Application, row.Peer, row.Change, row.BaselineObservations,
                    row.CurrentObservations, row.BeforePercent?.ToString("N1") ?? "—", row.AfterPercent?.ToString("N1") ?? "—");
            baselineLabel.Text = $"Baseline {baseline.CapturedUtc.ToLocalTime():g} · {comparison.Count:N0} changes · " +
                (baseline.DatabaseId == Snapshot.DatabaseId ? "Same journal. " : "Different journal. ") +
                "Traffic composition can affect comparisons; observed changes do not establish an attack.";
            changes.SetEmptyState("No qualifying baseline changes",
                "No cohort met the change and minimum-sample criteria in this time range.");
        }
        catch (InvalidDataException error) { baselineLabel.Text = error.Message; }
    }

    protected override void ClearResult()
    {
        Snapshot = null;
        grid.Rows.Clear();
        coverage.Rows.Clear();
        changes.Rows.Clear();
        capture.Enabled = false;
        details.Clear("Select a cohort to inspect evidence counts and gaps.");
        summary.Text = "Readiness is based on observed traffic and reported endpoint results.";
        foreach (var metric in new[] { keyEvidence, authEvidence, completionEvidence })
            metric.Set("—", "Evidence not loaded");
        grid.SetEmptyState(Source is null ? "Readiness needs observations" : "Loading readiness…",
            "Connect to a capture journal with cryptographic observations.", Source is null ? "Connect…" : "",
            Source is null ? Connect : null);
        coverage.SetEmptyState("No capture coverage loaded",
            "Capture health is recorded separately from viewer updates.");
        UpdateComparison();
    }
}
