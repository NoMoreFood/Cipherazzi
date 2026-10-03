namespace Cipherazzi.Viewer;

internal sealed class PoliciesView : InvestigationView
{
    private readonly ListBox list = new() { Dock = DockStyle.Fill, DisplayMember = nameof(CryptoPolicy.Name),
        IntegralHeight = false, AccessibleName = "Scoped cryptographic policies" };
    private readonly PropertyGrid editor = new() { Dock = DockStyle.Fill, ToolbarVisible = false, HelpVisible = true,
        PropertySort = PropertySort.Categorized, AccessibleName = "Cryptographic policy editor" };
    private readonly ComboBox window;
    private readonly ResultGrid grid = new() { Name = "PolicyGrid", AccessibleName = "Scoped policy results" };
    private readonly ResultGrid examples = new() { Name = "PolicyExamplesGrid", AccessibleName = "Policy evidence examples" };
    private readonly PropertyInspector details = new();
    private readonly Label note = new() { AutoSize = true, Dock = DockStyle.Fill, UseMnemonic = false,
        Text = "Matching protocol policies apply. Missing evidence is separate from observed violations." };
    private readonly CommandButton remove = new() { Text = "Re&move", AutoSize = true, Enabled = false };
    private readonly CommandButton apply = new() { Text = "Appl&y policies", AutoSize = true };
    private readonly List<CryptoPolicy> candidates;
    private List<PolicySummary> results = [];
    private bool fixedRange;
    public event Action? PoliciesChanged;
    protected override string ScopeKey => window.SelectedIndex.ToString();

    public PoliciesView(ViewerSettings settings) : base(settings)
    {
        candidates = settings.ScopedPolicies.Select(policy => policy.Clone()).ToList();
        window = WindowChoice();
        var tools = Toolbar();
        tools.Controls.Add(Choice("&Time range", window));
        var add = new CommandButton { Text = "&Add policy", AutoSize = true };
        var export = new CommandButton { Text = "&Export configuration…", AutoSize = true };
        tools.Controls.Add(add);
        tools.Controls.Add(remove);
        tools.Controls.Add(apply);
        tools.Controls.Add(export);
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
        root.ColumnStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.RowStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.Controls.Add(tools, 0, 0);
        root.Controls.Add(note, 0, 1);
        root.Controls.Add(Status, 0, 3);
        var split = new SplitContainer { Dock = DockStyle.Fill, SplitterWidth = 5, Size = new Size(1200, 600),
            SplitterDistance = 360, Panel1MinSize = 260, Panel2MinSize = 350 };
        var editRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        editRoot.ColumnStyles.Add(new(SizeType.Percent, 100));
        editRoot.RowStyles.Add(new(SizeType.Absolute, 105));
        editRoot.RowStyles.Add(new(SizeType.Percent, 100));
        editRoot.Controls.Add(list, 0, 0);
        editRoot.Controls.Add(editor, 0, 1);
        split.Panel1.Controls.Add(editRoot);
        foreach (var table in new[] { grid, examples })
            AnalyticsView.ConfigureGrid(table);
        foreach (var column in new[]
        {
            Column("Policy", "Policy", 180), Column("Applicable", "Applicable", 100, true),
            Column("Pass", "Pass", 80, true), Column("Violations", "Violations", 100, true),
            Column("Unknown", "Unknown", 95, true)
        })
            grid.Columns.Add(column);
        grid.Columns["Unknown"]!.ToolTipText = "Observations with insufficient evidence to determine compliance.";
        foreach (var column in new[]
        {
            Column("Observation", "Observation ID", 130, true), Column("Computer", "Computer", 140),
            Column("Application", "Application", 230), Column("Peer", "Server", 180),
            Column("Status", "Result", 175), Column("Reasons", "Findings", 500)
        })
            examples.Columns.Add(column);
        ConfigureColumns(grid);
        ConfigureColumns(examples);
        var right = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal,
            SplitterWidth = 5, Size = new Size(800, 600), SplitterDistance = 340, Panel1MinSize = 100, Panel2MinSize = 120 };
        var tabs = new WorkspaceTabs { Dock = DockStyle.Fill };
        foreach (var (name, table) in new[] { ("Policy results", grid), ("Evidence examples", examples) })
        {
            var tab = new TabPage(name);
            tab.Controls.Add(table);
            tabs.TabPages.Add(tab);
        }
        right.Panel1.Controls.Add(tabs);
        right.Panel2.Controls.Add(details);
        split.Panel2.Controls.Add(right);
        root.Controls.Add(split, 0, 2);
        Controls.Add(root);
        grid.SetEmptyState("Policy results need observations", "Connect to a capture to evaluate the enabled policies.",
            "Connect…", Connect);
        examples.SetEmptyState("Select a policy result",
            "Observed violations and insufficient evidence are listed separately.");
        UpdateList();
        list.SelectedIndexChanged += (_, _) => Selection();
        grid.CurrentCellChanged += (_, _) => ResultSelection();
        examples.CurrentCellChanged += (_, _) => ExampleSelection();
        editor.PropertyValueChanged += (_, _) =>
        {
            var selected = list.SelectedIndex;
            UpdateList(selected);
            Status.Text = "Policy edits are pending. Apply policies to save and evaluate.";
        };
        add.Click += (_, _) =>
        {
            if (candidates.Count >= 128)
                return;
            var number = 1;
            while (candidates.Any(policy => policy.Name == "Policy " + number))
                ++number;
            candidates.Add(new() { Name = "Policy " + number });
            UpdateList(candidates.Count - 1);
            Status.Text = "Policy edits are pending. Apply policies to save and evaluate.";
        };
        remove.Click += (_, _) =>
        {
            if (list.SelectedIndex < 0)
                return;
            var index = list.SelectedIndex;
            candidates.RemoveAt(index);
            UpdateList(Math.Min(index, candidates.Count - 1));
            Status.Text = "Policy edits are pending. Apply policies to save and evaluate.";
        };
        apply.Click += (_, _) => ApplyPolicies(null);
        export.Click += (_, _) =>
        {
            using var dialog = new SaveFileDialog { Filter = "Configuration (*.config)|*.config", FileName = "Cipherazzi.Viewer.config" };
            if (dialog.ShowDialog(this) == DialogResult.OK)
                ApplyPolicies(dialog.FileName);
        };
        examples.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && examples.Rows[e.RowIndex].Tag is PolicyExample example)
                Filter(example.Peer[..example.Peer.LastIndexOf(':')]);
        };
        Selection();
    }

    private void UpdateList(int selected = 0)
    {
        list.BeginUpdate();
        list.Items.Clear();
        list.Items.AddRange(candidates.Cast<object>().ToArray());
        list.EndUpdate();
        list.SelectedIndex = candidates.Count > 0 ? Math.Clamp(selected, 0, candidates.Count - 1) : -1;
    }

    private void Selection()
    {
        editor.SelectedObject = list.SelectedItem;
        remove.Enabled = list.SelectedIndex >= 0;
    }

    private void ApplyPolicies(string? exportPath)
    {
        try
        {
            foreach (var policy in candidates)
                policy.Validate();
            if (candidates.Select(policy => policy.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != candidates.Count)
                throw new InvalidDataException("Policy names must be unique.");
            var old = Settings.ScopedPolicies;
            Settings.ScopedPolicies = candidates.Select(policy => policy.Clone()).ToList();
            try { Settings.Save(exportPath ?? Settings.PersistencePath); }
            catch { Settings.ScopedPolicies = old; throw; }
            if (exportPath is not null)
            {
                Settings.ScopedPolicies = old;
                Status.Text = "Configuration exported. Pending edits have not been applied.";
                return;
            }
            Reset();
            PoliciesChanged?.Invoke();
        }
        catch (Exception error) when (error is IOException or InvalidDataException or
            UnauthorizedAccessException or ArgumentException)
        { Status.Text = "Policies could not be applied. " + error.Message; }
    }

    protected override Func<CancellationToken, object> PrepareRead(DatabaseSource source, Query query)
    {
        fixedRange = query.HasDateRange;
        window.Parent!.Visible = !fixedRange;
        var policies = Settings.ScopedPolicies.Select(policy => policy.Clone()).ToArray();
        var since = Since(WindowMinutes(window));
        return token => PqcInsights.Read(source, query, since, long.MaxValue, "Client application", policies, token);
    }

    protected override DateTime NextTimedRefresh(object result)
    {
        var snapshot = (PqcSnapshot)result;
        return fixedRange || WindowMinutes(window) == 0 || snapshot.FirstPolicyUs == long.MaxValue ? DateTime.MaxValue :
            DateTimeOffset.FromUnixTimeMilliseconds(snapshot.FirstPolicyUs / 1000)
                .AddMinutes(WindowMinutes(window)).AddMilliseconds(1).UtcDateTime;
    }

    internal Query ExportQuery(Query query) => query.HasDateRange ? query :
        query with { FromUs = Since(WindowMinutes(window)) };

    protected override void ApplyResult(object result)
    {
        var snapshot = (PqcSnapshot)result;
        results = snapshot.Policies;
        grid.Rows.Clear();
        foreach (var row in results)
        {
            var index = grid.Rows.Add(row.Name, row.Applicable, row.Pass, row.Violations, row.Insufficient);
            grid.Rows[index].Tag = row;
        }
        Status.Text = $"{snapshot.PolicyObservations:N0} applicable observations · " +
            $"{results.Count:N0} enabled policies · Representative evidence examples are capped at 250 per policy.";
        grid.SetEmptyState(results.Count == 0 ? "No enabled policies" : "No policy observations",
            "Add or enable a policy, or widen the time range to evaluate more observations.");
        ResultSelection();
    }

    private void ResultSelection()
    {
        if (grid.CurrentRow?.Tag is not PolicySummary summary)
            return;
        var properties = new List<ObservationProperty>
        {
            new("Policy", "Name", summary.Name), new("Policy", "Applicable observations", summary.Applicable.ToString("N0")),
            new("Policy", "Pass", summary.Pass.ToString("N0")), new("Policy", "Violations", summary.Violations.ToString("N0")),
            new("Policy", "Insufficient evidence", summary.Insufficient.ToString("N0"))
        };
        properties.AddRange(summary.Issues.OrderByDescending(item => item.Value).Select(item =>
            new ObservationProperty("Findings", item.Key, item.Value.ToString("N0"))));
        details.Show(summary.Name, summary.Name, properties, summary:
            $"Pass: {summary.Pass:N0} · Violations: {summary.Violations:N0} · " +
            $"Insufficient evidence: {summary.Insufficient:N0}");
        examples.Rows.Clear();
        foreach (var example in summary.Examples)
        {
            var index = examples.Rows.Add(example.EndpointEventId.Length > 0 ? example.EndpointEventId[..Math.Min(16,
                example.EndpointEventId.Length)] : example.Id, example.Computer, example.Application, example.Peer,
                example.Status, example.Reasons);
            examples.Rows[index].Tag = example;
        }
    }

    private void ExampleSelection()
    {
        if (examples.CurrentRow?.Tag is not PolicyExample example)
            return;
        var identity = example.EndpointEventId.Length > 0 ? example.EndpointEventId : example.Id.ToString();
        details.Show(identity, example.EndpointEventId.Length > 0 ? "Endpoint report" : "Observation " + identity, new()
        {
            new("Policy evidence", "Evidence ID", identity),
            new("Policy evidence", "Computer", example.Computer), new("Policy evidence", "Application", example.Application),
            new("Policy evidence", "Server", example.Peer), new("Policy evidence", "Result", example.Status),
            new("Policy evidence", "Findings", example.Reasons)
        });
    }

    protected override void ClearResult()
    {
        results = [];
        grid.Rows.Clear();
        examples.Rows.Clear();
        details.Clear("Select a policy result to inspect findings.");
    }
}
