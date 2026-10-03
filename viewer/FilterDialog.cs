namespace Cipherazzi.Viewer;

internal sealed class FilterDialog : Form
{
    private sealed record FieldChoice(ObservationField Value, string Caption);
    private sealed record ComparisonChoice(FilterComparison Value, string Caption);
    private readonly ViewerSettings settings;
    private readonly InvestigationTarget target;
    private readonly Query original;
    private Query loaded;
    private readonly ChoiceBox saved = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill,
        AccessibleName = "Saved searches" };
    private readonly InputTextBox search = new() { Dock = DockStyle.Fill, MaxLength = 256,
        AccessibleName = "Filter search text" };
    private readonly ChoiceBox protocol = new() { DropDownStyle = ComboBoxStyle.DropDown, MaxLength = 64,
        AccessibleName = "Filter protocol" };
    private readonly CheckBox partial = new() { Text = "Partial e&xchanges", AutoSize = true };
    private readonly DateTimePicker from = DatePicker("Observation start (UTC)");
    private readonly DateTimePicker to = DatePicker("Observation end (UTC)");
    private readonly DataGridView conditions = new()
    { Name = "FieldConditions", AccessibleName = "All matching conditions" };
    private readonly InputTextBox name = new()
    { Dock = DockStyle.Fill, MaxLength = 80, AccessibleName = "Saved search name" };
    private readonly Label message = new() { AutoSize = true, Dock = DockStyle.Fill, UseMnemonic = false };
    private readonly CommandButton delete = new() { Text = "&Delete search", AutoSize = true, Visible = false };
    private readonly CommandButton remove = new() { Text = "Re&move condition", AutoSize = true, Visible = false };
    private readonly CommandButton add = new() { Text = "Add &condition", AutoSize = true };
    private bool loading;
    public Query? SelectedQuery { get; private set; }
    internal static readonly string[] ProtocolNames = ["All protocols", "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0",
        "SSL 3.0", "DTLS 1.3", "DTLS 1.2", "DTLS 1.0", "SSH 2.0", "WireGuard", "IKEv2", "OpenVPN",
        "SMB", "RDP", "TDS", "Kerberos", "Unknown"];

    public FilterDialog(ViewerSettings settings, Query query, InvestigationTarget target, Font font)
    {
        this.settings = settings;
        this.target = target;
        original = loaded = query.CopyScope();
        Text = target == InvestigationTarget.Endpoints ? "Endpoint filters" : "Connection filters";
        Font = font;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96, 96);
        ClientSize = new Size(780, 610);
        MinimumSize = new Size(720, 550);
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false;
        ShowIcon = false;
        var root = new TableLayoutPanel
        { Dock = DockStyle.Fill, Padding = new Padding(10), ColumnCount = 1, RowCount = 8 };
        root.ColumnStyles.Add(new(SizeType.Percent, 100));
        for (var row = 0; row < 8; row++)
            root.RowStyles.Add(new(row == 3 ? SizeType.Percent : SizeType.AutoSize, row == 3 ? 100 : 0));
        var savedRow = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 3 };
        savedRow.ColumnStyles.Add(new(SizeType.AutoSize));
        savedRow.ColumnStyles.Add(new(SizeType.Percent, 100));
        savedRow.ColumnStyles.Add(new(SizeType.AutoSize));
        savedRow.Controls.Add(new Label { Text = "&Saved search", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        savedRow.Controls.Add(saved, 1, 0);
        savedRow.Controls.Add(delete, 2, 0);
        root.Controls.Add(savedRow, 0, 0);
        var textRow = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 5 };
        textRow.ColumnStyles.Add(new(SizeType.AutoSize));
        textRow.ColumnStyles.Add(new(SizeType.Percent, 100));
        for (var column = 2; column < 5; column++)
            textRow.ColumnStyles.Add(new(SizeType.AutoSize));
        textRow.Controls.Add(new Label { Text = "Sea&rch", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        textRow.Controls.Add(search, 1, 0);
        textRow.Controls.Add(new Label { Text = "&Protocol", AutoSize = true, Anchor = AnchorStyles.Left }, 2, 0);
        protocol.Items.AddRange(ProtocolNames);
        textRow.Controls.Add(protocol, 3, 0);
        partial.Visible = target == InvestigationTarget.Connections;
        textRow.Controls.Add(partial, 4, 0);
        root.Controls.Add(textRow, 0, 1);
        var dates = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 4 };
        dates.ColumnStyles.Add(new(SizeType.AutoSize));
        dates.ColumnStyles.Add(new(SizeType.Percent, 50));
        dates.ColumnStyles.Add(new(SizeType.AutoSize));
        dates.ColumnStyles.Add(new(SizeType.Percent, 50));
        dates.Controls.Add(new Label { Text = "&From (UTC)", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        dates.Controls.Add(from, 1, 0);
        dates.Controls.Add(new Label { Text = "&To (UTC)", AutoSize = true, Anchor = AnchorStyles.Left }, 2, 0);
        dates.Controls.Add(to, 3, 0);
        root.Controls.Add(dates, 0, 2);

        // Named conditions intersect; socket roles remain client/server even on a reporting server endpoint.
        AnalyticsView.ConfigureGrid(conditions);
        conditions.ReadOnly = false;
        conditions.EditMode = DataGridViewEditMode.EditOnEnter;
        conditions.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        var fields = Enum.GetValues<ObservationField>().Where(field => target == InvestigationTarget.Endpoints ||
            field != ObservationField.Provider).Select(field => new FieldChoice(field, field switch
            {
                ObservationField.ClientProcess => "Client process", ObservationField.ServerProcess => "Server process",
                ObservationField.ServerName => "Server name / peer", ObservationField.ClientAddress => "Client address",
                ObservationField.ServerAddress => "Server address", ObservationField.ClientPort => "Client port",
                ObservationField.ServerPort => "Server port", ObservationField.ProcessId => "Process ID",
                ObservationField.KeyClass => "Key class", ObservationField.State =>
                    target == InvestigationTarget.Endpoints ? "Result" : "State", _ => field.ToString()
            })).ToArray();
        conditions.Columns.Add(new DataGridViewComboBoxColumn { Name = "Field", HeaderText = "Field",
            DataSource = fields, ValueMember = "Value", DisplayMember = "Caption", FillWeight = 32, MinimumWidth = 135 });
        conditions.Columns.Add(new DataGridViewComboBoxColumn { Name = "Comparison", HeaderText = "Comparison",
            ValueMember = "Value", DisplayMember = "Caption", FillWeight = 27, MinimumWidth = 130 });
        conditions.Columns.Add(new DataGridViewTextBoxColumn { Name = "Value", HeaderText = "Value",
            MaxInputLength = 256, FillWeight = 41, MinimumWidth = 150 });
        root.Controls.Add(conditions, 0, 3);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        var clear = new CommandButton { Text = "C&lear filters", AutoSize = true };
        actions.Controls.AddRange([add, remove, clear]);
        actions.Controls.Add(new Label { AutoSize = true, Margin = new Padding(10, 7, 3, 3),
            Text = "All conditions must match. Checked dates replace the view's time range." });
        root.Controls.Add(actions, 0, 4);
        var saveRow = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 3 };
        saveRow.ColumnStyles.Add(new(SizeType.AutoSize));
        saveRow.ColumnStyles.Add(new(SizeType.Percent, 100));
        saveRow.ColumnStyles.Add(new(SizeType.AutoSize));
        saveRow.Controls.Add(new Label { Text = "&Name", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        saveRow.Controls.Add(name, 1, 0);
        var save = new CommandButton { Text = "Sa&ve search", AutoSize = true };
        saveRow.Controls.Add(save, 2, 0);
        root.Controls.Add(saveRow, 0, 5);
        root.Controls.Add(message, 0, 6);
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft };
        var cancel = new CommandButton { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var apply = new CommandButton { Text = "&Apply filters", AutoSize = true };
        buttons.Controls.AddRange([cancel, apply]);
        root.Controls.Add(buttons, 0, 7);
        Controls.Add(root);
        AcceptButton = apply;
        CancelButton = cancel;
        conditions.CellValueChanged += (_, e) => { if (!loading && e.RowIndex >= 0) UpdateRow(e.RowIndex); };
        conditions.CurrentCellDirtyStateChanged += (_, _) =>
        {
            if (conditions.IsCurrentCellDirty && conditions.CurrentCell is DataGridViewComboBoxCell)
                conditions.CommitEdit(DataGridViewDataErrorContexts.Commit);
        };
        conditions.CurrentCellChanged += (_, _) => remove.Visible = conditions.CurrentRow is not null;
        conditions.DataError += (_, e) => { e.ThrowException = false; Error("Choose a supported field and comparison."); };
        add.Click += (_, _) =>
        {
            if (conditions.RowCount == 16)
                return;
            var index = conditions.Rows.Add(ObservationField.Computer, FilterComparison.Contains, "");
            UpdateRow(index);
            conditions.CurrentCell = conditions.Rows[index].Cells[2];
            add.Enabled = conditions.RowCount < 16;
        };
        remove.Click += (_, _) =>
        {
            if (conditions.CurrentRow is { } row)
                conditions.Rows.Remove(row);
            add.Enabled = conditions.RowCount < 16;
        };
        clear.Click += (_, _) => SetScope(new("", "", false, PageCursor.Newest));
        saved.SelectedIndexChanged += (_, _) =>
        {
            if (loading)
                return;
            if (saved.SelectedItem is SavedSearch item)
            {
                SetScope(item.Query);
                name.Text = item.Name;
            }
            else
                SetScope(original);
            delete.Visible = saved.SelectedItem is SavedSearch;
        };
        save.Click += (_, _) => Persist(false);
        delete.Click += (_, _) => Persist(true);
        apply.Click += (_, _) =>
        {
            try { SelectedQuery = ReadScope(); DialogResult = DialogResult.OK; }
            catch (InvalidDataException error) { Error(error.Message); }
        };
        saved.DisplayMember = nameof(SavedSearch.Name);
        PopulateSaved();
        SetScope(query);
        void Metrics()
        {
            protocol.Width = protocol.Items.Cast<string>().Max(value => TextRenderer.MeasureText(value, Font).Width) +
                32 * DeviceDpi / 96;
            foreach (var picker in new[] { from, to })
            {
                picker.MinimumSize = new Size(TextRenderer.MeasureText("2026-12-31 23:59:59", Font).Width +
                    48 * DeviceDpi / 96, 0);
                picker.Width = picker.MinimumSize.Width;
            }
        }
        FontChanged += (_, _) => Metrics();
        DpiChanged += (_, _) => Metrics();
        Metrics();
        UiTheme.Apply(this, settings.Theme);
    }

    private static DateTimePicker DatePicker(string accessibleName) => new()
    {
        Format = DateTimePickerFormat.Custom, CustomFormat = "yyyy-MM-dd HH:mm:ss", ShowCheckBox = true,
        AccessibleName = accessibleName, Anchor = AnchorStyles.Left | AnchorStyles.Right,
        MinDate = DateTime.UnixEpoch, Value = DateTime.UtcNow
    };

    private void PopulateSaved(string? selected = null)
    {
        loading = true;
        saved.Items.Clear();
        saved.Items.Add("Current filters");
        saved.Items.AddRange(settings.SavedSearches.Where(item => item.Target == target).Cast<object>().ToArray());
        saved.SelectedIndex = selected is null ? 0 : saved.Items.Cast<object>().ToList()
            .FindIndex(item => item is SavedSearch search && search.Name.Equals(selected, StringComparison.OrdinalIgnoreCase));
        delete.Visible = saved.SelectedItem is SavedSearch;
        loading = false;
    }

    internal void SetScope(Query query)
    {
        loading = true;
        loaded = query.CopyScope();
        search.Text = query.Search;
        if (query.Protocol.Length > 0 && !protocol.Items.Contains(query.Protocol))
            protocol.Items.Add(query.Protocol);
        protocol.SelectedItem = query.Protocol.Length == 0 ? ProtocolNames[0] : query.Protocol;
        partial.Checked = query.Incomplete;
        from.Value = query.FromUs == 0 ? DateTime.UtcNow.AddDays(-1) : DateTime.UnixEpoch.AddTicks(query.FromUs * 10);
        to.Value = query.ToUs == long.MaxValue ? DateTime.UtcNow : DateTime.UnixEpoch.AddTicks(query.ToUs * 10);
        from.Checked = query.FromUs != 0;
        to.Checked = query.ToUs != long.MaxValue;
        conditions.Rows.Clear();
        foreach (var condition in query.Conditions)
        {
            var index = conditions.Rows.Add(condition.Field, condition.Comparison, condition.Value);
            UpdateRow(index);
        }
        add.Enabled = conditions.RowCount < 16;
        remove.Visible = conditions.CurrentRow is not null;
        message.Text = "";
        loading = false;
    }

    private void UpdateRow(int index)
    {
        var row = conditions.Rows[index];
        if (row.Cells[0].Value is not ObservationField field)
            return;
        var wasLoading = loading;
        loading = true;
        var numeric = new FieldFilter(field, FilterComparison.Equals).Numeric;
        var cell = (DataGridViewComboBoxCell)row.Cells[1];
        var comparison = cell.Value is FilterComparison selected ? selected : FilterComparison.Contains;
        if (numeric && comparison is FilterComparison.Contains or FilterComparison.StartsWith)
            comparison = FilterComparison.Equals;
        cell.DataSource = Enum.GetValues<FilterComparison>().Where(value => !numeric ||
            value is not (FilterComparison.Contains or FilterComparison.StartsWith)).Select(value =>
                new ComparisonChoice(value, value switch
                {
                    FilterComparison.Contains => "Contains", FilterComparison.Equals => "Equals",
                    FilterComparison.StartsWith => "Starts with", FilterComparison.NotEquals => "Does not equal",
                    FilterComparison.Observed => "Is observed", _ => "Not observed"
                })).ToArray();
        cell.Value = comparison;
        row.Cells[2].ReadOnly = comparison is FilterComparison.Observed or FilterComparison.NotObserved;
        row.Cells[2].Style.ForeColor = row.Cells[2].ReadOnly ? UiTheme.Muted : UiTheme.Foreground;
        loading = wasLoading;
    }

    internal Query ReadScope()
    {
        conditions.EndEdit();
        var fields = conditions.Rows.Cast<DataGridViewRow>().Select(row =>
        {
            if (row.Cells[0].Value is not ObservationField field || row.Cells[1].Value is not FilterComparison comparison)
                throw new InvalidDataException("Choose a field and comparison for each condition.");
            return new FieldFilter(field, comparison, row.Cells[2].Value?.ToString() ?? "");
        }).ToArray();
        long Microseconds(DateTime value) => (DateTime.SpecifyKind(value, DateTimeKind.Utc).Ticks -
            DateTime.UnixEpoch.Ticks) / 10;
        var until = to.Checked ? Microseconds(to.Value) : long.MaxValue;
        if (to.Checked && until != loaded.ToUs)
            until = until / 1000000 * 1000000 + 999999;
        var start = from.Checked ? Microseconds(from.Value) : 0;
        if (from.Checked && start != loaded.FromUs)
            start = start / 1000000 * 1000000;
        var query = new Query(search.Text, protocol.Text == ProtocolNames[0] ? "" : protocol.Text,
            target == InvestigationTarget.Connections && partial.Checked, PageCursor.Newest)
        {
            FromUs = start, ToUs = until, Conditions = fields
        };
        query.Validate(target);
        return query;
    }

    private void Persist(bool deleting)
    {
        try
        {
            var prior = settings.SavedSearches;
            var candidate = prior.ToList();
            if (deleting && saved.SelectedItem is SavedSearch item)
                candidate.Remove(item);
            else
            {
                var search = new SavedSearch(name.Text.Trim(), target, ReadScope());
                search.Validate();
                candidate.RemoveAll(item => item.Target == target && item.Name.Equals(search.Name,
                    StringComparison.OrdinalIgnoreCase));
                candidate.Add(search);
                if (candidate.Count > 64)
                    throw new InvalidDataException("At most 64 saved searches are supported.");
            }
            settings.SavedSearches = candidate;
            try { settings.Save(settings.PersistencePath); }
            catch { settings.SavedSearches = prior; throw; }
            PopulateSaved(deleting ? null : name.Text.Trim());
            if (deleting)
                name.Clear();
            message.ForeColor = UiTheme.Foreground;
            message.Text = deleting ? "Saved search deleted." : "Saved search saved.";
        }
        catch (Exception error) when (error is InvalidDataException or IOException or
            UnauthorizedAccessException or ArgumentException)
        { Error("Saved search could not be changed. " + error.Message); }
    }

    private void Error(string text)
    {
        message.ForeColor = UiTheme.Error;
        message.Text = text;
    }
}
