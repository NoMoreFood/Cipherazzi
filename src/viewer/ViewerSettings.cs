using System.Xml.Linq;

namespace Cipherazzi.Viewer;

internal sealed record ColumnSetting(string Name, bool Visible, int Width);

internal sealed class ViewerSettings
{
    private static readonly string[] DefaultColumnOrder =
        ["Peer", "Findings", "Confirmation", "Tls", "Process", "GroupClass", "Time"];
    public string Theme { get; set; } = "System";
    public bool Live { get; set; } = true;
    public bool ShowHttp { get; set; } = true;
    public bool ShowLoopback { get; set; } = true;
    public int PollMilliseconds { get; set; } = 250;
    public int PageSize { get; set; } = 250;
    public int AnalyticsMinutes { get; set; } = 1440;
    public int AnalyticsRefreshSeconds { get; set; } = 5;
    public int TopGroups { get; set; } = 20;
    public FindingPolicy Policy { get; set; } = new();
    public List<CryptoPolicy> ScopedPolicies { get; set; } = [new()];
    public int BaselineMinimumSamples { get; set; } = 5;
    public List<SavedSearch> SavedSearches { get; set; } = [];
    public Dictionary<string, List<ColumnSetting>> ViewColumns { get; set; } = new(StringComparer.Ordinal);
    public List<ColumnSetting> Columns { get; set; } =
        ColumnDefinitions.All.OrderBy(column => Array.IndexOf(DefaultColumnOrder, column.Name) is >= 0 and var index ?
            index : int.MaxValue).Select(column =>
                new ColumnSetting(column.Name, column.Visible, column.Width)).ToList();
    public string? Warning { get; private set; }
    public string PersistencePath { get; init; } = UserPath;
    public static string UserPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Cipherazzi", "Viewer.config");

    public static ViewerSettings Load(string? explicitPath = null)
    {
        var settings = new ViewerSettings();
        var defaults = explicitPath ?? Path.Combine(AppContext.BaseDirectory, "Cipherazzi.Viewer.config");
        foreach (var path in explicitPath is null ? new[] { defaults, UserPath } : new[] { defaults })
        {
            if (!File.Exists(path))
            {
                if (explicitPath is not null)
                    settings.Warning = "The specified configuration file does not exist; built-in defaults are active.";
                continue;
            }
            try { settings.Read(path); }
            catch (Exception error) when (error is IOException or System.Xml.XmlException or FormatException or
                ArgumentException or UnauthorizedAccessException or InvalidDataException or OverflowException)
            {
                settings.Warning = $"Configuration could not be loaded: {Path.GetFileName(path)}. {error.Message} " +
                    "The last valid settings are active.";
            }
        }
        return settings;
    }

    private void Read(string path)
    {
        // Validate a complete candidate before replacing active settings.
        using var input = File.OpenRead(path);
        if (input.Length > 262144)
            throw new InvalidDataException("Configuration exceeds 256 KiB.");
        var root = XDocument.Load(input).Root;
        if (root?.Name != "cipherazzi")
            throw new InvalidDataException("Expected a cipherazzi configuration element.");
        void Content(XElement element, string[] attributes, string[] children, bool repeated = false)
        {
            if (element.Attributes().Any(attribute => !attributes.Any(name => attribute.Name == name)) ||
                element.Elements().Any(child => !children.Any(name => child.Name == name)) ||
                element.Nodes().OfType<XText>().Any(text => !string.IsNullOrWhiteSpace(text.Value)) ||
                !repeated && element.Elements().GroupBy(child => child.Name).Any(group => group.Count() > 1))
                throw new InvalidDataException("Configuration contains an unknown, duplicate, or misplaced setting.");
        }
        Content(root, [], ["viewer", "findings", "policies", "savedSearches"]);
        var view = root.Element("viewer") ?? throw new InvalidDataException("Missing viewer settings.");
        Content(view, ["theme", "live", "showHttp", "showLoopback", "pollMilliseconds", "pageSize",
            "analyticsMinutes", "analyticsRefreshSeconds", "topGroups", "baselineMinimumSamples"],
            ["columns", "investigationColumns"]);
        int Number(XElement element, string name, int fallback, int min, int max)
        {
            var value = (int?)element.Attribute(name) ?? fallback;
            if (value < min || value > max)
                throw new InvalidDataException($"{name} must be between {min} and {max}.");
            return value;
        }
        var theme = (string?)view.Attribute("theme") ?? Theme;
        if (theme is not ("System" or "Light" or "Dark"))
            throw new InvalidDataException("Theme must be System, Light, or Dark.");
        var poll = Number(view, "pollMilliseconds", PollMilliseconds, 100, 10000);
        var page = Number(view, "pageSize", PageSize, 50, 2000);
        var minutes = Number(view, "analyticsMinutes", AnalyticsMinutes, 0, 525600);
        var refresh = Number(view, "analyticsRefreshSeconds", AnalyticsRefreshSeconds, 2, 300);
        var top = Number(view, "topGroups", TopGroups, 5, 100);
        var live = (bool?)view.Attribute("live") ?? Live;
        var showHttp = (bool?)view.Attribute("showHttp") ?? ShowHttp;
        var showLoopback = (bool?)view.Attribute("showLoopback") ?? ShowLoopback;
        var columns = Columns.ToList();
        if (view.Element("columns") is { } list)
        {
            Content(list, [], ["column"], repeated: true);
            columns.Clear();
            foreach (var column in list.Elements("column"))
            {
                Content(column, ["name", "visible", "width"], []);
                var name = (string?)column.Attribute("name") ?? "";
                var definition = ColumnDefinitions.All.SingleOrDefault(item => item.Name == name) ??
                    throw new InvalidDataException($"Unknown column: {name}");
                if (columns.Any(item => item.Name == name))
                    throw new InvalidDataException($"Duplicate column: {name}");
                columns.Add(new(name, (bool?)column.Attribute("visible") ?? definition.Visible,
                    Number(column, "width", definition.Width, 60, 2000)));
            }
            foreach (var definition in ColumnDefinitions.All.Where(item => columns.All(c => c.Name != item.Name)))
                columns.Add(new(definition.Name, false, definition.Width));
            if (columns.All(column => !column.Visible))
                throw new InvalidDataException("At least one column must be visible.");
        }
        var policy = Policy;
        if (root.Element("findings") is { } findings)
        {
            Content(findings, ["minimumTls", "minimumDhBits", "warnMissingEms"], []);
            policy = new(Number(findings, "minimumTls", policy.MinimumTls, 768, 772),
                Number(findings, "minimumDhBits", policy.MinimumDhBits, 512, 16384),
                (bool?)findings.Attribute("warnMissingEms") ?? policy.WarnMissingEms);
        }
        var scoped = ScopedPolicies;
        if (root.Element("policies") is { } policies)
        {
            Content(policies, [], ["policy"], repeated: true);
            scoped = policies.Elements("policy").Select(CryptoPolicy.FromXml).ToList();
            if (scoped.Count > 128 ||
                scoped.Select(item => item.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != scoped.Count)
                throw new InvalidDataException("Policy names must be unique; at most 128 policies are supported.");
        }
        var searches = SavedSearches;
        if (root.Element("savedSearches") is { } saved)
        {
            Content(saved, [], ["search"], repeated: true);
            searches = saved.Elements("search").Select(SavedSearch.FromXml).ToList();
        }
        if (searches.Count > 64 || searches.Select(item => item.Target + "\0" + item.Name.ToUpperInvariant())
            .Distinct().Count() != searches.Count)
            throw new InvalidDataException(
                "Saved search names must be unique in each scope; at most 64 are supported.");
        var samples = Number(view, "baselineMinimumSamples", BaselineMinimumSamples, 1, 1000000);
        var viewColumns = ViewColumns.ToDictionary(item => item.Key,
            item => item.Value.ToList(), StringComparer.Ordinal);
        if (view.Element("investigationColumns") is { } investigation)
        {
            Content(investigation, [], ["grid"], repeated: true);
            foreach (var table in investigation.Elements("grid"))
            {
                Content(table, ["name"], ["column"], repeated: true);
                var name = (string?)table.Attribute("name") ?? "";
                var definitions = table.Elements("column").Select(column =>
                {
                    Content(column, ["name", "visible", "width"], []);
                    return new ColumnSetting((string?)column.Attribute("name") ?? "",
                        (bool?)column.Attribute("visible") ?? true, Number(column, "width", 120, 60, 2000));
                }).ToList();
                if (name.Length is 0 or > 128 || definitions.Count is 0 or > 64 ||
                    definitions.Any(column => column.Name.Length is 0 or > 128) ||
                    definitions.Select(column => column.Name).Distinct().Count() != definitions.Count ||
                    definitions.All(column => !column.Visible) ||
                        (viewColumns.Count >= 32 && !viewColumns.ContainsKey(name)))
                    throw new InvalidDataException("Investigation column settings are invalid.");
                viewColumns[name] = definitions;
            }
        }
        Theme = theme;
        Live = live;
        ShowHttp = showHttp;
        ShowLoopback = showLoopback;
        PollMilliseconds = poll;
        PageSize = page;
        AnalyticsMinutes = minutes;
        AnalyticsRefreshSeconds = refresh;
        TopGroups = top;
        Policy = policy;
        ScopedPolicies = scoped;
        BaselineMinimumSamples = samples;
        SavedSearches = searches;
        Columns = columns;
        ViewColumns = viewColumns;
    }

    public void Save(string path)
    {
        var document = new XDocument(new XElement("cipherazzi",
            new XElement("viewer", new XAttribute("theme", Theme), new XAttribute("live", Live),
                new XAttribute("showHttp", ShowHttp), new XAttribute("showLoopback", ShowLoopback),
                new XAttribute("pollMilliseconds", PollMilliseconds), new XAttribute("pageSize", PageSize),
                new XAttribute("analyticsMinutes", AnalyticsMinutes),
                new XAttribute("analyticsRefreshSeconds", AnalyticsRefreshSeconds),
                new XAttribute("topGroups", TopGroups),
                new XAttribute("baselineMinimumSamples", BaselineMinimumSamples),
                new XElement("columns", Columns.Select(column => new XElement("column",
                    new XAttribute("name", column.Name), new XAttribute("visible", column.Visible),
                    new XAttribute("width", column.Width)))),
                new XElement("investigationColumns", ViewColumns.Select(table => new XElement("grid",
                    new XAttribute("name", table.Key), table.Value.Select(column => new XElement("column",
                        new XAttribute("name", column.Name), new XAttribute("visible", column.Visible),
                        new XAttribute("width", column.Width))))))),
            new XElement("findings", new XAttribute("minimumTls", Policy.MinimumTls),
                new XAttribute("minimumDhBits", Policy.MinimumDhBits),
                new XAttribute("warnMissingEms", Policy.WarnMissingEms)),
            new XElement("policies", ScopedPolicies.Select(policy => policy.ToXml())),
            new XElement("savedSearches", SavedSearches.Select(search => search.ToXml()))));
        var target = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        var temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            document.Save(temporary);
            if (new FileInfo(temporary).Length > 262144)
                throw new InvalidDataException("Configuration exceeds 256 KiB.");
            File.Move(temporary, target, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}

internal sealed class SettingsDialog : Form
{
    private sealed record Item(ColumnSetting Setting)
    {
        public override string ToString()
        {
            var column = ColumnDefinitions.All.Single(c => c.Name == Setting.Name);
            return column.Caption + "  [" + column.Category + "]";
        }
    }

    public SettingsDialog(ViewerSettings settings, DataGridView grid)
    {
        Text = "Display options";
        Font = grid.Font;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96, 96);
        ClientSize = new Size(650, 650);
        MinimumSize = new Size(570, 620);
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false;
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(10),
            ColumnCount = 2,
            RowCount = 7
        };
        root.ColumnStyles.Add(new(SizeType.Percent, 100));
        root.ColumnStyles.Add(new(SizeType.AutoSize));
        for (var i = 0; i < 7; ++i)
            root.RowStyles.Add(new(i == 4 ? SizeType.Percent : SizeType.AutoSize, i == 4 ? 100 : 0));
        var controls = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        var theme = new ChoiceBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            AutoSize = true,
            AccessibleName = "Theme"
        };
        theme.Items.AddRange(["System", "Light", "Dark"]);
        theme.SelectedItem = settings.Theme;
        var poll = new NumericUpDown
        {
            Minimum = 100,
            Maximum = 10000,
            Increment = 50,
            Value = settings.PollMilliseconds,
            AutoSize = true,
            AccessibleName = "Refresh milliseconds"
        };
        var page = new NumericUpDown
        {
            Minimum = 50,
            Maximum = 2000,
            Increment = 50,
            Value = settings.PageSize,
            AutoSize = true,
            AccessibleName = "Rows per page"
        };
        void AddField(string caption, Control control)
        {
            var field = new TableLayoutPanel
            {
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0, 0, 8, 2)
            };
            field.ColumnStyles.Add(new(SizeType.AutoSize));
            field.ColumnStyles.Add(new(SizeType.AutoSize));
            field.RowStyles.Add(new(SizeType.AutoSize));
            field.Controls.Add(new Label
            {
                Text = caption,
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(3, 3, 6, 3)
            }, 0, 0);
            control.Anchor = AnchorStyles.Left;
            field.Controls.Add(control, 1, 0);
            controls.Controls.Add(field);
        }
        AddField("&Theme", theme);
        AddField("&Refresh (ms)", poll);
        AddField("Ro&ws / page", page);
        root.Controls.Add(controls, 0, 0);
        root.SetColumnSpan(controls, 2);

        // Traffic visibility applies to every investigation view and its exported results.
        var traffic = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
        var showHttp = new CheckBox
        {
            Text = "Show &HTTP traffic",
            AutoSize = true,
            Checked = settings.ShowHttp,
            AccessibleName = "Show HTTP traffic"
        };
        var showLoopback = new CheckBox
        {
            Text = "Show &loopback traffic",
            AutoSize = true,
            Checked = settings.ShowLoopback,
            AccessibleName = "Show loopback traffic"
        };
        traffic.Controls.AddRange([showHttp, showLoopback]);
        root.Controls.Add(traffic, 0, 1);
        root.SetColumnSpan(traffic, 2);
        var help = new Label
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            Margin = new Padding(3, 6, 3, 6),
            Text = "Displayed columns and order. Column widths are adjustable in the results grid."
        };
        root.Controls.Add(help, 0, 2);
        root.SetColumnSpan(help, 2);
        var list = new CheckedListBox
        {
            Dock = DockStyle.Fill,
            CheckOnClick = true,
            IntegralHeight = false,
            HorizontalScrollbar = true,
            AccessibleName = "Displayed columns"
        };
        var columns = new List<Item>();
        foreach (var column in grid.Columns.Cast<DataGridViewColumn>().OrderBy(column => column.DisplayIndex))
            columns.Add(new Item(new(column.Name, column.Visible,
                Math.Clamp(column.Width * 96 / grid.DeviceDpi, 60, 2000))));
        var find = new InputTextBox
        {
            Dock = DockStyle.Fill,
            PlaceholderText = "Column name or category",
            AccessibleName = "Find columns"
        };
        var search = new TableLayoutPanel
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            Margin = new Padding(0, 0, 0, 6)
        };
        search.ColumnStyles.Add(new(SizeType.AutoSize));
        search.ColumnStyles.Add(new(SizeType.Percent, 100));
        search.Controls.Add(new Label { Text = "&Find columns", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        search.Controls.Add(find, 1, 0);
        root.Controls.Add(search, 0, 3);
        root.SetColumnSpan(search, 2);
        root.Controls.Add(list, 0, 4);
        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false
        };
        void Move(int offset)
        {
            var index = columns.FindIndex(item => item.Setting.Name == (list.SelectedItem as Item)?.Setting.Name);
            var next = index + offset;
            if (find.Text.Length > 0 || index < 0 || next < 0 || next >= columns.Count)
                return;
            var item = columns[index];
            columns.RemoveAt(index);
            columns.Insert(next, item);
            Populate(item.Setting.Name);
        }
        var up = new CommandButton { Text = "Move &up", AutoSize = true };
        var down = new CommandButton { Text = "Move &down", AutoSize = true };
        var reset = new CommandButton { Text = "Reset &columns", AutoSize = true };
        void UpdateSelection()
        {
            up.Enabled = find.Text.Length == 0 && list.SelectedIndex > 0;
            down.Enabled = find.Text.Length == 0 && list.SelectedIndex >= 0 &&
                list.SelectedIndex < list.Items.Count - 1;
        }
        var populating = false;
        void Populate(string? selected = null)
        {
            populating = true;
            list.BeginUpdate();
            list.Items.Clear();
            foreach (var item in columns.Where(item => item.ToString().Contains(find.Text.Trim(),
                StringComparison.OrdinalIgnoreCase)))
            {
                var index = list.Items.Add(item, item.Setting.Visible);
                if (item.Setting.Name == selected)
                    list.SelectedIndex = index;
            }
            if (list.SelectedIndex < 0 && list.Items.Count > 0)
                list.SelectedIndex = 0;
            list.EndUpdate();
            populating = false;
            UpdateSelection();
            help.Text = find.Text.Length == 0 ?
                "Choose displayed columns. Drag headers or use Move up / down to change their order." :
                $"{list.Items.Count:N0} matching columns. Clear the search to change column order.";
        }
        list.ItemCheck += (_, e) =>
        {
            if (populating || list.Items[e.Index] is not Item item)
                return;
            var index = columns.FindIndex(column => column.Setting.Name == item.Setting.Name);
            columns[index] = item with { Setting = item.Setting with { Visible = e.NewValue == CheckState.Checked } };
        };
        find.TextChanged += (_, _) => Populate();
        list.SelectedIndexChanged += (_, _) => UpdateSelection();
        up.Click += (_, _) => Move(-1);
        down.Click += (_, _) => Move(1);
        reset.Click += (_, _) =>
        {
            columns = new ViewerSettings().Columns.Select(column => new Item(column)).ToList();
            find.Clear();
            Populate();
        };
        buttons.Controls.AddRange([up, down, reset]);
        root.Controls.Add(buttons, 1, 4);
        Populate();
        var remember = new CheckBox
        {
            Text = "&Save as user defaults",
            Checked = true,
            AutoSize = true,
            Margin = new Padding(3, 6, 3, 6)
        };
        root.Controls.Add(remember, 0, 5);
        var actions = new FlowLayoutPanel
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false
        };
        var cancel = new CommandButton
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            AutoSize = true,
            TabIndex = 2
        };
        var apply = new CommandButton { Text = "&Apply", AutoSize = true, TabIndex = 1 };
        var export = new CommandButton { Text = "&Export defaults…", AutoSize = true, TabIndex = 0 };
        actions.Controls.AddRange([cancel, apply, export]);
        root.Controls.Add(actions, 0, 6);
        root.SetColumnSpan(actions, 2);
        ViewerSettings? Candidate()
        {
            if (columns.All(item => !item.Setting.Visible))
            {
                MessageBox.Show(this, "At least one displayed column is required.", Text);
                return null;
            }
            return new ViewerSettings
            {
                Theme = theme.Text,
                PollMilliseconds = (int)poll.Value,
                PageSize = (int)page.Value,
                ShowHttp = showHttp.Checked,
                ShowLoopback = showLoopback.Checked,
                Live = settings.Live,
                AnalyticsMinutes = settings.AnalyticsMinutes,
                AnalyticsRefreshSeconds = settings.AnalyticsRefreshSeconds,
                TopGroups = settings.TopGroups,
                Policy = settings.Policy,
                ScopedPolicies = settings.ScopedPolicies,
                ViewColumns = settings.ViewColumns,
                BaselineMinimumSamples = settings.BaselineMinimumSamples,
                SavedSearches = settings.SavedSearches,
                Columns = columns.Select(item => item.Setting).ToList()
            };
        }
        apply.Click += (_, _) =>
        {
            if (Candidate() is not { } candidate)
                return;
            try
            {
                if (remember.Checked)
                    candidate.Save(settings.PersistencePath);
                settings.Theme = candidate.Theme;
                settings.ShowHttp = candidate.ShowHttp;
                settings.ShowLoopback = candidate.ShowLoopback;
                settings.PollMilliseconds = candidate.PollMilliseconds;
                settings.PageSize = candidate.PageSize;
                settings.Columns = candidate.Columns;
                DialogResult = DialogResult.OK;
            }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                MessageBox.Show(this, "Settings could not be saved. " + error.Message, Text);
            }
        };
        export.Click += (_, _) =>
        {
            if (Candidate() is not { } candidate)
                return;
            using var dialog = new SaveFileDialog
            {
                Filter = "Configuration (*.config)|*.config",
                FileName = "Cipherazzi.Viewer.config",
                OverwritePrompt = true
            };
            if (dialog.ShowDialog(this) != DialogResult.OK)
                return;
            try { candidate.Save(dialog.FileName); }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                MessageBox.Show(this, "Defaults could not be exported. " + error.Message, Text);
            }
        };
        AcceptButton = apply;
        CancelButton = cancel;
        Controls.Add(root);
        UiTheme.Apply(this, settings.Theme);

        // Keep each option with its label and align column commands at every text and DPI scale.
        void UpdateTextMetrics()
        {
            var padding = SystemInformation.VerticalScrollBarWidth + 12 * DeviceDpi / 96;
            theme.Width = theme.Items.Cast<string>()
                .Max(value => TextRenderer.MeasureText(value, Font).Width) + padding;
            poll.Width = TextRenderer.MeasureText("10000", Font).Width + padding;
            page.Width = TextRenderer.MeasureText("2000", Font).Width + padding;
            foreach (var button in new[] { up, down, reset })
                button.MinimumSize = Size.Empty;
            var width = new[] { up, down, reset }.Max(button => button.GetPreferredSize(Size.Empty).Width);
            foreach (var button in new[] { up, down, reset })
                button.MinimumSize = new Size(width, 0);
        }

        // Reserve enough height for the full command stack after labels wrap at the current width.
        var sizing = false;
        void UpdateMinimumHeight()
        {
            if (sizing || !IsHandleCreated || root.GetRowHeights() is not { Length: 7 } heights)
                return;
            sizing = true;
            try
            {
                var commandHeight = buttons.GetPreferredSize(Size.Empty).Height + buttons.Margin.Vertical;
                var listHeight = list.ItemHeight * 4 + list.Margin.Vertical;
                var required = ClientSize.Height - heights[4] + Math.Max(commandHeight, listHeight);
                MinimumSize = new(MinimumSize.Width, required + Height - ClientSize.Height);
            }
            finally { sizing = false; }
        }
        root.Layout += (_, _) => UpdateMinimumHeight();
        Shown += (_, _) => UpdateMinimumHeight();
        FontChanged += (_, _) => UpdateTextMetrics();
        DpiChanged += (_, _) => UpdateTextMetrics();
        UpdateTextMetrics();
    }
}
