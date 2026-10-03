namespace Cipherazzi.Viewer;

// Chooses how to run the collector: live capture or the replay of a saved capture, and what it should record.
internal sealed class CollectorDialog : Form
{
    private readonly ChoiceBox mode = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList,
        AutoSize = true,
        AccessibleName = "Collector mode"
    };
    private readonly InputTextBox journal = new() { AccessibleName = "Journal file" };
    private readonly InputTextBox capture = new() { AccessibleName = "Capture file to replay" };
    private readonly InputTextBox keyLog = new() { AccessibleName = "TLS key log" };
    private readonly CommandButton target = new() { Text = "Launch target app with key log…", AutoSize = true };
    private string targetApp = "";
    private readonly ChoiceBox traffic = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList,
        AutoSize = true,
        AccessibleName = "Traffic to capture"
    };
    private readonly NumericUpDown duration = Number(0, 31536000, 0);
    private readonly CheckBox processes = new() { Text = "Attribute connections to &processes", Checked = true };
    private readonly CheckBox schannel = new() { Text = "Collect Schannel e&vents" };
    private readonly CheckBox http = new() { Text = "Monitor &HTTP metadata", Checked = true };
    private readonly CheckBox endpoint = new() { Text = "&Endpoint events only" };
    private readonly CheckBox classify = new() { Text = "&Classify unknown traffic" };
    private readonly CheckBox spy = new() { Text = "Decode &web traffic (HTTP Spy)" };
    private readonly CheckBox credentials = new() { Text = "Keep cookies and c&redentials" };
    private readonly NumericUpDown bodyKilobytes = Number(0, 16384, 64);
    private readonly NumericUpDown spyDays = Number(0, 36500, 7);
    private readonly NumericUpDown spyMegabytes = Number(0, 1048576, 1024);
    private readonly NumericUpDown retentionDays = Number(0, 36500, 30);
    private readonly NumericUpDown retentionMegabytes = Number(0, 1048576, 512);
    private readonly NumericUpDown flows = Number(1, 1000000, 32768);
    private readonly NumericUpDown buffer = Number(1, 4096, 128);
    private readonly Label note = new() { AutoSize = true, MaximumSize = new Size(620, 0), UseMnemonic = false };
    private readonly Label message = new() { AutoSize = true, MaximumSize = new Size(620, 0), UseMnemonic = false };
    private readonly InputTextBox command = new()
    {
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.Vertical,
        AccessibleName = "Collector command line"
    };
    private readonly CommandButton start = new() { Text = "&Start collector", AutoSize = true };
    private readonly ToolTip hints = new() { AutoPopDelay = 15000 };
    private readonly TableLayoutPanel fields;
    private readonly TableLayoutPanel limitsTable;
    private readonly List<(Label Caption, NumericUpDown Value, Func<bool> Applies)> limits = [];
    private bool spyActive;
    private readonly string collector;
    private bool synchronizing;
    public CollectorOptions? Options { get; private set; }

    public CollectorDialog(string? connectedJournal, string collector)
    {
        this.collector = collector;
        Text = "Launch collector";
        Font = new Font("Segoe UI", 9);
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96, 96);
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        MinimumSize = new Size(680, 0);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MinimizeBox = MaximizeBox = false;
        Padding = new Padding(12);
        fields = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 12 };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var index = 0; index < fields.RowCount; ++index)
            fields.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        void Add(string caption, Control control, int row)
        {
            fields.Controls.Add(new Label
            {
                Text = caption,
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 4, 12, 4)
            }, 0, row);
            control.Margin = new Padding(0, 3, 0, 3);
            if (control is TableLayoutPanel)
                control.Dock = DockStyle.Fill;
            else
                control.Anchor = control is TextBox or ComboBox ?
                    AnchorStyles.Left | AnchorStyles.Right : AnchorStyles.Left;
            fields.Controls.Add(control, 1, row);
        }
        (Control Row, CommandButton Browse) Picker(InputTextBox text, Func<string?> choose)
        {
            var row = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Fill };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            text.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            text.Margin = new Padding(0, 3, 8, 3);
            var browse = new CommandButton { Text = "Browse…", AutoSize = true, Margin = new Padding(0, 3, 0, 3) };
            browse.Click += (_, _) =>
            {
                if (choose() is { } path)
                    text.Text = path;
            };
            row.Controls.Add(text, 0, 0);
            row.Controls.Add(browse, 1, 0);
            return (row, browse);
        }
        mode.Items.AddRange(["Live capture", "Replay a capture file"]);
        traffic.Items.AddRange(["Network and same-host traffic", "Network only", "Same-host traffic only"]);
        mode.SelectedIndex = traffic.SelectedIndex = 0;
        Add("&Mode", mode, 0);
        var (journalRow, _) = Picker(journal, () =>
        {
            using var dialog = new SaveFileDialog
            {
                Title = "Choose the capture journal",
                Filter = "SQLite databases|*.db;*.sqlite;*.sqlite3|All files|*.*",
                OverwritePrompt = false,
                CheckPathExists = true
            };
            return dialog.ShowDialog(this) == DialogResult.OK ? dialog.FileName : null;
        });
        Add("&Journal", journalRow, 1);
        var (captureRow, _) = Picker(capture, () =>
        {
            using var dialog = new OpenFileDialog
            {
                Title = "Choose a capture to replay",
                Filter = "Packet captures|*.pcap|All files|*.*"
            };
            return dialog.ShowDialog(this) == DialogResult.OK ? dialog.FileName : null;
        });
        Add("Capture &file", captureRow, 2);
        var (keyRow, _) = Picker(keyLog, () =>
        {
            using var dialog = new OpenFileDialog
            {
                Title = "Choose the TLS key log",
                Filter = "Key logs|*.log;*.txt|All files|*.*",
                CheckFileExists = false
            };
            return dialog.ShowDialog(this) == DialogResult.OK ? dialog.FileName : null;
        });
        Add("&Key log", keyRow, 3);
        Add("&Traffic", traffic, 4);
        Add("&Duration (seconds)", duration, 5);

        // Collection choices sit in two columns to keep the dialog short.
        var checks = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 2,
            Dock = DockStyle.Fill,
            Margin = Padding.Empty
        };
        checks.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        checks.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var boxes = new[] { processes, schannel, http, endpoint, classify, spy, null, credentials };
        for (var index = 0; index < boxes.Length; ++index)
            if (boxes[index] is { } box)
            {
                box.AutoSize = true;
                box.Margin = new Padding(0, 3, 12, 3);
                checks.Controls.Add(box, index % 2, index / 2);
            }
        fields.Controls.Add(checks, 0, 6);
        fields.SetColumnSpan(checks, 2);
        checks.Controls.Add(target, 0, 4);
        checks.SetColumnSpan(target, 2);
        target.Click += (_, _) =>
        {
            using var dialog = new OpenFileDialog { Title = "Choose the target application", Filter = "Applications|*.exe" };
            if (dialog.ShowDialog(this) != DialogResult.OK)
                return;
            targetApp = dialog.FileName;
            if (keyLog.Text.Trim().Length == 0)
                keyLog.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Cipherazzi", "KeyLogs", Guid.NewGuid().ToString("N") + ".log");
            Synchronize();
        };

        // Limits pair a caption with its value, two to a row; Synchronize shows only those that apply.
        limitsTable = new TableLayoutPanel
        {
            AutoSize = true,
            ColumnCount = 4,
            Dock = DockStyle.Fill,
            Margin = Padding.Empty
        };
        limitsTable.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        limitsTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        limitsTable.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        limitsTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        foreach (var (caption, value, applies) in new (string, NumericUpDown, Func<bool>)[]
        {
            ("Keep metadata (days)", retentionDays, () => true), ("Journal size (MB)", retentionMegabytes, () => true),
            ("Max connections", flows, () => Live), ("Buffer (MB)", buffer, () => Live),
            ("Body limit (KB)", bodyKilobytes, () => spyActive), ("Keep decoded (days)", spyDays, () => spyActive),
            ("Decoded store (MB)", spyMegabytes, () => spyActive)
        })
        {
            var label = new Label { Text = caption, AutoSize = true, Anchor = AnchorStyles.Left };
            value.Anchor = AnchorStyles.Left;
            limitsTable.Controls.Add(label);
            limitsTable.Controls.Add(value);
            limits.Add((label, value, applies));
        }
        fields.Controls.Add(limitsTable, 0, 7);
        fields.SetColumnSpan(limitsTable, 2);
        fields.Controls.Add(note, 0, 8);
        fields.SetColumnSpan(note, 2);
        note.Margin = new Padding(0, 6, 0, 3);
        fields.Controls.Add(message, 0, 9);
        fields.SetColumnSpan(message, 2);
        message.Margin = new Padding(0, 3, 0, 3);
        Add("Command", command, 10);
        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false
        };
        var cancel = new CommandButton { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        start.TabIndex = 0;
        cancel.TabIndex = 1;
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(start);
        fields.Controls.Add(buttons, 0, 11);
        fields.SetColumnSpan(buttons, 2);
        Controls.Add(fields);
        AcceptButton = start;
        CancelButton = cancel;
        FitCommand();

        // Explain each choice and expose the same guidance to assistive tools.
        foreach (var (control, hint) in new (Control, string)[]
        {
            (mode, "Capture live traffic on this computer, or decode a packet capture that was saved earlier."),
            (journal, "The journal the collector writes. The viewer opens it while collection runs."),
            (capture, "A classic .pcap packet capture to analyze instead of live traffic."),
            (keyLog, "TLS secrets exported by the captured applications. Live capture tails this file and preserves " +
                "the application's TLS connection. Leave empty for interception."),
            (target, "Start a new application with SSLKEYLOGFILE after capture is ready. Close existing instances " +
                "first. The application must support exporting TLS secrets."),
            (traffic, "Choose which live traffic to capture; same-host traffic uses the packaged signed driver."),
            (duration, "Stop collecting after this many seconds; 0 runs until you stop the collector."),
            (processes, "Name the local process behind each connection when it can be determined."),
            (schannel, "Also record Windows Schannel and CAPI2 events from this computer's applications."),
            (http, "Record HTTP request metadata along with authentication and tunnel evidence."),
            (endpoint, "Collect only endpoint events, with no packet capture."),
            (classify, "Flag high-entropy traffic of unknown type as possibly encrypted."),
            (spy, "Read HTTP and HTTPS requests and responses into a store only administrators can open."),
            (credentials, "Cookies, Authorization, and API or CSRF token headers are masked by default. Keep their real " +
                "values; they then appear in the store and in HAR exports.")
        })
        {
            hints.SetToolTip(control, hint);
            control.AccessibleDescription = hint;
        }
        journal.Text = connectedJournal ?? Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData), "Cipherazzi", "capture.db");
        foreach (var control in new Control[] { mode, journal, capture, keyLog, traffic, duration, processes, schannel,
            http, endpoint, classify, spy, credentials, bodyKilobytes, spyDays, spyMegabytes, retentionDays,
            retentionMegabytes, flows, buffer })
        {
            if (control is TextBox text)
                text.TextChanged += (_, _) => Synchronize();
            else if (control is CheckBox check)
                check.CheckedChanged += (_, _) => Synchronize();
            else if (control is ComboBox choice)
                choice.SelectedIndexChanged += (_, _) => Synchronize();
            else if (control is NumericUpDown number)
                number.ValueChanged += (_, _) => Synchronize();
        }
        start.Click += (_, _) =>
        {
            Options = Gather();
            DialogResult = DialogResult.OK;
        };
        Synchronize();
    }

    private static NumericUpDown Number(int minimum, int maximum, int value) => new()
    {
        Minimum = minimum,
        Maximum = maximum,
        Value = value,
        AutoSize = true,
        ThousandsSeparator = true
    };

    private bool Live => mode.SelectedIndex == 0;

    private CollectorOptions Gather() => new()
    {
        Live = Live,
        Journal = journal.Text.Trim(),
        Replay = Live ? "" : capture.Text.Trim(),
        KeyLog = spy.Checked && !(Live && endpoint.Checked) ? keyLog.Text.Trim() : "",
        TargetApp = Live && spy.Checked && !endpoint.Checked && keyLog.Text.Trim().Length > 0 ? targetApp : "",
        Traffic = (CollectorTraffic)traffic.SelectedIndex,
        DurationSeconds = (int)duration.Value,
        Processes = processes.Checked,
        Http = http.Checked,
        ClassifyRaw = classify.Checked,
        Schannel = Live && schannel.Checked,
        EndpointOnly = Live && endpoint.Checked,
        HttpSpy = spy.Checked && !(Live && endpoint.Checked),
        Credentials = credentials.Checked && spy.Checked && !(Live && endpoint.Checked),
        BodyKilobytes = (int)bodyKilobytes.Value,
        HttpSpyDays = (int)spyDays.Value,
        HttpSpyMegabytes = (int)spyMegabytes.Value,
        RetentionDays = (int)retentionDays.Value,
        RetentionMegabytes = (int)retentionMegabytes.Value,
        MaxFlows = (int)flows.Value,
        BufferMegabytes = (int)buffer.Value
    };

    // Show only the choices that apply, and keep the command line and Start button in step with them.
    private void Synchronize()
    {
        if (synchronizing)
            return;
        synchronizing = true;
        var live = Live;
        foreach (Control control in fields.Controls)
            switch (fields.GetRow(control))
            {
                case 2: control.Visible = !live; break;
                case 3: control.Visible = spy.Checked && !(live && endpoint.Checked); break;
                case 4 or 5: control.Visible = live; break;
            }
        processes.Visible = schannel.Visible = endpoint.Visible = live;
        endpoint.Enabled = schannel.Checked;
        if (!schannel.Checked)
            endpoint.Checked = false;
        var endpointOnly = live && endpoint.Checked;
        if (endpointOnly)
            traffic.SelectedIndex = 0;
        traffic.Enabled = !endpointOnly;
        spy.Enabled = !endpointOnly;
        spyActive = spy.Checked && !endpointOnly;
        credentials.Enabled = spyActive;
        target.Visible = live && spyActive;
        var position = 0;
        foreach (var (caption, value, applies) in limits)
        {
            caption.Visible = value.Visible = applies();
            if (!caption.Visible)
                continue;
            caption.Margin = new Padding(position % 2 * 12, 4, 8, 4);
            limitsTable.SetCellPosition(caption, new TableLayoutPanelCellPosition(position % 2 * 2, position / 2));
            limitsTable.SetCellPosition(value, new TableLayoutPanelCellPosition(position % 2 * 2 + 1, position / 2));
            ++position;
        }
        var options = Gather();
        var problem = options.Validate();
        message.ForeColor = UiTheme.Error;
        message.Text = problem ?? "";
        message.Visible = problem is not null;
        start.Enabled = problem is null;
        command.Text = options.CommandLine(collector);
        note.Text = (live && !CollectorLauncher.Elevated() ? "Live capture asks for administrator approval. " : "") +
            (options.HttpSpy && live && options.KeyLog.Length > 0 ? "Passive HTTP Spy reads the growing key log. " +
                (options.TargetApp.Length > 0 ? $"Starts {Path.GetFileName(options.TargetApp)} with SSLKEYLOGFILE; " +
                    "close existing instances first. " : "") :
            options.HttpSpy && live ? "HTTP Spy installs a temporary root certificate and routes this computer's " +
                "outbound HTTPS through the collector while it runs; decoded traffic is readable only by " +
                "administrators. " : "") + "The collector runs in its own window; press Ctrl+C there to stop it.";
        synchronizing = false;
    }

    private void FitCommand() => command.MinimumSize = new Size(0, Font.Height * 3 + 8 * DeviceDpi / 96);

    protected override void OnFontChanged(EventArgs e)
    {
        base.OnFontChanged(e);
        FitCommand();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            hints.Dispose();
        base.Dispose(disposing);
    }
}
