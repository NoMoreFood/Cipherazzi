using Microsoft.Data.SqlClient;
using Npgsql;

namespace Cipherazzi.Viewer;

internal sealed class ConnectionDialog : Form
{
    private readonly ChoiceBox provider = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = true };
    private readonly InputTextBox file = new();
    private readonly InputTextBox server = new() { Text = "localhost" };
    private readonly InputTextBox database = new() { Text = "cipherazzi" };
    private readonly InputTextBox user = new();
    private readonly InputTextBox password = new() { UseSystemPasswordChar = true };
    private readonly NumericUpDown port = new() { Minimum = 1, Maximum = 65535, Value = 5432, AutoSize = true };
    private readonly CheckBox integrated = new() { Text = "&Windows authentication", Checked = true, AutoSize = true };
    private readonly CheckBox encryption = new() { Text = "Require &encrypted connection", Checked = true, AutoSize = true };
    private readonly CheckBox trust = new() { Text = "&Trust server certificate", AutoSize = true };
    private readonly Label message = new() { AutoSize = true, MaximumSize = new Size(550, 0), UseMnemonic = false };
    private readonly CommandButton connect = new() { Text = "&Connect", AutoSize = true };
    private readonly CommandButton load = new() { Text = "&Load connection…", AutoSize = true };
    private readonly CommandButton save = new() { Text = "Sa&ve connection…", AutoSize = true };
    private readonly ToolTip hints = new() { AutoPopDelay = 15000 };
    private readonly TableLayoutPanel fields;
    private readonly CancellationTokenSource cancellation = new();
    public DatabaseSource? Source { get; private set; }

    public ConnectionDialog(DatabaseSource? current)
    {
        Text = "Database connection";
        Font = new Font("Segoe UI", 9);
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96, 96);
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        MinimumSize = new Size(580, 0);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MinimizeBox = MaximizeBox = false;
        Padding = new Padding(12);
        fields = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 11 };
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var row = 0; row < fields.RowCount; ++row)
            fields.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        void Add(string caption, Control control, int row)
        {
            fields.Controls.Add(new Label { Text = caption, AutoSize = true, Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 4, 12, 4) }, 0, row);
            if (control is TextBox or ComboBox or NumericUpDown)
                control.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            else
                control.Dock = DockStyle.Fill;
            control.Margin = new Padding(0, 3, 0, 3);
            fields.Controls.Add(control, 1, row);
        }
        provider.Items.AddRange(["SQLite", "SQL Server", "PostgreSQL"]);
        Add("&Provider", provider, 0);
        var fileRow = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Fill };
        fileRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        fileRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        file.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        file.Margin = new Padding(0, 3, 8, 3);
        file.AccessibleName = "SQLite database path";
        var browse = new CommandButton { Text = "&Browse…", AutoSize = true };
        browse.Margin = new Padding(0, 3, 0, 3);
        fileRow.Controls.Add(file, 0, 0);
        fileRow.Controls.Add(browse, 1, 0);
        browse.Click += (_, _) =>
        {
            using var picker = new OpenFileDialog
            {
                Title = "Open Cipherazzi database", Filter = "SQLite databases|*.db;*.sqlite;*.sqlite3|All files|*.*",
                CheckFileExists = true
            };
            if (picker.ShowDialog(this) == DialogResult.OK)
                file.Text = picker.FileName;
        };
        Add("&File", fileRow, 1);
        Add("&Server", server, 2);
        Add("P&ort", port, 3);
        port.Anchor = AnchorStyles.Left;
        Add("&Database", database, 4);
        Add("", integrated, 5);
        Add("&User name", user, 6);
        Add("P&assword", password, 7);
        integrated.Margin = new Padding(0, 3, 0, 3);
        encryption.Margin = trust.Margin = new Padding(0, 3, 0, 3);
        var security = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown,
            WrapContents = false };
        security.Controls.Add(encryption);
        security.Controls.Add(trust);
        Add("", security, 8);
        fields.Controls.Add(message, 0, 9);
        fields.SetColumnSpan(message, 2);
        message.Margin = new Padding(0, 8, 0, 8);
        message.Text = "View an existing capture journal or replicated server database. " +
            "Start the collector separately from an elevated console or as the Cipherazzi Windows service. " +
            "Saved connections are encrypted for your Windows account.";
        var buttons = new FlowLayoutPanel
        {
            AutoSize = true, Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false
        };
        var cancel = new CommandButton { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel,
            TabIndex = 3 };
        load.TabIndex = 0;
        save.TabIndex = 1;
        connect.TabIndex = 2;
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(connect);
        buttons.Controls.Add(save);
        buttons.Controls.Add(load);
        fields.Controls.Add(buttons, 0, 10);
        fields.SetColumnSpan(buttons, 2);
        Controls.Add(fields);
        AcceptButton = connect;
        CancelButton = cancel;

        // Guide database selection and distinguish opening observations from starting collection.
        foreach (var (control, hint) in new (Control, string)[]
        {
            (provider, "Choose SQLite for a local journal, or SQL Server or PostgreSQL for replicated captures."),
            (file, "Path to an existing Cipherazzi journal. The viewer opens it read-only while collection runs."),
            (browse, "Select an existing local capture journal (.db, .sqlite, or .sqlite3)."),
            (server, "Host name or address of the database server. SQL Server also accepts a named instance."),
            (port, "TCP port of the PostgreSQL server."),
            (database, "Name of the server database containing replicated Cipherazzi observations."),
            (integrated, "Connect to SQL Server using your current Windows account."),
            (user, "Database login used to connect to the server."),
            (password, "Password for the database login. Saved connections are encrypted for your Windows account."),
            (encryption, "Require an encrypted connection to the database server."),
            (trust, "Skip validation of the database server's certificate when encryption is required."),
            (connect, "Open the database and display its captured observations. Start the collector separately."),
            (load, "Load an encrypted connection saved by your Windows account on this computer."),
            (save, "Save this server connection encrypted for your Windows account on this computer.")
        })
        {
            hints.SetToolTip(control, hint);
            control.AccessibleDescription = hint;
        }

        // Keep irrelevant authentication controls out of the tab order and the visible form.
        void UpdateFields()
        {
            var sqlite = provider.SelectedIndex == 0;
            var sqlServer = provider.SelectedIndex == 1;
            for (var row = 1; row <= 8; ++row)
            {
                var visible = row switch
                {
                    1 => sqlite, 3 => provider.SelectedIndex == 2, 5 => sqlServer,
                    6 or 7 => !sqlite && !(sqlServer && integrated.Checked), _ => !sqlite
                };
                foreach (Control control in fields.Controls)
                    if (fields.GetRow(control) == row)
                        control.Visible = visible;
            }
            trust.Enabled = encryption.Checked;
            save.Visible = !sqlite;
        }
        provider.SelectedIndexChanged += (_, _) => UpdateFields();
        integrated.CheckedChanged += (_, _) => UpdateFields();
        encryption.CheckedChanged += (_, _) => UpdateFields();
        void Populate(DatabaseSource? source)
        {
            password.Clear();
            provider.SelectedIndex = source is null ? 0 : (int)source.Provider;
            if (source?.Provider == DatabaseProvider.Sqlite)
                file.Text = source.FilePath;
            else if (source?.Provider == DatabaseProvider.SqlServer)
            {
                var value = new SqlConnectionStringBuilder(source.ConnectionString);
                server.Text = value.DataSource;
                database.Text = value.InitialCatalog;
                integrated.Checked = value.IntegratedSecurity;
                user.Text = value.UserID;
                password.Text = value.Password;
                encryption.Checked = value.Encrypt != SqlConnectionEncryptOption.Optional;
                trust.Checked = value.TrustServerCertificate;
            }
            else if (source?.Provider == DatabaseProvider.PostgreSql)
            {
                var value = new NpgsqlConnectionStringBuilder(source.ConnectionString);
                server.Text = value.Host;
                database.Text = value.Database;
                port.Value = value.Port;
                user.Text = value.Username;
                password.Text = value.Password;
                encryption.Checked = value.SslMode != SslMode.Disable;
                trust.Checked = value.SslMode is SslMode.Require or SslMode.Prefer;
            }
        }
        Populate(current);
        load.Click += (_, _) =>
        {
            using var picker = new OpenFileDialog
            {
                Title = "Load protected connection", Filter = "Protected connections|*.credential|All files|*.*"
            };
            if (picker.ShowDialog(this) != DialogResult.OK)
                return;
            try
            {
                Populate(ConnectionCredentials.Load(picker.FileName));
                message.ForeColor = UiTheme.Foreground;
                message.Text = "Protected connection loaded. Choose Connect to open the database.";
            }
            catch (Exception error)
            {
                message.ForeColor = UiTheme.Error;
                message.Text = error.Message;
            }
        };
        save.Click += (_, _) =>
        {
            using var picker = new SaveFileDialog
            {
                Title = "Save protected connection", Filter = "Protected connections|*.credential",
                DefaultExt = "credential", AddExtension = true
            };
            if (picker.ShowDialog(this) != DialogResult.OK)
                return;
            try
            {
                ConnectionCredentials.Save(picker.FileName, BuildSource());
                message.ForeColor = UiTheme.Foreground;
                message.Text = "Connection saved encrypted for your Windows account on this computer.";
            }
            catch (Exception)
            {
                message.ForeColor = UiTheme.Error;
                message.Text = "Could not save the protected connection. Check the connection details and file path.";
            }
        };
        connect.Click += async (_, _) =>
        {
            connect.Enabled = false;
            load.Enabled = save.Enabled = false;
            foreach (Control control in fields.Controls)
                if (fields.GetRow(control) < 9)
                    control.Enabled = false;
            message.ForeColor = UiTheme.Foreground;
            message.Text = "Connecting…";
            try
            {
                var selected = BuildSource();
                await Task.Run(() => Database.Read(selected, new Query("", "", false, PageCursor.Newest),
                    cancellation.Token), cancellation.Token);
                if (IsDisposed)
                    return;
                Source = selected;
                DialogResult = DialogResult.OK;
            }
            catch (Exception error)
            {
                if (IsDisposed || cancellation.IsCancellationRequested)
                    return;
                message.ForeColor = UiTheme.Error;
                message.Text = error.Message;
                foreach (Control control in fields.Controls)
                    if (fields.GetRow(control) < 9)
                        control.Enabled = true;
                UpdateFields();
                connect.Enabled = true;
                load.Enabled = save.Enabled = true;
            }
        };
        FormClosing += (_, _) =>
        {
            password.Clear();
            cancellation.Cancel();
        };
        void UpdateTextMetrics()
        {
            port.Width = TextRenderer.MeasureText("65535", Font).Width +
                SystemInformation.VerticalScrollBarWidth + 8 * DeviceDpi / 96;
            fields.PerformLayout();
        }
        FontChanged += (_, _) => UpdateTextMetrics();
        DpiChanged += (_, _) => UpdateTextMetrics();
        UpdateTextMetrics();
        UpdateFields();
    }

    private DatabaseSource BuildSource()
    {
        if (provider.SelectedIndex == 0)
        {
            if (!File.Exists(file.Text))
                throw new ArgumentException("An existing SQLite capture journal is required.");
            return DatabaseSource.Sqlite(file.Text);
        }
        if (string.IsNullOrWhiteSpace(server.Text) || string.IsNullOrWhiteSpace(database.Text))
            throw new ArgumentException("Enter a server and database name.");
        if (provider.SelectedIndex == 1)
        {
            var builder = new SqlConnectionStringBuilder
            {
                DataSource = server.Text.Trim(), InitialCatalog = database.Text.Trim(),
                IntegratedSecurity = integrated.Checked, ConnectTimeout = 5, ApplicationName = "Cipherazzi Viewer",
                Encrypt = encryption.Checked ? SqlConnectionEncryptOption.Mandatory : SqlConnectionEncryptOption.Optional,
                TrustServerCertificate = encryption.Checked && trust.Checked
            };
            if (!integrated.Checked)
            {
                builder.UserID = user.Text;
                builder.Password = password.Text;
            }
            return new DatabaseSource(DatabaseProvider.SqlServer, builder.ToString());
        }
        return new DatabaseSource(DatabaseProvider.PostgreSql, new NpgsqlConnectionStringBuilder
        {
            Host = server.Text.Trim(), Port = (int)port.Value, Database = database.Text.Trim(),
            Username = user.Text, Password = password.Text, Timeout = 5, ApplicationName = "Cipherazzi Viewer",
            SslMode = !encryption.Checked ? SslMode.Disable : trust.Checked ? SslMode.Require : SslMode.VerifyFull
        }.ToString());
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            hints.Dispose();
            cancellation.Dispose();
        }
        base.Dispose(disposing);
    }
}
