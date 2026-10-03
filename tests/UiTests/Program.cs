using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;
using Microsoft.Data.Sqlite;

namespace Cipherazzi.UiTests;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        Application.SetHighDpiMode(args.Contains("--dpi-unaware") ? HighDpiMode.DpiUnaware : HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        SQLitePCL.Batteries_V2.Init();
        if (args.FirstOrDefault() == "--browser-endpoint-ui")
            return BrowserEndpointUi.Run(args[1..]);
        if (args.FirstOrDefault() == "--investigation-ui")
            return InvestigationUi.Run(args[1..]);
        foreach (var (protocol, json, category, expected) in new[]
        {
            ("DTLS", """{"protocol":"DTLS","srtp_offered_profiles":[1,7,65090],"srtp_selected_profile":7}""",
                "DTLS-SRTP", "0x0007 (SRTP_AEAD_AES_128_GCM)"),
            ("SSH", """{"protocol":"SSH","ssh_peers":[],"ssh_host_key_type":"ssh-ed25519","ssh_host_key_trust":"Not verified"}""",
                "SSH host key", "Not verified"),
            ("SMB", """{"protocol":"SMB","smb_selected_dialect":"0x0311","smb_encrypted_transform_observed":true}""",
                "SMB negotiation", "0x0311"),
            ("RDP", """{"protocol":"RDP","rdp_selected_protocol":2}""",
                "RDP negotiation", "CredSSP (HYBRID)"),
            ("TDS", """{"protocol":"TDS","tds_packet_framing_observed":true}""",
                "TDS framing", "True"),
            ("TDS", """{"protocol":"TDS","tds_peer_b_prelogin":{"socket_address":"10.0.0.2","encryption":3}}""",
                "TDS peer b PRELOGIN", "Required"),
            ("TDS", """{"protocol":"TDS","tds_negotiated_encryption":"Login only"}""",
                "TDS negotiation", "Login only"),
            ("SMB", """{"protocol":"SMB","smb_legacy_selected_dialect":"NT LM 0.12"}""",
                "SMB negotiation", "NT LM 0.12"),
            ("Kerberos", """{"protocol":"Kerberos","krb_password_request":{"operation":"Set or change password"}}""",
                "Kerberos exchange", "Set or change password")
        })
        {
            var row = new ConnectionRow(1, 1, "", "", "", protocol, "", "", "", "", "");
            var projected = ObservationDetails.Enrich(row, name => name == "crypto_json" ? json : "");
            Require(projected.Properties.Any(property => property.Category == category && property.Value == expected),
                $"{protocol} evidence was not rendered with its expected meaning.");
        }

        // Findings assess evidence that was selected or used; offers and stronger selections produce none.
        foreach (var (json, expected) in new[]
        {
            ("""{"krb_tgs_reply":{"ticket_encryption":"rc4-hmac","reply_encryption":"aes256-cts-hmac-sha1-96"}}""",
                "Legacy Kerberos encryption observed"),
            ("""{"smb_selected_dialect":"0x0311","krb_ap_request":""" +
                """{"ticket_encryption":"aes256-cts-hmac-sha1-96","authenticator_encryption":"des3-cbc-sha1-kd"}}""",
                "Legacy Kerberos encryption observed"),
            ("""{"krb_as_request":{"offered_encryption_types":["aes256-cts-hmac-sha1-96","rc4-hmac"]},"krb_error":""" +
                """{"supported_encryption_types":["des-cbc-md5"]},"krb_as_reply":{"reply_encryption":"etype 99"}}""",
                ""),
            ("""{"ntlm_authenticate":{"nt_response":"NTLMv1 with extended session security"}}""",
                "NTLMv1 response observed"),
            ("""{"ntlm_authenticate":{"nt_response":"NTLMv1","lm_response":"LM"}}""",
                "NTLMv1 response observed; LM response observed"),
            ("""{"ntlm_authenticate":{"nt_response":"NTLMv2","lm_response":"LMv2"},"ntlm_challenge":{}}""", ""),
            ("""{"smb_legacy_response_format":"NT LM 0.12","smb_legacy_offered_dialects":["NT LM 0.12"]}""",
                "SMB1 dialect selected"),
            ("""{"smb_legacy_offered_dialects":["NT LM 0.12","SMB 2.002"],"smb_selected_dialect":"0x0202"}""", ""),
            ("""{"smb_legacy_dialect_rejected":true,"smb_legacy_selected_dialect_index":65535}""", ""),
            ("""{"rdp_requested_protocols":3,"rdp_selected_protocol":0}""", "Standard RDP Security selected"),
            ("""{"rdp_response_negotiation_observed":false,"rdp_server_encryption_method":"RC4 128-bit"}""",
                "Standard RDP Security selected"),
            ("""{"rdp_requested_protocols":0,"rdp_selected_protocol":2,"rdp_server_encryption_method":"None"}""", ""),
            ("""{"tds_negotiated_encryption":"None","tds_unencrypted_login_observed":true}""",
                "Unencrypted TDS login observed"),
            ("""{"tds_negotiated_encryption":"None"}""", "Unencrypted TDS session negotiated"),
            ("""{"tds_negotiated_encryption":"Login only"}""", "Login-only TDS encryption negotiated"),
            ("""{"tds_negotiated_encryption":"Entire session"}""", ""),
            ("""{"tds_negotiated_encryption":"Incompatible settings","tds_client_prelogin":{"encryption":1}}""", "")
        })
        {
            var row = new ConnectionRow(1, 1, "", "", "", "", "", "", "", "", "");
            var projected = ObservationDetails.Enrich(row, name => name == "crypto_json" ? json : "");
            Require(projected.Value("Findings") == expected,
                $"Evidence {json} produced the findings \"{projected.Value("Findings")}\".");

            // Configured thresholds apply to TLS parameters and leave the fixed conditions in place.
            Require(string.Join("; ", ObservationDetails.Findings(projected.Values,
                new FindingPolicy(MinimumTls: 772, MinimumDhBits: 4096, WarnMissingEms: false))) == expected,
                "A configured finding policy changed the findings for other protocols.");
        }
        if (args.FirstOrDefault() == "--endpoint-ui")
            return EndpointUi.Run(args[1..]);
        if (args.FirstOrDefault() == "--protocol-ui")
            return ProtocolUi.Run(args[1..]);
        if (args.FirstOrDefault() == "--stress")
            return Adversarial.Run(args[1..]);
        if (args.FirstOrDefault() == "--layout-audit")
            return LayoutAudit.Run(args[1..]);
        if (args.FirstOrDefault() == "--scroll-audit")
            return ScrollAudit.Run(args[1..]);
        if (args.FirstOrDefault() is "--migration-ui" or "--performance-ui")
            return MigrationUi.Run(args[1..], args[0] == "--performance-ui");
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "ui.db");
        var target = args.Length > 2 ? DatabaseSource.FromEnvironment(args[2], "CIPHERAZZI_CONNECTION") : null;
        using (var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var destination = new SqliteConnection($"Data Source={path}"))
        {
            source.Open();
            destination.Open();
            source.BackupDatabase(destination);
            using var command = destination.CreateCommand();
            command.CommandText = """
                PRAGMA foreign_keys=OFF;
                BEGIN IMMEDIATE;
                UPDATE metadata SET database_id=lower(hex(randomblob(16)));
                UPDATE capture_sessions SET id=@prefix||id;
                UPDATE connections SET run_id=@prefix||run_id,sni=substr(@prefix,1,8)||'-fixture-'||id||'.test',
                    first_us=@time+id,
                    source_account='ui-Δuser',source_account_domain='LAB',source_account_sid='S-1-5-21-1-2-3-1001';
                UPDATE connection_certificates SET run_id=@prefix||run_id;
                UPDATE endpoint_events SET run_id=@prefix||run_id;
                COMMIT;
                """;
            command.Parameters.AddWithValue("@prefix", Guid.NewGuid().ToString("N"));
            command.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000);
            command.ExecuteNonQuery();
            command.CommandText = """
                UPDATE connections SET crypto_json=json_patch(crypto_json,@pqc),
                    group_name='X25519MLKEM768',key_exchange='X25519MLKEM768',tls_name='TLS 1.3',tls_version=772,
                    cipher_name='TLS_AES_256_GCM_SHA384'
                WHERE id=(SELECT id FROM connections ORDER BY first_us DESC,id DESC LIMIT 1 OFFSET 10)
                """;
            command.Parameters.AddWithValue("@pqc", PqcFixture);
            command.ExecuteNonQuery();
        }
        async Task Publish()
        {
            if (target is not null)
                while ((await Replication.SyncAsync(path, target, CancellationToken.None)).More) {}
        }
        if (target is not null)
        {
            Replication.InitializeAsync(target, CancellationToken.None).GetAwaiter().GetResult();
            Publish().GetAwaiter().GetResult();
        }
        var settings = new ViewerSettings { Theme = "Light", AnalyticsMinutes = 0,
            PersistencePath = Path.Combine(output, "Viewer.config") };
        using var window = new MainForm(target ?? DatabaseSource.Sqlite(path), null, settings)
        {
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
        };
        var exit = 0;
        var livePrefix = "live-" + Guid.NewGuid().ToString("N")[..8] + "-";
        window.Shown += async (_, _) =>
        {
            try
            {
                var controls = Descendants(window).ToList();
                var grid = controls.OfType<DataGridView>().Single(c => c.Name == "ConnectionsGrid");
                var live = controls.OfType<CheckBox>().Single(c => c.Text == "&Live");
                var refresh = controls.OfType<Button>().Single(c => c.Text == "&Refresh");
                var search = controls.OfType<TextBox>().Single(c => c.PlaceholderText.Length != 0);
                var details = controls.OfType<PropertyInspector>().Single(c =>
                    c.AccessibleName == "Selected observation details");
                await Until(() => grid.RowCount == 250 && refresh.Enabled);
                window.ClientSize = new Size(1000, 650);
                window.PerformLayout();
                var visibleRows = grid.DisplayedRowCount(false);
                var rowHeight = grid.RowTemplate.Height;
                var gridHeight = grid.Height;
                Save(window, Path.Combine(output, "compact-light.png"));
                grid.CurrentCell = grid.Rows[10].Cells[0];
                grid.FirstDisplayedScrollingRowIndex = 5;
                grid.HorizontalScrollingOffset = 180;
                var horizontal = grid.HorizontalScrollingOffset;
                var selected = grid.CurrentRow!.Cells["Sni"].Value!.ToString();
                await Until(() => details.Summary.StartsWith(selected!));
                var sniProperty = System.ComponentModel.TypeDescriptor.GetProperties(details.Grid.SelectedObject!)
                    .Cast<System.ComponentModel.PropertyDescriptor>().Single(item => item.Category == "Connection" &&
                        item.DisplayName == "SNI");
                Require(sniProperty.GetValue(details.Grid.SelectedObject)?.ToString() == selected,
                    "The property grid retained values from the previous row.");
                var descriptor = (System.ComponentModel.ICustomTypeDescriptor)details.Grid.SelectedObject!;
                var descriptors = descriptor.GetProperties();
                Require(ReferenceEquals(descriptors, descriptor.GetProperties()) &&
                    ReferenceEquals(descriptors, descriptor.GetProperties(null)),
                    "An unchanged inspector snapshot rebuilt its property descriptors.");
                var identityProperties = System.ComponentModel.TypeDescriptor
                    .GetProperties(details.Grid.SelectedObject!)
                    .Cast<System.ComponentModel.PropertyDescriptor>()
                    .ToDictionary(item => (item.Category, item.DisplayName));
                string expectedComputer;
                using (var journal = new SqliteConnection($"Data Source={path}"))
                {
                    journal.Open();
                    using var command = journal.CreateCommand();
                    command.CommandText = """
                        SELECT s.computer_name FROM connections c JOIN capture_sessions s ON s.id=c.run_id
                        WHERE c.id=(SELECT id FROM connections ORDER BY first_us DESC,id DESC LIMIT 1 OFFSET @index)
                        """;
                    command.Parameters.AddWithValue("@index", grid.CurrentRow.Index);
                    expectedComputer = command.ExecuteScalar()?.ToString() ?? "";
                }
                Require(identityProperties[("Processes", "Client owner")].GetValue(details.Grid.SelectedObject)?
                    .ToString() == "LAB\\ui-Δuser" && identityProperties[("Connection", "Collector computer")]
                    .GetValue(details.Grid.SelectedObject)?.ToString() == expectedComputer,
                    $"Process account or computer details were not displayed: owner=" +
                    $"{identityProperties[("Processes", "Client owner")].GetValue(details.Grid.SelectedObject)}, " +
                    $"computer={identityProperties[("Connection", "Collector computer")].GetValue(details.Grid.SelectedObject)}, " +
                    $"expected computer={expectedComputer}.");
                Require(grid.CurrentRow!.Cells["GroupClass"].Value?.ToString() == "Hybrid post-quantum" &&
                    grid.CurrentRow.Cells["GroupComponents"].Value?.ToString() == "X25519, ML-KEM-768" &&
                    grid.CurrentRow.Cells["NegotiationStages"].Value?.ToString() == "4",
                    "PQC classification and stage columns were not populated.");
                Require(grid.CurrentRow.Cells["Transport"].Value?.ToString() == "QUIC" &&
                    grid.CurrentRow.Cells["Confirmation"].Value?.ToString() == "Endpoint confirmed completion" &&
                    identityProperties[("Endpoint evidence 1", "Peer handshake signature")]
                    .GetValue(details.Grid.SelectedObject)?.ToString() == "mldsa44" &&
                    identityProperties[("Endpoint evidence 1", "Local handshake signature")]
                    .GetValue(details.Grid.SelectedObject)?.ToString() == "mldsa65",
                    "QUIC transport or endpoint authentication evidence was not displayed.");
                Require(identityProperties[("Negotiation 01 · ClientHello", "Key shares")]
                    .GetValue(details.Grid.SelectedObject)?.ToString() == "0x001D (32 bytes)" &&
                    identityProperties[("Negotiation 03 · ClientHello", "Key shares")]
                    .GetValue(details.Grid.SelectedObject)?.ToString() == "0x11EC (1216 bytes)",
                    "The inspector did not preserve distinct key shares across the retry.");
                var firstVisible = grid.Rows[5].Cells["Sni"].Value!.ToString();
                var watch = Stopwatch.StartNew();
                Insert(path, 1, livePrefix);
                await Publish();
                await Until(() => grid.Rows[0].Cells["Sni"].Value?.ToString() == $"{livePrefix}1.test");
                var latency = watch.Elapsed.TotalMilliseconds;
                Require(grid.CurrentRow?.Cells["Sni"].Value?.ToString() == selected,
                    "Streaming changed the selected connection.");
                Require(grid.Rows[grid.FirstDisplayedScrollingRowIndex].Cells["Sni"].Value?.ToString() == firstVisible,
                    "Streaming moved the reader's vertical position.");
                Require(grid.HorizontalScrollingOffset == horizontal,
                    $"Streaming moved horizontal scrolling from {horizontal} to {grid.HorizontalScrollingOffset}.");

                // Updating evidence must preserve the selected property within its negotiation stage.
                var root = details.Grid.SelectedGridItem;
                while (root?.Parent is { } parent)
                    root = parent;
                var propertyMenu = details.Grid.ContextMenuStrip!;
                propertyMenu.Items.Cast<ToolStripItem>().Single(item => item.Text == "&Expand all").PerformClick();
                Require(root!.GridItems.Cast<GridItem>().Where(item => item.GridItemType == GridItemType.Category)
                    .All(item => item.Expanded), "Expand all left evidence categories collapsed.");
                propertyMenu.Items.Cast<ToolStripItem>().Single(item => item.Text == "&Collapse all").PerformClick();
                Require(root.GridItems.Cast<GridItem>().Where(item => item.GridItemType == GridItemType.Category)
                    .All(item => !item.Expanded), "Collapse all left evidence categories expanded.");
                var stageCategory = root!.GridItems.Cast<GridItem>().Single(item =>
                    item.Label == "Negotiation 01 · ClientHello");
                stageCategory.Expanded = true;
                details.Grid.SelectedGridItem = stageCategory.GridItems.Cast<GridItem>().Single(item =>
                    item.Label == "Key shares");
                using (var update = new SqliteConnection($"Data Source={path}"))
                {
                    update.Open();
                    using var command = update.CreateCommand();
                    command.CommandText = """
                        BEGIN IMMEDIATE;
                        UPDATE metadata SET revision=revision+1;
                        UPDATE connections SET crypto_json=json_set(crypto_json,'$.negotiation_stages_dropped',2,
                            '$.negotiation_history_truncated',json('true')),
                            change_revision=(SELECT revision FROM metadata) WHERE sni=@sni;
                        COMMIT;
                        """;
                    command.Parameters.AddWithValue("@sni", selected);
                    command.ExecuteNonQuery();
                }
                await Publish();
                await Until(() => grid.CurrentRow?.Cells["NegotiationTruncated"].Value?.ToString() == "Yes");
                Require(details.Grid.SelectedGridItem?.Label == "Key shares" &&
                    details.Grid.SelectedGridItem.Parent?.Label == "Negotiation 01 · ClientHello",
                    "Refreshing evidence moved the property selection to a different negotiation stage.");
                Save(window, Path.Combine(output, "pqc-evidence.png"));

                // Exercise pause, manual refresh, resume, and replacement while a live watcher is active.
                live.Checked = false;
                await Task.Delay(350);
                Insert(path, 2, livePrefix);
                await Publish();
                await Task.Delay(600);
                Require(grid.Rows[0].Cells["Sni"].Value?.ToString() == $"{livePrefix}1.test", "Pause did not stop updates.");
                refresh.PerformClick();
                await Until(() => grid.Rows[0].Cells["Sni"].Value?.ToString() == $"{livePrefix}2.test");
                live.Checked = true;
                Insert(path, 3, livePrefix);
                await Publish();
                await Until(() => grid.Rows[0].Cells["Sni"].Value?.ToString() == $"{livePrefix}3.test");
                search.Text = "no-match-ui-check";
                Require(grid.RowCount == 0, "A changed filter retained stale rows.");
                await Until(() => grid.RowCount == 0 && details.Summary.StartsWith("No matching observations."));
                var processKey = typeof(MainForm).GetMethod("ProcessCmdKey",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
                bool Shortcut(Keys keys) => (bool)processKey.Invoke(window, [Message.Create(window.Handle, 0, 0, 0), keys])!;
                Require(Shortcut(Keys.Control | Keys.F) && search.ContainsFocus &&
                    search.SelectionLength == search.TextLength,
                    "Ctrl+F did not focus and select the current search.");
                Require(Shortcut(Keys.Escape) && search.TextLength == 0,
                    "Escape did not clear the focused search.");
                Require(!Shortcut(Keys.Escape), "An empty search consumed Escape.");
                await Until(() => grid.RowCount == 250);
                search.Text = livePrefix.ToUpperInvariant();
                await Until(() => grid.RowCount == 3);
                search.Clear();
                await Until(() => grid.RowCount == 250);

                // Change the real modal settings dialog and verify startup configuration round-trips.
                var configure = controls.OfType<Button>().Single(c => c.Text == "&Options…");
                void Configure(bool apply)
                {
                    using var automation = new System.Windows.Forms.Timer { Interval = 50 };
                    automation.Tick += (_, _) =>
                    {
                        var dialog = Application.OpenForms.OfType<SettingsDialog>().FirstOrDefault();
                        if (dialog is null)
                            return;
                        automation.Stop();
                        var children = Descendants(dialog).ToList();
                        children.OfType<ComboBox>().Single().SelectedItem = apply ? "Dark" : "Light";
                        children.OfType<CheckBox>().Single().Checked = false;
                        children.OfType<NumericUpDown>().Single(c => c.AccessibleName == "Rows per page").Value = 150;
                        var columns = children.OfType<CheckedListBox>().Single();
                        columns.SetItemChecked(settings.Columns.FindIndex(column => column.Name == "Time"), false);
                        if (apply)
                        {
                            // Applying a filtered column list must preserve edits to fields outside the search results.
                            children.OfType<TextBox>().Single(control => control.AccessibleName == "Find columns")
                                .Text = "truncated";
                            var index = Enumerable.Range(0, columns.Items.Count).Single(index =>
                                columns.Items[index].ToString()!.StartsWith("Stage history truncated"));
                            columns.SetItemChecked(index, true);
                        }
                        Save(dialog, Path.Combine(output, apply ? "settings.png" : "settings-dark.png"));
                        children.OfType<Button>().Single(c => c.Text == (apply ? "&Apply" : "Cancel")).PerformClick();
                    };
                    automation.Start();
                    configure.PerformClick();
                }
                Configure(true);
                await Until(() => grid.RowCount == 150 && refresh.Enabled);
                Require(!grid.Columns["Time"]!.Visible && grid.Columns["NegotiationTruncated"]!.Visible &&
                    settings.Theme == "Dark" && UiTheme.Dark,
                    "Column or theme settings were not applied.");
                Configure(false);
                Require(settings.Theme == "Dark", "Cancel changed the active settings.");
                search.Text = selected!;
                await Until(() => grid.RowCount == 1 && details.Summary.StartsWith(selected!));
                window.ClientSize = new Size(1440, 900);
                grid.FirstDisplayedScrollingColumnIndex = grid.Columns["GroupClass"]!.Index;
                root = details.Grid.SelectedGridItem;
                while (root?.Parent is { } parent)
                    root = parent;
                var pqcCategory = root!.GridItems.Cast<GridItem>().Single(item => item.Label == "PQC evidence");
                pqcCategory.Expanded = true;
                details.Grid.SelectedGridItem = pqcCategory.GridItems.Cast<GridItem>().Single(item =>
                    item.Label == "Group components");
                Save(window, Path.Combine(output, "pqc-dark.png"));

                // Recover an empty search through the visible action and resume the normal investigation.
                search.Text = "no-match-empty-action-check";
                await Until(() => grid.RowCount == 0 && refresh.Enabled && Descendants(grid).OfType<Label>()
                    .Any(label => label.Visible && label.Text == "No matching connections"));
                Descendants(grid).OfType<Button>().Single(button => button.Visible && button.Text == "Clear filters")
                    .PerformClick();
                await Until(() => grid.RowCount == 150 && refresh.Enabled);
                var configPath = Path.Combine(output, "defaults.config");
                settings.Save(configPath);
                var loaded = ViewerSettings.Load(configPath);
                Require(loaded.Theme == "Dark" && loaded.PageSize == 150 &&
                    loaded.Columns.SequenceEqual(settings.Columns), "Configuration did not round-trip.");
                File.WriteAllText(Path.Combine(output, "invalid.config"),
                    "<cipherazzi><viewer theme='Light' pageSize='1'/></cipherazzi>");
                Require(ViewerSettings.Load(Path.Combine(output, "invalid.config")).Warning is not null,
                    "Invalid configuration was silently accepted.");
                var propertyRoot = details.Grid.SelectedGridItem;
                while (propertyRoot?.Parent is { } parent)
                    propertyRoot = parent;
                var categories = propertyRoot?.GridItems.Cast<GridItem>().Where(item =>
                    item.GridItemType == GridItemType.Category).Select(item => item.Label).ToArray() ?? [];
                Require(categories.Contains("Server selection"),
                    $"The inspector has no categories (sort={details.Grid.PropertySort}).");
                var tabs = controls.OfType<TabControl>().Single(tabControl => tabControl.AccessibleName == "Workspace views");
                for (var index = 1; index <= 3; ++index)
                {
                    tabs.SelectedIndex = index;
                    await Task.Delay(900);
                    Require(!Descendants(tabs.TabPages[index]).OfType<Label>().Any(label =>
                        label.Text.Contains("unavailable", StringComparison.OrdinalIgnoreCase)),
                        "A new workspace tab could not load.");
                    if (index == 2)
                    {
                        Descendants(tabs.TabPages[index]).OfType<ComboBox>()
                            .Single(control => control.AccessibleName == "Analytics grouping")
                            .SelectedItem = "Transport";
                        var table = Descendants(tabs.TabPages[index]).OfType<DataGridView>().Single();
                        await Until(() => table.RowCount > 0 && table.Rows.Cast<DataGridViewRow>().Sum(row =>
                            Convert.ToInt64(row.Cells["Count"].Value)) >= 20000);
                        Require(table.RowCount > 0 && table.Rows.Cast<DataGridViewRow>().Sum(row =>
                            Convert.ToInt64(row.Cells["Count"].Value)) >= 20000,
                            "Analytics only aggregated the current page.");
                        Require(table.Columns.Cast<DataGridViewColumn>().All(column => column.Width >=
                            TextRenderer.MeasureText(column.HeaderText, table.Font).Width + 8),
                            "An analytics header was clipped.");
                    }
                    Save(window, Path.Combine(output, $"tab-{index}.png"));
                }
                tabs.SelectedIndex = 0;
                window.ClientSize = new Size(1440, 900);
                Save(window, Path.Combine(output, "streaming.png"));
                window.ClientSize = new Size(1000, 650);
                await Task.Delay(150);
                Save(window, Path.Combine(output, "compact.png"));
                window.Font = new Font("Segoe UI", 12);
                window.ClientSize = new Size(1600, 1050);
                await Task.Delay(150);
                Save(window, Path.Combine(output, "large-text.png"));
                for (var index = 1; index <= 3; ++index)
                {
                    tabs.SelectedIndex = index;
                    await Task.Delay(150);
                    Save(window, Path.Combine(output, $"tab-{index}-large-text.png"));
                }
                tabs.SelectedIndex = 0;
                window.Scale(new SizeF(1.5f, 1.5f));
                await Task.Delay(150);
                Save(window, Path.Combine(output, "scaled-layout.png"));

                using var dialog = new ConnectionDialog(null)
                {
                    ShowInTaskbar = false, StartPosition = FormStartPosition.Manual,
                    Location = new Point(-20000, -20000)
                };
                UiTheme.Apply(dialog, settings.Theme);
                dialog.Show(window);
                var provider = Descendants(dialog).OfType<ComboBox>().Single();
                for (var index = 0; index < 3; ++index)
                {
                    provider.SelectedIndex = index;
                    await Task.Delay(100);
                    Save(dialog, Path.Combine(output, $"connection-{index}.png"));
                }
                dialog.Font = new Font("Segoe UI", 12);
                await Task.Delay(100);
                Save(dialog, Path.Combine(output, "connection-large-text.png"));
                dialog.Close();

                // Connect through the form so provider fields and authentication options reach the database.
                using var connectionDialog = new ConnectionDialog(target ?? DatabaseSource.Sqlite(path))
                {
                    ShowInTaskbar = false, StartPosition = FormStartPosition.Manual,
                    Location = new Point(-20000, -20000)
                };
                connectionDialog.Show(window);
                var connect = Descendants(connectionDialog).OfType<Button>().Single(c => c.Text == "&Connect");
                connect.PerformClick();
                Require(!connect.Enabled, "Connecting did not show a busy state.");
                await Until(() => connectionDialog.Source is not null);
                Require(connectionDialog.Source!.Provider == (target?.Provider ?? DatabaseProvider.Sqlite),
                    "The connection dialog selected the wrong provider.");
                connectionDialog.Close();

                // Closing during startup and analytics must drain callbacks before disposing the window.
                using var closingWindow = new MainForm(target ?? DatabaseSource.Sqlite(path), null, settings)
                {
                    ShowInTaskbar = false, StartPosition = FormStartPosition.Manual,
                    Location = new Point(-20000, -20000)
                };
                var closed = false;
                closingWindow.FormClosed += (_, _) => closed = true;
                closingWindow.Show(window);
                Descendants(closingWindow).OfType<TabControl>().Single(tabControl => tabControl.AccessibleName == "Workspace views").SelectedIndex = 2;
                await Task.Delay(25);
                closingWindow.Close();
                await Until(() => closed);
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                {
                    streaming_latency_ms = latency, selection_preserved = true, scroll_preserved = true,
                    provider = target?.Provider.ToString() ?? "Sqlite",
                    pause_resume = true, manual_refresh_while_paused = true, live_filtering = true,
                    database_dialogs = 3, dark_mode = true, configurable_columns = true,
                    configuration_roundtrip = true, searchable_columns = true, empty_result_action = true,
                    property_categories = categories.Length,
                    analytics_whole_scope = true, connection_dialog_connect = true, process_account_properties = true,
                    quic_transport = true, endpoint_authentication = true,
                    close_during_queries = true,
                    compact_visible_rows = visibleRows, connection_row_height = rowHeight,
                    compact_grid_height = gridHeight, layout_bounds = true, analytics_headers_visible = true,
                    large_text_all_views = true,
                    collector_computer = true, pqc_columns = true, negotiation_stages = true,
                    negotiation_selection_preserved = true, negotiation_truncation = true
                }, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception error)
            {
                exit = 1;
                File.WriteAllText(Path.Combine(output, "failure.txt"), error.ToString());
            }
            finally { window.Close(); }
        };
        Application.Run(window);
        return exit;
    }

    private const string PqcFixture = """
        {
          "transport":"QUIC","quic_version":1798521807,"quic_original_dcid":"1234567812345678",
          "handshake_confirmation":"Endpoint confirmed completion",
          "endpoint_confirmations":[{"event_id":"ui-endpoint","provider":"UI endpoint adapter",
            "timestamp_us":1790956000040000,"pid":1234,"process_started_us":1790955000000000,
            "local_role":"Client","success":true,"match":"Exact socket and process lifetime",
            "peer_verified":1,"handshake_signature_id":2308,"handshake_signature":"mldsa44",
            "local_handshake_signature_id":2309,"local_handshake_signature":"mldsa65",
            "local_authentication_class":"Post-quantum",
            "authentication_class":"Post-quantum","selected_alpn":"h3","server_certificates":[],
            "client_certificates":[]}],
          "group_class":"Hybrid post-quantum","group_standardization":"Standardized",
          "group_components":["X25519","ML-KEM-768"],"group_reference":"RFC10024",
          "classification_rule_version":1,"negotiation_stages_dropped":0,"negotiation_history_truncated":false,
          "negotiation_stages":[
            {"type":"ClientHello","ordinal":1,"timestamp_us":1790956000000000,"handshake_bytes":240,
             "legacy_version":771,"ech_offered":false,"sni":"pqc-fixture.test","alpn":["h2"],
             "offered_version_ids":[772,771],"cipher_ids":[4866,4865],"group_ids":[4588,29],
             "signature_ids":[2052,1027],"certificate_signature_ids":[],"extension_ids":[0,10,13,16,43,51],
             "key_shares":[{"group_id":29,"bytes":32}]},
            {"type":"HelloRetryRequest","ordinal":2,"timestamp_us":1790956000010000,"handshake_bytes":84,
             "legacy_version":771,"selected_version":772,"cipher_id":4866,"selected_group_id":4588,
             "extension_ids":[43,51],"key_shares":[]},
            {"type":"ClientHello","ordinal":3,"timestamp_us":1790956000020000,"handshake_bytes":1424,
             "legacy_version":771,"ech_offered":false,"sni":"pqc-fixture.test","alpn":["h2"],
             "offered_version_ids":[772,771],"cipher_ids":[4866,4865],"group_ids":[4588,29],
             "signature_ids":[2052,1027],"certificate_signature_ids":[],"extension_ids":[0,10,13,16,43,51],
             "key_shares":[{"group_id":4588,"bytes":1216}]},
            {"type":"ServerHello","ordinal":4,"timestamp_us":1790956000030000,"handshake_bytes":1212,
             "legacy_version":771,"selected_version":772,"cipher_id":4866,"selected_group_id":4588,
             "extension_ids":[43,51],"key_shares":[{"group_id":4588,"bytes":1120}]}
          ]
        }
        """;

    private static IEnumerable<Control> Descendants(Control control)
    {
        foreach (Control child in control.Controls)
        {
            yield return child;
            foreach (var descendant in Descendants(child))
                yield return descendant;
        }
    }

    private static async Task Until(Func<bool> condition)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(8))
                throw new TimeoutException("The UI did not reflect the committed change.");
            await Task.Delay(10);
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private static void Save(Form form, string path)
    {
        form.PerformLayout();

        // Verify command and input bounds while allowing intentional horizontal scrolling in result tables.
        foreach (var control in Descendants(form).Where(control => control.Visible &&
            control is Button or TextBox or ComboBox or CheckBox or NumericUpDown))
        {
            var bounds = form.RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
            Require(form.ClientRectangle.Contains(bounds), $"The {control.GetType().Name} is clipped by the window.");
            Require(control.Parent!.ClientRectangle.Contains(control.Bounds),
                $"The {control.GetType().Name} is clipped by its container.");
        }
        using var bitmap = new Bitmap(form.Width, form.Height);
        form.DrawToBitmap(bitmap, new Rectangle(0, 0, bitmap.Width, bitmap.Height));
        bitmap.Save(path, System.Drawing.Imaging.ImageFormat.Png);
    }

    private static void Insert(string path, int index, string livePrefix)
    {
        using var connection = new SqliteConnection($"Data Source={path}");
        connection.Open();
        var columns = new List<string>();
        using (var schema = connection.CreateCommand())
        {
            schema.CommandText = "PRAGMA table_info(connections)";
            using var reader = schema.ExecuteReader();
            while (reader.Read())
                if (reader.GetString(1) != "id")
                    columns.Add(reader.GetString(1));
        }
        using var command = connection.CreateCommand();
        command.CommandText = "BEGIN IMMEDIATE; UPDATE metadata SET revision=revision+1;" +
            $"INSERT INTO connections({string.Join(',', columns)}) SELECT " +
            string.Join(',', columns.Select(column => column switch
            {
                "flow_id" => "@flow", "sni" => "@sni", "first_us" or "last_us" => "@time",
                "change_revision" => "(SELECT revision FROM metadata)", _ => column
            })) + " FROM connections ORDER BY id LIMIT 1; COMMIT;";
        command.Parameters.AddWithValue("@flow", 1000000000 + index);
        command.Parameters.AddWithValue("@sni", $"{livePrefix}{index}.test");
        command.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000);
        command.ExecuteNonQuery();
    }
}
