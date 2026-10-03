using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;

namespace Cipherazzi.UiTests;

internal static class ProtocolUi
{
    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var source = DatabaseSource.Sqlite(args[0]);
        var snapshot = Database.Read(source, new("", "", false, PageCursor.Newest), CancellationToken.None);
        var all = snapshot.Rows;
        var network = args.Contains("--network");
        var edges = args.Contains("--edges");
        var iwarp = args.Contains("--iwarp");
        var roce = args.Contains("--roce");
        var kerberos = args.Contains("--kerberos");
        var negotiation = args.Contains("--negotiation");
        if (kerberos)
        {
            var readiness = PqcInsights.Read(source, new("", "", false, PageCursor.Newest), 0, long.MaxValue,
                "Client application", [new CryptoPolicy()], CancellationToken.None);
            Require(readiness.Total == 0 && readiness.Policies.All(policy => policy.Applicable == 0),
                "Kerberos observations were included in TLS readiness or TLS policy results.");
        }
        var settings = new ViewerSettings
        {
            Theme = "Light", Live = false, AnalyticsMinutes = 0,
            PersistencePath = Path.Combine(output, "Viewer.config")
        };
        using var window = new MainForm(source, null, settings)
        {
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
        };
        var exit = 0;
        var checkedProtocols = new List<object>();
        window.Shown += async (_, _) =>
        {
            try
            {
                var controls = Descendants(window).ToList();
                var grid = controls.OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
                var filter = controls.OfType<ComboBox>().Single(control =>
                    control.AccessibleName == "Observed protocol");
                var refresh = controls.OfType<Button>().Single(control => control.Text == "&Refresh");
                var partial = controls.OfType<CheckBox>().Single(control => control.Text == "Partial e&xchanges");
                var details = controls.OfType<PropertyInspector>().Single(control =>
                    control.AccessibleName == "Selected observation details");
                await Until(() => grid.RowCount == all.Count && refresh.Enabled);

                // Inspect captured protocol evidence through the actual filters and property grid.
                var protocols = kerberos ? new[] { "Kerberos" } : negotiation ? ["Kerberos", "TDS", "SMB"] :
                    iwarp || roce ? ["SMB"] :
                    edges ? ["SSH 2.0", "SMB", "RDP", "TDS", "TLS 1.3"] :
                    network ? ["DTLS 1.0", "DTLS 1.2", "TLS 1.3"] :
                    ["SSH 2.0", "Unknown", "WireGuard", "IKEv2", "OpenVPN"];
                foreach (var protocol in protocols)
                {
                    var expected = all.Where(row => row.Tls == protocol).ToArray();
                    Require(expected.Length != 0, "The UI database lacks the required protocol observations.");
                    filter.SelectedItem = protocol;
                    await Until(() => grid.RowCount == expected.Length && refresh.Enabled);
                    Require(grid.Rows.Cast<DataGridViewRow>().All(row =>
                        row.Cells["Tls"].Value?.ToString() == protocol),
                        "The protocol filter displayed observations from another protocol.");
                    var selected = negotiation ? grid.Rows.Cast<DataGridViewRow>().First(row =>
                        protocol == "Kerberos" ? expected[row.Index].State == "Kerberos error" :
                        protocol != "TDS" || expected[row.Index].Source.EndsWith(":42030", StringComparison.Ordinal)) :
                        roce ? grid.Rows.Cast<DataGridViewRow>().First(row =>
                        expected[row.Index].Value("Transport") == "RoCEv2") : iwarp ?
                        grid.Rows.Cast<DataGridViewRow>().First(row =>
                        expected[row.Index].Source.EndsWith(":41003", StringComparison.Ordinal)) :
                        network ? grid.Rows.Cast<DataGridViewRow>().First(row =>
                        protocol.StartsWith("DTLS") ? row.Cells["DtlsCookie"].Value?.ToString() == "Observed" :
                            row.Cells["Transport"].Value?.ToString() == "QUIC") : grid.Rows[0];
                    grid.CurrentCell = selected.Cells["Tls"];
                    await Until(() => details.Summary.Contains(" · " + protocol) &&
                        details.Grid.SelectedObject is not null);
                    var properties = TypeDescriptor.GetProperties(details.Grid.SelectedObject!)
                        .Cast<PropertyDescriptor>().ToArray();
                    File.WriteAllText(Path.Combine(output, protocol.Replace(' ', '-') + "-properties.json"),
                        JsonSerializer.Serialize(properties.Select(property => new
                        {
                            category = property.Category, name = property.DisplayName,
                            value = property.GetValue(details.Grid.SelectedObject)?.ToString()
                        }), new JsonSerializerOptions { WriteIndented = true }));
                    string Value(string category, string name) => properties.Single(property =>
                        property.Category == category && property.DisplayName == name)
                        .GetValue(details.Grid.SelectedObject)?.ToString() ?? "";
                    if (roce)
                    {
                        Require(Value("SMB negotiation", "SMB Transport Framing") == "SMB Direct / RoCEv2" &&
                            Descendants(details).Any(control => control.Text.Contains("Cipher: AES-128-GCM")) &&
                            Value("Server selection", "Encryption algorithm") == "AES-128-GCM" &&
                            Value("Server selection", "Symmetric key bits") == "128" &&
                            Value("RoCE transport", "RoCE Invariant CRC Checked") == "True" &&
                            Value("RoCE transport", "RoCE Queue Pair Pairing") == "Connection management" &&
                            int.Parse(Value("RoCE transport", "RoCE Client Queue Pair")) > 65535 &&
                            Value("SMB RDMA read", "Type") == "Signing" &&
                            Value("SMB RDMA write", "Descriptor Count") == "1" &&
                            Value("SMB negotiation", "SMB Encrypted Transform Observed") == "True",
                            "RoCE queue pairs and RDMA protection metadata were missing from the viewer.");
                        foreach (var transport in new[] { "RoCEv1", "RoCEv2" })
                        {
                            var query = new Query("", "SMB", false, PageCursor.Newest)
                            {
                                Conditions = [new(ObservationField.Transport, FilterComparison.Equals, transport)]
                            };
                            var filtered = Database.Read(source, query, CancellationToken.None);
                            Require(filtered.Rows.Count == all.Count(row => row.Value("Transport") == transport) &&
                                filtered.Rows.All(row => row.Value("Transport") == transport),
                                "The investigation transport condition disagreed with displayed RoCE metadata.");
                        }
                        var cipherQuery = new Query("", "SMB", false, PageCursor.Newest)
                        {
                            Conditions = [new(ObservationField.Cipher, FilterComparison.Equals, "AES-128-GCM")]
                        };
                        Require(Database.Read(source, cipherQuery, CancellationToken.None).Rows.Count == all.Count,
                            "The investigation cipher condition omitted SMB's negotiated encryption algorithm.");
                    }
                    else if (iwarp)
                    {
                        Require(Value("SMB negotiation", "SMB Transport Framing") == "SMB Direct / iWARP" &&
                            Value("SMB negotiation", "SMB iWARP Markers") == "True" &&
                            Value("SMB negotiation", "SMB iWARP CRC Checked") == "True" &&
                            Value("SMB negotiation", "SMB Signed Message Observed") == "True" &&
                            Value("SMB negotiation", "SMB Encrypted Transform Observed") == "True" &&
                            Value("SMB Direct server", "Selected Version") == "0x0100",
                            "SMB Direct's transport negotiation and protected framing were missing from the viewer.");
                    }
                    else if (network)
                    {
                        Require(snapshot.Diagnostics.Contains("Retention age:"),
                            "Capture health omitted the automatic retention configuration.");
                        Require(Value("Server selection", "Cipher suite").StartsWith("TLS_"),
                            "The network observation lost its selected cipher.");
                        if (protocol.StartsWith("DTLS"))
                        {
                            Require(Value("DTLS", "Cookie exchange") == "Observed" &&
                                properties.All(property => !property.Category.StartsWith("QUIC")),
                                "DTLS properties lost cookie evidence or retained QUIC-only fields.");
                        }
                        else
                        {
                            Require(properties.Any(property => property.Category == "QUIC path 02") &&
                                Value("QUIC", "Path association evidence").Contains("unverified"),
                                "QUIC path details omitted the migration evidence limit.");
                        }
                    }
                    else if (negotiation)
                    {
                        // Outcomes joined from both directions, as replayed from tests/NegotiationFixture.py.
                        int Rows(string name, string value) => expected.Count(row => row.Properties.Any(
                            property => property.Name == name && property.Value == value));
                        if (protocol == "Kerberos")
                            Require(Value("Kerberos exchange", "Kerberos Password Reply: Result") ==
                                    "KRB5_KPASSWD_ACCESSDENIED" &&
                                Value("Kerberos exchange", "Kerberos Error: Name") == "KRB_ERR_GENERIC" &&
                                Rows("Kerberos Password Request: Operation", "Change password") == 3 &&
                                Rows("Kerberos Password Request: Operation", "Set or change password") == 1 &&
                                Rows("Kerberos As Reply: Ticket Encryption", "rc4-hmac") == 1 &&
                                properties.All(property => property.DisplayName != "Handshake completed"),
                                "Change-password evidence was lost or implied a completed change.");
                        else if (protocol == "TDS")
                            Require(Value("TDS negotiation", "TDS Negotiated Encryption") == "None" &&
                                Value("TDS negotiation", "TDS Unencrypted Login Observed") == "True" &&
                                Value("TDS client PRELOGIN", "Encryption") == "Not supported" &&
                                Rows("TDS Negotiated Encryption", "Login only") == 1 &&
                                Rows("TDS Negotiated Encryption", "Entire session") == 1 &&
                                Rows("TDS Negotiated Encryption", "Incompatible settings") == 1 &&
                                Rows("TDS Unencrypted Login Observed", "True") == 1,
                                "Negotiated TDS encryption or an unencrypted login was not displayed.");
                        else
                            Require(Value("SMB negotiation", "SMB Legacy Selected Dialect") == "NT LM 0.12" &&
                                Value("SMB negotiation", "SMB Legacy Selected Dialect Index") == "2",
                                "The selected SMB1 dialect was not resolved in the viewer.");

                        // The grid and the selected observation's overview report the same fixed findings.
                        int Found(string finding) => grid.Rows.Cast<DataGridViewRow>().Count(row =>
                            row.Cells["Findings"].Value?.ToString()?.Contains(finding) == true);
                        bool Overview(string findings) => Descendants(details).Any(control =>
                            control.Text.Contains("findings: " + findings));
                        Require(protocol == "Kerberos" ? Found("Legacy Kerberos encryption observed") == 2 &&
                                Found("observed") == 2 && Overview("None") :
                            protocol == "TDS" ? Found("Unencrypted TDS login observed") == 1 &&
                                Found("Login-only TDS encryption negotiated") == 1 && Found("TDS") == 2 &&
                                Overview("Unencrypted TDS login observed") :
                            Found("SMB1 dialect selected") == 1 && Overview("SMB1 dialect selected"),
                            $"Findings for {protocol} evidence were missing from the grid or the overview.");
                    }
                    else if (edges)
                    {
                        if (protocol == "SSH 2.0")
                        {
                            Require(Value("SSH host certificate", "Type") == "Host" &&
                                Value("SSH host certificate", "Key ID") == "cipherazzi-test-host" &&
                                Value("SSH host certificate", "Principals") ==
                                    "service.example.test, alias.example.test" &&
                                Value("SSH host certificate", "Critical Options") == "None" &&
                                Value("SSH host certificate", "Valid Before") == "2030-01-01 00:00:00 UTC" &&
                                Value("SSH host certificate", "Trust") == "Not verified",
                                "SSH certificate identity, validity, or trust boundaries were not displayed.");
                        }
                        else if (protocol == "SMB")
                            Require(Value("SMB negotiation", "SMB Compression Decoded") == "True" &&
                                Value("SMB negotiation", "SMB Signed Message Observed") == "True" &&
                                Value("SMB negotiation", "SMB Transport Framing") == "NetBIOS over TCP",
                                "SMB transport and compressed signing evidence were missing.");
                        else if (protocol == "RDP")
                        {
                            Require(Value("RDP negotiation", "RDP Requested Protocols") == "TLS, CredSSP (HYBRID)" &&
                                Value("RDP negotiation", "RDP Correlation ID") == "0102030405060708090a0b0c0d0e0f10",
                                "RDP correlation displaced its requested security protocols.");
                            var failed = all.Single(row => row.Destination.EndsWith(":3390", StringComparison.Ordinal));
                            Require(failed.Properties.Any(property => property.Category == "RDP negotiation" &&
                                property.Name == "RDP Failure Code" &&
                                property.Value == "Entra authentication required by server"),
                                "The RDP negotiation failure was not decoded.");
                        }
                        else
                            Require(Value("TDS client PRELOGIN", "Encryption") ==
                                (protocol == "TDS" ? "Available, on" : "Required") &&
                                Value("TDS server PRELOGIN", "Product Version") == "16.0.6210.0",
                                "TDS PRELOGIN roles and encryption requirements were lost through TLS transition.");
                    }
                    else
                    {
                        Require(properties.All(property => property.Category is not ("Client offers" or "QUIC" or
                            "PQC evidence" or "Certificates" or "Session behavior")),
                            "TLS-only properties were presented as evidence for another protocol.");
                        Require(properties.All(property => property.DisplayName != "ClientHello observed"),
                            "The selected protocol retained TLS timing properties.");
                        if (protocol == "SSH 2.0")
                        {
                            Require(properties.Any(property => property.Category.StartsWith("SSH client offers")),
                                "SSH initial offers were missing from the property inspector.");
                        }
                        else if (protocol == "Kerberos")
                        {
                            Require(Value("Kerberos exchange", "Kerberos Tgs Reply: Ticket Encryption") == "rc4-hmac" &&
                                expected[0].State == "Kerberos reply" &&
                                properties.All(property => property.DisplayName != "Handshake completed"),
                                "The viewer lost Kerberos encryption evidence or implied authenticated completion.");
                        }
                        else if (protocol == "Unknown")
                        {
                            Require(details.Summary.Contains("Possible encryption"),
                                "The raw observation summary omitted its uncertain classification.");
                            Require(Value("Raw classification", "Classification") == "Possible encryption" &&
                                int.Parse(Value("Raw classification", "Sample bytes")) is >= 4096 and <= 8192,
                                "Raw classification lost its uncertainty or sample bounds.");
                            Require(Value("Server selection", "Cipher suite") == "Not observed",
                                "The viewer presented a cipher guessed from ciphertext.");
                            if (args.Contains("--require-endpoint"))
                                Require(Value("Raw endpoint", "Reported encryption algorithm") != "Not observed",
                                    "A matched public algorithm report was missing from the viewer.");
                        }
                        else
                        {
                            Require(Value("VPN evidence", "VPN Authentication") == "Unverified",
                                "The viewer omitted the VPN authentication limit.");
                            Require(Value("Server selection", "Cipher suite") == "Not observed",
                                "The viewer assigned a TLS cipher to a VPN protocol.");
                            if (protocol == "OpenVPN")
                                Require(properties.Any(property => property.Category == "OpenVPN control TLS" &&
                                    property.DisplayName == "Offered Ciphers"),
                                    "Encapsulated OpenVPN TLS offers were missing.");
                            var item = details.Grid.SelectedGridItem;
                            while (item?.Parent is { } parent)
                                item = parent;
                            foreach (GridItem category in item!.GridItems)
                                if (category.Label == (protocol == "OpenVPN" ? "OpenVPN control TLS" : "VPN evidence"))
                                    foreach (GridItem property in category.GridItems)
                                        if (property.Label ==
                                            (protocol == "OpenVPN" ? "Offered Ciphers" : "VPN Authentication"))
                                            details.Grid.SelectedGridItem = property;
                        }
                    }
                    checkedProtocols.Add(new { protocol, rows = expected.Length, properties = properties.Length });
                    foreach (var size in new[] { 9, 12 })
                    {
                        window.Font = new Font("Segoe UI", size);
                        window.ClientSize = edges || iwarp || roce || kerberos || negotiation ?
                            new Size(1600, 900) : new Size(1000, 650);
                        window.PerformLayout();
                        if (edges || iwarp || roce || kerberos || negotiation)
                        {
                            var split = controls.OfType<SplitContainer>().Single(control =>
                                control.Panel2.Controls.Contains(details));
                            split.SplitterDistance = Math.Max(split.Panel1MinSize, split.Height / 3);
                            details.Grid.ExpandAllGridItems();
                            var item = details.Grid.SelectedGridItem;
                            while (item?.Parent is { } parent)
                                item = parent;
                            var categoryName = kerberos || protocol == "Kerberos" ? "Kerberos exchange" :
                                negotiation && protocol == "TDS" ? "TDS negotiation" : roce ? "RoCE transport" :
                                protocol == "SSH 2.0" ? "SSH host certificate" :
                                protocol == "SMB" ? "SMB negotiation" : protocol == "RDP" ? "RDP negotiation" :
                                "TDS client PRELOGIN";
                            var propertyName = kerberos ? "Kerberos Tgs Reply: Ticket Encryption" :
                                negotiation ? protocol == "Kerberos" ? "Kerberos Password Reply: Result" :
                                protocol == "TDS" ? "TDS Negotiated Encryption" : "SMB Legacy Selected Dialect" :
                                roce ? "RoCE Client Queue Pair" :
                                iwarp ? "SMB Transport Framing" :
                                protocol == "SSH 2.0" ? "Key ID" :
                                protocol == "SMB" ? "SMB Compression Decoded" : protocol == "RDP" ?
                                "RDP Correlation ID" : "Encryption";
                            foreach (GridItem category in item!.GridItems)
                                if (category.Label == categoryName)
                                    foreach (GridItem property in category.GridItems)
                                        if (property.Label == propertyName)
                                            details.Grid.SelectedGridItem = property;
                        }
                        foreach (var control in controls.Where(control => control.Visible &&
                            control is Button or CheckBox or ComboBox or TextBox))
                            Require(window.ClientRectangle.Contains(window.RectangleToClient(
                                control.RectangleToScreen(control.ClientRectangle))),
                                "A protocol control was clipped at the tested text scale.");
                        using var bitmap = new Bitmap(window.Width, window.Height);
                        window.DrawToBitmap(bitmap, new Rectangle(0, 0, window.Width, window.Height));
                        bitmap.Save(Path.Combine(output, protocol.Replace(' ', '-') + $"-{size}.png"));
                    }
                }

                // Partial exchanges retain protocol offers while excluding uncertain raw samples.
                filter.SelectedIndex = 0;
                await Until(() => grid.RowCount == all.Count && refresh.Enabled);
                partial.Checked = true;
                var expectedPartial = all.Count(row => row.State is "ClientHello" or "ServerHello" or
                    "HelloRetryRequest" or "SSH identification" or "SSH algorithm offers" or
                    "WireGuard initiation" or "IKEv2 SA offers" or "OpenVPN control" or "OpenVPN ClientHello");
                await Until(() => grid.RowCount == expectedPartial && refresh.Enabled);
                var readiness = PqcInsights.Read(source, new("", "", false, PageCursor.Newest), 0, long.MaxValue,
                    "Client application", [], CancellationToken.None);
                Require(readiness.Total == all.Count(row => row.Value("Protocol") is "TLS" or "DTLS"),
                    "TLS/DTLS readiness included observations from another protocol.");
                Require(grid.Rows.Cast<DataGridViewRow>().All(row => row.Cells["Tls"].Value?.ToString() != "Unknown"),
                    "The partial-exchange filter treated an entropy estimate as a handshake.");
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                {
                    verified = true, protocols = checkedProtocols, partial_rows = expectedPartial,
                    dpi = window.DeviceDpi, text_sizes = new[] { 9, 12 }
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
            if (watch.Elapsed > TimeSpan.FromSeconds(15))
                throw new TimeoutException("The protocol UI did not finish loading.");
            await Task.Delay(20);
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
