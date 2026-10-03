using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;

namespace Cipherazzi.UiTests;

internal static class BrowserEndpointUi
{
    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var source = DatabaseSource.Sqlite(args[0]);
        var mode = args.Length > 2 ? args[2] : "";
        var socketProcess = mode.StartsWith("socket-", StringComparison.Ordinal);
        if (socketProcess) mode = mode[7..];
        var chromium = mode.StartsWith("chromium-", StringComparison.Ordinal);
        if (chromium) mode = mode[9..];
        var protocolFailure = chromium && mode == "protocol";
        var failure = mode == "failure" || protocolFailure;
        var library = mode == "library";
        var noResponse = mode == "no-response";
        var transport = chromium ? failure ? "Unknown" : mode == "tcp" ? "TCP" : "QUIC" :
            socketProcess && noResponse ? "TCP" : failure || library || noResponse ? "Unknown" : "QUIC";
        var settings = new ViewerSettings
        {
            Live = false, AnalyticsMinutes = 0, PersistencePath = Path.Combine(output, "Viewer.config"),
            ScopedPolicies =
            [
                new() { Name = "Completed TLS", MinimumTls = 772, RequirePostQuantumKeyExchange = false,
                    RequirePeerVerification = true, RequireCertificateEvidence = true,
                    AllowedServerSignatures = "0x0804" },
                new() { Name = "Post-quantum keys", MinimumTls = 772, RequireEndpointCompletion = !failure }
            ]
        };
        if (failure)
            settings.ScopedPolicies.Add(new()
            {
                Name = "Peer verification", RequirePostQuantumKeyExchange = false,
                RequireEndpointCompletion = false, RequirePeerVerification = true
            });
        using var window = new MainForm(source, null, settings)
        {
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
        };
        var checks = new List<string>();
        var exit = 0;
        void Check(bool condition, string message)
        {
            if (!condition)
                throw new InvalidOperationException(message);
            checks.Add(message);
        }
        window.Shown += async (_, _) =>
        {
            try
            {
                // Inspect actual imported browser evidence without creating a packet confirmation.
                var controls = Descendants(window).ToList();
                var tabs = controls.OfType<TabControl>().Single(control => control.AccessibleName == "Workspace views");
                tabs.SelectedIndex = 3;
                var grid = controls.OfType<DataGridView>().Single(control => control.Name == "EndpointGrid");
                var inspector = Descendants(tabs.SelectedTab!).OfType<PropertyInspector>().Single();
                await Until(() => grid.RowCount == 1 && inspector.Grid.SelectedObject is not null);
                var properties = TypeDescriptor.GetProperties(inspector.Grid.SelectedObject!).Cast<PropertyDescriptor>()
                    .ToDictionary(property => (property.Category, property.DisplayName),
                        property => property.GetValue(inspector.Grid.SelectedObject)?.ToString() ?? "");
                if (chromium)
                {
                    Check(properties[("Provider metadata", "Local Address")] == "" &&
                        properties[("Provider metadata", "Remote Address")] == "" &&
                        properties[("Provider metadata", "Process Scope")] == "application" &&
                        properties[("Provider metadata", "Process Role")] == "unknown" &&
                        properties[("Provider metadata", "Role")] == "client" &&
                        properties[("Provider metadata", "Transport")] == transport,
                        "Chromium application evidence preserves unknown socket identity and process role");
                    Check((properties[("Provider metadata", "Server Certificates")].Length > 2) == !protocolFailure &&
                        (failure ? properties[("Provider metadata", "Error Name")] ==
                            (protocolFailure ? "ERR_SSL_VERSION_OR_CIPHER_MISMATCH" : "ERR_CERT_AUTHORITY_INVALID") :
                            properties[("Provider metadata", "Selected ALPN")].StartsWith(mode == "tcp" ? "h2" : "h3")),
                        "The browser's actual result and available public certificates appear in the inspector");
                    if (mode == "quic")
                        Check(properties[("Endpoint evidence", "Protocol")] == "QUIC" &&
                            properties[("Provider metadata", "TLS Version")] == "0",
                            "QUIC evidence does not display an invented TLS wire version");
                }
                else if (failure || library || noResponse)
                {
                    Check((noResponse || socketProcess || properties[("Provider metadata", "Local Address")] == "" &&
                        properties[("Provider metadata", "Remote Address")] == "") &&
                        (!failure || properties[("Endpoint evidence", "Cipher")] == "") &&
                        properties[("Provider metadata", "Transport")] ==
                            (socketProcess && noResponse ? "TCP" : "Unknown") &&
                        properties[("Provider metadata", "Process Scope")] ==
                            (socketProcess || library ? "endpoint" : "application") &&
                        properties[("Provider metadata", "Role")] ==
                            (failure && !socketProcess ? "unknown" : "client"),
                        "Endpoint evidence retains its process scope without inventing socket identity or transport");
                    if (noResponse)
                        Check(properties[("Provider metadata", "Process Role")] ==
                            (socketProcess ? "client" : "unknown") &&
                            properties[("Provider metadata", "Local Address")] == "127.0.0.1" &&
                            properties[("Provider metadata", "Remote Address")] == "127.0.0.1",
                            "The TLS connection role remains distinct from the emitting application's process role");
                    if (socketProcess)
                        Check(properties[("Provider metadata", "Process Role")] == "client",
                            "The endpoint inspector retains the identified socket process's TLS role");
                    Check(properties[("Provider metadata", "Server Certificates")].Length > 2 && (failure ?
                        properties[("Provider metadata", "Error Name")] == "SSL_ERROR_BAD_CERT_DOMAIN" :
                        properties[("Provider metadata", "Selected ALPN")] == (noResponse ? "http/1.1" : "h2")),
                        "The endpoint inspector retains public certificates and the reported handshake evidence");
                }
                else
                {
                    Check(properties[("Provider metadata", "Local Address")] == "" &&
                        properties[("Provider metadata", "Local Binding Address")] == "0.0.0.0",
                        "An unspecified binding is distinct from the concrete source address");
                    Check(properties[("Provider metadata", "Selected ALPN")] == "h3" &&
                        properties[("Provider metadata", "Server Certificates")].Length > 2,
                        "The endpoint inspector retains HTTP/3 negotiation and public certificates");
                }
                Check((socketProcess && noResponse ? properties[("Provider metadata", "Correlation")] ==
                    "Unmatched socket, process lifetime, timing, or parameters" :
                    properties[("Provider metadata", "Correlation")].Contains("no packet association asserted")) &&
                    !properties.Keys.Any(key => key.DisplayName is "Matched Flow ID" or "Matched Run ID"),
                    "The endpoint inspector makes the absent packet association explicit");

                // Unassociated endpoint evidence still supports readiness and applicable policy results.
                tabs.SelectedIndex = 4;
                var readiness = controls.OfType<ReadinessView>().Single();
                await Until(() => readiness.Snapshot is not null);
                var snapshot = readiness.Snapshot!;
                Check(snapshot.Total == 1 && snapshot.Rows.Sum(row => row.Complete) == (failure ? 0 : 1) &&
                    snapshot.Rows.Sum(row => row.Failures) == (failure ? 1 : 0) &&
                    snapshot.Rows.Sum(row => row.Count("Evidence source", "Endpoint")) == 1 &&
                    snapshot.Rows.All(row => row.Transport == transport),
                    "Readiness counts the browser endpoint once with its reported outcome and transport");
                tabs.SelectedIndex = 6;
                var policies = controls.OfType<DataGridView>().Single(control => control.Name == "PolicyGrid");
                await Until(() => policies.RowCount == (failure ? 3 : 2) && policies.Rows.Cast<DataGridViewRow>()
                    .All(row => Convert.ToInt64(row.Cells["Applicable"].Value) == 1));
                var complete = policies.Rows.Cast<DataGridViewRow>().Single(row =>
                    row.Cells["Policy"].Value?.ToString() == "Completed TLS");
                var quantum = policies.Rows.Cast<DataGridViewRow>().Single(row =>
                    row.Cells["Policy"].Value?.ToString() == "Post-quantum keys");
                if (chromium)
                {
                    var quantumStatus = protocolFailure ? "Unknown" : failure ? "Violations" : "Pass";
                    Check(Convert.ToInt64(complete.Cells["Unknown"].Value) == (failure ? 0 : 1) &&
                        Convert.ToInt64(complete.Cells["Violations"].Value) == (failure ? 1 : 0) &&
                        Convert.ToInt64(quantum.Cells[quantumStatus].Value) == 1,
                        "Chromium policies preserve missing handshake signatures and reported completion outcomes");
                    if (failure)
                    {
                        var verification = policies.Rows.Cast<DataGridViewRow>().Single(row =>
                            row.Cells["Policy"].Value?.ToString() == "Peer verification");
                        var verificationStatus = protocolFailure ? "Unknown" : "Violations";
                        Check(Convert.ToInt64(verification.Cells[verificationStatus].Value) == 1,
                            "A protocol failure does not invent a certificate trust decision");
                    }
                }
                else if (failure)
                {
                    var verification = policies.Rows.Cast<DataGridViewRow>().Single(row =>
                        row.Cells["Policy"].Value?.ToString() == "Peer verification");
                    Check(Convert.ToInt64(complete.Cells["Violations"].Value) == 1 &&
                        Convert.ToInt64(verification.Cells["Violations"].Value) == 1 &&
                        Convert.ToInt64(quantum.Cells["Unknown"].Value) == 1 &&
                        Convert.ToInt64(quantum.Cells["Violations"].Value) == 0,
                        "Policies distinguish the reported failure from unavailable negotiated algorithms");
                }
                else
                    Check(Convert.ToInt64(complete.Cells["Pass"].Value) == 1 &&
                        Convert.ToInt64(complete.Cells["Unknown"].Value) == 0 &&
                        Convert.ToInt64(quantum.Cells["Violations"].Value) == 1,
                        "Policy results use reported completion, verification, certificates, and algorithms");

                // Verify the affected views at alternate text sizes in light and dark themes.
                foreach (var theme in new[] { "Light", "Dark" })
                {
                    settings.Theme = theme;
                    typeof(MainForm).GetMethod("ApplyTheme", BindingFlags.Instance | BindingFlags.NonPublic)!
                        .Invoke(window, null);
                    foreach (var size in new[] { 9, 12 })
                    {
                        window.Font = new Font("Segoe UI", size);
                        window.ClientSize = new Size(1100, 720);
                        foreach (var view in new[] { 3, 4, 6 })
                        {
                            tabs.SelectedIndex = view;
                            await Until(() => !Descendants(window).OfType<Label>().Any(control => control.Visible &&
                                control.Text.StartsWith("Loading", StringComparison.Ordinal)));
                            window.PerformLayout();
                            var filterButton = Descendants(window).Single(control => control.AccessibleName ==
                                "Dates, field filters, and saved searches");
                            if (filterButton.Visible)
                                for (var ancestor = filterButton; ancestor.Parent is { } parent; ancestor = parent)
                                    Check(parent.ClientRectangle.Contains(ancestor.Bounds),
                                        "The investigation filter action fits within its visible toolbar and viewport");
                            foreach (var control in controls.Where(control => control.Visible &&
                                control is Button or CheckBox or ComboBox or TextBox))
                                Check(window.ClientRectangle.Contains(window.RectangleToClient(
                                    control.RectangleToScreen(control.ClientRectangle))),
                                    "An affected view control fits at the tested text scale");
                            if (view == 3)
                            {
                                var split = controls.OfType<SplitContainer>().Single(control =>
                                    control.Panel2.Controls.Contains(inspector));
                                split.SplitterDistance = Math.Max(split.Panel1MinSize, split.Height / 3);
                                inspector.Grid.ExpandAllGridItems();
                                var item = inspector.Grid.SelectedGridItem;
                                while (item?.Parent is { } parent)
                                    item = parent;
                                foreach (GridItem category in item!.GridItems)
                                    if (category.Label == "Provider metadata")
                                        foreach (GridItem property in category.GridItems)
                                            if (property.Label == "Correlation")
                                                inspector.Grid.SelectedGridItem = property;
                            }
                            using var bitmap = new Bitmap(window.Width, window.Height);
                            window.DrawToBitmap(bitmap, new Rectangle(Point.Empty, window.Size));
                            bitmap.Save(Path.Combine(output, $"{theme}-{size}-{view}.png"));
                        }
                    }
                }
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                {
                    result = "passed", checks = checks.Distinct(), dpi = window.DeviceDpi,
                    text_sizes = new[] { 9, 12 }, views = new[] { "Endpoints", "Readiness", "Policies" }
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

    private static IEnumerable<Control> Descendants(Control control) => control.Controls.Cast<Control>()
        .SelectMany(child => new[] { child }.Concat(Descendants(child)));

    private static async Task Until(Func<bool> ready)
    {
        var watch = Stopwatch.StartNew();
        while (!ready())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(15))
                throw new TimeoutException("The browser endpoint UI did not finish loading.");
            await Task.Delay(25);
        }
    }
}
