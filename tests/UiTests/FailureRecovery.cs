using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Xml.Linq;
using Cipherazzi.Data;
using Cipherazzi.Viewer;
using Microsoft.Data.Sqlite;

namespace Cipherazzi.UiTests;

internal static class FailureRecovery
{
    public static async Task<object> ConfigurationNoticeAsync(Form runner, DatabaseSource source, string directory)
    {
        var path = Path.Combine(directory, "startup-invalid.config");
        File.WriteAllText(path, "<cipherazzi><viewer theme='invalid'/></cipherazzi>");
        var settings = ViewerSettings.Load(path);
        var warning = settings.Warning ?? throw new InvalidOperationException(
            "The startup fixture must have a configuration warning.");
        settings.Live = false;
        using var window = new MainForm(source, null, settings)
        {
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000)
        };
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        window.FormClosed += (_, _) => closed.TrySetResult();
        var flags = BindingFlags.NonPublic | BindingFlags.Instance;
        bool VisibleWarning() => Descendants(window).OfType<Label>()
            .Any(label => label.Visible && label.Text.Contains(warning, StringComparison.Ordinal));
        async Task Until(Func<bool> condition)
        {
            var deadline = Stopwatch.StartNew();
            while (!condition())
            {
                Require(deadline.Elapsed < TimeSpan.FromSeconds(5), "The configuration warning view did not settle.");
                await Task.Delay(20);
            }
        }
        window.Show(runner);
        try
        {
            // Refreshing capture health must not hide a rejected configuration or its fallback settings.
            var grid = Descendants(window).OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
            await Until(() => grid.RowCount > 0 && VisibleWarning());
            var initial = VisibleWarning();
            Require(initial && grid.RowCount > 0, "The initial configuration warning or connection page is missing.");
            var refresh = typeof(MainForm).GetMethod("RefreshAsync", flags)!;
            await ((Task)refresh.Invoke(window, [false, false])!).WaitAsync(TimeSpan.FromSeconds(5));
            var afterRefresh = VisibleWarning();
            File.WriteAllText(Path.Combine(directory, "configuration-notice.json"), JsonSerializer.Serialize(new
            {
                initial_warning_visible = initial,
                warning_visible_after_refresh = afterRefresh,
                status = ((Label)typeof(MainForm).GetField("status", flags)!.GetValue(window)!).Text
            }, new JsonSerializerOptions { WriteIndented = true }));
            Require(afterRefresh, "Refreshing capture health hid the rejected-configuration warning.");

            // Live polling and investigation changes preserve the notice while keeping health feedback available.
            var health = typeof(MainForm).GetField("healthRefreshed", flags)!;
            var live = Descendants(window).OfType<CheckBox>().Single(control => control.Text == "&Live");
            live.Checked = true;
            await ((Task)refresh.Invoke(window, [false, false])!).WaitAsync(TimeSpan.FromSeconds(5));
            health.SetValue(window, DateTime.MinValue);
            await Until(() => (DateTime)health.GetValue(window)! > DateTime.MinValue);
            live.Checked = false;
            Require(VisibleWarning(), "Live polling hid the rejected-configuration warning.");
            var tabs = Descendants(window).OfType<TabControl>()
                .Single(control => control.AccessibleName == "Workspace views");
            tabs.SelectedIndex = 4;
            await Until(() => Descendants(window).OfType<ReadinessView>().Single().Snapshot is not null);
            Require(VisibleWarning(), "Changing investigations hid the rejected-configuration warning.");
            tabs.SelectedIndex = 0;

            // Long warnings and acknowledgement remain reachable at compact and enlarged text sizes in both themes.
            var label = Descendants(window).OfType<Label>()
                .Single(control => control.AccessibleName == "Configuration warning");
            var dismiss = Descendants(window).OfType<Button>()
                .Single(control => control.AccessibleName == "Dismiss configuration warning");
            var frames = new List<object>();
            var font = window.Font;
            foreach (var theme in new[] { "Light", "Dark" })
            {
                settings.Theme = theme;
                typeof(MainForm).GetMethod("ApplyTheme", flags)!.Invoke(window, null);
                foreach (var points in new[] { 9f, 12f })
                {
                    using var scaled = new Font("Segoe UI", points);
                    window.Font = scaled;
                    foreach (var size in new[] { new Size(1000, 650), new Size(1440, 900) })
                    {
                        window.ClientSize = size;
                        window.PerformLayout();
                        await Task.Delay(40);
                        var bounds = label.RectangleToScreen(label.ClientRectangle);
                        var visible = bounds;
                        for (var parent = label.Parent; parent is not null; parent = parent.Parent)
                            visible.Intersect(parent.RectangleToScreen(parent.ClientRectangle));
                        var fits = visible == bounds && label.GetPreferredSize(new(label.Width, 0)).Height <=
                            label.Height && dismiss.GetPreferredSize(Size.Empty).Width <= dismiss.Width &&
                            label.Right <= dismiss.Left && tabs.Top >= label.Parent!.Bottom;
                        frames.Add(new { theme, points, dpi = window.DeviceDpi, size = window.ClientSize,
                            dark = UiTheme.Dark, label = label.Bounds, dismiss = dismiss.Bounds, fits });
                        using var bitmap = new Bitmap(window.Width, window.Height);
                        window.DrawToBitmap(bitmap, new Rectangle(Point.Empty, window.Size));
                        bitmap.Save(Path.Combine(directory,
                            $"configuration-warning-{theme}-{points}-{size.Width}.png"));
                        Require(fits, "Configuration warning or acknowledgement is clipped at this text scale.");
                    }
                    window.Font = font;
                }
            }
            File.WriteAllText(Path.Combine(directory, "configuration-notice-layout.json"), JsonSerializer.Serialize(
                frames, new JsonSerializerOptions { WriteIndented = true }));

            // Tab navigation is independent of which application currently owns desktop keyboard focus.
            window.ActiveControl = null;
            var reached = false;
            for (var attempt = 0; attempt < Descendants(window).Count(); ++attempt)
            {
                if (!window.SelectNextControl(window.ActiveControl, true, true, true, false))
                    break;
                if (window.ActiveControl != dismiss)
                    continue;
                reached = true;
                break;
            }
            Require(reached, "Configuration acknowledgement is not keyboard reachable.");
            dismiss.PerformClick();
            await ((Task)refresh.Invoke(window, [false, false])!).WaitAsync(TimeSpan.FromSeconds(5));
            Require(!VisibleWarning(), "A dismissed configuration warning reappeared after refresh.");
            return new { initial_warning_visible = initial, warning_visible_after_refresh = afterRefresh,
                warning_visible_after_poll_and_navigation = true, dismissed_warning_stays_hidden = true,
                layout_frames = frames.Count };
        }
        finally
        {
            window.Close();
            await closed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        }
    }

    public static async Task<object> ConfigurationAsync(Form runner, DatabaseSource source, string directory)
    {
        // Protected connections retain advanced security settings through the actual dialog's edit/save path.
        var flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var build = typeof(ConnectionDialog).GetMethod("BuildSource", flags)!;
        foreach (var configured in new[]
        {
            new DatabaseSource(DatabaseProvider.SqlServer, "Server=database.example;Database=cipherazzi;" +
                "Integrated Security=true;Encrypt=Strict;Host Name In Certificate=certificate.example;" +
                "Connect Timeout=17;Application Name=Configured viewer"),
            new DatabaseSource(DatabaseProvider.SqlServer, "Server=database.example;Database=cipherazzi;" +
                "Authentication=Sql Password;User ID=fixture;Password=fixture;Encrypt=Strict;" +
                "Host Name In Certificate=certificate.example"),
            new DatabaseSource(DatabaseProvider.PostgreSql, "Host=database.example;Database=cipherazzi;" +
                "SSL Mode=VerifyFull;Root Certificate=C:/PrivateCA/root.pem;" +
                "Passfile=C:/PrivateCA/passwords;Timeout=17;Application Name=Configured viewer"),
            new DatabaseSource(DatabaseProvider.PostgreSql, "Host=database.example;Database=cipherazzi;" +
                "SSL Mode=VerifyCA;Root Certificate=C:/PrivateCA/root.pem;Username=fixture;Password=fixture")
        })
        {
            var credential = Path.Combine(directory, "connection.credential");
            ConnectionCredentials.Save(credential, configured);
            using var dialog = new ConnectionDialog(ConnectionCredentials.Load(credential));
            System.Data.Common.DbConnectionStringBuilder Parse(DatabaseSource value) =>
                value.Provider == DatabaseProvider.SqlServer ?
                    new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(value.ConnectionString) :
                    new Npgsql.NpgsqlConnectionStringBuilder(value.ConnectionString);
            var before = Parse(configured);
            var after = Parse((DatabaseSource)build.Invoke(dialog, null)!);
            Require(before.Keys.Cast<string>().All(key => Equals(before[key], after[key])),
                "The connection dialog changed a loaded connection option without an edit.");
            ((TextBox)typeof(ConnectionDialog).GetField("database", flags)!.GetValue(dialog)!).Text = "edited";
            after = Parse((DatabaseSource)build.Invoke(dialog, null)!);
            var databaseKey = configured.Provider == DatabaseProvider.SqlServer ? "Initial Catalog" : "Database";
            Require((string)after[databaseKey] == "edited" && before.Keys.Cast<string>()
                .Where(key => key != databaseKey).All(key => Equals(before[key], after[key])),
                "Editing a database name discarded advanced connection settings.");
            var encrypted = (CheckBox)typeof(ConnectionDialog).GetField("encryption", flags)!.GetValue(dialog)!;
            var trust = (CheckBox)typeof(ConnectionDialog).GetField("trust", flags)!.GetValue(dialog)!;
            encrypted.Checked = false;
            var unencrypted = (DatabaseSource)build.Invoke(dialog, null)!;
            Require(unencrypted.Provider == DatabaseProvider.SqlServer ?
                new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(unencrypted.ConnectionString).Encrypt ==
                    Microsoft.Data.SqlClient.SqlConnectionEncryptOption.Optional :
                new Npgsql.NpgsqlConnectionStringBuilder(unencrypted.ConnectionString).SslMode ==
                    Npgsql.SslMode.Disable,
                "An explicit encryption edit was ignored.");
            encrypted.Checked = true;
            trust.Checked = true;
            var trusted = (DatabaseSource)build.Invoke(dialog, null)!;
            Require(trusted.Provider == DatabaseProvider.SqlServer ?
                new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(trusted.ConnectionString) is var sql &&
                    sql.Encrypt == Microsoft.Data.SqlClient.SqlConnectionEncryptOption.Mandatory &&
                    sql.TrustServerCertificate :
                new Npgsql.NpgsqlConnectionStringBuilder(trusted.ConnectionString).SslMode == Npgsql.SslMode.Require,
                "An explicit certificate-trust edit was ignored.");
            if (configured.Provider == DatabaseProvider.SqlServer)
            {
                ((CheckBox)typeof(ConnectionDialog).GetField("integrated", flags)!.GetValue(dialog)!).Checked = true;
                var windows = new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(
                    ((DatabaseSource)build.Invoke(dialog, null)!).ConnectionString);
                using var windowsConnection = new Microsoft.Data.SqlClient.SqlConnection(windows.ConnectionString);
                Require(windows.IntegratedSecurity && windows.UserID == "" && windows.Password == "" &&
                    windows.Authentication == Microsoft.Data.SqlClient.SqlAuthenticationMethod.NotSpecified,
                    "Windows authentication retained incompatible password authentication settings.");
            }
        }
        var path = Path.Combine(directory, "configuration-valid.config");
        var settings = new ViewerSettings
        {
            Theme = "Dark",
            Live = false,
            ScopedPolicies = [new() { Name = "Configured rules", RequirePeerVerification = true }],
            SavedSearches = [new("Scoped", InvestigationTarget.Connections,
                new("", "", false, PageCursor.Newest)
                { Conditions = [new(ObservationField.ServerName, FilterComparison.Equals, "case-1.migration.test")] })]
        };
        settings.Save(path);
        var loaded = ViewerSettings.Load(path);
        Require(loaded.Warning is null && loaded.ScopedPolicies.Single().RequirePeerVerification,
            "The valid configuration did not preserve its policy requirements.");
        var expected = Database.Read(source, loaded.SavedSearches.Single().Query, CancellationToken.None).Rows.Count;
        Require(expected > 0 && expected < 250, "The configuration fixture needs a bounded filtered population.");
        using var connection = source.CreateConnection();
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT max(first_us)+1 FROM connections";
        var afterLast = Convert.ToInt64(command.ExecuteScalar());
        var cases = new List<object>();
        var rejected = 0;
        foreach (var (name, change, policyFile) in new (string, Action<XElement>, bool)[]
        {
            ("policy-element", root => root.Element("policies")!.Element("policy")!.Name = "polciy", true),
            ("nested-policy-rule", root =>
            {
                var policy = root.Element("policies")!.Element("policy")!;
                policy.Attribute("requirePeerVerification")!.Remove();
                policy.Add(new XElement("requirePeerVerification", true));
            }, true),
            ("namespaced-policy-rule", root =>
            {
                var policy = root.Element("policies")!.Element("policy")!;
                policy.Attribute("requirePeerVerification")!.Remove();
                policy.Add(new XAttribute(XNamespace.Xmlns + "requirePeerVerification", "urn:configuration-test"),
                    new XAttribute(XName.Get("requirePeerVerification", "urn:configuration-test"), true));
            }, true),
            ("duplicate-policies", root => root.Add(new XElement(root.Element("policies")!)), true),
            ("policy-section-text", root => root.Element("policies")!
                .ReplaceNodes("requirePeerVerification=true"), true),
            ("search-element", root => root.Element("savedSearches")!.Element("search")!.Name = "serach", false),
            ("search-text", root => root.Element("savedSearches")!.Element("search")!
                .ReplaceNodes("case-1.migration.test"), false),
            ("condition-element", root => root.Element("savedSearches")!.Element("search")!
                .Element("condition")!.Name = "conditon", false),
            ("condition-text", root => root.Element("savedSearches")!.Element("search")!
                .Element("condition")!.Add("another.migration.test"), false),
            ("search-date-attribute", root =>
            {
                var search = root.Element("savedSearches")!.Element("search")!;
                search.Attribute("fromUs")!.Remove();
                search.Add(new XAttribute("fromUss", afterLast));
            }, false),
            ("nested-condition", root => root.Element("savedSearches")!.Element("search")!
                .Element("condition")!.Add(new XElement("extra", "ignored")), false),
            ("viewer-attribute", root =>
            {
                var view = root.Element("viewer")!;
                view.Attribute("showLoopback")!.Remove();
                view.Add(new XAttribute("showLoopBack", false));
            }, false),
            ("nested-viewer-setting", root =>
            {
                var view = root.Element("viewer")!;
                view.Attribute("showLoopback")!.Remove();
                view.Add(new XElement("showLoopback", false));
            }, false),
            ("findings-attribute", root =>
            {
                var findings = root.Element("findings")!;
                findings.Attribute("minimumTls")!.Remove();
                findings.Add(new XAttribute("minimumTlsVersion", 772));
            }, false),
            ("nested-findings-setting", root =>
            {
                var findings = root.Element("findings")!;
                findings.Attribute("minimumTls")!.Remove();
                findings.Add(new XElement("minimumTls", 772));
            }, false)
        })
        {
            // An invalid candidate must not silently remove scope or weaken a saved policy.
            var document = XDocument.Load(path);
            change(document.Root!);
            var candidate = Path.Combine(directory, "invalid-" + name + ".config");
            document.Save(candidate);
            var parsed = ViewerSettings.Load(candidate);
            var policyRejected = true;
            if (policyFile)
            {
                policyRejected = false;
                try { PolicyEvaluator.Load(candidate); }
                catch (InvalidDataException) { policyRejected = true; }
            }
            var rows = parsed.SavedSearches.Count > 0 ? Database.Read(source,
                parsed.SavedSearches[0].Query, CancellationToken.None).Rows.Count : 0;
            var complete = parsed.Warning is not null && parsed.Theme == "System" &&
                parsed.SavedSearches.Count == 0 && parsed.ScopedPolicies.Single().Name == "PQC migration";
            cases.Add(new
            {
                name,
                warning = parsed.Warning,
                theme = parsed.Theme,
                policies = parsed.ScopedPolicies.Count,
                peer_verification = parsed.ScopedPolicies.FirstOrDefault()?.RequirePeerVerification,
                saved_searches = parsed.SavedSearches.Count,
                conditions = parsed.SavedSearches.FirstOrDefault()?.Query.Conditions.Count,
                visible_rows = rows,
                policy_reader_rejected = policyRejected,
                complete_candidate_rejected = complete
            });
            if (complete && policyRejected)
                ++rejected;
        }
        File.WriteAllText(Path.Combine(directory, "configuration-validation.json"), JsonSerializer.Serialize(new
        { filtered_rows = expected, invalid_candidates = cases }, new JsonSerializerOptions { WriteIndented = true }));
        Require(rejected == cases.Count, "Malformed configuration silently changed policies or saved-search scope.");

        // An explicitly empty policy/search list is a valid choice, and exported settings still round-trip.
        var empty = XDocument.Load(path);
        empty.Root!.Element("policies")!.RemoveNodes();
        empty.Root.Element("savedSearches")!.RemoveNodes();
        var emptyPath = Path.Combine(directory, "configuration-empty.config");
        empty.Save(emptyPath);
        var disabled = ViewerSettings.Load(emptyPath);
        Require(disabled.Warning is null && disabled.ScopedPolicies.Count == 0 && disabled.SavedSearches.Count == 0 &&
            PolicyEvaluator.Load(emptyPath).Policies.Count == 0, "Explicitly empty settings were rejected.");
        Require(ViewerSettings.Load(path).SavedSearches.Single().Query.CacheKey ==
            settings.SavedSearches[0].Query.CacheKey,
            "A valid saved-search scope did not round-trip after failures.");

        // Concurrent replacements must preserve the configuration size bound.
        var replacing = Path.Combine(directory, "replacing.config");
        var alternate = Path.Combine(directory, "alternate.config");
        var previous = Path.Combine(directory, "previous.config");
        File.WriteAllText(replacing, "<cipherazzi><viewer theme=\"Light\"/></cipherazzi>");
        File.WriteAllText(alternate, "<cipherazzi><!--" + new string('x', 300 * 1024) +
            "--><viewer theme=\"Dark\"/></cipherazzi>");
        using var stopping = new CancellationTokenSource();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var swaps = 0;
        var swapping = Task.Run(() =>
        {
            while (!stopping.IsCancellationRequested)
            {
                try
                {
                    File.Replace(alternate, replacing, previous);
                    File.Move(previous, alternate);
                    Interlocked.Increment(ref swaps);
                    started.TrySetResult();
                }
                catch (IOException) when (File.Exists(alternate) && File.Exists(replacing)) { }
            }
        });
        var oversizedAccepted = 0;
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
            for (var attempt = 0; attempt < 1000; attempt++)
            {
                var candidate = ViewerSettings.Load(replacing);
                if (candidate.Warning is null && candidate.Theme == "Dark")
                    ++oversizedAccepted;
            }
        }
        finally
        {
            stopping.Cancel();
            await swapping;
        }
        File.WriteAllText(Path.Combine(directory, "configuration-replacements.json"), JsonSerializer.Serialize(new
        { swaps, reads = 1000, oversized_accepted = oversizedAccepted }));
        Require(swaps > 0 && oversizedAccepted == 0,
            "Atomic replacement bypassed the configuration size bound.");
        return new { malformed_candidates_rejected = rejected, valid_scope_rows = expected,
            explicitly_empty_lists_allowed = true, valid_configuration_recovered = true,
            atomic_replacement_reads = 1000, oversized_accepted = oversizedAccepted };
    }

    public static Task<object> PoliciesAsync(Form runner, string directory)
    {
        var path = Path.Combine(directory, "policies.config");
        var settings = new ViewerSettings { PersistencePath = path };
        settings.Save(path);
        var original = File.ReadAllBytes(path);
        using var host = Host(runner);
        using var view = new PoliciesView(settings);
        host.Controls.Add(view);
        var editor = Descendants(view).OfType<PropertyGrid>()
            .Single(control => control.AccessibleName == "Cryptographic policy editor");
        var apply = Descendants(view).OfType<Button>().Single(button => button.Text == "Appl&y policies");
        var policy = (CryptoPolicy)editor.SelectedObject!;
        var applied = 0;
        view.PoliciesChanged += () => ++applied;

        // Invalid edits must stay editable without publishing them or losing the saved configuration.
        foreach (var change in new Action<CryptoPolicy>[]
        {
            candidate => candidate.Name = "", candidate => candidate.AllowedGroups = "0x10000",
            candidate => candidate.AllowedCertificateKeys = "bad.oid"
        })
        {
            policy.Name = "Recovery policy";
            policy.AllowedGroups = policy.AllowedCertificateKeys = "";
            change(policy);
            apply.PerformClick();
            Require(applied == 0 && File.ReadAllBytes(path).SequenceEqual(original),
                "Invalid policy edits changed the active or saved configuration.");
            Require(Descendants(view).OfType<Label>()
                .Any(label => label.Text.StartsWith("Policies could not be applied.")),
                "Invalid policy edits did not report a recoverable error.");
        }
        policy.Name = "Recovery policy";
        policy.AllowedGroups = policy.AllowedCertificateKeys = "";
        apply.PerformClick();
        Require(applied == 1 && ViewerSettings.Load(path).ScopedPolicies.Single().Name == policy.Name,
            "A corrected policy could not be applied after validation failed.");

        // A locked target must preserve the active and saved policies, then accept the same edit after release.
        var saved = File.ReadAllBytes(path);
        policy.Name = "Locked save recovery";
        using (var locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            apply.PerformClick();
            Require(applied == 1 && File.ReadAllBytes(path).SequenceEqual(saved) &&
                settings.ScopedPolicies.Single().Name == "Recovery policy",
                "A blocked settings replacement changed active policies or damaged the saved file.");
        }
        apply.PerformClick();
        Require(applied == 2 && ViewerSettings.Load(path).ScopedPolicies.Single().Name == policy.Name,
            "A policy save did not recover after its target lock was released.");

        // Protocol changes keep the same editable object while displaying only applicable requirements.
        foreach (var (protocol, category) in new[]
        {
            (PolicyProtocol.Ssh, "SSH"), (PolicyProtocol.Smb, "SMB"), (PolicyProtocol.WireGuard, "VPN"),
            (PolicyProtocol.IkeV2, "VPN"), (PolicyProtocol.OpenVpn, "OpenVPN control")
        })
        {
            policy.Protocol = protocol;
            editor.Refresh();
            var properties = System.ComponentModel.TypeDescriptor.GetProperties(editor.SelectedObject!)
                .Cast<System.ComponentModel.PropertyDescriptor>().ToArray();
            Require(properties.Any(property => property.Category == category) &&
                properties.All(property => property.Category is "Scope" or "Identity" ||
                    property.Category == category || protocol == PolicyProtocol.OpenVpn && property.Category == "VPN"),
                "The protocol policy editor displayed irrelevant requirements.");
            policy.Name = protocol + " policy";
            apply.PerformClick();
            Require(ViewerSettings.Load(path).ScopedPolicies.Single().Protocol == protocol,
                "The protocol policy selection did not survive a settings round trip.");
            foreach (var points in new[] { 9, 12 })
            {
                view.Font = new Font("Segoe UI", points);
                view.PerformLayout();
                using var bitmap = new Bitmap(view.Width, view.Height);
                view.DrawToBitmap(bitmap, view.ClientRectangle);
                bitmap.Save(Path.Combine(directory, protocol + $"-policy-{points}.png"));
            }
        }

        // Compact input can be valid while its complete exported settings exceed the file limit.
        var largePath = Path.Combine(directory, "large-policies.config");
        var groups = string.Join(',', Enumerable.Repeat("0x11EC", 128));
        new XDocument(new XElement("cipherazzi", new XElement("viewer"), new XElement("policies",
            Enumerable.Range(0, 78).Select(index => new XElement("policy", new XAttribute("name", "Policy " + index),
                new XAttribute("allowedGroups", groups), new XAttribute("allowedServerSignatures", groups),
                new XAttribute("allowedClientSignatures", groups)))))).Save(largePath);
        var large = ViewerSettings.Load(largePath);
        Require(large.Warning is null, "The compact configuration fixture must be valid.");
        using var crowded = new PoliciesView(new()
        {
            ScopedPolicies = large.ScopedPolicies,
            PersistencePath = Path.Combine(directory, "large-save.config")
        });
        host.Controls.Clear();
        host.Controls.Add(crowded);
        Descendants(crowded).OfType<Button>().Single(button => button.Text == "Appl&y policies").PerformClick();
        Require(Descendants(crowded).OfType<Label>()
            .Any(label => label.Text.StartsWith("Policies could not be applied.")),
            "An oversized configuration escaped its save error handler.");
        Require(!Directory.EnumerateFiles(directory, "*.tmp").Any(),
            "A failed settings save retained temporary files.");
        return Task.FromResult<object>(new
        {
            invalid_edits = 3,
            corrected_policy_saved = true,
            locked_save_recovered = true,
            oversized_configuration_rejected = true
        });
    }

    public static async Task<object> BaselinesAsync(Form runner, DatabaseSource source, string directory)
    {
        using var host = Host(runner);
        using var view = new ReadinessView(new() { AnalyticsMinutes = 0 });
        host.Controls.Add(view);
        await view.RefreshAsync(source, new Query("", "", false, PageCursor.Newest), true)
            .WaitAsync(TimeSpan.FromSeconds(10));
        Require(view.Snapshot is { Total: > 0 }, "Readiness must load before exercising baseline failures.");
        var good = Path.Combine(directory, "baseline-good.json");
        await view.SaveBaselineAsync(good);
        var field = typeof(ReadinessView).GetField("baseline", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var original = field.GetValue(view);
        var bad = Path.Combine(directory, "baseline-invalid.json");
        var large = Path.Combine(directory, "baseline-oversized.json");
        using (var file = File.Create(large))
            file.SetLength(32L * 1024 * 1024 + 1);

        // Both syntax and semantic failures must preserve the last usable baseline and allow another import.
        foreach (var content in new[] { "{}", "null", "{broken",
            JsonSerializer.Serialize(MigrationBaseline.Load(good) with { Rows = [null!] }) })
        {
            File.WriteAllText(bad, content);
            await view.ImportBaselineAsync(bad);
            Require(ReferenceEquals(original, field.GetValue(view)) &&
                Descendants(view).OfType<Label>().Any(label => label.Text.StartsWith("Baseline could not be loaded.")),
                "A malformed baseline escaped recovery or replaced the usable baseline.");
        }

        // A corrupted count partition must not invent percentages or replace the usable comparison baseline.
        var partitions = new List<object>();
        var rejected = 0;
        foreach (var category in new[] { "Key establishment", "Server authentication", "Completion", "Overflow" })
        {
            var candidate = MigrationBaseline.Load(good);
            var row = candidate.Rows[0];
            row.Total = category == "Overflow" ? long.MaxValue : 10;
            row.Counts = category switch
            {
                "Key establishment" => new() { ["Key establishment: Hybrid post-quantum"] = 8,
                    ["Key establishment: Post-quantum"] = 8 },
                "Server authentication" => new() { ["Server authentication: Post-quantum"] = 8,
                    ["Server authentication: Classical"] = 8 },
                "Completion" => new() { ["Completion: Completed"] = 8, ["Completion: Failed"] = 8 },
                _ => new() { ["Key establishment: Hybrid post-quantum"] = long.MaxValue,
                    ["Key establishment: Post-quantum"] = long.MaxValue }
            };
            File.WriteAllText(bad, JsonSerializer.Serialize(candidate));
            await view.ImportBaselineAsync(bad);
            var preserved = ReferenceEquals(original, field.GetValue(view));
            partitions.Add(new { category, preserved, candidate_total = row.Total, candidate_pq_keys = row.PqKeys });
            if (preserved)
                ++rejected;
            else
            {
                await view.ImportBaselineAsync(good);
                original = field.GetValue(view);
            }
        }
        File.WriteAllText(Path.Combine(directory, "baseline-partitions.json"), JsonSerializer.Serialize(partitions,
            new JsonSerializerOptions { WriteIndented = true }));
        Require(rejected == partitions.Count, "An inconsistent baseline replaced the usable evidence comparison.");
        foreach (var failedPath in new[] { large, Path.Combine(directory, "missing-baseline.json") })
        {
            await view.ImportBaselineAsync(failedPath);
            Require(ReferenceEquals(original, field.GetValue(view)),
                "A failed baseline import replaced current evidence.");
        }
        // Reject a database destination without losing the active comparison or the journal's bytes.
        var protectedJournal = Path.Combine(directory, "baseline-database.json");
        using (var input = (SqliteConnection)source.CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={protectedJournal};Pooling=False"))
        {
            input.Open();
            copy.Open();
            input.BackupDatabase(copy);
        }
        var journalBytes = File.ReadAllBytes(protectedJournal);
        await view.SaveBaselineAsync(protectedJournal);
        Require(ReferenceEquals(original, field.GetValue(view)) &&
            File.ReadAllBytes(protectedJournal).SequenceEqual(journalBytes) &&
            Descendants(view).OfType<Label>().Any(label => label.Text.StartsWith("Baseline could not be saved.")),
            "A database export destination escaped UI recovery or changed the current baseline.");
        await view.SaveBaselineAsync(Path.Combine(directory, "missing-directory", "baseline.json"));
        Require(ReferenceEquals(original, field.GetValue(view)) &&
            Descendants(view).OfType<Label>().Any(label => label.Text.StartsWith("Baseline could not be saved.")),
            "A failed baseline save escaped recovery or replaced current evidence.");
        await view.ImportBaselineAsync(good);
        Require(field.GetValue(view) is MigrationBaseline && !ReferenceEquals(original, field.GetValue(view)) &&
            Descendants(view).OfType<Label>().Any(label => label.Text == "Migration baseline loaded."),
            "A valid baseline could not be loaded after failures.");
        return new
        {
            malformed_imports = 4,
            inconsistent_count_partitions_rejected = rejected,
            oversized_and_missing_files_rejected = true,
            failed_save_recovered = true,
            valid_baseline_restored = true
        };
    }

    public static async Task<object> AnalyticsAsync(Form runner, DatabaseSource source, string directory)
    {
        // Exercise the window's actual task tracking and shutdown with a corrupted analytics range.
        var path = Path.Combine(directory, "analytics-damaged.db");
        using (var original = (SqliteConnection)source.CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
            using var command = copy.CreateCommand();
            command.CommandText = "UPDATE connections SET first_us=CASE WHEN id=(SELECT MIN(id) FROM connections) " +
                "THEN @first ELSE @last END";
            command.Parameters.AddWithValue("@first", long.MinValue);
            command.Parameters.AddWithValue("@last", long.MaxValue);
            command.ExecuteNonQuery();
        }
        var damaged = DatabaseSource.Sqlite(path);
        using var window = new MainForm(damaged, null,
            new ViewerSettings { Live = false, AnalyticsMinutes = 0 })
        {
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000)
        };
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        window.FormClosed += (_, _) => closed.TrySetResult();
        window.Show(runner);

        // Wait for the startup event to select the journal before switching views.
        var startup = Stopwatch.StartNew();
        while (!Descendants(window).OfType<Label>().Any(label => label.Text == damaged.DisplayName) ||
            !Descendants(window).OfType<Button>().Single(button => button.Text == "&Refresh").Enabled)
        {
            if (startup.Elapsed > TimeSpan.FromSeconds(3))
                throw new TimeoutException("The damaged journal did not finish its initial read.");
            await Task.Delay(10);
        }
        Descendants(window).OfType<TabControl>()
            .Single(control => control.AccessibleName == "Workspace views").SelectedIndex = 2;
        var refresh = typeof(MainForm).GetMethod("RefreshActiveViewAsync",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        await ((Task)refresh.Invoke(window, [true])!).WaitAsync(TimeSpan.FromSeconds(3));
        Require(Descendants(window).OfType<Label>()
            .Any(label => label.Text == "Analytics unavailable; refresh to retry."),
            "Corrupted observation dates did not produce a recoverable analytics error.");
        var watch = Stopwatch.StartNew();
        window.Close();
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        return new { corrupt_dates_reported = true, close_ms = watch.Elapsed.TotalMilliseconds };
    }

    private static Form Host(Form runner)
    {
        var host = new Form
        {
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000),
            ClientSize = new Size(1440, 900)
        };
        host.Show(runner);
        return host;
    }

    private static IEnumerable<Control> Descendants(Control parent)
    {
        foreach (Control child in parent.Controls)
        {
            yield return child;
            foreach (var descendant in Descendants(child))
                yield return descendant;
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
