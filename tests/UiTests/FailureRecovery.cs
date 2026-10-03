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
        using var crowded = new PoliciesView(new() { ScopedPolicies = large.ScopedPolicies,
            PersistencePath = Path.Combine(directory, "large-save.config") });
        host.Controls.Clear();
        host.Controls.Add(crowded);
        Descendants(crowded).OfType<Button>().Single(button => button.Text == "Appl&y policies").PerformClick();
        Require(Descendants(crowded).OfType<Label>()
            .Any(label => label.Text.StartsWith("Policies could not be applied.")),
            "An oversized configuration escaped its save error handler.");
        Require(!Directory.EnumerateFiles(directory, "*.tmp").Any(),
            "A failed settings save retained temporary files.");
        return Task.FromResult<object>(new { invalid_edits = 3, corrected_policy_saved = true,
            oversized_configuration_rejected = true });
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
        foreach (var failedPath in new[] { large, Path.Combine(directory, "missing-baseline.json") })
        {
            await view.ImportBaselineAsync(failedPath);
            Require(ReferenceEquals(original, field.GetValue(view)),
                "A failed baseline import replaced current evidence.");
        }
        await view.SaveBaselineAsync(Path.Combine(directory, "missing-directory", "baseline.json"));
        Require(ReferenceEquals(original, field.GetValue(view)) &&
            Descendants(view).OfType<Label>().Any(label => label.Text.StartsWith("Baseline could not be saved.")),
            "A failed baseline save escaped recovery or replaced current evidence.");
        await view.ImportBaselineAsync(good);
        Require(field.GetValue(view) is MigrationBaseline && !ReferenceEquals(original, field.GetValue(view)) &&
            Descendants(view).OfType<Label>().Any(label => label.Text == "Migration baseline loaded."),
            "A valid baseline could not be loaded after failures.");
        return new { malformed_imports = 4, oversized_and_missing_files_rejected = true,
            failed_save_recovered = true, valid_baseline_restored = true };
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
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
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
        var host = new Form { ShowInTaskbar = false, StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000), ClientSize = new Size(1440, 900) };
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
