using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;

namespace Cipherazzi.UiTests;

// Builds collector command lines from the launch options, starts the real collector the way the viewer does, and
// checks that the toolbar offers to start one only while none is running.
internal static class CollectorUi
{
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(Microsoft.Win32.SafeHandles.SafeWaitHandle handle,
        uint information, byte[] descriptor);

    public static int Run(string[] args)
    {
        var collector = Path.GetFullPath(args[0]);
        var fixtures = Path.GetFullPath(args[1]);
        var output = Path.GetFullPath(args[2]);
        Directory.CreateDirectory(output);
        var checks = new List<string>();
        var exit = 0;
        try
        {
            CheckArguments(output, checks);
            CheckLaunch(collector, fixtures, output, checks);
            CheckDialog(collector, fixtures, output, checks);
        }
        catch (Exception error)
        {
            File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
            { result = "failed", checks, error = error.ToString() },
                new JsonSerializerOptions { WriteIndented = true }));
            return 1;
        }
        var settings = new ViewerSettings { Live = false, Theme = "Light",
            PersistencePath = Path.Combine(output, "Viewer.config") };
        UiTheme.Select(settings.Theme);
        var running = false;
        CollectorLauncher.RunningProbe = () => running;
        using var window = new MainForm(DatabaseSource.Sqlite(args[3]), null, settings)
        {
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000)
        };
        window.Shown += async (_, _) =>
        {
            try
            {
                var start = Descendants(window).OfType<Button>().Single(control =>
                    control.Text == "La&unch collector…");
                await Until(() => start.Visible);
                running = true;
                await Until(() => !start.Visible);
                running = false;
                await Until(() => start.Visible);
                checks.Add("The toolbar offers to start a collector only while none is running");
                foreach (var (points, size) in new[] { (9f, new Size(1440, 900)), (12f, new Size(1100, 750)),
                    (16f, new Size(1000, 750)) })
                {
                    window.Font = new Font("Segoe UI", points);
                    window.ClientSize = size;
                    await Task.Delay(200);
                    CheckToolbar(window);
                    using var bitmap = new Bitmap(window.Width, window.Height);
                    window.DrawToBitmap(bitmap, window.ClientRectangle);
                    bitmap.Save(Path.Combine(output, $"toolbar-{points}.png"));
                }
                checks.Add("Toolbar commands fit without overlap at compact widths and larger text sizes");
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                { result = "passed", checks }, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception error)
            {
                exit = 1;
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                { result = "failed", checks, error = error.ToString() },
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            finally { window.Close(); }
        };
        Application.Run(window);
        return exit;
    }

    internal static void CheckToolbar(Form window)
    {
        var toolbar = Descendants(window).OfType<FlowLayoutPanel>().Single(control =>
            control.AccessibleName == "Main commands");
        var controls = toolbar.Controls.Cast<Control>().Where(control => control.Visible).ToArray();
        foreach (var control in controls)
        {
            Require(toolbar.ClientRectangle.Contains(control.Bounds) && window.ClientRectangle.Contains(
                window.RectangleToClient(control.RectangleToScreen(control.ClientRectangle))),
                $"Toolbar control '{control.Text}' is clipped.");
            Require(controls.Where(other => other != control).All(other =>
                !other.Bounds.IntersectsWith(control.Bounds)),
                $"Toolbar control '{control.Text}' overlaps another control.");
            Require(control.Width >= control.GetPreferredSize(Size.Empty).Width,
                $"Toolbar control '{control.Text}' is narrower than its text.");
        }
    }

    private static void CheckArguments(string output, List<string> checks)
    {
        var journal = Path.Combine(output, "arguments.db");
        Require(new CollectorOptions { Journal = journal }.Arguments().SequenceEqual(["--db", journal]),
            "Default options should pass only the journal.");
        var tuned = new CollectorOptions
        {
            Journal = journal,
            Traffic = CollectorTraffic.Loopback,
            DurationSeconds = 30,
            Processes = false,
            Http = false,
            ClassifyRaw = true,
            Schannel = true,
            HttpSpy = true,
            Credentials = true,
            BodyKilobytes = 128,
            HttpSpyDays = 1,
            RetentionDays = 0,
            MaxFlows = 1000,
            BufferMegabytes = 64
        };
        Require(tuned.Validate() is null && tuned.Arguments().SequenceEqual(["--db", journal, "--loopback-only",
            "--duration", "30", "--no-process", "--schannel", "--max-flows", "1000", "--buffer-mb", "64",
            "--no-http", "--classify-raw", "--httpspy", "--httpspy-credentials", "--httpspy-body-kb", "128",
            "--httpspy-retention-days", "1", "--retention-days", "0"]), "Changed options map to the wrong arguments.");
        var spaced = Path.Combine(output, "has space", "a.db");
        Require(new CollectorOptions { Journal = spaced }.CommandLine("C:\\Program Files\\c.exe")
            .Equals($"\"C:\\Program Files\\c.exe\" --db \"{spaced}\""), "Paths with spaces were not quoted.");
        var missing = Path.Combine(output, "missing");
        foreach (var (options, expected) in new (CollectorOptions, string)[]
        {
            (new() { Journal = Path.Combine(missing, "deeper", "a.db") }, "parent does not exist"),
            (new() { Journal = Path.Combine(output, "invalid\".db") }, "double quotes"),
            (new() { Journal = journal, Live = false, Replay = Path.Combine(missing, "a.pcap") }, "capture file"),
            (new() { Journal = journal, Live = false }, "capture file"),
            (new() { Journal = journal, KeyLog = journal }, "key log"),
            (new() { Journal = journal, Credentials = true }, "HTTP Spy is on"),
            (new() { Journal = journal, EndpointOnly = true }, "needs Schannel"),
            (new() { Journal = journal, EndpointOnly = true, Schannel = true, HttpSpy = true }, "endpoint-only"),
            (new() { Journal = journal, EndpointOnly = true, Schannel = true, Traffic = CollectorTraffic.Network },
                "live packet capture")
        })
            Require(options.Validate() is { } problem && problem.Contains(expected, StringComparison.OrdinalIgnoreCase),
                $"Invalid options were accepted or misreported: {expected}.");
        checks.Add("Launch options become collector arguments and invalid combinations are rejected");
        var passive = new CollectorOptions { Journal = journal, HttpSpy = true,
            KeyLog = Path.Combine(output, "not-created-yet.log") };
        Require(passive.Validate() is null && passive.Arguments().Contains("--keylog"),
            "Live passive capture rejected a key log that the target will create.");
    }

    private static void CheckLaunch(string collector, string fixtures, string output, List<string> checks)
    {
        // The folder name holds characters that the command interpreter treats specially outside quotes.
        var folder = Path.Combine(output, "run&(1)^100%PATH%");
        Directory.CreateDirectory(folder);
        var capture = Path.Combine(folder, "replay&(1).pcap");
        var keyLog = Path.Combine(folder, "secrets%PATH%.log");
        File.Copy(Path.Combine(fixtures, "httpspy.pcap"), capture, true);
        File.Copy(Path.Combine(fixtures, "secrets.log"), keyLog, true);
        var options = new CollectorOptions
        {
            Journal = Path.Combine(folder, "new folder", "replay%PATH%.db"),
            Live = false,
            Replay = capture,
            KeyLog = keyLog,
            HttpSpy = true
        };
        using (var process = CollectorLauncher.Start(options, collector, visible: false))
        {
            Require(process.WaitForExit(120000) && process.ExitCode == 0, "The replay did not finish cleanly.");
        }
        Require(HttpSpyStore.Read(DatabaseSource.Sqlite(options.Journal), "", PageCursor.Newest, 50, null,
            CancellationToken.None)?.Rows.Count > 0, "The replay produced no decoded messages.");
        checks.Add("The collector starts from launch options and decodes a replayed capture");

        // A ready capture launches a real child with a private key-log environment, without changing its parent.
        var probe = Path.Combine(folder, "target-keylog.txt");
        File.Delete(probe);
        var previousProbe = Environment.GetEnvironmentVariable(Program.KeyLogProbe);
        var previousKeyLog = Environment.GetEnvironmentVariable("SSLKEYLOGFILE");
        using (var current = Process.GetCurrentProcess())
        using (var ready = new EventWaitHandle(false, EventResetMode.ManualReset,
            $"Local\\Cipherazzi-Ready-{current.Id}"))
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var access = new RawSecurityDescriptor($"D:P(A;;0x00100000;;;{identity.User!.Value})");
                var descriptor = new byte[access.BinaryLength];
                access.GetBinaryForm(descriptor, 0);
                Require(SetKernelObjectSecurity(ready.SafeWaitHandle, 4, descriptor),
                    "Could not restrict the capture readiness event to waiting only.");
                Environment.SetEnvironmentVariable(Program.KeyLogProbe, probe);
                var launch = CollectorLauncher.StartTargetAsync(options with { Live = true, Replay = "",
                    TargetApp = Environment.ProcessPath! }, current);
                Thread.Sleep(100);
                Require(!File.Exists(probe), "The target application launched before capture was ready.");
                ready.Set();
                launch.GetAwaiter().GetResult();
                Require(SpinWait.SpinUntil(() =>
                {
                    try { return File.ReadAllText(probe) == keyLog; }
                    catch (IOException) { return false; }
                }, 10000),
                    "The target application did not inherit its TLS key log.");
                Require(Environment.GetEnvironmentVariable("SSLKEYLOGFILE") == previousKeyLog,
                    "Launching a target changed the parent process's TLS key log.");
            }
            finally { Environment.SetEnvironmentVariable(Program.KeyLogProbe, previousProbe); }
        }
        checks.Add("Target launch waits for capture readiness and gives only the child its TLS key log");

        // A collector that fails must report its exit code to whoever started it.
        var damaged = Path.Combine(folder, "damaged.pcap");
        File.WriteAllText(damaged, "this is not a packet capture");
        using (var process = CollectorLauncher.Start(options with { Journal = Path.Combine(folder, "failed.db"),
            Replay = damaged, KeyLog = "", HttpSpy = false }, collector, visible: false))
        {
            Require(process.WaitForExit(60000) && process.ExitCode != 0, "A failed replay reported success.");
        }
        checks.Add("A collector that fails reports a failing exit code");
    }

    private static void CheckDialog(string collector, string fixtures, string output, List<string> checks)
    {
        using var dialog = new CollectorDialog(null, collector)
        {
            ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000)
        };
        dialog.Show();
        var controls = Descendants(dialog).ToArray();
        T Find<T>(Func<T, bool> match) where T : Control => controls.OfType<T>().Single(match);
        var mode = Find<ComboBox>(control => control.AccessibleName == "Collector mode");
        var journal = Find<TextBox>(control => control.AccessibleName == "Journal file");
        var capture = Find<TextBox>(control => control.AccessibleName == "Capture file to replay");
        var keyLog = Find<TextBox>(control => control.AccessibleName == "TLS key log");
        var command = Find<TextBox>(control => control.AccessibleName == "Collector command line");
        var start = Find<Button>(control => control.Text == "&Start collector");
        var spy = Find<CheckBox>(control => control.Text == "Decode &web traffic (HTTP Spy)");
        var schannel = Find<CheckBox>(control => control.Text == "Collect Schannel e&vents");
        var endpoint = Find<CheckBox>(control => control.Text == "&Endpoint events only");
        var processes = Find<CheckBox>(control => control.Text == "Attribute connections to &processes");

        // Live capture hides the replay files, and choices that cannot combine stay unavailable.
        journal.Text = Path.Combine(output, "dialog.db");
        Require(start.Enabled && !capture.Visible && processes.Visible && command.Text.Contains("dialog.db") &&
            !command.Text.Contains("--replay"), "The live capture dialog is not ready to start: " +
            $"start {start.Enabled}, capture {capture.Visible}, processes {processes.Visible}, {command.Text}");
        Require(!endpoint.Enabled, "Endpoint-only collection is offered without Schannel events.");
        schannel.Checked = true;
        endpoint.Checked = true;
        Require(!spy.Enabled && command.Text.Contains("--endpoint-only"),
            "Endpoint-only collection can still be combined with HTTP Spy.");
        schannel.Checked = false;
        Require(!endpoint.Checked && spy.Enabled, "Clearing Schannel events left endpoint-only collection on.");
        spy.Checked = true;
        keyLog.Text = Path.Combine(output, "new-live-keys.log");
        Require(keyLog.Visible && start.Enabled && command.Text.Contains("--keylog") &&
            Descendants(dialog).OfType<Button>().Any(button => button.Visible &&
                button.Text == "Launch target app with key log…"), "Live key log and target launch are unavailable.");
        spy.Checked = false;
        keyLog.Clear();

        // Replay asks for the capture and, with HTTP Spy, the key log; a missing file blocks Start with a reason.
        mode.SelectedIndex = 1;
        Require(capture.Visible && !keyLog.Visible && !processes.Visible && !start.Enabled,
            "The replay dialog does not ask for a capture file.");
        capture.Text = Path.Combine(output, "missing.pcap");
        Require(!start.Enabled && Descendants(dialog).OfType<Label>().Any(label =>
            label.Visible && label.Text.Contains("capture file")), "A missing capture file was accepted.");
        capture.Text = Path.Combine(fixtures, "httpspy.pcap");
        spy.Checked = true;
        keyLog.Text = Path.Combine(fixtures, "secrets.log");
        Require(keyLog.Visible && start.Enabled && command.Text.Contains("--replay") &&
            command.Text.Contains("--keylog") && command.Text.Contains("--httpspy"),
            "The replay options did not reach the command line.");
        start.PerformClick();
        Require(dialog.Options is { Live: false, HttpSpy: true } chosen &&
            chosen.KeyLog == Path.Combine(fixtures, "secrets.log"), "Start did not return the chosen options.");
        checks.Add("The launch dialog shows only the choices that apply and explains what blocks Start");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private static IEnumerable<Control> Descendants(Control control) => control.Controls.Cast<Control>()
        .SelectMany(child => new[] { child }.Concat(Descendants(child)));

    private static async Task Until(Func<bool> ready)
    {
        var watch = Stopwatch.StartNew();
        while (!ready())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(45))
                throw new TimeoutException("The collector toolbar did not reach the expected state.");
            await Task.Delay(25);
        }
    }
}
