using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Cipherazzi.Viewer;

internal enum CollectorTraffic { Combined, Network, Loopback }

// What to run the collector for. Arguments appear only where they differ from the collector's own defaults.
internal sealed record CollectorOptions
{
    private static readonly CollectorOptions Defaults = new();
    public string Journal { get; init; } = "";
    public bool Live { get; init; } = true;
    public string Replay { get; init; } = "";
    public string KeyLog { get; init; } = "";
    public string TargetApp { get; init; } = "";
    public CollectorTraffic Traffic { get; init; }
    public int DurationSeconds { get; init; }
    public bool Processes { get; init; } = true;
    public bool Http { get; init; } = true;
    public bool ClassifyRaw { get; init; }
    public bool Schannel { get; init; }
    public bool EndpointOnly { get; init; }
    public bool HttpSpy { get; init; }
    public bool Credentials { get; init; }
    public int BodyKilobytes { get; init; } = 64;
    public int HttpSpyDays { get; init; } = 7;
    public int HttpSpyMegabytes { get; init; } = 1024;
    public int RetentionDays { get; init; } = 30;
    public int RetentionMegabytes { get; init; } = 512;
    public int MaxFlows { get; init; } = 32768;
    public int BufferMegabytes { get; init; } = 128;

    // Capturing live traffic needs an administrator; replaying a file does not.
    public bool NeedsElevation => Live;

    public string? Validate()
    {
        if (new[] { Journal, Replay, KeyLog, TargetApp }.Any(path => path.Contains('"')))
            return "Paths cannot contain double quotes.";
        if (Journal.Length == 0)
            return "Choose the journal file to write.";

        // The journal's own folder is created on demand, but not a whole missing path.
        try
        {
            var folder = Path.GetDirectoryName(Path.GetFullPath(Journal));
            if (!Directory.Exists(folder) && !Directory.Exists(Path.GetDirectoryName(folder)))
                return "The journal folder cannot be created because its parent does not exist.";
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return "The journal path is not valid.";
        }
        if (!Live && (Replay.Length == 0 || !File.Exists(Replay)))
            return "Choose an existing capture file to replay.";
        if (KeyLog.Length > 0 && !HttpSpy)
            return "A key log requires HTTP Spy.";
        if (!Live && KeyLog.Length > 0 && !File.Exists(KeyLog))
            return "The key log file does not exist.";
        if (TargetApp.Length > 0 && (!Live || !HttpSpy || KeyLog.Length == 0 || !File.Exists(TargetApp)))
            return "Launching a target needs live HTTP Spy, a key log path, and an existing application.";
        if (KeyLog.Length > 0)
        {
            try
            {
                var keyPath = Path.GetFullPath(KeyLog);
                if (keyPath.Equals(Path.GetFullPath(Journal), StringComparison.OrdinalIgnoreCase) ||
                    !Live && keyPath.Equals(Path.GetFullPath(Replay), StringComparison.OrdinalIgnoreCase))
                    return "The key log must use a different file from the journal and capture.";
            }
            catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
            { return "The key log path is not valid."; }
        }
        if (Credentials && !HttpSpy)
            return "Credential headers are kept only when HTTP Spy is on.";
        if (EndpointOnly && !Schannel)
            return "Endpoint-only collection needs Schannel events.";
        if (EndpointOnly && HttpSpy)
            return "HTTP Spy decodes packets, so it cannot run with endpoint-only collection.";
        if (Traffic != CollectorTraffic.Combined && (EndpointOnly || !Live))
            return "Choosing traffic applies to live packet capture.";
        return null;
    }

    // An unfinished path still appears in the command line preview as typed.
    private static string Full(string path)
    {
        try { return path.Length == 0 ? path : Path.GetFullPath(path); }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return path;
        }
    }

    public List<string> Arguments()
    {
        string Number(int value) => value.ToString(CultureInfo.InvariantCulture);
        var arguments = new List<string> { "--db", Full(Journal) };
        if (!Live)
        {
            // A captured file has no live processes to attribute.
            arguments.AddRange(["--replay", Full(Replay), "--no-process"]);
        }
        else
        {
            if (Traffic != CollectorTraffic.Combined)
                arguments.Add(Traffic == CollectorTraffic.Loopback ? "--loopback-only" : "--no-loopback");
            if (DurationSeconds > 0)
                arguments.AddRange(["--duration", Number(DurationSeconds)]);
            if (!Processes)
                arguments.Add("--no-process");
            if (Schannel)
                arguments.Add("--schannel");
            if (EndpointOnly)
                arguments.Add("--endpoint-only");
            if (MaxFlows != Defaults.MaxFlows)
                arguments.AddRange(["--max-flows", Number(MaxFlows)]);
            if (BufferMegabytes != Defaults.BufferMegabytes)
                arguments.AddRange(["--buffer-mb", Number(BufferMegabytes)]);
        }
        if (!Http)
            arguments.Add("--no-http");
        if (ClassifyRaw)
            arguments.Add("--classify-raw");
        if (HttpSpy)
        {
            arguments.Add("--httpspy");
            if (KeyLog.Length > 0)
                arguments.AddRange(["--keylog", Full(KeyLog)]);
            if (Credentials)
                arguments.Add("--httpspy-credentials");
            if (BodyKilobytes != Defaults.BodyKilobytes)
                arguments.AddRange(["--httpspy-body-kb", Number(BodyKilobytes)]);
            if (HttpSpyDays != Defaults.HttpSpyDays)
                arguments.AddRange(["--httpspy-retention-days", Number(HttpSpyDays)]);
            if (HttpSpyMegabytes != Defaults.HttpSpyMegabytes)
                arguments.AddRange(["--httpspy-retention-mb", Number(HttpSpyMegabytes)]);
        }
        if (RetentionDays != Defaults.RetentionDays)
            arguments.AddRange(["--retention-days", Number(RetentionDays)]);
        if (RetentionMegabytes != Defaults.RetentionMegabytes)
            arguments.AddRange(["--retention-mb", Number(RetentionMegabytes)]);
        return arguments;
    }

    public string CommandLine(string collector) => string.Join(' ', new[] { collector }.Concat(Arguments())
        .Select(token => token.Length == 0 || token.IndexOfAny([' ', '\t']) >= 0 ? "\"" + token + "\"" : token));
}

// Finds and starts the collector in its own console, where Ctrl+C or closing the window stops it cleanly.
internal static class CollectorLauncher
{
    private const string ProcessName = "Cipherazzi.Collector";
    private const int Cancelled = 1223;

    // Waiting on an elevated collector's event must not request permission to change it.
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeWaitHandle OpenEvent(uint desiredAccess, bool inheritHandle, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeWaitHandle handle, uint milliseconds);

    // Tests replace the probe so the toolbar does not depend on collectors that happen to be running.
    internal static Func<bool> RunningProbe { get; set; } = () =>
    {
        var processes = Process.GetProcessesByName(ProcessName);
        foreach (var process in processes)
            process.Dispose();
        return processes.Length > 0;
    };

    public static bool Running() => RunningProbe();

    public static bool Elevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    // The collector ships beside the viewer; a source build keeps it in the native output folder.
    public static string? Locate()
    {
        var beside = AppContext.BaseDirectory;
        return new[]
        {
            beside,
            Path.GetFullPath(Path.Combine(beside, "..", "..", "..", "..", "bin", "Release")),
            Path.GetFullPath(Path.Combine(beside, "..", "..", "..", "..", "bin", "Debug")),
            Environment.SystemDirectory
        }.Select(directory => Path.Combine(directory, ProcessName + ".exe")).FirstOrDefault(File.Exists);
    }

    // The user cancelling elevation throws a Win32Exception with Cancelled as its native error.
    public static Process Start(CollectorOptions options, string collector, bool visible = true)
    {
        if (options.Validate() is { } problem)
            throw new ArgumentException(problem);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(options.Journal))!);
        var start = new ProcessStartInfo(collector)
        {
            UseShellExecute = true,
            WorkingDirectory = Path.GetDirectoryName(collector)!,
            WindowStyle = visible ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden
        };
        foreach (var argument in options.Arguments())
            start.ArgumentList.Add(argument);
        if (options.NeedsElevation && !Elevated())
            start.Verb = "runas";
        return Process.Start(start) ?? throw new InvalidOperationException("The collector did not start.");
    }

    public static bool WasCancelled(System.ComponentModel.Win32Exception error) => error.NativeErrorCode == Cancelled;

    public static async Task StartTargetAsync(CollectorOptions options, Process collector)
    {
        if (options.TargetApp.Length == 0)
            return;
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!collector.HasExited && DateTime.UtcNow < deadline)
        {
            using var ready = OpenEvent(0x00100000, false, $"Local\\Cipherazzi-Ready-{collector.Id}");
            if (ready.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                if (error != 2)
                    throw new System.ComponentModel.Win32Exception(error);
            }
            else if (WaitForSingleObject(ready, 0) == 0)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(options.KeyLog))!);
                var start = new ProcessStartInfo(options.TargetApp)
                {
                    UseShellExecute = false,
                    WorkingDirectory = Path.GetDirectoryName(options.TargetApp)!
                };
                start.Environment["SSLKEYLOGFILE"] = Path.GetFullPath(options.KeyLog);
                using var target = Process.Start(start) ?? throw new InvalidOperationException(
                    "The target application did not start.");
                return;
            }
            await Task.Delay(100);
        }
        throw new InvalidOperationException("The collector did not become ready to capture the target application.");
    }
}
