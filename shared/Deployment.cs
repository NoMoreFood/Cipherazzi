using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Cipherazzi.Deployment;

internal static class Deployment
{
    public static string[] Configuration(string[] arguments)
    {
        var result = new List<string>();
        var loaded = false;
        for (var index = 0; index < arguments.Length; index++)
        {
            if (arguments[index] != "--config")
            {
                result.Add(arguments[index]);
                continue;
            }
            if (loaded || ++index == arguments.Length)
                throw new ArgumentException("Supply one configuration file.");
            loaded = true;
            var path = Path.GetFullPath(arguments[index]);
            using var input = File.OpenRead(path);
            if (input.Length > 256 * 1024)
                throw new InvalidDataException("Configuration exceeds 256 KiB.");
            using var document = JsonDocument.Parse(input, new() { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Configuration must be a JSON object of command options.");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!names.Add(property.Name) || property.Name.Length == 0 ||
                    property.Name.Any(value => !char.IsAsciiLetterOrDigit(value) && value != '-') ||
                    property.Name is "config" or "service" or "help" or "unregister" or "register-event-source" or
                        "protect-connection" or "local-system" or "credential-service")
                    throw new InvalidDataException("Configuration contains an invalid or duplicate option.");
                if (property.Value.ValueKind == JsonValueKind.False)
                    continue;
                result.Add("--" + property.Name);
                if (property.Value.ValueKind == JsonValueKind.True)
                    continue;
                if (property.Value.ValueKind is not (JsonValueKind.String or JsonValueKind.Number))
                    throw new InvalidDataException("Configuration values must be strings, numbers, or booleans.");
                var value = property.Value.ToString();
                if (property.Name is "source" or "syslog-ca" or "event-message-file" or "connection-file" or "policies")
                    value = Path.GetFullPath(value, Path.GetDirectoryName(path)!);
                result.Add(value);
            }
        }
        return result.ToArray();
    }

    // Register with SCM before reading configuration or opening a destination.
    public static int Run(string name, string[] arguments, Func<string[], CancellationToken, int> work,
        bool logService = true)
    {
        var service = arguments.Contains("--service");
        arguments = arguments.Where(value => value != "--service").ToArray();
        if (!service)
        {
            try { return work(Configuration(arguments), CancellationToken.None); }
            catch (Exception error) { Console.Error.WriteLine(error.Message); return 1; }
        }
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Windows services require Windows.");
            return 1;
        }
        using var shutdown = new CancellationTokenSource();
        var gate = new object();
        var status = new ServiceStatus { Type = 0x10, State = 2, WaitHint = 30000 };
        nint handle = 0;
        var exit = 0;
        void State(uint value)
        {
            lock (gate)
            {
                if (status.State == 1 && value != 1)
                    return;
                if (status.State == 3 && value == 4)
                    return;
                status.State = value;
                status.Accepted = value == 4 ? 5U : 0;
                status.WaitHint = value is 2 or 3 ? 30000U : 0;
                status.Checkpoint = value is 2 or 3 ? status.Checkpoint + 1 : 0;
                status.Win32Exit = value == 1 && exit != 0 ? 1066U : 0;
                status.ServiceExit = (uint)exit;
                if (handle != 0)
                    SetServiceStatus(handle, ref status);
            }
        }
        Handler control = (code, _, _, _) =>
        {
            if (code is 1 or 5)
            {
                State(3);
                shutdown.Cancel();
                return 0;
            }
            lock (gate)
                SetServiceStatus(handle, ref status);
            return code == 4 ? 0U : 120U;
        };
        ServiceMain main = (_, _) =>
        {
            handle = RegisterServiceCtrlHandlerEx(name, control, 0);
            if (handle == 0)
            {
                exit = 1;
                return;
            }
            State(2);
            try
            {
                var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Cipherazzi");
                if (logService)
                    Directory.CreateDirectory(directory);
                var path = Path.Combine(directory, name + ".log");
                using TextWriter log = logService ? new ServiceLog(path) : TextWriter.Null;
                var output = Console.Out;
                var error = Console.Error;
                Console.SetOut(TextWriter.Synchronized(log));
                Console.SetError(Console.Out);
                try
                {
                    Console.WriteLine($"{DateTimeOffset.UtcNow:u} Starting {name}.");
                    ConfigureRecovery(name);
                    var options = Configuration(arguments);
                    shutdown.Token.ThrowIfCancellationRequested();
                    if (options.Any(value => value is "--once" or "--duration" or "--help" or "-h" or
                        "--unregister" or "--register-event-source"))
                        throw new ArgumentException("Service mode requires continuous operation.");
                    State(4);
                    exit = work(options, shutdown.Token);
                    Console.WriteLine($"{DateTimeOffset.UtcNow:u} Stopped {name}; result {exit}.");
                }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { exit = 0; }
                catch (Exception exception)
                {
                    exit = 1;
                    Console.Error.WriteLine(exception.Message);
                }
                finally
                {
                    Console.SetOut(output);
                    Console.SetError(error);
                }
            }
            catch (Exception) { exit = 1; }
            State(1);
        };
        var table = new[] { new ServiceEntry { Name = name, Main = main }, new ServiceEntry() };
        if (!StartServiceCtrlDispatcher(table))
        {
            Console.Error.WriteLine(new Win32Exception(Marshal.GetLastWin32Error(),
                "Service mode must be started by Windows Services.").Message);
            return 1;
        }
        GC.KeepAlive(main);
        GC.KeepAlive(control);
        return exit;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint;
    }

    // Use SCM's native configuration so a returned worker error also triggers installer recovery actions.
    private static void ConfigureRecovery(string name)
    {
        using var manager = OpenSCManager(null, null, 1);
        if (manager.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        using var service = OpenService(manager, name, 2);
        var enabled = 1;
        if (service.IsInvalid || !ChangeServiceConfig2(service, 4, ref enabled))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private ServiceHandle() : base(true) {}
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    private sealed class ServiceLog(string path) : TextWriter
    {
        private readonly StreamWriter output = new(path, append: true) { AutoFlush = true };
        public override Encoding Encoding => Encoding.UTF8;
        public override void WriteLine(string? value)
        {
            // Bound operational logs while keeping the journal's durable acknowledgements independent.
            if (output.BaseStream.Length >= 1024 * 1024)
            {
                output.Flush();
                output.BaseStream.SetLength(0);
                output.BaseStream.Position = 0;
            }
            output.WriteLine(value);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
                output.Dispose();
            base.Dispose(disposing);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? Name;
        public ServiceMain? Main;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMain(uint count, nint arguments);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint Handler(uint code, uint type, nint data, nint context);

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2(ServiceHandle service, uint level, ref int enabled);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(nint service);

    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcher([In] ServiceEntry[] table);
    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern nint RegisterServiceCtrlHandlerEx(string name, Handler handler, nint context);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(nint handle, ref ServiceStatus status);
}
