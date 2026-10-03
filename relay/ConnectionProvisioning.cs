using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Win32.SafeHandles;

namespace Cipherazzi.Relay;

internal static class ConnectionProvisioning
{
    private sealed record Request(DatabaseProvider Provider, string Path, string Connection);
    private sealed record Response(bool Success, string Message);

    public static int? Run(string[] arguments)
    {
        if (arguments is ["--credential-service", var name, var pipe])
            return Cipherazzi.Deployment.Deployment.Run(name, ["--service"], (_, cancellation) =>
                ReceiveAsync(pipe, cancellation).GetAwaiter().GetResult(), logService: false);
        if (!arguments.Contains("--protect-connection"))
            return null;
        try
        {
            string? path = null;
            string? provider = null;
            var system = false;
            for (var index = 0; index < arguments.Length; index++)
            {
                string Value() => ++index < arguments.Length ? arguments[index] :
                    throw new ArgumentException("Missing option value.");
                switch (arguments[index])
                {
                    case "--protect-connection": path = Path.GetFullPath(Value()); break;
                    case "--provider": provider = Value(); break;
                    case "--local-system": system = true; break;
                    default: throw new ArgumentException("Choose only provisioning options.");
                }
            }
            if (path is null || provider is not ("sqlserver" or "postgresql"))
                throw new ArgumentException("Supply --protect-connection <file> and --provider sqlserver|postgresql.");
            using var identity = WindowsIdentity.GetCurrent();
            if (system && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new ArgumentException("Provisioning for LocalSystem requires an elevated console.");
            var kind = provider == "sqlserver" ? DatabaseProvider.SqlServer : DatabaseProvider.PostgreSql;
            var source = new DatabaseSource(kind, ReadConnection());
            if (system)
                SaveForSystemAsync(path, source).GetAwaiter().GetResult();
            else
                ConnectionCredentials.Save(path, source);
            Console.WriteLine("Protected connection saved for " +
                (system ? "LocalSystem." : identity.Name + "."));
            return 0;
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or IOException or
            UnauthorizedAccessException or Win32Exception or CryptographicException or OperationCanceledException)
        {
            using var identity = WindowsIdentity.GetCurrent();
            Console.Error.WriteLine(error is ArgumentException && arguments.Contains("--local-system") &&
                !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator) ?
                "Provisioning for LocalSystem requires an elevated console." :
                "Could not protect the connection. Check the provider, connection details, account, and file path.");
            return 1;
        }
    }

    private static string ReadConnection()
    {
        Console.Error.Write("Connection string (input hidden): ");
        if (Console.IsInputRedirected)
        {
            Console.InputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            var text = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(text) || text.Length > 65536)
                throw new ArgumentException("Supply a connection string.");
            return text;
        }
        var input = new StringBuilder();
        for (;;)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Escape)
                throw new OperationCanceledException();
            if (key.Key == ConsoleKey.Backspace && input.Length > 0)
                input.Length--;
            else if (!char.IsControl(key.KeyChar) && input.Length < 65536)
                input.Append(key.KeyChar);
        }
        Console.Error.WriteLine();
        if (input.Length == 0)
            throw new ArgumentException("Supply a connection string.");
        return input.ToString();
    }

    private static async Task SaveForSystemAsync(string path, DatabaseSource source)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(identity.User!,
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        var name = "CipherazziCredentials-" + Guid.NewGuid().ToString("N");
        using var channel = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 4096, 4096, security);
        using var manager = OpenSCManager(null, null, 3);
        if (manager.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        var processPath = Environment.ProcessPath ??
            throw new InvalidOperationException("Cannot locate the application.");
        var executable = "\"" + processPath + "\"";
        if (Path.GetFileNameWithoutExtension(processPath).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            executable += " \"" + Path.GetFullPath(Environment.GetCommandLineArgs()[0]) + "\"";
        using var service = CreateService(manager, name, name, 0x10034, 0x10, 3, 1,
            executable + " --credential-service " + name + " " + name, null, 0, null, null, null);
        if (service.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            // Send the secret only through a local pipe restricted to the operator and LocalSystem.
            if (!StartService(service, 0, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await channel.WaitForConnectionAsync(timeout.Token);
            _ = await ReadAsync<Response>(channel, timeout.Token);
            var system = false;
            channel.RunAsClient(() =>
            {
                using var client = WindowsIdentity.GetCurrent();
                system = client.User!.IsWellKnown(WellKnownSidType.LocalSystemSid);
            });
            if (!system)
                throw new InvalidOperationException("The credential service is not LocalSystem.");
            await WriteAsync(channel, new Request(source.Provider, path, source.ConnectionString), timeout.Token);
            var result = await ReadAsync<Response>(channel, timeout.Token);
            if (!result.Success)
                throw new InvalidOperationException(result.Message);
        }
        finally
        {
            ControlService(service, 1, out _);
            DeleteService(service);
        }
    }

    private static async Task<int> ReceiveAsync(string name, CancellationToken cancellation)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(timeout.Token);
        await WriteAsync(pipe, new Response(true, "Ready."), timeout.Token);
        try
        {
            var request = await ReadAsync<Request>(pipe, timeout.Token);
            ConnectionCredentials.Save(request.Path, new DatabaseSource(request.Provider, request.Connection));
            await WriteAsync(pipe, new Response(true, "Protected connection saved."), timeout.Token);
            return 0;
        }
        catch (Exception)
        {
            await WriteAsync(pipe, new Response(false, "Could not save the protected connection."), timeout.Token);
            return 1;
        }
    }

    private static async Task WriteAsync<T>(Stream pipe, T value, CancellationToken cancellation)
    {
        var data = JsonSerializer.SerializeToUtf8Bytes(value);
        var size = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(size, data.Length);
        try
        {
            if (data.Length > 256 * 1024)
                throw new InvalidDataException("The credential message exceeds 256 KiB.");
            await pipe.WriteAsync(size, cancellation);
            await pipe.WriteAsync(data, cancellation);
            await pipe.FlushAsync(cancellation);
        }
        finally { CryptographicOperations.ZeroMemory(data); }
    }

    private static async Task<T> ReadAsync<T>(Stream pipe, CancellationToken cancellation)
    {
        var size = new byte[4];
        await pipe.ReadExactlyAsync(size, cancellation);
        var length = BinaryPrimitives.ReadInt32LittleEndian(size);
        if (length is <= 0 or > 256 * 1024)
            throw new InvalidDataException("Invalid credential message.");
        var data = new byte[length];
        try
        {
            await pipe.ReadExactlyAsync(data, cancellation);
            return JsonSerializer.Deserialize<T>(data) ?? throw new InvalidDataException("Invalid credential message.");
        }
        finally { CryptographicOperations.ZeroMemory(data); }
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private ServiceHandle() : base(true) {}
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "CreateServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle CreateService(ServiceHandle manager, string name, string displayName,
        uint access, uint type, uint start, uint error, string binary, string? group, nint tag,
        string? dependencies, string? account, string? password);
    [DllImport("advapi32.dll", EntryPoint = "StartServiceW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(ServiceHandle service, uint count, nint arguments);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(ServiceHandle service, uint control, out ServiceStatus status);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(ServiceHandle service);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(nint service);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint;
    }
}
