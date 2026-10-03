using System.ComponentModel;
using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Cipherazzi.Publisher;

internal interface IEventDestination : IDisposable
{
    string Identity { get; }
    Task WriteAsync(PublishedEvent value, CancellationToken cancellation);
    void Reset();
}

internal sealed class SyslogDestination : IEventDestination
{
    private readonly Options options;
    private readonly Uri address;
    private readonly int port;
    private readonly X509Certificate2Collection roots = [];
    private readonly X509Certificate2? clientCertificate;
    private TcpClient? client;
    private Stream? stream;
    public string Identity => $"syslog|{address.Scheme}|{address.IdnHost.ToLowerInvariant()}|{port}";

    public SyslogDestination(Options settings)
    {
        options = settings;
        address = settings.Syslog!;
        port = address.Port < 0 ? address.Scheme == "tls" ? 6514 : 514 : address.Port;
        if (settings.CertificateAuthority is { } file)
        {
            if (new FileInfo(file).Length > 1024 * 1024)
                throw new ArgumentException("The syslog CA file exceeds 1 MiB.");
            if (File.ReadAllText(file).Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
                roots.ImportFromPemFile(file);
            else
                roots.Add(X509CertificateLoader.LoadCertificateFromFile(file));
            if (roots.Count is 0 or > 16)
                throw new ArgumentException("Supply between one and sixteen public CA certificates.");
        }
        if (settings.ClientCertificate is { } thumbprint)
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var certificate in store.Certificates)
            {
                if (clientCertificate is null &&
                    (certificate.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase) ||
                     certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256)
                        .Equals(thumbprint, StringComparison.OrdinalIgnoreCase)))
                    clientCertificate = certificate;
                else
                    certificate.Dispose();
            }
            if (clientCertificate is null || !clientCertificate.HasPrivateKey)
                throw new ArgumentException("The TLS client certificate and accessible private key were not found.");
        }
    }

    public async Task WriteAsync(PublishedEvent value, CancellationToken cancellation)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            if (stream is null)
            {
                client = new TcpClient { NoDelay = true };
                await client.ConnectAsync(address.IdnHost, port, timeout.Token);
                stream = client.GetStream();
                if (address.Scheme == "tls")
                {
                    // Preserve certificate and hostname validation with connection-local custom trust roots.
                    var tls = new SslStream(stream, false);
                    stream = tls;
                    var authentication = new SslClientAuthenticationOptions
                    {
                        TargetHost = address.IdnHost, AllowRenegotiation = false,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        CertificateRevocationCheckMode = X509RevocationMode.Online
                    };
                    if (roots.Count > 0)
                    {
                        authentication.CertificateChainPolicy = new X509ChainPolicy
                        {
                            TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.Online
                        };
                        authentication.CertificateChainPolicy.CustomTrustStore.AddRange(roots);
                    }
                    if (clientCertificate is not null)
                        authentication.ClientCertificates = new X509CertificateCollection { clientCertificate };
                    await tls.AuthenticateAsClientAsync(authentication, timeout.Token);
                }
            }
            var time = value.Timestamp is > 0 and <= 253402300799999999 ?
                DateTimeOffset.UnixEpoch.AddTicks(value.Timestamp * 10).ToString(
                    "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture) : "-";
            var host = new string(value.Computer.Take(255).Select(character =>
                character is >= '!' and <= '~' ? character : '_').ToArray());
            if (host.Length == 0)
                host = "-";

            // Count UTF-8 bytes so Unicode and embedded newlines cannot break message framing.
            var kind = value.EventKind switch { 1 => "CONNECTION", 2 => "ENDPOINT", 4 => "POLICY", _ => "HEALTH" };
            var message = Encoding.UTF8.GetBytes($"<{options.Facility * 8 + value.Severity}>1 {time} {host} " +
                $"Cipherazzi {Environment.ProcessId} {kind} - {value.Json}");
            var prefix = Encoding.ASCII.GetBytes(message.Length.ToString(CultureInfo.InvariantCulture) + " ");
            await stream.WriteAsync(prefix, timeout.Token);
            await stream.WriteAsync(message, timeout.Token);
        }
        catch
        {
            Reset();
            throw;
        }
    }

    public void Reset()
    {
        stream?.Dispose();
        client?.Dispose();
        stream = null;
        client = null;
    }

    public void Dispose()
    {
        Reset();
        foreach (var certificate in roots)
            certificate.Dispose();
        clientCertificate?.Dispose();
    }
}

internal sealed class WindowsDestination(string source) : IEventDestination
{
    private EventHandle? handle;
    public string Identity => "windows|Application|" + source.ToLowerInvariant();
    private static string SourceKey(string name) =>
        @"SYSTEM\CurrentControlSet\Services\EventLog\Application\" + name;

    private sealed class EventHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        protected override bool ReleaseHandle() => DeregisterEventSource(handle);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern EventHandle RegisterEventSource(string? server, string source);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeregisterEventSource(IntPtr handle);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReportEvent(EventHandle handle, ushort type, ushort category, uint id,
        IntPtr sid, ushort count, uint bytes,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] values, IntPtr data);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint FormatMessage(uint flags, IntPtr source, uint id, uint language,
        StringBuilder text, uint size, IntPtr arguments);

    public static void Register(string name, string messageFile)
    {
        // Validate the resource before registering a persistent, administrator-owned event source.
        messageFile = Path.GetFullPath(messageFile);
        var module = LoadLibraryEx(messageFile, IntPtr.Zero, 0x22);
        if (module == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Open the event message resource");
        try
        {
            for (uint id = 1001; id <= 1004; id++)
                if (FormatMessage(0xA00, module, id, 0, new StringBuilder(256), 256, IntPtr.Zero) == 0)
                    throw new ArgumentException("Use a collector binary containing the Cipherazzi event messages.");
        }
        finally { FreeLibrary(module); }
        using var existing = Registry.LocalMachine.OpenSubKey(SourceKey(name));
        if (existing is not null && !string.Equals(
            Environment.ExpandEnvironmentVariables(existing.GetValue("EventMessageFile")?.ToString() ?? ""),
            messageFile, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The event source is registered to a different message file.");
        using var key = Registry.LocalMachine.CreateSubKey(SourceKey(name), true);
        key.SetValue("EventMessageFile", messageFile, RegistryValueKind.ExpandString);
        key.SetValue("TypesSupported", 7, RegistryValueKind.DWord);
    }

    public Task WriteAsync(PublishedEvent value, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        if (handle is null)
        {
            using var registration = Registry.LocalMachine.OpenSubKey(SourceKey(source));
            if (registration?.GetValue("EventMessageFile") is not string)
                throw new InvalidOperationException("Register the Windows event source before publishing.");
            handle = RegisterEventSource(null, source);
            if (handle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Open the Windows event source");
        }
        if (!ReportEvent(handle, value.Severity <= 4 ? (ushort)2 : (ushort)4, 0,
            (uint)(1000 + value.EventKind), IntPtr.Zero, 1, 0, [value.Json], IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Publish the Windows event");
        return Task.CompletedTask;
    }

    public void Reset()
    {
        handle?.Dispose();
        handle = null;
    }
    public void Dispose() => Reset();
}
