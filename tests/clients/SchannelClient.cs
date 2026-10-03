using System.Diagnostics;
using System.Text.Json;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

// Certificate acceptance is confined to the isolated integration lab.
using var transport = new TcpClient();
await transport.ConnectAsync(args.Length > 3 ? IPAddress.Parse(args[3]) : IPAddress.Loopback, int.Parse(args[0]));
using var tls = new SslStream(transport.GetStream(), false, (_, _, _, _) => true);
var started = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
{
    TargetHost = args[2],
    EnabledSslProtocols = args[1] == "TLSv1.3" ? SslProtocols.Tls13 : SslProtocols.Tls12,
    ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]
});
Console.WriteLine($"{tls.SslProtocol} {tls.NegotiatedCipherSuite}");
if (args.Length > 4)
{
    // Export public results from the actual socket; the lab's permissive trust callback is explicit.
    var local = (IPEndPoint)transport.Client.LocalEndPoint!;
    var remote = (IPEndPoint)transport.Client.RemoteEndPoint!;
    using var process = Process.GetCurrentProcess();
    var report = new
    {
        schema = "cipherazzi.endpoint/1", provider = "Schannel SslStream adapter", pid = process.Id,
        process_started_us = process.StartTime.ToUniversalTime().ToFileTimeUtc() / 10 - 11644473600000000,
        handshake_started_us = started, timestamp_us = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000,
        local = new { address = local.Address.ToString(), port = local.Port },
        remote = new { address = remote.Address.ToString(), port = remote.Port },
        role = "client", transport = "TCP", success = true, peer_verified = false,
        tls_version = tls.SslProtocol == SslProtocols.Tls13 ? 772 : 771,
        cipher_id = (int)tls.NegotiatedCipherSuite, selected_alpn = tls.NegotiatedApplicationProtocol.ToString(),
        server_certificates_der = tls.RemoteCertificate is { } certificate ?
            new[] { Convert.ToBase64String(certificate.GetRawCertData()) } : []
    };
    Directory.CreateDirectory(args[4]);
    var path = Path.Combine(args[4], $"schannel-{process.Id}-{started}");
    File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(report));
    File.Move(path + ".tmp", path + ".json");
}
await tls.WriteAsync(new byte[] { 42 });
var response = new byte[1];
if (await tls.ReadAsync(response) != 1 || response[0] != 42)
    throw new IOException("TLS echo failed");
