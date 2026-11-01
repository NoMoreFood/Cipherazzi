import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.*;

class JavaClient
{
    public static void main(String[] args) throws Exception
    {
        // Trust only within the isolated integration lab; no production trust settings are changed.
        var context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] { new X509TrustManager()
        {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] chain, String auth) {}
            public void checkServerTrusted(X509Certificate[] chain, String auth) {}
        } }, new SecureRandom());
        try (var transport = new Socket(args.length > 3 ? InetAddress.getByName(args[3]) :
                 InetAddress.getLoopbackAddress(), Integer.parseInt(args[0]));
             var socket = (SSLSocket)context.getSocketFactory().createSocket(transport, args[2],
                 Integer.parseInt(args[0]), true))
        {
            var parameters = socket.getSSLParameters();
            parameters.setProtocols(new String[] { args[1] });
            parameters.setServerNames(List.of(new SNIHostName(args[2])));
            parameters.setApplicationProtocols(new String[] { "h2", "http/1.1" });
            socket.setSSLParameters(parameters);
            var started = java.time.Instant.now();
            socket.startHandshake();
            System.out.println(socket.getSession().getProtocol() + " " + socket.getSession().getCipherSuite());
            if (args.length > 4)
            {
                // Export only the socket identity and public session results from the Java TLS endpoint.
                var process = ProcessHandle.current();
                var creation = process.info().startInstant().orElseThrow();
                var completed = java.time.Instant.now();
                int cipher = switch (socket.getSession().getCipherSuite())
                {
                    case "TLS_AES_128_GCM_SHA256" -> 4865;
                    case "TLS_AES_256_GCM_SHA384" -> 4866;
                    case "TLS_CHACHA20_POLY1305_SHA256" -> 4867;
                    case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" -> 49199;
                    case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" -> 49200;
                    default -> throw new Exception("Lab adapter does not map this cipher suite");
                };
                var certificates = java.util.Arrays.stream(socket.getSession().getPeerCertificates()).map(value ->
                {
                    try { return "\"" + java.util.Base64.getEncoder().encodeToString(value.getEncoded()) + "\""; }
                    catch (Exception error) { throw new RuntimeException(error); }
                }).collect(java.util.stream.Collectors.joining(","));
                var report = """
                    {"schema":"cipherazzi.endpoint/1","provider":"Java SSLSession adapter","pid":%d,
                    "process_started_us":%d,"handshake_started_us":%d,"timestamp_us":%d,
                    "local":{"address":"%s","port":%d},"remote":{"address":"%s","port":%d},
                    "role":"client","transport":"TCP","success":true,"peer_verified":false,
                    "tls_version":%d,"cipher_id":%d,"selected_alpn":"%s","server_certificates_der":[%s]}
                    """.formatted(process.pid(), creation.getEpochSecond() * 1000000 + creation.getNano() / 1000,
                    started.getEpochSecond() * 1000000 + started.getNano() / 1000,
                    completed.getEpochSecond() * 1000000 + completed.getNano() / 1000,
                    socket.getLocalAddress().getHostAddress(), socket.getLocalPort(),
                    socket.getInetAddress().getHostAddress(), socket.getPort(),
                    socket.getSession().getProtocol().equals("TLSv1.3") ? 772 : 771, cipher,
                    socket.getApplicationProtocol(), certificates);
                var directory = java.nio.file.Path.of(args[4]);
                java.nio.file.Files.createDirectories(directory);
                var temporary = directory.resolve("java-" + process.pid() + ".tmp");
                java.nio.file.Files.writeString(temporary, report);
                java.nio.file.Files.move(temporary, directory.resolve("java-" + process.pid() + ".json"),
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            }
            socket.getOutputStream().write(42);
            socket.getOutputStream().flush();
            if (socket.getInputStream().read() != 42)
                throw new Exception("TLS echo failed");
        }
    }
}
