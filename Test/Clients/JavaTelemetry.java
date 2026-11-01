import java.io.FileInputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;
import jdk.jfr.Recording;

class JavaTelemetry
{
    public static void main(String[] args) throws Exception
    {
        try (var recording = new Recording())
        {
            recording.enable("jdk.TLSHandshake");
            recording.enable("jdk.X509Certificate");
            recording.enable("jdk.X509Validation");
            recording.start();

            // Use the lab certificate as a private trust anchor without changing system trust.
            var store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            try (var input = new FileInputStream(args[2]))
            {
                store.setCertificateEntry("lab", CertificateFactory.getInstance("X.509").generateCertificate(input));
            }
            var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            var context = SSLContext.getInstance("TLS");
            context.init(null, trust.getTrustManagers(), null);
            System.out.println("ready");
            Thread.sleep(5000);
            for (int index = 0; index < 8; ++index)
            {
                try (var transport = new Socket(args[0], Integer.parseInt(args[1]));
                     var socket = (SSLSocket)context.getSocketFactory().createSocket(
                         transport, "java-endpoint.cipherazzi.test", Integer.parseInt(args[1]), true))
                {
                    socket.startHandshake();
                    socket.getOutputStream().write(42);
                    if (socket.getInputStream().read() != 42)
                        throw new Exception("TLS echo failed");
                }
                Thread.sleep(400);
            }

            // Publish a complete JDK export while the source process is still available for attribution.
            recording.stop();
            var directory = Path.of(args[3]);
            var binary = directory.resolve("telemetry.jfr");
            var pending = directory.resolve("telemetry.tmp");
            recording.dump(binary);
            var exporter = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "jfr.exe").toString(),
                "print", "--json", "--events", "jdk.TLSHandshake,jdk.X509Certificate,jdk.X509Validation",
                binary.toString()).redirectOutput(pending.toFile()).redirectError(ProcessBuilder.Redirect.INHERIT).start();
            if (!exporter.waitFor(10, TimeUnit.SECONDS))
            {
                exporter.destroyForcibly().waitFor();
                throw new Exception("JFR export timed out");
            }
            if (exporter.exitValue() != 0)
                throw new Exception("JFR export failed");
            var process = ProcessHandle.current();
            var started = process.info().startInstant().orElseThrow();
            var path = process.info().command().orElseThrow();
            var identity = "{\"pid\":" + process.pid() + ",\"process_started_us\":" +
                (started.getEpochSecond() * 1000000 + started.getNano() / 1000) +
                ",\"process_name\":\"java.exe\",\"process_path\":\"" + path.replace("\\", "\\\\") + "\",";
            Files.writeString(pending, identity + Files.readString(pending).stripLeading().substring(1));
            Files.move(pending, directory.resolve("telemetry.json"), StandardCopyOption.ATOMIC_MOVE);
            System.out.println("completed");
            Thread.sleep(15000);
        }
    }
}
