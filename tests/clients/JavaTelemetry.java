import java.io.FileInputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import javax.net.ssl.*;

class JavaTelemetry
{
    public static void main(String[] args) throws Exception
    {
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
        System.out.println("completed");
        Thread.sleep(15000);
    }
}
