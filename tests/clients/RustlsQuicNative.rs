use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{io::Write, sync::Arc, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>>
{
    let args: Vec<String> = std::env::args().collect();
    let (role, address, certificate, key, mode) = (&args[1], &args[2], &args[3], &args[4], &args[5]);
    let certificates = CertificateDer::pem_file_iter(certificate)?.collect::<Result<Vec<_>, _>>()?;
    let private = PrivateKeyDer::from_pem_file(key)?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(10).try_into()?));
    let endpoint = if role == "server"
    {
        let mut tls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certificates, private)?;
        tls.alpn_protocols = vec![b"coverage".to_vec()];
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)?));
        config.transport_config(Arc::new(transport));
        quinn::Endpoint::server(config, address.parse()?)?
    }
    else
    {
        let mut roots = rustls::RootCertStore::empty();
        if mode != "reject"
        {
            for certificate in certificates { roots.add(certificate)?; }
        }
        let mut tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        tls.alpn_protocols = vec![b"coverage".to_vec()];
        let mut config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
        config.transport_config(Arc::new(transport));
        let local = if address.starts_with('[') { "[::1]:0" } else { "127.0.0.1:0" };
        let socket = std::net::UdpSocket::bind(local)?;
        let mut endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket,
            Arc::new(quinn::TokioRuntime))?;
        endpoint.set_default_client_config(config);
        endpoint
    };
    if role == "server"
    {
        println!("{}", endpoint.local_addr()?.port());
        std::io::stdout().flush()?;
        let connection = endpoint.accept().await.ok_or("QUIC listener ended")?.await?;
        let (mut send, mut receive) = connection.accept_bi().await?;
        let received = receive.read_to_end(64).await?;
        assert_eq!(received, b"private-application-payload");
        send.write_all(&received).await?;
        send.finish()?;
        connection.closed().await;
    }
    else
    {
        let result = endpoint.connect(address.parse()?, "coverage.test")?.await;
        if mode == "reject" { assert!(result.is_err()); return Ok(()); }
        let connection = result?;
        let (mut send, mut receive) = connection.open_bi().await?;
        send.write_all(b"private-application-payload").await?;
        send.finish()?;
        assert_eq!(receive.read_to_end(64).await?, b"private-application-payload");
        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    }
    Ok(())
}
