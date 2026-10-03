use rustls::{ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject}};
use std::{io::{Read, Write}, net::{TcpListener, TcpStream}, sync::Arc, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let args: Vec<String> = std::env::args().collect();
    let (role, version, address, certificate, key, mode) =
        (&args[1], &args[2], &args[3], &args[4], &args[5], &args[6]);
    let certificates = CertificateDer::pem_file_iter(certificate)?.collect::<Result<Vec<_>, _>>()?;
    let private = PrivateKeyDer::from_pem_file(key)?;
    let mut roots = RootCertStore::empty();
    if mode != "reject"
    {
        for certificate in &certificates { roots.add(certificate.clone())?; }
    }
    let versions = [if version == "TLSv1.2" { &rustls::version::TLS12 } else { &rustls::version::TLS13 }];
    let mut client = ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(roots.clone()).with_client_auth_cert(certificates.clone(), private.clone_key())?;
    client.alpn_protocols = vec![b"h2".to_vec()];
    let client = Arc::new(client);
    let server = if role == "server"
    {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
        let mut server = ServerConfig::builder_with_protocol_versions(&versions)
            .with_client_cert_verifier(verifier).with_single_cert(certificates, private)?;
        server.alpn_protocols = vec![b"h2".to_vec()];
        Some(Arc::new(server))
    } else { None };
    #[cfg(feature = "async")]
    if args.get(7).is_some_and(|value| value == "async")
    {
        return tokio::runtime::Builder::new_current_thread().enable_all().build()?
            .block_on(run_async(client, server, address, mode));
    }
    let listener = if role == "server"
    {
        let listener = TcpListener::bind(address)?;
        println!("{}", listener.local_addr()?.port());
        std::io::stdout().flush()?;
        Some(listener)
    } else { None };
    for _ in 0..if mode == "ok" { 2 } else { 1 }
    {
        let mut socket = match &listener
        {
            Some(listener) => listener.accept()?.0,
            None => TcpStream::connect(address)?,
        };
        socket.set_read_timeout(Some(Duration::from_secs(15)))?;
        socket.set_write_timeout(Some(Duration::from_secs(15)))?;
        let mut connection = match &server
        {
            Some(server) => Connection::Server(ServerConnection::new(server.clone())?),
            None => Connection::Client(ClientConnection::new(client.clone(), ServerName::try_from("coverage.test")?)?),
        };
        let result = connection.complete_io(&mut socket);
        if mode == "reject" { assert!(result.is_err()); return Ok(()); }
        result?;
        match &mut connection
        {
            Connection::Client(connection) => echo(rustls::Stream::new(connection, &mut socket), true)?,
            Connection::Server(connection) => echo(rustls::Stream::new(connection, &mut socket), false)?,
        }
    }
    Ok(())
}

#[cfg(feature = "async")]
async fn run_async(client: Arc<ClientConfig>, server: Option<Arc<ServerConfig>>, address: &str, mode: &str)
    -> Result<(), Box<dyn std::error::Error>>
{
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    let listener = if server.is_some()
    {
        let listener = tokio::net::TcpListener::bind(address).await?;
        println!("{}", listener.local_addr()?.port());
        std::io::stdout().flush()?;
        Some(listener)
    } else { None };
    async fn echo(mut stream: impl AsyncRead + AsyncWrite + Unpin, client: bool) -> std::io::Result<()>
    {
        let mut payload = [b'*'];
        if client
        {
            stream.write_all(&payload).await?;
            stream.flush().await?;
            stream.read_exact(&mut payload).await?;
        }
        else
        {
            stream.read_exact(&mut payload).await?;
            stream.write_all(&payload).await?;
            stream.flush().await?;
        }
        assert_eq!(payload, [b'*']);
        Ok(())
    }
    for _ in 0..if mode == "ok" { 2 } else { 1 }
    {
        if let (Some(listener), Some(server)) = (&listener, &server)
        {
            let socket = listener.accept().await?.0;
            echo(TlsAcceptor::from(server.clone()).accept(socket).await?, false).await?;
        }
        else
        {
            let socket = tokio::net::TcpStream::connect(address).await?;
            let tls = TlsConnector::from(client.clone())
                .connect(ServerName::try_from("coverage.test")?, socket).await;
            if mode == "reject" { assert!(tls.is_err()); return Ok(()); }
            echo(tls?, true).await?;
        }
    }
    Ok(())
}

fn echo(mut stream: impl Read + Write, client: bool) -> std::io::Result<()>
{
    let mut payload = [b'*'];
    if client
    {
        stream.write_all(&payload)?;
        stream.flush()?;
        stream.read_exact(&mut payload)?;
    }
    else
    {
        stream.read_exact(&mut payload)?;
        stream.write_all(&payload)?;
        stream.flush()?;
    }
    assert_eq!(payload, [b'*']);
    Ok(())
}
