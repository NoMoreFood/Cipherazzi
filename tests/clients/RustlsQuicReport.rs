use cipherazzi_rustls::Reporter;
use rustls::{ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    quic::{ClientConnection, Connection, ServerConnection, Version}};
use std::{net::UdpSocket, sync::Arc, time::SystemTime};

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let args: Vec<String> = std::env::args().collect();
    let (directory, certificate, key, mode, address) = (&args[1], &args[2], &args[3], &args[4], &args[5]);
    let reporter = Reporter::new(directory)?;
    let certificates = CertificateDer::pem_file_iter(certificate)?.collect::<Result<Vec<_>, _>>()?;
    let private = PrivateKeyDer::from_pem_file(key)?;
    let mut roots = RootCertStore::empty();
    if mode != "reject"
    {
        for certificate in &certificates { roots.add(certificate.clone())?; }
    }
    let mut client = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    client.alpn_protocols = vec![b"coverage".to_vec()];
    let mut server = ServerConfig::builder().with_no_client_auth().with_single_cert(certificates, private)?;
    server.alpn_protocols = vec![b"coverage".to_vec()];
    let mut client = Connection::Client(ClientConnection::new(Arc::new(client), Version::V1,
        ServerName::try_from("coverage.test")?, vec![])?);
    let mut server = Connection::Server(ServerConnection::new(Arc::new(server), Version::V1, vec![])?);
    let local = UdpSocket::bind(address)?;
    let remote = UdpSocket::bind(address)?;
    let (local, remote) = (local.local_addr()?, remote.local_addr()?);
    let started = SystemTime::now();
    assert!(reporter.observe_quic(&client, local, remote, Some("coverage.test")).is_err());
    assert!(reporter.quic_handshake_result(&client, local, remote, Some("coverage.test"), started, &Ok(())).is_err());
    let mut result = Ok(());
    for _ in 0..32
    {
        let mut outbound = Vec::new();
        client.write_hs(&mut outbound);
        if !outbound.is_empty() { server.read_hs(&outbound)?; }
        outbound.clear();
        server.write_hs(&mut outbound);
        if !outbound.is_empty() { result = client.read_hs(&outbound); }
        if result.is_err() || (!client.is_handshaking() && !server.is_handshaking()) { break; }
    }
    if mode == "reject"
    {
        assert!(result.is_err());
        reporter.quic_handshake_result(&client, local, remote, Some("coverage.test"), started, &result)?;
        return Ok(());
    }
    result?;
    assert!(!client.is_handshaking() && !server.is_handshaking());
    if mode == "lost-directory" { std::fs::remove_dir(directory)?; }
    let report = reporter.quic_handshake_result(&client, local, remote, Some("coverage.test"), started, &Ok(()));
    if mode == "lost-directory" { assert!(report.is_err()); return Ok(()); }
    report?;
    reporter.quic_handshake_result(&server, remote, local, None, started, &Ok(()))?;
    reporter.observe_quic(&client, local, remote, Some("coverage.test"))?;
    reporter.observe_quic(&server, remote, local, None)?;
    Ok(())
}
