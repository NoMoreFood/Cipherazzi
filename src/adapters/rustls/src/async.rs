use crate::{Metadata, Reporter};
use rustls::pki_types::ServerName;
use std::{io, path::PathBuf, time::SystemTime};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

impl Reporter
{
    /// Runs a Tokio client handshake and returns TLS and reporting results independently.
    /// The caller can cancel this future or wrap it in an application timeout.
    pub async fn connect_async(&self, connector: &TlsConnector, name: ServerName<'static>, socket: TcpStream)
        -> (io::Result<client::TlsStream<TcpStream>>, io::Result<PathBuf>)
    {
        let started = SystemTime::now();
        let endpoints = socket.local_addr().and_then(|local| Ok((local, socket.peer_addr()?)));
        let hostname = name.to_str().into_owned();
        let tls = connector.connect(name, socket).await;
        let state = tls.as_ref().ok().map(|stream| stream.get_ref().1 as &rustls::CommonState);
        let encoded = self.encode(Metadata { state, endpoints, server_name: Some(&hostname),
            client: true, quic: false }, Some(started), tls.is_ok());
        let report = self.publish_async(encoded).await;
        (tls, report)
    }

    /// Runs a Tokio server handshake without making assumptions about custom certificate verifiers.
    pub async fn accept_async(&self, acceptor: &TlsAcceptor, socket: TcpStream)
        -> (io::Result<server::TlsStream<TcpStream>>, io::Result<PathBuf>)
    {
        let started = SystemTime::now();
        let endpoints = socket.local_addr().and_then(|local| Ok((local, socket.peer_addr()?)));
        let tls = acceptor.accept(socket).await;
        let connection = tls.as_ref().ok().map(|stream| stream.get_ref().1);
        let encoded = self.encode(Metadata { state: connection.map(|state| state as &rustls::CommonState), endpoints,
            server_name: connection.and_then(|state| state.server_name()), client: false, quic: false },
            Some(started), tls.is_ok());
        let report = self.publish_async(encoded).await;
        (tls, report)
    }

    async fn publish_async(&self, encoded: io::Result<Vec<u8>>) -> io::Result<PathBuf>
    {
        let bytes = encoded?;
        let reporter = self.clone();
        tokio::task::spawn_blocking(move || reporter.publish(bytes)).await.map_err(io::Error::other)?
    }
}
