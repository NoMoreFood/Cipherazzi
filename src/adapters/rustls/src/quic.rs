use crate::{Metadata, Reporter};
use rustls::quic::Connection;
use std::{io, net::SocketAddr, path::PathBuf, time::SystemTime};

impl Reporter
{
    /// Records a completed QUIC connection without asserting its handshake timing or verification policy.
    pub fn observe_quic(&self, connection: &Connection, local: SocketAddr, remote: SocketAddr,
        server_name: Option<&str>) -> io::Result<PathBuf>
    {
        if connection.is_handshaking()
        {
            return Err(io::Error::other("QUIC connection is not established"));
        }
        self.quic_result(connection, local, remote, server_name, None, true)
    }

    /// Records a completed or failed QUIC TLS handshake using its public rustls state.
    /// Started is the application's recorded start; success requires authentication to be complete.
    pub fn quic_handshake_result(&self, connection: &Connection, local: SocketAddr, remote: SocketAddr,
        server_name: Option<&str>, started: SystemTime, result: &Result<(), rustls::Error>) -> io::Result<PathBuf>
    {
        if result.is_ok() && connection.is_handshaking()
        {
            return Err(io::Error::other("QUIC handshake is still in progress"));
        }
        self.quic_result(connection, local, remote, server_name, Some(started), result.is_ok())
    }

    fn quic_result(&self, connection: &Connection, local: SocketAddr, remote: SocketAddr,
        server_name: Option<&str>, started: Option<SystemTime>, success: bool) -> io::Result<PathBuf>
    {
        let name = match connection
        {
            Connection::Server(server) => server.server_name(),
            Connection::Client(_) => server_name,
        };
        let encoded = self.encode(Metadata { state: Some(connection), endpoints: Ok((local, remote)),
            server_name: name, client: matches!(connection, Connection::Client(_)), quic: true }, started, success)?;
        self.publish(encoded)
    }
}
