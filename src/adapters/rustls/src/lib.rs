#![cfg(windows)]

#[cfg(feature = "async")]
mod r#async;
#[cfg(feature = "quic")]
mod quic;

use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{CommonState, Connection, HandshakeKind};
use serde_json::{Value, json};
use std::{fs, io::{self, Write}, net::{SocketAddr, TcpStream}, path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering}, time::{SystemTime, UNIX_EPOCH}};
use windows_sys::Win32::{Foundation::FILETIME, System::Threading::{GetCurrentProcess, GetProcessTimes},
    Security::Cryptography::{CertCreateCertificateContext, CertFreeCertificateContext, X509_ASN_ENCODING}};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Publishes public TLS reports atomically. The application manages directory retention.
#[derive(Clone)]
pub struct Reporter
{
    directory: PathBuf,
    started: u64,
    executable: PathBuf,
}

struct Metadata<'a>
{
    state: Option<&'a CommonState>,
    endpoints: io::Result<(SocketAddr, SocketAddr)>,
    server_name: Option<&'a str>,
    client: bool,
    quic: bool,
}

impl Reporter
{
    pub fn new(directory: impl AsRef<Path>) -> io::Result<Self>
    {
        if !directory.as_ref().is_dir()
        {
            return Err(io::Error::other("Endpoint output is not a directory"));
        }
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // The pseudo-handle and output structures remain valid for the duration of the call.
        if unsafe { GetProcessTimes(GetCurrentProcess(), &mut created, &mut exited, &mut kernel, &mut user) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        Ok(Self { directory: directory.as_ref().to_owned(), started: (ticks - 116444736000000000) / 10,
            executable: std::env::current_exe()? })
    }

    /// Completes a blocking TCP TLS handshake, keeping TLS and reporting results separate.
    /// The application supplies its configured client server name, when available.
    pub fn handshake(&self, connection: &mut Connection, socket: &mut TcpStream, server_name: Option<&str>)
        -> (io::Result<()>, io::Result<PathBuf>)
    {
        let observation = !connection.is_handshaking();
        let started = SystemTime::now();
        let tls = if observation { Ok(()) } else { connection.complete_io(socket).map(|_| ()) };
        let report = self.write(connection, socket, server_name,
            if observation { None } else { Some(started) }, tls.is_ok());
        (tls, report)
    }

    /// Records an established TCP connection without asserting handshake timing or a verification policy.
    pub fn observe(&self, connection: &Connection, socket: &TcpStream, server_name: Option<&str>) -> io::Result<PathBuf>
    {
        if connection.is_handshaking()
        {
            return Err(io::Error::other("TLS connection is not established"));
        }
        self.write(connection, socket, server_name, None, true)
    }

    fn write(&self, connection: &Connection, socket: &TcpStream, server_name: Option<&str>,
        started: Option<SystemTime>, success: bool) -> io::Result<PathBuf>
    {
        let name = match connection
        {
            Connection::Server(server) => server.server_name(),
            Connection::Client(_) => server_name,
        };
        let encoded = self.encode(Metadata { state: Some(connection),
            endpoints: socket.local_addr().and_then(|local| Ok((local, socket.peer_addr()?))),
            server_name: name, client: matches!(connection, Connection::Client(_)), quic: false }, started, success)?;
        self.publish(encoded)
    }

    fn encode(&self, metadata: Metadata<'_>, started: Option<SystemTime>, success: bool) -> io::Result<Vec<u8>>
    {
        let micros = |time: SystemTime| -> io::Result<u64>
        {
            let value = time.duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_micros();
            u64::try_from(value).map_err(io::Error::other)
        };
        let timestamp = micros(SystemTime::now())?;
        let client = metadata.client;
        let success = success && metadata.state.is_some_and(|state| !state.is_handshaking());
        let mut report = json!({"schema": "cipherazzi.endpoint/1", "provider": "Rust/rustls",
            "pid": std::process::id(), "process_started_us": self.started,
            "process_name": self.executable.file_name().unwrap_or_default().to_string_lossy(),
            "process_path": self.executable.to_string_lossy(), "timestamp_us": timestamp,
            "transport": if metadata.quic { "QUIC" } else { "TCP" },
            "role": if client { "client" } else { "server" }, "success": success});
        if timestamp < self.started
        {
            return Err(io::Error::other("Endpoint timing is outside the report bounds"));
        }
        if let Some(started) = started
        {
            let started = micros(started)?;
            if started < self.started || started > timestamp || timestamp - started > 120000000
            {
                return Err(io::Error::other("Endpoint timing is outside the report bounds"));
            }
            report["handshake_started_us"] = json!(started);
        }
        else
        {
            report["observation"] = json!("connection");
        }
        if !success
        {
            report["error_name"] = json!("TLS_HANDSHAKE_FAILED");
        }
        let (local, remote) = metadata.endpoints?;
        if !local.ip().is_unspecified() && !remote.ip().is_unspecified() && local.port() != 0 && remote.port() != 0
        {
            for (field, address) in [("local", local), ("remote", remote)]
            {
                report[field] = json!({"address": address.ip().to_string(), "port": address.port()});
            }
        }
        if let Some(version) = metadata.state.and_then(|state| state.protocol_version())
        {
            report["tls_version"] = json!(u16::from(version));
        }
        if let Some(cipher) = metadata.state.and_then(|state| state.negotiated_cipher_suite())
        {
            report["cipher_id"] = json!(u16::from(cipher.suite()));
        }
        if let Some(group) = metadata.state.and_then(|state| state.negotiated_key_exchange_group())
        {
            report["group_id"] = json!(u16::from(group.name()));
        }
        if let Some(alpn) = metadata.state.and_then(|state| state.alpn_protocol())
            .and_then(|value| std::str::from_utf8(value).ok())
        {
            report["selected_alpn"] = json!(alpn);
        }
        if let Some(name) = metadata.server_name.filter(|name| name.len() <= 253 &&
            !name.bytes().any(|b| b <= 32 || b == 127))
        {
            report["server_name"] = json!(name);
        }
        if success && let Some(kind) = metadata.state.and_then(|state| state.handshake_kind())
        {
            report["session_resumed"] = json!(kind == HandshakeKind::Resumed);
        }

        // Validate the public certificate encoding without asserting trust or exporting raw public keys as X.509.
        let mut chain = Vec::<Value>::new();
        let mut bytes = 0;
        for certificate in metadata.state.and_then(|state| state.peer_certificates()).unwrap_or_default()
        {
            bytes += certificate.len();
            if chain.len() == 16 || certificate.len() > 262144 || bytes > 1048576
            {
                return Err(io::Error::other("Public certificate chain exceeds the report bounds"));
            }
            let context = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING,
                certificate.as_ref().as_ptr(), certificate.len() as u32) };
            if context.is_null() { continue; }
            unsafe { CertFreeCertificateContext(context); }
            chain.push(json!(STANDARD.encode(certificate.as_ref())));
        }
        report[if client { "server_certificates_der" } else { "client_certificates_der" }] = json!(chain);
        Ok(serde_json::to_vec(&report)?)
    }

    fn publish(&self, encoded: Vec<u8>) -> io::Result<PathBuf>
    {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_micros();
        let name = format!("cipherazzi-rustls-{}-{}-{}", std::process::id(), timestamp,
            SEQUENCE.fetch_add(1, Ordering::Relaxed));
        let temporary = self.directory.join(format!("{name}.tmp"));
        let destination = self.directory.join(format!("{name}.json"));
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        let written = file.write_all(&encoded);
        drop(file);
        let result = written.and_then(|_| fs::rename(&temporary, &destination));
        if result.is_err() { let _ = fs::remove_file(&temporary); }
        result.map(|_| destination)
    }
}
