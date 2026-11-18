//! The line kith talks to kithd over: the Unix socket, or with `--server` a TLS connection to a
//! node's `--listen` port (cargo feature `remote`). The node's certificate must be signed by the
//! cluster CA in the identity directory and name `kith`; kith shows the identity's own certificate
//! (T-0404). Both kinds read and write like a socket, so the callers do not know which they have.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
#[cfg(feature = "remote")]
use std::{
    net::TcpStream,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

/// Where kithd is: its Unix socket, or a node's `--listen` address and the identity to show it.
#[derive(Clone)]
pub enum Route {
    Socket(PathBuf),
    Node { server: String, identity: PathBuf },
}

impl Route {
    pub fn name(&self) -> String {
        match self {
            Route::Socket(path) => path.display().to_string(),
            Route::Node { server, .. } => server.clone(),
        }
    }
}

/// One connection to kithd. A `Node` is shared between the threads that read and write it.
pub enum Wire {
    Socket(UnixStream),
    #[cfg(feature = "remote")]
    Node(Arc<Node>),
}

/// How long one socket wait lasts before the lock is let go: a write must not wait on a read
/// for longer than this, and a read does not hold up a write for longer.
#[cfg(feature = "remote")]
const POLL: Duration = Duration::from_millis(20);

impl Wire {
    /// kithd, open. `patience` is how long it may stay silent (None: as long as it likes). A TLS
    /// handshake waits as long as that, or half a minute if there is no patience.
    pub fn connect(route: &Route, patience: Option<Duration>) -> io::Result<Wire> {
        match route {
            Route::Socket(path) => {
                let socket = UnixStream::connect(path)?;
                socket.set_read_timeout(patience)?;
                socket.set_write_timeout(patience)?;
                Ok(Wire::Socket(socket))
            }
            #[cfg(feature = "remote")]
            Route::Node { server, identity } => dial(server, identity, patience),
            #[cfg(not(feature = "remote"))]
            Route::Node { server, identity } => Err(io::Error::other(format!(
                "cannot reach {server} with {}: this kith was built without the remote feature (cargo build --features remote)",
                identity.display()
            ))),
        }
    }

    /// Another handle on the same connection, for the thread that writes while this one reads.
    pub fn dup(&self) -> io::Result<Wire> {
        match self {
            Wire::Socket(socket) => Ok(Wire::Socket(socket.try_clone()?)),
            #[cfg(feature = "remote")]
            Wire::Node(node) => Ok(Wire::Node(node.clone())),
        }
    }

    /// Both ways shut: a read on another handle ends too.
    pub fn end(&self) {
        match self {
            Wire::Socket(socket) => drop(socket.shutdown(Shutdown::Both)),
            #[cfg(feature = "remote")]
            Wire::Node(node) => drop(node.closer.shutdown(Shutdown::Both)),
        }
    }

    /// No more to send: the peer's reads end, and ours go on.
    pub fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Wire::Socket(socket) => socket.shutdown(Shutdown::Write),
            #[cfg(feature = "remote")]
            Wire::Node(node) => node.finish(),
        }
    }

    /// How long it may stay silent from now on (None: as long as it likes).
    pub fn set_patience(&self, patience: Option<Duration>) -> io::Result<()> {
        match self {
            Wire::Socket(socket) => {
                socket.set_read_timeout(patience)?;
                socket.set_write_timeout(patience)
            }
            #[cfg(feature = "remote")]
            Wire::Node(node) => {
                let mut link = node.lock();
                link.patience = patience;
                link.quiet_since = Instant::now();
                Ok(())
            }
        }
    }
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Wire::Socket(socket) => socket.read(buf),
            #[cfg(feature = "remote")]
            Wire::Node(node) => node.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Wire::Socket(socket) => socket.write(buf),
            #[cfg(feature = "remote")]
            Wire::Node(node) => node.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Wire::Socket(socket) => socket.flush(),
            #[cfg(feature = "remote")]
            Wire::Node(node) => node.flush(),
        }
    }
}

/// A TLS connection to a node. Its lock is held for one poll at a time, never through a wait
/// for the other direction, so a read and a write on two threads cannot wait on each other.
#[cfg(feature = "remote")]
pub struct Node {
    link: Mutex<Link>,
    /// The same socket, for the shutdowns, which must not wait on the lock.
    closer: TcpStream,
}

#[cfg(feature = "remote")]
struct Link {
    tls: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    patience: Option<Duration>,
    /// When anything last moved: the patience counts from here.
    quiet_since: Instant,
}

#[cfg(feature = "remote")]
fn is_poll(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

#[cfg(feature = "remote")]
impl Link {
    /// Called when a poll found nothing: silent for longer than the patience, kithd is gone.
    fn silent(&self) -> io::Result<()> {
        match self.patience {
            Some(patience) if self.quiet_since.elapsed() >= patience => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "kithd has said nothing for too long",
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(feature = "remote")]
impl Node {
    fn lock(&self) -> std::sync::MutexGuard<'_, Link> {
        self.link.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut link = self.lock();
            match link.tls.read(buf) {
                Ok(n) => {
                    link.quiet_since = Instant::now();
                    return Ok(n);
                }
                // No close_notify: a cut connection reads as its end, and the HTTP framing says
                // whether the answer was whole.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) if is_poll(&e) => link.silent()?,
                Err(e) => return Err(e),
            }
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        // Rustls takes the bytes into its buffer without touching the socket; flush sends them.
        let n = self.lock().tls.write(buf)?;
        self.flush()?;
        Ok(n)
    }

    fn flush(&self) -> io::Result<()> {
        loop {
            let mut link = self.lock();
            match link.tls.flush() {
                Ok(()) => {
                    link.quiet_since = Instant::now();
                    return Ok(());
                }
                Err(e) if is_poll(&e) => link.silent()?,
                Err(e) => return Err(e),
            }
        }
    }

    fn finish(&self) -> io::Result<()> {
        self.lock().tls.conn.send_close_notify();
        self.flush()?;
        self.closer.shutdown(Shutdown::Write)
    }
}

/// The TLS handshake to `server`, presenting the identity; the node must check out against the
/// cluster CA and be named `kith`. A refusal comes back as the handshake's error.
#[cfg(feature = "remote")]
fn dial(server: &str, identity: &Path, patience: Option<Duration>) -> io::Result<Wire> {
    let (roots, chain, key) = identity_files(identity)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        // TLS 1.3 only: kithd's server speaks it, and 1.2's code is most of what the remote build adds.
        .with_protocol_versions(&[&rustls::version::TLS13])
        .and_then(|builder| builder.with_root_certificates(roots).with_client_auth_cert(chain, key))
        .map_err(io::Error::other)?;
    let name = rustls::pki_types::ServerName::try_from("kith").map_err(io::Error::other)?;
    let mut tcp = TcpStream::connect(server)?;
    let handshake = patience.unwrap_or(Duration::from_secs(30));
    tcp.set_read_timeout(Some(handshake))?;
    tcp.set_write_timeout(Some(handshake))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(io::Error::other)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)?;
    }
    let closer = tcp.try_clone()?;
    tcp.set_read_timeout(Some(POLL))?;
    tcp.set_write_timeout(Some(POLL))?;
    let link = Link {
        tls: rustls::StreamOwned::new(conn, tcp),
        patience,
        quiet_since: Instant::now(),
    };
    Ok(Wire::Node(Arc::new(Node {
        link: Mutex::new(link),
        closer,
    })))
}

/// The identity directory `kith identity` leaves: the cluster's ca.crt, and one NAME.crt with
/// its NAME.key. A key that anyone but its owner can read is refused, and named.
#[cfg(feature = "remote")]
fn identity_files(
    dir: &Path,
) -> io::Result<(
    rustls::RootCertStore,
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let mut keys = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "key") {
            keys.push(path);
        }
    }
    let [key] = keys.as_slice() else {
        let found = keys.len();
        return Err(io::Error::other(format!(
            "identity {} needs exactly one NAME.key, found {found}",
            dir.display()
        )));
    };
    let mode = std::fs::metadata(key)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is readable by others (mode {mode:o}): a key others can read is no secret; run: chmod 600 {}",
                key.display(),
                key.display()
            ),
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    for ca in CertificateDer::pem_file_iter(dir.join("ca.crt")).map_err(io::Error::other)? {
        roots.add(ca.map_err(io::Error::other)?).map_err(io::Error::other)?;
    }
    let chain = CertificateDer::pem_file_iter(key.with_extension("crt"))
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(io::Error::other)?;
    Ok((roots, chain, key))
}
