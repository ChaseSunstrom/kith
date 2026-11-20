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
    net::{TcpStream, ToSocketAddrs},
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

/// The longest nap before another try at a socket that is not ready (the lock is let go for it).
#[cfg(feature = "remote")]
const POLL: Duration = Duration::from_millis(20);

/// The most one write takes into the TLS buffer, so that a write of a big body waits for the socket.
#[cfg(feature = "remote")]
const PIECE: usize = 16 << 10;

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

    /// No more to send: the peer's reads end, and ours go on. A TLS link is only flushed, not
    /// half-closed: its close_notify and FIN read to kithd as the client gone, and it hangs up
    /// before it has answered.
    pub fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Wire::Socket(socket) => socket.shutdown(Shutdown::Write),
            #[cfg(feature = "remote")]
            Wire::Node(node) => node.flush(),
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

/// A TLS connection to a node. The socket is never waited on under the lock: an operation takes
/// what the socket has at once, and a wait for it sleeps with the lock let go, so a read and a
/// write on two threads cannot wait on each other.
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
    /// Called when the socket was not ready: silent for longer than the patience, kithd is gone.
    fn silent(&self) -> io::Result<()> {
        match self.patience {
            Some(patience) if self.quiet_since.elapsed() >= patience => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "kithd has said nothing for too long",
            )),
            _ => Ok(()),
        }
    }

    /// Sends what rustls holds, as far as the socket takes it: WouldBlock if it is full. Each
    /// send that moves bytes is progress, and the patience counts from the last one.
    fn send(&mut self) -> io::Result<()> {
        while self.tls.conn.wants_write() {
            if self.tls.conn.write_tls(&mut self.tls.sock)? == 0 {
                break;
            }
            self.quiet_since = Instant::now();
        }
        Ok(())
    }

    /// Takes in what kithd has sent, as far as the socket has it; 0 when kithd has closed.
    fn take(&mut self) -> io::Result<usize> {
        let n = self.tls.conn.read_tls(&mut self.tls.sock)?;
        if n > 0 {
            self.quiet_since = Instant::now();
            self.tls.conn.process_new_packets().map_err(io::Error::other)?;
        }
        Ok(n)
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.tls.conn.reader().read(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                done => return done,
            }
            // The socket ended with no close_notify: kithd closes a finished connection with one
            // (its TLS stream shuts down), so this one was cut. Tunnels end this way too, and drop it.
            if self.take()? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "kithd closed the connection without closing TLS",
                ));
            }
        }
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // What was buffered goes first, and a write waits for the socket before it takes more:
        // rustls would otherwise hold the whole body in memory, and the waiting would be deferred.
        self.send()?;
        let n = self.tls.conn.writer().write(&buf[..buf.len().min(PIECE)])?;
        // Sent now if the socket takes it; otherwise the next write or flush sends it.
        match self.send() {
            Err(e) if !is_poll(&e) => Err(e),
            _ => Ok(n),
        }
    }
}

#[cfg(feature = "remote")]
impl Node {
    fn lock(&self) -> std::sync::MutexGuard<'_, Link> {
        self.link.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `op` under the lock, which is let go whenever the socket is not ready: the nap before
    /// the next try doubles from 50 µs up to POLL, and the lock is free for the other direction.
    fn step<T>(&self, mut op: impl FnMut(&mut Link) -> io::Result<T>) -> io::Result<T> {
        let mut nap = Duration::from_micros(50);
        loop {
            {
                let mut link = self.lock();
                match op(&mut link) {
                    Err(e) if is_poll(&e) => link.silent()?,
                    done => return done,
                }
            }
            std::thread::sleep(nap);
            nap = (nap * 2).min(POLL);
        }
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.step(|link| link.read(buf))
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.step(|link| link.write(buf))
    }

    fn flush(&self) -> io::Result<()> {
        self.step(|link| link.send())
    }
}

/// The first address of `server` that takes a connection within `timeout`.
#[cfg(feature = "remote")]
fn connect_to(server: &str, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::InvalidInput, format!("{server} has no address"));
    for addr in server.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The TLS handshake to `server`, presenting the identity; the node must check out against the
/// cluster CA and be named `kith`. A refusal comes back as the handshake's error.
#[cfg(feature = "remote")]
fn dial(server: &str, identity: &Path, patience: Option<Duration>) -> io::Result<Wire> {
    let config = client_config(identity)?;
    let name = rustls::pki_types::ServerName::try_from("kith").map_err(io::Error::other)?;
    let handshake = patience.unwrap_or(Duration::from_secs(30));
    let mut tcp = connect_to(server, handshake)?;
    tcp.set_read_timeout(Some(handshake))?;
    tcp.set_write_timeout(Some(handshake))?;
    let mut conn = rustls::ClientConnection::new(config, name).map_err(io::Error::other)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)?;
    }
    let closer = tcp.try_clone()?;
    // Not waited on: an operation takes what the socket has, and Node::step naps between tries.
    tcp.set_nonblocking(true)?;
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

/// The client's TLS settings for `identity`, built once and then reused by every connection to it
/// (the ui opens one per browser request). A changed identity directory is built afresh.
#[cfg(feature = "remote")]
static CONFIG: Mutex<Option<(PathBuf, Arc<rustls::ClientConfig>)>> = Mutex::new(None);

#[cfg(feature = "remote")]
fn client_config(identity: &Path) -> io::Result<Arc<rustls::ClientConfig>> {
    let mut built = CONFIG.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, config)) = built.as_ref().filter(|(dir, _)| dir == identity) {
        return Ok(config.clone());
    }
    let (roots, chain, key) = identity_files(identity)?;
    let config = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            // TLS 1.3 only: kithd's server speaks it, and 1.2's code is most of what the remote build adds.
            .with_protocol_versions(&[&rustls::version::TLS13])
            .and_then(|builder| builder.with_root_certificates(roots).with_client_auth_cert(chain, key))
            .map_err(io::Error::other)?,
    );
    *built = Some((identity.to_path_buf(), config.clone()));
    Ok(config)
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
    // Exactly one, as kithd's own reading of its CA: a second one would be trusted without being named.
    let ca_path = dir.join("ca.crt");
    let cas = CertificateDer::pem_file_iter(&ca_path)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let [ca] = cas.as_slice() else {
        return Err(io::Error::other(format!(
            "{} needs exactly one certificate (the cluster CA), found {}",
            ca_path.display(),
            cas.len()
        )));
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).map_err(io::Error::other)?;
    let chain = CertificateDer::pem_file_iter(key.with_extension("crt"))
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(io::Error::other)?;
    Ok((roots, chain, key))
}
