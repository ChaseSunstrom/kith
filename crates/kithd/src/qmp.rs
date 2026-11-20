//! A client of QEMU's machine protocol (QMP) on the control socket [`crate::vm::control`] gives
//! a machine: what a live migration of a VM workload is driven through.
//!
//! One JSON object a line. QEMU greets, the client says `qmp_capabilities`, and each command
//! after it is answered by one `return` or `error` object with the command's id; `event`
//! objects come between and are skipped. Blocking (std's socket): an async caller runs it on
//! a blocking thread. Every call has one deadline, not one per read, so a peer that trickles
//! bytes cannot hold it past its time; the whole connection has another.
//
// ponytail: the migration is started and polled by URI (`tcp:`, `unix:`, `exec:`); handing
// QEMU an open descriptor (SCM_RIGHTS, `fd:`) is not done: the migration stream between two
// nodes is a TCP connection QEMU makes itself. Each is left for later.

// (Nothing calls it yet: the migration of slices C and D of T-1135 does.)
#![allow(dead_code)]

use serde_json::{Value, json};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// The longest line read from QEMU (a `query-*` reply is a few KiB).
const MAX_LINE: usize = 1 << 20;

/// Why a call to QEMU did not give an answer.
#[derive(Debug)]
pub enum Error {
    /// The path is not a control socket of this node's own making: refused unread.
    Foreign(String),
    /// The socket, or what was written to or read from it.
    Io(io::Error),
    /// The call's time, or the connection's, ran out.
    Timeout,
    /// A line longer than [`MAX_LINE`].
    TooLong,
    /// QEMU hung up.
    Closed,
    /// What QEMU said is not the protocol.
    Protocol(String),
    /// QEMU refused the command: its error class and description.
    Qemu { class: String, desc: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Foreign(why) => write!(f, "not this replica's control socket: {why}"),
            Error::Io(e) => write!(f, "qmp: {e}"),
            Error::Timeout => f.write_str("qmp: timed out"),
            Error::TooLong => write!(f, "qmp: a line over {MAX_LINE} bytes"),
            Error::Closed => f.write_str("qmp: qemu hung up"),
            Error::Protocol(why) => write!(f, "qmp: {why}"),
            Error::Qemu { class, desc } => write!(f, "qemu refused ({class}): {desc}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Error::Timeout,
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => Error::Closed,
            _ => Error::Io(e),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// What `query-status` says.
#[derive(Debug, PartialEq, Eq)]
pub struct Status {
    pub running: bool,
    /// QEMU's run state: `running`, `paused`, `prelaunch`, `inmigrate`, `postmigrate`, ...
    pub state: String,
}

/// What `query-migrate` says: `setup`, `active`, `completed`, `failed`, ... or `none` before any.
#[derive(Debug, PartialEq, Eq)]
pub struct Migration {
    pub status: String,
    /// Bytes of RAM sent, left to send and in all, while one is going.
    pub ram: Option<(u64, u64, u64)>,
    /// Why it failed, when it did.
    pub error: Option<String>,
}

/// A connection to one machine's QEMU, past the handshake.
pub struct Qmp {
    stream: UnixStream,
    buf: Vec<u8>,
    next: u64,
    call: Duration,
    end: Instant,
    broken: bool,
}

/// The replica's own: `path` is in a directory that is ours alone (a replica's, from
/// [`crate::files::of`]), and is a socket, not a link to somewhere else.
fn own(path: &Path) -> Result<()> {
    let foreign = |why: &str| Err(Error::Foreign(format!("{}: {why}", path.display())));
    let me = nix::unistd::geteuid().as_raw();
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    let Some(dir) = dir else { return foreign("no directory") };
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != me || meta.mode() & 0o077 != 0 {
        return foreign("its directory is a link, not ours, or open to others");
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_socket() => foreign("not a socket"),
        Ok(_) => Ok(()),
        // (Not there yet: QEMU makes it as it starts, and `connect` waits for it.)
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn left(until: Instant) -> Result<Duration> {
    until
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Timeout)
}

impl Qmp {
    /// Connect to `path`, waiting up to `call` for QEMU to make the socket and greet, then
    /// the handshake. `call` is also each later call's time; `overall` is the connection's,
    /// from now: nothing is answered after it.
    pub fn connect(path: &Path, call: Duration, overall: Duration) -> Result<Qmp> {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, socket, sockopt};
        let (start, deadline) = (Instant::now(), Instant::now() + call.min(overall));
        own(path)?;
        let stream = loop {
            let fd = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
                None,
            )
            .map_err(io::Error::from)?;
            let addr = UnixAddr::new(path).map_err(io::Error::from)?;
            match connect(fd.as_raw_fd(), &addr) {
                Ok(()) => {
                    // (After the check above and before this a link could have been put there.)
                    own(path)?;
                    let peer = getsockopt(&fd, sockopt::PeerCredentials).map_err(io::Error::from)?;
                    if peer.uid() != nix::unistd::geteuid().as_raw() {
                        return Err(Error::Foreign(format!(
                            "{}: made by uid {}",
                            path.display(),
                            peer.uid()
                        )));
                    }
                    let stream = UnixStream::from(fd);
                    stream.set_nonblocking(false)?;
                    break stream;
                }
                // Not made yet, not listening yet, or its queue is full: again, till the time.
                Err(nix::Error::ENOENT | nix::Error::ECONNREFUSED | nix::Error::EAGAIN) => {
                    left(deadline)?;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(io::Error::from(e).into()),
            }
        };
        // (Owner only, whatever QEMU's umask made it.)
        let _ = std::fs::set_permissions(path, PermissionsExt::from_mode(0o600));
        let mut qmp = Qmp {
            stream,
            buf: Vec::new(),
            next: 1,
            call,
            end: start + overall,
            broken: false,
        };
        let greeting = qmp.read(qmp.until())?;
        if !greeting.get("QMP").is_some_and(Value::is_object) {
            return Err(Error::Protocol(format!("no greeting: {greeting}")));
        }
        qmp.run("qmp_capabilities", None)?;
        Ok(qmp)
    }

    /// The time this call has: `call` from now, and never past the connection's end.
    fn until(&self) -> Instant {
        (Instant::now() + self.call).min(self.end)
    }

    /// One line of JSON, by `until`: one deadline for the line, however its bytes arrive.
    fn read(&mut self, until: Instant) -> Result<Value> {
        loop {
            if let Some(at) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=at).collect();
                if at > MAX_LINE {
                    return Err(Error::TooLong);
                }
                return serde_json::from_slice(&line[..at]).map_err(|e| Error::Protocol(format!("not JSON: {e}")));
            }
            if self.buf.len() > MAX_LINE {
                return Err(Error::TooLong);
            }
            self.stream.set_read_timeout(Some(left(until)?))?;
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(Error::Closed),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// `command` with `arguments`: its `return`, skipping the events and the answers to calls
    /// given up on that come first.
    fn run(&mut self, command: &str, arguments: Option<Value>) -> Result<Value> {
        if self.broken {
            return Err(Error::Closed);
        }
        let answer = self.ask(command, arguments);
        // (A timeout leaves the stream as it was: the late answer is skipped by its id.)
        if matches!(
            answer,
            Err(Error::Io(_) | Error::TooLong | Error::Closed | Error::Protocol(_))
        ) {
            self.broken = true;
        }
        answer
    }

    fn ask(&mut self, command: &str, arguments: Option<Value>) -> Result<Value> {
        let until = self.until();
        let id = self.next;
        self.next += 1;
        let mut said = json!({ "execute": command, "id": id });
        if let Some(arguments) = arguments {
            said["arguments"] = arguments;
        }
        self.stream.set_write_timeout(Some(left(until)?))?;
        self.stream.write_all(format!("{said}\n").as_bytes())?;
        loop {
            let got = self.read(until)?;
            if got.get("event").is_some() || got.get("id").is_some_and(|got| *got != id) {
                continue;
            }
            if let Some(error) = got.get("error") {
                let text = |key| error.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
                return Err(Error::Qemu {
                    class: text("class"),
                    desc: text("desc"),
                });
            }
            return got
                .get("return")
                .cloned()
                .ok_or_else(|| Error::Protocol(format!("no answer in {got}")));
        }
    }

    pub fn status(&mut self) -> Result<Status> {
        let got = self.run("query-status", None)?;
        match (got["running"].as_bool(), got["status"].as_str()) {
            (Some(running), Some(state)) => Ok(Status {
                running,
                state: state.into(),
            }),
            _ => Err(Error::Protocol(format!("query-status: {got}"))),
        }
    }

    /// `migrate-set-capabilities`: each named capability on or off (`events`, `auto-converge`, ...).
    pub fn set_capabilities(&mut self, capabilities: &[(&str, bool)]) -> Result<()> {
        let list: Vec<Value> = capabilities
            .iter()
            .map(|(name, on)| json!({ "capability": name, "state": on }))
            .collect();
        self.run("migrate-set-capabilities", Some(json!({ "capabilities": list })))
            .map(drop)
    }

    /// `migrate-set-parameters`: the longest the machine may be stopped for the last of its
    /// memory, in milliseconds.
    pub fn set_downtime_limit(&mut self, milliseconds: u64) -> Result<()> {
        self.run(
            "migrate-set-parameters",
            Some(json!({ "downtime-limit": milliseconds })),
        )
        .map(drop)
    }

    /// `migrate`: start sending this machine to `uri`. It returns at once; [`Qmp::migration`] tells how far.
    pub fn migrate(&mut self, uri: &str) -> Result<()> {
        self.run("migrate", Some(json!({ "uri": uri }))).map(drop)
    }

    /// `migrate-incoming`: a machine started with `-incoming defer` listens at `uri`.
    pub fn migrate_incoming(&mut self, uri: &str) -> Result<()> {
        self.run("migrate-incoming", Some(json!({ "uri": uri }))).map(drop)
    }

    pub fn migration(&mut self) -> Result<Migration> {
        let got = self.run("query-migrate", None)?;
        let number = |key: &str| got["ram"][key].as_u64();
        Ok(Migration {
            // (No `status` before a migration was ever asked for.)
            status: got["status"].as_str().unwrap_or("none").into(),
            ram: Some((number("transferred"), number("remaining"), number("total")))
                .and_then(|(a, b, c)| Some((a?, b?, c?))),
            error: got["error-desc"].as_str().map(str::to_string),
        })
    }

    /// `cont`: run the machine (after it arrived, or if it was started stopped).
    pub fn cont(&mut self) -> Result<()> {
        self.run("cont", None).map(drop)
    }

    /// `quit`: end QEMU. It may hang up before it answers: that is the answer.
    pub fn quit(&mut self) -> Result<()> {
        match self.run("quit", None) {
            Err(Error::Closed) => Ok(()),
            other => other.map(drop),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread::JoinHandle;

    /// A directory of its own in TMPDIR, mode 0700, as a replica's is.
    fn dir(name: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "kith-qmp-{}-{}-{name}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o700)).unwrap();
        dir
    }

    const GREETING: &str = r#"{"QMP":{"version":{"qemu":{"major":9,"minor":0,"micro":0}},"capabilities":["oob"]}}"#;

    /// A fake QEMU on a socket in a directory of its own: greets, then `play` has the
    /// connection (given the lines it reads).
    fn fake(name: &str, play: impl FnOnce(UnixStream) + Send + 'static) -> (PathBuf, JoinHandle<()>) {
        let path = dir(name).join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            writeln!(stream, "{GREETING}").unwrap();
            play(stream);
        });
        (path, server)
    }

    /// The server's side of a conversation: for each line read, what to write back, given the
    /// command, its arguments and its id.
    fn answer(mut stream: UnixStream, mut reply: impl FnMut(&str, &Value, &Value) -> Vec<String>) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
            while let Some(at) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=at).collect();
                let said: Value = serde_json::from_slice(&line).unwrap();
                let lines = reply(said["execute"].as_str().unwrap(), &said["arguments"], &said["id"]);
                for line in lines {
                    writeln!(stream, "{line}").unwrap();
                }
            }
        }
    }

    fn ok(id: &Value, value: Value) -> String {
        json!({ "return": value, "id": id }).to_string()
    }

    const EVENT: &str = r#"{"event":"STOP","timestamp":{"seconds":1,"microseconds":2}}"#;
    const SECOND: Duration = Duration::from_secs(1);

    /// The handshake, query-status, the migration commands and query-migrate against a fake
    /// QEMU that puts events before every answer and a late answer to an old call among them.
    #[test]
    fn qmp_calls_are_answered_through_events() {
        let (path, server) = fake("flow", |stream| {
            let seen = std::cell::RefCell::new(Vec::new());
            answer(stream, |command, arguments, id| {
                seen.borrow_mut().push(command.to_string());
                let value = match command {
                    "query-status" => json!({ "running": false, "status": "inmigrate" }),
                    "migrate-set-capabilities" => {
                        assert_eq!(
                            arguments["capabilities"][0],
                            json!({ "capability": "events", "state": true })
                        );
                        json!({})
                    }
                    "migrate-set-parameters" => {
                        assert_eq!(arguments["downtime-limit"], 300);
                        json!({})
                    }
                    "migrate" | "migrate-incoming" => {
                        assert!(arguments["uri"].as_str().unwrap().starts_with("tcp:127.0.0.1:"));
                        json!({})
                    }
                    "query-migrate" if seen.borrow().iter().filter(|c| *c == "query-migrate").count() == 1 => json!({}),
                    "query-migrate" => {
                        json!({ "status": "active", "ram": { "transferred": 10, "remaining": 20, "total": 30 } })
                    }
                    _ => json!({}),
                };
                let stale = json!({ "return": {}, "id": 0 }).to_string();
                vec![EVENT.into(), stale, EVENT.into(), ok(id, value)]
            });
            assert_eq!(seen.borrow()[0], "qmp_capabilities");
        });
        let mut qmp = Qmp::connect(&path, SECOND * 5, SECOND * 20).unwrap();
        assert_eq!(
            qmp.status().unwrap(),
            Status {
                running: false,
                state: "inmigrate".into()
            }
        );
        qmp.set_capabilities(&[("events", true)]).unwrap();
        qmp.set_downtime_limit(300).unwrap();
        qmp.migrate("tcp:127.0.0.1:4444").unwrap();
        qmp.migrate_incoming("tcp:127.0.0.1:4444").unwrap();
        assert_eq!(
            qmp.migration().unwrap(),
            Migration {
                status: "none".into(),
                ram: None,
                error: None
            }
        );
        let going = qmp.migration().unwrap();
        assert_eq!((going.status.as_str(), going.ram), ("active", Some((10, 20, 30))));
        qmp.cont().unwrap();
        qmp.quit().unwrap();
        drop(qmp);
        server.join().unwrap();
    }

    /// QEMU's refusal comes back typed, and the connection is still good for the next call;
    /// a hang-up on `quit` is its answer.
    #[test]
    fn qmp_error_replies_are_typed() {
        let (path, server) = fake("error", |stream| {
            answer(stream, |command, _, id| match command {
                "migrate" => {
                    vec![json!({ "error": { "class": "GenericError", "desc": "no such thing" }, "id": id }).to_string()]
                }
                "quit" => vec![ok(id, json!({}))],
                _ => vec![ok(id, json!({ "running": true, "status": "running" }))],
            })
        });
        let mut qmp = Qmp::connect(&path, SECOND * 5, SECOND * 20).unwrap();
        match qmp.migrate("tcp:127.0.0.1:1") {
            Err(Error::Qemu { class, desc }) => {
                assert_eq!((class.as_str(), desc.as_str()), ("GenericError", "no such thing"))
            }
            other => panic!("{other:?}"),
        }
        assert!(qmp.status().unwrap().running);
        qmp.quit().unwrap();
        drop(qmp);
        server.join().unwrap();
    }

    /// A peer that says nothing, one that trickles a line a byte at a time for ever, and a
    /// connection past its overall time: each ends at its deadline, not at the peer's pace.
    #[test]
    fn qmp_slow_peers_are_cut_at_the_deadline() {
        let (path, server) = fake("silent", |mut stream| {
            // (The handshake is answered; the next call never is.)
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            writeln!(stream, "{}", ok(&json!(1), json!({}))).unwrap();
            let _ = stream.read(&mut buf);
            std::thread::sleep(Duration::from_millis(700));
        });
        let mut qmp = Qmp::connect(&path, Duration::from_millis(300), SECOND * 20).unwrap();
        let start = Instant::now();
        assert!(matches!(qmp.status(), Err(Error::Timeout)));
        assert!(start.elapsed() < Duration::from_millis(600), "{:?}", start.elapsed());
        server.join().unwrap();

        let (path, server) = fake("trickle", |mut stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            writeln!(stream, "{}", ok(&json!(1), json!({}))).unwrap();
            let _ = stream.read(&mut buf);
            // (A line that never ends, a byte every 20 ms: a per-read timeout would never fire.)
            for _ in 0..100 {
                if stream.write_all(b" ").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let mut qmp = Qmp::connect(&path, Duration::from_millis(300), SECOND * 20).unwrap();
        let start = Instant::now();
        assert!(matches!(qmp.status(), Err(Error::Timeout)));
        assert!(start.elapsed() < Duration::from_millis(900), "{:?}", start.elapsed());
        drop(qmp);
        server.join().unwrap();

        // The call's time is long; the connection's is short: the shorter wins.
        let (path, server) = fake("overall", |mut stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            writeln!(stream, "{}", ok(&json!(1), json!({}))).unwrap();
            let _ = stream.read(&mut buf);
            std::thread::sleep(Duration::from_millis(900));
        });
        let mut qmp = Qmp::connect(&path, SECOND * 30, Duration::from_millis(300)).unwrap();
        let start = Instant::now();
        assert!(matches!(qmp.status(), Err(Error::Timeout)));
        assert!(start.elapsed() < Duration::from_millis(800), "{:?}", start.elapsed());
        assert!(matches!(qmp.status(), Err(Error::Timeout)));
        server.join().unwrap();
    }

    /// A line past the bound, a line that is not JSON, no greeting and a hang-up are errors, not hangs.
    #[test]
    fn qmp_refuses_what_is_not_the_protocol() {
        let (path, server) = fake("long", |mut stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            writeln!(stream, "{}", ok(&json!(1), json!({}))).unwrap();
            let _ = stream.read(&mut buf);
            let big = vec![b'a'; MAX_LINE + 8192];
            let _ = stream.write_all(&big);
            let _ = stream.write_all(b"\n");
        });
        let mut qmp = Qmp::connect(&path, SECOND * 5, SECOND * 20).unwrap();
        assert!(matches!(qmp.status(), Err(Error::TooLong)));
        // (A connection that lost its place does not go on.)
        assert!(matches!(qmp.status(), Err(Error::Closed)));
        server.join().unwrap();

        let (path, server) = fake("junk", |mut stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            writeln!(stream, "{}", ok(&json!(1), json!({}))).unwrap();
            let _ = stream.read(&mut buf);
            writeln!(stream, "not json").unwrap();
        });
        let mut qmp = Qmp::connect(&path, SECOND * 5, SECOND * 20).unwrap();
        assert!(matches!(qmp.status(), Err(Error::Protocol(_))));
        server.join().unwrap();

        let (path, server) = fake("hangup", drop);
        match Qmp::connect(&path, SECOND * 5, SECOND * 20) {
            Err(Error::Closed) => {}
            other => panic!("{:?}", other.map(drop)),
        }
        server.join().unwrap();

        let path = dir("nogreeting").join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            writeln!(stream, r#"{{"hello":1}}"#).unwrap();
        });
        assert!(matches!(
            Qmp::connect(&path, SECOND * 5, SECOND * 20),
            Err(Error::Protocol(_))
        ));
        server.join().unwrap();
    }

    /// `connect` waits for QEMU to make its socket (it is made as QEMU starts), and not past its time.
    #[test]
    fn qmp_connect_waits_for_the_socket() {
        let path = dir("late").join("qmp.sock");
        let at = path.clone();
        let server = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            let listener = UnixListener::bind(&at).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            writeln!(stream, "{GREETING}").unwrap();
            answer(stream, |_, _, id| vec![ok(id, json!({}))]);
        });
        let qmp = Qmp::connect(&path, SECOND * 5, SECOND * 20).unwrap();
        drop(qmp);
        server.join().unwrap();

        let start = Instant::now();
        let missing = dir("never").join("qmp.sock");
        assert!(matches!(
            Qmp::connect(&missing, Duration::from_millis(200), SECOND),
            Err(Error::Timeout)
        ));
        assert!(start.elapsed() < SECOND);
    }

    /// A socket that is not in the replica's own directory, or is a link, is refused before anything is sent.
    #[test]
    fn qmp_refuses_a_socket_that_is_not_the_replicas_own() {
        let refused = |path: &Path| match Qmp::connect(path, Duration::from_millis(300), SECOND) {
            Err(Error::Foreign(_)) => true,
            other => panic!("{:?}", other.map(drop)),
        };
        // A directory others may enter.
        let open = dir("open");
        let path = open.join("qmp.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&open, PermissionsExt::from_mode(0o755)).unwrap();
        assert!(refused(&path));
        // A link to a socket, in a directory that is ours.
        let ours = dir("link");
        let target = open.join("qmp.sock");
        std::os::unix::fs::symlink(&target, ours.join("qmp.sock")).unwrap();
        assert!(refused(&ours.join("qmp.sock")));
        // A file that is not a socket.
        let plain = dir("plain");
        std::fs::write(plain.join("qmp.sock"), b"x").unwrap();
        assert!(refused(&plain.join("qmp.sock")));
        // No directory at all, and a directory that is a link.
        assert!(refused(Path::new("qmp.sock")));
        let linked = dir("linked");
        std::os::unix::fs::symlink(&open, linked.join("replica")).unwrap();
        assert!(refused(&linked.join("replica").join("qmp.sock")));
    }

    /// QEMU's command line gets the control socket right after the binary, the incoming mode
    /// only on request; another hypervisor's is left alone; a comma in the path is doubled.
    #[test]
    fn vm_command_carries_the_control_socket() {
        let words = |words: &[&str]| words.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        let has = |line: &[String], at: &[&str]| line.windows(at.len()).any(|w| w == at);
        let mut line = words(&["qemu-system-x86_64", "-nodefaults", "-m", "64M"]);
        crate::vm::control(&mut line, Path::new("/run/kith/replicas/r1/qmp.sock"), false);
        assert_eq!(
            line[..3],
            words(&[
                "qemu-system-x86_64",
                "-qmp",
                "unix:/run/kith/replicas/r1/qmp.sock,server=on,wait=off"
            ])[..]
        );
        assert!(has(&line, &["-m", "64M"]) && !line.iter().any(|w| w == "-incoming"));
        let mut line = words(&["qemu-system-aarch64", "-nodefaults"]);
        crate::vm::control(&mut line, Path::new("/run/a,b/qmp.sock"), true);
        assert!(
            has(&line, &["-qmp", "unix:/run/a,,b/qmp.sock,server=on,wait=off"]),
            "{line:?}"
        );
        assert!(has(&line, &["-incoming", "defer"]));
        let mut other = words(&["cloud-hypervisor", "--cpus", "boot=1"]);
        crate::vm::control(&mut other, Path::new("/run/x/qmp.sock"), true);
        assert_eq!(other, words(&["cloud-hypervisor", "--cpus", "boot=1"]));
    }

    /// Ends the QEMU it holds, whatever the test did.
    struct Qemu(Child);
    impl Drop for Qemu {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn start(dir: &Path, incoming: bool) -> Qemu {
        // (No machine to speak of and no KVM: the protocol is what is tried.)
        let mut line = vec!["qemu-system-x86_64".to_string()];
        line.extend(
            [
                "-nodefaults",
                "-no-user-config",
                "-display",
                "none",
                "-S",
                "-machine",
                "none",
            ]
            .map(String::from),
        );
        crate::vm::control(&mut line, &dir.join(crate::vm::CONTROL), incoming);
        let child = Command::new(&line[0])
            .args(&line[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Qemu(child)
    }

    /// A real QEMU answers the client: the handshake, query-status, the migration commands, and
    /// a machine started with `-incoming defer` says it waits for one. Skipped without QEMU.
    #[test]
    fn qmp_real_qemu_answers() {
        if Command::new("qemu-system-x86_64")
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .is_err()
        {
            println!("skipped: qemu-system-x86_64 is not on this machine");
            return;
        }
        let dir = dir("real");
        let mut qemu = start(&dir, false);
        let mut qmp = Qmp::connect(&dir.join(crate::vm::CONTROL), SECOND * 20, SECOND * 60).unwrap();
        let status = qmp.status().unwrap();
        assert!(!status.running, "{status:?}");
        qmp.set_capabilities(&[("events", true)]).unwrap();
        qmp.set_downtime_limit(300).unwrap();
        assert_eq!(qmp.migration().unwrap().status, "none");
        // (A refusal from the real thing is typed too.)
        assert!(matches!(qmp.migrate("nonsense:"), Err(Error::Qemu { .. })));
        qmp.quit().unwrap();
        assert!(qemu.0.wait().unwrap().success());

        let dir = self::dir("real-incoming");
        let _qemu = start(&dir, true);
        let mut qmp = Qmp::connect(&dir.join(crate::vm::CONTROL), SECOND * 20, SECOND * 60).unwrap();
        assert_eq!(qmp.status().unwrap().state, "inmigrate");
        qmp.migrate_incoming("tcp:127.0.0.1:0").unwrap();
        qmp.quit().unwrap();
    }
}
