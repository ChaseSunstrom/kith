//! The Docker Engine API in front of kith (T-1205): the socket `kith docker serve` listens on, so
//! the `docker` command can be pointed at a kith node with `DOCKER_HOST=unix://SOCKET`.
//!
//! This step answers the base calls only (`/_ping`, `/version`, `/info`, each also under a
//! `/v1.NN/` prefix) and says 501 with a JSON `{"message": ...}` to anything else: never a hang.
//! The server is plain `std`: a thread per connection, a cap on connections, on the head of a
//! request and on its body, keep-alive and HEAD. Nothing here is in kithd.
//!
//! A socket left by a process that was killed (SIGTERM included) is not cleaned up: the next
//! `listen` on that path finds nobody answering and replaces it.

use ring::digest;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

mod containers;
mod stream;
pub use containers::{Containers, NAMESPACE, Store};
pub use stream::{Event, Input, Kind, LogChunk, LogFrom, Session};

/// The newest and the oldest Docker API this front speaks, as (major, minor).
pub const API_VERSION: (u32, u32) = (1, 47);
pub const MIN_API_VERSION: (u32, u32) = (1, 40);
/// Open connections at once; one more is answered 503 and closed.
const MAX_CONNECTIONS: usize = 64;
/// The request line and headers together, and a request's body (step 2's create call is a few KiB).
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: u64 = 1 << 20;
/// A connection that is silent this long is closed (a waiting keep-alive too); a head, from its
/// first byte, or a body, from the end of the head, that takes longer than these to arrive is
/// dropped, however steadily it trickles in.
const IDLE: Duration = Duration::from_secs(30);
const HEAD_DEADLINE: Duration = Duration::from_secs(30);
const BODY_DEADLINE: Duration = Duration::from_secs(60);
/// A socket's path, in bytes, is at most this (sun_path is 108 with its NUL).
const MAX_SOCKET_PATH: usize = 107;

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut context = digest::Context::new(&digest::SHA256);
    for part in parts {
        context.update(part);
    }
    context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The ID `docker` shows for the container that is Workload `name` of `namespace`: 64 hex digits,
/// the SHA-256 of "namespace\0name". The same on every run and on every machine, so it needs no
/// store of its own; the NUL keeps ("a", "bc") and ("ab", "c") apart.
pub fn container_id(namespace: &str, name: &str) -> String {
    sha256_hex(&[namespace.as_bytes(), b"\0", name.as_bytes()])
}

/// Bind the socket at `path`, readable by its owner alone from its first moment: it is made in a
/// private (0700) directory beside `path`, made 0600 and renamed into place, so no other user sees
/// it with a wider mode. A socket left behind by a run that died is replaced; a live one, or a
/// file that is not a socket, is an error.
pub fn listen(path: &Path) -> io::Result<UnixListener> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            // Stale only if nobody is there to be refused by; any other failure is not ours to guess at.
            match UnixStream::connect(path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("{} is served by another process", path.display()),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(e) => return Err(e),
            }
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Where a stranger could plant a name for us to trip on, we do not go: `parent` is ours and
    // nobody else's to write in (a sticky directory of another's, like /tmp, is not).
    let meta = std::fs::metadata(parent)?;
    let me = std::fs::metadata("/proc/self")?.uid();
    if meta.uid() != me || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be owned by you and writable by no one else: put the socket in a directory of your own",
                parent.display()
            ),
        ));
    }
    // A name no one can guess, made here or not at all: nothing already there is ever touched.
    // (Short: a socket's path is at most about 100 bytes.)
    let too_long = |p: &Path| {
        let n = p.as_os_str().len();
        (n > MAX_SOCKET_PATH).then(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is {n} bytes: a Unix socket's path is at most {MAX_SOCKET_PATH}, so use a shorter --listen",
                    p.display()
                ),
            )
        })
    };
    let mut private = None;
    for _ in 0..4 {
        let mut random = [0u8; 6];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let name = format!(
            ".kd-{}-{}",
            std::process::id(),
            random.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        if let Some(e) = too_long(path).or_else(|| too_long(&parent.join(&name).join("s"))) {
            return Err(e);
        }
        match std::fs::DirBuilder::new().mode(0o700).create(parent.join(&name)) {
            Ok(()) => {
                private = Some(parent.join(name));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let private = private.ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "no free private name"))?;
    let made = (|| {
        let listener = UnixListener::bind(private.join("s"))?;
        std::fs::set_permissions(private.join("s"), std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(private.join("s"), path)?;
        Ok(listener)
    })();
    // Only what this call made: after the rename the directory is empty; after a failure the
    // socket may still be in it.
    let _ = std::fs::remove_file(private.join("s"));
    let _ = std::fs::remove_dir(&private);
    made
}

/// Answer on `listener` until the process ends, the container calls 501: see `serve_with`.
pub fn serve(listener: UnixListener) {
    serve_with(listener, None);
}

/// Answer on `listener` until the process ends: one thread per connection, at most
/// MAX_CONNECTIONS at a time. With a `store`, the container calls are answered from it; without,
/// they are 501.
pub fn serve_with(listener: UnixListener, store: Option<Box<dyn Store>>) {
    let containers = store.map(|s| Arc::new(Containers::new(s)));
    let live = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            // (Out of descriptors, say: do not spin.)
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };
        let _ = stream.set_write_timeout(Some(IDLE));
        let Some(slot) = Slot::take(&live, MAX_CONNECTIONS) else {
            let _ = write_reply(&stream, &message(503, "kith: too many connections"), false, true);
            continue;
        };
        let containers = containers.clone();
        let _ = std::thread::Builder::new().stack_size(256 * 1024).spawn(move || {
            let _slot = slot;
            handle(stream, HEAD_DEADLINE, BODY_DEADLINE, containers.as_deref());
        });
    }
}

/// One of the connection places; giving it back is its drop.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(live: &Arc<AtomicUsize>, cap: usize) -> Option<Slot> {
        if live.fetch_add(1, Ordering::SeqCst) >= cap {
            live.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot(live.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Request {
    method: String,
    target: String,
    body: Vec<u8>,
    close: bool,
}

#[derive(Debug)]
struct Reply {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

fn json_reply(status: u16, body: String) -> Reply {
    Reply {
        status,
        content_type: "application/json",
        body: body.into_bytes(),
    }
}

/// Docker's error shape: `{"message": "..."}`.
fn message(status: u16, text: impl AsRef<str>) -> Reply {
    json_reply(status, format!(r#"{{"message":{}}}"#, q(text.as_ref())))
}

/// A stream whose every read ends at `until`: the clock is the stream's, not each read's, so a peer
/// sending a byte a second cannot hold a connection past it.
struct Clocked {
    stream: UnixStream,
    until: Instant,
}

impl Read for Clocked {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

/// A clock that never runs out in practice: a stream's reads (a hijacked connection's stdin) wait as long as it lives.
const NEVER: Duration = Duration::from_secs(10 * 365 * 86_400);

/// Has the client hung up? A 1 ms look at the socket: EOF or an error says yes, a timeout (nothing
/// sent) or buffered bytes (a pipelined request) say no.
fn hung_up(reader: &mut BufReader<Clocked>) -> bool {
    reader.get_mut().until = Instant::now() + Duration::from_millis(1);
    match reader.fill_buf() {
        Ok(bytes) => bytes.is_empty(),
        Err(e) => !matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock),
    }
}

/// Has a hijacked connection broken? Its client closes its sending side when it has no stdin to send
/// (the docker CLI does for `run` without `-i`) and goes on reading, so an EOF is not a hang-up here:
/// only an error is. (A client that left shows by a write that fails.)
fn broken(reader: &mut BufReader<Clocked>) -> bool {
    reader.get_mut().until = Instant::now() + Duration::from_millis(1);
    match reader.fill_buf() {
        Ok(_) => false,
        Err(e) => !matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock),
    }
}

/// Requests and replies on one connection until it closes.
fn handle(stream: UnixStream, head: Duration, body: Duration, containers: Option<&Containers>) {
    let mut reader = BufReader::new(Clocked {
        stream,
        until: Instant::now(),
    });
    loop {
        let (reply, head_only, close) = match read_request(&mut reader, head, body) {
            Ok(None) => return,
            Ok(Some(request)) => {
                // A stream (logs, attach, an exec's start) is written by the call itself, and the
                // connection is done with it; a refusal before its first byte is an ordinary reply.
                let streamed = containers.and_then(|c| {
                    let (path, query) = api_path(&request).ok()?;
                    c.stream(&request.method, path, query, &request.body, &mut reader)
                });
                match streamed {
                    Some(Ok(())) => return,
                    Some(Err(reply)) => (reply, false, request.close),
                    None => {
                        let mut gone = || hung_up(&mut reader);
                        (
                            route(&request, containers, &mut gone),
                            request.method == "HEAD",
                            request.close,
                        )
                    }
                }
            }
            Err(reply) => (reply, false, true),
        };
        if write_reply(&reader.get_ref().stream, &reply, head_only, close).is_err() || close {
            return;
        }
    }
}

fn write_reply(mut out: impl Write, reply: &Reply, head_only: bool, close: bool) -> io::Result<()> {
    let reason = match reply.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Error",
    };
    // A 204 or a 304 has no body, so no length either.
    let bodiless = matches!(reply.status, 204 | 304);
    let length = if bodiless {
        String::new()
    } else {
        format!("Content-Length: {}\r\n", reply.body.len())
    };
    let mut bytes = format!(
        "HTTP/1.1 {} {reason}\r\nApi-Version: {}.{}\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: kith-docker/{}\r\nContent-Type: {}\r\n{length}{}\r\n",
        reply.status,
        API_VERSION.0,
        API_VERSION.1,
        env!("CARGO_PKG_VERSION"),
        reply.content_type,
        if close { "Connection: close\r\n" } else { "" },
    )
    .into_bytes();
    if !head_only {
        bytes.extend_from_slice(&reply.body);
    }
    out.write_all(&bytes)
}

/// One line of the head without its line end. `None`: the peer went away, went quiet or was too slow.
fn head_line(reader: &mut BufReader<Clocked>, used: &mut usize) -> Result<Option<String>, Reply> {
    let mut line = String::new();
    let room = (MAX_HEAD - (*used).min(MAX_HEAD)) as u64 + 1;
    let n = match reader.by_ref().take(room).read_line(&mut line) {
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return Err(message(400, "kith: the request is not text")),
        Err(_) => return Ok(None),
    };
    *used += n;
    if *used > MAX_HEAD {
        return Err(message(431, "kith: the request head is too large"));
    }
    if !line.ends_with('\n') {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
}

/// The next request, its body read and dropped (no endpoint here takes one). `Err`: the reply to
/// send before closing; `None`: close without one.
fn read_request(reader: &mut BufReader<Clocked>, head: Duration, body: Duration) -> Result<Option<Request>, Reply> {
    // Waiting for the first byte of a request is the idle time of a keep-alive; the head's clock
    // starts when that byte is here.
    reader.get_mut().until = Instant::now() + IDLE;
    if !reader.fill_buf().is_ok_and(|b| !b.is_empty()) {
        return Ok(None);
    }
    reader.get_mut().until = Instant::now() + head;
    let mut used = 0;
    let Some(first) = head_line(reader, &mut used)? else {
        return Ok(None);
    };
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(message(400, "kith: malformed request line"));
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(message(400, "kith: only HTTP/1.0 and HTTP/1.1"));
    }
    let (mut length, mut chunked, mut close) = (None, false, version == "HTTP/1.0");
    loop {
        let Some(line) = head_line(reader, &mut used)? else {
            return Ok(None);
        };
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line
            .split_once(':')
            .filter(|(n, _)| !n.is_empty() && !n.contains(char::is_whitespace))
        else {
            return Err(message(400, "kith: malformed header"));
        };
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                let n = value
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| value.parse::<u64>().ok())
                    .flatten();
                match n {
                    Some(n) if length.is_none_or(|l| l == n) => length = Some(n),
                    _ => return Err(message(400, "kith: bad Content-Length")),
                }
            }
            "transfer-encoding" => chunked = true,
            "connection" => close |= value.to_ascii_lowercase().split(',').any(|t| t.trim() == "close"),
            _ => {}
        }
    }
    if chunked {
        return Err(message(501, "kith: chunked request bodies are not supported"));
    }
    let length = length.unwrap_or(0);
    if length > MAX_BODY {
        return Err(message(
            413,
            format!("kith: a request body is at most {MAX_BODY} bytes"),
        ));
    }
    reader.get_mut().until = Instant::now() + body;
    // (Not with_capacity(length): the length is the client's word, and a lie costs memory it never sends.)
    let mut bytes = Vec::new();
    if reader.by_ref().take(length).read_to_end(&mut bytes).is_ok() && bytes.len() as u64 == length {
        Ok(Some(Request {
            method: method.to_string(),
            target: target.to_string(),
            body: bytes,
            close,
        }))
    } else {
        Ok(None)
    }
}

/// `/v1.47/info` as (Some((1, 47)), "/info"); a path without such a prefix as (None, path).
fn split_version(path: &str) -> (Option<(u32, u32)>, &str) {
    let number = |s: &str| {
        Some(s)
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))?
            .parse()
            .ok()
    };
    path.strip_prefix("/v")
        .and_then(|rest| {
            let (version, _) = rest.split_once('/')?;
            let (major, minor) = version.split_once('.')?;
            Some(((number(major)?, number(minor)?), &path[2 + version.len()..]))
        })
        .map_or((None, path), |(version, rest)| (Some(version), rest))
}

/// The path (without its `/v1.NN` prefix) and the query of a request, or the reply for a client
/// whose version is not one this front speaks.
fn api_path(request: &Request) -> Result<(&str, &str), Reply> {
    let (path, query) = request.target.split_once('?').unwrap_or((request.target.as_str(), ""));
    let (version, path) = split_version(path);
    // (Like dockerd, `/_ping` answers any client: the version it names is how a client learns ours.)
    if let Some(v) = version.filter(|_| path != "/_ping") {
        let (max, min) = (API_VERSION, MIN_API_VERSION);
        let (v0, v1) = v;
        if v > max {
            return Err(message(
                400,
                format!(
                    "client version {v0}.{v1} is too new. Maximum supported API version is {}.{}",
                    max.0, max.1
                ),
            ));
        }
        if v < min {
            return Err(message(
                400,
                format!(
                    "client version {v0}.{v1} is too old. Minimum supported API version is {}.{}, please upgrade your client to a newer version",
                    min.0, min.1
                ),
            ));
        }
    }
    Ok((path, query))
}

fn route(request: &Request, containers: Option<&Containers>, gone: &mut dyn FnMut() -> bool) -> Reply {
    let (path, query) = match api_path(request) {
        Ok(found) => found,
        Err(refused) => return refused,
    };
    match (request.method.as_str(), path) {
        ("GET" | "HEAD", "/_ping") => Reply {
            status: 200,
            content_type: "text/plain; charset=utf-8",
            body: b"OK".to_vec(),
        },
        ("GET" | "HEAD", "/version") => json_reply(200, version_json()),
        ("GET" | "HEAD", "/info") => json_reply(200, info_json()),
        (method, _) => containers
            .and_then(|c| c.route(method, path, query, &request.body, gone))
            .unwrap_or_else(|| {
                message(
                    501,
                    format!(
                        "kith: {method} {path} is not supported by the Docker front (docs/guide/kubernetes.md says what is)"
                    ),
                )
            }),
    }
}

fn read_trimmed(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Docker names the architectures its own way.
fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// `text` as a JSON string. (The two documents below are written out as text with these in it: a
/// tree of `Value`s for them was some 45 KB of the kith-remote build.)
fn q(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_default()
}

fn version_json() -> String {
    let (version, arch) = (env!("CARGO_PKG_VERSION"), arch());
    let (api, min) = (
        format!("{}.{}", API_VERSION.0, API_VERSION.1),
        format!("{}.{}", MIN_API_VERSION.0, MIN_API_VERSION.1),
    );
    let kernel = q(&read_trimmed("/proc/sys/kernel/osrelease"));
    format!(
        r#"{{"Platform":{{"Name":"kith"}},"Components":[{{"Name":"kith","Version":"{version}","Details":{{"ApiVersion":"{api}","MinAPIVersion":"{min}","Os":"linux","Arch":"{arch}"}}}}],"Version":"{version}","ApiVersion":"{api}","MinAPIVersion":"{min}","GitCommit":"","GoVersion":"","Os":"linux","Arch":"{arch}","KernelVersion":{kernel},"BuildTime":""}}"#
    )
}

fn info_json() -> String {
    let name = read_trimmed("/proc/sys/kernel/hostname");
    // "MemTotal:  16318388 kB"
    let memory: u64 = read_trimmed("/proc/meminfo")
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|l| l.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0);
    let id = sha256_hex(&[b"kith-docker\0", name.as_bytes()]);
    let (kernel, name) = (q(&read_trimmed("/proc/sys/kernel/osrelease")), q(&name));
    // (Not available_parallelism: std's reads cgroup files and is some KB of the build.)
    let cpus = read_trimmed("/proc/cpuinfo")
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count()
        .max(1);
    let (version, arch, memory) = (env!("CARGO_PKG_VERSION"), std::env::consts::ARCH, memory * 1024);
    format!(
        r#"{{"ID":"{id}","Containers":0,"ContainersRunning":0,"ContainersPaused":0,"ContainersStopped":0,"Images":0,"Driver":"kith","DriverStatus":[],"Plugins":{{"Volume":["local"],"Network":["bridge"],"Authorization":null,"Log":[]}},"MemoryLimit":true,"SwapLimit":false,"IPv4Forwarding":true,"Debug":false,"LoggingDriver":"json-file","CgroupDriver":"cgroupfs","CgroupVersion":"2","KernelVersion":{kernel},"OperatingSystem":"kith","OSVersion":"","OSType":"linux","Architecture":"{arch}","IndexServerAddress":"https://index.docker.io/v1/","NCPU":{cpus},"MemTotal":{memory},"DockerRootDir":"/var/lib/kith","Name":{name},"Labels":[],"ExperimentalBuild":false,"ServerVersion":"{version}","Runtimes":{{"kith":{{"path":"kith"}}}},"DefaultRuntime":"kith","Swarm":{{"NodeID":"","NodeAddr":"","LocalNodeState":"inactive","ControlAvailable":false,"Error":"","RemoteManagers":null}},"LiveRestoreEnabled":false,"Isolation":"","SecurityOptions":[],"Warnings":["kith: this is the kith Docker front, not Docker: the container calls it answers are in docs/guide/kubernetes.md; the rest of the API says 501"]}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::os::unix::net::UnixStream;

    /// A connection to `handle`, the way `docker` would hold one.
    struct Client(BufReader<UnixStream>);

    impl Client {
        fn new() -> Client {
            let (client, server) = UnixStream::pair().unwrap();
            client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            std::thread::spawn(move || handle(server, HEAD_DEADLINE, BODY_DEADLINE, None));
            Client(BufReader::new(client))
        }

        /// Send `raw` and read one reply: status, headers (lowercased names), body.
        fn ask(&mut self, raw: &str) -> (u16, Vec<(String, String)>, String) {
            self.0.get_mut().write_all(raw.as_bytes()).unwrap();
            self.read(raw.starts_with("HEAD "))
        }

        fn read(&mut self, head_only: bool) -> (u16, Vec<(String, String)>, String) {
            let mut line = String::new();
            self.0.read_line(&mut line).unwrap();
            let status = line.split(' ').nth(1).unwrap().parse().unwrap();
            let mut headers = Vec::new();
            loop {
                line.clear();
                self.0.read_line(&mut line).unwrap();
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                let (name, value) = line.split_once(": ").unwrap();
                headers.push((name.to_ascii_lowercase(), value.to_string()));
            }
            let length: usize = headers
                .iter()
                .find(|(n, _)| n == "content-length")
                .unwrap()
                .1
                .parse()
                .unwrap();
            let mut body = vec![0; if head_only { 0 } else { length }];
            self.0.read_exact(&mut body).unwrap();
            (status, headers, String::from_utf8(body).unwrap())
        }

        /// True when the server has closed the connection.
        fn closed(&mut self) -> bool {
            self.0.fill_buf().is_ok_and(|b| b.is_empty())
        }
    }

    fn get(path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: kith\r\n\r\n")
    }

    #[test]
    fn container_id_is_stable_and_64_hex() {
        let id = container_id("docker", "web");
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(id, container_id("docker", "web"));
        assert_ne!(id, container_id("docker", "web2"));
        assert_ne!(id, container_id("other", "web"));
        // The NUL between the two: no pair of names runs into another.
        assert_ne!(container_id("a", "bc"), container_id("ab", "c"));
        assert_eq!(id, sha256_hex(&[b"docker\0web"]));
        // SHA-256 of "abc", from FIPS 180-2.
        assert_eq!(
            sha256_hex(&[b"abc"]),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ping_answers_get_and_head_and_the_connection_stays_open() {
        let mut c = Client::new();
        let (status, headers, body) = c.ask(&get("/_ping"));
        assert_eq!((status, body.as_str()), (200, "OK"));
        assert!(headers.contains(&("api-version".into(), "1.47".into())));
        // HEAD: the headers of GET, no body.
        let (status, headers, body) = c.ask("HEAD /_ping HTTP/1.1\r\nHost: kith\r\n\r\n");
        assert_eq!((status, body.as_str()), (200, ""));
        assert!(headers.contains(&("content-length".into(), "2".into())));
        // Both on the one connection; a request that says close ends it.
        let (status, headers, _) = c.ask("GET /_ping HTTP/1.1\r\nConnection: close\r\n\r\n");
        assert_eq!(status, 200);
        assert!(headers.contains(&("connection".into(), "close".into())));
        assert!(c.closed());
    }

    #[test]
    fn http_1_0_closes_after_one_reply() {
        let mut c = Client::new();
        assert_eq!(c.ask("GET /_ping HTTP/1.0\r\n\r\n").0, 200);
        assert!(c.closed());
    }

    #[test]
    fn version_and_info_are_json_docker_reads() {
        let mut c = Client::new();
        let (_, headers, body) = c.ask(&get("/version"));
        assert!(headers.contains(&("content-type".into(), "application/json".into())));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ApiVersion"], "1.47");
        assert_eq!(v["MinAPIVersion"], "1.40");
        assert_eq!(v["Os"], "linux");
        let (status, _, body) = c.ask(&get("/info?x=1"));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!((status, v["OSType"].as_str()), (200, Some("linux")));
        assert!(v["NCPU"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn a_version_prefix_is_checked_against_what_kith_speaks() {
        let mut c = Client::new();
        for path in ["/v1.47/version", "/v1.40/info", "/v1.44/_ping"] {
            assert_eq!(c.ask(&get(path)).0, 200, "{path}");
        }
        // /_ping answers a client of any version.
        assert_eq!(c.ask(&get("/v1.99/_ping")).0, 200);
        let (status, _, body) = c.ask(&get("/v1.48/version"));
        assert_eq!(status, 400);
        assert!(
            body.contains("client version 1.48 is too new. Maximum supported API version is 1.47"),
            "{body}"
        );
        let (status, _, body) = c.ask(&get("/v1.39/info"));
        assert_eq!(status, 400);
        assert!(
            body.contains("too old. Minimum supported API version is 1.40"),
            "{body}"
        );
        // Too old or too new is the same for an endpoint kith does not have.
        assert_eq!(c.ask(&get("/v0.9/containers/json")).0, 400);
        // Not a version prefix: just a path nobody serves.
        assert_eq!(c.ask(&get("/v1/info")).0, 501);
        assert_eq!(c.ask(&get("/vx.y/info")).0, 501);
    }

    #[test]
    fn anything_else_is_501_with_a_json_message_and_the_connection_goes_on() {
        let mut c = Client::new();
        for raw in [
            get("/containers/json"),
            get("/v1.47/images/json"),
            "POST /version HTTP/1.1\r\n\r\n".into(),
            "DELETE /_ping HTTP/1.1\r\n\r\n".into(),
            // A body is read and dropped, so the next request on the connection is not garbled by it.
            "POST /containers/create HTTP/1.1\r\nContent-Length: 11\r\n\r\n{\"Image\":1}".into(),
        ] {
            let (status, headers, body) = c.ask(&raw);
            assert_eq!(status, 501, "{raw}");
            assert!(headers.contains(&("content-type".into(), "application/json".into())));
            let v: Value = serde_json::from_str(&body).unwrap();
            assert!(v["message"].as_str().unwrap().contains("not supported"), "{body}");
        }
        assert_eq!(c.ask(&get("/_ping")).0, 200);
    }

    #[test]
    fn a_chunked_body_is_501_and_the_connection_closes() {
        let mut c = Client::new();
        let (status, _, body) =
            c.ask("POST /containers/create HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
        assert_eq!(status, 501);
        assert!(body.contains("chunked"), "{body}");
        assert!(c.closed());
    }

    #[test]
    fn requests_over_a_cap_or_malformed_are_refused_and_closed() {
        let cases = [
            (
                format!("GET /_ping HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD)),
                431,
            ),
            (
                format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1),
                413,
            ),
            ("POST /x HTTP/1.1\r\nContent-Length: -1\r\n\r\n".into(), 400),
            (
                "POST /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n".into(),
                400,
            ),
            ("GET /_ping\r\n\r\n".into(), 400),
            ("GET /_ping HTTP/2\r\n\r\n".into(), 400),
            ("GET /_ping HTTP/1.1\r\nNo colon\r\n\r\n".into(), 400),
            ("GET /_ping HTTP/1.1\r\nContent-Length : 0\r\n\r\n".into(), 400),
        ];
        for (raw, want) in cases {
            let mut c = Client::new();
            let (status, _, body) = c.ask(&raw);
            assert_eq!(status, want, "{}", &raw[..raw.len().min(60)]);
            assert!(serde_json::from_str::<Value>(&body).unwrap()["message"].is_string());
            assert!(c.closed());
        }
    }

    #[test]
    fn a_connection_that_stops_mid_request_is_closed_not_waited_on() {
        let mut c = Client::new();
        c.0.get_mut().write_all(b"GET /_ping HTTP/1.1\r\nHost: ki").unwrap();
        c.0.get_mut().shutdown(std::net::Shutdown::Write).unwrap();
        assert!(c.closed());
    }

    #[test]
    fn the_connection_cap_is_held_and_given_back() {
        let live = Arc::new(AtomicUsize::new(0));
        let slots: Vec<_> = (0..3).map(|_| Slot::take(&live, 3).unwrap()).collect();
        assert!(Slot::take(&live, 3).is_none());
        assert_eq!(live.load(Ordering::SeqCst), 3);
        drop(slots);
        assert!(Slot::take(&live, 3).is_some());
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("kith-docker-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_socket_is_0600_replaces_a_dead_one_and_leaves_nothing_beside_it() {
        let dir = scratch("listen");
        let path = dir.join("docker.sock");
        let first = listen(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["docker.sock"]);
        // One that is being served is not taken over ...
        assert_eq!(listen(&path).unwrap_err().kind(), io::ErrorKind::AddrInUse);
        // ... one nobody listens on any more is.
        drop(first);
        let second = listen(&path).unwrap();
        std::thread::spawn(move || serve_with(second, None));
        let mut c = Client(BufReader::new(UnixStream::connect(&path).unwrap()));
        assert_eq!(c.ask(&get("/_ping")).0, 200);
        // A file that is not a socket is never replaced.
        let file = dir.join("plain");
        std::fs::write(&file, "x").unwrap();
        assert_eq!(listen(&file).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "x");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Feed `bytes` to `handle` one every 40 ms (16 s in all); how long until it hung up (None: it
    /// never did in 30 s). The deadline is 1.5 s and the test allows 12: a loaded host cannot flake it.
    fn trickle(head: &'static [u8], rest: &'static [u8]) -> Option<Duration> {
        let (client, server) = UnixStream::pair().unwrap();
        std::thread::spawn(move || handle(server, Duration::from_millis(1500), Duration::from_millis(1500), None));
        let start = Instant::now();
        let mut writer = client.try_clone().unwrap();
        std::thread::spawn(move || {
            let _ = writer.write_all(head);
            for b in rest {
                if writer.write_all(&[*b]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let mut client = client;
        client.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut sink = Vec::new();
        client.read_to_end(&mut sink).ok().map(|_| start.elapsed())
    }

    #[test]
    fn a_head_or_a_body_that_trickles_in_is_cut_off_at_its_deadline() {
        // A head: every read arrives in time, the head as a whole does not.
        let cut = trickle(b"GET /_ping HTTP/1.1\r\nX-Slow: ", &[b'a'; 400]).expect("a slow head was never cut");
        assert!(cut < Duration::from_secs(12), "cut after {cut:?}");
        // A body.
        let cut = trickle(b"POST /x HTTP/1.1\r\nContent-Length: 1000\r\n\r\n", &[b'a'; 400])
            .expect("a slow body was never cut");
        assert!(cut < Duration::from_secs(12), "cut after {cut:?}");
    }

    #[test]
    fn an_idle_keep_alive_is_not_on_the_head_clock() {
        let (client, server) = UnixStream::pair().unwrap();
        std::thread::spawn(move || handle(server, Duration::from_millis(300), Duration::from_millis(300), None));
        let mut c = Client(BufReader::new(client));
        assert_eq!(c.ask(&get("/_ping")).0, 200);
        // Longer than the head deadline, with no byte in flight: the next request still works.
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(c.ask(&get("/_ping")).0, 200);
    }

    #[test]
    fn a_too_long_socket_path_says_so_and_any_other_connect_error_is_returned() {
        let dir = scratch("long");
        let long = dir.join("x".repeat(100)).join("docker.sock");
        let err = listen(&long).unwrap_err();
        assert!(err.to_string().contains("at most 107"), "{err}");
        assert!(!dir.join("x".repeat(100)).join("docker.sock").exists());
        // A socket this user cannot connect to is not "stale".
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("docker.sock");
        let held = listen(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        // (root connects regardless; there the socket is simply live.)
        let kind = listen(&path).unwrap_err().kind();
        assert!(
            matches!(kind, io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse),
            "{kind:?}"
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_planted_private_name_is_not_followed_and_a_shared_parent_is_refused() {
        let dir = scratch("planted");
        let (elsewhere, path) = (dir.join("elsewhere"), dir.join("docker.sock"));
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("s"), "keep").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // The name the first version made: a stranger's symlink there led to a file of ours.
        std::os::unix::fs::symlink(&elsewhere, dir.join(format!(".kd-{}", std::process::id()))).unwrap();
        let listener = listen(&path).unwrap();
        assert_eq!(std::fs::read_to_string(elsewhere.join("s")).unwrap(), "keep");
        drop(listener);
        // A directory others can write in (and not sticky) is no place for it.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = listen(&dir.join("other.sock")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(!dir.join("other.sock").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
