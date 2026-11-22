//! A VM's live migration between two nodes (T-1135, slice C1): kithd carries the stream QEMU writes at the
//! source across the authenticated node hop (`/v1/pod-hop`, `Spec::Migrate`, nodes only) to the QEMU that
//! waits for it at the target, and drives both QEMUs over QMP (`qmp.rs`). A migration that fails, is
//! cancelled or runs too long leaves the source running and quits the target.
//!
//! QEMU's `migrate-incoming` listens and `migrate` connects, so each kithd meets its QEMU the other way
//! round: the source's binds a socket in the replica's private directory for QEMU to connect to, the
//! target's connects to the socket QEMU listens at.
//!
//! ponytail: nothing calls `migrate_out` yet (slice C2 picks the node and switches the placement after
//! it), and it takes the pod's name to be the same on both nodes (a replica's name is its owner's).
#![allow(dead_code)]

use crate::Shared;
use crate::access::Caller;
use crate::pod_exec::{self, Spec};
use crate::qmp::{self, Qmp};
use crate::view::Upstream;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout};

/// The time one QMP call has (a connection is made for each: QEMU serves one client at a time).
const CALL: Duration = Duration::from_secs(10);
/// The sockets a migration is carried over, in the replica's directory: where the target's QEMU listens,
/// and where the source's kithd does.
const INCOMING: &str = "migrate-in.sock";
const OUT: &str = "migrate-out.sock";
/// The longest a socket's path may be (the kernel's limit is a little over 100 bytes).
const PATH_MAX: usize = 100;
/// The longest the machine may be stopped for the last of its memory.
const DOWNTIME_MS: u64 = 300;
/// How long the target waits for the source's end of the hop after it said yes.
const UPGRADE_WAIT: Duration = Duration::from_secs(15);

/// The clock of one migration: how often progress is read, how long it may take in all, and how long the
/// stream is given to drain once one end of it is done.
#[derive(Clone, Copy)]
pub(crate) struct Pace {
    pub tick: Duration,
    pub cap: Duration,
    pub end: Duration,
}

impl Pace {
    // ponytail: one cap for every machine (30 min); size it by memory and the link once a move has been seen to run.
    pub(crate) const LIVE: Pace = Pace {
        tick: Duration::from_millis(500),
        cap: Duration::from_secs(30 * 60),
        end: Duration::from_secs(10),
    };
}

/// The machines (by control socket) a migration is going into or out of here: one at a time each, or a second
/// hop would quit the first one's target.
static BUSY: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

struct Busy(PathBuf);

impl Busy {
    fn take(path: &Path) -> Option<Busy> {
        let mut busy = BUSY.lock().unwrap_or_else(|e| e.into_inner());
        if busy.iter().any(|held| held == path) {
            return None;
        }
        busy.push(path.to_path_buf());
        Some(Busy(path.to_path_buf()))
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|held| *held != self.0);
    }
}

/// `call` on a fresh connection to the QEMU at `path` (on a blocking thread: the client is blocking).
async fn ask<T: Send + 'static>(
    path: &Path,
    call: impl FnOnce(&mut Qmp) -> Result<T, qmp::Error> + Send + 'static,
) -> Result<T, String> {
    let path = path.to_path_buf();
    let done = tokio::task::spawn_blocking(move || call(&mut Qmp::connect(&path, CALL, CALL * 3)?));
    done.await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())
}

/// The private directory of the replica `pod` of `namespace` on this node. The names come from another node: they
/// are checked to be a resource's (no `/`, `..` or `_`), and nothing is made here.
fn replica_dir(shared: &Shared, namespace: &str, pod: &str) -> Result<PathBuf, (StatusCode, String)> {
    let name = |text: &str| {
        !text.is_empty()
            && text.len() <= 63
            && !text.contains("..")
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    };
    if !name(namespace) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("namespace {namespace:?} is no namespace"),
        ));
    }
    let Some((holder, owner, replica)) = crate::kube::pod_owner(pod).filter(|(_, owner, _)| name(owner)) else {
        return Err((StatusCode::NOT_FOUND, format!("pod {namespace}/{pod} is not found")));
    };
    let id = crate::controller::pod_of(&format!("{holder}/{namespace}/{owner}"), replica);
    let state = shared.logs.parent().unwrap_or(&shared.logs);
    let dir = state.join(crate::files::REPLICAS).join(id);
    if dir.as_os_str().len() + 1 + OUT.len().max(INCOMING.len()) > PATH_MAX {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "the state directory's path is too long for a socket in {}",
                dir.display()
            ),
        ));
    }
    Ok(dir)
}

/// Carries bytes both ways between `a` and `b` until one side is done (EOF, or an error): what it sent is
/// delivered and the other side is told (its write end is shut), and the other direction has `grace` to finish
/// before it is let go. The first error is the result.
pub(crate) async fn relay<A, B>(a: A, b: B, grace: Duration) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let ((mut a_read, mut a_write), (mut b_read, mut b_write)) = (tokio::io::split(a), tokio::io::split(b));
    let up = async {
        let carried = tokio::io::copy(&mut a_read, &mut b_write).await;
        let _ = b_write.shutdown().await;
        carried
    };
    let down = async {
        let carried = tokio::io::copy(&mut b_read, &mut a_write).await;
        let _ = a_write.shutdown().await;
        carried
    };
    tokio::pin!(up, down);
    let first = tokio::select! {
        done = &mut up => { let _ = timeout(grace, &mut down).await; done }
        done = &mut down => { let _ = timeout(grace, &mut up).await; done }
    };
    // (The one that did not end in time is dropped with the sockets: its side sees the end.)
    first.map(drop)
}

/// Quit the QEMU at `path` (what a migration into it that did not happen leaves), and say so.
async fn quit(path: &Path, why: &str) {
    eprintln!("kithd: migration into {}: {why}; quitting it", path.display());
    if let Err(e) = ask(path, |qmp| qmp.quit()).await {
        eprintln!("kithd: quit {}: {e}", path.display());
    }
}

/// The target's: the QEMU at `qmp_path` must be waiting for a migration (`-incoming defer`); it is told to
/// listen at a socket of its replica's directory, and the connection to it is given.
async fn incoming(qmp_path: &Path) -> Result<UnixStream, (StatusCode, String)> {
    let down = |what: &str, e: String| (StatusCode::BAD_GATEWAY, format!("{what}: {e}"));
    let state = ask(qmp_path, |qmp| qmp.status())
        .await
        .map_err(|e| down("query-status", e))?;
    if state.state != "inmigrate" {
        let why = format!("the machine is {}, not waiting for a migration", state.state);
        return Err((StatusCode::CONFLICT, why));
    }
    let sock = qmp_path.with_file_name(INCOMING);
    // (Ours to remove: the directory is the replica's own, and a QEMU that listens there makes it new.)
    let _ = std::fs::remove_file(&sock);
    let uri = format!("unix:{}", sock.display());
    ask(qmp_path, move |qmp| qmp.migrate_incoming(&uri))
        .await
        .map_err(|e| down("migrate-incoming", e))?;
    let reached = async {
        loop {
            match UnixStream::connect(&sock).await {
                Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused) => {
                    sleep(Duration::from_millis(20)).await;
                }
                other => return other,
            }
        }
    };
    match timeout(CALL, reached).await {
        Ok(Ok(stream)) => Ok(stream),
        failed => {
            let e = failed.map_or_else(
                |_| "timed out".to_string(),
                |r| r.err().map(|e| e.to_string()).unwrap_or_default(),
            );
            quit(qmp_path, &format!("its socket is out of reach: {e}")).await;
            Err(down("migrate-incoming's socket", e))
        }
    }
}

/// The target's, once it listens: the stream between the source (`near`, the other end of the hop) and the
/// QEMU is carried, and B's progress is read until it is `completed` (the machine is then B's to start: the
/// cutover is slice C2's). Any other end (QEMU says failed, a QMP call fails, the time is up, kithd is stopping,
/// the stream ended with nothing completed) quits the QEMU.
async fn finish<S>(
    qmp_path: PathBuf,
    qemu: UnixStream,
    near: impl Future<Output = io::Result<S>> + Send + 'static,
    pace: Pace,
    mut stop: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let relaying = tokio::spawn(async move { relay(qemu, near.await?, pace.end).await });
    let (start, mut ended) = (Instant::now(), None);
    let why = loop {
        tokio::select! {
            _ = sleep(pace.tick) => {}
            _ = stop.changed() => break "kithd is stopping".to_string(),
        }
        if start.elapsed() > pace.cap {
            break format!("not finished in {} s", pace.cap.as_secs());
        }
        match ask(&qmp_path, |qmp| qmp.migration()).await {
            Ok(got) if got.status == "completed" => return,
            Ok(got) if got.status == "failed" => break format!("failed: {}", got.error.unwrap_or_default()),
            Ok(_) => {}
            Err(e) => break e,
        }
        // (The stream is over and QEMU has had `end` to say it got all of it.)
        if relaying.is_finished() && ended.get_or_insert_with(Instant::now).elapsed() > pace.end {
            break "the stream ended before the migration did".to_string();
        }
    };
    relaying.abort();
    quit(&qmp_path, &why).await;
}

/// The far end of the hop, on the target: the gate's checks, QEMU told to listen, and a task that carries the
/// stream (the hop is answered `101` first) and quits QEMU if the migration does not complete.
async fn receive(
    shared: &Arc<Shared>,
    namespace: &str,
    pod: &str,
    upgrade: hyper::upgrade::OnUpgrade,
) -> Result<(), (StatusCode, String)> {
    let qmp_path = replica_dir(shared, namespace, pod)?.join(crate::vm::CONTROL);
    if !std::fs::symlink_metadata(&qmp_path).is_ok_and(|meta| meta.file_type().is_socket()) {
        let why = format!("pod {namespace}/{pod} has no control socket here: it is no VM of this node");
        return Err((StatusCode::NOT_FOUND, why));
    }
    let Some(busy) = Busy::take(&qmp_path) else {
        return Err((
            StatusCode::CONFLICT,
            "a migration into this machine is already going".into(),
        ));
    };
    let qemu = incoming(&qmp_path).await?;
    let stop = shared.stop.subscribe();
    tokio::spawn(async move {
        let _busy = busy;
        let near = async {
            match timeout(UPGRADE_WAIT, upgrade).await {
                Ok(Ok(upgraded)) => Ok(TokioIo::new(upgraded)),
                Ok(Err(e)) => Err(io::Error::other(e)),
                Err(_) => Err(io::ErrorKind::TimedOut.into()),
            }
        };
        finish(qmp_path, qemu, near, Pace::LIVE, stop).await;
    });
    Ok(())
}

/// `Spec::Migrate` of the node hop, for `from` (a node: the certificate is the gate, checked by the caller).
pub(crate) async fn hop(
    shared: &Arc<Shared>,
    from: &str,
    namespace: &str,
    pod: &str,
    upgrade: hyper::upgrade::OnUpgrade,
) -> Response {
    let done = receive(shared, namespace, pod, upgrade).await;
    let outcome = done.as_ref().map(|_| ()).map_err(|(_, why)| why.clone());
    shared.audit.record(
        &Caller::Node(from.to_string()),
        "migrate",
        vec![format!("pod {namespace}/{pod}")],
        outcome,
    );
    match done {
        Ok(()) => pod_exec::switching(),
        Err((status, why)) => crate::cluster::refuse(status, why).into_response(),
    }
}

/// The source's: A's QEMU is told to send to a socket kithd listens at, and what it sends crosses `far` (the hop
/// to the target); progress is read until `completed` (the bytes sent are the result). A migration that fails, is
/// cancelled (`cancel` turns true), or runs past `pace.cap` is stopped and A is left as it was: running again if it
/// was running.
async fn near<S>(
    qmp_path: &Path,
    sock: &Path,
    far: S,
    pace: Pace,
    mut cancel: watch::Receiver<bool>,
) -> Result<u64, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let was = ask(qmp_path, |qmp| qmp.status()).await?.running;
    let mut relaying = None;
    let outcome = 'go: {
        let started = async {
            ask(qmp_path, |qmp| {
                qmp.set_capabilities(&[("events", true), ("auto-converge", true)])
            })
            .await?;
            ask(qmp_path, |qmp| qmp.set_downtime_limit(DOWNTIME_MS)).await?;
            let _ = std::fs::remove_file(sock);
            let listener = UnixListener::bind(sock).map_err(|e| format!("{}: {e}", sock.display()))?;
            let uri = format!("unix:{}", sock.display());
            ask(qmp_path, move |qmp| qmp.migrate(&uri)).await?;
            Ok::<_, String>(listener)
        };
        let listener = match started.await {
            Ok(listener) => listener,
            Err(e) => break 'go Err(e),
        };
        relaying = Some(tokio::spawn(async move {
            let (qemu, _) = listener.accept().await?;
            relay(qemu, far, pace.end).await
        }));
        let (start, mut sent) = (Instant::now(), 0);
        loop {
            let stopped = *cancel.borrow()
                || tokio::select! {
                    _ = sleep(pace.tick) => false,
                    gone = cancel.changed() => gone.is_err() || *cancel.borrow(),
                };
            if stopped {
                break 'go Err("cancelled".to_string());
            }
            if start.elapsed() > pace.cap {
                break 'go Err(format!("not finished in {} s", pace.cap.as_secs()));
            }
            let got = match ask(qmp_path, |qmp| qmp.migration()).await {
                Ok(got) => got,
                Err(e) => break 'go Err(e),
            };
            sent = got.ram.map_or(sent, |(transferred, ..)| transferred);
            match got.status.as_str() {
                "completed" => break 'go Ok(sent),
                "failed" => break 'go Err(format!("failed: {}", got.error.unwrap_or_default())),
                "cancelled" => break 'go Err("cancelled".to_string()),
                _ => {}
            }
        }
    };
    let _ = std::fs::remove_file(sock);
    match (outcome, relaying) {
        (Ok(sent), Some(mut carrying)) => {
            // (The tail of the stream is still on its way: it is given `end` to drain.)
            if timeout(pace.end, &mut carrying).await.is_err() {
                carrying.abort();
            }
            Ok(sent)
        }
        (Ok(sent), None) => Ok(sent),
        (Err(why), carrying) => {
            if let Some(carrying) = carrying {
                carrying.abort();
            }
            Err(resume(qmp_path, was, why).await)
        }
    }
}

/// A failed migration's end on the source: the migration stopped if it still is one, and the machine running
/// again if it was running before (`cont` on a running machine is no change). `why` with what could not be done.
async fn resume(qmp_path: &Path, was: bool, why: String) -> String {
    let done = ask(qmp_path, move |qmp| {
        // (Not going, or over: a refusal is no news.)
        let _ = qmp.migrate_cancel();
        if was { qmp.cont() } else { Ok(()) }
    })
    .await;
    match done {
        Ok(()) => why,
        Err(e) => format!("{why}; the machine could not be resumed: {e}"),
    }
}

/// Move the VM replica `pod` of `namespace` from this node to `node` (`there`): the target's gate is asked over the
/// hop, then the migration is driven here. The bytes sent when it completed, or why it did not (the machine here
/// is running as before).
pub(crate) async fn migrate_out(
    shared: &Arc<Shared>,
    namespace: &str,
    pod: &str,
    node: &str,
    there: &Upstream,
) -> Result<u64, String> {
    let dir = replica_dir(shared, namespace, pod).map_err(|(_, why)| why)?;
    let qmp_path = dir.join(crate::vm::CONTROL);
    let Some(_busy) = Busy::take(&qmp_path) else {
        return Err("a migration of this machine is already going".into());
    };
    let Some(cluster) = &shared.cluster else {
        return Err("this kithd is not part of a cluster".into());
    };
    let me = Caller::Node(cluster.me.name.clone());
    let far = pod_exec::send(shared, &me, namespace, pod, Spec::Migrate, node, there)
        .await
        .map_err(|failed| failed.message)?;
    near(&qmp_path, &dir.join(OUT), far, Pace::LIVE, shared.stop.subscribe()).await
}

#[cfg(test)]
mod fakes {
    //! A fake QEMU: a QMP socket in a directory of its own, answering what a migration asks, and
    //! (source) sending a payload to the socket it is told to `migrate` to, or (target) listening at
    //! the socket it is told to `migrate-incoming` at and reading what arrives.
    use serde_json::{Value, json};
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const GREETING: &str = r#"{"QMP":{"version":{"qemu":{"major":9,"minor":0,"micro":0}},"capabilities":["oob"]}}"#;

    /// How a source's migration ends.
    #[derive(Clone, Copy)]
    pub enum End {
        Complete,
        /// The stream breaks after a little, and QEMU says it failed with the machine stopped.
        Die,
        /// It never ends: only `migrate_cancel` does.
        Hang,
    }

    #[derive(Clone)]
    pub enum Role {
        Source { payload: Vec<u8>, end: End },
        Target { expect: usize },
    }

    pub struct Sim {
        /// Every command it was given (but the handshake's), in order.
        pub calls: Vec<String>,
        pub running: bool,
        pub state: &'static str,
        pub migration: &'static str,
        pub error: Option<String>,
        pub sent: u64,
        pub received: Vec<u8>,
        /// A command it answers with an error.
        pub refuse: Option<&'static str>,
    }

    pub type Machine = Arc<Mutex<Sim>>;

    pub fn machine(running: bool, state: &'static str) -> Machine {
        Arc::new(Mutex::new(Sim {
            calls: Vec::new(),
            running,
            state,
            migration: "none",
            error: None,
            sent: 0,
            received: Vec::new(),
            refuse: None,
        }))
    }

    pub fn calls(machine: &Machine) -> Vec<String> {
        machine.lock().unwrap().calls.clone()
    }

    /// A private directory (mode 0700) for the test `name`.
    pub fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kithd-vm-migrate-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o700)).unwrap();
        dir
    }

    pub fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    /// Waits (up to 10 s) for `what` to hold.
    pub async fn until(what: &str, mut holds: impl FnMut() -> bool) {
        for _ in 0..500 {
            if holds() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("never: {what}");
    }

    /// Serves `machine` at `dir`/qmp.sock; the socket's path.
    pub fn serve(dir: &Path, machine: Machine, role: Role) -> PathBuf {
        let path = dir.join(crate::vm::CONTROL);
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (machine, role) = (machine.clone(), role.clone());
                std::thread::spawn(move || talk(stream, &machine, &role));
            }
        });
        path
    }

    fn talk(mut stream: UnixStream, machine: &Machine, role: &Role) {
        writeln!(stream, "{GREETING}").unwrap();
        let (mut buf, mut chunk) = (Vec::new(), [0u8; 1024]);
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            while let Some(at) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=at).collect();
                let said: Value = serde_json::from_slice(&line).unwrap();
                let command = said["execute"].as_str().unwrap();
                let reply = match command_result(machine, role, command, &said["arguments"]) {
                    Ok(value) => json!({ "return": value, "id": said["id"] }),
                    Err(desc) => json!({ "error": { "class": "GenericError", "desc": desc }, "id": said["id"] }),
                };
                if writeln!(stream, "{reply}").is_err() {
                    return;
                }
            }
        }
    }

    fn command_result(machine: &Machine, role: &Role, command: &str, arguments: &Value) -> Result<Value, String> {
        let mut sim = machine.lock().unwrap();
        if command != "qmp_capabilities" {
            sim.calls.push(command.to_string());
        }
        if sim.refuse == Some(command) {
            return Err(format!("{command} refused"));
        }
        let socket = || PathBuf::from(arguments["uri"].as_str().unwrap().strip_prefix("unix:").unwrap());
        match (command, role) {
            ("query-status", _) => Ok(json!({ "running": sim.running, "status": sim.state })),
            ("cont", _) => {
                (sim.running, sim.state) = (true, "running");
                Ok(json!({}))
            }
            ("migrate_cancel", _) => {
                // (The machine stays stopped: QEMU would start it, and this one makes the caller `cont`.)
                if sim.migration == "active" {
                    sim.migration = "cancelled";
                }
                Ok(json!({}))
            }
            ("query-migrate", _) => {
                let mut said = json!({ "status": sim.migration });
                if sim.migration != "none" {
                    said["ram"] = json!({ "transferred": sim.sent, "remaining": 1, "total": 4 << 20 });
                }
                if let Some(error) = &sim.error {
                    said["error-desc"] = json!(error);
                }
                Ok(if sim.migration == "none" { json!({}) } else { said })
            }
            ("migrate", Role::Source { payload, end }) => {
                sim.migration = "active";
                let (machine, payload, end, socket) = (machine.clone(), payload.clone(), *end, socket());
                std::thread::spawn(move || send(&machine, &payload, end, &socket));
                Ok(json!({}))
            }
            ("migrate-incoming", Role::Target { expect }) => {
                let listener = UnixListener::bind(socket()).map_err(|e| e.to_string())?;
                sim.migration = "active";
                let (machine, expect) = (machine.clone(), *expect);
                std::thread::spawn(move || receive(&machine, &listener, expect));
                Ok(json!({}))
            }
            _ => Ok(json!({})),
        }
    }

    fn send(machine: &Machine, payload: &[u8], end: End, socket: &Path) {
        let mut stream = UnixStream::connect(socket).unwrap();
        let cut = match end {
            End::Complete => payload.len(),
            End::Die | End::Hang => 1024,
        };
        let _ = stream.write_all(&payload[..cut]);
        match end {
            End::Complete => {
                let mut sim = machine.lock().unwrap();
                (sim.sent, sim.migration, sim.running, sim.state) =
                    (payload.len() as u64, "completed", false, "postmigrate");
            }
            End::Die => {
                drop(stream);
                let mut sim = machine.lock().unwrap();
                (sim.migration, sim.error, sim.running) = ("failed", Some("boom".into()), false);
            }
            End::Hang => {
                while machine.lock().unwrap().migration == "active" {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn receive(machine: &Machine, listener: &UnixListener, expect: usize) {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let mut got = Vec::new();
        let _ = stream.read_to_end(&mut got);
        let mut sim = machine.lock().unwrap();
        sim.migration = if got.len() == expect { "completed" } else { "failed" };
        sim.received = got;
    }
}

mod relay {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const MIB4: usize = 4 << 20;

    /// Several MiB each way cross the relay unchanged, at once; one side closing ends it.
    #[tokio::test]
    async fn relay_carries_several_mib_unchanged_in_both_directions() {
        let (mut left, a) = tokio::io::duplex(1 << 16);
        let (b, mut right) = tokio::io::duplex(1 << 16);
        let relaying = tokio::spawn(relay(a, b, Duration::from_millis(200)));
        let (up, down) = (fakes::payload(MIB4), fakes::payload(MIB4 + 7));
        let (up_in, down_in) = (up.clone(), down.clone());
        let (mut left_r, mut left_w) = tokio::io::split(&mut left);
        let (mut right_r, mut right_w) = tokio::io::split(&mut right);
        let (mut got_up, mut got_down) = (Vec::new(), Vec::new());
        let sent = async {
            tokio::join!(
                async {
                    left_w.write_all(&up_in).await.unwrap();
                    left_w.shutdown().await.unwrap();
                },
                async {
                    right_w.write_all(&down_in).await.unwrap();
                    right_w.shutdown().await.unwrap();
                },
                async { right_r.read_to_end(&mut got_up).await.unwrap() },
                async { left_r.read_to_end(&mut got_down).await.unwrap() },
            )
        };
        tokio::time::timeout(Duration::from_secs(20), sent)
            .await
            .expect("the relay carried it");
        assert!(got_up == up, "left to right is changed");
        assert!(got_down == down, "right to left is changed");
        tokio::time::timeout(Duration::from_secs(5), relaying)
            .await
            .expect("the relay ended")
            .unwrap()
            .unwrap();
    }

    /// Either side hanging up ends the relay (the other, still open, is given the grace and then let go),
    /// and what the closed side had sent is delivered first.
    #[tokio::test]
    async fn relay_ends_cleanly_when_either_side_closes() {
        for closing_left in [true, false] {
            let (mut left, a) = tokio::io::duplex(1 << 12);
            let (b, mut right) = tokio::io::duplex(1 << 12);
            let relaying = tokio::spawn(relay(a, b, Duration::from_millis(100)));
            let (closes, other) = if closing_left {
                (&mut left, &mut right)
            } else {
                (&mut right, &mut left)
            };
            closes.write_all(b"last words").await.unwrap();
            closes.shutdown().await.unwrap();
            let mut heard = vec![0u8; 10];
            other.read_exact(&mut heard).await.unwrap();
            assert_eq!(heard, b"last words");
            // (The side that did not close stays open and says nothing.)
            let ended = tokio::time::timeout(Duration::from_secs(5), relaying).await;
            assert!(
                ended.expect("the relay ends").unwrap().is_ok(),
                "left closing: {closing_left}"
            );
            let mut rest = Vec::new();
            assert_eq!(
                other.read_to_end(&mut rest).await.unwrap(),
                0,
                "the open side sees the end"
            );
        }
    }
}

mod drive {
    use super::fakes::*;
    use super::*;
    use std::time::Duration;
    use tokio::sync::watch;

    struct Rig {
        a: Machine,
        b: Machine,
        data: Vec<u8>,
        result: Result<u64, String>,
    }

    /// Two fake QEMUs and one migration between them: B's end (`incoming`, `finish`) and A's (`near`) joined
    /// by a pipe where the node hop is.
    async fn migrate(
        name: &str,
        end: End,
        cap_ms: u64,
        cancel_after_ms: Option<u64>,
        tweak: impl FnOnce(&mut Sim),
    ) -> Rig {
        let data = payload(3 << 20);
        let (a_dir, b_dir) = (dir(&format!("{name}-a")), dir(&format!("{name}-b")));
        let (a, b) = (machine(true, "running"), machine(false, "inmigrate"));
        tweak(&mut a.lock().unwrap());
        let a_qmp = serve(
            &a_dir,
            a.clone(),
            Role::Source {
                payload: data.clone(),
                end,
            },
        );
        let b_qmp = serve(&b_dir, b.clone(), Role::Target { expect: data.len() });
        let pace = Pace {
            tick: Duration::from_millis(20),
            cap: Duration::from_millis(cap_ms),
            end: Duration::from_millis(500),
        };
        let qemu = incoming(&b_qmp).await.unwrap();
        let (near_end, far_end) = tokio::io::duplex(1 << 16);
        let (_stop, stop_rx) = watch::channel(false);
        let b_side = tokio::spawn(finish(b_qmp, qemu, async move { Ok(far_end) }, pace, stop_rx));
        let (cancel, cancel_rx) = watch::channel(false);
        if let Some(ms) = cancel_after_ms {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                cancel.send(true).unwrap();
            });
        } else {
            std::mem::forget(cancel);
        }
        let result = near(&a_qmp, &a_dir.join("out.sock"), near_end, pace, cancel_rx).await;
        tokio::time::timeout(Duration::from_secs(10), b_side)
            .await
            .expect("B's end finished")
            .unwrap();
        Rig { a, b, data, result }
    }

    fn has(calls: &[String], command: &str) -> bool {
        calls.iter().any(|call| call == command)
    }

    /// The whole of it: B told to listen, A told to send, the capabilities and the downtime set, the progress
    /// read until completed, and the bytes of A's memory arrive at B as they left.
    #[tokio::test]
    async fn drive_moves_a_machine_from_one_fake_qemu_to_another() {
        let rig = migrate("done", End::Complete, 10_000, None, |_| {}).await;
        assert_eq!(rig.result, Ok(rig.data.len() as u64));
        let (a, b) = (calls(&rig.a), calls(&rig.b));
        for command in [
            "query-status",
            "migrate-set-capabilities",
            "migrate-set-parameters",
            "migrate",
            "query-migrate",
        ] {
            assert!(has(&a, command), "A was not told {command}: {a:?}");
        }
        assert!(has(&b, "migrate-incoming"), "{b:?}");
        assert!(
            rig.b.lock().unwrap().received == rig.data,
            "B got other bytes than A sent"
        );
        // Nothing is undone: A is left as the migration made it (stopped), for the cutover; B is not quit.
        assert!(!has(&a, "migrate_cancel") && !has(&a, "cont"), "{a:?}");
        assert!(!has(&b, "quit"), "{b:?}");
    }

    /// What a failed, cancelled or capped migration leaves: A running (`cont`, after a cancel), B quit.
    fn resumed(rig: &Rig) {
        let (a, b) = (calls(&rig.a), calls(&rig.b));
        assert!(has(&a, "migrate_cancel") && has(&a, "cont"), "A was not resumed: {a:?}");
        assert!(rig.a.lock().unwrap().running);
        assert!(has(&b, "quit"), "B was not quit: {b:?}");
    }

    #[tokio::test]
    async fn drive_a_failed_migration_resumes_a_and_quits_b() {
        let rig = migrate("failed", End::Die, 10_000, None, |_| {}).await;
        assert!(
            rig.result.as_ref().is_err_and(|why| why.contains("boom")),
            "{:?}",
            rig.result
        );
        resumed(&rig);
    }

    #[tokio::test]
    async fn drive_a_cancelled_migration_resumes_a_and_quits_b() {
        let rig = migrate("cancelled", End::Hang, 10_000, Some(200), |_| {}).await;
        assert!(
            rig.result.as_ref().is_err_and(|why| why.contains("cancelled")),
            "{:?}",
            rig.result
        );
        resumed(&rig);
    }

    #[tokio::test]
    async fn drive_a_migration_past_its_cap_resumes_a_and_quits_b() {
        let rig = migrate("capped", End::Hang, 300, None, |_| {}).await;
        assert!(
            rig.result.as_ref().is_err_and(|why| why.contains("not finished")),
            "{:?}",
            rig.result
        );
        resumed(&rig);
    }

    /// A that refuses `migrate` fails the move, and a machine that was not running is not started by it.
    #[tokio::test]
    async fn drive_a_machine_that_was_stopped_stays_stopped_when_the_move_fails() {
        let rig = migrate("stopped", End::Complete, 10_000, None, |a| {
            (a.running, a.state, a.refuse) = (false, "paused", Some("migrate"));
        })
        .await;
        assert!(
            rig.result.as_ref().is_err_and(|why| why.contains("refused")),
            "{:?}",
            rig.result
        );
        let (a, b) = (calls(&rig.a), calls(&rig.b));
        assert!(!has(&a, "cont") && !rig.a.lock().unwrap().running, "{a:?}");
        assert!(has(&b, "quit"), "{b:?}");
    }
}

mod hop {
    use super::fakes::*;
    use crate::access::Caller;
    use crate::api::run::tests::World;
    use crate::pod_exec::{self, Spec};
    use crate::view::Upstream;
    use tokio::io::AsyncWriteExt;

    /// The private directory of replica 0 of Workload `owner` in `default` on `shared`'s node.
    fn replica(shared: &crate::Shared, owner: &str) -> std::path::PathBuf {
        let state = shared.logs.parent().unwrap();
        let id = crate::controller::pod_of(&format!("Workload/default/{owner}"), 0);
        let dir = state.join(crate::files::REPLICAS).join(id);
        std::fs::create_dir_all(&dir).unwrap();
        for dir in [dir.parent().unwrap(), &dir] {
            std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        }
        dir
    }

    fn b_of(world: &World) -> Upstream {
        let state = world.a.store.lock().unwrap();
        Upstream::of(state.store.get("Node/b").unwrap()).unwrap()
    }

    async fn ask(world: &World, namespace: &str, pod: &str) -> Result<reqwest::Upgraded, String> {
        let a = Caller::Node("a".into());
        pod_exec::send(&world.a, &a, namespace, pod, Spec::Migrate, "b", &b_of(world))
            .await
            .map_err(|failed| failed.message)
    }

    /// A node's hop reaches the incoming socket of a VM replica waiting for its migration, B's QEMU is told to
    /// listen, and the stream written at A's end arrives there as it was written.
    #[tokio::test]
    async fn hop_carries_a_migration_stream_to_a_vm_replicas_incoming_socket() {
        let world = World::new("migrate-hop").await;
        let data = payload(2 << 20);
        let b = machine(false, "inmigrate");
        serve(&replica(&world.b, "vm"), b.clone(), Role::Target { expect: data.len() });
        let mut far = ask(&world, "default", "vm-0").await.expect("the hop is let through");
        far.write_all(&data).await.unwrap();
        far.shutdown().await.unwrap();
        until("B has the stream", || b.lock().unwrap().migration == "completed").await;
        assert!(b.lock().unwrap().received == data, "B got other bytes");
        assert!(calls(&b).contains(&"migrate-incoming".to_string()));
        let entries = world.b.audit.tail(10).unwrap();
        let entry = entries
            .iter()
            .find(|entry| entry["verb"] == "migrate")
            .expect("audited");
        assert_eq!(entry["who"], "node a");
        assert_eq!(entry["ok"], true);
    }

    #[tokio::test]
    async fn hop_refuses_what_is_no_node_and_what_is_no_vm_waiting_for_its_migration() {
        let world = World::new("migrate-refused").await;
        // A person's certificate is no node's.
        let alice = world.user("alice");
        let reply = alice
            .post(format!("https://127.0.0.1:{}/v1/pod-hop", world.b_port))
            .header("connection", "upgrade")
            .header("upgrade", "kith-pod-hop")
            .json(&serde_json::json!({"namespace": "default", "pod": "vm-0", "caller": "node a", "spec": "migrate"}))
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), 403);
        // A pod with no control socket here: not a VM of this node.
        let why = ask(&world, "default", "web-0").await.unwrap_err();
        assert!(why.contains("no control socket"), "{why}");
        // A machine that is running, not waiting for a migration: nothing is asked of it.
        let running = machine(true, "running");
        serve(&replica(&world.b, "run"), running.clone(), Role::Target { expect: 0 });
        let why = ask(&world, "default", "run-0").await.unwrap_err();
        assert!(why.contains("not waiting for a migration"), "{why}");
        assert!(
            calls(&running).iter().all(|call| call == "query-status"),
            "{:?}",
            calls(&running)
        );
        // Names that are no resource's are refused before they are a path.
        let why = ask(&world, "../x", "vm-0").await.unwrap_err();
        assert!(why.contains("namespace"), "{why}");
        let why = ask(&world, "default", "nonsense").await.unwrap_err();
        assert!(why.contains("not found"), "{why}");
    }

    #[tokio::test]
    async fn hop_refuses_a_second_migration_into_a_replica_that_has_one() {
        let world = World::new("migrate-busy").await;
        serve(
            &replica(&world.b, "vm"),
            machine(false, "inmigrate"),
            Role::Target { expect: 1 << 30 },
        );
        let _first = ask(&world, "default", "vm-0").await.expect("the first is let through");
        let why = ask(&world, "default", "vm-0").await.unwrap_err();
        assert!(why.contains("already"), "{why}");
    }
}
