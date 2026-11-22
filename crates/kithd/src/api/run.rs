//! Remote apps: `POST /v1/run` opens a byte tunnel to an app that runs on a node.
//!
//! ```text
//! POST /v1/run      {on, via?, argv}            -> 101, then bytes both ways   caller that may exec on Nodes
//! POST /v1/run-hop  {on, via?, argv, caller}    -> 101, then bytes both ways   nodes only
//! ```
//! `on` is a node's name, or `key=value[,key=value]` for the first ready Node (by name)
//! with those labels. The first node checks the caller (it may `exec` on `Node`, a
//! rule for the whole cluster), writes the audit entry and, when the app is to run elsewhere, passes
//! the tunnel to that node's `run-hop` over the cluster's mutual TLS: the hop is for
//! members only, so a client token cannot call it and skip the check, and the node it
//! arrives at asks its own store whether the caller the first node names may. The node that runs
//! the app starts `VIA --socket S server -- ARGV…` (VIA is `waypipe` unless said) with S
//! in a private directory, and joins S to the tunnel; the `kith` command runs
//! `VIA --socket L client` on its side. `argv` is an array end to end, never a shell line.

use super::{ApiError, permit};
use crate::Shared;
use crate::access::Caller;
use crate::cluster::{Peer, refuse};
use crate::pki::{self, Subject};
use crate::view::Upstream;
use axum::Extension;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use kith_api::Resource;
use kith_api::kinds::Verb;
use kith_api::store::Error;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::future::Future;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::sync::watch;

/// How long the app has to connect to its socket (the tests shorten it, and [`BODY`]).
const START: Duration = Duration::from_secs(if cfg!(test) { 8 } else { 30 });
/// How long the second node has to answer, and the caller to take the connection over.
const HOP: Duration = Duration::from_secs(15);
/// How long the caller has to send its ask: a few hundred bytes.
const BODY: Duration = Duration::from_secs(if cfg!(test) { 2 } else { 10 });
const PROTOCOL: &str = "kith-run";

#[derive(Serialize, Deserialize)]
pub struct Spec {
    pub on: String,
    pub via: Option<String>,
    pub argv: Vec<String>,
    /// On the hop only: who asked the first node.
    #[serde(default)]
    pub caller: String,
}

fn say(status: StatusCode, why: impl Display) -> Response {
    refuse(status, why).into_response()
}

fn invalid(why: String) -> ApiError {
    ApiError::Store(Error::Invalid(why))
}

/// The request's upgrade, and what it asks for. The body is read to its end before anything
/// is answered, which is what lets the connection be taken over afterwards.
async fn take(mut request: Request) -> Result<(Spec, OnUpgrade, axum::body::Bytes), (StatusCode, String)> {
    if request.headers().get(header::UPGRADE).is_none_or(|v| v != PROTOCOL) {
        return Err((StatusCode::BAD_REQUEST, format!("ask with `Upgrade: {PROTOCOL}`")));
    }
    let upgrade = hyper::upgrade::on(&mut request);
    // A body that stops half way is answered, not waited on for ever.
    let bytes = tokio::time::timeout(BODY, to_bytes(request.into_body(), 64 << 10))
        .await
        .map_err(|_| {
            (
                StatusCode::REQUEST_TIMEOUT,
                "the ask's body did not arrive in time".to_string(),
            )
        })?
        .map_err(|e| {
            // (Too long is 413; a body that broke on the way is the caller's, 400.)
            let long = std::error::Error::source(&e).is_some_and(|s| s.to_string().contains("length limit"));
            (
                if long {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                },
                e.to_string(),
            )
        })?;
    let spec: Spec = serde_json::from_slice(&bytes).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if spec.argv.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "argv names no program".into()));
    }
    // (A NUL cannot be in an argument or a path: starting the program would fail on it, late.)
    if spec.argv.iter().chain(&spec.via).any(|word| word.contains('\0')) {
        return Err((StatusCode::BAD_REQUEST, "argv and via cannot hold a NUL byte".into()));
    }
    Ok((spec, upgrade, bytes))
}

/// The node to run on, and where to reach it (`None`: this one). `on` is a node's name, or
/// `key=value[,key=value]`: the first Node, by name, that is ready and has all these labels.
// ponytail: labels by equality only; no set-based selectors, no choosing by load.
fn resolve(shared: &Shared, on: &str) -> Result<(String, Option<Upstream>), ApiError> {
    let me = shared.cluster.as_ref().map_or("local", |c| c.me.name.as_str());
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let ready = |node: &Resource| node.status.as_ref().is_some_and(|s| s["state"] == "ready");
    let node = if on.contains('=') {
        let wants = on.split(',').map(|pair| {
            pair.split_once('=')
                .ok_or_else(|| invalid(format!("{pair:?} in {on:?} is not key=value")))
        });
        let wants = wants.collect::<Result<Vec<_>, _>>()?;
        let has = |node: &Resource| {
            wants
                .iter()
                .all(|(k, v)| node.metadata.labels.get(*k).is_some_and(|l| l == v))
        };
        let mut nodes = state.store.list(Some("Node"));
        nodes
            .find(|node| ready(node) && has(node))
            .ok_or_else(|| ApiError::Store(Error::NotFound(format!("no ready Node has the labels {on}"))))?
    } else if on == me {
        return Ok((me.into(), None));
    } else {
        let node = state.store.get(&format!("Node/{on}"));
        let node = node.ok_or_else(|| ApiError::Store(Error::NotFound(format!("there is no node {on}"))))?;
        if !ready(node) {
            return Err(invalid(format!("node {on} is unreachable")));
        }
        node
    };
    let name = node.metadata.name.clone();
    if name == me {
        return Ok((name, None));
    }
    match Upstream::of(node) {
        Some(there) => Ok((name, Some(there))),
        None => Err(invalid(format!("node {name} has no address"))),
    }
}

fn audit(shared: &Shared, who: &impl Display, node: &str, spec: &Spec, outcome: Result<(), String>) {
    let via = spec.via.as_deref().unwrap_or("waypipe");
    let what = [format!("node {node}"), format!("via {via}")];
    shared.audit.record(
        who,
        "run",
        what.into_iter().chain(spec.argv.iter().cloned()).collect(),
        outcome,
    );
}

/// `POST /v1/run`: the first node. Checks the caller, writes it down, and runs the app
/// here or has the node it is for run it.
pub async fn run(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    request: Request,
) -> Response {
    // The app runs as kithd's user, outside any container: that is the run of the node, so it
    // takes a rule for the whole cluster (`exec` on `Node`, no namespaces), never one namespace's.
    // (Before the body is read: a caller that may not run anything makes kithd buffer nothing.)
    if let Err(refused) = permit(&shared, &caller, Verb::Exec, |_| vec![("Node".into(), None)]) {
        return refused.into_response();
    }
    let (spec, upgrade, _) = match take(request).await {
        Ok(taken) => taken,
        Err((status, why)) => return say(status, why),
    };
    let (node, there) = match resolve(&shared, &spec.on) {
        Ok(found) => found,
        Err(e) => return e.into_response(),
    };
    let Some(there) = there else {
        return start(&shared, &caller, &node, spec, upgrade);
    };
    forward(&shared, &caller, &node, &there, spec, upgrade).await
}

/// Passes the tunnel to the node `there`'s `run-hop`, as this node: that node, and no other at its address.
async fn forward(
    shared: &Arc<Shared>,
    caller: &Caller,
    node: &str,
    there: &Upstream,
    spec: Spec,
    upgrade: OnUpgrade,
) -> Response {
    let Some(cluster) = &shared.cluster else {
        return say(StatusCode::UNPROCESSABLE_ENTITY, "this kithd is not part of a cluster");
    };
    audit(shared, caller, node, &spec, Ok(()));
    let failed = |status, why: String| {
        audit(shared, caller, node, &spec, Err(why.clone()));
        say(status, why)
    };
    let hop = Spec {
        caller: caller.to_string(),
        on: spec.on.clone(),
        via: spec.via.clone(),
        argv: spec.argv.clone(),
    };
    let client = match cluster.to(there) {
        Ok(client) => client,
        Err(why) => return failed(StatusCode::BAD_GATEWAY, why),
    };
    let send = crate::access_sign::pass_on(client.post(format!("https://{}/v1/run-hop", there.address)))
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, PROTOCOL)
        .json(&hop)
        .send();
    let reply = match tokio::time::timeout(HOP, send).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(e)) => {
            return failed(
                StatusCode::BAD_GATEWAY,
                format!("node {node} did not answer: {}", crate::cluster::why(&e)),
            );
        }
        Err(_) => {
            return failed(
                StatusCode::GATEWAY_TIMEOUT,
                format!("node {node} did not answer in time"),
            );
        }
    };
    if reply.status() != StatusCode::SWITCHING_PROTOCOLS {
        let status = reply.status();
        let said = reply.text().await.unwrap_or_default();
        audit(
            shared,
            caller,
            node,
            &spec,
            Err(format!("node {node} said {status}: {said}")),
        );
        return (status, [(header::CONTENT_TYPE, "application/json")], said).into_response();
    }
    let Ok(Ok(far)) = tokio::time::timeout(HOP, reply.upgrade()).await else {
        return failed(StatusCode::BAD_GATEWAY, format!("node {node} did not give the tunnel"));
    };
    let stop = shared.stop.subscribe();
    switch(upgrade, move |near| join(stop, near, far))
}

/// `POST /v1/run-hop`: the node the app is for, asked by the first node (members only).
pub async fn hop(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: Request,
) -> Response {
    let Some(Subject::Node(from, ..)) = peer.subject else {
        return say(StatusCode::FORBIDDEN, "this is for the cluster's nodes");
    };
    let header = request
        .headers()
        .get(crate::access_sign::SIGNED)
        .map(|header| header.to_str().unwrap_or_default().to_string());
    let path = request
        .uri()
        .path_and_query()
        .map_or("/v1/run-hop", |path| path.as_str())
        .to_string();
    let (spec, upgrade, body) = match take(request).await {
        Ok(taken) => taken,
        Err((status, why)) => return say(status, why),
    };
    let me = shared
        .cluster
        .as_ref()
        .map_or("local", |c| c.me.name.as_str())
        .to_string();
    // The first node checked the caller, and so does this one, in its own store: it takes a
    // node's word for who asked, not for what they may do. (A worker that runs from a view has
    // no store to ask: there the control node's word is all there is, `access::passed`.)
    let Some(who) = Caller::named(&spec.caller) else {
        let why = format!("caller: {:?} is no caller a node passes on", spec.caller);
        return say(StatusCode::BAD_REQUEST, why);
    };
    // Under `signing: required` the node's word is not enough: the asker's signature is passed
    // on with it (docs/adr-taken-node.md).
    let asked = crate::access_sign::Asked {
        method: "POST",
        path: &path,
        body: &body,
    };
    if let Err(why) = crate::access_sign::hop(&shared, from.as_str(), header.as_deref(), &asked, Some(&who), false) {
        let who = crate::access::passed(&shared, from, who);
        audit(&shared, &who, &me, &spec, Err(why.clone()));
        return say(StatusCode::FORBIDDEN, why);
    }
    let who = crate::access::passed(&shared, from, who);
    if let Err(refused) = permit(&shared, &who, Verb::Exec, |_| vec![("Node".into(), None)]) {
        return refused.into_response();
    }
    start(&shared, &who, &me, spec, upgrade)
}

/// Writes the run down, starts the app, and joins it to the tunnel once it is up.
fn start(shared: &Arc<Shared>, who: &impl Display, node: &str, spec: Spec, upgrade: OnUpgrade) -> Response {
    // Whoever the cluster says may: this node's owner has it run no app for anyone (the root
    // part's to say, as it is of what it would run: docs/adr-privilege.md, "Node").
    let via = spec.via.as_deref().unwrap_or("waypipe");
    if let Err(why) = crate::root_part::run(via, &spec.argv) {
        audit(shared, who, node, &spec, Err(why.clone()));
        return say(StatusCode::FORBIDDEN, why);
    }
    audit(shared, who, node, &spec, Ok(()));
    let app = match App::start(node, &spec) {
        Ok(app) => app,
        Err(why) => {
            audit(shared, who, node, &spec, Err(why.clone()));
            return say(StatusCode::UNPROCESSABLE_ENTITY, why);
        }
    };
    let stop = shared.stop.subscribe();
    switch(upgrade, move |tunnel| app.serve(stop, tunnel))
}

/// Answers 101 and, once the connection is ours, does `work` with it.
fn switch<F: Future<Output = ()> + Send + 'static>(
    upgrade: OnUpgrade,
    work: impl FnOnce(TokioIo<Upgraded>) -> F + Send + 'static,
) -> Response {
    tokio::spawn(async move {
        // (An upgrade that is not made in time is let go: the connection is dropped with it.)
        if let Ok(Ok(upgraded)) = tokio::time::timeout(HOP, upgrade).await {
            work(TokioIo::new(upgraded)).await;
        }
    });
    let mut reply = Response::new(Body::empty());
    *reply.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    reply
        .headers_mut()
        .insert(header::CONNECTION, "upgrade".parse().expect("a header value"));
    reply
        .headers_mut()
        .insert(header::UPGRADE, PROTOCOL.parse().expect("a header value"));
    reply
}

/// Copies both ways until both ends are done, either fails, or kithd is told to stop.
pub(crate) async fn join(
    mut stop: watch::Receiver<bool>,
    mut a: impl AsyncRead + AsyncWrite + Unpin,
    mut b: impl AsyncRead + AsyncWrite + Unpin,
) {
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut a, &mut b) => {}
        _ = stop.wait_for(|stopped| *stopped) => {}
    }
}

/// A directory only kithd's user can enter, with a name nobody can guess, gone when dropped.
struct Dir(PathBuf);

impl Dir {
    fn make() -> Result<Dir, String> {
        let mut random = [0u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| "no random numbers".to_string())?;
        // The socket in here (`s`) must fit `sun_path` (107 bytes): a long temp dir, as a build's,
        // is passed over for /tmp.
        // (Not `kith-run-`: the `kith` command makes those in the same temp dir, and the sweep
        // at start must not take a live one of theirs.)
        let name = format!("{DIR_PREFIX}{}-{}", owner(), pki::hex(&random));
        let mut path = std::env::temp_dir().join(&name);
        if path.join("s").as_os_str().len() > 107 {
            path = Path::new("/tmp").join(&name);
        }
        let made = std::fs::DirBuilder::new().mode(0o700).create(&path);
        made.map_err(|e| format!("cannot make {}: {e}", path.display()))?;
        Ok(Dir(path))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// The names a run's directory and its cgroup start with; then the owner and a random part.
const DIR_PREFIX: &str = "kithd-run-";
const CGROUP_PREFIX: &str = "kith-run-";

/// Which kithd made a run: eight hex digits of a hash of its state directory, set at start
/// ([`sweep_stale`]). Many kithds of one user can be on one machine (a dev one beside a node's,
/// the test suites'), and each sweeps only what carries its own.
static OWNER: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn owner_of(state: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    pki::hex(&ring::digest::digest(&ring::digest::SHA256, state.as_os_str().as_bytes()).as_ref()[..4])
}

/// (Before `sweep_stale` no owner is set, as in a test: the runs' names carry a fixed `none`,
/// which no sweep takes.)
fn owner() -> &'static str {
    OWNER.get().map_or("none", String::as_str)
}

/// True the first time it is asked of `flag`: for a line every run would repeat.
fn first(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::Relaxed)
}

/// A cgroup of a run's own, in the subtree the node was delegated: what the run started is in it
/// however it left the process group (a `setsid`), and is killed with it. Gone when dropped.
struct Leaf(PathBuf);

impl Leaf {
    /// `None` where none can be made (no cgroup v2, no delegation): the process group is all there is.
    fn make(name: &str) -> Option<Leaf> {
        static SAID: AtomicBool = AtomicBool::new(false);
        match kith_runtime::leaf_cgroup(name) {
            Ok(leaf) => Some(Leaf(leaf)),
            Err(e) => {
                if first(&SAID) {
                    eprintln!(
                        "kithd: run: no cgroup for runs, the process group is all that ends one (said once): {e}"
                    );
                }
                None
            }
        }
    }

    fn kill(&self) {
        kill_cgroup(&self.0);
    }
}

/// Kills everything in the cgroup `path`: `cgroup.kill` (Linux 5.14), and where that cannot be
/// written, a SIGKILL to each pid in `cgroup.procs` (not atomic against a fork: a program that
/// forks as fast as it is killed can leave a child, which the process group still catches).
/// A cgroup that is gone is nothing to kill.
fn kill_cgroup(path: &Path) {
    // (No `create`: on a cgroup the file is there, and where it is not, there is no cgroup.)
    let written = std::fs::OpenOptions::new()
        .write(true)
        .open(path.join("cgroup.kill"))
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"1"));
    let Err(e) = written else { return };
    if e.kind() == std::io::ErrorKind::NotFound {
        return;
    }
    static SAID: AtomicBool = AtomicBool::new(false);
    if first(&SAID) {
        eprintln!(
            "kithd: run: cannot write cgroup.kill ({e}): killing each process of a run's cgroup instead (said once)"
        );
    }
    let procs = std::fs::read_to_string(path.join("cgroup.procs")).unwrap_or_default();
    for pid in procs.lines().filter_map(|pid| pid.trim().parse::<i32>().ok()) {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
    }
}

/// Removes the empty directory `path` once what was in it is gone (a cgroup is removed once what
/// was in it is waited for, which is not by this thread): tries for ten seconds, off the
/// runtime's threads, and leaves it after that.
fn remove_when_empty(path: PathBuf) {
    std::thread::spawn(move || {
        for _ in 0..200 {
            if std::fs::remove_dir(&path).is_ok() || !path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
}

/// At kithd's start, what a kithd before left of runs (it was killed, or crashed, with runs going:
/// their cgroups are beside kithd's own, not in it, and live on): the `kith-run-OWNER-*` cgroups
/// in `cgroups` are killed and removed, and the `kithd-run-OWNER-*` directories in `tmps`
/// removed. Nothing of this kithd's is yet there; what is not this user's, what another kithd's
/// state directory made, and a name with no owner (one a kithd before this wrote) are left.
fn sweep(cgroups: Option<&Path>, tmps: &[&Path], owner: &str) {
    use std::os::unix::fs::MetadataExt;
    let ours = |path: &Path, prefix: &str| {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(prefix));
        let meta = std::fs::symlink_metadata(path);
        name && meta.is_ok_and(|meta| meta.is_dir() && meta.uid() == nix::unistd::geteuid().as_raw())
    };
    for entry in cgroups
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .into_iter()
        .flatten()
        .flatten()
    {
        if ours(&entry.path(), &format!("{CGROUP_PREFIX}{owner}-")) {
            kill_cgroup(&entry.path());
            remove_when_empty(entry.path());
        }
    }
    for tmp in tmps {
        for entry in std::fs::read_dir(tmp).ok().into_iter().flatten().flatten() {
            if ours(&entry.path(), &format!("{DIR_PREFIX}{owner}-")) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
}

/// Names this kithd's runs after its `state` directory, and [`sweep`]s where runs go.
pub(crate) fn sweep_stale(state: &Path) {
    let owner = OWNER.get_or_init(|| owner_of(state));
    let cgroups = kith_runtime::units_cgroup_dir();
    let temp = std::env::temp_dir();
    // (`Dir::make` falls back to /tmp for a long temp dir.)
    sweep(cgroups.as_deref(), &[&temp, Path::new("/tmp")], owner);
}

impl Drop for Leaf {
    fn drop(&mut self) {
        self.kill();
        remove_when_empty(std::mem::take(&mut self.0));
    }
}

/// `VIA --socket S server -- ARGV…`, started and waiting for the tunnel's other end.
struct App {
    /// VIA's process group (VIA leads it): the app and whatever it started are in it.
    group: Option<i32>,
    child: Child,
    listener: UnixListener,
    leaf: Option<Leaf>,
    _dir: Dir,
}

impl App {
    // ponytail: one tunnel carries one connection of the app to VIA; the `kith` command
    // starts VIA's client for it, so an app that opens a second Wayland connection through
    // another VIA process needs its own `kith run`.
    // ponytail: VIA and the app run as kithd's user, in a process group of their own and in a
    // cgroup of their own (where one can be made), both killed when the tunnel ends: a program
    // that makes its own session is caught by the cgroup. VIA joins it between the fork and the
    // exec (`kith_dm_sys::join_cgroup_before_exec`, the one place with the unsafe), so nothing it
    // forks is outside; without delegation only the group is.
    // ponytail: a tunnel whose far end vanishes without a word (a node powered off) is ended by
    // the keepalive on the nodes' connections (`cluster::listen` and reqwest's own), not at once:
    // about a minute (see "Remote apps" in docs/guide/storage.md).
    fn start(node: &str, spec: &Spec) -> Result<App, String> {
        let via = spec.via.as_deref().unwrap_or("waypipe");
        let dir = Dir::make()?;
        let leaf = (dir.0.file_name().and_then(|name| name.to_str()))
            .and_then(|name| name.strip_prefix(DIR_PREFIX))
            .and_then(|id| Leaf::make(&format!("{CGROUP_PREFIX}{id}")));
        let socket = dir.0.join("s");
        let listener =
            UnixListener::bind(&socket).map_err(|e| format!("cannot listen on {}: {e}", socket.display()))?;
        let start = |procs: Option<&Path>| {
            let mut command = Command::new(via);
            command
                .arg("--socket")
                .arg(&socket)
                .args(["server", "--"])
                .args(&spec.argv)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .process_group(0)
                .kill_on_drop(true);
            if let Some(procs) = procs {
                kith_dm_sys::join_cgroup_before_exec(command.as_std_mut(), procs)?;
            }
            command.spawn()
        };
        // In the cgroup before its exec (so nothing it forks is outside). If that fails the
        // program is not started, and it is started again without: the process group still ends it.
        // (Not for a program that is not there: no cgroup is to blame, and a second try is the same.)
        let procs = leaf.as_ref().map(|leaf| leaf.0.join("cgroup.procs"));
        let spawned = match start(procs.as_deref()) {
            Err(e) if procs.is_some() && e.kind() != std::io::ErrorKind::NotFound => {
                eprintln!(
                    "kithd: run: could not start the app in its cgroup, the process group is all that ends it: {e}"
                );
                start(None)
            }
            other => other,
        };
        let child = spawned.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => format!("{via} is not installed on node {node} (kith does not ship it)"),
            _ => format!("cannot start {via} on node {node}: {e}"),
        })?;
        Ok(App {
            group: child.id().and_then(|pid| i32::try_from(pid).ok()),
            child,
            listener,
            leaf,
            _dir: dir,
        })
    }

    /// Waits for VIA to connect, joins it to `tunnel`, and when either end is done kills VIA
    /// and waits for it.
    async fn serve(mut self, mut stop: watch::Receiver<bool>, tunnel: impl AsyncRead + AsyncWrite + Unpin) {
        let connected = tokio::select! {
            accepted = self.listener.accept() => accepted.ok(),
            _ = self.child.wait() => None,
            _ = tokio::time::sleep(START) => None,
            _ = stop.wait_for(|stopped| *stopped) => None,
        };
        if let Some((connection, _)) = connected {
            join(stop, tunnel, connection).await;
        }
        self.end();
        drop(self.child.kill().await);
    }

    /// Kill VIA, the app and what the app started, while VIA (not yet waited for) still holds
    /// the group's number; and whatever is in the cgroup, a session of its own or not.
    fn end(&mut self) {
        if let Some(group) = self.group.take() {
            let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(group), nix::sys::signal::Signal::SIGKILL);
        }
        if let Some(leaf) = &self.leaf {
            leaf.kill();
        }
    }
}

/// (An app whose tunnel never came up: the upgrade failed, kithd is stopping.)
impl Drop for App {
    fn drop(&mut self) {
        self.end();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cluster::{self, Cluster};
    use crate::pki::{Ca, Identity};
    use futures_util::StreamExt;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::OnceLock;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    /// What waypipe would be: `--socket S server -- APP…` joins APP's input and output
    /// to the socket S, and tells APP where S is.
    const STAND_IN: &str = r#"#!/usr/bin/env python3
import os, socket, subprocess, sys
args = sys.argv[1:]
if args[0] != "--socket" or args[2:4] != ["server", "--"]:
    sys.exit(3)
s = socket.socket(socket.AF_UNIX)
s.connect(args[1])
os.environ["KITH_TEST_SOCKET"] = args[1]
sys.exit(subprocess.run(args[4:], stdin=s, stdout=s).returncode)
"#;

    /// A VIA that never connects to its socket: it writes its pid and the socket's path beside
    /// itself, then waits.
    const SILENT: &str = "#!/bin/sh\necho \"$$ $2\" > \"$0.said\"\nexec sleep 300\n";

    fn installed(cell: &'static OnceLock<String>, name: &str, body: &str) -> &'static str {
        cell.get_or_init(|| {
            let path = std::env::temp_dir().join(format!("kith-run-on-{name}-{}", std::process::id()));
            // Not `fs::write` on `path`: while this process holds it open for writing, another
            // test thread that forks keeps a copy of the descriptor until its exec, and running
            // the file meanwhile fails with ETXTBSY. `cp` is the only writer, and forks nothing.
            let mut draft = path.clone().into_os_string();
            draft.push(".draft");
            std::fs::write(&draft, body).unwrap();
            let copied = std::process::Command::new("cp")
                .arg(&draft)
                .arg(&path)
                .status()
                .unwrap();
            assert!(copied.success(), "cp of {name}: {copied}");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.display().to_string()
        })
    }

    fn stand_in() -> &'static str {
        static PATH: OnceLock<String> = OnceLock::new();
        installed(&PATH, "stand-in", STAND_IN)
    }

    fn silent() -> &'static str {
        static PATH: OnceLock<String> = OnceLock::new();
        installed(&PATH, "silent", SILENT)
    }

    /// Two kithds in this process, `a` and `b`, each serving the node API on a loopback
    /// port with its own certificate from one CA. Both have the Identities, Roles and Nodes,
    /// as two nodes of one store do.
    pub(crate) struct World {
        pub(crate) a: Arc<Shared>,
        pub(crate) b: Arc<Shared>,
        pub(crate) a_port: u16,
        pub(crate) b_port: u16,
        ca: Ca,
    }

    const ROLES: &str = "
apiVersion: kith.dev/v1
kind: Role
metadata: {name: jobber}
spec:
  rules:
    - {kinds: [Node], verbs: [exec]}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: other-jobber}
spec:
  rules:
    - {kinds: [Node], verbs: [exec], namespaces: [other]}
    - {kinds: [Job], verbs: [apply]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: alice-jobber}
spec: {role: jobber, subjects: [alice]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: carol-other}
spec: {role: other-jobber, subjects: [carol]}
";

    impl World {
        pub(crate) async fn new(tag: &str) -> World {
            let dir = std::env::temp_dir().join(format!("kithd-run-on-{tag}-{}", std::process::id()));
            let ca = Ca::create().unwrap();
            let mut nodes = Vec::new();
            for name in ["a", "b"] {
                let (cert, key) = ca.issue(name).unwrap();
                let me = Identity {
                    name: name.into(),
                    ca: ca.cert.clone(),
                    cert,
                    key,
                };
                let shared = crate::replica(
                    Some(Cluster::new(me.clone(), None).unwrap()),
                    &dir.join(name),
                    std::time::Duration::from_secs(300),
                )
                .await;
                let shared = shared.unwrap();
                let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = tcp.local_addr().unwrap().port();
                let listener = cluster::listen(tcp, pki::server_config(&me).unwrap()).unwrap();
                let app = cluster::node_router(shared.clone()).into_make_service_with_connect_info::<Peer>();
                tokio::spawn(async move { drop(axum::serve(listener, app).await) });
                nodes.push((shared, port));
            }
            let [(a, a_port), (b, b_port)] = <[_; 2]>::try_from(nodes).ok().unwrap();
            let world = World {
                a,
                b,
                a_port,
                b_port,
                ca,
            };
            world.node("a", "", Some(a_port));
            world.node("b", "role: display", Some(b_port));
            for shared in [&world.a, &world.b] {
                let mut state = shared.store.lock().unwrap();
                for resource in kith_api::Resource::from_source(ROLES).unwrap() {
                    state.store.apply(resource.unwrap()).unwrap();
                }
            }
            world
        }

        /// A Node of `a`'s store: ready, and at `port` unless it is not (`None`: unreachable).
        fn node(&self, name: &str, labels: &str, port: Option<u16>) {
            let text = format!(
                "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}, labels: {{{labels}}}}}\nspec: {{}}\n"
            );
            let resource = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            // (With a `raftId`, as a node that joined has: one without is let in nowhere.)
            let status = match port {
                Some(port) => json!({"address": format!("127.0.0.1:{port}"), "state": "ready", "raftId": "1"}),
                None => json!({"address": "127.0.0.1:1", "state": "unreachable", "raftId": "1"}),
            };
            // Both nodes have the store: the one asked looks the asking node up in its own.
            for shared in [&self.a, &self.b] {
                let mut state = shared.store.lock().unwrap();
                state.store.apply(resource.clone()).unwrap();
                state
                    .store
                    .set_status(&format!("Node/{name}"), Some(status.clone()))
                    .unwrap();
            }
        }

        /// A client that shows the certificate of the Identity `name` (made now, on `a`).
        pub(crate) fn user(&self, name: &str) -> reqwest::Client {
            let (cert, key, public) = self.ca.issue_user(name).unwrap();
            let identity = json!({
                "apiVersion": kith_api::API_VERSION, "kind": "Identity",
                "metadata": {"name": name}, "spec": {"publicKey": public},
            });
            let identity: kith_api::Resource = serde_json::from_value(identity).unwrap();
            for shared in [&self.a, &self.b] {
                shared.store.lock().unwrap().store.apply(identity.clone()).unwrap();
            }
            let me = Identity {
                name: name.into(),
                ca: self.ca.cert.clone(),
                cert,
                key,
            };
            Self::client(pki::client_config(&me.ca, Some(&me), None).unwrap())
        }

        fn client(config: rustls::ClientConfig) -> reqwest::Client {
            reqwest::Client::builder()
                .use_preconfigured_tls(config)
                .no_proxy()
                .build()
                .unwrap()
        }
    }

    /// Asks for a tunnel: the byte stream, or why not.
    async fn tunnel(
        client: &reqwest::Client,
        port: u16,
        path: &str,
        spec: serde_json::Value,
    ) -> Result<reqwest::Upgraded, (u16, String)> {
        let reply = client
            .post(format!("https://127.0.0.1:{port}{path}"))
            .header(reqwest::header::CONNECTION, "upgrade")
            .header(reqwest::header::UPGRADE, "kith-run")
            .json(&spec)
            .send()
            .await
            .unwrap();
        let status = reply.status().as_u16();
        if status != 101 {
            let said: serde_json::Value = reply.json().await.unwrap_or_default();
            return Err((status, said["error"].as_str().unwrap_or_default().to_string()));
        }
        Ok(reply.upgrade().await.unwrap())
    }

    async fn gone(path: &str) -> bool {
        for _ in 0..100 {
            if !Path::new(path).exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// An app that says what it was given and where its socket is, answers one line, and
    /// then waits for the tunnel to close. Through `on`, as alice.
    async fn tunnel_to(on: &str) {
        let world = World::new(&format!("tunnel-{on}")).await;
        let alice = world.user("alice");
        // (The app's own pid: it stays after its input ends, so only being killed ends it.)
        let line = "echo \"$1:$$:$KITH_TEST_SOCKET\"; read line; echo \"$1:$line\"; read line; exec sleep 300";
        let argv = ["sh", "-c", line, "sh", "two words; $(touch pwned)"];
        let spec = json!({"on": on, "via": stand_in(), "argv": argv});
        let tunnel = tunnel(&alice, world.a_port, "/v1/run", spec).await.unwrap();
        let mut tunnel = BufReader::new(tunnel);
        let mut first = String::new();
        tunnel.read_line(&mut first).await.unwrap();
        let parts: Vec<&str> = first.trim_end().splitn(3, ':').collect();
        let [arg, pid, socket] = parts.as_slice() else {
            panic!("the app said {first:?}")
        };
        // argv is an array: nothing of it went through a shell.
        assert_eq!(*arg, "two words; $(touch pwned)");
        assert!(!std::env::current_dir().unwrap().join("pwned").exists());
        // The socket is in a private directory with a name nobody can guess.
        let dir = Path::new(socket).parent().unwrap();
        let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{}", dir.display());
        assert!(dir.file_name().unwrap().len() > 32, "{}", dir.display());
        tunnel.get_mut().write_all(b"ping\n").await.unwrap();
        let mut second = String::new();
        tunnel.read_line(&mut second).await.unwrap();
        assert_eq!(second, "two words; $(touch pwned):ping\n");

        // The audit entry names alice and the node; on another node it carries alice's name over.
        let (here, there) = (world.a.audit.tail(10).unwrap(), world.b.audit.tail(10).unwrap());
        let ran = |entries: &[serde_json::Value]| entries.iter().find(|entry| entry["verb"] == "run").cloned();
        let entry = ran(&here).expect("no run entry on the first node");
        assert_eq!((&entry["who"], &entry["ok"]), (&json!("alice"), &json!(true)));
        assert_eq!(entry["what"][0], format!("node {on}"));
        assert_eq!(entry["what"][2], "sh");
        if on == "b" {
            assert_eq!(ran(&there).unwrap()["who"], "alice via node a");
        }

        // Either end closing ends the app, which is waited for, and the directory goes.
        drop(tunnel);
        assert!(gone(&dir.display().to_string()).await, "the directory stays");
        assert!(gone(&format!("/proc/{pid}")).await, "the app stays");
    }

    #[tokio::test]
    async fn run_on_another_node_joins_the_tunnel_to_the_app_there() {
        tunnel_to("b").await;
    }

    #[tokio::test]
    async fn run_on_this_node_needs_no_second_hop() {
        tunnel_to("a").await;
    }

    #[tokio::test]
    async fn run_on_refuses_a_caller_who_may_not_exec_on_nodes_before_anything_starts() {
        let world = World::new("refused").await;
        let spec = json!({"on": "b", "via": stand_in(), "argv": ["true"]});
        let bob = world.user("bob");
        let (status, why) = tunnel(&bob, world.a_port, "/v1/run", spec.clone()).await.unwrap_err();
        assert_eq!(status, 403);
        assert!(why.contains("bob may not exec Node"), "{why}");
        // Carol may apply Jobs anywhere, and exec in one namespace: neither is the run of a node.
        let carol = world.user("carol");
        let (status, _) = tunnel(&carol, world.a_port, "/v1/run", spec.clone()).await.unwrap_err();
        assert_eq!(status, 403);
        // The refusals are written down on the first node; the second never heard of them.
        let entries = world.a.audit.tail(10).unwrap();
        let refused: Vec<_> = entries.iter().filter(|entry| entry["ok"] == false).collect();
        assert_eq!(refused[0]["who"], "bob");
        assert_eq!(refused[1]["who"], "carol");
        let there = world.b.audit.tail(10).unwrap();
        assert!(there.is_empty(), "{there:?}");
    }

    #[tokio::test]
    async fn run_on_names_a_program_that_is_not_there_and_writes_the_audit_first() {
        let world = World::new("missing").await;
        let alice = world.user("alice");
        let spec = json!({"on": "b", "via": "/nonexistent/waypipe", "argv": ["true"]});
        let (status, why) = tunnel(&alice, world.a_port, "/v1/run", spec).await.unwrap_err();
        assert_eq!(status, 422);
        assert!(why.contains("/nonexistent/waypipe") && why.contains("node b"), "{why}");
        // Written before the program was started (ok), and again with what went wrong.
        let entries = world.b.audit.tail(10).unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(
            (&entries[0]["who"], &entries[0]["ok"]),
            (&json!("alice via node a"), &json!(true))
        );
        assert_eq!(entries[1]["ok"], false);
    }

    #[tokio::test]
    async fn run_on_the_hop_is_for_nodes_not_for_a_client_token() {
        let world = World::new("hop").await;
        let spec = json!({"on": "b", "via": stand_in(), "argv": ["true"], "caller": "root"});
        // Alice may apply Jobs, and still cannot ask the second node herself.
        let alice = world.user("alice");
        let (status, why) = tunnel(&alice, world.b_port, "/v1/run-hop", spec.clone())
            .await
            .unwrap_err();
        assert_eq!((status, why.contains("not for an Identity")), (403, true), "{why}");
        // Nor can a certificate that is no one's, or none.
        let none = World::client(pki::client_config(&world.ca.cert, None, None).unwrap());
        let (status, _) = tunnel(&none, world.b_port, "/v1/run-hop", spec).await.unwrap_err();
        assert_eq!(status, 401);
        assert!(
            world
                .b
                .audit
                .tail(10)
                .map_or(true, |entries| entries.iter().all(|e| e["verb"] != "run"))
        );
        // And the first node does not open the hop to Identities either.
        let spec = json!({"on": "a", "via": stand_in(), "argv": ["true"], "caller": "root"});
        let (status, _) = tunnel(&alice, world.a_port, "/v1/run-hop", spec).await.unwrap_err();
        assert_eq!(status, 403);
    }

    /// The node a hop arrives at asks its own store whether the one the first node names may:
    /// a node's word is taken for who asked, not for what they may do.
    #[tokio::test]
    async fn hop_checks_the_named_caller_on_the_node_it_arrives_at() {
        let world = World::new("hop-checks").await;
        world.user("alice");
        world.user("bob");
        let a = world.a.cluster.as_ref().unwrap().client.clone();
        let ask = |caller: &'static str| {
            let spec = json!({"on": "b", "via": "/nonexistent/waypipe", "argv": ["true"], "caller": caller});
            let (a, port) = (a.clone(), world.b_port);
            async move { tunnel(&a, port, "/v1/run-hop", spec).await.unwrap_err() }
        };
        let (status, why) = ask("bob").await;
        assert_eq!(status, 403, "{why}");
        assert!(why.contains("bob via node a may not exec Node"), "{why}");
        // No Identity of the store: no right either.
        assert_eq!(ask("mallory").await.0, 403);
        // A node, someone a node was itself passed, or nobody: not a caller a hop is for.
        for caller in ["node a", "alice via node b", ""] {
            assert_eq!(ask(caller).await.0, 400, "{caller:?}");
        }
        let ran = world.b.audit.tail(10).unwrap();
        assert!(ran.iter().all(|entry| entry["ok"] == false), "{ran:?}");
        assert_eq!(ran[0]["who"], "bob via node a");
        // Who may: the hop goes on to the program (which is not there).
        assert_eq!(ask("alice").await.0, 422);
        assert_eq!(ask("local socket").await.0, 422);
    }

    /// A worker's word for who asked is not taken, on the hop or on what nodes pass on, and
    /// its Raft messages are refused: whatever caller it names, the socket even.
    #[tokio::test]
    async fn hop_forged_by_a_worker_is_refused_whoever_it_names() {
        let world = World::new("hop-forged").await;
        let a = world.a.cluster.as_ref().unwrap().client.clone();
        let hop = || {
            let spec = json!({"on": "b", "via": "/nonexistent/waypipe", "argv": ["true"], "caller": "local socket"});
            let (a, port) = (a.clone(), world.b_port);
            async move { tunnel(&a, port, "/v1/run-hop", spec).await.unwrap_err() }
        };
        let ask = |method: reqwest::Method, path: &str| {
            let url = format!("https://127.0.0.1:{}{path}", world.b_port);
            let ask = a.request(method, url).header(crate::access::FOR, "local socket");
            async move {
                let reply = ask.send().await.unwrap();
                let status = reply.status().as_u16();
                let said: serde_json::Value = reply.json().await.unwrap_or_default();
                (status, said["error"].as_str().unwrap_or_default().to_string())
            }
        };
        let logs = "/v1/logs/Workload/default/web";
        // A control node, as every node is unless said: the socket's rights where it arrives.
        assert_eq!(hop().await.0, 422);
        assert_eq!(ask(reqwest::Method::GET, logs).await.0, 404);
        // b's store says a is a worker (a's own store does not count).
        let trust = |trust: &str| {
            let text =
                format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: a}}\nspec: {{trust: {trust}}}\n");
            let node = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            world.b.store.lock().unwrap().store.apply(node).unwrap();
        };
        trust("worker");
        let (status, why) = hop().await;
        assert_eq!(status, 403, "{why}");
        assert!(why.contains("node a is a worker"), "{why}");
        let (status, why) = ask(reqwest::Method::GET, logs).await;
        assert_eq!(status, 403, "{why}");
        assert!(
            why.contains("its word for who asked is not taken: ask a control node"),
            "{why}"
        );
        // Raft's messages are taken from a worker only while it still votes in b's membership
        // (it hands the vote over itself); the hop above is refused either way.
        for message in ["append", "vote", "snapshot"] {
            let (status, why) = ask(reqwest::Method::POST, &format!("/v1/raft/{message}")).await;
            assert_eq!(status, 403, "{message}: {why}");
            assert!(why.contains("only a control node sends this"), "{why}");
        }
        let ids = [world.b.raft.metrics().borrow().id, kith_store::node_id("a")];
        let voters = ids.map(|id| (id, kith_store::openraft::BasicNode::new("")));
        world
            .b
            .raft
            .initialize(std::collections::BTreeMap::from(voters))
            .await
            .unwrap();
        assert_ne!(ask(reqwest::Method::POST, "/v1/raft/vote").await.0, 403);
        assert_eq!(hop().await.0, 403);
        // What every node sends is still taken from it.
        assert_ne!(ask(reqwest::Method::POST, "/v1/raft/write").await.0, 403);
        // Nothing ran, and it is written down.
        let entries = world.b.audit.tail(20).unwrap();
        assert!(
            entries.iter().any(|e| e["ok"] == false && e["who"] == "node a"),
            "{entries:?}"
        );
        trust("control");
        assert_eq!(hop().await.0, 422);
    }

    /// Who asked is a node's to say, on what nodes pass on: an Identity that names the local
    /// socket is still itself, and a node that names nobody is given nothing.
    #[tokio::test]
    async fn who_asked_is_read_from_a_node_only_and_checked_where_it_arrives() {
        let world = World::new("named").await;
        let alice = world.user("alice");
        let a = world.a.cluster.as_ref().unwrap().client.clone();
        let ask = |client: &reqwest::Client, named: Option<&'static str>| {
            let url = format!("https://127.0.0.1:{}/v1/logs/Workload/default/web", world.b_port);
            let ask = client.get(url);
            let ask = named
                .into_iter()
                .fold(ask, |ask, named| ask.header(crate::access::FOR, named));
            async move {
                let reply = ask.send().await.unwrap();
                let status = reply.status().as_u16();
                let said: serde_json::Value = reply.json().await.unwrap_or_default();
                (status, said["error"].as_str().unwrap_or_default().to_string())
            }
        };
        let (status, why) = ask(&alice, Some("local socket")).await;
        assert_eq!(status, 403, "{why}");
        assert!(why.starts_with("alice may not get Workload"), "{why}");
        // From a node: she is asked for by name, and has no more right for it.
        let (status, why) = ask(&a, Some("alice")).await;
        assert_eq!(status, 403, "{why}");
        assert!(why.starts_with("alice via node a may not get Workload"), "{why}");
        // Nobody named: nothing on the node's own word.
        let (status, why) = ask(&a, None).await;
        assert_eq!(status, 400, "{why}");
        assert!(why.contains("without saying who asked"), "{why}");
        // The socket named: let through to the handler (there is no such Workload).
        let (status, why) = ask(&a, Some("local socket")).await;
        assert_eq!(status, 404, "{why}");
    }

    /// Whether the kernel's keepalive timer is armed (`tr` 2 in /proc/net/tcp, which SO_KEEPALIVE
    /// sets) on each open connection with `port` at one end: the option, read from the socket.
    fn keepalive(port: u16) -> Vec<bool> {
        let want = format!(":{port:04X}");
        let table = std::fs::read_to_string("/proc/net/tcp").unwrap();
        let rows = table
            .lines()
            .skip(1)
            .map(|line| line.split_whitespace().collect::<Vec<_>>());
        rows.filter(|f| f[3] == "01" && (f[1].ends_with(&want) || f[2].ends_with(&want)))
            .map(|f| f[5].starts_with("02:"))
            .collect()
    }

    /// A tunnel to a node that goes quiet (a node powered off) is ended by the kernel's
    /// keepalive on both nodes' ends of the connection between them, not only on a write.
    #[tokio::test]
    async fn run_between_nodes_sets_keepalive_on_both_ends_of_the_connection() {
        let world = World::new("keepalive").await;
        let alice = world.user("alice");
        let spec = json!({"on": "b", "via": stand_in(), "argv": ["sh", "-c", "exec sleep 300"]});
        let _tunnel = tunnel(&alice, world.a_port, "/v1/run", spec).await.unwrap();
        let mut seen = Vec::new();
        for _ in 0..100 {
            seen = keepalive(world.b_port);
            if seen.len() >= 2 && seen.iter().all(|armed| *armed) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the connections to node b, armed or not: {seen:?} (two expected: a's end and b's)");
    }

    /// A VIA that reads its own cgroup as its first act (and forks `cat` to do it, which keeps
    /// whatever cgroup it is in at that moment): it is in the run's cgroup from its first
    /// instruction, however fast it forks. (Skipped where no cgroup can be made: no delegation.)
    #[tokio::test]
    async fn run_puts_a_program_that_forks_at_once_in_the_runs_cgroup() {
        let probe = format!("kith-run-probe-{}", std::process::id());
        if Leaf::make(&probe).is_none() {
            eprintln!("skipped: no delegated cgroup to make one in (run in a systemd user session or scope)");
            return;
        }
        static PATH: OnceLock<String> = OnceLock::new();
        let fast = installed(
            &PATH,
            "fast",
            "#!/bin/sh\ncat /proc/self/cgroup > \"$0.cgroup\"\nexec sleep 300\n",
        );
        let world = World::new("cgroup-fast").await;
        let alice = world.user("alice");
        let spec = json!({"on": "a", "via": fast, "argv": ["true"]});
        let tunnel = tunnel(&alice, world.a_port, "/v1/run", spec).await.unwrap();
        let mut seen = String::new();
        for _ in 0..200 {
            seen = std::fs::read_to_string(format!("{fast}.cgroup")).unwrap_or_default();
            if !seen.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        drop(tunnel);
        assert!(
            seen.contains("kith-run-"),
            "the program's first look at its cgroup: {seen:?}"
        );
    }

    /// A program that makes its own session leaves the process group, and is still ended with the
    /// tunnel: it is in the run's cgroup. (Skipped where no cgroup can be made: no delegation.)
    #[tokio::test]
    async fn run_ends_a_program_that_left_its_session_through_the_runs_cgroup() {
        let probe = format!("kith-run-probe-{}", std::process::id());
        if Leaf::make(&probe).is_none() {
            eprintln!("skipped: no delegated cgroup to make one in (run in a systemd user session or scope)");
            return;
        }
        let world = World::new("cgroup").await;
        let alice = world.user("alice");
        let line = "setsid sh -c 'echo $$; exec sleep 300' & read line; exec sleep 300";
        let spec = json!({"on": "a", "via": stand_in(), "argv": ["sh", "-c", line]});
        let tunnel = tunnel(&alice, world.a_port, "/v1/run", spec).await.unwrap();
        let mut tunnel = BufReader::new(tunnel);
        let mut first = String::new();
        tunnel.read_line(&mut first).await.unwrap();
        let pid: i32 = first.trim().parse().expect("the daemon's pid");
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
        let cgroup = cgroup.trim().strip_prefix("0::").unwrap().to_string();
        assert!(cgroup.contains("kith-run-"), "the program is in {cgroup}");
        drop(tunnel);
        let ended = gone(&format!("/proc/{pid}")).await;
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
        assert!(ended, "the program that left its session stays");
        assert!(gone(&format!("/sys/fs/cgroup{cgroup}")).await, "{cgroup} stays");
    }

    /// At start, what an earlier kithd of the same state directory left (runs' cgroups and
    /// directories) goes; what is not a run's, what is a `kith` command's own directory, and what
    /// another kithd (another state directory) or one whose owner cannot be told has going, stays.
    #[tokio::test]
    async fn sweep_removes_the_runs_a_kithd_before_left_and_nothing_else() {
        let root = std::env::temp_dir().join(format!("kithd-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (cgroups, tmp) = (root.join("cgroup"), root.join("tmp"));
        for dir in [
            "cgroup/kith-run-aaaaaaaa-stale",
            "cgroup/kith-run-bbbbbbbb-live",
            "cgroup/kith-run-noowner",
            "cgroup/kith-unit-1",
            "tmp/kithd-run-aaaaaaaa-stale",
            "tmp/kithd-run-bbbbbbbb-live",
            "tmp/kithd-run-noowner",
            "tmp/kith-run-cli",
            "tmp/other",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(tmp.join("kithd-run-aaaaaaaa-stale/s"), "").unwrap();
        std::fs::write(cgroups.join("kith-run-aaaaaaaa-file"), "").unwrap();
        sweep(Some(&cgroups), &[&tmp], "aaaaaaaa");
        assert!(
            gone(cgroups.join("kith-run-aaaaaaaa-stale").to_str().unwrap()).await,
            "the stale cgroup stays"
        );
        assert!(
            gone(tmp.join("kithd-run-aaaaaaaa-stale").to_str().unwrap()).await,
            "the stale directory stays"
        );
        for kept in [
            "cgroup/kith-run-bbbbbbbb-live",
            "cgroup/kith-run-noowner",
            "cgroup/kith-unit-1",
            "cgroup/kith-run-aaaaaaaa-file",
            "tmp/kithd-run-bbbbbbbb-live",
            "tmp/kithd-run-noowner",
            "tmp/kith-run-cli",
            "tmp/other",
        ] {
            assert!(root.join(kept).exists(), "{kept} was removed");
        }
        sweep(None, &[&root.join("nowhere")], "aaaaaaaa"); // nothing to read is nothing to do
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A run's names carry its kithd's owner id, so the sweep of one state directory can tell
    /// them from another's.
    #[test]
    fn owners_differ_by_state_directory_and_a_runs_dir_carries_its_owner() {
        let (a, b) = (owner_of(Path::new("/var/a")), owner_of(Path::new("/var/b")));
        assert!(a != b && a.len() == 8 && a == owner_of(Path::new("/var/a")), "{a} {b}");
        // (No other test sets the owner: `sweep_stale` is only called by kithd's start.)
        assert_eq!(OWNER.get_or_init(|| a.clone()), &a);
        let dir = Dir::make().unwrap();
        let name = dir.0.file_name().unwrap().to_str().unwrap().to_string();
        assert!(name.starts_with(&format!("{DIR_PREFIX}{a}-")), "{name}");
    }

    /// Where `cgroup.kill` cannot be written (before Linux 5.14: here a directory stands for it),
    /// each pid in `cgroup.procs` is killed.
    #[tokio::test]
    async fn kill_cgroup_kills_the_pids_listed_where_cgroup_kill_cannot_be_written() {
        let dir = std::env::temp_dir().join(format!("kithd-kill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("cgroup.kill")).unwrap();
        let mut sleeper = Command::new("sleep").arg("300").spawn().unwrap();
        std::fs::write(dir.join("cgroup.procs"), format!("{}\n", sleeper.id().unwrap())).unwrap();
        kill_cgroup(&dir);
        let status = tokio::time::timeout(Duration::from_secs(10), sleeper.wait()).await;
        let _ = std::fs::remove_dir_all(&dir);
        let status = status.expect("not killed").unwrap();
        assert_eq!(std::os::unix::process::ExitStatusExt::signal(&status), Some(9));
        kill_cgroup(&dir); // a cgroup that is gone is nothing to kill
    }

    /// Whatever is wrong with the ask, it is answered, not waited on.
    async fn answered(world: &World, spec: serde_json::Value) -> (u16, String) {
        let alice = world.user("alice");
        let asked = tunnel(&alice, world.a_port, "/v1/run", spec);
        tokio::time::timeout(Duration::from_secs(20), asked)
            .await
            .expect("no answer")
            .expect_err("a tunnel, for an ask that is wrong")
    }

    #[tokio::test]
    async fn run_answers_an_ask_that_names_no_program_or_has_a_nul_byte_or_is_too_big() {
        let world = World::new("asks").await;
        let (status, why) = answered(&world, json!({"on": "a", "argv": []})).await;
        assert_eq!((status, why.contains("names no program")), (400, true), "{why}");
        for spec in [
            json!({"on": "a", "via": stand_in(), "argv": ["tr\u{0}ue"]}),
            json!({"on": "a", "via": "way\u{0}pipe", "argv": ["true"]}),
        ] {
            let (status, why) = answered(&world, spec).await;
            assert_eq!((status, why.contains("NUL")), (400, true), "{why}");
        }
        let pad = "x".repeat(100 << 10);
        let (status, _) = answered(&world, json!({"on": "a", "argv": ["true"], "pad": pad})).await;
        assert_eq!(status, 413);
        // Nothing was started for any of them.
        let entries = world.a.audit.tail(10).unwrap_or_default();
        assert!(entries.iter().all(|entry| entry["verb"] != "run"), "{entries:?}");
    }

    /// An ask whose body never ends (so the upgrade is never reached) is answered when the time
    /// for the body is up, and does not hold the connection.
    #[tokio::test]
    async fn run_answers_an_ask_whose_body_never_ends() {
        let world = World::new("stalled").await;
        let alice = world.user("alice");
        let begun = Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{\"on\": \"a\", "));
        let body = futures_util::stream::once(async move { begun }).chain(futures_util::stream::pending());
        let ask = alice
            .post(format!("https://127.0.0.1:{}/v1/run", world.a_port))
            .header(reqwest::header::CONNECTION, "upgrade")
            .header(reqwest::header::UPGRADE, "kith-run")
            .body(reqwest::Body::wrap_stream(body))
            .send();
        let reply = tokio::time::timeout(Duration::from_secs(20), ask)
            .await
            .expect("no answer")
            .unwrap();
        assert_eq!(reply.status().as_u16(), 408);
    }

    /// A VIA that never connects: the tunnel ends when the time for it is up, and the program,
    /// the directory and the cgroup are gone.
    #[tokio::test]
    async fn run_ends_a_tunnel_whose_program_never_connects() {
        let world = World::new("start-timeout").await;
        let alice = world.user("alice");
        let spec = json!({"on": "a", "via": silent(), "argv": ["true"]});
        let mut tunnel = tunnel(&alice, world.a_port, "/v1/run", spec).await.unwrap();
        let mut rest = Vec::new();
        let read = tokio::time::timeout(START + Duration::from_secs(20), tunnel.read_to_end(&mut rest));
        // (Closed, whether with a goodbye or without one.)
        let _ = read.await.expect("the tunnel stays");
        let said = std::fs::read_to_string(format!("{}.said", silent())).unwrap();
        let (pid, socket) = said.trim().split_once(' ').unwrap();
        assert!(gone(&format!("/proc/{pid}")).await, "the program stays");
        let dir = Path::new(socket).parent().unwrap();
        assert!(gone(&dir.display().to_string()).await, "the directory stays");
    }

    #[tokio::test]
    async fn run_on_a_selector_is_the_first_ready_node_with_the_labels() {
        let world = World::new("selector").await;
        world.node("aa", "role: display", None);
        world.node("c", "role: display, zone: x", Some(1));
        let said = |on: &str| resolve(&world.a, on).map_err(|e| e.into_response().status().as_u16());
        let at = |name: &str, port: u16| {
            Some(crate::cluster::pinned_peer::at(
                name,
                &format!("127.0.0.1:{port}"),
                None,
            ))
        };
        assert_eq!(said("role=display"), Ok(("b".into(), at("b", world.b_port))));
        assert_eq!(said("role=display,zone=x"), Ok(("c".into(), at("c", 1))));
        assert_eq!(said("a"), Ok(("a".into(), None)));
        assert_eq!(said("b"), Ok(("b".into(), at("b", world.b_port))));
        assert_eq!(said("role=nothing"), Err(404));
        assert_eq!(said("nobody"), Err(404));
        assert_eq!(said("aa"), Err(422));
        assert_eq!(said("role=display,oops"), Err(422));
    }
}
