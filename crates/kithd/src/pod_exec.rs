//! `kubectl exec` and `kubectl cp` (a tar run by exec) into a replica: a process run in the
//! replica's own mount, pid and net namespaces on the node that runs it, its stdin, stdout, stderr
//! and exit status carried as the channels of a WebSocket (`v5.channel.k8s.io`, or `v4`): channel
//! 0 is stdin, 1 stdout, 2 stderr, 3 the Status that says how it ended, and `[255, 0]` (v5) that
//! stdin is over.
//!
//! ```text
//! kubectl --WebSocket--> node A (checks Exec on the pod's owner)
//!                          \-- replica here:  enters the container, speaks the channels
//!                          \-- replica there: POST /v1/pod-hop --> node B (checks it again in
//!                                             its own store, enters, speaks the channels)
//! ```
//! `/v1/pod-hop` is the one route between nodes for a pod: `kubectl port-forward` (kube/portforward.rs) asks
//! it for a byte stream to a port instead ([`Spec::Connect`]). It has one gate ([`hop`]) and one sender
//! ([`send`]); what the gate lets through is run by what the body asks.
//! Node A passes the client's bytes on without reading them (the WebSocket is the client's, to
//! node B, which is the one that answers it). A failure after the upgrade is a Status on channel
//! 3 and a close: a client that was refused an upgrade would fall back to another protocol.
//!
//! Not carried, said in that Status: a TTY, resize, attach to the main process, and a
//! NodeWorkload's pod (its unit runs on the host, not in a container).
//!
//! A process whose client has gone is killed (`pump` ends it, and `hop` ends one whose upgrade
//! fails), but not while kithd is blocked writing its stdin: that one ends when it does.
//! ponytail: its kill is the process's own, not what it started in turn.

use crate::Shared;
use crate::access::Caller;
use crate::api::permit;
use crate::cluster::{POD_HOP, Peer, refuse};
use crate::pki::Subject;
use crate::view::Upstream;
use crate::websocket::{self, Op};
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use hyper_util::rt::TokioIo;
use kith_api::kinds::Verb;
use kith_runtime::Entered;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::unix::pipe;
use tokio::sync::{Mutex, watch};

/// The largest frame a client may send: a frame longer than this is refused before its body is read.
// ponytail: one frame's bytes held at a time; a stdin larger than this comes as more frames.
pub(crate) const FRAME_MAX: usize = 1 << 20;

const PROTOCOL: &str = "kith-pod-hop";
/// How long the node that runs the replica has to answer the hop.
const HOP: Duration = Duration::from_secs(15);
/// How long a session may take to say how it ended and read the client's close back.
const FAREWELL: Duration = Duration::from_secs(5);
/// How long what a process wrote is carried on after it ended (a program it started may hold the pipe).
const DRAIN: Duration = Duration::from_secs(2);
/// The most a command may be, in bytes of all its words: the hop's body has room for it.
const COMMAND_MAX: usize = 32 << 10;

/// The most exec sessions open on this node at once, and the most one caller holds: each is a
/// process, three pipes and a task, so a loop of `kubectl exec` is refused, not queued.
const SESSIONS_MAX: usize = 64;
const PER_CALLER: usize = 8;

/// The sessions open now, by the caller that asked. (ponytail: one per process, as a node has one kithd.)
static OPEN: std::sync::Mutex<BTreeMap<String, usize>> = std::sync::Mutex::new(BTreeMap::new());

/// A place among the open sessions, given back when it is dropped.
struct Slot(String);

/// A place for a session of `who`, or the refusal that says which cap it met.
fn take(who: &str) -> Result<Slot, Failed> {
    let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
    let full = |why: String| Failed::new(429, "TooManyRequests", why);
    if open.values().sum::<usize>() >= SESSIONS_MAX {
        return Err(full(format!(
            "this node has {SESSIONS_MAX} exec sessions open: try again when one ends"
        )));
    }
    if open.get(who).is_some_and(|n| *n >= PER_CALLER) {
        return Err(full(format!(
            "{who} has {PER_CALLER} exec sessions open: end one first"
        )));
    }
    *open.entry(who.to_string()).or_default() += 1;
    Ok(Slot(who.to_string()))
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = open.get_mut(&self.0) {
            *n -= 1;
            if *n == 0 {
                open.remove(&self.0);
            }
        }
    }
}

/// What a client asked of `exec`, from the query of its request.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Ask {
    pub command: Vec<String>,
    pub container: Option<String>,
    pub stdin: bool,
}

/// An answer that is no: the Status's code and reason, and what it says.
#[derive(Debug)]
pub(crate) struct Failed {
    code: u16,
    reason: &'static str,
    pub(crate) message: String,
}

impl Failed {
    fn new(code: u16, reason: &'static str, message: impl std::fmt::Display) -> Failed {
        Failed {
            code,
            reason,
            message: message.to_string(),
        }
    }

    /// What another node's refusal of the hop says, as a Status says it.
    fn of(status: StatusCode, message: String) -> Failed {
        let reason = match status {
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => "Forbidden",
            StatusCode::NOT_FOUND => "NotFound",
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => "Invalid",
            StatusCode::TOO_MANY_REQUESTS => "TooManyRequests",
            _ => "InternalError",
        };
        Failed::new(status.as_u16(), reason, message)
    }

    fn status(&self) -> Value {
        json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Failure",
            "reason": self.reason, "code": self.code, "message": self.message,
        })
    }
}

impl Ask {
    /// The query of `exec`: `command` once for each word, `container`, and `stdin`, `stdout`,
    /// `stderr` and `tty` as `true` or `false`. A TTY is not carried.
    fn parse(query: &str) -> Result<Ask, Failed> {
        let invalid = |why: String| Failed::new(400, "BadRequest", why);
        let url = reqwest::Url::parse(&format!("http://kith/?{query}")).map_err(|e| invalid(e.to_string()))?;
        let mut ask = Ask::default();
        for (name, value) in url.query_pairs() {
            match &*name {
                "command" => ask.command.push(value.into_owned()),
                "container" => ask.container = Some(value.into_owned()).filter(|c| !c.is_empty()),
                "stdin" => ask.stdin = value == "true",
                "tty" if value == "true" => {
                    let why = "a TTY is not carried: run `kubectl exec` without -t";
                    return Err(Failed::new(501, "NotImplemented", why));
                }
                _ => {}
            }
        }
        if ask.command.is_empty() {
            return Err(invalid("exec asks for a command".into()));
        }
        if ask.command.iter().map(String::len).sum::<usize>() > COMMAND_MAX {
            return Err(invalid(format!("a command over {COMMAND_MAX} bytes is refused")));
        }
        Ok(ask)
    }
}

/// Where a pod's unit runs: its container's id, and the node.
struct Placed {
    id: String,
    node: String,
    /// Where to reach the node (`None`: this one).
    there: Option<Upstream>,
}

/// The container that `pod` of `namespace` is, by what this node's store holds, and the node that
/// runs it. The id is made from the stored resource, never from what the client sent.
fn place(shared: &Shared, namespace: &str, pod: &str, container: Option<&str>) -> Result<Placed, Failed> {
    let missing = || Failed::new(404, "NotFound", format!("pod {namespace}/{pod} is not found"));
    let me = shared.cluster.as_ref().map_or("local", |c| c.me.name.as_str());
    let state = shared.store.lock().expect("a handler panicked holding the store");
    // (A bare Pod's name too: it is held under the name it was sent as.)
    let (holder, owner, replica) = crate::kube::resolve_pod(&state.store, namespace, pod).ok_or_else(missing)?;
    if holder == "NodeWorkload" {
        let why = "a NodeWorkload's pod runs on the host, not in a container: `kith run` runs a command there";
        return Err(Failed::new(501, "NotImplemented", why));
    }
    let resource = state
        .store
        .get(&format!("{holder}/{namespace}/{owner}"))
        .ok_or_else(missing)?;
    let (id, _) = crate::controller::log_of(resource, container, replica)
        .map_err(|e| Failed::new(404, "NotFound", format!("pod {namespace}/{pod}: {e}")))?;
    // (A Job is run by one node, all of its runs.)
    let at = if holder == "Job" { 0 } else { replica };
    let status = resource.status.as_ref();
    let node = status.and_then(|s| s["nodes"][at.to_string()].as_str()).unwrap_or(me);
    let there = match node == me {
        true => None,
        false => {
            let known = state.store.get(&format!("Node/{node}")).and_then(Upstream::of);
            Some(known.ok_or_else(|| Failed::new(502, "InternalError", format!("node {node} is not known")))?)
        }
    };
    Ok(Placed {
        id,
        node: node.to_string(),
        there,
    })
}

/// Enters the container `id`, off the runtime's threads: it forks and waits for a helper.
async fn enter(id: String, command: Vec<String>) -> Result<Entered, Failed> {
    let entered = tokio::task::spawn_blocking(move || crate::root_part::enter(&id, &command)).await;
    match entered {
        Ok(Ok(entered)) => Ok(entered),
        Ok(Err(why)) => Err(Failed::new(422, "Invalid", why)),
        Err(e) => Err(Failed::new(500, "InternalError", e)),
    }
}

/// Where an exec that was let through runs: in a container here, or on the node that has it.
enum Run {
    Here(Entered, bool),
    There(reqwest::Upgraded),
}

/// The WebSocket of an upgraded `exec` of `pod`: the process is run here, or the node that runs
/// the replica is asked to, and what it does goes to the client. Ends when the session does.
pub async fn session<IO>(
    shared: Arc<Shared>,
    who: Caller,
    verb: String,
    namespace: String,
    pod: String,
    query: String,
    io: IO,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stop = shared.stop.subscribe();
    // (The slot is held until the session ends, whichever way it goes.)
    let (run, _slot) = match take(&who.to_string()) {
        Ok(slot) => (
            prepare(&shared, &who, &verb, &namespace, &pod, &query).await,
            Some(slot),
        ),
        Err(failed) => (Err(failed), None),
    };
    let failed = match run {
        Ok(Run::There(far)) => return crate::api::run::join(stop, io, far).await,
        Ok(Run::Here(run, stdin)) => {
            let (from, to) = tokio::io::split(io);
            return pump(from, &Mutex::new(to), run, stdin, stop).await;
        }
        Err(failed) => failed,
    };
    let (from, to) = tokio::io::split(io);
    let to = Mutex::new(to);
    // (The close frame's reason is what kubectl prints of a refusal: it holds 123 bytes.)
    let why: String = failed
        .message
        .chars()
        .scan(0, |n, c| {
            *n += c.len_utf8();
            (*n <= 123).then_some(c)
        })
        .collect();
    let said = status_frames(failed.status(), &websocket::close_body(1011, &why));
    farewell(&to, said, listen(from, &to, None)).await;
}

async fn prepare(
    shared: &Arc<Shared>,
    who: &Caller,
    verb: &str,
    namespace: &str,
    pod: &str,
    query: &str,
) -> Result<Run, Failed> {
    if verb == "attach" {
        let why = "attach to the main process is not carried: `kubectl exec` runs a process in the replica";
        return Err(Failed::new(501, "NotImplemented", why));
    }
    let ask = Ask::parse(query)?;
    let placed = place(shared, namespace, pod, ask.container.as_deref())?;
    let Some(there) = &placed.there else {
        return Ok(Run::Here(enter(placed.id, ask.command.clone()).await?, ask.stdin));
    };
    // The replica is on another node: its session is that node's, and this one passes the bytes.
    send(shared, who, namespace, pod, Spec::Exec(ask), &placed.node, there)
        .await
        .map(Run::There)
}

/// The one sender of the hop: asks the node that runs the replica to do `spec` for `who`, and gives the
/// connection it upgrades to (the client's WebSocket for an exec, a byte stream for a connect).
pub(crate) async fn send(
    shared: &Shared,
    who: &Caller,
    namespace: &str,
    pod: &str,
    spec: Spec,
    node: &str,
    there: &Upstream,
) -> Result<reqwest::Upgraded, Failed> {
    let Some(cluster) = &shared.cluster else {
        return Err(Failed::new(422, "Invalid", "this kithd is not part of a cluster"));
    };
    let hop = Hop {
        namespace: namespace.into(),
        pod: pod.into(),
        caller: who.to_string(),
        spec,
    };
    let down = |why: String| Failed::new(502, "InternalError", format!("node {node} {why}"));
    let client = cluster.to(there).map_err(|e| Failed::new(502, "InternalError", e))?;
    let send = crate::access_sign::pass_on(client.post(format!("https://{}{POD_HOP}", there.address)))
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, PROTOCOL)
        .json(&hop)
        .send();
    let reply = match tokio::time::timeout(HOP, send).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(e)) => return Err(down(format!("did not answer: {}", crate::cluster::why(&e)))),
        Err(_) => return Err(down("did not answer in time".into())),
    };
    let status = reply.status();
    if status != StatusCode::SWITCHING_PROTOCOLS {
        let said = reply.text().await.unwrap_or_default();
        let said: Value = serde_json::from_str(&said).unwrap_or(Value::String(said));
        let said = said["error"].as_str().map_or_else(|| said.to_string(), str::to_string);
        return Err(Failed::of(status, said));
    }
    match tokio::time::timeout(HOP, reply.upgrade()).await {
        Ok(Ok(far)) => Ok(far),
        Ok(Err(_)) => Err(down("did not give the session".into())),
        Err(_) => Err(down("did not give the session in time".into())),
    }
}

/// What node A asks node B: the pod, the caller, and what to do for it.
#[derive(Serialize, Deserialize)]
struct Hop {
    namespace: String,
    pod: String,
    /// Who asked node A.
    caller: String,
    spec: Spec,
}

/// What node B does for the pod: runs a command in it (the client's WebSocket is then node B's to answer), or
/// connects to a port of it and passes the bytes.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Spec {
    Exec(Ask),
    Connect { port: u16 },
}

/// `POST /v1/pod-hop`: the node that runs the replica, asked by the node the client reached
/// (members only). It checks, in its own store, that the caller named may exec on what runs the
/// pod (a connection to a port of it takes the same right), then does what the body asks on the connection it is given.
pub async fn hop(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    mut request: Request,
) -> Response {
    let say = |status, why: String| refuse(status, why).into_response();
    let Some(Subject::Node(from, ..)) = peer.subject else {
        return say(StatusCode::FORBIDDEN, "this is for the cluster's nodes".into());
    };
    if request.headers().get(header::UPGRADE).is_none_or(|v| v != PROTOCOL) {
        return say(StatusCode::BAD_REQUEST, format!("ask with `Upgrade: {PROTOCOL}`"));
    }
    let signed = request
        .headers()
        .get(crate::access_sign::SIGNED)
        .map(|header| header.to_str().unwrap_or_default().to_string());
    let path = request.uri().path_and_query().map_or(POD_HOP, |p| p.as_str());
    let path = path.to_string();
    let upgrade = hyper::upgrade::on(&mut request);
    let body = match to_bytes(request.into_body(), 64 << 10).await {
        Ok(body) => body,
        Err(e) => return say(StatusCode::PAYLOAD_TOO_LARGE, e.to_string()),
    };
    let hop: Hop = match serde_json::from_slice(&body) {
        Ok(hop) => hop,
        Err(e) => return say(StatusCode::BAD_REQUEST, e.to_string()),
    };
    // The first node checked the caller, and so does this one, in its own store: it takes a
    // node's word for who asked, not for what they may do.
    let Some(who) = Caller::named(&hop.caller) else {
        return say(
            StatusCode::BAD_REQUEST,
            format!("caller: {:?} is no caller a node passes on", hop.caller),
        );
    };
    let asked = crate::access_sign::Asked {
        method: "POST",
        path: &path,
        body: &body,
    };
    let held = crate::access_sign::hop(&shared, from.as_str(), signed.as_deref(), &asked, Some(&who), false);
    let who = crate::access::passed(&shared, from, who);
    let verb = match hop.spec {
        Spec::Exec(_) => "exec",
        Spec::Connect { .. } => "portforward",
    };
    let audit = |outcome| {
        let what = vec![format!("pod {}/{}", hop.namespace, hop.pod)];
        shared.audit.record(&who, verb, what, outcome);
    };
    if let Err(why) = held {
        audit(Err(why.clone()));
        return say(StatusCode::FORBIDDEN, why);
    }
    // (What the pod's name says is enough to ask: a caller without the right is refused whether or not the pod is there.)
    let named = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let named = crate::kube::resolve_pod(&state.store, &hop.namespace, &hop.pod);
        named.map(|(holder, owner, replica)| (holder, owner.to_string(), replica))
    };
    let Some((holder, owner, replica)) = named else {
        let why = format!("pod {}/{} is not found", hop.namespace, hop.pod);
        audit(Err(why.clone()));
        return say(StatusCode::NOT_FOUND, why);
    };
    let right = vec![(holder.to_string(), Some(hop.namespace.clone()))];
    if let Err(refused) = permit(&shared, &who, Verb::Exec, |_| right) {
        audit(Err("refused".into()));
        return refused.into_response();
    }
    // (Past the gate: what is asked is done here, or refused with a status that says why.)
    let done = match hop.spec {
        Spec::Exec(ask) => exec_here(&shared, &hop.namespace, &hop.pod, &hop.caller, ask, upgrade).await,
        // (A NodeWorkload's unit runs on the host: there is no pod to connect to.)
        Spec::Connect { .. } if holder == "NodeWorkload" => {
            let why = "port-forward does not reach a NodeWorkload's unit, which runs on the host";
            Err((StatusCode::NOT_IMPLEMENTED, why.to_string()))
        }
        Spec::Connect { port: 0 } => Err((StatusCode::BAD_REQUEST, "port 0 is no port".to_string())),
        Spec::Connect { port } => {
            let key = format!("{holder}/{}/{owner}", hop.namespace);
            crate::kube::portforward::tunnel(&shared, &key, replica, port, upgrade).await
        }
    };
    if let Err((status, why)) = done {
        audit(Err(why.clone()));
        return say(status, why);
    }
    audit(Ok(()));
    let mut reply = Response::new(Body::empty());
    *reply.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let headers = reply.headers_mut();
    headers.insert(header::CONNECTION, "upgrade".parse().expect("a header value"));
    headers.insert(header::UPGRADE, PROTOCOL.parse().expect("a header value"));
    reply
}

/// An exec the gate let through, run here: the container is entered and the client's connection (once it is
/// upgraded) is given to `pump`. The replica is on this node, or the hop is refused.
async fn exec_here(
    shared: &Arc<Shared>,
    namespace: &str,
    pod: &str,
    caller: &str,
    ask: Ask,
    upgrade: hyper::upgrade::OnUpgrade,
) -> Result<(), (StatusCode, String)> {
    let no = |failed: Failed, code| (code, failed.message);
    let placed = place(shared, namespace, pod, ask.container.as_deref()).map_err(|failed| {
        let code = StatusCode::from_u16(failed.code).unwrap_or(StatusCode::BAD_REQUEST);
        no(failed, code)
    })?;
    // (Passed on once: the node it is passed to is the one that runs it, or it is refused.)
    if placed.there.is_some() {
        let why = format!("pod {namespace}/{pod} does not run on this node");
        return Err((StatusCode::CONFLICT, why));
    }
    let slot = take(caller).map_err(|failed| no(failed, StatusCode::TOO_MANY_REQUESTS))?;
    let run = enter(placed.id, ask.command)
        .await
        .map_err(|failed| no(failed, StatusCode::UNPROCESSABLE_ENTITY))?;
    let (stop, stdin) = (shared.stop.subscribe(), ask.stdin);
    tokio::spawn(async move {
        let _slot = slot;
        match upgrade.await {
            Ok(upgraded) => {
                let (from, to) = tokio::io::split(TokioIo::new(upgraded));
                pump(from, &Mutex::new(to), run, stdin, stop).await;
            }
            // The client never took the connection: nobody is left to end the process.
            Err(_) => run.kill(),
        }
    });
    Ok(())
}

/// The Status on channel 3 and the close that follows it, as one write.
fn status_frames(status: Value, closing: &[u8]) -> Vec<u8> {
    let mut error = vec![3u8];
    error.extend_from_slice(status.to_string().as_bytes());
    [
        websocket::encode(Op::Binary, &error, None),
        websocket::encode(Op::Close, closing, None),
    ]
    .concat()
}

/// Says `said`, then waits for `closed` (the client's close read back), then shuts the connection
/// down: all of it in the [`FAREWELL`] a client that stopped answering is given.
async fn farewell<W: AsyncWrite + Unpin>(to: &Mutex<W>, said: Vec<u8>, closed: impl Future<Output = ()>) {
    let _ = tokio::time::timeout(FAREWELL, async {
        if to.lock().await.write_all(&said).await.is_err() {
            return;
        }
        closed.await;
        let _ = to.lock().await.shutdown().await;
    })
    .await;
}

/// Reads the client's frames until it closes or ends. What is on channel 0 goes to `stdin`,
/// `[255, 0]` ends it; a ping is answered with its pong. (A message in parts keeps the channel
/// its first part named.)
async fn listen<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut from: R,
    to: &Mutex<W>,
    mut stdin: Option<pipe::Sender>,
) {
    let (mut buf, mut channel) = (Vec::new(), None);
    loop {
        match websocket::decode(&buf, true, FRAME_MAX) {
            Ok(Some((frame, used))) => {
                buf.drain(..used);
                let data = match frame.op {
                    Op::Close => return,
                    Op::Ping => {
                        let pong = websocket::encode(Op::Pong, &frame.payload, None);
                        if to.lock().await.write_all(&pong).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    Op::Pong | Op::Text => continue,
                    Op::Binary => match frame.payload.split_first() {
                        Some((first, rest)) => {
                            channel = Some(*first);
                            // (v5's signal that a channel is closed: stdin's end.)
                            if *first == 255 && rest.first() == Some(&0) {
                                stdin = None;
                            }
                            rest.to_vec()
                        }
                        None => continue,
                    },
                    Op::Continue => frame.payload,
                };
                if let (Some(0), Some(pipe)) = (channel, stdin.as_mut())
                    && pipe.write_all(&data).await.is_err()
                {
                    stdin = None;
                }
            }
            Ok(None) => {
                let mut chunk = [0u8; 16 << 10];
                match from.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            Err(_) => return,
        }
    }
}

/// What `run` wrote to a pipe, as frames of `channel`, until it ends; a client that did not ask
/// for it (`kept`) has it read and dropped, so the process is not held up writing it.
async fn carry<W: AsyncWrite + Unpin>(to: &Mutex<W>, channel: u8, file: Option<std::fs::File>, kept: bool) {
    let Some(Ok(mut pipe)) = file.map(pipe::Receiver::from_file) else {
        return;
    };
    let mut chunk = [channel; 1 + (16 << 10)];
    loop {
        match pipe.read(&mut chunk[1..]).await {
            Ok(0) | Err(_) => return,
            Ok(n) if kept => {
                let frame = websocket::encode(Op::Binary, &chunk[..=n], None);
                if to.lock().await.write_all(&frame).await.is_err() {
                    return;
                }
            }
            Ok(_) => {}
        }
    }
}

/// The Status that says how a process ended: `Success`, or the exit code `kubectl` reads.
fn ended(code: Result<i32, String>) -> Value {
    match code {
        Ok(0) => json!({"kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Success"}),
        Ok(code) => json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Failure",
            "reason": "NonZeroExitCode",
            "message": format!("command terminated with non-zero exit code: exit status {code}"),
            "details": {"causes": [{"reason": "ExitCode", "message": code.to_string()}]},
        }),
        Err(why) => Failed::new(500, "InternalError", why).status(),
    }
}

/// Runs the session of `run` with the client: its output goes to the client as frames, what the
/// client sends to it, and when it ends, how, and the client's close read back. The client going
/// (or kithd stopping) ends the process.
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    from: R,
    to: &Mutex<W>,
    mut run: Entered,
    stdin: bool,
    mut stop: watch::Receiver<bool>,
) {
    let stdin = run
        .stdin
        .take()
        .filter(|_| stdin)
        .and_then(|file| pipe::Sender::from_file(file).ok());
    let (out, err) = (run.stdout.take(), run.stderr.take());
    let run = Arc::new(run);
    let mut wait = {
        let run = run.clone();
        tokio::task::spawn_blocking(move || run.wait().map_err(|e| e.to_string()))
    };
    let listening = listen(from, to, stdin);
    tokio::pin!(listening);
    let main = async {
        let drain = async { tokio::join!(carry(to, 1, out, true), carry(to, 2, err, true)) };
        tokio::pin!(drain);
        let code = tokio::select! {
            _ = &mut drain => (&mut wait).await,
            code = &mut wait => {
                let _ = tokio::time::timeout(DRAIN, &mut drain).await;
                code
            }
        };
        code.unwrap_or_else(|e| Err(e.to_string()))
    };
    let code = tokio::select! {
        code = main => code,
        _ = &mut listening => {
            // The client is gone: the process goes with it.
            run.kill();
            return;
        }
        _ = stop.wait_for(|stopped| *stopped) => {
            run.kill();
            return;
        }
    };
    let said = status_frames(ended(code), &websocket::close_body(1000, ""));
    farewell(to, said, &mut listening).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{DuplexStream, ReadBuf};

    /// The next frame the server sends, read from `client` with what `buf` already holds.
    async fn frame(client: &mut DuplexStream, buf: &mut Vec<u8>) -> websocket::Frame {
        loop {
            match websocket::decode(buf, false, FRAME_MAX) {
                Ok(Some((frame, used))) => {
                    buf.drain(..used);
                    return frame;
                }
                Ok(None) => {}
                Err(_) => panic!("the server sent a malformed frame"),
            }
            let mut chunk = [0u8; 4096];
            let n = client.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the server ended before its frame");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// A stream whose shutdown never completes, as a peer that stopped answering leaves it.
    struct StuckShutdown(DuplexStream);

    impl AsyncRead for StuckShutdown {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for StuckShutdown {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    /// A failure, as `session` ends it: the Status and the close, the client's close read back, the shutdown.
    async fn fail<IO: AsyncRead + AsyncWrite + Unpin>(io: IO) {
        let (from, to) = tokio::io::split(io);
        let to = Mutex::new(to);
        let said = status_frames(
            Failed::new(501, "NotImplemented", "x").status(),
            &websocket::close_body(1011, "x"),
        );
        farewell(&to, said, listen(from, &to, None)).await;
    }

    /// A caller holds at most `PER_CALLER` sessions and the node `SESSIONS_MAX`: the next is a
    /// named 429, and a place given back is free for the next.
    #[test]
    fn sessions_are_capped_per_caller_and_per_node_and_given_back() {
        let mut held: Vec<Slot> = (0..PER_CALLER).map(|_| take("cap-alice").unwrap()).collect();
        let refused = take("cap-alice").err().expect("a ninth session of one caller");
        assert_eq!((refused.code, refused.reason), (429, "TooManyRequests"));
        assert!(refused.message.contains("cap-alice"), "{}", refused.message);
        assert!(take("cap-bob").is_ok(), "another caller is not held up by it");
        held.pop();
        let again = take("cap-alice").expect("a place given back is free");
        drop((held, again));
        assert!(
            !OPEN.lock().unwrap().contains_key("cap-alice"),
            "no entry is left once all are back"
        );
        let many: Vec<Slot> = (0..SESSIONS_MAX).map(|n| take(&format!("cap-{n}")).unwrap()).collect();
        let refused = take("cap-last").err().expect("a session over the node's cap");
        assert!(
            refused.message.contains(&SESSIONS_MAX.to_string()),
            "{}",
            refused.message
        );
        drop(many);
        assert!(take("cap-last").is_ok());
    }

    #[test]
    fn exec_asks_for_a_command_in_the_words_it_was_sent_and_refuses_a_tty() {
        let ask = Ask::parse(
            "command=sh&command=-c&command=echo%20a%26b&container=app&stdin=true&stdout=true&stderr=true&tty=false",
        );
        assert_eq!(
            ask.ok(),
            Some(Ask {
                command: vec!["sh".into(), "-c".into(), "echo a&b".into()],
                container: Some("app".into()),
                stdin: true,
            })
        );
        assert_eq!(Ask::parse("command=ls&tty=true").err().map(|f| f.code), Some(501));
        assert_eq!(Ask::parse("stdout=true").err().map(|f| f.code), Some(400));
        let long = format!("command={}", "a".repeat(COMMAND_MAX + 1));
        assert_eq!(Ask::parse(&long).err().map(|f| f.code), Some(400));
    }

    /// What a process wrote is carried on its channel, and how it ended is the Status: Success for
    /// 0, and the code in a cause for any other.
    #[test]
    fn exec_says_how_a_process_ended_the_way_kubectl_reads_it() {
        assert_eq!(ended(Ok(0))["status"], "Success");
        let said = ended(Ok(7));
        assert_eq!(
            (&said["reason"], &said["details"]["causes"][0]["message"]),
            (&json!("NonZeroExitCode"), &json!("7"))
        );
        assert_eq!(ended(Err("lost".into()))["code"], 500);
    }

    #[tokio::test]
    async fn exec_answers_a_masked_ping_with_its_pong() {
        let (server, mut client) = tokio::io::duplex(1 << 16);
        let failing = tokio::spawn(fail(server));
        let mut buf = Vec::new();
        assert_eq!(frame(&mut client, &mut buf).await.op, Op::Binary);
        assert_eq!(frame(&mut client, &mut buf).await.op, Op::Close);
        client
            .write_all(&websocket::encode(Op::Ping, b"hi", Some([1, 2, 3, 4])))
            .await
            .unwrap();
        let pong = frame(&mut client, &mut buf).await;
        assert_eq!((pong.op, pong.payload.as_slice()), (Op::Pong, &b"hi"[..]));
        failing.abort();
    }

    #[tokio::test]
    async fn exec_ends_when_the_client_closes() {
        let (server, mut client) = tokio::io::duplex(1 << 16);
        let failing = tokio::spawn(fail(server));
        let mut buf = Vec::new();
        let said = frame(&mut client, &mut buf).await;
        assert_eq!(said.op, Op::Binary);
        assert_eq!(said.payload[0], 3, "the Status is on the error channel");
        assert_eq!(frame(&mut client, &mut buf).await.op, Op::Close);
        let closing = websocket::close_body(1000, "bye");
        client
            .write_all(&websocket::encode(Op::Close, &closing, Some([9, 8, 7, 6])))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), failing)
            .await
            .expect("it ends")
            .unwrap();
    }

    /// A client that never reads its reply does not hold the session past the five seconds.
    #[tokio::test(start_paused = true)]
    async fn exec_returns_within_the_cap_when_the_client_never_reads() {
        // A 16-byte buffer cannot take the reply, and the client keeps its end open without reading.
        let (server, _client) = tokio::io::duplex(16);
        let started = tokio::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(60), fail(server))
            .await
            .expect("it returned");
        assert!(started.elapsed() <= Duration::from_secs(6), "{:?}", started.elapsed());
    }

    const HOP_STORE: &str = "
apiVersion: kith.dev/v1
kind: Workload
metadata: {name: web, namespace: default}
spec: {replicas: 1, template: {exec: [{name: sleep, command: [sleep, '3600']}]}}
---
apiVersion: kith.dev/v1
kind: Workload
metadata: {name: far, namespace: default}
spec: {replicas: 1, template: {exec: [{name: sleep, command: [sleep, '3600']}]}}
---
apiVersion: kith.dev/v1
kind: Workload
metadata:
  name: solo
  namespace: default
  annotations:
    kith.dev/pod: 'true'
    kube.kith.dev/sent: '{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"solo\",\"namespace\":\"default\"}}'
spec: {replicas: 1, template: {exec: [{name: sleep, command: [sleep, '3600']}]}}
---
apiVersion: kith.dev/v1
kind: NodeWorkload
metadata: {name: agent, namespace: default}
spec: {template: {exec: [{name: sleep, command: [sleep, '3600']}]}}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: execer}
spec:
  rules:
    - {kinds: [Workload, NodeWorkload], verbs: [exec], namespaces: [default]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: alice-execer}
spec: {role: execer, subjects: [alice]}
";

    /// What the node the hop is sent to answers when it is asked as node a: the status and what it says.
    async fn ask_hop(client: &reqwest::Client, port: u16, caller: &str, pod: &str, spec: &Value) -> (u16, String) {
        ask_at(client, port, POD_HOP, caller, pod, spec).await
    }

    async fn ask_at(
        client: &reqwest::Client,
        port: u16,
        path: &str,
        caller: &str,
        pod: &str,
        spec: &Value,
    ) -> (u16, String) {
        let body = json!({"namespace": "default", "pod": pod, "caller": caller, "spec": spec});
        let reply = client
            .post(format!("https://127.0.0.1:{port}{path}"))
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, PROTOCOL)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = reply.status().as_u16();
        let said: Value = reply.json().await.unwrap_or_default();
        (status, said["error"].as_str().unwrap_or_default().to_string())
    }

    /// The two things a node is asked to do for a pod, as the hop's body says them.
    fn specs() -> [Value; 2] {
        [
            json!({"exec": {"command": ["true"], "container": null, "stdin": false}}),
            json!({"connect": {"port": 80}}),
        ]
    }

    /// The node the replica runs on asks its own store whether the caller a node names may exec,
    /// and answers for what it finds there, for an exec and for a connection to a port alike (one route, one
    /// gate); nothing is entered or connected for a caller it refuses.
    #[tokio::test]
    async fn hop_checks_the_named_caller_and_the_pod_on_the_node_it_arrives_at() {
        let world = crate::api::run::tests::World::new("pod-hop").await;
        let alice = world.user("alice");
        world.user("bob");
        for shared in [&world.a, &world.b] {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(HOP_STORE).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
            // web runs on b, far and the host's agent elsewhere.
            for (key, node) in [
                ("Workload/default/web", "b"),
                ("Workload/default/far", "a"),
                ("Workload/default/solo", "b"),
            ] {
                let unit = json!({"replica": 0, "node": node, "state": "running"});
                let status = json!({"nodes": {"0": node}, "containers": [unit]});
                state.store.set_status(key, Some(status)).unwrap();
            }
        }
        let a = world.a.cluster.as_ref().unwrap().client.clone();
        for spec in specs() {
            let ask = |caller: &'static str, pod: &'static str| ask_hop(&a, world.b_port, caller, pod, &spec);

            let (status, why) = ask("bob", "web-0").await;
            assert_eq!(status, 403, "{spec}: {why}");
            assert!(why.contains("bob via node a may not exec Workload"), "{why}");
            // Refused for what it is, whatever the pod: a caller without the right learns nothing of it.
            assert_eq!(ask("bob", "ghost-0").await.0, 403, "{spec}");
            assert_eq!(ask("mallory", "web-0").await.0, 403, "{spec}");
            // Not a caller a hop is for.
            for caller in ["node a", "alice via node b", ""] {
                assert_eq!(ask(caller, "web-0").await.0, 400, "{spec} {caller:?}");
            }
            // A pod that runs on another node is not reached from here, and no pod is not found.
            assert_eq!(ask("alice", "far-0").await.0, 409, "{spec}");
            assert_eq!(ask("alice", "ghost-0").await.0, 404, "{spec}");
            assert_eq!(ask("alice", "ghost").await.0, 404, "{spec}");
            // A NodeWorkload's pod is the host's, not a container's.
            assert_eq!(ask("alice", "agent-n0").await.0, 501, "{spec}");
            // An Identity is no node: the hop is not its way past node a.
            assert_eq!(ask_hop(&alice, world.b_port, "alice", "web-0", &spec).await.0, 403);
        }
        // Who may exec: the hop goes on to enter the container, which this node did not make, or to
        // connect to a pod that has no network here.
        let [exec, connect] = specs();
        let (status, why) = ask_hop(&a, world.b_port, "alice", "web-0", &exec).await;
        assert_eq!(status, 422, "{why}");
        assert!(why.contains("not a unit made here"), "{why}");
        // A bare Pod's replica on that node is found by its own name, as web-0 is: the exec goes on to enter.
        let (status, why) = ask_hop(&a, world.b_port, "alice", "solo", &exec).await;
        assert_eq!(status, 422, "{why}");
        assert_eq!(ask_hop(&a, world.b_port, "bob", "solo", &exec).await.0, 403);
        let (status, why) = ask_hop(&a, world.b_port, "alice", "web-0", &connect).await;
        assert_eq!(status, 502, "{why}");
        // Neither a spec that names nothing nor one that names both is a hop.
        for spec in [
            json!({}),
            json!({"exec": {"command": ["true"]}, "connect": {"port": 80}}),
            json!({"connect": {"port": 0}}),
        ] {
            let (status, why) = ask_hop(&a, world.b_port, "alice", "web-0", &spec).await;
            assert_eq!(status, 400, "{spec}: {why}");
        }

        let entries = world.b.audit.tail(60).unwrap();
        let verbs = |who: &str| {
            let refused = entries.iter().filter(|e| e["who"] == who && e["ok"] == false);
            refused
                .map(|e| e["verb"].as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        };
        let bob = verbs("bob via node a");
        assert!(
            bob.contains(&"exec".to_string()) && bob.contains(&"portforward".to_string()),
            "{bob:?}"
        );
        assert!(!verbs("alice via node a").is_empty(), "{entries:?}");
    }

    /// The two routes this one replaced are gone: a node that asks for either is told there is no such route,
    /// and a worker is refused this one as it was refused port-forward's.
    #[tokio::test]
    async fn hop_is_one_route_and_the_old_exec_route_is_gone() {
        let world = crate::api::run::tests::World::new("pod-hop-one").await;
        world.user("alice");
        for shared in [&world.a, &world.b] {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(HOP_STORE).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        let a = world.a.cluster.as_ref().unwrap().client.clone();
        let [exec, connect] = specs();
        for (path, spec) in [("/v1/exec-hop", &exec), ("/v1/exec-hop", &connect)] {
            assert_eq!(
                ask_at(&a, world.b_port, path, "alice", "web-0", spec).await.0,
                404,
                "{path}"
            );
        }
        assert_ne!(ask_at(&a, world.b_port, POD_HOP, "alice", "web-0", &exec).await.0, 404);
        // b's store says a is a worker: a worker's hop is refused for either, whoever it names.
        let text = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: a}\nspec: {trust: worker}\n";
        let node = kith_api::Resource::from_source(text).unwrap().remove(0).unwrap();
        world.b.store.lock().unwrap().store.apply(node).unwrap();
        for spec in [&exec, &connect] {
            let (status, why) = ask_hop(&a, world.b_port, "alice", "web-0", spec).await;
            assert_eq!(status, 403, "{why}");
            assert!(
                why.contains("node a is a worker: only a control node sends this"),
                "{why}"
            );
        }
    }

    /// The shutdown is inside the five seconds too: a shutdown that never completes is given up.
    #[tokio::test(start_paused = true)]
    async fn exec_gives_up_a_shutdown_that_never_completes() {
        let (server, mut client) = tokio::io::duplex(1 << 16);
        // The client's close is already sent, so the reading back ends at once and only the shutdown is left.
        let closing = websocket::close_body(1000, "");
        client
            .write_all(&websocket::encode(Op::Close, &closing, Some([1, 1, 1, 1])))
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(60), fail(StuckShutdown(server)))
            .await
            .expect("it returned");
        assert!(started.elapsed() <= Duration::from_secs(6), "{:?}", started.elapsed());
    }
}
