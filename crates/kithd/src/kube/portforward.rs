//! `kubectl port-forward POD LOCAL:REMOTE`: `/api/v1/namespaces/NS/pods/NAME/portforward`, a WebSocket
//! that speaks SPDY/3.1 (`SPDY/3.1+portforward.k8s.io`, spdy.rs). The Exec right on the Workload or Job
//! that owns the pod is checked before anything is upgraded (`pod_access`); the plain `POST` + `Upgrade:
//! SPDY/3.1` kubectl falls back to is not carried.
//!
//! One session is one WebSocket. Each local connection kubectl takes is a pair of streams with one
//! `requestid`: an error stream, then a data stream. The data stream's bytes go to the pod's port and back;
//! what goes wrong is said as text on the error stream; when the data stream ends both are FINed, which
//! is what makes kubectl close the local connection.
//!
//! The bytes go to the node that runs the replica over `POD_HOP`, the one hop route for a pod (pod_exec.rs):
//! it is asked for the pod and a port (`Spec::Connect`), never an address, and that node connects to the pod's
//! own address (`pods::connect`) after the same gate `exec` has: the caller the first node names and signs, and the
//! Exec right in its own store.
//!
//! Bounds: a caller has [`SESSIONS_MAX`] sessions at a node (counted at the upgrade, not by streams), a
//! session [`STREAMS_MAX`] connections, and a connection that moves no byte for [`idle`] ends.

use super::{Call, No, pod_access, status};
use crate::Shared;
use crate::access::Caller;
use crate::cluster::refuse;
use crate::ingress::Idle;
use crate::pod_exec::Spec;
use crate::spdy::{self, Frame, Reader, Writer};
use crate::view::Upstream;
use crate::websocket::{self, Op};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use kith_api::kinds::Verb;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};

/// The WebSocket subprotocol kubectl asks for, and the one between nodes.
const PROTOCOL: &str = "SPDY/3.1+portforward.k8s.io";
/// Sessions one caller holds at a node, and the connections one session carries at once.
const SESSIONS_MAX: usize = 8;
const STREAMS_MAX: usize = 16;
/// A connection that moves no byte for this long ends (`KITHD_PORTFORWARD_IDLE_MS` sets it in a debug build).
const IDLE: Duration = Duration::from_secs(300);
/// The node that runs the replica has this long to answer, and the pod's port to accept.
const HOP: Duration = Duration::from_secs(15);
/// What a WebSocket frame may hold (kubectl writes 4 KiB pieces), what is read from a pod at once, and how many
/// frames wait for the client and how many chunks of its bytes wait for a pod.
const FRAME_MAX: usize = 64 << 10;
const CHUNK: usize = 32 << 10;
const QUEUE: usize = 64;
const BACKLOG: usize = 4;

fn idle() -> Duration {
    if !cfg!(debug_assertions) {
        return IDLE;
    }
    let set = std::env::var("KITHD_PORTFORWARD_IDLE_MS")
        .ok()
        .filter(|_| cfg!(debug_assertions));
    set.and_then(|ms| ms.parse().ok()).map_or(IDLE, Duration::from_millis)
}

/// What a byte stream to a pod's port is, here or through another node.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Sessions per caller, by who the first node says asked.
static SESSIONS: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());

/// A place among a caller's sessions, given back when dropped.
struct Held(String);

impl Held {
    fn take(who: &str) -> Option<Held> {
        let mut held = SESSIONS.lock().expect("nothing panics holding the sessions");
        let count = held.entry(who.to_string()).or_default();
        if *count >= SESSIONS_MAX {
            return None;
        }
        *count += 1;
        Some(Held(who.to_string()))
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut held = SESSIONS.lock().expect("nothing panics holding the sessions");
        if let Some(count) = held.get_mut(&self.0) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.0);
            }
        }
    }
}

/// The replica a session reaches and who asked.
#[derive(Clone)]
struct Owner {
    key: String,
    namespace: String,
    pod: String,
    replica: u32,
    caller: Caller,
}

/// `GET .../pods/NAME/portforward`: the right on what runs the pod, then the upgrade. Each decision is in the audit log.
pub(super) async fn forward(
    call: &Call,
    namespace: &str,
    pod: &str,
    method: &str,
    headers: &HeaderMap,
    upgrade: Option<OnUpgrade>,
) -> Result<Response, No> {
    let decided = decide(call, namespace, pod, method, headers, upgrade);
    let outcome = decided.as_ref().map(|_| ()).map_err(|no| no.why.clone());
    let what = vec![format!("pod {namespace}/{pod}")];
    call.shared.audit.record(&call.caller, "portforward", what, outcome);
    decided
}

fn decide(
    call: &Call,
    namespace: &str,
    pod: &str,
    method: &str,
    headers: &HeaderMap,
    upgrade: Option<OnUpgrade>,
) -> Result<Response, No> {
    let (holder, key, replica) = pod_access(call, namespace, pod)?;
    if holder == "NodeWorkload" {
        let why = "port-forward does not reach a NodeWorkload's unit, which runs on the host";
        return Err(status(StatusCode::NOT_IMPLEMENTED, "NotImplemented", why.into()));
    }
    // (The name says which replica; the owner's status says whether there is one: a replica past the last has no pod.)
    place(&call.shared, &key, replica).map_err(|why| status(StatusCode::NOT_FOUND, "NotFound", why))?;
    // kubectl sends no Origin: one is a browser's.
    if headers.contains_key(header::ORIGIN) {
        let why = "an upgrade that carries an Origin is refused: kubectl sends none";
        return Err(status(StatusCode::FORBIDDEN, "Forbidden", why.into()));
    }
    let said = |name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    };
    let offered = said(header::SEC_WEBSOCKET_PROTOCOL)
        .split(',')
        .any(|one| one.trim() == PROTOCOL);
    let upgrading = said(header::UPGRADE).eq_ignore_ascii_case("websocket")
        && said(header::CONNECTION).to_ascii_lowercase().contains("upgrade")
        && said(header::SEC_WEBSOCKET_VERSION) == "13";
    let accept = crate::websocket::accept_key(said(header::SEC_WEBSOCKET_KEY));
    let (Some(upgrade), Some(accept), true, true, "GET") = (upgrade, accept, offered, upgrading, method) else {
        let why =
            format!("port-forward is a WebSocket: a GET that upgrades, with version 13 and the protocol {PROTOCOL}");
        return Err(status(StatusCode::BAD_REQUEST, "BadRequest", why));
    };
    let who = call.caller.to_string();
    let Some(held) = Held::take(&who) else {
        let why = format!("{who} has {SESSIONS_MAX} port-forward sessions at this node: one has to end first");
        return Err(status(StatusCode::TOO_MANY_REQUESTS, "TooManyRequests", why));
    };
    let shared = call.shared.clone();
    let owner = Owner {
        key,
        namespace: namespace.to_string(),
        pod: pod.to_string(),
        replica,
        caller: call.caller.clone(),
    };
    tokio::spawn(async move {
        if let Ok(upgraded) = upgrade.await {
            session(shared, owner, TokioIo::new(upgraded), held).await;
        }
    });
    Ok((
        StatusCode::SWITCHING_PROTOCOLS,
        [
            (header::UPGRADE, "websocket".to_string()),
            (header::CONNECTION, "Upgrade".to_string()),
            (header::SEC_WEBSOCKET_ACCEPT, accept),
            (header::SEC_WEBSOCKET_PROTOCOL, PROTOCOL.to_string()),
        ],
    )
        .into_response())
}

fn wire(frame: Vec<u8>) -> Vec<u8> {
    websocket::encode(Op::Binary, &frame, None)
}

/// One WebSocket, until the client closes it, it breaks the protocol or kithd stops.
async fn session(shared: Arc<Shared>, owner: Owner, io: TokioIo<Upgraded>, _held: Held) {
    let (mut read, write) = tokio::io::split(io);
    let (out, queue) = mpsc::channel::<Vec<u8>>(QUEUE);
    let gone = out.clone();
    let mut writer = tokio::spawn(drain(queue, write, idle()));
    let mut stop = shared.stop.subscribe();
    let mut at = Session {
        shared,
        owner,
        out,
        reply: Writer::new(),
        requests: HashMap::new(),
        tasks: JoinSet::new(),
        last: 0,
    };
    let (code, why) = tokio::select! {
        ended = at.run(&mut read) => ended,
        _ = stop.wait_for(|stopped| *stopped) => (1001, "kithd is stopping".to_string()),
        _ = gone.closed() => (1011, "the client reads nothing".to_string()),
    };
    // (Every connection ends before the queue's last sender does; the close is the last frame.)
    at.tasks.shutdown().await;
    let close = websocket::encode(Op::Close, &websocket::close_body(code, &why), None);
    // (A client that reads nothing is let hold the close and the writer for five seconds each, and no longer.)
    let _ = tokio::time::timeout(Duration::from_secs(5), at.out.send(close)).await;
    drop((at, gone));
    if tokio::time::timeout(Duration::from_secs(5), &mut writer).await.is_err() {
        writer.abort();
    }
}

/// Writes what is queued for the client until the queue ends, or a write takes `wait`: a client that reads nothing is let
/// hold one frame that long, then the queue closes and every sender sees it.
async fn drain(mut queue: mpsc::Receiver<Vec<u8>>, mut write: impl AsyncWrite + Unpin, wait: Duration) {
    while let Some(bytes) = queue.recv().await {
        if !matches!(tokio::time::timeout(wait, write.write_all(&bytes)).await, Ok(Ok(()))) {
            return;
        }
    }
    let _ = write.shutdown().await;
}

/// The connections of a session: a request is the error stream and the data stream of one.
struct Pending {
    port: u16,
    error: u32,
    data: Option<u32>,
    /// What the client sends on the data stream, on its way to the pod (dropped: it sent FIN).
    input: Option<mpsc::Sender<Vec<u8>>>,
    abort: Option<AbortHandle>,
}

struct Session {
    shared: Arc<Shared>,
    owner: Owner,
    out: mpsc::Sender<Vec<u8>>,
    reply: Writer,
    requests: HashMap<String, Pending>,
    /// One task for each connection that has both its streams; it gives its request id when it ends.
    tasks: JoinSet<String>,
    last: u32,
}

impl Session {
    /// Reads until the WebSocket ends: its close code and reason.
    async fn run(&mut self, read: &mut (impl AsyncRead + Unpin)) -> (u16, String) {
        let mut spdy = Reader::new();
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            loop {
                match websocket::decode_with(&buf, true, FRAME_MAX, true) {
                    Ok(Some((frame, used))) => {
                        buf.drain(..used);
                        match frame.op {
                            Op::Binary | Op::Continue => spdy.push(&frame.payload),
                            Op::Ping => {
                                let pong = websocket::encode(Op::Pong, &frame.payload, None);
                                if self.out.send(pong).await.is_err() {
                                    return (1011, "the connection is gone".into());
                                }
                            }
                            Op::Close => return (1000, String::new()),
                            Op::Text => return (1003, "SPDY is binary".into()),
                            Op::Pong => {}
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return (1002, "a frame that is not one".into()),
                }
            }
            loop {
                match spdy.next() {
                    Ok(Some(frame)) => {
                        if let Err(ended) = self.handle(frame).await {
                            return ended;
                        }
                    }
                    Ok(None) => break,
                    Err(why) => return (1002, why),
                }
            }
            tokio::select! {
                // A session with no connection that hears nothing for the idle time ends (a connection ends by its own).
                _ = tokio::time::sleep(idle()), if self.tasks.is_empty() => return (1000, "idle".into()),
                read = read.read(&mut chunk) => match read {
                    Ok(0) | Err(_) => return (1000, String::new()),
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                },
                Some(done) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    if let Ok(request) = done {
                        self.requests.remove(&request);
                    }
                }
            }
        }
    }

    async fn say(&self, frame: Vec<u8>) -> Result<(), (u16, String)> {
        let gone = |_| (1011, "the connection is gone".to_string());
        self.out.send(wire(frame)).await.map_err(gone)
    }

    async fn handle(&mut self, frame: Frame) -> Result<(), (u16, String)> {
        match frame {
            Frame::Open { id, headers } => self.open(id, &headers).await,
            Frame::Data { id, fin, data } => {
                // (Data on an error stream is ignored: kubectl FINs it as soon as it is open.)
                if let Some(request) = self.requests.values_mut().find(|request| request.data == Some(id)) {
                    if let Some(input) = &request.input
                        && !data.is_empty()
                        && input.send(data).await.is_err()
                    {
                        request.input = None;
                    }
                    if fin {
                        request.input = None;
                    }
                }
                Ok(())
            }
            Frame::Reset { id } => {
                let found = self.requests.iter().find(|(_, r)| r.error == id || r.data == Some(id));
                let found = found.map(|(request, _)| request.clone());
                if let Some(request) = found.and_then(|request| self.requests.remove(&request))
                    && let Some(abort) = request.abort
                {
                    abort.abort();
                }
                Ok(())
            }
            Frame::Ping(payload) => self.say(self.reply.ping(&payload)).await,
            Frame::GoAway => Err((1000, String::new())),
            Frame::Skip => Ok(()),
        }
    }

    /// A stream the client opens: the error stream of a new connection, or its data stream.
    async fn open(&mut self, id: u32, headers: &[(String, String)]) -> Result<(), (u16, String)> {
        let get = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, value)| value.as_str());
        let port = get("port")
            .and_then(|port| port.parse::<u16>().ok())
            .filter(|port| *port != 0);
        let (Some(request), Some(kind), Some(port), true) = (get("requestid"), get("streamtype"), port, id % 2 == 1)
        else {
            return self.say(self.reply.reset(id, spdy::PROTOCOL)).await;
        };
        // (Ids a client opens are odd and rise.)
        if id <= self.last {
            return self.say(self.reply.reset(id, spdy::PROTOCOL)).await;
        }
        self.last = id;
        // The right is asked again for each connection: a session that is upgraded does not outlast it being taken away.
        if kind == "data" && may_exec(&self.shared, &self.owner.caller, &self.owner.key).is_err() {
            if let Some(open) = self.requests.remove(request) {
                open.abort.iter().for_each(|task| task.abort());
            }
            return self.say(self.reply.reset(id, spdy::REFUSED)).await;
        }
        let full = self.requests.len() >= STREAMS_MAX;
        match (kind, self.requests.get_mut(request)) {
            ("error", None) if full => self.say(self.reply.reset(id, spdy::REFUSED)).await,
            ("error", None) => {
                let new = Pending {
                    port,
                    error: id,
                    data: None,
                    input: None,
                    abort: None,
                };
                self.requests.insert(request.to_string(), new);
                let reply = self.reply.reply(id);
                self.say(reply).await
            }
            ("data", Some(open)) if open.data.is_none() && open.port == port => {
                open.data = Some(id);
                let (input, backlog) = mpsc::channel(BACKLOG);
                open.input = Some(input);
                let error = open.error;
                let task = connection(
                    self.shared.clone(),
                    self.owner.clone(),
                    request.to_string(),
                    port,
                    (error, id),
                    backlog,
                    self.out.clone(),
                );
                let abort = self.tasks.spawn(task);
                if let Some(open) = self.requests.get_mut(request) {
                    open.abort = Some(abort);
                }
                let reply = self.reply.reply(id);
                self.say(reply).await
            }
            _ => self.say(self.reply.reset(id, spdy::PROTOCOL)).await,
        }
    }
}

/// One connection: the data stream's bytes to the pod's port and back until one side ends, then both streams are
/// FINed; why it went wrong, if it did, is said as text on the error stream first. Gives the request.
async fn connection(
    shared: Arc<Shared>,
    owner: Owner,
    request: String,
    port: u16,
    (error, data): (u32, u32),
    mut input: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<Vec<u8>>,
) -> String {
    let spdy = Writer::new();
    let send = |id: u32, fin: bool, bytes: &[u8]| put(&out, wire(spdy.data(id, fin, bytes)), idle());
    let said = match reach(&shared, &owner, port).await {
        Err(why) => Some(why),
        Ok(pod) => {
            let (mut from_pod, mut to_pod) = tokio::io::split(pod);
            let up = async {
                while let Some(chunk) = input.recv().await {
                    to_pod.write_all(&chunk).await?;
                }
                to_pod.shutdown().await
            };
            let down = async {
                let mut chunk = vec![0u8; CHUNK];
                loop {
                    let n = from_pod.read(&mut chunk).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    send(data, false, &chunk[..n]).await?;
                }
            };
            // The client's end of its bytes is no end of the connection: the pod may still answer. The pod's is.
            let ended = tokio::select! {
                ended = down => ended,
                ended = async {
                    let ended = up.await;
                    if ended.is_ok() {
                        std::future::pending::<()>().await;
                    }
                    ended
                } => ended,
            };
            // (A silent connection that idles out is ended without a word: any text on the error stream ends kubectl
            // itself, and with it every other connection of the session.)
            ended
                .err()
                .filter(|e| e.kind() != std::io::ErrorKind::TimedOut)
                .map(|e| e.to_string())
        }
    };
    // (Each is given up on after the idle time, and a client that took none of them is not asked the next.)
    if let Some(why) = said
        && send(error, false, why.as_bytes()).await.is_err()
    {
        return request;
    }
    if send(data, true, &[]).await.is_ok() {
        let _ = send(error, true, &[]).await;
    }
    request
}

/// A frame for the client, given up on after `wait`: a client that reads nothing keeps no connection here.
async fn put(out: &mpsc::Sender<Vec<u8>>, frame: Vec<u8>, wait: Duration) -> std::io::Result<()> {
    match tokio::time::timeout(wait, out.send(frame)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(std::io::Error::other("the client is gone")),
        Err(_) => Err(std::io::ErrorKind::TimedOut.into()),
    }
}

/// Where the replica `replica` of `key` runs: `None` is this node, else the node and where to reach it.
fn place(shared: &Shared, key: &str, replica: u32) -> Result<Option<(String, Upstream)>, String> {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let owner = state.store.get(key).ok_or("what runs the pod is gone")?;
    let units = owner.status.as_ref().and_then(|status| status["containers"].as_array());
    let unit = units
        .into_iter()
        .flatten()
        .find(|unit| unit["replica"] == replica && unit["state"] != "exited");
    let unit = unit.ok_or_else(|| format!("replica {replica} has no unit that runs"))?;
    let me = shared.cluster.as_ref().map(|cluster| cluster.me.name.as_str());
    let node = match (unit["node"].as_str(), me) {
        (None, _) | (_, None) => return Ok(None),
        (Some(node), Some(me)) if node == me => return Ok(None),
        (Some(node), _) => node,
    };
    let there = state.store.get(&format!("Node/{node}")).and_then(Upstream::of);
    let there = there.ok_or_else(|| format!("node {node} has no address"))?;
    Ok(Some((node.to_string(), there)))
}

/// A connection to `port` of the pod that is the replica, on this node: through the pod's own namespace and no other
/// way (a pod not made yet is refused, not answered by the host's loopback). A byte that moves renews its idle time
/// (`idle`). A debug build with `KITHD_PORTFORWARD_HOST` set reaches the loopback instead, for a test that has no
/// network to make a pod with.
async fn pod(shared: &Shared, key: &str, replica: u32, port: u16) -> Result<Idle<TcpStream>, String> {
    let live = {
        let pods = shared.pods.lock().expect("nothing panics holding the pods");
        pods.live_id(&crate::controller::pod_of(key, replica)).to_string()
    };
    let host = cfg!(debug_assertions) && std::env::var_os("KITHD_PORTFORWARD_HOST").is_some();
    let connecting = async {
        match host {
            true => crate::pods::connect(Some((shared, &live)), port).await,
            false => crate::pods::connect_made(&shared.pods, &live, port).await,
        }
    };
    let stream = tokio::time::timeout(HOP, connecting).await;
    let stream = stream.map_err(|_| format!("port {port} did not answer in {} s", HOP.as_secs()))?;
    let stream = stream.map_err(|e| format!("port {port} of the pod: {e}"))?;
    Ok(Idle::new(stream, idle(), None))
}

/// A byte stream to `port` of the replica, from the node that runs it (through its `POD_HOP` when that is another).
async fn reach(shared: &Shared, owner: &Owner, port: u16) -> Result<Box<dyn Io>, String> {
    let Some((node, there)) = place(shared, &owner.key, owner.replica)? else {
        return Ok(Box::new(pod(shared, &owner.key, owner.replica, port).await?));
    };
    let spec = Spec::Connect { port };
    let far = crate::pod_exec::send(shared, &owner.caller, &owner.namespace, &owner.pod, spec, &node, &there)
        .await
        .map_err(|failed| failed.message)?;
    Ok(Box::new(Idle::new(far, idle(), None)))
}

/// The Exec right of `who` on what owns `key`, a Workload's or a Job's replica and nothing else: the key is parsed,
/// never trusted as a path.
fn may_exec(shared: &Shared, who: &Caller, key: &str) -> Result<(), Box<Response>> {
    let mut parts = key.splitn(3, '/');
    let (Some(kind @ ("Workload" | "Job")), Some(namespace)) = (parts.next(), parts.next()) else {
        return Err(Box::new(say(
            StatusCode::BAD_REQUEST,
            format!("{key:?} is no Workload or Job"),
        )));
    };
    let held = vec![(kind.to_string(), Some(namespace.to_string()))];
    crate::api::permit(shared, who, Verb::Exec, |_| held).map_err(|refused| Box::new(refused.into_response()))
}

fn say(code: StatusCode, why: impl std::fmt::Display) -> Response {
    refuse(code, why).into_response()
}

/// The far end of a `Spec::Connect` hop (`pod_exec::hop` has checked the caller and the right): connects to `port` of
/// the replica, which has to run on this node, and passes the bytes of the upgraded connection both ways.
pub(crate) async fn tunnel(
    shared: &Arc<Shared>,
    key: &str,
    replica: u32,
    port: u16,
    upgrade: OnUpgrade,
) -> Result<(), (StatusCode, String)> {
    match place(shared, key, replica) {
        Ok(None) => {}
        Ok(Some(_)) => return Err((StatusCode::CONFLICT, "that replica does not run on this node".into())),
        Err(why) => return Err((StatusCode::NOT_FOUND, why)),
    }
    let mut pod = pod(shared, key, replica, port)
        .await
        .map_err(|why| (StatusCode::BAD_GATEWAY, why))?;
    let mut stop = shared.stop.subscribe();
    tokio::spawn(async move {
        if let Ok(upgraded) = upgrade.await {
            // (Idle: a node that reads nothing is no more let hold the pod's bytes than a client is.)
            let mut near = Idle::new(TokioIo::new(upgraded), idle(), None);
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut near, &mut pod) => {}
                _ = stop.wait_for(|stopped| *stopped) => {}
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portforward_a_caller_has_as_many_sessions_as_the_bound_and_a_place_is_given_back() {
        let held: Vec<_> = (0..SESSIONS_MAX)
            .map(|_| Held::take("test-caller").expect("within the bound"))
            .collect();
        assert!(Held::take("test-caller").is_none());
        assert!(Held::take("test-other").is_some(), "another caller's own");
        drop(held);
        assert!(Held::take("test-caller").is_some());
    }

    #[tokio::test]
    async fn portforward_a_client_that_reads_nothing_frees_every_sender_and_its_queue_closes() {
        // (A pipe of 8 bytes nobody reads: the writer is stuck in its first frame.)
        let (client, _unread) = tokio::io::duplex(8);
        let (out, queue) = mpsc::channel(1);
        let writer = tokio::spawn(drain(queue, client, Duration::from_millis(100)));
        out.send(vec![0; 64]).await.unwrap();
        out.send(vec![0; 64]).await.unwrap();
        // The third waits for room, until the writer gives up and the queue closes: an error, not a wait for ever.
        let third = put(&out, vec![1], Duration::from_secs(30)).await.unwrap_err();
        assert_ne!(third.kind(), std::io::ErrorKind::TimedOut, "{third}");
        tokio::time::timeout(Duration::from_secs(5), out.closed())
            .await
            .expect("the queue is closed");
        tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .expect("the writer ended")
            .unwrap();
    }

    #[tokio::test]
    async fn portforward_a_frame_that_finds_no_room_is_given_up_after_the_wait() {
        let (out, _queue) = mpsc::channel(1);
        out.send(vec![0]).await.unwrap();
        let said = put(&out, vec![1], Duration::from_millis(50)).await.unwrap_err();
        assert_eq!(said.kind(), std::io::ErrorKind::TimedOut);
    }
}
