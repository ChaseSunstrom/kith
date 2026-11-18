//! This node's replica of the store, and Raft between nodes (PLAN.md §4.3).
//!
//! ```text
//! POST /v1/raft/append | vote | snapshot    Raft's own messages
//! POST /v1/raft/write  Command -> [reply, log index] | null    for the leader; null: ask again
//! ```
//! Members only. Every change goes through [`Shared::submit`]: the leader puts it in
//! the log, and each node applies it to its own copy once a majority has it on disk.
//! Reads are answered from the node's own copy, which may be a moment behind.
//
// ponytail: Raft messages are JSON over the node API (a snapshot is an array of numbers).
// Fine for stores of a few MB; a binary body is the upgrade if snapshots get slow.

use crate::access::{self, Caller};
use crate::access_sign;
use crate::cluster::Peer;
use crate::{Shared, pki};
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use kith_api::store::Error;
use kith_store::openraft::error::{
    ClientWriteError, InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError, Unreachable,
};
use kith_store::openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use kith_store::openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse, VoteRequest,
    VoteResponse,
};
use kith_store::openraft::{BasicNode, ChangeMembers};
use kith_store::{Command, Done, NodeId, Reply, TypeConfig};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// How Raft reaches the other nodes: the node API, as this node, each link held to the voter it
/// is for. The store is opened with the network, so what a link looks the voter's Node up in is
/// set once the node's state is made: until then, and outside a cluster, a link reaches no one.
#[derive(Clone, Default)]
pub struct Network(pub Arc<OnceLock<Weak<Shared>>>);

pub struct Link {
    shared: Arc<OnceLock<Weak<Shared>>>,
    target: NodeId,
    address: String,
    /// The last refusal or failure put in the log, so a link that fails at every heartbeat says it once.
    said: Option<String>,
}

impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = Link;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Link {
        Link {
            shared: self.0.clone(),
            target,
            address: node.addr.clone(),
            said: None,
        }
    }
}

/// What the store says of the voter whose Raft id is `id`.
enum Found {
    /// No Node carries the id.
    No,
    /// The Node that does: its name, and the print of its key where it names one.
    One(String, Option<String>),
    /// Two or more Nodes carry it: none of them is known to be the voter.
    Many,
}

fn voter(shared: &Shared, id: NodeId) -> Found {
    let state = shared.store.lock().expect("nothing panics holding the store");
    let id = id.to_string();
    let named = |node: &&kith_api::Resource| {
        node.status
            .as_ref()
            .is_some_and(|status| status["raftId"].as_str() == Some(&id))
    };
    let mut nodes = state.store.list(Some("Node")).filter(named);
    let print = |node: &kith_api::Resource| node.status.as_ref()?["certificate"].as_str().map(str::to_string);
    match (nodes.next(), nodes.next()) {
        (None, _) => Found::No,
        (Some(node), None) => Found::One(node.metadata.name.clone(), print(node)),
        (Some(_), Some(_)) => Found::Many,
    }
}

/// The client for the voter `id`, held to it: to the name and key of the Node that has that id,
/// and, for a voter with no Node in the store (a join, an empty store, a Node deleted), to a name
/// that gives the id. With the name its Node has, for a log line; the error says who was called
/// and who answered, or why no one is.
pub(crate) fn to_voter(shared: &Shared, id: NodeId) -> Result<(reqwest::Client, Option<String>), String> {
    let cluster = shared.cluster.as_ref().ok_or("this node is not in a cluster")?;
    match voter(shared, id) {
        Found::One(name, print) => Ok((cluster.to_name(&name, print)?, Some(name))),
        Found::No => Ok((cluster.to_voter(id)?, None)),
        Found::Many => Err(format!(
            "two Nodes of the store have the raft id {id}, so none is known to be the voter: nothing is sent"
        )),
    }
}

/// Whether the candidate voter `id`, at `address`, is there: it answers for the CA, as itself.
async fn answers(shared: &Shared, id: NodeId, address: &str) -> bool {
    let Ok((client, _)) = to_voter(shared, id) else {
        return false;
    };
    let asked = client.get(format!("https://{address}/v1/ca"));
    asked.timeout(Duration::from_secs(2)).send().await.is_ok()
}

impl Link {
    /// Put in the log what a link cannot do, once for each text.
    fn say(&mut self, said: String) {
        if self.said.as_ref() != Some(&said) {
            eprintln!("kithd: {said}");
            self.said = Some(said);
        }
    }

    // The error type is openraft's.
    #[allow(clippy::result_large_err)]
    async fn call<Q, A, E>(
        &mut self,
        what: &str,
        rpc: &Q,
        option: RPCOption,
    ) -> Result<A, RPCError<NodeId, BasicNode, E>>
    where
        Q: Serialize,
        A: DeserializeOwned,
        E: std::error::Error + DeserializeOwned,
    {
        let unreachable = |why: &str| Unreachable::new(&std::io::Error::other(why.to_string()));
        let shared = self.shared.get().and_then(Weak::upgrade);
        let shared = shared.ok_or_else(|| unreachable("this node is not in a cluster"))?;
        let (client, name) = match to_voter(&shared, self.target) {
            Ok(held) => held,
            Err(why) => {
                self.say(format!("raft link at {}: {why}", self.address));
                return Err(unreachable(&why).into());
            }
        };
        // A marked store is sent whole only to a kithd that said it reads one: a kithd from
        // before would take the snapshot, drop when each resource was made, and order by what
        // is left. (It is heard before: a link sends entries, or a heartbeat, first.)
        let marked = shared
            .store
            .lock()
            .expect("nothing panics holding the store")
            .store
            .marked();
        let said = heard(self.target).map(|(format, _)| format);
        let to = name.map_or(String::new(), |name| format!(" to node {name}"));
        if marked && what == "snapshot" && said.is_none_or(|said| said < kith_store::FORMAT) {
            let why = "no snapshot is sent: the store is in format 2, and its kithd has not said it reads that";
            self.say(format!(
                "raft link{to} at {}: {why} (update it, if it is older)",
                self.address
            ));
            return Err(unreachable(why).into());
        }
        let call = client.post(format!("https://{}/v1/raft/{what}", self.address));
        let reply = call.timeout(option.hard_ttl()).json(rpc).send().await;
        // (Whatever it answers, it is the voter that answers: what its kithd reads is heard.)
        if let Ok(reply) = &reply {
            let said = reply
                .headers()
                .get(READS)
                .and_then(|said| said.to_str().ok()?.parse().ok());
            let said = (said.unwrap_or(1), Instant::now());
            HEARD
                .lock()
                .expect("nothing panics holding what was heard")
                .insert(self.target, said);
        }
        let reply = reply.and_then(reqwest::Response::error_for_status);
        let reply = reply.map_err(|e| {
            // (An entry a kithd from before cannot read is refused by it as a bad request.)
            let older = marked && heard(self.target).is_some_and(|(said, _)| said < kith_store::FORMAT);
            let update = if older {
                " (the store is in format 2, which its kithd does not read: update it)"
            } else {
                ""
            };
            self.say(format!(
                "raft link{to} at {}: {}{update}",
                self.address,
                crate::cluster::why(&e)
            ));
            Unreachable::new(&e)
        })?;
        self.said = None;
        let reply: Result<A, E> = reply.json().await.map_err(|e| NetworkError::new(&e))?;
        reply.map_err(|e| RemoteError::new(self.target, e).into())
    }
}

type Rpc<A, E = kith_store::openraft::error::Infallible> = Result<A, RPCError<NodeId, BasicNode, RaftError<NodeId, E>>>;

impl RaftNetwork<TypeConfig> for Link {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Rpc<AppendEntriesResponse<NodeId>> {
        self.call("append", &rpc, option).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Rpc<InstallSnapshotResponse<NodeId>, InstallSnapshotError> {
        self.call("snapshot", &rpc, option).await
    }

    async fn vote(&mut self, rpc: VoteRequest<NodeId>, option: RPCOption) -> Rpc<VoteResponse<NodeId>> {
        self.call("vote", &rpc, option).await
    }
}

/// What other nodes' Raft calls. A snapshot chunk is 3 MiB of bytes, each written as a number.
pub fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/v1/raft/append", post(append))
        .route("/v1/raft/vote", post(vote))
        .route("/v1/raft/snapshot", post(snapshot))
        .route("/v1/raft/write", post(write))
        .layer(DefaultBodyLimit::max(64 << 20))
        .with_state(shared)
}

type Answer<A, E = kith_store::openraft::error::Infallible> = Json<Result<A, RaftError<NodeId, E>>>;

async fn append(
    State(shared): State<Arc<Shared>>,
    Json(rpc): Json<AppendEntriesRequest<TypeConfig>>,
) -> Answer<AppendEntriesResponse<NodeId>> {
    Json(shared.raft.append_entries(rpc).await)
}

async fn vote(State(shared): State<Arc<Shared>>, Json(rpc): Json<VoteRequest<NodeId>>) -> Answer<VoteResponse<NodeId>> {
    Json(shared.raft.vote(rpc).await)
}

async fn snapshot(
    State(shared): State<Arc<Shared>>,
    Json(rpc): Json<InstallSnapshotRequest<TypeConfig>>,
) -> Answer<InstallSnapshotResponse<NodeId>, InstallSnapshotError> {
    Json(shared.raft.install_snapshot(rpc).await)
}

/// The empty writes (the controller's barrier before it starts a unit) each worker last sent.
static BARRIERS: Mutex<BTreeMap<String, Instant>> = Mutex::new(BTreeMap::new());

/// Whether worker `name` may do a thing at `now` that it may do once `every`, `last` being
/// when each last did it.
fn due(last: &mut BTreeMap<String, Instant>, name: &str, now: Instant, every: Duration) -> bool {
    let soon = |at: &Instant| now.duration_since(*at) < every;
    if last.get(name).is_some_and(soon) {
        return false;
    }
    // (What is older holds nobody back: the map is as long as the workers of the last `every`.)
    last.retain(|_, at| soon(at));
    last.insert(name.to_string(), now);
    true
}

/// The most a worker's write may be. A report of 300 units, each with a long message and
/// notes, is 131 KiB (`worker_bound_is_several_times_an_honest_report`).
const WORKER_WRITE: usize = 1 << 20;
/// Writes a second a worker may send a control node, and how many at once after a rest. A
/// write counts one, and one more for each whole 64 KiB: so 640 KiB a second at the most.
const WORKER_RATE: f64 = 10.0;
const WORKER_BURST: f64 = 50.0;

/// How long a worker's write may take to send (its buffer is held meanwhile); a moment in
/// tests, which send one that never ends.
const BODY_PATIENCE: Duration = Duration::from_secs(if cfg!(test) { 2 } else { 15 });

/// What a worker's write of `bytes` counts for against [`WORKER_RATE`].
fn cost(bytes: usize) -> f64 {
    1.0 + (bytes >> 16) as f64
}

/// `node`'s report of `statuses` as writes a worker may make: whole statuses, as many as fit
/// in half of [`WORKER_WRITE`] each. (One status larger than that is a write of its own, and
/// is refused for its size: the rest of the report still lands.)
pub(crate) fn in_parts(node: &str, statuses: Vec<(String, Option<serde_json::Value>)>) -> Vec<Command> {
    let mut parts: Vec<Vec<_>> = Vec::new();
    let mut size = 0;
    for status in statuses {
        let more = serde_json::to_vec(&status).map_or(0, |bytes| bytes.len());
        match parts.last_mut() {
            Some(part) if size + more <= WORKER_WRITE / 2 => part.push(status),
            _ => {
                parts.push(vec![status]);
                size = 0;
            }
        }
        size += more;
    }
    let report = |statuses| Command::Report {
        node: node.to_string(),
        statuses,
    };
    parts.into_iter().map(report).collect()
}

/// What each worker that wrote lately may still write: how much, and when that was counted;
/// and when the workers that may write their whole burst again were last let go.
#[derive(Default)]
struct Spent {
    buckets: BTreeMap<String, (f64, Instant)>,
    pruned: Option<Instant>,
}

static SPENT: Mutex<Spent> = Mutex::new(Spent {
    buckets: BTreeMap::new(),
    pruned: None,
});

/// Take `cost` from what worker `name` may write at `now`; or, taking nothing, how long until it may.
fn spend(spent: &mut Spent, name: &str, cost: f64, now: Instant) -> Result<(), Duration> {
    let has =
        |(left, at): &(f64, Instant)| (left + now.duration_since(*at).as_secs_f64() * WORKER_RATE).min(WORKER_BURST);
    let had = spent.buckets.get(name).map_or(WORKER_BURST, has);
    if had < cost {
        return Err(Duration::from_secs_f64((cost - had) / WORKER_RATE));
    }
    // (A worker that may write its whole burst again is as one that never wrote: the map is as
    // long as the workers of the last few seconds. Looked over every few seconds, not each write.)
    if spent
        .pruned
        .is_none_or(|at| now.duration_since(at) >= Duration::from_secs(5))
    {
        spent.buckets.retain(|_, bucket| has(bucket) < WORKER_BURST);
        spent.pruned = Some(now);
    }
    spent.buckets.insert(name.to_string(), (had - cost, now));
    Ok(())
}

/// Take `cost` from what worker `name` may write; past its rate, the answer that says how long to wait.
fn over_rate(shared: &Shared, name: &str, cost: f64) -> Option<Response> {
    let mut spent = SPENT.lock().expect("nothing panics holding what workers spent");
    let wait = spend(&mut spent, name, cost, Instant::now()).err()?;
    drop(spent);
    let why = format!(
        "a worker writes at most {WORKER_RATE} times a second (a write counts once more for each 64 KiB), \
         and {name} wrote more: asked again in {} ms",
        wait.as_millis()
    );
    audit_throttled(shared, name, "rate", &why);
    Some(too_many(wait, why))
}

/// The refusals of a worker, of a kind, held to a line a minute in the audit log: when the
/// last was written, and how many have not been since.
type Said = BTreeMap<(String, &'static str), (Instant, u64)>;
static SAID: Mutex<Said> = Mutex::new(BTreeMap::new());

/// Does worker `name`'s refusal of `kind` at `now` open a minute in the audit log? If so, how
/// many of that kind were not written since the last that was.
fn throttled(said: &mut Said, name: &str, kind: &'static str, now: Instant) -> Option<u64> {
    let minute = Duration::from_secs(60);
    let key = (name.to_string(), kind);
    match said.get_mut(&key) {
        Some((at, unwritten)) if now.duration_since(*at) < minute => {
            *unwritten += 1;
            return None;
        }
        _ => {}
    }
    // (A minute with nothing unwritten has nothing left to say: the map is as long as the
    // workers refused in the last minute, and those with a count still to give.)
    said.retain(|_, (at, unwritten)| *unwritten > 0 || now.duration_since(*at) < minute);
    Some(said.insert(key, (now, 0)).map_or(0, |(_, unwritten)| unwritten))
}

/// Put worker `name`'s refused write in the audit log.
fn audit(shared: &Shared, name: &str, why: String) {
    let who = crate::access::Caller::Node(name.to_string());
    shared
        .audit
        .record(&who, "POST", vec!["/v1/raft/write".into()], Err(why));
}

/// [`audit`] a refusal for the size or the rate of worker `name`'s write: a line a minute of
/// each kind, which says how many were not written since the last.
fn audit_throttled(shared: &Shared, name: &str, kind: &'static str, why: &str) {
    let unwritten = throttled(
        &mut SAID.lock().expect("nothing panics holding the refusals said"),
        name,
        kind,
        Instant::now(),
    );
    match unwritten {
        None => {}
        Some(0) => audit(shared, name, why.to_string()),
        // (First: the audit log cuts a long error short.)
        Some(n) => audit(shared, name, format!("{n} more not written since the last: {why}")),
    }
}

/// A worker's write past its rate: 429, and when to send it again (whole seconds, at least one).
fn too_many(wait: Duration, why: String) -> Response {
    let seconds = (wait.as_secs_f64().ceil() as u64).max(1);
    let wait = [(header::RETRY_AFTER, seconds.to_string())];
    (
        StatusCode::TOO_MANY_REQUESTS,
        wait,
        Json(serde_json::json!({ "error": why })),
    )
        .into_response()
}

/// How long a control node that answered 429 asks a write to wait (`Retry-After`): a second at least
/// (one that says none would be asked again at once, and again), a minute at most.
pub(crate) fn wait_of(reply: &reqwest::Response) -> Duration {
    let said = reply.headers().get(reqwest::header::RETRY_AFTER);
    let seconds = said.and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    Duration::from_secs(seconds.unwrap_or(1).clamp(1, 60))
}

/// What a worker's write becomes, held to what a worker may write (`crate::worker`):
/// `Ok(None)` for a barrier that comes too soon after its last (asked again in a moment).
fn from_worker(shared: &Shared, name: &str, command: Command) -> Result<Option<Command>, String> {
    if matches!(&command, Command::Patch { statuses } if statuses.is_empty()) {
        let mut last = BARRIERS.lock().expect("nothing panics holding the barriers");
        return Ok(due(&mut last, name, Instant::now(), Duration::from_secs(1)).then_some(command));
    }
    let blobs = crate::blobs::dir(shared);
    let held = |blob: &str| blobs.join(blob).exists();
    let prefix = shared
        .cluster
        .as_ref()
        .map(|cluster| crate::mesh::prefix(&cluster.me.ca));
    let who = crate::worker::Worker {
        name,
        prefix,
        held: &held,
    };
    let state = shared.store.lock().expect("a handler panicked holding the store");
    crate::worker::checked(&state.store, &who, command).map(Some)
}

/// Is the node `name`, which sends a write, a worker? `None` where this node has no Node for it.
fn sender(store: &kith_api::store::Store, name: &str) -> Option<bool> {
    let node = store.get(&format!("Node/{name}"))?;
    Some(node.spec["trust"] == "worker")
}

/// The node a change came from.
fn sent_by(peer: &Peer) -> String {
    match &peer.subject {
        Some(pki::Subject::Node(node, ..)) => node.clone(),
        _ => "unknown".into(),
    }
}

/// Who signed a change a control node passed on (its signature for this node, as it came),
/// where that holds. Under `spec.signing: required` a node's word for whose write it is
/// (`who`) stands only with their signature; a change it sends as its own is its own.
fn signer(
    shared: &Shared,
    peer: &Peer,
    headers: &axum::http::HeaderMap,
    uri: &axum::http::Uri,
    body: &[u8],
    who: Option<&Caller>,
) -> Result<Option<access_sign::Signed>, String> {
    let path = uri.path_and_query().map_or(uri.path(), |path| path.as_str());
    let asked = access_sign::Asked {
        method: "POST",
        path,
        body,
    };
    let header = headers
        .get(access_sign::SIGNED)
        .map(|header| header.to_str().unwrap_or_default());
    // (`who` is the Identity, as the node names it: not the node it came through.)
    let named = who.and_then(Caller::identity).map(|name| Caller::Identity(name.into()));
    access_sign::hop(shared, &sent_by(peer), header, &asked, named.as_ref(), true)
}

/// A change another node passes to the leader: the reply and where in the log it is. A
/// control node's is given to Raft as it comes; a worker's is held to its size, its rate
/// and its list first.
async fn write(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    body: Body,
) -> Response {
    let worker = match &peer.subject {
        Some(pki::Subject::Node(name, ..)) => {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            match sender(&state.store, name) {
                // No Node for it here (this node is behind, or was started to admit deleted
                // nodes): what it may write is not known, so it is asked again, not taken.
                None => return Json(None::<(Reply, u64)>).into_response(),
                Some(worker) => worker.then(|| name.clone()),
            }
        }
        _ => None,
    };
    let Some(name) = worker else {
        let Ok(bytes) = axum::body::to_bytes(body, 64 << 20).await else {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        };
        let command: Command = match serde_json::from_slice(&bytes) {
            Ok(command) => command,
            Err(e) => return (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response(),
        };
        // The Identity a control node passes the write on for, if it says one: whose Roles
        // are asked again here, in the log's order (a node that says none is let write as itself).
        let who = match headers
            .get(access::FOR)
            .map(|name| name.to_str().ok().and_then(Caller::named))
        {
            None => None,
            Some(Some(Caller::Identity(name))) => Some(Caller::Via(sent_by(&peer), Box::new(Caller::Identity(name)))),
            Some(_) => {
                let why = format!("{} names no Identity", access::FOR);
                return Json(Some((Err::<Done, _>(Error::Invalid(why)), 0u64))).into_response();
            }
        };
        // Decided only where the log is led: a node that no longer leads may be behind, and
        // sends it back to be passed to whichever does.
        let leads = {
            let metrics = shared.raft.metrics();
            let metrics = metrics.borrow();
            metrics.current_leader == Some(metrics.id)
        };
        if !leads {
            return Json(None::<(Reply, u64)>).into_response();
        }
        let signed = match signer(&shared, &peer, &headers, &uri, &bytes, who.as_ref()) {
            Ok(signed) => signed,
            Err(why) => {
                let caller = who.clone().unwrap_or_else(|| Caller::Node(sent_by(&peer)));
                shared
                    .audit
                    .record(&caller, "write", vec![uri.path().into()], Err(why.clone()));
                return Json(Some((Err::<Done, _>(Error::Invalid(why)), 0u64))).into_response();
            }
        };
        // On a task of its own: a sender that hangs up neither lets go of the turn while the
        // write is on its way nor stops it.
        let shared = shared.clone();
        let done = tokio::spawn(access_sign::within(signed, async move {
            let turn = shared.turn(&command, who.as_ref()).await?;
            let written = tokio::time::timeout(PATIENCE, shared.raft.client_write(command)).await;
            drop(turn);
            Ok(match written {
                Ok(Ok(written)) => Some((written.data, written.log_id.index)),
                _ => None,
            })
        }));
        return Json(match done.await {
            Ok(Ok(written)) => written,
            Ok(Err(refused)) => Some((Err::<Done, Error>(refused), 0u64)),
            Err(_) => None,
        })
        .into_response();
    };
    let refused = |why: String| Json(Some((Err::<Done, _>(Error::Invalid(why)), 0u64))).into_response();
    let too_large = |why: String| {
        audit_throttled(&shared, &name, "size", &why);
        refused(why)
    };
    let audited = |why: String| {
        audit(&shared, &name, why.clone());
        refused(why)
    };
    // Every write of a worker counts, refused or not, for the size it says it is (once, where
    // it says none), and past its rate it is not read.
    let most = WORKER_WRITE >> 10;
    let declared = headers.get(header::CONTENT_LENGTH);
    let declared = declared.and_then(|length| length.to_str().ok()?.parse::<u64>().ok());
    let charged = declared.map_or(1.0, |bytes| cost(bytes.min(WORKER_WRITE as u64) as usize));
    if let Some(wait) = over_rate(&shared, &name, charged) {
        return wait;
    }
    if let Some(bytes) = declared.filter(|bytes| *bytes > WORKER_WRITE as u64) {
        let said = bytes >> 10;
        return too_large(format!(
            "a worker's write is at most {most} KiB, and this one says it is {said} KiB"
        ));
    }
    // (Its buffer is held while it comes: a write that stalls is let go.)
    let read = tokio::time::timeout(BODY_PATIENCE, axum::body::to_bytes(body, WORKER_WRITE)).await;
    let bytes = match read {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            return too_large(format!(
                "a worker's write is at most {most} KiB, and this one was not read whole ({e})"
            ));
        }
        Err(_) => {
            let why = format!(
                "a worker's write was not sent in {} s, and is let go",
                BODY_PATIENCE.as_secs()
            );
            audit_throttled(&shared, &name, "slow", &why);
            return refused(why);
        }
    };
    // (What else it counts for, now that its size is known: one that did not say.)
    let more = cost(bytes.len()) - charged;
    if more > 0.0
        && let Some(wait) = over_rate(&shared, &name, more)
    {
        return wait;
    }
    let command: Command = match serde_json::from_slice(&bytes) {
        Ok(command) => command,
        Err(e) => return audited(format!("not a change: {e}")),
    };
    match from_worker(&shared, &name, command) {
        // (Through this node to whichever leads: a worker asks one control node.)
        Ok(Some(command)) => Json(passed(&shared, command).await).into_response(),
        Ok(None) => Json(None::<(Reply, u64)>).into_response(),
        Err(why) => audited(why),
    }
}

/// A worker's change that was held to its list, made as this node's own: asked again
/// (`None`) while the store takes no change.
async fn passed(shared: &Shared, command: Command) -> Option<(Reply, u64)> {
    match shared.write_at(command).await {
        Ok((done, index)) => Some((Ok(done), index)),
        Err(Error::Io(_)) => None,
        Err(refused) => Some((Err(refused), 0)),
    }
}

/// How long a change waits for a leader and a majority.
const PATIENCE: Duration = Duration::from_secs(10);

fn unavailable(why: impl std::fmt::Display) -> Error {
    Error::Io(format!("the store cannot take changes now: {why}"))
}

impl Shared {
    /// Make a change to the store, on every node. Returns once this node has applied it.
    //
    // ponytail: a change whose answer is lost (the leader died after writing it, or was
    // too slow) is reported as failed although it may have happened, and a change that is
    // tried again here after such a loss can find its own first try: a delete then says
    // "not found", an apply that names a revision "conflict". Request ids kept in the
    // state machine are the fix when that matters.
    pub async fn submit(&self, command: Command) -> Result<Done, Error> {
        self.submit_as(command, None).await
    }

    /// [`Shared::submit`] for `who`: an Identity's write is decided again where it is put in
    /// the log ([`Shared::turn`]).
    pub async fn submit_as(&self, command: Command, who: Option<&Caller>) -> Result<Done, Error> {
        // What every writer is asked, a Release's, a Source's and a controller's too: these
        // are not rules of the API alone. (Asked of this node's store: of two writes at once
        // both can pass, and then each node's own rule decides, `pods::chosen`.)
        if let Command::Apply { resources, .. } = &command {
            let state = self.store.lock().expect("a handler panicked holding the store");
            let asked = crate::blobs::put_first(&state.store, resources)
                .and_then(|()| crate::exits::admitted(&state.store, resources))
                .and_then(|()| crate::pods::unshared(&state.store, resources))
                .and_then(|()| crate::access::runs_as(&state.store, resources))
                .and_then(|()| {
                    self.cluster.as_ref().map_or(Ok(()), |cluster| {
                        crate::services::unclaimed(&state.store, crate::mesh::prefix(&cluster.me.ca), resources)
                    })
                });
            asked.map_err(Error::Invalid)?;
        }
        self.write_as(command, who).await.map(|(done, _)| done)
    }

    /// [`Shared::submit`] for the blob store's own Blobs: the bytes were just put.
    pub async fn write(&self, command: Command) -> Result<Done, Error> {
        self.write_at(command).await.map(|(done, _)| done)
    }

    /// [`Shared::write`], and the index of the log the change is at: this node has applied it.
    pub async fn write_at(&self, command: Command) -> Result<(Done, u64), Error> {
        self.write_as(command, None).await
    }

    /// Leave to put `command` in the log here, to be held until it is in: decided again for
    /// an Identity, in the log's order with what changes access.
    ///
    /// A change to who may do what (a Role, a RoleBinding, an Identity, a KindDefinition, or a
    /// whole store) is put in the log by itself, nothing of an Identity's on its way beside it, and is applied
    /// here before its leave is given back. An Identity's write waits for what is in this
    /// node's log to be applied, and is asked about again on the store that makes: a Role taken
    /// away before it is in the log is a Role it no longer has. Everything else goes as it comes.
    /// Each wait is held to [`PATIENCE`]: past it the write is refused, to be tried again.
    /// An Identity's own access change is held to both: alone, and asked about again.
    //
    // ponytail: the leave is held until the change is applied, not only until it is in the log
    // (openraft 0.9 says nothing between): an Identity's write waits for it to be applied anyway.
    pub(crate) async fn turn(
        &self,
        command: &Command,
        who: Option<&Caller>,
    ) -> Result<Option<Box<dyn Send + '_>>, Error> {
        let alone = changes_access(command);
        let caller = who.filter(|who| who.identity().is_some());
        if caller.is_none() && !alone {
            return Ok(None);
        }
        let asked = async {
            let held: Box<dyn Send + '_> = match alone {
                true => Box::new(self.order.write().await),
                false => Box::new(self.order.read().await),
            };
            if caller.is_some() {
                let last = self.raft.metrics().borrow().last_log_index;
                let wait = self.raft.wait(None);
                wait.applied_index_at_least(last, "access decided again")
                    .await
                    .map_err(unavailable)?;
            }
            Ok(held)
        };
        let late = unavailable("an access change before this write is not applied yet; try again");
        let held = tokio::time::timeout(PATIENCE, asked).await.map_err(|_| late)??;
        let refused = caller.and_then(|caller| {
            let state = self.store.lock().expect("a handler panicked holding the store");
            crate::api::refused(&state.store, caller, command)
        });
        // The admin's key and whether callers sign, by the store as it is in this turn.
        let refused = refused.or_else(|| {
            let state = self.store.lock().expect("a handler panicked holding the store");
            access_sign::guard(&state.store, command, access_sign::by_admin()).err()
        });
        match refused {
            Some(why) => Err(Error::Invalid(why)),
            None => Ok(Some(held)),
        }
    }

    /// [`Shared::submit_as`] after the blobs: [`Shared::write_at`] for `who`.
    async fn write_as(&self, command: Command, who: Option<&Caller>) -> Result<(Done, u64), Error> {
        // Whoever applies, here is where a kind's admission module is asked.
        let command = match command {
            Command::Apply { resources, at } => {
                let resources = self.admitted(resources).await?;
                Command::Apply { resources, at }
            }
            Command::Rollback { key, to, at } => {
                self.restorable(&key, to).await?;
                Command::Rollback { key, to, at }
            }
            other => other,
        };
        // A worker that runs from a view has no Raft: the control node it follows is asked.
        let viewing = self.view.borrow().is_some();
        if viewing {
            return crate::view::write(self, &command).await;
        }
        let deadline = Instant::now() + PATIENCE;
        let mut refused = None;
        loop {
            let turn = self.turn(&command, who).await?;
            let written = tokio::time::timeout(PATIENCE, self.raft.client_write(command.clone())).await;
            // (Let go before the leader is asked: it holds its own.)
            drop(turn);
            let leader = match written {
                Ok(Ok(written)) => return written.data.map(|done| (done, written.log_id.index)),
                Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(to)))) => to.leader_id.zip(to.leader_node),
                Ok(Err(e)) => return Err(unavailable(e)),
                Err(_) => return Err(no_majority(refused)),
            };
            if let Some((id, leader)) = leader {
                match self.forward(id, &leader, &command, who).await {
                    Forward::Done(reply, index) => return reply.map(|done| (done, index)),
                    Forward::Failed(e) => return Err(e),
                    Forward::Again(why) => refused = why.or(refused),
                    Forward::Wait(wait, why) if Instant::now() + wait > deadline => return Err(rate_wait(&why)),
                    // (Waited already: asked again at once, and the deadline still ahead.)
                    Forward::Wait(wait, _) => {
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                }
            }
            if Instant::now() > deadline {
                return Err(no_majority(refused));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// The change, sent to the leader the store says is node `id`.
    //
    // The change may hold a Secret: it goes to the node the leader is by its Node, and to no
    // other at that address. A leader no Node names is not sent it; asking again waits for
    // the store to say.
    async fn forward(&self, id: NodeId, leader: &BasicNode, command: &Command, who: Option<&Caller>) -> Forward {
        let named = {
            let state = self.store.lock().expect("a handler panicked holding the store");
            let node = state.store.list(Some("Node")).find(|node| {
                let status = node.status.as_ref();
                status.is_some_and(|status| status["raftId"].as_str() == Some(&id.to_string()))
            });
            node.and_then(crate::view::Upstream::of)
        };
        let at = &leader.addr;
        let (Some(there), Some(cluster)) = (named, &self.cluster) else {
            return Forward::Again(Some(format!("no Node names the leader (raft id {id}) at {at}")));
        };
        let client = match cluster.to(&there) {
            Ok(client) if !at.is_empty() => client,
            Ok(_) => return Forward::Again(None),
            Err(e) => return Forward::Again(Some(e)),
        };
        // A signed apply, delete or rollback goes to the leader as it came (its method, path, body and
        // header), and the leader runs it as its own route would (its audit names that route): a
        // Command re-serialized would not be what was signed. `carries` checks the route matches.
        if let Some(relay) = access_sign::current().and_then(|signed| signed.relay) {
            if relay.carries(command) {
                let url = format!("https://{at}{}", relay.path);
                let call = match command {
                    Command::Delete { .. } => client.delete(url),
                    _ => client.post(url),
                }
                .header(access::FOR, relay.who.to_string())
                .header("content-type", "application/json")
                .body(relay.body);
                return self.relayed(access_sign::pass_on(call), at, command).await;
            }
        }
        let mut call = access_sign::pass_on(client.post(format!("https://{at}/v1/raft/write")));
        // Whose write it is, for the leader to decide again in the log's order (`write`).
        if let Some(name) = who.and_then(Caller::identity) {
            call = call.header(access::FOR, name);
        }
        match call.timeout(PATIENCE).json(command).send().await {
            // Only a worker is held to a rate (this one keeps the log, as a learner): it sends
            // the change again once the leader says it may, if that is before its deadline.
            Ok(reply) if reply.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                let wait = wait_of(&reply);
                Forward::Wait(wait, format!("the leader at {at} asked to wait {} s", wait.as_secs()))
            }
            Ok(reply) => {
                if let Ok(Some((reply, index))) = reply.json::<Option<(Reply, u64)>>().await {
                    // What a client writes through this node, it can read from this node.
                    let caught_up = self.raft.wait(Some(PATIENCE));
                    let _ = caught_up.applied_index_at_least(Some(index), "own write").await;
                    return Forward::Done(reply, index);
                }
                Forward::Again(None)
            }
            // Never reached it (or refused it, which is the same to the change): nothing
            // happened, and asking again is safe.
            Err(e) if e.is_connect() => Forward::Again(Some(format!(
                "the leader at {at} was not reached: {}",
                crate::cluster::why(&e)
            ))),
            Err(e) => {
                let why = format!(
                    "the leader at {at} did not answer ({}); look before trying again",
                    crate::cluster::why(&e)
                );
                Forward::Failed(unavailable(why))
            }
        }
    }

    /// What the leader did with a signed write passed on as it came (`call`), as this node's
    /// reply, read as the route `command` came from answers (`api.rs`: a delete a Resource, a
    /// rollback a Change, an apply its Changes). The leader's write is in the log before it
    /// answers: a `Mark` after it has the index this node waits for.
    async fn relayed(&self, call: reqwest::RequestBuilder, at: &str, command: &Command) -> Forward {
        match call.timeout(PATIENCE).send().await {
            Ok(reply) if reply.status().is_success() => {
                let done = match command {
                    Command::Delete { .. } => {
                        reply.json::<kith_api::Resource>().await.map(|r| Done::Deleted(Box::new(r)))
                    }
                    Command::Rollback { .. } => {
                        reply.json::<kith_api::store::Change>().await.map(|c| Done::Changes(vec![c]))
                    }
                    _ => reply.json::<Vec<kith_api::store::Change>>().await.map(Done::Changes),
                };
                let Ok(done) = done else {
                    let why = format!("the leader at {at} did not answer with the changes it made");
                    return Forward::Failed(unavailable(why));
                };
                let index = match Box::pin(self.write_as(Command::Mark, None)).await {
                    Ok((_, index)) => index,
                    Err(e) => return Forward::Failed(e),
                };
                let caught_up = self.raft.wait(Some(PATIENCE));
                let _ = caught_up.applied_index_at_least(Some(index), "own write").await;
                Forward::Done(Ok(done), index)
            }
            // (The leader refused it: what it says is the reply, as for a write.)
            Ok(reply) => Forward::Failed(Error::Invalid(reply.text().await.unwrap_or_default())),
            // Never reached it: nothing happened, and asking again is safe.
            Err(e) if e.is_connect() => Forward::Again(Some(format!(
                "the leader at {at} was not reached: {}",
                crate::cluster::why(&e)
            ))),
            Err(e) => {
                let why = format!(
                    "the leader at {at} did not answer ({}); look before trying again",
                    crate::cluster::why(&e)
                );
                Forward::Failed(unavailable(why))
            }
        }
    }
}

/// Whether `command` can change who may do what: it is put in the log alone ([`Shared::turn`]).
fn changes_access(command: &Command) -> bool {
    let access = |kind: &str| {
        // (A KindDefinition says whether a kind is namespaced: which rule matches it. A
        // Cluster holds the admin's key, asked of in the same turn: `access_sign::guard`.)
        ["Role", "RoleBinding", "Identity", "KindDefinition", "Cluster"]
            .iter()
            .any(|of| of.eq_ignore_ascii_case(kind))
    };
    let keyed = |key: &str| access(key.split('/').next().unwrap_or_default());
    match command {
        Command::Apply { resources, .. } => resources.iter().any(|resource| access(&resource.kind)),
        Command::Delete { key } | Command::Rollback { key, .. } => keyed(key),
        Command::Import { .. } => true,
        Command::Status { .. } | Command::Patch { .. } | Command::Report { .. } | Command::Mark => false,
    }
}

/// What came of sending a change to the leader.
enum Forward {
    Done(Reply, u64),
    Failed(Error),
    /// Not sent, or not reached: ask again, and say why if it is still so at the deadline.
    Again(Option<String>),
    /// Refused for now (a worker that wrote too much): ask again after this long.
    Wait(Duration, String),
}

/// The change was not taken in time; `refused` is why the last leader called was not reached.
fn no_majority(refused: Option<String>) -> Error {
    match refused {
        Some(why) => unavailable(format!("{NO_MAJORITY} (the last try: {why})")),
        None => unavailable(NO_MAJORITY),
    }
}

/// The change was not taken in time because this worker writes past its rate, not for want
/// of a leader: `why` is what the control node said.
fn rate_wait(why: &str) -> Error {
    unavailable(format!(
        "the control node asked this worker to wait: it wrote more than {WORKER_RATE} writes a second \
         (or more than its burst of {WORKER_BURST}) ({why})"
    ))
}

const NO_MAJORITY: &str = "no leader, or it did not hear from more than half of the voting nodes in time \
    (they have to be running); the change may still happen, so look before trying again";

/// Voters once the cluster has this many nodes; a single voter below that, since two
/// voters stop when either one does.
const VOTERS: usize = 3;
/// A voter out of contact this long gives its vote to a node that is there, if one is.
const LOST: Duration = Duration::from_secs(60);

/// On the leader, keep Raft's members the same as the `Node` resources: a new Node
/// starts receiving the store, a deleted one stops, and there are [`VOTERS`] voters when
/// there are that many nodes.
/// It also writes down which nodes are there (`state` in the Node's status).
pub async fn tend_members(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let mut generation = shared.generation.subscribe();
    loop {
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = stopping.changed() => return,
        }
        if let Err(e) = tend_once(&shared).await {
            eprintln!("kithd: changing the cluster's members: {e}");
        }
    }
}

/// The Raft id and address of every Node in `store` that has reported them and is sent the
/// store: not a worker that runs from a view (`status.view`, which a control node writes as
/// it sends the first, `view::serve`).
fn nodes_of(store: &kith_api::store::Store) -> BTreeMap<NodeId, BasicNode> {
    let member = |node: &kith_api::Resource| {
        let status = node.status.as_ref()?;
        if node.spec["trust"] == "worker" && status["view"] == true {
            return None;
        }
        let id = status["raftId"].as_str()?.parse().ok()?;
        Some((id, BasicNode::new(status["address"].as_str()?)))
    };
    store.list(Some("Node")).filter_map(member).collect()
}

/// The header a node answers Raft's calls with: the newest store format its kithd reads.
pub(crate) const READS: &str = "x-kith-store";
/// What each member last answered with ([`READS`]; 1 where it said nothing, as a kithd from
/// before does), and when: heard by the links, so only the member itself can say it.
static HEARD: Mutex<BTreeMap<NodeId, (u32, Instant)>> = Mutex::new(BTreeMap::new());
fn heard(member: NodeId) -> Option<(u32, Instant)> {
    let heard = HEARD.lock().expect("nothing panics holding what was heard");
    heard.get(&member).copied()
}

/// A member not heard for this long is not known to read anything: it may have been put
/// back on an older kithd since.
const FRESH: Duration = Duration::from_secs(30);

/// Which of `members` (but `me`) are not known to read the store's newest format: not
/// heard lately, or heard saying less. While there is one the leader does not mark the
/// store ([`Command::Mark`]), which such a kithd could not read.
fn not_reading(
    heard: &BTreeMap<NodeId, (u32, Instant)>,
    members: &BTreeSet<NodeId>,
    me: NodeId,
    now: Instant,
) -> BTreeSet<NodeId> {
    let reads = |member: &NodeId| {
        let said = heard.get(member);
        said.is_some_and(|(format, at)| *format >= kith_store::FORMAT && now.duration_since(*at) < FRESH)
    };
    let others = members.iter().filter(|member| **member != me);
    others.filter(|member| !reads(member)).copied().collect()
}

/// On the leader, until the store is marked: mark it once every member's kithd reads a
/// marked one. On every node that keeps the store, in a cluster or not: any may come to lead.
pub async fn tend_format(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    // (A worker that runs from a view keeps no store, and marks none.)
    if shared.view.borrow().is_some() {
        return;
    }
    let mut said = Vec::new();
    loop {
        if shared
            .store
            .lock()
            .expect("nothing panics holding the store")
            .store
            .marked()
        {
            return;
        }
        if let Err(e) = mark(&shared, &mut said).await {
            eprintln!("kithd: {e}");
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = stopping.changed() => return,
        }
    }
}

/// One look: where this node leads, mark the store, or say (in `said`, and in the log when
/// it changes) who is waited for.
async fn mark(shared: &Shared, said: &mut Vec<String>) -> Result<(), String> {
    let metrics = shared.raft.metrics().borrow().clone();
    if metrics.current_leader != Some(metrics.id) {
        return Ok(());
    }
    // The members, and the Nodes about to be: one that joined on an older kithd is waited for.
    let members = metrics.membership_config.membership().nodes().map(|(id, _)| *id);
    let members: BTreeSet<NodeId> = members.chain(nodes_of_store(shared).into_keys()).collect();
    let waiting = {
        let heard = HEARD.lock().expect("nothing panics holding what was heard");
        not_reading(&heard, &members, metrics.id, Instant::now())
    };
    if waiting.is_empty() {
        let marked = shared.submit(Command::Mark).await;
        marked.map_err(|e| format!("marking the store: {e}"))?;
        eprintln!(
            "kithd: the store keeps from now on when each resource was first made (format 2: an older kithd does not read it)"
        );
        return Ok(());
    }
    let named = |id: &NodeId| match voter(shared, *id) {
        Found::One(name, _) => name,
        _ => format!("member {id}"),
    };
    let waiting: Vec<String> = waiting.iter().map(named).collect();
    if *said != waiting {
        let names = waiting.join(", ");
        eprintln!(
            "kithd: the store stays in format 1 until every member's kithd reads format 2: {names} did not say so (down, or on an older kithd)"
        );
        *said = waiting;
    }
    Ok(())
}

fn nodes_of_store(shared: &Shared) -> BTreeMap<NodeId, BasicNode> {
    nodes_of(&shared.store.lock().expect("nothing panics holding the store").store)
}

/// Every Node's name, key, the state its status gives, and its Raft id.
fn states_of(shared: &Shared) -> Vec<(String, String, Option<String>, Option<NodeId>)> {
    let store = shared.store.lock().expect("nothing panics holding the store");
    let state = |node: &kith_api::Resource| {
        let status = node.status.as_ref();
        let text = |field: &str| status.and_then(|status| status[field].as_str());
        let id = text("raftId").and_then(|id| id.parse().ok());
        (
            node.metadata.name.clone(),
            node.key(),
            text("state").map(str::to_string),
            id,
        )
    };
    store.store.list(Some("Node")).map(state).collect()
}

/// The next change to make, if any: one at a time, each seen in the metrics before the next.
/// `current` are the nodes that have (nearly) all of the log: only those may start to vote.
#[allow(clippy::too_many_arguments)]
fn next_change(
    me: NodeId,
    wanted: &BTreeMap<NodeId, BasicNode>,
    known: &BTreeMap<NodeId, BasicNode>,
    voters: &BTreeSet<NodeId>,
    current: &BTreeSet<NodeId>,
    lost: &BTreeSet<NodeId>,
    roaming: &BTreeSet<NodeId>,
    workers: &BTreeSet<NodeId>,
) -> Option<ChangeMembers<NodeId, BasicNode>> {
    let differ = |(id, node): &(&NodeId, &BasicNode)| known.get(id) != Some(node);
    let (changed, new): (BTreeMap<_, _>, BTreeMap<_, _>) = wanted
        .iter()
        .filter(differ)
        .map(|(id, node)| (*id, node.clone()))
        .partition(|(id, _)| known.contains_key(id));
    if !new.is_empty() {
        return Some(ChangeMembers::AddNodes(new));
    }
    if !changed.is_empty() {
        return Some(ChangeMembers::SetNodes(changed));
    }
    // The leader stays a voter, then those that already are, then by id; a voter that is
    // lost comes last, so it votes on only while nobody is there to take its place. A node that
    // is not receiving the store (down, or it gave an address nobody can reach) must not
    // become a voter: with two such voters of three, nothing could be agreed again.
    // A node that roams (a laptop) is as good as lost for this: it votes only if it leads
    // or nobody else can, and the cluster is as large as the nodes that stay.
    // A worker (`spec.trust`) never votes, whoever else there is: it is not counted, and one
    // that votes (it was a control node until now, the leader even) stops.
    let may = |id: &&NodeId| !workers.contains(id);
    let staying = wanted.keys().filter(may).filter(|id| !roaming.contains(id)).count();
    // (Never fewer voters because a node was said to roam: those that vote go on, last in line.)
    let enough = staying >= VOTERS || voters.iter().filter(may).count() >= VOTERS;
    let target = if wanted.keys().filter(may).count() >= VOTERS && enough {
        VOTERS
    } else {
        1
    };
    let there = |id: &&NodeId| !lost.contains(id) && !roaming.contains(id);
    let by_preference = [me]
        .into_iter()
        .chain(voters.iter().filter(there).copied())
        .chain(current.iter().filter(there).copied())
        .chain(voters.iter().copied());
    let mut next = BTreeSet::new();
    for id in by_preference.filter(|id| (*id == me || wanted.contains_key(id)) && may(&id)) {
        if next.len() < target {
            next.insert(id);
        }
    }
    // Not from one voter to two while the third is not ready: two stop when either does.
    // (And never to no voter: a cluster of workers alone goes on as it is. The API refuses to
    // make the last control node one.)
    let waiting = voters.len() == 1 && next.len() == 2 || next.is_empty();
    if next != *voters && !waiting {
        return Some(ChangeMembers::ReplaceAllVoters(next));
    }
    let gone: BTreeSet<NodeId> = known
        .keys()
        .filter(|id| **id != me && !wanted.contains_key(id))
        .copied()
        .collect();
    (!gone.is_empty()).then_some(ChangeMembers::RemoveNodes(gone))
}

async fn tend_once(shared: &Shared) -> Result<(), String> {
    let metrics = shared.raft.metrics().borrow().clone();
    if metrics.current_leader != Some(metrics.id) {
        return Ok(());
    }
    // Which nodes are there: written down when it changes, never as a heartbeat.
    let now = Instant::now();
    let (wanted, mut statuses, mut lost) = (nodes_of_store(shared), Vec::new(), BTreeSet::new());
    for (name, key, state, id) in states_of(shared) {
        // Too early to say: what is written stays.
        let Some(gone) = shared.members.lost_for(&name, now) else {
            continue;
        };
        let is = if gone >= crate::members::GRACE {
            "unreachable"
        } else {
            "ready"
        };
        if state.as_deref() != Some(is) {
            statuses.push((key, serde_json::Map::from_iter([("state".to_string(), is.into())])));
        }
        if let Some(id) = id.filter(|_| gone >= LOST) {
            lost.insert(id);
        }
    }
    if !statuses.is_empty() {
        let written = shared.submit(Command::Patch { statuses }).await;
        written.map_err(|e| format!("writing down which nodes are there: {e}"))?;
    }
    let membership = metrics.membership_config.membership();
    let known: BTreeMap<NodeId, BasicNode> = membership.nodes().map(|(id, node)| (*id, node.clone())).collect();
    let voters: BTreeSet<NodeId> = membership.voter_ids().collect();
    // Within a hundred changes of the leader's log counts as having it.
    let last = metrics.last_log_index.unwrap_or(0);
    let has_it =
        |matched: &Option<kith_store::openraft::LogId<NodeId>>| matched.is_some_and(|log| log.index + 100 >= last);
    let replication = metrics.replication.iter().flatten();
    let current: BTreeSet<NodeId> = replication
        .filter(|(_, matched)| has_it(matched))
        .map(|(id, _)| *id)
        .collect();
    let roaming: BTreeSet<NodeId> = {
        let store = shared.store.lock().expect("nothing panics holding the store");
        let roams = |node: &&kith_api::Resource| node.spec["roaming"] == true;
        let id = |node: &kith_api::Resource| node.status.as_ref()?["raftId"].as_str()?.parse().ok();
        store.store.list(Some("Node")).filter(roams).filter_map(id).collect()
    };
    let workers: BTreeSet<NodeId> = {
        let store = shared.store.lock().expect("nothing panics holding the store");
        let id = |node: &kith_api::Resource| node.status.as_ref()?["raftId"].as_str()?.parse().ok();
        let nodes = store.store.list(Some("Node"));
        nodes
            .filter(|node| node.spec["trust"] == "worker")
            .filter_map(id)
            .collect()
    };
    let Some(mut change) = next_change(
        metrics.id, &wanted, &known, &voters, &current, &lost, &roaming, &workers,
    ) else {
        return Ok(());
    };
    // Having the log says a node was there, not that it is: ask the ones about to vote.
    if let ChangeMembers::ReplaceAllVoters(next) = &change {
        let mut there = current.clone();
        for id in next.difference(&voters) {
            // (The candidate and no other: the Node it is in the store, or its name alone.)
            let address = wanted.get(id).map_or("", |node| node.addr.as_str());
            if !answers(shared, *id, address).await {
                there.remove(id);
            }
        }
        match next_change(metrics.id, &wanted, &known, &voters, &there, &lost, &roaming, &workers) {
            Some(with_those_there) => change = with_those_there,
            None => return Ok(()),
        }
    }
    eprintln!("kithd: cluster members: {change:?}");
    // Voters that stop being voters keep receiving the store until their Node is deleted.
    let changing = shared.raft.change_membership(change, true);
    match tokio::time::timeout(PATIENCE, changing).await {
        Ok(changed) => changed.map(drop).map_err(|e| e.to_string()),
        Err(_) => Err("not agreed on in time: too few of the voting nodes answer".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A worker is held to one barrier a second, and the map keeps no name whose second is over
    /// (a deleted worker's, or one of many names that came and went).
    #[test]
    fn barrier_map_is_bounded() {
        let (mut last, begun) = (BTreeMap::new(), Instant::now());
        let second = Duration::from_secs(1);
        for worker in 0..100 {
            assert!(due(&mut last, &format!("w{worker}"), begun, second));
        }
        assert!(
            !due(&mut last, "w0", begun + Duration::from_millis(999), second),
            "one a second"
        );
        assert!(due(&mut last, "w0", begun + second, second));
        assert_eq!(last.len(), 1, "the others' second is over");
    }

    /// The report a worker running 300 units sends (100 Workloads of 3, each unit with a long
    /// message and an address, each Workload with notes; `controller.rs` "4. Report") is far
    /// below what a worker may write at once, and counts for little of its burst.
    //
    // How often: one report is in flight at a time (the next waits for it), a Node's own status
    // is patched when its serving or mesh changes, devices every 30 s, and barriers one a second
    // at most (each counted one). A worker held to the rate only sends fewer, larger reports.
    #[test]
    fn worker_bound_is_several_times_an_honest_report() {
        let report = Command::Report {
            node: "a-worker-with-a-long-name".into(),
            statuses: honest(100),
        };
        let bytes = serde_json::to_vec(&report).unwrap().len();
        eprintln!("an honest report of 300 units: {bytes} bytes, counted {}", cost(bytes));
        assert!(
            bytes * 4 <= WORKER_WRITE,
            "{bytes} bytes: the bound is not several times it"
        );
        assert!(cost(bytes) * 5.0 <= WORKER_BURST, "it alone takes most of the burst");
    }

    /// A report too large for one write goes in parts, each a write a worker may make, every
    /// status whole and in its order; a small one is one write.
    #[test]
    fn worker_report_goes_in_parts_under_the_bound() {
        let statuses = honest(1000);
        let keys: Vec<_> = statuses.iter().map(|(key, _)| key.clone()).collect();
        let parts = in_parts("w", statuses);
        assert!(parts.len() > 1, "{} parts", parts.len());
        let mut kept = Vec::new();
        for part in &parts {
            let bytes = serde_json::to_vec(part).unwrap().len();
            assert!(bytes <= WORKER_WRITE, "a part of {bytes} bytes");
            let Command::Report { node, statuses } = part else {
                panic!("{part:?}")
            };
            assert_eq!(node, "w");
            kept.extend(statuses.iter().map(|(key, _)| key.clone()));
        }
        assert_eq!(kept, keys);
        assert_eq!(in_parts("w", honest(100)).len(), 1);
        assert!(in_parts("w", Vec::new()).is_empty(), "nothing to report is no write");
    }

    /// The statuses of `workloads` Workloads of 3 units, each with a long message and notes.
    fn honest(workloads: usize) -> Vec<(String, Option<serde_json::Value>)> {
        let message = "stopping: the unit did not stop in its grace period and was killed; its devices and \
                       its name are held until it is gone, and it is started again once they are free (try 4)";
        (0..workloads)
            .map(|n| {
                let units: Vec<_> = (0..3)
                    .map(|replica| {
                        serde_json::json!({
                            "name": format!("workload-number-{n:03}-{replica}"), "replica": replica,
                            "state": "restarting", "ready": false, "restarts": 12345, "revision": 1_000_000 + n,
                            "exitCode": 137, "message": message, "address": "fd6b:6974:6800:1234:5678:9abc:def0:1234",
                        })
                    })
                    .collect();
                let notes = ["the image could not be pulled: the registry answered 503 Service Unavailable"; 2];
                let status = serde_json::json!({ "replicas": 3, "containers": units, "notes": notes });
                (format!("Workload/default/workload-number-{n:03}"), Some(status))
            })
            .collect()
    }

    /// A worker that wrote its burst waits, and how long is what refills what it asks; a write
    /// it may not make is not counted, a worker's rest gives it no more than its burst, and the
    /// map keeps no worker that may write its whole burst again.
    #[test]
    fn worker_bound_spends_a_bucket_per_worker() {
        let (mut spent, begun) = (Spent::default(), Instant::now());
        for _ in 0..WORKER_BURST as usize {
            assert!(spend(&mut spent, "w", 1.0, begun).is_ok());
        }
        let wait = spend(&mut spent, "w", 2.0, begun).unwrap_err();
        assert_eq!(wait, Duration::from_millis(200));
        assert!(
            spend(&mut spent, "v", 1.0, begun).is_ok(),
            "another worker is held by w"
        );
        let later = begun + Duration::from_millis(200);
        assert!(
            spend(&mut spent, "w", 2.0, later).is_ok(),
            "the refused write was counted"
        );
        // A long rest: the burst, no more.
        let rested = begun + Duration::from_secs(3600);
        for _ in 0..WORKER_BURST as usize {
            assert!(spend(&mut spent, "w", 1.0, rested).is_ok());
        }
        assert!(spend(&mut spent, "w", 1.0, rested).is_err());
        assert_eq!(spent.buckets.keys().collect::<Vec<_>>(), ["w"], "v has its burst again");
        assert_eq!(
            (cost(0), cost(65535), cost(65536), cost(WORKER_WRITE)),
            (1.0, 1.0, 2.0, 17.0)
        );
    }

    /// A worker's refusals of a kind open a minute in the audit log, and the next minute's first
    /// says how many were not written; another kind, or another worker, has its own minute.
    #[test]
    fn worker_refusals_are_a_line_a_minute_of_each_kind() {
        let (mut said, begun) = (Said::new(), Instant::now());
        assert_eq!(throttled(&mut said, "w", "size", begun), Some(0));
        for _ in 0..5 {
            assert_eq!(throttled(&mut said, "w", "size", begun + Duration::from_secs(30)), None);
        }
        assert_eq!(
            throttled(&mut said, "w", "rate", begun),
            Some(0),
            "rate has its own minute"
        );
        assert_eq!(
            throttled(&mut said, "v", "size", begun),
            Some(0),
            "v has its own minute"
        );
        let later = begun + Duration::from_secs(61);
        assert_eq!(throttled(&mut said, "w", "size", later), Some(5));
        assert_eq!(throttled(&mut said, "w", "size", later), None);
        assert_eq!(
            said.len(),
            1,
            "the minutes over with nothing unwritten are let go: {said:?}"
        );
    }

    /// A control node that says to wait no time, or an hour, is waited a second, or a minute.
    #[test]
    fn wait_of_is_a_second_to_a_minute() {
        let reply = |after: &str| {
            let said = axum::http::Response::builder()
                .header("retry-after", after)
                .body("")
                .unwrap();
            reqwest::Response::from(said)
        };
        let seconds = |after| wait_of(&reply(after)).as_secs();
        assert_eq!(
            (seconds("0"), seconds("5"), seconds("3600"), seconds("soon")),
            (1, 5, 60, 1)
        );
    }

    /// A worker's write over the size is refused unread, one off its list refused, and one past
    /// its rate answered 429 with the wait; none reaches the log, and each kind is in the audit
    /// log (the rate's once that minute). Another worker and a control node are not held by it,
    /// and a worker's own write, refused for its rate, is sent again once it may, whether it
    /// runs from a view or keeps the log.
    #[tokio::test]
    async fn worker_bound_holds_a_worker_to_its_size_and_rate_and_no_one_else() {
        use crate::cluster::pinned_peer::{at, node, shared_with};
        use crate::cluster::{Cluster, listen, node_router};
        let ca = pki::Ca::create().unwrap();
        let (c, w, v, k) = (
            node(&ca, "bound-c"),
            node(&ca, "bound-w"),
            node(&ca, "bound-v"),
            node(&ca, "bound-k"),
        );
        let shared = shared_with("bound", c.clone(), &[]).await;
        for (name, spec) in [
            ("bound-w", "{trust: worker}"),
            ("bound-v", "{trust: worker}"),
            ("bound-k", "{}"),
        ] {
            let text = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}}}\nspec: {spec}\n");
            let node = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(node).unwrap();
            // Joined: a Node made by hand is not let in.
            let joined = serde_json::json!({ "raftId": kith_store::node_id(name).to_string() });
            store.set_status(&format!("Node/{name}"), Some(joined)).unwrap();
        }
        let id = shared.raft.metrics().borrow().id;
        shared
            .raft
            .initialize(BTreeMap::from([(id, BasicNode::new(""))]))
            .await
            .unwrap();
        let leads = shared.raft.wait(Some(Duration::from_secs(30)));
        leads.current_leader(id, "leads").await.unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap().to_string();
        let listener = listen(tcp, pki::server_config(&c).unwrap()).unwrap();
        let app = node_router(shared.clone()).into_make_service_with_connect_info::<Peer>();
        tokio::spawn(async move { drop(axum::serve(listener, app).await) });
        let client = |who: &pki::Identity| {
            let cluster = Cluster::new(who.clone(), None).unwrap();
            cluster.to(&at("bound-c", &address, None)).unwrap()
        };
        let (to_w, to_v, to_k) = (client(&w), client(&v), client(&k));
        let url = format!("https://{address}/v1/raft/write");
        let os = |name: &str, bytes: usize| {
            let fields = serde_json::json!({ "os": "x".repeat(bytes) });
            let fields = fields.as_object().unwrap().clone();
            Command::Patch {
                statuses: vec![(format!("Node/{name}"), fields)],
            }
        };
        let logged = || shared.raft.metrics().borrow().last_log_index.unwrap_or(0);

        // Over the size: refused by what it says it is, before a byte of it is read (none is
        // ever sent here), and never in the log.
        let before = logged();
        let never = futures_util::stream::pending::<Result<Vec<u8>, std::io::Error>>();
        let big = to_w
            .post(&url)
            .header(reqwest::header::CONTENT_LENGTH, WORKER_WRITE + 1)
            .body(reqwest::Body::wrap_stream(never))
            .send();
        let big = tokio::time::timeout(Duration::from_secs(30), big).await;
        let said = big.expect("answered before the body").unwrap().text().await.unwrap();
        assert!(said.contains("at most 1024 KiB"), "{said}");
        // Not on its list: refused, and written in the audit log each time.
        let theirs = Command::Rollback {
            key: "Node/bound-c".into(),
            to: 1,
            at: 0,
        };
        let said = to_w
            .post(&url)
            .json(&theirs)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(said.contains("Err"), "{said}");
        // Past the rate: all at once, so the bucket is not refilled between them.
        let mut sent = tokio::task::JoinSet::new();
        let begun = Instant::now();
        for _ in 0..(WORKER_BURST as usize * 2) {
            let call = to_w.post(&url).json(&os("bound-w", 10));
            sent.spawn(async move {
                let reply = call.send().await.unwrap();
                let wait = reply.headers().get(reqwest::header::RETRY_AFTER).cloned();
                (reply.status().as_u16(), wait, reply.text().await.unwrap())
            });
        }
        let (mut taken, mut waited) = (0, 0);
        while let Some(done) = sent.join_next().await {
            let (status, wait, said) = done.unwrap();
            match status {
                200 => {
                    assert!(said.contains("Ok"), "{said}");
                    taken += 1;
                }
                429 => {
                    let wait: u64 = wait.expect("the wait is said").to_str().unwrap().parse().unwrap();
                    assert!(wait >= 1 && said.contains("asked again in"), "{wait} {said}");
                    waited += 1;
                }
                _ => panic!("{status} {said}"),
            }
        }
        let refilled = (begun.elapsed().as_secs_f64() * WORKER_RATE).ceil() as usize;
        assert!(waited > 0, "a burst twice the bound was all taken");
        assert!(taken <= WORKER_BURST as usize + refilled, "{taken} taken");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(logged(), before + taken as u64, "a refused write is in the log");
        let refusals = shared.audit.tail(200).unwrap();
        let of_w: Vec<_> = refusals.iter().filter(|e| e["who"] == "node bound-w").collect();
        // Its size, its list and its rate: a line each, the rate's once that minute.
        assert_eq!(of_w.len(), 3, "{of_w:?}");
        assert!(of_w.iter().all(|e| e["ok"] == false), "{of_w:?}");

        // Another worker, and a control node (its writes as fast and as large as it likes).
        let reply = to_v.post(&url).json(&os("bound-v", 10)).send().await.unwrap();
        assert!(reply.text().await.unwrap().contains("Ok"), "v was held by w");
        let mut sent = tokio::task::JoinSet::new();
        for _ in 0..(WORKER_BURST as usize * 2) {
            let call = to_k.post(&url).json(&os("bound-k", 10));
            sent.spawn(async move { call.send().await.unwrap().status().as_u16() });
        }
        while let Some(status) = sent.join_next().await {
            assert_eq!(status.unwrap(), 200, "a control node was held");
        }
        let large = to_k
            .post(&url)
            .json(&os("bound-k", WORKER_WRITE * 2))
            .send()
            .await
            .unwrap();
        assert!(
            large.text().await.unwrap().contains("Ok"),
            "a control node's large write was refused"
        );
        assert!(
            shared
                .audit
                .tail(200)
                .unwrap()
                .iter()
                .all(|e| e["who"] != "node bound-k")
        );

        // What a worker may still write, set here.
        let left = |writes: f64| {
            let bucket = (writes, Instant::now());
            SPENT.lock().unwrap().buckets.insert("bound-w".into(), bucket);
        };
        // A body that never ends: none of these is sent a byte of it.
        let unsent = |length: Option<usize>| {
            let never = futures_util::stream::pending::<Result<Vec<u8>, std::io::Error>>();
            let call = to_w.post(&url).body(reqwest::Body::wrap_stream(never));
            let call = match length {
                Some(length) => call.header(reqwest::header::CONTENT_LENGTH, length),
                None => call,
            };
            tokio::time::timeout(Duration::from_secs(30), call.send())
        };
        // One that says it is 1 MiB, with a write left: it counts for 17, so it is answered
        // 429 at once, unread.
        left(1.0);
        let reply = unsent(Some(WORKER_WRITE)).await.expect("answered unread").unwrap();
        assert_eq!(reply.status().as_u16(), 429, "{:?}", reply.text().await);
        // One that does not say, and stalls: refused once its time is up, and in the audit log.
        left(WORKER_BURST);
        let begun = Instant::now();
        let reply = unsent(None).await.expect("answered when its time was up").unwrap();
        let said = reply.text().await.unwrap();
        assert!(said.contains("was not sent in"), "{said}");
        assert!(begun.elapsed() >= BODY_PATIENCE, "{:?}", begun.elapsed());
        let audited = shared.audit.tail(200).unwrap();
        assert!(
            audited
                .iter()
                .any(|e| e["who"] == "node bound-w" && e.to_string().contains("was not sent in")),
            "{audited:?}"
        );

        // The worker's own kithd (from a view, through c) sends a write c asks it to wait for
        // again once it may: here, after 3 s (its bucket 20 writes short).
        let worker = shared_with("bound-worker", w.clone(), &[]).await;
        worker.view.send_replace(Some(u64::MAX));
        *worker.upstream.lock().unwrap() = Some((address.clone(), to_w.clone()));
        let short = |by: f64| left(-by);
        short(20.0);
        let begun = Instant::now();
        let done = worker.write(os("bound-w", 10)).await;
        assert!(done.is_ok(), "{done:?}");
        assert!(begun.elapsed() >= Duration::from_secs(2), "it was not asked to wait");

        // A worker's kithd that keeps the log (a learner) sends it to the leader, and is told
        // to wait as well.
        let learner = shared_with("bound-learner", w.clone(), &[at("bound-c", &address, None)]).await;
        short(20.0);
        match learner
            .forward(1, &BasicNode::new(&address), &os("bound-w", 10), None)
            .await
        {
            Forward::Wait(wait, why) => {
                assert!(wait >= Duration::from_secs(1), "{why}");
                // Past its deadline, its log says why: not that there is no leader.
                let said = rate_wait(&why).to_string();
                assert!(
                    said.contains("asked this worker to wait") && !said.contains("no leader"),
                    "{said}"
                );
            }
            _ => panic!("not asked to wait"),
        }
    }

    /// [`super::next_change`] of a cluster with no worker.
    fn next_change(
        me: NodeId,
        wanted: &BTreeMap<NodeId, BasicNode>,
        known: &BTreeMap<NodeId, BasicNode>,
        voters: &BTreeSet<NodeId>,
        current: &BTreeSet<NodeId>,
        lost: &BTreeSet<NodeId>,
        roaming: &BTreeSet<NodeId>,
    ) -> Option<ChangeMembers<NodeId, BasicNode>> {
        super::next_change(me, wanted, known, voters, current, lost, roaming, &BTreeSet::new())
    }

    #[tokio::test]
    async fn raft_link_goes_to_the_voter_it_is_for_and_to_no_other() {
        use crate::cluster::pinned_peer::{answering_as, at, node, shared_with};
        use kith_store::openraft::Vote;
        use std::sync::atomic::Ordering;
        let ca = pki::Ca::create().unwrap();
        let (a, b, x) = (node(&ca, "a"), node(&ca, "b"), node(&ca, "x"));
        let (taken, to_x) = answering_as(&x).await;
        let (home, to_b) = answering_as(&b).await;
        let (print_b, print_x) = (pki::print_of(&b.cert).unwrap(), pki::print_of(&x.cert).unwrap());
        let id = kith_store::node_id("b");
        // A vote to voter b at `address`: the link it was sent on, and how it came out.
        let vote_at = |shared: Arc<Shared>, address: String| async move {
            let mut network = Network::default();
            let _ = network.0.set(Arc::downgrade(&shared));
            let mut link = network.new_client(id, &BasicNode::new(address)).await;
            let vote = VoteRequest::new(Vote::new(1, kith_store::node_id("a")), None);
            let done = link.vote(vote, RPCOption::new(Duration::from_secs(5))).await;
            (done.is_ok(), link.said)
        };
        let said = |said: Option<String>| said.expect("the refusal is in the log");

        // A store with no Node yet (a join, an empty one): by the name alone. Another node of the
        // CA at b's address is refused in the handshake, with who was called and who answered.
        let empty = shared_with("link-empty", a.clone(), &[]).await;
        let (done, why) = vote_at(empty.clone(), taken.clone()).await;
        assert!(!done && said(why).contains("the voter with raft id"), "answered");
        assert_eq!(to_x.load(Ordering::SeqCst), 0, "x was sent the vote");
        let (_, why) = vote_at(empty.clone(), taken.clone()).await;
        assert!(said(why).contains("was called, and node x answered"));
        // b itself is sent it (whatever it answers: the call was made, and its refusal is not a pin's).
        let (_, why) = vote_at(empty.clone(), home.clone()).await;
        assert_eq!(to_b.load(Ordering::SeqCst), 1);
        assert!(
            why.is_none_or(|w| !w.contains("was called")),
            "b was refused as another node"
        );

        // With the Node (raft id b's) the key is held to as well: the right name and another key.
        let known = |tag: &'static str, print: String| {
            let (a, home) = (a.clone(), home.clone());
            async move {
                let shared = shared_with(tag, a, &[at("b", &home, Some(print.clone()))]).await;
                let status = serde_json::json!({
                    "address": home, "certificate": print, "state": "ready", "raftId": id.to_string(),
                });
                shared
                    .store
                    .lock()
                    .unwrap()
                    .store
                    .set_status("Node/b", Some(status))
                    .unwrap();
                shared
            }
        };
        let wrong = known("link-wrong", print_x).await;
        let (done, why) = vote_at(wrong, home.clone()).await;
        assert!(!done && said(why).contains("node b at"), "refused, and said by whom");
        assert_eq!(
            to_b.load(Ordering::SeqCst),
            1,
            "b was sent a vote on another key than its Node's"
        );
        let right = known("link-right", print_b).await;
        let (_, why) = vote_at(right.clone(), home.clone()).await;
        assert_eq!(to_b.load(Ordering::SeqCst), 2, "b, on its own key, is sent the vote");
        assert!(
            why.is_none_or(|w| !w.contains("another key")),
            "b was refused on its own key"
        );
        // And another node at b's address is refused here too.
        let (done, why) = vote_at(right, taken).await;
        assert!(!done && said(why).contains("was called, and node x answered"));
        assert_eq!(to_x.load(Ordering::SeqCst), 0);
    }

    /// Two Nodes with one Raft id: neither is known to be the voter, so the vote is sent to neither.
    #[tokio::test]
    async fn raft_link_two_nodes_one_id_is_sent_nothing() {
        use crate::cluster::pinned_peer::{answering_as, at, node, shared_with};
        use kith_store::openraft::Vote;
        use std::sync::atomic::Ordering;
        let ca = pki::Ca::create().unwrap();
        let (a, b, x) = (node(&ca, "a"), node(&ca, "b"), node(&ca, "x"));
        let (home, to_b) = answering_as(&b).await;
        let (there, to_x) = answering_as(&x).await;
        let id = kith_store::node_id("b");
        let nodes = [at("b", &home, None), at("x", &there, None)];
        let shared = shared_with("link-two", a, &nodes).await;
        for name in ["b", "x"] {
            let status = serde_json::json!({ "address": home, "state": "ready", "raftId": id.to_string() });
            let set = shared
                .store
                .lock()
                .unwrap()
                .store
                .set_status(&format!("Node/{name}"), Some(status));
            set.unwrap();
        }
        let mut network = Network::default();
        let _ = network.0.set(Arc::downgrade(&shared));
        let mut link = network.new_client(id, &BasicNode::new(&home)).await;
        let vote = VoteRequest::new(Vote::new(1, kith_store::node_id("a")), None);
        assert!(link.vote(vote, RPCOption::new(Duration::from_secs(5))).await.is_err());
        let said = link.said.expect("the refusal is in the log");
        assert!(said.contains("two Nodes") && said.contains("nothing is sent"), "{said}");
        assert_eq!((to_b.load(Ordering::SeqCst), to_x.load(Ordering::SeqCst)), (0, 0));
        // And the probe of that candidate finds no one there either.
        assert!(!answers(&shared, id, &home).await);
        assert_eq!(to_b.load(Ordering::SeqCst), 0);
    }

    /// The candidate voter is asked as itself: another node of the CA at its address is not taken for it.
    #[tokio::test]
    async fn raft_probe_of_a_candidate_is_not_answered_by_another_node() {
        use crate::cluster::pinned_peer::{answering_as, at, node, shared_with};
        use std::sync::atomic::Ordering;
        let ca = pki::Ca::create().unwrap();
        let (a, b, x) = (node(&ca, "a"), node(&ca, "b"), node(&ca, "x"));
        let (taken, to_x) = answering_as(&x).await;
        let (home, to_b) = answering_as(&b).await;
        let id = kith_store::node_id("b");
        // Not yet a Node: held to a name that gives b's id.
        let empty = shared_with("probe-empty", a.clone(), &[]).await;
        assert!(!answers(&empty, id, &taken).await, "x was taken for b");
        assert!(answers(&empty, id, &home).await, "b was not taken for b");
        // With its Node: held to the name and key it has.
        let shared = shared_with("probe-known", a, &[at("b", &home, None)]).await;
        let status = serde_json::json!({ "address": home, "state": "ready", "raftId": id.to_string() });
        shared
            .store
            .lock()
            .unwrap()
            .store
            .set_status("Node/b", Some(status))
            .unwrap();
        assert!(!answers(&shared, id, &taken).await, "x was taken for b");
        assert!(answers(&shared, id, &home).await, "b was not taken for b");
        // (/v1/ca is asked of each, and the handshake is what refuses: x is sent nothing.)
        assert_eq!(to_x.load(Ordering::SeqCst), 0);
        assert!(to_b.load(Ordering::SeqCst) >= 1, "b was not reached");
    }

    #[tokio::test]
    async fn pinned_peer_is_sent_no_write_and_the_refusal_is_what_a_person_is_told() {
        use crate::cluster::pinned_peer::{answering_as, at, node, shared_with};
        use std::sync::atomic::Ordering;
        let ca = pki::Ca::create().unwrap();
        let (a, b, x) = (node(&ca, "a"), node(&ca, "b"), node(&ca, "x"));
        // Node/b, raft id 1, is where another node of the cluster answers now.
        let (taken, to_x) = answering_as(&x).await;
        let there = at("b", &taken, Some(pki::print_of(&b.cert).unwrap()));
        let shared = shared_with("write", a, &[there]).await;
        let command = Command::Delete {
            key: "Secret/default/s".into(),
        };
        let leader = BasicNode::new(&taken);
        let Forward::Again(why) = shared.forward(1, &leader, &command, None).await else {
            panic!("a write was taken by another node than the leader");
        };
        let why = why.expect("the refusal is kept");
        assert!(why.contains("node b was called, and node x answered"), "{why}");
        assert_eq!(to_x.load(Ordering::SeqCst), 0, "x was sent the write");
        // A leader that no Node names is sent nothing either, and that is what is said.
        let Forward::Again(why) = shared.forward(7, &leader, &command, None).await else {
            panic!("a write was sent to a leader no Node names");
        };
        assert!(why.is_some_and(|why| why.contains("no Node names")));
        assert_eq!(to_x.load(Ordering::SeqCst), 0);
        // What a person is told when no leader takes it, and why.
        let said = no_majority(Some("the leader at 127.0.0.1:1 was refused".into())).to_string();
        assert!(said.contains("no leader") && said.contains("was refused"), "{said}");
        assert_eq!(no_majority(None).to_string(), unavailable(NO_MAJORITY).to_string());
    }

    #[test]
    fn a_write_is_held_to_what_its_senders_node_says_and_one_with_no_node_is_not_taken() {
        let mut store = kith_api::store::Store::default();
        let nodes = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: a }\nspec: {}\n---\n\
                     apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: w }\nspec: { trust: worker }\n";
        for node in kith_api::Resource::from_source(nodes).unwrap() {
            store.apply(node.unwrap()).unwrap();
        }
        assert_eq!(sender(&store, "a"), Some(false));
        assert_eq!(sender(&store, "w"), Some(true));
        // (Deleted and let in by `--admit-deleted-nodes`, or not heard of yet: asked again.)
        assert_eq!(sender(&store, "gone"), None);
    }

    #[test]
    fn a_worker_never_votes_and_one_that_votes_or_leads_stops() {
        let nodes = |ids: &[u64]| {
            let node = |n: &u64| (*n, BasicNode::new(format!("10.0.0.{n}:7443")));
            ids.iter().map(node).collect::<BTreeMap<_, _>>()
        };
        let set = |ids: &[u64]| ids.iter().copied().collect::<BTreeSet<_>>();
        let next = |me: u64, all: &[u64], voters: &[u64], workers: &[u64]| {
            let (all, none) = (nodes(all), set(&[]));
            let current = all.keys().copied().collect();
            super::next_change(me, &all, &all, &set(voters), &current, &none, &none, &set(workers))
        };
        let voters = |ids: &[u64]| Some(ChangeMembers::ReplaceAllVoters(set(ids)));
        // Three control nodes of five vote; the workers only receive, though they have the log.
        assert_eq!(next(1, &[1, 2, 3, 4, 5], &[1], &[2, 3]), voters(&[1, 4, 5]));
        // One control node and two workers: one voter, as with fewer than three nodes.
        assert_eq!(next(1, &[1, 2, 3], &[1], &[2, 3]), None);
        // A voter made a worker stops, and another control node takes its place.
        assert_eq!(next(1, &[1, 2, 3, 4], &[1, 2, 3], &[2]), voters(&[1, 3, 4]));
        // With no one to take its place the cluster is back to one voter, not two.
        assert_eq!(next(1, &[1, 2, 3], &[1, 2, 3], &[2]), voters(&[1]));
        // The leader made a worker hands the vote to those that are not, itself left out.
        assert_eq!(next(1, &[1, 2, 3, 4], &[1, 2, 3], &[1]), voters(&[2, 3, 4]));
        // The only voter made a worker hands over too (the others take its messages till then).
        assert_eq!(next(1, &[1, 2], &[1], &[1]), voters(&[2]));
        // Every node a worker (the API refuses it): nothing is changed, the voters go on.
        assert_eq!(next(1, &[1, 2, 3], &[1, 2, 3], &[1, 2, 3]), None);
    }

    /// A marked store is sent whole to no kithd that has not said it reads one (a kithd from
    /// before would take it and drop when each resource was made); entries still go.
    #[tokio::test]
    async fn marked_store_is_sent_as_a_snapshot_only_to_a_kithd_that_reads_it() {
        use crate::cluster::pinned_peer::{answering_as, at, node, shared_with};
        use kith_store::openraft::error::Infallible;
        use std::sync::atomic::Ordering;
        let ca = pki::Ca::create().unwrap();
        let (a, b) = (node(&ca, "a"), node(&ca, "b"));
        // (Answers `{}` and says nothing of formats, as a kithd from before does.)
        let (home, to_b) = answering_as(&b).await;
        let shared = shared_with("mark-snapshot", a, &[at("b", &home, None)]).await;
        // (An id no other test's link has: what is heard is kept by id.)
        let id = 7_233_001;
        let status = serde_json::json!({ "address": home, "state": "ready", "raftId": id.to_string() });
        let marked = {
            let mut state = shared.store.lock().unwrap();
            state.store.set_status("Node/b", Some(status)).unwrap();
            kith_store::run(&mut state.store, Command::Mark)
        };
        marked.unwrap();
        let cell = Arc::new(OnceLock::new());
        cell.set(Arc::downgrade(&shared)).ok().unwrap();
        let mut link = Link {
            shared: cell,
            target: id,
            address: home.clone(),
            said: None,
        };
        let option = || RPCOption::new(Duration::from_secs(5));
        let nothing = serde_json::json!({});
        let mut send = async |what: &str| {
            let sent = link
                .call::<_, serde_json::Value, Infallible>(what, &nothing, option())
                .await;
            sent.map_err(|e| e.to_string())
        };
        let reached = || to_b.load(Ordering::SeqCst);
        // Never heard: no snapshot. Entries go, and with their answer it is heard to read format 1.
        assert!(send("snapshot").await.unwrap_err().contains("no snapshot is sent"));
        assert_eq!(reached(), 0);
        let _ = send("append").await;
        assert_eq!((reached(), heard(id).map(|(said, _)| said)), (1, Some(1)));
        assert!(send("snapshot").await.unwrap_err().contains("no snapshot is sent"));
        assert_eq!(reached(), 1);
        // Updated, it says so, and is sent one.
        HEARD.lock().unwrap().insert(id, (kith_store::FORMAT, Instant::now()));
        let _ = send("snapshot").await;
        assert_eq!(reached(), 2);
    }

    /// What an apply is asked, every writer is asked: a Workload a Release, a Source or a
    /// controller writes goes into the log through `Shared::submit`, and is refused there for
    /// a port another namespace publishes or an Exit that does not list its namespace.
    #[tokio::test]
    async fn every_writer_is_asked_what_an_apply_is() {
        let dir = std::env::temp_dir().join(format!("kithd-every-writer-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let workload = |namespace: &str, name: &str, template: serde_json::Value| -> kith_api::Resource {
            let mut template = template;
            template["pod"] = true.into();
            template["containers"][0]["name"] = "c".into();
            template["containers"][0]["image"] = "x".into();
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kith.dev/v1", "kind": "Workload", "metadata": {"name": name, "namespace": namespace},
                "spec": {"template": template},
            }))
            .unwrap()
        };
        let web = || serde_json::json!({ "containers": [{ "ports": [{ "port": 8080, "publish": true }] }] });
        let write = async |resources: Vec<kith_api::Resource>| {
            let written = shared.submit(Command::Apply { resources, at: 1 }).await;
            written.map(drop).map_err(|e| e.to_string())
        };
        write(vec![workload("media", "web", web())]).await.unwrap();
        let refused = write(vec![workload("other", "web", web())]).await.unwrap_err();
        assert!(refused.ends_with("TCP port 8080 is not available"), "{refused}");
        write(vec![workload("media", "second", web())]).await.unwrap();
        let through = serde_json::json!({ "exit": "vpn", "containers": [{}] });
        let refused = write(vec![workload("other", "dl", through)]).await.unwrap_err();
        assert!(refused.ends_with("there is no Exit vpn"), "{refused}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The store is marked (format 2, which a kithd from before does not read) only once
    /// every other member was heard saying, lately, that its kithd reads it.
    #[test]
    fn store_format_waits_for_every_member_to_say_it_reads_it() {
        let now = Instant::now() + Duration::from_secs(3600);
        let ago = |seconds: u64| now - Duration::from_secs(seconds);
        let set = |ids: &[u64]| ids.iter().copied().collect::<BTreeSet<_>>();
        // 2 reads it, 3 said nothing (a kithd from before), 4 read it a while ago (put
        // back since, or down), 5 was never heard, 6 reads a later format.
        let heard = BTreeMap::from([(2, (2, ago(1))), (3, (1, ago(1))), (4, (2, ago(31))), (6, (3, ago(29)))]);
        let waits = |members: &[u64]| not_reading(&heard, &set(members), 1, now);
        // (The leader is not asked: it runs this.)
        assert_eq!(waits(&[1]), set(&[]));
        assert_eq!(waits(&[1, 2, 6]), set(&[]));
        assert_eq!(waits(&[1, 2, 3, 4, 5, 6]), set(&[3, 4, 5]));
    }

    #[test]
    fn members_follow_the_nodes_and_a_roaming_one_never_starts_to_vote() {
        let node = |n: u64| (n, BasicNode::new(format!("10.0.0.{n}:7443")));
        let nodes = |ids: &[u64]| ids.iter().map(|n| node(*n)).collect::<BTreeMap<_, _>>();
        let set = |ids: &[u64]| ids.iter().copied().collect::<BTreeSet<_>>();
        // Every known node has the store, unless said otherwise.
        let next = |wanted: &[u64], known: &[u64], voters: &[u64]| {
            next_change(
                1,
                &nodes(wanted),
                &nodes(known),
                &set(voters),
                &set(known),
                &set(&[]),
                &set(&[]),
            )
        };
        let voters = |ids: &[u64]| Some(ChangeMembers::ReplaceAllVoters(set(ids)));

        assert_eq!(next(&[1], &[1], &[1]), None);
        // A second node only receives; with a third, all three vote.
        assert_eq!(next(&[1, 2], &[1], &[1]), Some(ChangeMembers::AddNodes(nodes(&[2]))));
        assert_eq!(next(&[1, 2], &[1, 2], &[1]), None);
        assert_eq!(
            next(&[1, 2, 3], &[1, 2], &[1]),
            Some(ChangeMembers::AddNodes(nodes(&[3])))
        );
        assert_eq!(next(&[1, 2, 3], &[1, 2, 3], &[1]), voters(&[1, 2, 3]));
        // A fourth does not vote, and takes the place of a voter whose Node is deleted.
        assert_eq!(next(&[1, 2, 3, 4], &[1, 2, 3, 4], &[1, 2, 3]), None);
        assert_eq!(next(&[1, 3, 4], &[1, 2, 3, 4], &[1, 2, 3]), voters(&[1, 3, 4]));
        let gone = Some(ChangeMembers::RemoveNodes(set(&[2])));
        assert_eq!(next(&[1, 3, 4], &[1, 2, 3, 4], &[1, 3, 4]), gone);
        // Back under three nodes: one voter, the leader, even if its own Node is gone.
        assert_eq!(next(&[2, 3], &[1, 2, 3], &[1, 2, 3]), voters(&[1]));
        assert_eq!(next(&[2, 3], &[1, 2, 3], &[1]), None);
        // A node that moved is told to the others.
        let mut moved = nodes(&[1, 2]);
        moved.insert(2, BasicNode::new("10.0.0.9:7443"));
        let told = next_change(1, &moved, &nodes(&[1, 2]), &set(&[1]), &set(&[2]), &set(&[]), &set(&[]));
        let there = BTreeMap::from([(2, BasicNode::new("10.0.0.9:7443"))]);
        assert_eq!(told, Some(ChangeMembers::SetNodes(there)));

        // A node that does not have the store does not get to vote: not the dead one of
        // three, and not one of two while the third is still catching up.
        let all = nodes(&[1, 2, 3]);
        assert_eq!(
            next_change(1, &all, &all, &set(&[1]), &set(&[]), &set(&[]), &set(&[])),
            None
        );
        assert_eq!(
            next_change(1, &all, &all, &set(&[1]), &set(&[3]), &set(&[]), &set(&[])),
            None
        );
        assert_eq!(
            next_change(1, &all, &all, &set(&[1]), &set(&[2, 3]), &set(&[]), &set(&[])),
            voters(&[1, 2, 3])
        );
        // With four, the three that have it; a voter that falls behind stays one.
        let four = nodes(&[1, 2, 3, 4]);
        assert_eq!(
            next_change(1, &four, &four, &set(&[1]), &set(&[3, 4]), &set(&[]), &set(&[])),
            voters(&[1, 3, 4])
        );
        assert_eq!(
            next_change(1, &four, &four, &set(&[1, 2, 3]), &set(&[4]), &set(&[]), &set(&[])),
            None
        );
        // A voter that is lost gives way to a node that is there, and stays when there is none.
        // A node that roams does not start to vote, and does not count towards three:
        // of three nodes with one roaming, one votes; of four, the three that stay.
        let roams = |all: &BTreeMap<u64, BasicNode>, voters: &[u64], current: &[u64]| {
            next_change(1, all, all, &set(voters), &set(current), &set(&[]), &set(&[3]))
        };
        assert_eq!(roams(&all, &[1], &[2, 3]), None);
        assert_eq!(roams(&four, &[1], &[2, 3, 4]), voters(&[1, 2, 4]));
        assert_eq!(roams(&four, &[1, 2, 3], &[2, 3, 4]), voters(&[1, 2, 4]));
        // Saying that voters roam never leaves fewer of them: the leader (1) and 4, with
        // only 2 and 3 staying, go on voting as three.
        let leader = next_change(
            1,
            &four,
            &four,
            &set(&[1, 2, 3]),
            &set(&[2, 3, 4]),
            &set(&[]),
            &set(&[1, 4]),
        );
        assert_eq!(leader, None);
        let most = next_change(
            1,
            &all,
            &all,
            &set(&[1, 2, 3]),
            &set(&[2, 3]),
            &set(&[]),
            &set(&[1, 2, 3]),
        );
        assert_eq!(most, None);
        let lost =
            |current: &[u64]| next_change(1, &four, &four, &set(&[1, 2, 3]), &set(current), &set(&[2]), &set(&[]));
        assert_eq!(lost(&[2, 3, 4]), voters(&[1, 3, 4]));
        assert_eq!(lost(&[2, 3]), None);
        assert_eq!(
            next_change(1, &all, &all, &set(&[1, 2, 3]), &set(&[2, 3]), &set(&[2]), &set(&[])),
            None
        );
        // When a voter's Node is deleted and nobody is ready to take its place, two go on.
        let left = nodes(&[1, 3, 4]);
        assert_eq!(
            next_change(1, &left, &four, &set(&[1, 2, 3]), &set(&[]), &set(&[]), &set(&[])),
            voters(&[1, 3])
        );
    }

    /// A node `{tag}-c` that leads a cluster of its own, whose store lets the Identity alice
    /// apply ConfigMaps (by `RoleBinding/alice-writes`), with a control Node for each of `controls`.
    async fn leading(tag: &str, controls: &[&str]) -> (Arc<Shared>, pki::Ca) {
        use crate::cluster::pinned_peer::{node, shared_with};
        let ca = pki::Ca::create().unwrap();
        let shared = shared_with(tag, node(&ca, &format!("{tag}-c")), &[]).await;
        for name in controls {
            let text = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}}}\nspec: {{}}\n");
            let node = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(node).unwrap();
            // Joined: a Node made by hand is not let in.
            let joined = serde_json::json!({ "raftId": kith_store::node_id(name).to_string() });
            store.set_status(&format!("Node/{name}"), Some(joined)).unwrap();
        }
        let id = shared.raft.metrics().borrow().id;
        let one = BTreeMap::from([(id, BasicNode::new(""))]);
        shared.raft.initialize(one).await.unwrap();
        let leads = shared.raft.wait(Some(Duration::from_secs(30)));
        leads.current_leader(id, "leads").await.unwrap();
        let access = "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: alice}\nspec: {}\n---\n\
                      apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: maps}\n\
                      spec: {rules: [{kinds: [ConfigMap], verbs: [apply]}]}\n---\n\
                      apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: alice-writes}\n\
                      spec: {role: maps, subjects: [alice]}\n";
        let resources = kith_api::Resource::from_source(access).unwrap();
        let resources = resources.into_iter().map(Result::unwrap).collect();
        let at = kith_api::store::now();
        shared.write(Command::Apply { resources, at }).await.unwrap();
        (shared, ca)
    }

    fn map(name: &str) -> kith_api::Resource {
        let text =
            format!("apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{name: {name}}}\nspec: {{data: {{a: b}}}}\n");
        kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap()
    }

    fn unbind() -> Command {
        Command::Delete {
            key: "RoleBinding/alice-writes".into(),
        }
    }

    fn alice() -> Caller {
        Caller::Identity("alice".into())
    }

    fn holds(shared: &Shared, key: &str) -> bool {
        shared.store.lock().unwrap().store.get(key).is_some()
    }

    /// Alice's write is let through by her Role as it comes, and her RoleBinding is deleted
    /// before the write is in the log: asked again in the log's order, it is refused.
    #[tokio::test]
    async fn rechecked_refuses_a_write_ordered_after_its_role_went() {
        let (shared, _ca) = leading("recheck-order", &[]).await;
        let first = crate::api::applied(&shared, &alice(), vec![map("first")]).await;
        assert!(
            first.is_ok() && holds(&shared, "ConfigMap/default/first"),
            "alice's Role did not let her write"
        );

        // An access change holds the log: alice's write is asked about and let through, then
        // waits its turn while her RoleBinding goes (by Raft itself, past the turn held here).
        let alone = shared.order.write().await;
        let waiting = shared.clone();
        let late = tokio::spawn(async move { crate::api::applied(&waiting, &alice(), vec![map("late")]).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!late.is_finished(), "the write did not wait for the access change");
        shared.raft.client_write(unbind()).await.unwrap();
        drop(alone);
        match late.await.unwrap() {
            Err(crate::api::ApiError::Store(Error::Invalid(why))) => {
                assert!(why.contains("decided again") && why.contains("ConfigMap"), "{why}")
            }
            Err(_) => panic!("refused for another reason"),
            Ok(_) => panic!("a write ordered after its RoleBinding went was applied"),
        }
        assert!(
            !holds(&shared, "ConfigMap/default/late"),
            "the refused write is in the store"
        );
        // And her next write is refused where it comes in, as before.
        let next = crate::api::applied(&shared, &alice(), vec![map("next")]).await;
        assert!(matches!(next, Err(crate::api::ApiError::Refused(_))));
    }

    /// An Identity's own change to who may do what is decided again too: once its right to make
    /// it went, no apply, delete or rollback of a Role, RoleBinding or Identity of its is applied.
    #[tokio::test]
    async fn rechecked_refuses_an_access_change_by_one_whose_right_went() {
        let (shared, _ca) = leading("recheck-keys", &[]).await;
        let apply = |text: &str| Command::Apply {
            resources: kith_api::Resource::from_source(text)
                .unwrap()
                .into_iter()
                .map(Result::unwrap)
                .collect(),
            at: kith_api::store::now(),
        };
        let keys = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: keys}\n\
                    spec: {rules: [{kinds: [Role, RoleBinding, Identity], verbs: [apply, delete]}]}\n---\n\
                    apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: alice-keys}\n\
                    spec: {role: keys, subjects: [alice]}\n";
        shared.write(apply(keys)).await.unwrap();
        // While it is bound, the change is hers to make.
        let spare = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: spare}\n\
                     spec: {rules: [{kinds: [ConfigMap], verbs: [get]}]}\n";
        let made = shared.submit_as(apply(spare), Some(&alice())).await;
        assert!(made.is_ok() && holds(&shared, "Role/spare"), "{made:?}");
        let revoke = Command::Delete {
            key: "RoleBinding/alice-keys".into(),
        };
        shared.write(revoke).await.unwrap();

        let kept = ["Role/maps", "Role/spare", "RoleBinding/alice-writes", "Identity/alice"];
        let now = |shared: &Shared| {
            let state = shared.store.lock().unwrap();
            kept.map(|key| state.store.get(key).cloned())
        };
        let before = now(&shared);
        let mut tried = vec![
            apply(
                "apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: alice-all}\n\
                 spec: {role: keys, subjects: [alice]}\n",
            ),
            apply(
                "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: maps}\n\
                 spec: {rules: [{kinds: [ConfigMap, Secret, Role, RoleBinding], verbs: [apply, delete]}]}\n",
            ),
            apply("apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: bob}\nspec: {}\n"),
        ];
        for key in kept {
            let at = kith_api::store::now();
            tried.push(Command::Delete { key: key.into() });
            tried.push(Command::Rollback {
                key: key.into(),
                to: 1,
                at,
            });
        }
        for (n, command) in tried.into_iter().enumerate() {
            let said = format!("{command:?}");
            // Hers, and hers as passed on by another node.
            let who = match n % 2 {
                0 => alice(),
                _ => Caller::Via("recheck-keys-f".into(), Box::new(alice())),
            };
            match shared.submit_as(command, Some(&who)).await {
                Err(Error::Invalid(why)) => assert!(why.contains("decided again"), "{said}: {why}"),
                done => panic!("{said} by {who}: {done:?}"),
            }
        }
        assert!(now(&shared) == before, "a refused access change is in the store");
        assert!(!holds(&shared, "RoleBinding/alice-all") && !holds(&shared, "Identity/bob"));
    }

    /// A write passed on by another control node says whose it is, and the leader decides
    /// it again; one that says no one is the node's own, and a name that is no Identity's is refused.
    #[tokio::test]
    async fn rechecked_through_a_follower() {
        use crate::cluster::pinned_peer::{at, node, shared_with};
        use crate::cluster::{Cluster, listen, node_router};
        let (shared, ca) = leading("recheck-via", &["recheck-via-f"]).await;
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap().to_string();
        let c = node(&ca, "recheck-via-c");
        let listener = listen(tcp, pki::server_config(&c).unwrap()).unwrap();
        let app = node_router(shared.clone()).into_make_service_with_connect_info::<Peer>();
        tokio::spawn(async move { drop(axum::serve(listener, app).await) });
        let f = node(&ca, "recheck-via-f");
        let client = Cluster::new(f.clone(), None).unwrap();
        let client = client.to(&at("recheck-via-c", &address, None)).unwrap();
        let url = format!("https://{address}/v1/raft/write");
        // A worker that names an Identity too: what it may write is a worker's, whoever it names.
        let worker = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: recheck-via-w}\nspec: {trust: worker}\n";
        let worker = kith_api::Resource::from_source(worker).unwrap().remove(0).unwrap();
        {
            let store = &mut shared.store.lock().unwrap().store;
            store.apply(worker).unwrap();
            let joined = serde_json::json!({ "raftId": kith_store::node_id("recheck-via-w").to_string() });
            store.set_status("Node/recheck-via-w", Some(joined)).unwrap();
        }
        let worker = Cluster::new(node(&ca, "recheck-via-w"), None).unwrap();
        let worker = worker.to(&at("recheck-via-c", &address, None)).unwrap();
        let send_as = |client: &reqwest::Client, command: Command, who: Option<&[u8]>| {
            let call = client.post(&url).json(&command);
            let call = match who {
                Some(name) => call.header(access::FOR, reqwest::header::HeaderValue::from_bytes(name).unwrap()),
                None => call,
            };
            async move {
                let said = call.send().await.unwrap().text().await.unwrap();
                serde_json::from_str::<Option<(Reply, u64)>>(&said).unwrap_or_else(|e| panic!("{e}: {said}"))
            }
        };
        let send = |command, who: Option<&str>| send_as(&client, command, who.map(str::as_bytes));
        let apply = |name: &str| Command::Apply {
            resources: vec![map(name)],
            at: kith_api::store::now(),
        };
        let written = |text: &str| Command::Apply {
            resources: kith_api::Resource::from_source(text)
                .unwrap()
                .into_iter()
                .map(Result::unwrap)
                .collect(),
            at: kith_api::store::now(),
        };
        let bind = |name: &str| {
            written(&format!(
                "apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{name: {name}}}\nspec: {{role: keys, subjects: [alice]}}\n"
            ))
        };
        let keys = "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: keys}\n\
                    spec: {rules: [{kinds: [Role, RoleBinding, Identity], verbs: [apply, delete]}]}\n---\n\
                    apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: alice-keys}\n\
                    spec: {role: keys, subjects: [alice]}\n";
        shared.write(written(keys)).await.unwrap();

        // While her RoleBindings are there, alice's writes passed on are taken, a RoleBinding too.
        let said = send(apply("via-1"), Some("alice")).await;
        assert!(matches!(said, Some((Ok(_), index)) if index > 0), "{said:?}");
        let said = send(bind("via-bound"), Some("alice")).await;
        assert!(matches!(said, Some((Ok(_), _))), "{said:?}");
        assert!(holds(&shared, "RoleBinding/via-bound"));
        let revoke = |key: &str| Command::Delete { key: key.into() };
        shared.write(revoke("RoleBinding/via-bound")).await.unwrap();
        // A name that is no Identity's is not taken as one, nor one that is not text.
        for name in [&b"local socket"[..], b"\xff"] {
            let said = send_as(&client, apply("via-2"), Some(name)).await;
            assert!(
                matches!(&said, Some((Err(Error::Invalid(why)), 0)) if why.contains("names no Identity")),
                "{said:?}"
            );
        }
        assert!(!holds(&shared, "ConfigMap/default/via-2"));
        shared.write(unbind()).await.unwrap();
        shared.write(revoke("RoleBinding/alice-keys")).await.unwrap();

        // Her right to change access went on the leader: passed on, she cannot bind herself
        // again, nor make an Identity.
        let identity = written("apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: bob}\nspec: {}\n");
        for command in [bind("via-rebound"), identity] {
            let said = send(command, Some("alice")).await;
            assert!(
                matches!(&said, Some((Err(Error::Invalid(why)), 0)) if why.contains("decided again")),
                "{said:?}"
            );
        }
        assert!(!holds(&shared, "RoleBinding/via-rebound") && !holds(&shared, "Identity/bob"));

        // A worker's write is held to what a worker may write, whatever Identity it names.
        let mut worker_said = vec![];
        for (n, name) in [None, Some(&b"alice"[..]), Some(b"local socket"), Some(b"\xff")]
            .into_iter()
            .enumerate()
        {
            let mut os = serde_json::Map::new();
            os.insert("os".into(), format!("v{n}").into());
            let mine = Command::Patch {
                statuses: vec![("Node/recheck-via-w".into(), os)],
            };
            let said = send_as(&worker, mine, name).await;
            let theirs = Command::Apply {
                resources: vec![map(&format!("worker-{n}"))],
                at: kith_api::store::now(),
            };
            let refused = send_as(&worker, theirs, name).await;
            worker_said.push((matches!(said, Some((Ok(_), _))), refused));
        }
        for (n, (taken, refused)) in worker_said.into_iter().enumerate() {
            assert!(taken, "the worker's own status was not taken (header {n})");
            assert!(
                matches!(&refused, Some((Err(Error::Invalid(why)), 0)) if !why.contains("decided again") && !why.contains("names no Identity")),
                "{refused:?}"
            );
            assert!(!holds(&shared, &format!("ConfigMap/default/worker-{n}")));
        }

        // After it went: the follower's own forward says alice's, and the leader refuses it.
        let follower = shared_with("recheck-via-f", f, &[at("recheck-via-c", &address, None)]).await;
        let id = follower.raft.metrics().borrow().id;
        follower
            .raft
            .initialize(BTreeMap::from([(id, BasicNode::new(""))]))
            .await
            .unwrap();
        let applied = follower.raft.wait(Some(Duration::from_secs(30)));
        applied.applied_index_at_least(Some(0), "applies").await.unwrap();
        let leader = BasicNode::new(&address);
        match follower.forward(1, &leader, &apply("via-3"), Some(&alice())).await {
            Forward::Done(Err(Error::Invalid(why)), _) => assert!(why.contains("decided again"), "{why}"),
            Forward::Done(reply, _) => panic!("the leader did not decide again: {reply:?}"),
            _ => panic!("the leader was not reached"),
        }
        assert!(!holds(&shared, "ConfigMap/default/via-3"));
        // The same write as the node's own (no one named) is the node's to make.
        let said = send(apply("via-4"), None).await;
        assert!(matches!(said, Some((Ok(_), _))), "{said:?}");
        assert!(holds(&shared, "ConfigMap/default/via-4") && holds(&shared, "ConfigMap/default/via-1"));
    }

    /// A write passed on to a node that does not lead (any more) is not decided there, on a
    /// store that may be behind: it is sent back, to be passed to whichever leads.
    #[tokio::test]
    async fn rechecked_only_where_the_log_is_led() {
        use crate::cluster::pinned_peer::{at, node, shared_with};
        use crate::cluster::{Cluster, listen, node_router};
        let ca = pki::Ca::create().unwrap();
        let behind = shared_with("recheck-led-c", node(&ca, "recheck-led-c"), &[]).await;
        {
            let text = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: recheck-led-f}\nspec: {}\n";
            let node = kith_api::Resource::from_source(text).unwrap().remove(0).unwrap();
            let store = &mut behind.store.lock().unwrap().store;
            store.apply(node).unwrap();
            let joined = serde_json::json!({ "raftId": kith_store::node_id("recheck-led-f").to_string() });
            store.set_status("Node/recheck-led-f", Some(joined)).unwrap();
        }
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap().to_string();
        let listener = listen(tcp, pki::server_config(&node(&ca, "recheck-led-c")).unwrap()).unwrap();
        let app = node_router(behind.clone()).into_make_service_with_connect_info::<Peer>();
        tokio::spawn(async move { drop(axum::serve(listener, app).await) });
        let client = Cluster::new(node(&ca, "recheck-led-f"), None).unwrap();
        let client = client.to(&at("recheck-led-c", &address, None)).unwrap();
        let command = Command::Apply {
            resources: vec![map("led")],
            at: kith_api::store::now(),
        };
        let call = client.post(format!("https://{address}/v1/raft/write"));
        let said = call.header(access::FOR, "alice").json(&command).send().await.unwrap();
        let said = said.text().await.unwrap();
        // Its store knows no alice: decided here, it would be refused for good.
        let said = serde_json::from_str::<Option<(Reply, u64)>>(&said).unwrap_or_else(|e| panic!("{e}: {said}"));
        assert!(said.is_none(), "{said:?}");
    }

    /// While an access change holds the log, what is no one's (the node's own, a join, the
    /// admin's) goes as it comes.
    #[tokio::test]
    async fn rechecked_leaves_a_nodes_own_writes_alone() {
        let (shared, _ca) = leading("recheck-own", &[]).await;
        let _alone = shared.order.write().await;
        let soon = Duration::from_secs(3);
        let node = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: joins}\nspec: {}\n";
        let node = kith_api::Resource::from_source(node).unwrap().remove(0).unwrap();
        let at = kith_api::store::now();
        let fields = serde_json::json!({ "os": "x" }).as_object().unwrap().clone();
        let writes = [
            (
                Command::Apply {
                    resources: vec![map("own")],
                    at,
                },
                None,
            ),
            (
                Command::Apply {
                    resources: vec![node],
                    at,
                },
                None,
            ),
            (
                Command::Patch {
                    statuses: vec![("Node/joins".into(), fields)],
                },
                None,
            ),
            (
                Command::Apply {
                    resources: vec![map("admin")],
                    at,
                },
                Some(Caller::Admin),
            ),
        ];
        for (command, who) in writes {
            let done = tokio::time::timeout(soon, shared.submit_as(command, who.as_ref())).await;
            assert!(matches!(done, Ok(Ok(_))), "{done:?}");
        }
        assert!(holds(&shared, "ConfigMap/default/own") && holds(&shared, "Node/joins"));
        // What holds the log alone: a change to who may do what, and only that.
        assert!(changes_access(&unbind()));
        assert!(changes_access(&Command::Rollback {
            key: "role/x".into(),
            to: 1,
            at
        }));
        assert!(changes_access(&Command::Import {
            store: Default::default()
        }));
        // (A KindDefinition says whether a kind is namespaced, so which rule matches it.)
        assert!(changes_access(&Command::Delete {
            key: "KindDefinition/widgets".into()
        }));
        assert!(!changes_access(&Command::Delete {
            key: "ConfigMap/default/own".into()
        }));
        assert!(!changes_access(&Command::Status { statuses: vec![] }));
    }

    /// What the leader asks again of a rollback, a delete and anything else: the kind's own
    /// right, what the kind reaches into besides, and nothing past an apply, delete or rollback.
    #[test]
    fn rechecked_rollback_delete_and_the_rest() {
        let mut store = kith_api::store::Store::default();
        let access = "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: carol}\nspec: {}\n---\n\
                      apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: dave}\nspec: {}\n---\n\
                      apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: kinds}\n\
                      spec: {rules: [{kinds: [Share, Backup, Release, ConfigMap], verbs: [apply]}]}\n---\n\
                      apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: files}\n\
                      spec: {rules: [{kinds: [Volume, Secret], verbs: [get, apply]}]}\n---\n\
                      apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: carol-kinds}\n\
                      spec: {role: kinds, subjects: [carol, dave]}\n---\n\
                      apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: dave-files}\n\
                      spec: {role: files, subjects: [dave]}\n";
        for resource in kith_api::Resource::from_source(access).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let (carol, dave) = (Caller::Identity("carol".into()), Caller::Identity("dave".into()));
        let back = |key: &str| Command::Rollback {
            key: key.into(),
            to: 1,
            at: kith_api::store::now(),
        };
        let refused = crate::api::refused;
        // Apply on a Share or a Backup is not enough: what it reaches into is asked too.
        let why = refused(&store, &carol, &back("Share/default/s")).expect("a Share without Volume");
        assert!(why.contains("apply Volume") && why.contains("decided again"), "{why}");
        let why = refused(&store, &carol, &back("Backup/default/b")).expect("a Backup without Volume");
        assert!(why.contains("get Volume"), "{why}");
        // With it, both go back.
        assert_eq!(refused(&store, &dave, &back("Share/default/s")), None);
        assert_eq!(refused(&store, &dave, &back("Backup/default/b")), None);
        // A Release goes back while its binding stands, and not once it is gone.
        assert_eq!(refused(&store, &carol, &back("Release/default/r")), None);
        // A delete asks Delete, which Apply is not.
        let delete = Command::Delete {
            key: "ConfigMap/default/m".into(),
        };
        let why = refused(&store, &carol, &delete).expect("a delete without Delete");
        assert!(why.contains("delete ConfigMap"), "{why}");
        // Nothing but an apply, a delete or a rollback is an Identity's to write.
        let why = refused(&store, &dave, &Command::Status { statuses: vec![] }).expect("a Status");
        assert!(why.contains("not an apply, a delete or a rollback"), "{why}");
        store.delete("RoleBinding/carol-kinds").unwrap();
        let why = refused(&store, &carol, &back("Release/default/r")).expect("a Release, unbound");
        assert!(why.contains("apply Release"), "{why}");
    }

    /// Neither wait is past [`PATIENCE`]: an Identity's write behind an access change that
    /// never finishes, and an access change behind an Identity's write that never finishes, are
    /// each refused, to be tried again.
    #[tokio::test]
    async fn rechecked_wait_is_bounded() {
        let ((one, _), (two, _)) = tokio::join!(leading("recheck-wait-1", &[]), leading("recheck-wait-2", &[]));
        let _alone = one.order.write().await;
        let _beside = two.order.read().await;
        let begun = Instant::now();
        let at = kith_api::store::now();
        let theirs = Command::Apply {
            resources: vec![map("waits")],
            at,
        };
        let alice = alice();
        let (written, changed) = tokio::join!(one.submit_as(theirs, Some(&alice)), two.write(unbind()));
        let took = begun.elapsed();
        for done in [written.map(drop), changed.map(drop)] {
            assert!(
                matches!(&done, Err(Error::Io(why)) if why.contains("try again")),
                "{done:?}"
            );
        }
        assert!(took >= PATIENCE && took < PATIENCE + Duration::from_secs(5), "{took:?}");
        assert!(!holds(&one, "ConfigMap/default/waits") && holds(&two, "RoleBinding/alice-writes"));
    }
}
