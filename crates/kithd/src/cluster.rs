//! Nodes talking to nodes: the API over TLS on TCP, where both ends show a
//! certificate from the cluster CA, and how a new node gets one.
//!
//! ```text
//! GET  /v1/ca                          -> the CA certificate (PEM)     no certificate needed
//! POST /v1/join {token, name, port}    -> {ca, cert, key}              no certificate needed
//! POST /v1/claim {token, name}         -> {ca, cert, key}              no certificate needed
//! POST /v1/tokens                      -> {token}                      local socket, or an Identity that may apply Nodes, Roles and RoleBindings
//! POST /v1/identities/<name>/certificate -> {ca, cert, key}            local socket only
//! GET  /v1/cluster                    -> {node, leader, voters, learners, applied, mesh}   local socket only
//! ```
//! Raft (`raft.rs`), which gives every node its own copy of the store, is for members
//! only. The resource API is for members and for Identities with a certificate, who
//! may do what their Roles allow (`access.rs`).
//

use crate::pki::{self, Identity};
use crate::{Shared, api};
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::IncomingStream;
use axum::{Json, Router};
use kith_store::Command;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_rustls::server::TlsStream;

/// This node as a member of a cluster.
pub struct Cluster {
    pub me: Identity,
    /// Held by the node that can admit others.
    pub ca: Option<pki::Ca>,
    pub tokens: pki::Tokens,
    /// Tokens of another use: who sends one becomes the cluster's first admin (`--claim`).
    pub claims: pki::Tokens,
    joining: tokio::sync::Mutex<()>,
    /// Calls other nodes as this one: any node of the cluster is taken at the address. Only for
    /// calls that carry nothing for one node alone; the rest go through [`Cluster::to`].
    pub client: reqwest::Client,
    /// The clients [`Cluster::to`] made, by node name: each with the print it was pinned to.
    pinned: std::sync::Mutex<std::collections::HashMap<String, (Option<String>, reqwest::Client)>>,
}

type Fallible<T> = Result<T, String>;

fn client(ca: &str, me: Option<&Identity>) -> Fallible<reqwest::Client> {
    client_for(ca, me, None)
}

/// A client that calls one node as `me`: no other node's certificate is taken at its address.
pub(crate) fn client_for(ca: &str, me: Option<&Identity>, pin: Option<pki::Held>) -> Fallible<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .use_preconfigured_tls(pki::client_config(ca, me, pin)?)
        .connect_timeout(Duration::from_secs(5))
        .no_proxy();
    builder.build().map_err(|e| format!("setting up the node client: {e}"))
}

impl Cluster {
    pub fn new(me: Identity, ca: Option<pki::Ca>) -> Fallible<Cluster> {
        Ok(Cluster {
            client: client(&me.ca, Some(&me))?,
            me,
            ca,
            tokens: pki::Tokens::default(),
            claims: pki::Tokens::default(),
            joining: tokio::sync::Mutex::new(()),
            pinned: Default::default(),
        })
    }

    /// A client that calls the node `to` and no other: its certificate must be that node's by
    /// name, and by the key its Node names where it names one. One per node (a new one when
    /// the key changes), so a connection kept open is not made again for each call.
    pub fn to(&self, to: &crate::view::Upstream) -> Fallible<reqwest::Client> {
        self.to_name(&to.name, to.certificate.clone())
    }

    /// [`Cluster::to`] of the node called `name` whose Node names the key `print`, if it does.
    pub fn to_name(&self, name: &str, print: Option<String>) -> Fallible<reqwest::Client> {
        self.pin_to(name.to_string(), pki::Who::Name(name.to_string()), print)
    }

    /// A client that calls the voter whose id in Raft is `id`, for a voter that has no Node in
    /// the store: its certificate must be for a node name that gives that id. That is weaker than
    /// [`Cluster::to`]: any name the CA issued whose id it is will do, and a Node of a name
    /// that is not the voter's cannot have it, as `join` refuses an id that is taken.
    pub fn to_voter(&self, id: kith_store::NodeId) -> Fallible<reqwest::Client> {
        // (Not a node name, so `forget_but` knows these apart.)
        self.pin_to(format!("#{id}"), pki::Who::Id(id), None)
    }

    fn pin_to(&self, key: String, who: pki::Who, print: Option<String>) -> Fallible<reqwest::Client> {
        let mut made = self.pinned.lock().expect("nothing panics holding the pinned clients");
        if let Some((kept, client)) = made.get(&key)
            && *kept == print
        {
            return Ok(client.clone());
        }
        let client = client_for(&self.me.ca, Some(&self.me), Some((who, print.clone())))?;
        made.insert(key, (print, client.clone()));
        Ok(client)
    }

    /// Forget the clients of nodes that are no more (`is_node` says which are), so what [`Cluster::to`]
    /// holds is as big as the nodes there are, whatever Nodes came and went. (A voter's, by id,
    /// stay: as many as the ids Raft has had as members, which only an admin's changes make.)
    pub fn forget_but(&self, is_node: impl Fn(&str) -> bool) {
        let mut made = self.pinned.lock().expect("nothing panics holding the pinned clients");
        made.retain(|key, _| key.starts_with('#') || is_node(key));
    }
}

/// An error with what caused it: a refused certificate is the last of the chain, and names
/// the node that was called and who answered.
pub fn why(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text = format!("{text}: {cause}");
        source = cause.source();
    }
    text
}

/// Who is on the other end of a TCP connection.
#[derive(Clone, Debug)]
pub struct Peer {
    pub addr: SocketAddr,
    /// Whose certificate it showed; `None` when it showed none.
    pub subject: Option<pki::Subject>,
}

/// A TLS connection. One from a caller without a certificate (a guest) keeps one of the
/// few guest slots and is cut off after `GUEST_TIME`: a join is two short requests.
pub struct Connection {
    stream: TlsStream<TcpStream>,
    guest: Option<(Slot, Pin<Box<tokio::time::Sleep>>)>,
}

impl Connection {
    /// An error once a guest has outstayed its time.
    fn check(&mut self, cx: &mut Context<'_>) -> std::io::Result<()> {
        let late = self
            .guest
            .as_mut()
            .is_some_and(|(_, deadline)| deadline.as_mut().poll(cx).is_ready());
        if late {
            Err(std::io::ErrorKind::TimedOut.into())
        } else {
            Ok(())
        }
    }
}

impl AsyncRead for Connection {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.check(cx)?;
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.check(cx)?;
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Accepts TCP connections and hands them on once TLS is up.
pub struct TlsListener {
    ready: mpsc::Receiver<(Connection, Peer)>,
    local: SocketAddr,
}

/// Handshakes in progress plus guest connections at once; more wait in the kernel's queue.
/// Members are not counted: they are trusted, and few.
const GUESTS: usize = 64;
/// How long a handshake may take, and how long a guest connection may last.
const GUEST_TIME: Duration = Duration::from_secs(15);

/// Of the [`GUESTS`] slots, how many one address may hold: a host that opens connections
/// and says nothing fills its own share, and nobody else's.
//
// ponytail: many addresses still fill the slots between them. A firewall then, or slots
// kept apart for the addresses the members have, if that is ever seen.
const GUESTS_EACH: u32 = GUESTS as u32 / 8;

/// How many slots each address holds now.
#[derive(Default)]
struct Crowd(std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>);

/// A guest slot and its address's hold on it.
type Slot = (OwnedSemaphorePermit, Place);

/// One address's hold on a slot, given back when dropped.
struct Place(Arc<Crowd>, Option<std::net::IpAddr>);

impl Crowd {
    /// A place for a connection from `from`, unless that address holds its share already.
    /// An IPv6 /64 is one address here (it is one host's to hand out), and this machine's
    /// own are not counted: only what runs on it can use them.
    fn place(self: &Arc<Crowd>, from: std::net::IpAddr) -> Option<Place> {
        use std::net::IpAddr;
        let from = match from {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(from, IpAddr::V4),
            v4 => v4,
        };
        if from.is_loopback() {
            return Some(Place(self.clone(), None));
        }
        let from = match from {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
            v4 => v4,
        };
        let mut held = self.0.lock().expect("nothing panics holding the crowd");
        let count = held.entry(from).or_default();
        if *count >= GUESTS_EACH {
            return None;
        }
        *count += 1;
        Some(Place(self.clone(), Some(from)))
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let Some(from) = self.1 else { return };
        let mut held = self.0.0.lock().expect("nothing panics holding the crowd");
        if let Some(count) = held.get_mut(&from) {
            *count -= 1;
            if *count == 0 {
                held.remove(&from);
            }
        }
    }
}

pub fn listen(tcp: TcpListener, config: Arc<rustls::ServerConfig>) -> std::io::Result<TlsListener> {
    let local = tcp.local_addr()?;
    let (tx, ready) = mpsc::channel(GUESTS);
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let slots = Arc::new(Semaphore::new(GUESTS));
    let crowd = Arc::new(Crowd::default());
    tokio::spawn(async move {
        loop {
            let Ok(slot) = slots.clone().acquire_owned().await else {
                return;
            };
            let Ok((stream, addr)) = tcp.accept().await else {
                // Out of file descriptors, most likely: let some close.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            // An address that holds its share already is hung up on: it waits for itself.
            let Some(place) = crowd.place(addr.ip()) else {
                continue;
            };
            let slot: Slot = (slot, place);
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                // A client that connects and says nothing does not hold a slot for long.
                let shaken = tokio::time::timeout(GUEST_TIME, acceptor.accept(stream)).await;
                if let Ok(Ok(stream)) = shaken {
                    let certs = stream.get_ref().1.peer_certificates();
                    let subject = certs.and_then(|certs| pki::subject_of(certs.first()?));
                    // Whoever the CA vouches for gives the slot back; a guest keeps it, for a short while.
                    // ponytail: that includes an Identity or a node since deleted (each request of theirs is refused, the slot is not kept), until certificates expire or are revoked by more than the store.
                    let guest = subject
                        .is_none()
                        .then(|| (slot, Box::pin(tokio::time::sleep(GUEST_TIME))));
                    let _ = tx.send((Connection { stream, guest }, Peer { addr, subject })).await;
                }
            });
        }
    });
    Ok(TlsListener { ready, local })
}

impl axum::serve::Listener for TlsListener {
    type Io = Connection;
    type Addr = Peer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(accepted) => accepted,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Peer> {
        Ok(Peer {
            addr: self.local,
            subject: None,
        })
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Peer {
        stream.remote_addr().clone()
    }
}

type Refusal = (StatusCode, Json<serde_json::Value>);

pub(crate) fn refuse(status: StatusCode, why: impl std::fmt::Display) -> Refusal {
    (status, Json(serde_json::json!({ "error": why.to_string() })))
}

fn cluster(shared: &Shared) -> Result<&Cluster, Refusal> {
    let none = || {
        refuse(
            StatusCode::NOT_FOUND,
            "this kithd is not part of a cluster (start it with --listen)",
        )
    };
    shared.cluster.as_ref().ok_or_else(none)
}

pub const EVICTED: &str = "this certificate is not a node of this cluster's any more: its Node was deleted, or the \
     name has joined again with another";

/// Set by `--admit-deleted-nodes`: [`admitted`] says yes to every node certificate.
pub static ADMIT_DELETED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Does the certificate for the key `key` (DER) still stand for the node `name`? Its Node
/// has to be in the store this node has, admitted (a Node made by hand never joined), and
/// to name that key: a name that joined again got another. A Node from before certificates
/// were written down names none, and stands by its name.
pub fn admitted(shared: &Shared, name: &str, key: &[u8]) -> bool {
    if ADMIT_DELETED.load(std::sync::atomic::Ordering::Relaxed) {
        return true;
    }
    let state = shared.store.lock().expect("a handler panicked holding the store");
    stands(&state.store, name, key)
}

/// [`admitted`], asked of a store.
fn stands(store: &kith_api::store::Store, name: &str, key: &[u8]) -> bool {
    let node = store.get(&node_key(name));
    let Some(status) = node.and_then(|node| node.status.as_ref()) else {
        return false;
    };
    let joined = status["raftId"].is_string();
    joined
        && status["certificate"]
            .as_str()
            .is_none_or(|print| print == pki::key_print(key))
}

/// What the leader sends a node to bring its store up to date, and what asks for its vote:
/// the only routes a node this one has not heard of is let into ([`unheard`]).
const CATCHING_UP: [&str; 3] = ["/v1/raft/append", "/v1/raft/vote", "/v1/raft/snapshot"];

/// Is `path` one of those routes, is there no Node `name` in the store of the node `me`,
/// which has applied its log up to `applied`, and can this node not know that one was deleted? A node that was away while
/// another joined must take what that one sends it (it may lead by now), or it would never
/// catch up. A certificate from a join says by which index of the store its Node was there
/// (`born`): a store that is past it had the Node, and it is gone. One that says none (the
/// node the cluster started on, whose Node is older than every join; a certificate from
/// before this) is unheard of only by a node that has not heard of itself: one that has
/// just joined, or the one that was deleted.
fn unheard(store: &kith_api::store::Store, me: &str, applied: u64, path: &str, name: &str, born: Option<u64>) -> bool {
    CATCHING_UP.contains(&path)
        && store.get(&node_key(name)).is_none()
        && match born {
            Some(born) => applied < born,
            None => store.get(&node_key(me)).is_none(),
        }
}

/// [`unheard`], asked of this node.
fn catching_up(shared: &Shared, path: &str, name: &str, born: Option<u64>) -> bool {
    let Some(cluster) = &shared.cluster else {
        return false;
    };
    // (Read before the store: an index that is a moment old only says "behind" a moment longer.)
    let applied = shared.raft.metrics().borrow().last_applied.map_or(0, |log| log.index);
    let state = shared.store.lock().expect("a handler panicked holding the store");
    unheard(&state.store, &cluster.me.name, applied, path, name, born)
}

/// What a worker (`spec.trust`) is refused among the nodes' routes: the second hop of
/// `kith run`, and Raft's own messages, which only one that votes or leads sends.
const CONTROL_ONLY: [&str; 4] = ["/v1/raft/append", "/v1/raft/vote", "/v1/raft/snapshot", RUN_HOP];
const RUN_HOP: &str = "/v1/run-hop";

/// Whether the Node `name` votes in the membership this node has. Raft's messages are taken
/// from a worker for as long as it does (it hands its vote over itself, `raft::next_change`):
/// refusing them the moment a voter is made a worker would cut a store's only voter off from
/// the others, with nothing left that could agree on putting it right.
pub(crate) fn votes(shared: &Shared, name: &str) -> bool {
    // (Its id in Raft is made from the name its certificate has: nothing a node can write.)
    let id = kith_store::node_id(name);
    let metrics = shared.raft.metrics().borrow().clone();
    metrics
        .membership_config
        .membership()
        .voter_ids()
        .any(|voter| voter == id)
}

async fn members_only(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    // A worker that runs from a view keeps no store: nothing of Raft's is its to take.
    let viewing = shared.view.borrow().is_some();
    if viewing && path.starts_with("/v1/raft/") {
        let why = "this node is a worker: it keeps a view of the store and takes no part in it";
        return refuse(StatusCode::FORBIDDEN, why).into_response();
    }
    let (status, why) = match &peer.subject {
        Some(pki::Subject::Node(name, key, born))
            if admitted(&shared, name, key) || catching_up(&shared, path, name, *born) =>
        {
            // A worker does not vote, is not followed, and its word for who asked is not taken.
            let worker = CONTROL_ONLY.contains(&path) && crate::access::worker(&shared, name);
            if worker && (path == RUN_HOP || !votes(&shared, name)) {
                let why = format!("node {name} is a worker: only a control node sends this");
                if shared.audit.stranger() {
                    let who = crate::access::Caller::Node(name.clone());
                    let refused = Err(why.clone());
                    shared
                        .audit
                        .record(&who, request.method().as_str(), vec![path.to_string()], refused);
                }
                return refuse(StatusCode::FORBIDDEN, why).into_response();
            }
            return next.run(request).await;
        }
        Some(pki::Subject::Node(name, ..)) => {
            // (One a minute, as on the API.)
            if shared.audit.stranger() {
                let who = crate::access::Caller::Node(name.clone());
                let refused = Err(EVICTED.to_string());
                shared
                    .audit
                    .record(&who, request.method().as_str(), vec![path.to_string()], refused);
            }
            (StatusCode::UNAUTHORIZED, EVICTED)
        }
        Some(pki::Subject::User(..)) => (
            StatusCode::FORBIDDEN,
            "this is for the cluster's nodes, not for an Identity",
        ),
        None => (
            StatusCode::UNAUTHORIZED,
            "a certificate from this cluster's CA is needed",
        ),
    };
    refuse(status, why).into_response()
}

/// What is served on the TCP port.
pub fn node_router(shared: Arc<Shared>) -> Router {
    let open = Router::new()
        .route("/v1/ca", get(ca))
        .route("/v1/join", post(join))
        .route("/v1/claim", post(claim))
        .route("/v1/unlock", post(crate::crypt::unlock))
        .layer(DefaultBodyLimit::max(4096))
        .with_state(shared.clone());
    let ping = Router::new().route("/v1/ping", post(crate::members::ping));
    let ping = ping.layer(DefaultBodyLimit::max(64 << 10)).with_state(shared.clone());
    let callers = axum::middleware::from_fn_with_state(shared.clone(), crate::access::caller);
    let api = api::router(shared.clone()).layer(callers);
    // (The second hop of `kith run`: the caller was checked on the first node.)
    let hop = Router::new()
        .route("/v1/run-hop", post(api::run::hop))
        .route("/v1/view", get(crate::view::serve))
        .route("/v1/blob-copy/{name}", get(crate::blobs::copy))
        .route("/v1/volume-copy/{namespace}/{name}", get(crate::replicas::copy))
        .route(
            "/v1/volume-key/{namespace}/{name}",
            get(crate::encrypted::get).put(crate::encrypted::put),
        )
        .with_state(shared.clone());
    let members = crate::raft::router(shared.clone()).merge(ping).merge(hop);
    let members_only = axum::middleware::from_fn_with_state(shared, members_only);
    open.merge(crate::ui::pages())
        .merge(api)
        .merge(members.layer(members_only))
}

/// What only the local socket serves.
pub fn admin_router(shared: Arc<Shared>) -> Router {
    let admin = Router::new().route("/v1/identities/{name}/certificate", post(certificate));
    admin.route("/v1/cluster", get(status)).with_state(shared)
}

const CA_ELSEWHERE: &str =
    "only the node that holds the cluster CA key can do this: the one the cluster was started on";

/// A certificate and key for the Identity `name`, which is made if it is not there. Its
/// `publicKey` becomes this key: a certificate it had before stops standing for it.
async fn certificate(
    State(shared): State<Arc<Shared>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<Joined>, Refusal> {
    issue(&shared, &name, Vec::new(), crate::access::Caller::Admin, "certificate").await
}

#[derive(Deserialize)]
struct ClaimRequest {
    token: String,
    name: String,
}

/// The cluster's first admin, on a node nobody can log in to (kith OS): whoever sends the
/// token kithd printed at its start (`--claim`) is given a certificate for a new Identity
/// that may do everything. The token is good once.
async fn claim(State(shared): State<Arc<Shared>>, Json(request): Json<ClaimRequest>) -> Result<Json<Joined>, Refusal> {
    let cluster = cluster(&shared)?;
    // The token first: someone without one learns nothing about the cluster.
    let refused = "the claim token is wrong, already used, or older than an hour";
    if cluster.claims.good(&request.token, false).is_none() {
        return Err(refuse(StatusCode::FORBIDDEN, refused));
    }
    pki::valid_name(&request.name).map_err(|e| refuse(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    // Only a cluster nobody administers yet: a token printed before the socket's admin
    // made an Identity must not give that Identity's name, or a Role, to someone else.
    if claimed(&shared) {
        let why = "this cluster has an Identity already: its admin gives out certificates (`kith identity cert`)";
        return Err(refuse(StatusCode::CONFLICT, why));
    }
    // (Spent here, and once: of two who send it together, one is refused.)
    if cluster.claims.good(&request.token, true).is_none() {
        return Err(refuse(StatusCode::FORBIDDEN, refused));
    }
    let grant = serde_json::json!([
        { "apiVersion": kith_api::API_VERSION, "kind": "Role", "metadata": { "name": "cluster-admin" },
          "spec": { "rules": [{ "kinds": ["*"], "verbs": ["get", "list", "watch", "apply", "delete", "exec"] }] } },
        { "apiVersion": kith_api::API_VERSION, "kind": "RoleBinding",
          "metadata": { "name": format!("cluster-admin-{}", request.name) },
          "spec": { "role": "cluster-admin", "subjects": [request.name] } },
    ]);
    let grant = serde_json::from_value(grant).expect("a Role and a RoleBinding with valid names");
    let caller = crate::access::Caller::Identity(request.name.clone());
    let done = issue(&shared, &request.name, grant, caller, "claim").await;
    // (The token is spent: where nothing came of it, the console gets another.)
    let done = done.inspect_err(|_| offer_claim(&shared))?;
    eprintln!("kithd: {} claimed this cluster: it may do everything", request.name);
    Ok(done)
}

fn claimed(shared: &Shared) -> bool {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    state.store.list(Some("Identity")).next().is_some()
}

/// `--claim`: while the cluster has no Identity, say how its first admin is made.
pub fn offer_claim(shared: &Shared) {
    let Some(Cluster {
        ca: Some(ca), claims, ..
    }) = &shared.cluster
    else {
        return eprintln!("kithd: --claim is for the node the cluster was started on: this one cannot make its admin");
    };
    if claimed(shared) {
        return;
    }
    match claims.mint(&ca.cert, pki::Lets::Control) {
        Ok(token) => eprintln!(
            "kithd: nobody administers this cluster from outside yet. For an hour, whoever sends this token to /v1/claim does: {token}"
        ),
        Err(e) => eprintln!("kithd: no claim token: {e}"),
    }
}

/// A certificate for Identity `name`, applied together with `more` (what it is granted).
async fn issue(
    shared: &Arc<Shared>,
    name: &str,
    more: Vec<kith_api::Resource>,
    caller: crate::access::Caller,
    what: &str,
) -> Result<Json<Joined>, Refusal> {
    let cluster = cluster(shared)?;
    let Some(ca) = &cluster.ca else {
        return Err(refuse(StatusCode::CONFLICT, CA_ELSEWHERE));
    };
    let issued = ca.issue_user(name);
    let (cert, key, public) = issued.map_err(|e| refuse(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let key_of = format!("Identity/{name}");
    let identity = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        state.store.get(&key_of).cloned()
    };
    let mut identity = identity.unwrap_or_else(|| {
        let new = serde_json::json!({
            "apiVersion": kith_api::API_VERSION, "kind": "Identity", "metadata": { "name": name }, "spec": {},
        });
        serde_json::from_value(new).expect("an Identity with a valid name")
    });
    identity.spec["publicKey"] = public.into();
    let resources = std::iter::once(identity).chain(more).collect();
    let done = shared
        .submit(Command::Apply {
            resources,
            at: kith_api::store::now(),
        })
        .await;
    let said = done.as_ref().map(drop).map_err(ToString::to_string);
    shared.audit.record(&caller, what, vec![key_of], said);
    done.map_err(|e| refuse(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let ca = cluster.me.ca.clone();
    Ok(Json(Joined {
        ca,
        cert,
        key,
        peers: Vec::new(),
        view: None,
    }))
}

/// Who leads the store and who votes, as this node sees it. Nodes are named where a
/// Node says which Raft id is whose, and shown as that id otherwise.
async fn status(State(shared): State<Arc<Shared>>) -> Json<serde_json::Value> {
    let metrics = shared.raft.metrics().borrow().clone();
    let names: std::collections::BTreeMap<String, String> = {
        let store = shared.store.lock().expect("a handler panicked holding the store");
        let named = |node: &kith_api::Resource| {
            let id = node.status.as_ref()?["raftId"].as_str()?;
            Some((id.to_string(), node.metadata.name.clone()))
        };
        store.store.list(Some("Node")).filter_map(named).collect()
    };
    let me = shared.cluster.as_ref().map_or("this node", |cluster| &cluster.me.name);
    let name = |id: u64| match names.get(&id.to_string()) {
        Some(name) => name.clone(),
        None if id == metrics.id => me.to_string(),
        None => id.to_string(),
    };
    let membership = metrics.membership_config.membership();
    let voters: Vec<u64> = membership.voter_ids().collect();
    let by_name = |ids: Vec<u64>| {
        let mut names: Vec<String> = ids.into_iter().map(name).collect();
        names.sort();
        names
    };
    let learners = membership.nodes().map(|(id, _)| *id).filter(|id| !voters.contains(id));
    // A worker that runs from a view: the index its view is at, and whom it is sent by.
    if let Some(at) = *shared.view.borrow() {
        let upstream = shared.upstream.lock().expect("nothing panics holding the upstream");
        return Json(serde_json::json!({
            "node": me,
            "view": { "applied": at, "from": upstream.as_ref().map(|(address, _)| address) },
            "mesh": shared.mesh.lock().expect("nothing panics holding the mesh").clone(),
        }));
    }
    Json(serde_json::json!({
        "node": name(metrics.id),
        "leader": metrics.current_leader.map(name),
        "learners": by_name(learners.collect()),
        "voters": by_name(voters),
        "applied": metrics.last_applied.map_or(0, |log| log.index),
        "mesh": shared.mesh.lock().expect("nothing panics holding the mesh").clone(),
    }))
}

async fn ca(State(shared): State<Arc<Shared>>) -> Result<String, Refusal> {
    Ok(cluster(&shared)?.me.ca.clone())
}

/// A join token: for the local socket, and for an Identity that may apply Nodes, Roles
/// and RoleBindings (a node nobody can log in to has no socket to ask). A node may do
/// everything, so who brings one in must be someone who could give itself every right
/// anyway. Not for a node: one that is taken over must not be able to bring others in.
pub async fn token(
    State(shared): State<Arc<Shared>>,
    axum::Extension(caller): axum::Extension<crate::access::Caller>,
    axum::extract::Query(asked): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if caller.node().is_some() {
        return refuse(StatusCode::FORBIDDEN, "a node may not make join tokens").into_response();
    }
    let node = |_: &_| {
        ["Node", "Role", "RoleBinding"]
            .map(|kind| (kind.to_string(), None))
            .to_vec()
    };
    if let Err(refused) = api::permit(&shared, &caller, kith_api::kinds::Verb::Apply, node) {
        return refused.into_response();
    }
    // `?trust=worker`: the node it lets in is one (`spec.trust`), from its first moment, and
    // is sent a view of the store; `&store=whole`: the store all the same (it serves ingress).
    let said = |field: &str| asked.get(field).map(String::as_str);
    let lets = match (said("trust"), said("store")) {
        (None | Some("control"), None) => pki::Lets::Control,
        (Some("worker"), None) => pki::Lets::Worker,
        (Some("worker"), Some("whole")) => pki::Lets::WorkerWhole,
        (trust, store) => {
            let (trust, store) = (trust.unwrap_or("control"), store.unwrap_or_default());
            let why = format!(
                "trust is `control` or `worker` (not `{trust}`), and store is `whole` for a worker or left out (not `{store}`)"
            );
            return refuse(StatusCode::UNPROCESSABLE_ENTITY, why).into_response();
        }
    };
    let minted = mint(&shared, lets);
    let said = minted.as_ref().map(drop).map_err(|_| "no token".to_string());
    shared.audit.record(&caller, "token", vec!["Node".into()], said);
    minted.into_response()
}

/// `/v1/netboot`: GET says whether this node answers machines that start from the
/// network; PUT turns it on (the body is the network boot file; `?macs=` the cards'
/// addresses, with commas, `minutes=` and `disk=`); DELETE turns it off. See netboot.rs.
/// It makes join tokens and has machines erase their disks: for who may make tokens.
pub async fn netboot(
    State(shared): State<Arc<Shared>>,
    axum::Extension(caller): axum::Extension<crate::access::Caller>,
    method: axum::http::Method,
    axum::extract::Query(asked): axum::extract::Query<std::collections::BTreeMap<String, String>>,
    image: axum::body::Body,
) -> Response {
    use crate::netboot;
    if caller.node().is_some() {
        return refuse(StatusCode::FORBIDDEN, "a node may not turn netboot on or off").into_response();
    }
    let node = |_: &_| {
        ["Node", "Role", "RoleBinding"]
            .map(|kind| (kind.to_string(), None))
            .to_vec()
    };
    if let Err(refused) = api::permit(&shared, &caller, kith_api::kinds::Verb::Apply, node) {
        return refused.into_response();
    }
    if method == axum::http::Method::GET {
        return Json(netboot::status()).into_response();
    }
    let done = if method == axum::http::Method::DELETE {
        netboot::off();
        Ok(netboot::status())
    } else {
        async {
            // (Read only now: who may not turn it on has sent 96 MB to nobody.)
            let image = axum::body::to_bytes(image, 96 << 20).await;
            let image = image.map_err(|_| "the boot file did not arrive whole, or is more than 96 MB")?;
            let ca = cluster(&shared)
                .ok()
                .and_then(|cluster| Some((cluster, cluster.ca.as_ref()?)));
            let (cluster, ca) = ca.ok_or(CA_ELSEWHERE)?;
            let macs = asked.get("macs").map(String::as_str).unwrap_or_default();
            let mut machines = Vec::new();
            for mac in macs.split(',').filter(|mac| !mac.is_empty()) {
                let card =
                    netboot::mac(mac).ok_or(format!("`{mac}` is not a network card's address (52:54:00:12:34:56)"))?;
                machines.push(card);
            }
            let minutes = asked.get("minutes").map_or(Ok(30), |minutes| minutes.parse());
            let minutes = minutes.map_err(|_| "minutes is a number")?;
            let disk = asked.get("disk").map_or("only", String::as_str);
            let encrypt = asked.get("encrypt").is_some_and(|encrypt| encrypt == "true");
            netboot::on(image.to_vec(), machines, minutes, disk, encrypt, || {
                cluster.tokens.mint(&ca.cert, pki::Lets::Control)
            })
            .await
        }
        .await
    };
    let said = done.as_ref().map(drop).map_err(String::clone);
    shared.audit.record(
        &caller,
        "netboot",
        vec![format!("{method} {}", asked.get("macs").map_or("", String::as_str))],
        said,
    );
    match done {
        Ok(status) => Json(status).into_response(),
        Err(why) => refuse(StatusCode::BAD_REQUEST, why).into_response(),
    }
}

fn mint(shared: &Shared, lets: pki::Lets) -> Result<Json<serde_json::Value>, Refusal> {
    let cluster = cluster(shared)?;
    let Some(ca) = &cluster.ca else {
        return Err(refuse(StatusCode::CONFLICT, CA_ELSEWHERE));
    };
    let token = cluster.tokens.mint(&ca.cert, lets);
    let token = token.map_err(|e| refuse(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(serde_json::json!({ "token": token, "expiresInSeconds": 3600 })))
}

#[derive(Serialize, Deserialize)]
struct JoinRequest {
    token: String,
    name: String,
    /// The port the new node serves its API on, at the address this request comes from.
    port: u16,
    /// From a node that roams: it is to be reached on the mesh, and this is its key there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mesh: Option<OnMesh>,
    /// It can run from a view if it is let in as a worker (a kithd from before views says
    /// nothing; one that serves ingress says no). What it is sent is its token's to say.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    view: bool,
}

#[derive(Serialize, Deserialize)]
pub struct OnMesh {
    /// The public key, in hex.
    pub key: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
pub struct Joined {
    pub ca: String,
    pub cert: String,
    pub key: String,
    /// For a node that roams: the nodes on the mesh (`name`, `key`, `endpoint`), to call
    /// before it has the store.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<serde_json::Value>,
    /// For a worker that runs from a view: the node that let it in, which it asks for its first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<pki::Pin>,
}

fn node_key(name: &str) -> String {
    format!("Node/{name}")
}

/// Put `Node/<name>` in the store: reachable at `address`, `id` in Raft (as text: not
/// every JSON reader keeps 64 bits), and holding the certificate whose key's print is
/// `print` ([`admitted`]), with what it says of itself on the mesh if it joined there, all
/// in one entry: no entry makes it half a node. The leader then starts sending it the store.
/// `more` is what else its status says from the start: `ca` (it is the node that holds the CA
/// key, which no change may make a worker), `view` (a worker that is sent a view instead).
pub async fn register(
    shared: &Shared,
    name: &str,
    address: &str,
    id: u64,
    print: &str,
    more: serde_json::Value,
) -> Result<(), kith_api::store::Error> {
    let node = serde_json::json!({
        "apiVersion": kith_api::API_VERSION, "kind": "Node", "metadata": { "name": name }, "spec": {},
    });
    let node: kith_api::Resource = serde_json::from_value(node).expect("a Node with a valid name");
    let known = {
        let store = shared.store.lock().expect("a handler panicked holding the store");
        store.store.get(&node_key(name)).is_some()
    };
    if !known {
        let (resources, at) = (vec![node], kith_api::store::now());
        shared.submit(Command::Apply { resources, at }).await?;
    }
    let status = serde_json::json!({ "address": address, "raftId": id.to_string(), "certificate": print });
    let serde_json::Value::Object(mut status) = status else {
        unreachable!("an object")
    };
    if let serde_json::Value::Object(more) = more {
        status.extend(more);
    }
    let statuses = vec![(node_key(name), status)];
    shared.submit(Command::Patch { statuses }).await.map(drop)
}

/// Why `name` may not be a node: its Raft id ([`kith_store::node_id`]) is the one a Node of the
/// store says it has, or one of the members of the cluster.
fn taken_raft_id(shared: &Shared, name: &str) -> Option<String> {
    let id = kith_store::node_id(name);
    let text = id.to_string();
    let has = |node: &&kith_api::Resource| {
        node.status
            .as_ref()
            .is_some_and(|status| status["raftId"].as_str() == Some(&text))
    };
    let other = {
        let store = shared.store.lock().expect("a handler panicked holding the store");
        store
            .store
            .list(Some("Node"))
            .find(has)
            .map(|node| node.metadata.name.clone())
    };
    let by = match other {
        Some(other) => format!("node `{other}`"),
        None if shared
            .raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .nodes()
            .any(|(member, _)| *member == id) =>
        {
            "a member of the cluster".into()
        }
        None => return None,
    };
    Some(format!(
        "the name `{name}` gives the Raft id {id}, which {by} has: pick another --name"
    ))
}

async fn join(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    Json(request): Json<JoinRequest>,
) -> Result<Json<Joined>, Refusal> {
    let cluster = cluster(&shared)?;
    let Some(ca) = &cluster.ca else {
        return Err(refuse(
            StatusCode::CONFLICT,
            "this node cannot admit nodes: it does not hold the CA key",
        ));
    };
    // One join at a time: a token is checked here and spent at the end, and is good once.
    let _one = cluster.joining.lock().await;
    // The token first: someone without one learns nothing about the cluster.
    let Some(lets) = cluster.tokens.good(&request.token, false) else {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "the join token is wrong, already used, or older than an hour",
        ));
    };
    // Whether a worker is sent the store is its token's maker's to say: a node that cannot run
    // from a view (it serves ingress, or its kithd is from before views) is not let in by a
    // token that does not say so.
    let (worker, view) = (lets != pki::Lets::Control, lets == pki::Lets::Worker);
    if view && !request.view {
        let why = "this token lets in a worker that runs from a view of the store, and this node cannot \
                   (it serves ingress, or its kithd is older): ask for a token with `kith node token --worker --ingress` \
                   (the node is then sent the whole store), or join it without --ingress";
        return Err(refuse(StatusCode::CONFLICT, why));
    }
    pki::valid_name(&request.name).map_err(|e| refuse(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let taken = {
        let store = shared.store.lock().expect("a handler panicked holding the store");
        store.store.get(&node_key(&request.name)).is_some()
    };
    if taken {
        let why = format!(
            "a node named `{0}` is already in the cluster: pick another --name, or `kith delete node/{0}` first",
            request.name
        );
        return Err(refuse(StatusCode::CONFLICT, why));
    }
    // A Raft id comes from a name too: a name whose id a Node or a member already has would be
    // taken for that voter by a link that knows its voter by the id.
    if let Some(why) = taken_raft_id(&shared, &request.name) {
        return Err(refuse(StatusCode::CONFLICT, why));
    }
    // Mesh addresses come from names: two names with the same ones cannot both be nodes.
    let net = |name: &str| kith_mesh::node_net(crate::mesh::prefix(&cluster.me.ca), name);
    let clash = {
        let store = shared.store.lock().expect("a handler panicked holding the store");
        let mut names = store.store.list(Some("Node")).map(|node| node.metadata.name.clone());
        names.find(|name| net(name) == net(&request.name))
    };
    if let Some(other) = clash {
        let why = format!(
            "the name `{}` gets the mesh addresses node `{other}` has: pick another --name",
            request.name
        );
        return Err(refuse(StatusCode::CONFLICT, why));
    }
    // A node that roams is reached on the mesh, wherever it is: the nodes it can call there.
    let mesh_address = kith_mesh::node_address(crate::mesh::prefix(&cluster.me.ca), &request.name);
    let peers: Vec<serde_json::Value> = if let Some(said) = &request.mesh {
        if crate::mesh::key_of(&said.key).is_none() || said.port == 0 {
            return Err(refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                "that is not a mesh key and port",
            ));
        }
        let store = shared.store.lock().expect("a handler panicked holding the store");
        // (Two nodes with one key are both left out of the mesh: a key that is taken is refused.)
        let has = |node: &kith_api::Resource| {
            node.status
                .as_ref()
                .is_some_and(|status| status["mesh"]["key"] == *said.key)
        };
        if store.store.list(Some("Node")).any(has) {
            return Err(refuse(
                StatusCode::CONFLICT,
                "a node of this cluster already has that mesh key",
            ));
        }
        let peer = |node: &kith_api::Resource| {
            let status = node.status.as_ref()?;
            let at: SocketAddr = status["address"].as_str()?.parse().ok()?;
            let port = u16::try_from(status["mesh"]["port"].as_u64()?).ok()?;
            let (name, key) = (&node.metadata.name, status["mesh"]["key"].as_str()?);
            let stays = node.spec["roaming"] != true;
            stays.then(|| serde_json::json!({ "name": name, "key": key, "endpoint": SocketAddr::new(at.ip(), port) }))
        };
        store.store.list(Some("Node")).filter_map(peer).collect()
    } else {
        Vec::new()
    };
    if request.mesh.is_some() && peers.is_empty() {
        let why = "no node of this cluster is on the mesh (--mesh), and a node that roams is reached there";
        return Err(refuse(StatusCode::CONFLICT, why));
    }
    // Its Node first, then its certificate, which says by which index of the store the Node
    // was there (`unheard`). The Node admits nobody until `register` gives it a status.
    let unavailable = |e| refuse(StatusCode::SERVICE_UNAVAILABLE, e);
    let failed = |e| refuse(StatusCode::INTERNAL_SERVER_ERROR, e);
    let mut spec = match request.mesh {
        Some(_) => serde_json::json!({ "roaming": true }),
        None => serde_json::json!({}),
    };
    // (Its token's maker says so, not the node.)
    if worker {
        spec["trust"] = "worker".into();
    }
    let node = serde_json::json!({
        "apiVersion": kith_api::API_VERSION, "kind": "Node",
        "metadata": { "name": request.name }, "spec": spec,
    });
    let resources = vec![serde_json::from_value(node).expect("a Node with a valid name")];
    let at = kith_api::store::now();
    let (_, born) = shared
        .write_at(Command::Apply { resources, at })
        .await
        .map_err(unavailable)?;
    let (cert, key) = ca.issue_born(&request.name, born).map_err(failed)?;
    let print = pki::print_of(&cert).map_err(failed)?;
    // (What a roaming node says of itself on the mesh goes in with the rest: the other
    // nodes take it as a peer by this key, and it calls them.)
    let mut more = serde_json::Map::new();
    let address = match &request.mesh {
        None => SocketAddr::new(peer.addr.ip(), request.port),
        Some(said) => {
            let mesh = serde_json::json!({ "key": said.key, "address": mesh_address.to_string(), "port": said.port });
            more.insert("mesh".into(), mesh);
            SocketAddr::new(mesh_address.into(), request.port)
        }
    };
    // A worker that runs from a view is never sent the store: its Node says so from the start.
    if view {
        more.insert("view".into(), true.into());
    }
    let address = address.to_string();
    let id = kith_store::node_id(&request.name);
    register(&shared, &request.name, &address, id, &print, more.into())
        .await
        .map_err(unavailable)?;
    cluster.tokens.good(&request.token, true);
    eprintln!(
        "kithd: node {} joined from {}, to be reached at {address}",
        request.name,
        peer.addr.ip()
    );
    Ok(Json(Joined {
        ca: ca.cert.clone(),
        cert,
        key,
        peers,
        view: view.then(|| (cluster.me.name.clone(), pki::print_of(&cluster.me.cert).ok())),
    }))
}

/// Trade a join token for an identity, at the node `address`.
/// `view`: let in as a worker, it will run from a view.
pub async fn request_join(
    address: &str,
    token: &str,
    name: &str,
    port: u16,
    mesh: Option<OnMesh>,
    view: bool,
) -> Fallible<Joined> {
    pki::valid_name(name)?;
    let (_, pinned) = pki::token_parts(token)?;
    let failed = |what: &str, e: reqwest::Error| format!("{what} {address}: {e}");
    // Whoever answers is not trusted yet: the CA it hands over has to be the one the token names.
    let anyone = reqwest::Client::builder()
        .tls_danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .no_proxy();
    let anyone = anyone.build().map_err(|e| failed("setting up to reach", e))?;
    // (A machine that has just started may have no address yet, and the node may be starting
    // too: giving up at once restarts a kith OS machine, over and over.)
    let mut tries = 0;
    let reply = loop {
        let reply = anyone.get(format!("https://{address}/v1/ca")).send().await;
        match reply.and_then(reqwest::Response::error_for_status) {
            Err(e) if e.is_connect() && tries < 60 => {
                if tries == 0 {
                    eprintln!("kithd: {address} cannot be reached yet ({e}): trying for a minute");
                }
                tokio::time::sleep(Duration::from_secs(1)).await
            }
            reply => break reply,
        }
        tries += 1;
    };
    let ca = reply.map_err(|e| failed("reaching", e))?.text().await;
    let ca = ca.map_err(|e| failed("reading the CA from", e))?;
    if pki::fingerprint(&ca).ok().as_deref() != Some(pinned) {
        return Err(format!(
            "the node at {address} is not from the cluster this token is for: its CA does not match the token"
        ));
    }
    let request = JoinRequest {
        token: token.trim().into(),
        name: name.into(),
        port,
        mesh,
        view,
    };
    let member = client(&ca, None)?
        .post(format!("https://{address}/v1/join"))
        .json(&request);
    let reply = member.timeout(Duration::from_secs(15)).send().await;
    let reply = reply.map_err(|e| failed("joining through", e))?;
    if !reply.status().is_success() {
        let refusal: serde_json::Value = reply.json().await.unwrap_or_default();
        let why = refusal["error"].as_str().unwrap_or("it refused without saying why");
        return Err(format!("{address} did not let this node join: {why}"));
    }
    let joined: Joined = reply.json().await.map_err(|e| failed("reading the reply of", e))?;
    // What is kept is what the token pinned, nothing the reply slipped in.
    if pki::fingerprint(&joined.ca).ok().as_deref() != Some(pinned) {
        return Err(format!("{address} answered with a CA the token is not for"));
    }
    Ok(joined)
}

/// What the tests of a call to one node need: nodes of one CA, and one that counts what it is sent.
#[cfg(test)]
pub(crate) mod pinned_peer {
    use super::*;
    use crate::view::Upstream;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub fn node(ca: &pki::Ca, name: &str) -> Identity {
        let (cert, key) = ca.issue(name).unwrap();
        Identity {
            name: name.into(),
            ca: ca.cert.clone(),
            cert,
            key,
        }
    }

    /// Serves, on a loopback port, as the node `me`: whatever is asked is counted, and answered `{}`.
    /// The address, and how many requests got through.
    pub async fn answering_as(me: &Identity) -> (String, Arc<AtomicUsize>) {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap().to_string();
        let listener = listen(tcp, pki::server_config(me).unwrap()).unwrap();
        let sent = Arc::new(AtomicUsize::new(0));
        let counted = sent.clone();
        let app = Router::new().fallback(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Json(serde_json::json!({})))
        });
        tokio::spawn(async move { drop(axum::serve(listener, app.into_make_service()).await) });
        (address, sent)
    }

    /// `node` as a Node would say it is called at `address`, its key printed or not.
    pub fn at(node: &str, address: &str, certificate: Option<String>) -> Upstream {
        Upstream {
            name: node.into(),
            address: address.into(),
            certificate,
        }
    }

    /// The state of the node `me`, whose store has a Node for each of `nodes`, called where they say.
    pub async fn shared_with(tag: &str, me: Identity, nodes: &[Upstream]) -> Arc<Shared> {
        shared_of(tag, Cluster::new(me, None).unwrap(), nodes).await
    }

    /// [`shared_with`] of a cluster already made.
    pub async fn shared_of(tag: &str, cluster: Cluster, nodes: &[Upstream]) -> Arc<Shared> {
        let dir = std::env::temp_dir().join(format!("kithd-pinned-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let shared = crate::replica(Some(cluster), &dir, Duration::from_secs(300)).await;
        let shared = shared.unwrap();
        for node in nodes {
            let text = format!(
                "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {}}}\nspec: {{}}\n",
                node.name
            );
            let resource = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            let status = serde_json::json!({
                "address": node.address, "certificate": node.certificate, "state": "ready", "raftId": "1",
            });
            let mut state = shared.store.lock().unwrap();
            state.store.apply(resource).unwrap();
            let key = format!("Node/{}", node.name);
            state.store.set_status(&key, Some(status)).unwrap();
        }
        shared
    }

    #[tokio::test]
    async fn pinned_peer_is_the_node_named_and_no_other() {
        let ca = pki::Ca::create().unwrap();
        let (a, b, x) = (node(&ca, "a"), node(&ca, "b"), node(&ca, "x"));
        let cluster = Cluster::new(a, None).unwrap();
        let (taken, to_x) = answering_as(&x).await;
        let (home, to_b) = answering_as(&b).await;
        let (print_b, print_x) = (pki::print_of(&b.cert).unwrap(), pki::print_of(&x.cert).unwrap());
        let call = |address: &str, print: Option<String>| {
            let client = cluster.to(&at("b", address, print)).unwrap();
            client
                .post(format!("https://{address}/v1/secret"))
                .body("hunter2")
                .send()
        };

        // Another node of the cluster answers at the address of b: refused in the handshake, so
        // nothing of the request is sent, and the error says who was called and who answered.
        for print in [Some(print_b.clone()), None] {
            let said = why(&call(&taken, print).await.unwrap_err());
            assert!(said.contains("node b was called, and node x answered"), "{said}");
        }
        assert_eq!(to_x.load(Ordering::SeqCst), 0);
        // The right name with another key than its Node names: refused.
        let said = why(&call(&home, Some(print_x)).await.unwrap_err());
        assert!(said.contains("node b answered with another key"), "{said}");
        // A Node that names no key is held to its name alone; one that does, to both.
        assert_eq!(to_b.load(Ordering::SeqCst), 0);
        for print in [None, Some(print_b.clone())] {
            assert!(call(&home, print).await.unwrap().status().is_success());
        }
        assert_eq!(to_b.load(Ordering::SeqCst), 2);
        // One client for a node, replaced when its key changes: the map is as big as the nodes called.
        assert_eq!(cluster.pinned.lock().unwrap().len(), 1);
        // A node whose Node is deleted is forgotten, and the others are not.
        cluster.to(&at("c", &home, None)).unwrap();
        cluster.forget_but(|name| name == "c");
        assert_eq!(cluster.pinned.lock().unwrap().keys().collect::<Vec<_>>(), ["c"]);
        // The plain client takes any node of the cluster: it is not for what is meant for one.
        let any = cluster.client.post(format!("https://{taken}/v1/secret")).send().await;
        assert!(any.unwrap().status().is_success() && to_x.load(Ordering::SeqCst) == 1);
    }

    /// A name whose Raft id a Node has is refused at the join (it would be taken for that Node's
    /// voter), the token is not spent, and a name with a free id is not refused for it.
    #[tokio::test]
    async fn join_refuses_a_taken_raft_id() {
        let ca = pki::Ca::create().unwrap();
        let a = node(&ca, "a");
        let cluster = Cluster::new(a, Some(ca)).unwrap();
        let token = cluster.tokens.mint(&cluster.me.ca, pki::Lets::Control).unwrap();
        // Node/other has the id the name `joiner` gives (found by no search: it is set).
        let shared = shared_of("join-id", cluster, &[at("other", "127.0.0.1:1", None)]).await;
        let id = kith_store::node_id("joiner");
        let status = serde_json::json!({ "address": "127.0.0.1:1", "state": "ready", "raftId": id.to_string() });
        let set = shared
            .store
            .lock()
            .unwrap()
            .store
            .set_status("Node/other", Some(status));
        set.unwrap();
        let peer = Peer {
            addr: "127.0.0.1:2".parse().unwrap(),
            subject: None,
        };
        let join = |name: &str| {
            let request = JoinRequest {
                token: token.clone(),
                name: name.into(),
                port: 7000,
                mesh: None,
                view: false,
            };
            join(State(shared.clone()), ConnectInfo(peer.clone()), Json(request))
        };
        let (status, Json(said)) = join("joiner").await.err().expect("a taken id is refused");
        assert_eq!(status, StatusCode::CONFLICT);
        let said = said["error"].as_str().unwrap();
        assert!(
            said.contains("gives the Raft id") && said.contains("node `other`"),
            "{said}"
        );
        assert!(said.contains("pick another --name"), "{said}");
        let cluster = shared.cluster.as_ref().unwrap();
        assert!(
            cluster.tokens.good(&token, false).is_some(),
            "the refusal spent the token"
        );
        assert!(shared.store.lock().unwrap().store.get("Node/joiner").is_none());
        // A free id passes this check (it goes on, and fails later on what the test does not have).
        let other = join("someone-else").await.err().map(|(_, Json(said))| said.to_string());
        assert!(
            other.as_ref().is_none_or(|said| !said.contains("gives the Raft id")),
            "{other:?}"
        );
    }

    fn sources(dir: &std::path::Path, into: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, into);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                // What a file does is above its first test module.
                let code = text.split("#[cfg(test)]").next().unwrap().to_string();
                let name = path.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap();
                into.push((name.display().to_string().replace('\\', "/"), code));
            }
        }
    }

    /// A call that carries what is meant for one node goes through `Cluster::to`, which pins the
    /// peer to its name and key. Every other way a client is made or used here (the cluster's plain
    /// client, which takes any node of the cluster; a client of one's own; the TLS settings of one)
    /// is on this list, each with its reason, and no others.
    #[test]
    fn every_call_to_a_node_is_pinned_or_on_the_short_list() {
        let short_list = [
            // The upload to a bucket: a client of the world outside, by the name it was given.
            ("src/backups.rs", 1),
            // A blob fetched by digest and checked against it, whoever sends it (two calls).
            ("src/blobs.rs", 2),
            // The boot-time unlock: only a key wrapped under the disk's own secret goes.
            ("src/crypt.rs", 1),
            // `client_for` (the pinned clients and the plain one) and the join, which the token's
            // hash of the CA makes safe: its client takes any certificate, and the CA it is handed
            // has to be the token's.
            ("src/cluster.rs", 3),
            // The TLS settings of a client, which `client_for` is given a pin for.
            ("src/pki.rs", 1),
            // The world outside: registries, images, ACME, the update, the installer.
            ("src/registry.rs", 2),
            ("src/acme.rs", 3),
            ("src/update.rs", 1),
            ("src/install.rs", 1),
        ];
        let mut files = Vec::new();
        sources(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        assert!(files.len() > 20, "the sources were not found");
        for (file, code) in &files {
            // (`.client` takes in `cluster.client` and an alias of it: `&c.client`, a closure.)
            // (Not `.clients`, a field of its own: what follows the name is not a letter.)
            let field = code
                .split(".client")
                .skip(1)
                .filter(|after| !after.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
                .count();
            let plain = code.matches("Client::builder").count() + code.matches("client_config(").count() + field;
            let allowed = short_list.iter().find(|(name, _)| name == file).map_or(0, |(_, n)| *n);
            assert_eq!(
                plain, allowed,
                "{file} makes or uses a client {plain} times; the short list says {allowed}"
            );
            // The key a Node names is only ever put in a pin here and in `to`.
            if file != "src/cluster.rs" && file != "src/pki.rs" {
                assert!(!code.contains("client_for("), "{file} builds its own pinned client");
            }
        }
        // And what is pinned is: each relay goes through `to`.
        for relay in [
            "src/crypt.rs",
            "src/volume_files.rs",
            "src/backups.rs",
            "src/api/run.rs",
            "src/api.rs",
            "src/encrypted.rs",
            "src/replicas.rs",
            "src/view.rs",
            "src/raft.rs",
            "src/blobs.rs",
            "src/members.rs",
        ] {
            let (_, code) = files.iter().find(|(name, _)| name == relay).unwrap();
            assert!(code.contains("cluster.to("), "{relay} does not pin");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::Caller;
    use axum::body::{Body, Bytes};
    use futures_util::stream;
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;

    #[test]
    fn an_evicted_nodes_key_stands_for_no_node() {
        let mut store = kith_api::store::Store::default();
        // A node that has not heard of itself has not heard of the others: it is being sent
        // the store, and takes it from a node whose certificate says no index.
        let unheard = |store: &kith_api::store::Store, applied, name: &str, born| {
            unheard(store, "a", applied, "/v1/raft/append", name, born)
        };
        assert!(!stands(&store, "b", b"key") && unheard(&store, 0, "b", None));
        // On the routes that bring it up to date, and on no other: not to write, not to run.
        for (path, let_in) in [
            ("/v1/raft/snapshot", true),
            ("/v1/raft/vote", true),
            ("/v1/raft/write", false),
        ] {
            assert_eq!(super::unheard(&store, "a", 0, path, "b", None), let_in, "{path}");
        }
        assert!(!super::unheard(&store, "a", 0, "/v1/run-hop", "b", Some(5)));
        for name in ["a", "b", "old", "made"] {
            let node = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{ name: {name} }}\nspec: {{}}\n");
            let node = kith_api::Resource::from_source(&node).unwrap().remove(0);
            store.apply(node.unwrap()).unwrap();
        }
        let joined = |print: Option<String>| serde_json::json!({ "raftId": "7", "certificate": print });
        store.set_status("Node/a", Some(joined(None))).unwrap();
        store
            .set_status("Node/b", Some(joined(Some(pki::key_print(b"key")))))
            .unwrap();
        // (A Node from before certificates were written down: by its name.)
        store.set_status("Node/old", Some(joined(None))).unwrap();
        assert!(stands(&store, "b", b"key") && stands(&store, "old", b"any"));
        // Another key under the name, a Node made by hand, and one that is not there.
        assert!(!stands(&store, "b", b"another") && !stands(&store, "made", b"key"));
        assert!(!stands(&store, "gone", b"key"));
        // A Node that is there is not unheard of, whatever its certificate says.
        assert!(!unheard(&store, 0, "b", Some(5)) && !unheard(&store, 0, "made", None));
        store.delete("Node/b").unwrap();
        assert!(!stands(&store, "b", b"key"));
        // A certificate from a join says by which index its Node was there: a node that is
        // past it knows the Node was deleted; one that was away and is not there yet takes
        // what it sends (it may lead by now, and would be the one to send this node the store).
        assert!(!unheard(&store, 9, "b", Some(5)) && !unheard(&store, 5, "b", Some(5)));
        assert!(unheard(&store, 4, "b", Some(5)));
        // One that says no index, to a node that has heard of itself: deleted.
        assert!(!unheard(&store, 0, "b", None));
    }

    /// `/v1/netboot` refuses an Identity that may not apply Nodes before it reads the body:
    /// the body here says when it is read, and it is never.
    #[tokio::test]
    async fn netboot_refuses_a_roleless_identity_before_reading_its_body() {
        let dir = std::env::temp_dir().join(format!("kithd-netboot-refused-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        let read = Arc::new(AtomicBool::new(false));
        let said = read.clone();
        let image = Body::from_stream(stream::poll_fn(move |_| {
            said.store(true, Ordering::SeqCst);
            Poll::Ready(Some(Ok::<_, Infallible>(Bytes::from_static(b"kith-netboot"))))
        }));
        let refused = netboot(
            State(shared),
            axum::Extension(Caller::Identity("carol".into())),
            axum::http::Method::PUT,
            axum::extract::Query(BTreeMap::new()),
            image,
        )
        .await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let why = axum::body::to_bytes(refused.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&why).contains("carol may not apply Node"));
        assert!(!read.load(Ordering::SeqCst), "the body was read before the refusal");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn guests_of_one_address_hold_only_their_share() {
        let crowd = Arc::new(Crowd::default());
        let from = |text: &str| -> std::net::IpAddr { text.parse().unwrap() };
        // One host fills its share and no more; another host is not kept out by it.
        let mut held: Vec<_> = (0..GUESTS_EACH)
            .map(|_| crowd.place(from("203.0.113.9")).unwrap())
            .collect();
        assert!(crowd.place(from("203.0.113.9")).is_none());
        assert!(
            crowd.place(from("::ffff:203.0.113.9")).is_none(),
            "the same host, as IPv6 sees it"
        );
        assert!(crowd.place(from("203.0.113.10")).is_some());
        // A place given back is one more to take.
        held.pop();
        let again = crowd.place(from("203.0.113.9"));
        assert!(again.is_some() && crowd.place(from("203.0.113.9")).is_none());
        drop((held, again));
        assert!(
            crowd.0.lock().unwrap().is_empty(),
            "nothing is remembered of who has left"
        );
        // A /64 is one host's to hand out; this machine itself is not counted.
        let _held: Vec<_> = (0..GUESTS_EACH)
            .map(|n| crowd.place(from(&format!("2001:db8::{n:x}"))).unwrap())
            .collect();
        assert!(crowd.place(from("2001:db8::ffff")).is_none());
        assert!(crowd.place(from("2001:db8:0:1::1")).is_some());
        let local: Vec<_> = (0..GUESTS).filter_map(|_| crowd.place(from("127.0.0.1"))).collect();
        assert_eq!(local.len(), GUESTS);
        assert!(crowd.place(from("::1")).is_some());
    }
}
