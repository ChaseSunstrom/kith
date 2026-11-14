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
    /// Calls other nodes as this one.
    pub client: reqwest::Client,
}

type Fallible<T> = Result<T, String>;

fn client(ca: &str, me: Option<&Identity>) -> Fallible<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .use_preconfigured_tls(pki::client_config(ca, me)?)
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
        })
    }
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
                    // ponytail: that includes an Identity since deleted, until certificates expire or are revoked by more than the store.
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

async fn members_only(ConnectInfo(peer): ConnectInfo<Peer>, request: Request, next: Next) -> Response {
    let (status, why) = match peer.subject {
        Some(pki::Subject::Node(_)) => return next.run(request).await,
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
        .route("/v1/blob-copy/{name}", get(crate::blobs::copy))
        .route("/v1/volume-copy/{namespace}/{name}", get(crate::replicas::copy))
        .route(
            "/v1/volume-key/{namespace}/{name}",
            get(crate::encrypted::get).put(crate::encrypted::put),
        )
        .with_state(shared.clone());
    let members = crate::raft::router(shared).merge(ping).merge(hop);
    open.merge(crate::ui::pages())
        .merge(api)
        .merge(members.layer(axum::middleware::from_fn(members_only)))
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
    if !cluster.claims.good(&request.token, false) {
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
    if !cluster.claims.good(&request.token, true) {
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
    match claims.mint(&ca.cert) {
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
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if matches!(caller, crate::access::Caller::Node(_)) {
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
    let minted = mint(&shared);
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
    if matches!(caller, crate::access::Caller::Node(_)) {
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
                cluster.tokens.mint(&ca.cert)
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

fn mint(shared: &Shared) -> Result<Json<serde_json::Value>, Refusal> {
    let cluster = cluster(shared)?;
    let Some(ca) = &cluster.ca else {
        return Err(refuse(StatusCode::CONFLICT, CA_ELSEWHERE));
    };
    let token = cluster.tokens.mint(&ca.cert);
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
}

fn node_key(name: &str) -> String {
    format!("Node/{name}")
}

/// Put `Node/<name>` in the store: reachable at `address`, and `id` in Raft (as text:
/// not every JSON reader keeps 64 bits). The leader then starts sending it the store.
pub async fn register(shared: &Shared, name: &str, address: &str, id: u64) -> Result<(), kith_api::store::Error> {
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
    let status = serde_json::json!({ "address": address, "raftId": id.to_string() });
    let serde_json::Value::Object(status) = status else {
        unreachable!("an object")
    };
    let statuses = vec![(node_key(name), status)];
    shared.submit(Command::Patch { statuses }).await.map(drop)
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
    if !cluster.tokens.good(&request.token, false) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "the join token is wrong, already used, or older than an hour",
        ));
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
    let (cert, key) = ca
        .issue(&request.name)
        .map_err(|e| refuse(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let unavailable = |e| refuse(StatusCode::SERVICE_UNAVAILABLE, e);
    let address = match &request.mesh {
        None => SocketAddr::new(peer.addr.ip(), request.port).to_string(),
        Some(said) => {
            // Its Node says so before anything is sent to it: the other nodes take it as a
            // peer by this key, and it calls them.
            let node = serde_json::json!({
                "apiVersion": kith_api::API_VERSION, "kind": "Node",
                "metadata": { "name": request.name }, "spec": { "roaming": true },
            });
            let resources = vec![serde_json::from_value(node).expect("a Node with a valid name")];
            let at = kith_api::store::now();
            shared
                .submit(Command::Apply { resources, at })
                .await
                .map_err(unavailable)?;
            let mesh = serde_json::json!({ "key": said.key, "address": mesh_address.to_string(), "port": said.port });
            let fields = serde_json::Map::from_iter([("mesh".to_string(), mesh)]);
            let statuses = vec![(node_key(&request.name), fields)];
            shared.submit(Command::Patch { statuses }).await.map_err(unavailable)?;
            SocketAddr::new(mesh_address.into(), request.port).to_string()
        }
    };
    register(&shared, &request.name, &address, kith_store::node_id(&request.name))
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
    }))
}

/// Trade a join token for an identity, at the node `address`.
pub async fn request_join(address: &str, token: &str, name: &str, port: u16, mesh: Option<OnMesh>) -> Fallible<Joined> {
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

    /// `/v1/netboot` refuses an Identity that may not apply Nodes before it reads the body:
    /// the body here says when it is read, and it is never.
    #[tokio::test]
    async fn netboot_refuses_a_roleless_identity_before_reading_its_body() {
        let dir = std::env::temp_dir().join(format!("kithd-netboot-refused-{}", std::process::id()));
        let shared = crate::replica(None, &dir).await.unwrap();
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
