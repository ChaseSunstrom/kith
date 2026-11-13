//! Nodes talking to nodes: the API over TLS on TCP, where both ends show a
//! certificate from the cluster CA, and how a new node gets one.
//!
//! ```text
//! GET  /v1/ca                          -> the CA certificate (PEM)     no certificate needed
//! POST /v1/join {token, name, port}    -> {ca, cert, key}              no certificate needed
//! POST /v1/tokens                      -> {token}                      local socket only
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
    guest: Option<(OwnedSemaphorePermit, Pin<Box<tokio::time::Sleep>>)>,
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

pub fn listen(tcp: TcpListener, config: Arc<rustls::ServerConfig>) -> std::io::Result<TlsListener> {
    let local = tcp.local_addr()?;
    let (tx, ready) = mpsc::channel(GUESTS);
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let slots = Arc::new(Semaphore::new(GUESTS));
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
        .layer(DefaultBodyLimit::max(4096))
        .with_state(shared.clone());
    let ping = Router::new().route("/v1/ping", post(crate::members::ping));
    let ping = ping.layer(DefaultBodyLimit::max(64 << 10)).with_state(shared.clone());
    let callers = axum::middleware::from_fn_with_state(shared.clone(), crate::access::caller);
    let api = api::router(shared.clone()).layer(callers);
    let members = crate::raft::router(shared).merge(ping);
    open.merge(api)
        .merge(members.layer(axum::middleware::from_fn(members_only)))
}

/// What only the local socket serves.
pub fn admin_router(shared: Arc<Shared>) -> Router {
    let admin = Router::new().route("/v1/tokens", post(token));
    let admin = admin.route("/v1/identities/{name}/certificate", post(certificate));
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
    let cluster = cluster(&shared)?;
    let Some(ca) = &cluster.ca else {
        return Err(refuse(StatusCode::CONFLICT, CA_ELSEWHERE));
    };
    let issued = ca.issue_user(&name);
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
    let (resources, at) = (vec![identity], kith_api::store::now());
    let done = shared.submit(Command::Apply { resources, at }).await;
    let said = done.as_ref().map(drop).map_err(ToString::to_string);
    let caller = crate::access::Caller::Admin;
    shared.audit.record(&caller, "certificate", vec![key_of], said);
    done.map_err(|e| refuse(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let ca = cluster.me.ca.clone();
    Ok(Json(Joined { ca, cert, key }))
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

async fn token(State(shared): State<Arc<Shared>>) -> Result<Json<serde_json::Value>, Refusal> {
    let cluster = cluster(&shared)?;
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
}

#[derive(Serialize, Deserialize)]
pub struct Joined {
    pub ca: String,
    pub cert: String,
    pub key: String,
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
    let (cert, key) = ca
        .issue(&request.name)
        .map_err(|e| refuse(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let address = SocketAddr::new(peer.addr.ip(), request.port).to_string();
    register(&shared, &request.name, &address, kith_store::node_id(&request.name))
        .await
        .map_err(|e| refuse(StatusCode::SERVICE_UNAVAILABLE, e))?;
    cluster.tokens.good(&request.token, true);
    eprintln!("kithd: node {} joined from {address}", request.name);
    Ok(Json(Joined {
        ca: ca.cert.clone(),
        cert,
        key,
    }))
}

/// Trade a join token for an identity, at the node `address`.
pub async fn request_join(address: &str, token: &str, name: &str, port: u16) -> Fallible<Joined> {
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
    let reply = anyone.get(format!("https://{address}/v1/ca")).send().await;
    let reply = reply.and_then(reqwest::Response::error_for_status);
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
