//! Nodes talking to nodes: the API over TLS on TCP, where both ends show a
//! certificate from the cluster CA, and how a new node gets one.
//!
//! ```text
//! GET  /v1/ca                          -> the CA certificate (PEM)     no certificate needed
//! POST /v1/join {token, name, port}    -> {ca, cert, key}              no certificate needed
//! POST /v1/tokens                      -> {token}                      local socket only
//! ```
//! Everything else on the TCP port is the resource API, for members only.
//
// ponytail: a node that joined keeps no store of its own yet: it forwards every API
// call to the node it joined, and runs no workloads. Its own replica of the store and
// its share of the workloads come with Raft and the scheduler.

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
    /// Calls other nodes as this one.
    pub client: reqwest::Client,
    /// `address:port` of the node this one forwards its API to, if it joined one.
    pub leader: Option<String>,
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
    pub fn new(me: Identity, ca: Option<pki::Ca>, leader: Option<String>) -> Fallible<Cluster> {
        Ok(Cluster {
            client: client(&me.ca, Some(&me))?,
            me,
            ca,
            tokens: pki::Tokens::default(),
            leader,
        })
    }
}

/// Who is on the other end of a TCP connection.
#[derive(Clone, Debug)]
pub struct Peer {
    pub addr: SocketAddr,
    /// The node its certificate names; `None` when it showed none.
    pub node: Option<String>,
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
                    let node = certs.and_then(|certs| pki::node_of(certs.first()?));
                    // A member gives its slot back; a guest keeps it, for a short while.
                    let guest = node.is_none().then(|| (slot, Box::pin(tokio::time::sleep(GUEST_TIME))));
                    let _ = tx.send((Connection { stream, guest }, Peer { addr, node })).await;
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
            node: None,
        })
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Peer {
        stream.remote_addr().clone()
    }
}

type Refusal = (StatusCode, Json<serde_json::Value>);

fn refuse(status: StatusCode, why: impl std::fmt::Display) -> Refusal {
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
    match peer.node {
        Some(_) => next.run(request).await,
        None => refuse(
            StatusCode::UNAUTHORIZED,
            "a certificate from this cluster's CA is needed",
        )
        .into_response(),
    }
}

/// What is served on the TCP port.
pub fn node_router(shared: Arc<Shared>) -> Router {
    let open = Router::new()
        .route("/v1/ca", get(ca))
        .route("/v1/join", post(join))
        .layer(DefaultBodyLimit::max(4096))
        .with_state(shared.clone());
    open.merge(local_router(shared).layer(axum::middleware::from_fn(members_only)))
}

/// The resource API of this node: its own store, or the node it joined.
pub fn local_router(shared: Arc<Shared>) -> Router {
    match shared.cluster.as_ref().and_then(|cluster| cluster.leader.as_ref()) {
        Some(_) => Router::new().fallback(forward).with_state(shared),
        None => api::router(shared),
    }
}

/// What only the local socket serves.
pub fn admin_router(shared: Arc<Shared>) -> Router {
    Router::new().route("/v1/tokens", post(token)).with_state(shared)
}

async fn ca(State(shared): State<Arc<Shared>>) -> Result<String, Refusal> {
    Ok(cluster(&shared)?.me.ca.clone())
}

async fn token(State(shared): State<Arc<Shared>>) -> Result<Json<serde_json::Value>, Refusal> {
    let cluster = cluster(&shared)?;
    let Some(ca) = &cluster.ca else {
        let leader = cluster.leader.as_deref().unwrap_or("the first node");
        let why = format!("only a node that holds the cluster CA key can admit nodes: ask {leader}");
        return Err(refuse(StatusCode::CONFLICT, why));
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

/// Put `Node/<name>` in the store, reachable at `address`.
pub fn register(shared: &Shared, name: &str, address: &str) -> Result<(), kith_api::store::Error> {
    let node = serde_json::json!({
        "apiVersion": kith_api::API_VERSION, "kind": "Node", "metadata": { "name": name }, "spec": {},
    });
    let node: kith_api::Resource = serde_json::from_value(node).expect("a Node with a valid name");
    let written = api::write(shared, |store| {
        if store.get(&node_key(name)).is_none() {
            store.apply(node)?;
        }
        store.set_status(&node_key(name), Some(serde_json::json!({ "address": address })))
    });
    written.map_err(|e| e.0)
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
    let (cert, key) = ca
        .issue(&request.name)
        .map_err(|e| refuse(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let address = SocketAddr::new(peer.addr.ip(), request.port).to_string();
    register(&shared, &request.name, &address).map_err(|e| refuse(StatusCode::INTERNAL_SERVER_ERROR, e))?;
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

/// Requests larger than this are not forwarded.
const FORWARD_LIMIT: usize = 16 << 20;

/// Pass a request on to the node this one joined, and its answer back.
async fn forward(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let cluster = shared.cluster.as_ref().expect("only routed in a cluster");
    let leader = cluster.leader.as_ref().expect("only routed on a node that joined");
    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, FORWARD_LIMIT).await else {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, "the request is too large").into_response();
    };
    let path = parts.uri.path_and_query().map_or("/", |path| path.as_str());
    // Longer than the longest long-poll (watch, 25 s).
    let call = cluster.client.request(parts.method, format!("https://{leader}{path}"));
    let mut call = call.timeout(Duration::from_secs(40)).body(body);
    if let Some(kind) = parts.headers.get(axum::http::header::CONTENT_TYPE) {
        call = call.header(axum::http::header::CONTENT_TYPE, kind);
    }
    let reply = match call.send().await {
        Ok(reply) => reply,
        Err(e) => {
            let why = format!("node {leader}, which this node joined, cannot be reached: {e}");
            return refuse(StatusCode::BAD_GATEWAY, why).into_response();
        }
    };
    let (status, kind) = (
        reply.status(),
        reply.headers().get(axum::http::header::CONTENT_TYPE).cloned(),
    );
    match reply.bytes().await {
        Ok(body) => {
            let mut response = (status, body).into_response();
            if let Some(kind) = kind {
                response.headers_mut().insert(axum::http::header::CONTENT_TYPE, kind);
            }
            response
        }
        Err(e) => refuse(StatusCode::BAD_GATEWAY, format!("node {leader} stopped answering: {e}")).into_response(),
    }
}
