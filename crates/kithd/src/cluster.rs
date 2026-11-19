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
use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::IncomingStream;
use axum::{Json, Router};
use kith_store::Command;
use kith_store::openraft::error::{CheckIsLeaderError, RaftError};
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
    /// What the voters this node last knew said of a node it has not heard of, by its name and
    /// the print of its key ([`vouched`]).
    vouched: std::sync::Mutex<std::collections::HashMap<(String, String), Kept>>,
    /// The keys `POST /v1/peers` is making here and has made lately (`people.rs`).
    pub keys: crate::people::Making,
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
            vouched: Default::default(),
            keys: Default::default(),
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
    /// holds is as big as the nodes there are, whatever Nodes came and went. (The clients of a
    /// voter, by id, are left as they are: one for each id Raft has ever had as a member, which
    /// only an admin's changes make.)
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

/// Whether our certificate check refused what answered (a certificate that is not the one
/// called): not a node that is not up yet, or a handshake cut short, which may be asked again.
fn refused_tls(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(e) = cause {
        if let Some(tls) = e.downcast_ref::<rustls::Error>() {
            // (The pinned check refuses with General; the CA's check with InvalidCertificate.)
            return matches!(tls, rustls::Error::InvalidCertificate(_) | rustls::Error::General(_));
        }
        // (An io::Error's source skips the error it wraps, and the handshake's error comes
        // wrapped twice: step into each.)
        cause = match e.downcast_ref::<std::io::Error>() {
            Some(io) => io.get_ref().map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => e.source(),
        };
    }
    false
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
        let from = from.to_canonical();
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
    stands(&state.store, name, &pki::key_print(key))
}

/// [`admitted`], asked of a store, for the key whose print is `print`.
fn stands(store: &kith_api::store::Store, name: &str, print: &str) -> bool {
    let node = store.get(&node_key(name));
    let Some(status) = node.and_then(|node| node.status.as_ref()) else {
        return false;
    };
    let joined = status["raftId"].is_string();
    joined && status["certificate"].as_str().is_none_or(|named| named == print)
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
    CATCHING_UP.contains(&path) && behind(store, me, applied, name, born)
}

/// [`unheard`] on any route: whether the store of `me` is too far behind to know of `name`.
fn behind(store: &kith_api::store::Store, me: &str, applied: u64, name: &str, born: Option<u64>) -> bool {
    store.get(&node_key(name)).is_none()
        && match born {
            Some(born) => applied < born,
            None => store.get(&node_key(me)).is_none(),
        }
}

/// The index of the store this node has applied.
fn applied(shared: &Shared) -> u64 {
    shared.raft.metrics().borrow().last_applied.map_or(0, |log| log.index)
}

/// [`unheard`], asked of this node.
fn catching_up(shared: &Shared, path: &str, name: &str, born: Option<u64>) -> bool {
    let Some(cluster) = &shared.cluster else {
        return false;
    };
    // (Read before the store: an index that is a moment old only says "behind" a moment longer.)
    let applied = applied(shared);
    let state = shared.store.lock().expect("a handler panicked holding the store");
    unheard(&state.store, &cluster.me.name, applied, path, name, born)
}

/// How long the voters are given to say whether a node stands.
const ASKING: Duration = Duration::from_secs(2);
/// How long a voter's "no" is kept, and the most a "yes" is. (Tests keep every answer for as
/// long as they run, however slow the machine: what they count does not lapse midway.)
const KEPT: Duration = Duration::from_secs(if cfg!(test) { 600 } else { 30 });
/// How long no word is kept: the voters may be back in a moment.
const QUIET: Duration = Duration::from_secs(if cfg!(test) { 600 } else { 5 });
/// How many senders' answers are kept: a node is led by one at a time, and sent a store by it.
const VOUCHED: usize = 16;

type Asking = futures_util::future::Shared<futures_util::future::BoxFuture<'static, Option<bool>>>;

/// What the voters said of one sender, and until when it holds.
struct Kept {
    word: Word,
    until: std::time::Instant,
    /// The index its certificate says its Node was there by: a "yes" holds until this node is past it.
    born: Option<u64>,
}

enum Word {
    /// Being asked: what else that node sends meanwhile waits for the same answer.
    Asking(Asking),
    Yes,
    /// One said no, or none said either.
    No,
}

/// Forget what no longer holds at `now`, for a store applied up to `applied`.
fn keep(kept: &mut std::collections::HashMap<(String, String), Kept>, now: std::time::Instant, applied: u64) {
    kept.retain(|_, kept| {
        let past = matches!(kept.word, Word::Yes) && kept.born.is_some_and(|born| applied >= born);
        now < kept.until && !past
    });
}

/// Keep what the voters said (`said`, [`verdict`]) of `id`, at `now`, if what is kept of it is
/// still the asking that was to lapse at `until`: one that took longer was dropped by [`keep`],
/// and the asking that took its place has its own answer coming.
fn answered(
    kept: &mut std::collections::HashMap<(String, String), Kept>,
    id: &(String, String),
    until: std::time::Instant,
    said: Option<bool>,
    now: std::time::Instant,
) {
    let Some(kept) = kept.get_mut(id) else {
        return;
    };
    if matches!(kept.word, Word::Asking(_)) && kept.until == until {
        kept.word = if said == Some(true) { Word::Yes } else { Word::No };
        kept.until = now + if said.is_some() { KEPT } else { QUIET };
    }
}

/// Does a voter this node last knew say the node `name`, of the key `key`, stands, and none that
/// it does not? Asked of a node this one has not heard of ([`unheard`]): it was away, and the
/// sender joined since (it may lead by now) or was deleted since (it must not lead this node,
/// nor send it a store). Each sender is asked about once, whatever it sends meanwhile, and the
/// answer kept; a voter that does not answer, answers "not yet", or is of a build with no such
/// question says nothing either way. A node that knows of no voter at all (it has just joined)
/// takes the sender, as before: it has no one to ask.
async fn vouched(shared: &Arc<Shared>, name: &str, key: &[u8], born: Option<u64>) -> bool {
    let Some(cluster) = &shared.cluster else {
        return false;
    };
    let id = (name.to_string(), pki::key_print(key));
    let asking = {
        let mut kept = cluster.vouched.lock().expect("nothing panics holding what was vouched");
        let now = std::time::Instant::now();
        keep(&mut kept, now, applied(shared));
        match kept.get(&id).map(|kept| &kept.word) {
            Some(Word::Yes) => return true,
            Some(Word::No) => return false,
            Some(Word::Asking(asking)) => asking.clone(),
            None if kept.len() >= VOUCHED => return false,
            None => {
                let (shared, asked) = (shared.clone(), id.clone());
                let until = now + 2 * ASKING;
                // (A task of its own: a sender that hangs up does not leave it half asked.)
                let asked = tokio::spawn(async move {
                    // (Each voter is given ASKING, its answer read and all: no more is waited.)
                    let said = ask(&shared, &asked.0, &asked.1, born).await;
                    let cluster = shared.cluster.as_ref().expect("asked by a node of a cluster");
                    let mut kept = cluster.vouched.lock().expect("nothing panics holding what was vouched");
                    answered(&mut kept, &asked, until, said, std::time::Instant::now());
                    said
                });
                use futures_util::FutureExt;
                let asked = asked.map(|done| done.ok().flatten()).boxed().shared();
                let word = Word::Asking(asked.clone());
                kept.insert(id, Kept { word, until, born });
                asked
            }
        }
    };
    asking.await == Some(true)
}

/// What the voters this node last knew (not itself, and not the sender, whose word for itself is
/// worth nothing) say of the node `name` whose key has the print `print`: [`verdict`].
async fn ask(shared: &Shared, name: &str, print: &str, born: Option<u64>) -> Option<bool> {
    let me = kith_store::node_id(&shared.cluster.as_ref()?.me.name);
    let sender = kith_store::node_id(name);
    // Raft says which voters it has only once it has started: until then it seems to know none,
    // and that would take the sender. A call it answers comes after that.
    let started = shared.raft.with_raft_state(|_| ());
    if tokio::time::timeout(ASKING, started).await.is_err() {
        return None;
    }
    let voters: Vec<_> = {
        let metrics = shared.raft.metrics().borrow().clone();
        let membership = metrics.membership_config.membership();
        if membership.voter_ids().next().is_none() {
            return Some(true);
        }
        let asked = |id: &kith_store::NodeId| *id != me && *id != sender;
        let at = |id| Some((id, membership.get_node(&id)?.addr.clone()));
        membership.voter_ids().filter(asked).filter_map(at).collect()
    };
    let asked = voters.into_iter().map(|(id, address)| async move {
        // (Held to the voter's name, and to its key where this node's store names one.)
        let (client, _) = crate::raft::to_voter(shared, id).ok()?;
        let mut url = reqwest::Url::parse(&format!("https://{address}/v1/raft/stands")).ok()?;
        url.query_pairs_mut()
            .append_pair("name", name)
            .append_pair("key", print);
        if let Some(born) = born {
            url.query_pairs_mut().append_pair("born", &born.to_string());
        }
        let answer = client.get(url).timeout(ASKING).send().await.ok()?;
        answer.error_for_status().ok()?.json::<String>().await.ok()
    });
    verdict(&futures_util::future::join_all(asked).await)
}

/// No if any voter said so, yes if one did and none said no, and otherwise nothing.
fn verdict(said: &[Option<String>]) -> Option<bool> {
    let any = |word: &str| said.iter().any(|said| said.as_deref() == Some(word));
    if any("no") {
        Some(false)
    } else {
        any("yes").then_some(true)
    }
}

#[derive(Deserialize)]
struct Standing {
    name: String,
    key: String,
    born: Option<u64>,
}

/// Whether the certificate of the node `name` for the key whose print is `key` stands in this
/// node's store: "yes", "no", or "not yet" where this store is too far behind to know (as by
/// [`behind`]). Asked by a node that was away and is sent Raft's messages by a node it has not
/// heard of ([`vouched`]); answered only to a node that stands here (`members_only`).
async fn standing(State(shared): State<Arc<Shared>>, Query(asked): Query<Standing>) -> Json<&'static str> {
    let me = shared.cluster.as_ref().map_or("", |cluster| cluster.me.name.as_str());
    let applied = applied(&shared);
    let state = shared.store.lock().expect("a handler panicked holding the store");
    Json(if stands(&state.store, &asked.name, &asked.key) {
        "yes"
    } else if behind(&state.store, me, applied, &asked.name, asked.born) {
        "not yet"
    } else {
        "no"
    })
}

/// What a worker (`spec.trust`) is refused among the nodes' routes: the second hop of
/// `kith run`, the hop of `kubectl port-forward` and Raft's own messages, which only one that votes or leads sends.
const CONTROL_ONLY: [&str; 5] = [
    "/v1/raft/append",
    "/v1/raft/vote",
    "/v1/raft/snapshot",
    RUN_HOP,
    POD_HOP,
];
const RUN_HOP: &str = "/v1/run-hop";
pub(crate) const POD_HOP: &str = "/v1/pod-hop";

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
    // A node this one has not heard of is taken once a voter this one last knew vouches for it.
    let (known, unheard) = match &peer.subject {
        Some(pki::Subject::Node(name, key, born)) => {
            let known = admitted(&shared, name, key);
            (known, !known && catching_up(&shared, path, name, *born))
        }
        _ => (false, false),
    };
    let let_in = match &peer.subject {
        Some(pki::Subject::Node(name, key, born)) if unheard => vouched(&shared, name, key, *born).await,
        _ => known,
    };
    let (status, why) = match &peer.subject {
        Some(pki::Subject::Node(name, ..)) if let_in => {
            // A worker does not vote, is not followed, and its word for who asked is not taken.
            let worker = CONTROL_ONLY.contains(&path) && crate::access::worker(&shared, name);
            if worker && (path == RUN_HOP || path == POD_HOP || !votes(&shared, name)) {
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
            // (What Raft's caller hears with every answer: the store format this kithd reads.)
            let raft = path.starts_with("/v1/raft/");
            let mut answer = next.run(request).await;
            if raft {
                answer
                    .headers_mut()
                    .insert(crate::raft::READS, kith_store::FORMAT.into());
            }
            return answer;
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
            // (Unheard of and not vouched for: as a node it is, but not to be followed.)
            let status = if unheard {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            };
            (status, EVICTED)
        }
        Some(pki::Subject::User(..) | pki::Subject::Workload { .. }) => (
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
        .route("/v1/forget", post(crate::crypt::forget))
        .layer(DefaultBodyLimit::max(4096))
        .with_state(shared.clone());
    let ping = Router::new().route("/v1/ping", post(crate::members::ping));
    let ping = ping.layer(DefaultBodyLimit::max(64 << 10)).with_state(shared.clone());
    let callers = axum::middleware::from_fn_with_state(shared.clone(), crate::access::caller);
    let api = api::router(shared.clone()).layer(callers);
    // (The second hop of `kith run`: the caller was checked on the first node.)
    let hop = Router::new()
        .route("/v1/run-hop", post(api::run::hop))
        .route(POD_HOP, post(crate::kube::portforward::hop))
        .route("/v1/raft/stands", get(standing))
        .route("/v1/view", get(crate::view::serve))
        .route("/v1/blob-copy/{name}", get(crate::blobs::copy))
        .route("/v1/volume-copy/{namespace}/{name}", get(crate::replicas::copy))
        .route(
            "/v1/volume-key/{namespace}/{name}",
            get(crate::encrypted::get).put(crate::encrypted::put),
        )
        .route(
            "/v1/workload-certificate/{namespace}/{name}/{replica}",
            post(crate::workload_identity::issue),
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

pub(crate) const CA_ELSEWHERE: &str =
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
    match claims.mint(&ca.cert, None, pki::Lets::Control) {
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
    let mut identity = identity.unwrap_or_else(|| crate::access_sign::new_identity(name));
    identity.spec["publicKey"] = public.into();
    let resources = std::iter::once(identity).chain(more).collect();
    // (As the admin's, not this node's own: a control node that is not the leader passes it on,
    // and the leader holds a node's own writes to what it holds. `claim` cannot be the Identity's
    // own write, as the Role it grants is not there until this one is in; its console token is
    // this node's admin's, as `certificate` is. The caller is still the audit's.)
    let admin = crate::access::Caller::Admin;
    let done = shared
        .submit_as(
            Command::Apply {
                resources,
                at: kith_api::store::now(),
            },
            Some(&admin),
        )
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
    // What a signer needs (kith's passphrase key is salted with the cluster id): the id is the
    // print of the CA, and `signing` says whether writes must be signed.
    let id = shared
        .cluster
        .as_ref()
        .and_then(|cluster| crate::pki::fingerprint(&cluster.me.ca).ok());
    let signing = match crate::access_sign::requires(&shared) {
        true => "required",
        false => "open",
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
            "clusterId": id,
            "signing": signing,
            "view": { "applied": at, "from": upstream.as_ref().map(|(address, _)| address) },
            "mesh": shared.mesh.lock().expect("nothing panics holding the mesh").clone(),
        }));
    }
    Json(serde_json::json!({
        "node": name(metrics.id),
        "clusterId": id,
        "signing": signing,
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
    no_store(made(shared, caller, asked).await)
}

/// An answer that holds a secret (a join token, a recovery key): no browser or proxy keeps it.
pub(crate) fn no_store(mut answer: Response) -> Response {
    answer.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    answer
}

async fn made(
    shared: Arc<Shared>,
    caller: crate::access::Caller,
    asked: std::collections::BTreeMap<String, String>,
) -> Response {
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
    // is sent a view of the store; `&store=whole`: it serves ingress (`spec.ingress`), and its
    // view holds the certificates of the exposed hosts too. (The words are from when such a
    // worker was sent the whole store: a control node from then still makes that token of them.)
    let said = |field: &str| asked.get(field).map(String::as_str);
    let lets = match (said("trust"), said("store")) {
        (None | Some("control"), None) => pki::Lets::Control,
        (Some("worker"), None) => pki::Lets::Worker,
        (Some("worker"), Some("whole")) => pki::Lets::WorkerIngress,
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
                cluster.tokens.mint(&ca.cert, Some(&cluster.me), pki::Lets::Control)
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
    let token = cluster.tokens.mint(&ca.cert, Some(&cluster.me), lets);
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
    /// nothing, and one from before ingress workers said no if it served ingress). What it is
    /// sent is its token's to say.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    view: bool,
    /// It serves ingress (`--ingress`): a worker token has to say so too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    ingress: bool,
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

/// How long [`register_first`] waits for the store to hold what the cluster committed.
const WAIT_FOR_STORE: Duration = Duration::from_secs(30);

/// Whether a node that is not the leader has applied all its log holds, and that is of the term it
/// is in, with a leader known: a restart in the same term leaves what it applied (up to its
/// snapshot) in that term too, with entries of the term behind it, a delete of its Node among them.
fn applied_what_it_holds(
    m: &kith_store::openraft::RaftMetrics<kith_store::NodeId, kith_store::openraft::BasicNode>,
) -> bool {
    let applied = |log: &kith_store::openraft::LogId<_>| {
        log.leader_id.term == m.current_term && Some(log.index) >= m.last_log_index
    };
    m.current_leader.is_some() && m.last_applied.as_ref().is_some_and(applied)
}

/// A write that changes nothing, put in the log through the leader (a follower sends it on), and
/// waited for here, giving the index it is at: the leader's log up to it is this node's store, so a
/// delete committed there is in it. The leader's own read index is not asked of a follower; this
/// is what stands for it. A leader that refuses this node says so at once, in the error.
async fn leader_barrier(shared: &Shared) -> Result<u64, kith_api::store::Error> {
    let unsaid = |e: &dyn std::fmt::Display| kith_api::store::Error::Io(format!("the leader did not confirm: {e}"));
    let barrier = shared.write_at(Command::Patch { statuses: vec![] });
    let (_, index) = tokio::time::timeout(WAIT_FOR_STORE, barrier)
        .await
        .map_err(|e| unsaid(&e))??;
    let wait = shared.raft.wait(Some(WAIT_FOR_STORE));
    let applied = wait.applied_index_at_least(Some(index), "the leader's barrier applied");
    applied.await.map_err(|e| unsaid(&e))?;
    Ok(index)
}

/// [`register`] for the node the cluster started on, at each start, and the only way it is called for it:
/// it makes its Node only while the store holds no Node at all (the start that made the cluster, or one
/// that ended before its Node was in), so a node deleted stays deleted across its restart. False: its Node
/// is gone, or is a joiner's under the name (another certificate), and nothing was written.
/// It waits first for the store to have applied what the cluster committed (on the leader, Raft's
/// linearizable read; on any other node, all the log it holds, of the term it is in, and then a
/// barrier write through the leader, applied here): until then a
/// Node that is there may not show, and one deleted may.
pub async fn register_first(
    shared: &Shared,
    name: &str,
    address: &str,
    id: u64,
    print: &str,
    more: serde_json::Value,
) -> Result<bool, kith_api::store::Error> {
    let unsaid =
        |e: &dyn std::fmt::Display| kith_api::store::Error::Io(format!("no leader to say what the store holds: {e}"));
    // The leader: its store has what a quorum says is committed once the read index is applied.
    let read = tokio::time::timeout(WAIT_FOR_STORE, shared.raft.ensure_linearizable());
    match read.await.map_err(|e| unsaid(&e))? {
        Ok(_) => {}
        // Not the leader (yet): wait for the log it holds to be applied, with a leader known.
        Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(_))) => {
            let wait = shared.raft.wait(Some(WAIT_FOR_STORE));
            wait.metrics(applied_what_it_holds, "everything its log holds applied")
                .await
                .map_err(|e| unsaid(&e))?;
            // The leader may have committed more than this log holds (a delete of its Node among it):
            // a write through the leader is at an index past all that, and this store has applied it.
            leader_barrier(shared).await?;
        }
        Err(e) => return Err(unsaid(&e)),
    }
    let (has_none, own) = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let own = state.store.get(&node_key(name)).map(|node| {
            let said = node.status.as_ref().and_then(|status| status["certificate"].as_str());
            said.is_some_and(|said| said != print)
        });
        (state.store.list(Some("Node")).next().is_none(), own)
    };
    if !has_none && own.is_none() {
        eprintln!(
            "kithd: node {name} was deleted, or never registered: it does not put itself back; join again with a token to be a node"
        );
        return Ok(false);
    }
    // A Node of the name that holds another certificate is a joiner's, made after the delete: not written over.
    if own == Some(true) {
        eprintln!("kithd: node {name}: the Node of that name holds another node's certificate: not written over");
        return Ok(false);
    }
    register(shared, name, address, id, print, more).await.map(|()| true)
}

/// Put `Node/<name>` in the store: reachable at `address`, `id` in Raft (as text: not
/// every JSON reader keeps 64 bits), and holding the certificate whose key's print is
/// `print` ([`admitted`]), with what it says of itself on the mesh if it joined there, all
/// in one entry: no entry makes it half a node. The leader then starts sending it the store.
/// `more` is what else its status says from the start: `ca` (it is the node that holds the CA
/// key, which no change may make a worker), `view` (a worker that is sent a view instead).
async fn register(
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
    if let Some(other) = other {
        return Some(format!(
            "the name `{name}` gives the Raft id {id}, which node `{other}` has: pick another --name"
        ));
    }
    let metrics = shared.raft.metrics().borrow().clone();
    let member = metrics
        .membership_config
        .membership()
        .nodes()
        .any(|(member, _)| *member == id);
    // A member with no Node of that name is the node of this name, deleted and not yet out of the
    // membership (the id is the name's): a rejoin right after `kith delete node/X`.
    member.then(|| format!("the node `{name}` that was deleted has not left the cluster yet: try again in a moment"))
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
    // A worker runs from a view, and whether it serves ingress (and is sent the certificates
    // of the exposed hosts) is its token's maker's to say: the joiner has to say the same.
    let (worker, ingress) = (lets != pki::Lets::Control, lets == pki::Lets::WorkerIngress);
    let mismatch = match (worker, ingress, request.view, request.ingress) {
        (true, _, false, _) => Some(
            "this token lets in a worker, which runs from a view of the store, and this node's kithd is older \
             than views: update it, or ask for a token without --worker",
        ),
        (true, false, _, true) => Some(
            "this token lets in a worker that serves no ingress: ask for a token with \
             `kith node token --worker --ingress`, or join it without --ingress",
        ),
        (true, true, _, false) => Some(
            "this token lets in a worker that serves ingress: join it with --ingress, or ask for a token \
             with `kith node token --worker`",
        ),
        _ => None,
    };
    if let Some(why) = mismatch {
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
    // A discovered Device's name is the node's with the longest name that starts it: a name
    // that would take one from the node that has it is not the joiner's to choose.
    let takes = {
        let store = shared.store.lock().expect("a handler panicked holding the store");
        crate::devices::taken_by(&store.store, &request.name)
    };
    if let Some((key, of)) = takes {
        let why = format!(
            "the name `{}` would take {key} from node `{of}` (a discovered Device's name is the node's with the \
             longest name that starts it): pick another --name",
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
    if ingress {
        spec["ingress"] = true.into();
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
        // (An IPv4 machine on a socket that takes both is `::ffff:a.b.c.d`: kept as a.b.c.d.)
        None => SocketAddr::new(peer.addr.ip().to_canonical(), request.port),
        Some(said) => {
            let mesh = serde_json::json!({ "key": said.key, "address": mesh_address.to_string(), "port": said.port });
            more.insert("mesh".into(), mesh);
            SocketAddr::new(mesh_address.into(), request.port)
        }
    };
    // A worker runs from a view and is never sent the store: its Node says so from the start.
    if worker {
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
        view: worker.then(|| (cluster.me.name.clone(), pki::print_of(&cluster.me.cert).ok())),
    }))
}

/// Trade a join token for an identity, at the node `address`. Let in as a worker, it runs
/// from a view; `ingress`: it serves ingress (`--ingress`).
pub async fn request_join(
    address: &str,
    token: &str,
    name: &str,
    port: u16,
    mesh: Option<OnMesh>,
    ingress: bool,
) -> Fallible<Joined> {
    pki::valid_name(name)?;
    let (secret, pinned, maker) = pki::token_parts(token)?;
    // (The whole cause: a refused certificate says who was called and who answered.)
    let failed = |what: &str, e: reqwest::Error| format!("{what} {address}: {}", why(&e));
    // The node that made the token is the one called, by its name and key: any other node of
    // the cluster that answers at `address` is sent nothing. The CA it hands over has to be the
    // one the token names. A token from before tokens named their maker is taken from whoever
    // answers, as it was.
    let held = maker.map(|(name, print)| (pki::Who::Name(name.into()), Some(print.to_string())));
    if maker.is_none() {
        eprintln!(
            "kithd: this token names no node (it was made before tokens did): any node of its cluster that answers at {address} is sent it"
        );
    }
    let anyone = reqwest::Client::builder()
        .use_preconfigured_tls(pki::maker_config(maker)?)
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
            // (A refused certificate is not tried again: what answers there is not the maker.)
            Err(e) if e.is_connect() && !refused_tls(&e) && tries < 60 => {
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
        // What a node that admits checks is the secret and the CA: the form every kithd reads.
        token: format!("kith1.{secret}.{pinned}"),
        name: name.into(),
        port,
        mesh,
        view: true,
        ingress,
    };
    let member = client_for(&ca, None, held)?
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

    /// The node a cluster started on makes its Node when the store holds none at all (the start
    /// that made the cluster, or one that died before the first Node was in), and later only
    /// says where it is.
    #[tokio::test]
    async fn first_node_makes_its_node_when_the_store_has_none_and_then_only_its_address() {
        let ca = pki::Ca::create().unwrap();
        let cluster = Cluster::new(node(&ca, "a"), Some(ca)).unwrap();
        let shared = shared_of("first-node", cluster, &[]).await;
        let address = |shared: &Shared| {
            let state = shared.store.lock().unwrap();
            let node = state.store.get("Node/a").map(|node| node.status.clone().unwrap());
            node.map(|status| status["address"].as_str().unwrap().to_string())
        };
        assert!(
            register_first(&shared, "a", "127.0.0.1:1", 1, "p", serde_json::Value::Null)
                .await
                .unwrap()
        );
        assert_eq!(address(&shared).as_deref(), Some("127.0.0.1:1"));
        assert!(
            register_first(&shared, "a", "127.0.0.1:2", 1, "p", serde_json::Value::Null)
                .await
                .unwrap()
        );
        assert_eq!(address(&shared).as_deref(), Some("127.0.0.1:2"));
    }

    /// With another node's Node in the store and its own gone, it is deleted: nothing is written.
    #[tokio::test]
    async fn first_node_deleted_is_not_made_again() {
        let ca = pki::Ca::create().unwrap();
        let cluster = Cluster::new(node(&ca, "a"), Some(ca)).unwrap();
        let shared = shared_of("first-node-deleted", cluster, &[at("b", "127.0.0.1:3", None)]).await;
        for _ in 0..2 {
            let put = register_first(&shared, "a", "127.0.0.1:1", 1, "p", serde_json::Value::Null);
            assert!(!put.await.unwrap());
            assert!(shared.store.lock().unwrap().store.get("Node/a").is_none());
        }
    }

    /// A Node of its name that holds another certificate is a joiner's, made after the delete: its
    /// status is not written over.
    #[tokio::test]
    async fn first_node_leaves_a_node_that_holds_another_certificate_alone() {
        let ca = pki::Ca::create().unwrap();
        let cluster = Cluster::new(node(&ca, "a"), Some(ca)).unwrap();
        let others = [at("a", "127.0.0.1:9", Some("joiner".into()))];
        let shared = shared_of("first-node-joiner", cluster, &others).await;
        let put = register_first(&shared, "a", "127.0.0.1:1", 1, "p", serde_json::Value::Null);
        assert!(!put.await.unwrap());
        let state = shared.store.lock().unwrap();
        let status = state.store.get("Node/a").unwrap().status.clone().unwrap();
        assert_eq!(
            (status["address"].as_str(), status["certificate"].as_str()),
            (Some("127.0.0.1:9"), Some("joiner"))
        );
    }

    /// A name whose Raft id a Node has is refused at the join (it would be taken for that Node's
    /// voter), the token is not spent, and a name with a free id is not refused for it.
    #[tokio::test]
    async fn join_refuses_a_taken_raft_id() {
        let ca = pki::Ca::create().unwrap();
        let a = node(&ca, "a");
        let cluster = Cluster::new(a, Some(ca)).unwrap();
        let token = cluster
            .tokens
            .mint(&cluster.me.ca, Some(&cluster.me), pki::Lets::Control)
            .unwrap();
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
                ingress: false,
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
        // A member of Raft with no Node of its name (this node's own, here) is a node deleted and not
        // yet out: the same name is told to wait, not to pick another.
        let (status, Json(said)) = join("a").await.err().expect("a member's id is refused");
        let said = said["error"].as_str().unwrap();
        assert!(
            status == StatusCode::CONFLICT && said.contains("has not left the cluster yet"),
            "{said}"
        );
        // A free id is let in.
        let other = join("someone-else").await.map(drop);
        assert_eq!(
            other.map_err(|(status, Json(said))| format!("{status}: {said}")),
            Ok(())
        );
    }

    /// A name that would take a discovered Device from the node that has it is refused at the
    /// join, the token is not spent, and the Device stays that node's.
    #[tokio::test]
    async fn join_refuses_a_longest_name_that_takes_a_nodes_device() {
        let ca = pki::Ca::create().unwrap();
        let a = node(&ca, "a");
        let cluster = Cluster::new(a, Some(ca)).unwrap();
        let token = cluster
            .tokens
            .mint(&cluster.me.ca, Some(&cluster.me), pki::Lets::Worker)
            .unwrap();
        let shared = shared_of("join-name", cluster, &[at("w", "127.0.0.1:1", None)]).await;
        let device: kith_api::Resource = serde_json::from_value(serde_json::json!({
            "apiVersion": "kith.dev/v1", "kind": "Device",
            "metadata": { "name": "w-gpu-card0", "labels": { "kith.dev/discovered": "true", "kith.dev/node": "w" } },
            "spec": { "node": "w", "class": "gpu", "path": "/dev/dri/card0" },
        }))
        .unwrap();
        shared.store.lock().unwrap().store.apply(device).unwrap();
        let peer = Peer {
            addr: "127.0.0.1:2".parse().unwrap(),
            subject: None,
        };
        let request = JoinRequest {
            token: token.clone(),
            name: "w-gpu".into(),
            port: 7000,
            mesh: None,
            view: true,
            ingress: false,
        };
        let refused = join(State(shared.clone()), ConnectInfo(peer), Json(request)).await;
        let (status, Json(said)) = refused.err().expect("a name that takes a Device is refused");
        let said = said["error"].as_str().unwrap();
        assert_eq!(status, StatusCode::CONFLICT, "{said}");
        assert!(
            said.contains("would take Device/w-gpu-card0 from node `w`") && said.contains("pick another --name"),
            "{said}"
        );
        let cluster = shared.cluster.as_ref().unwrap();
        assert!(
            cluster.tokens.good(&token, false).is_some(),
            "the refusal spent the token"
        );
        let store = shared.store.lock().unwrap();
        assert!(store.store.get("Node/w-gpu").is_none() && store.store.get("Device/w-gpu-card0").is_some());
    }

    /// A machine that joins over IPv4 to a socket that takes both is seen as `::ffff:a.b.c.d`:
    /// its Node is reached at `a.b.c.d`, the form every reader of `status.address` expects.
    #[tokio::test]
    async fn joined_from_a_mapped_address_is_stored_at_its_ipv4() {
        let ca = pki::Ca::create().unwrap();
        let cluster = Cluster::new(node(&ca, "a"), Some(ca)).unwrap();
        let token = cluster
            .tokens
            .mint(&cluster.me.ca, Some(&cluster.me), pki::Lets::Worker)
            .unwrap();
        let shared = shared_of("join-mapped", cluster, &[]).await;
        let peer = Peer {
            addr: "[::ffff:192.0.2.7]:40000".parse().unwrap(),
            subject: None,
        };
        let request = JoinRequest {
            token,
            name: "w".into(),
            port: 7000,
            mesh: None,
            view: true,
            ingress: false,
        };
        let joined = join(State(shared.clone()), ConnectInfo(peer), Json(request)).await;
        let _joined = joined.map_err(|(_, Json(said))| said).unwrap();
        let node = shared.store.lock().unwrap().store.get("Node/w").cloned().unwrap();
        assert_eq!(node.status.unwrap()["address"], "192.0.2.7:7000");
    }

    /// A token for an ingress worker lets in a worker that runs from a view, and the node that
    /// admits it writes `spec.ingress` on its Node (the joiner never does). The joiner has to say
    /// what its token says; a refusal does not spend the token.
    #[tokio::test]
    async fn join_lets_in_an_ingress_worker_to_a_view_its_node_saying_ingress() {
        let ca = pki::Ca::create().unwrap();
        let cluster = Cluster::new(node(&ca, "a"), Some(ca)).unwrap();
        let mint = |lets| cluster.tokens.mint(&cluster.me.ca, Some(&cluster.me), lets).unwrap();
        let (edge, plain) = (mint(pki::Lets::WorkerIngress), mint(pki::Lets::Worker));
        let shared = shared_of("join-ingress", cluster, &[]).await;
        let peer = Peer {
            addr: "127.0.0.1:2".parse().unwrap(),
            subject: None,
        };
        let join = |token: &str, name: &str, view: bool, ingress: bool| {
            let request = JoinRequest {
                token: token.into(),
                name: name.into(),
                port: 7000,
                mesh: None,
                view,
                ingress,
            };
            join(State(shared.clone()), ConnectInfo(peer.clone()), Json(request))
        };
        let refusal = |said: Result<Json<Joined>, Refusal>| {
            let (status, Json(said)) = said.err().expect("refused");
            assert_eq!(status, StatusCode::CONFLICT);
            said["error"].as_str().unwrap().to_string()
        };
        // An ingress joiner with a token that does not say ingress, and the other way round.
        let said = refusal(join(&plain, "w", true, true).await);
        assert!(said.contains("kith node token --worker --ingress"), "{said}");
        let said = refusal(join(&edge, "w", true, false).await);
        assert!(said.contains("join it with --ingress"), "{said}");
        // A kithd from before views cannot run from one.
        let said = refusal(join(&edge, "w", false, true).await);
        assert!(said.contains("update it"), "{said}");
        let cluster = shared.cluster.as_ref().unwrap();
        assert!(cluster.tokens.good(&edge, false).is_some() && cluster.tokens.good(&plain, false).is_some());

        let joined = join(&edge, "edge", true, true)
            .await
            .map_err(|(_, Json(said))| said)
            .unwrap();
        assert_eq!(joined.0.view.as_ref().map(|(name, _)| name.as_str()), Some("a"));
        let edge = shared.store.lock().unwrap().store.get("Node/edge").cloned().unwrap();
        assert_eq!(
            (&edge.spec["trust"], &edge.spec["ingress"]),
            (&"worker".into(), &true.into())
        );
        assert_eq!(edge.status.as_ref().unwrap()["view"], true);
        // A worker without it: no `ingress` on its Node.
        let _ = join(&plain, "w", true, false)
            .await
            .map_err(|(_, Json(said))| said)
            .unwrap();
        let store = shared.store.lock().unwrap();
        assert!(store.store.get("Node/w").unwrap().spec.get("ingress").is_none());
    }

    /// Only our certificate check's refusal ends a join's asking; a handshake cut short (an alert)
    /// or a node not up yet is asked again.
    #[test]
    fn only_a_refused_certificate_is_not_asked_again() {
        use std::io::{Error, ErrorKind};
        // (As hyper-rustls hands it on: an io::Error around an io::Error around the TLS error.)
        let wrapped = |tls: rustls::Error| Error::other(Error::new(ErrorKind::InvalidData, tls));
        assert!(refused_tls(&wrapped(rustls::Error::General(
            "node a was called".into()
        ))));
        assert!(refused_tls(&wrapped(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer
        ))));
        assert!(!refused_tls(&wrapped(rustls::Error::AlertReceived(
            rustls::AlertDescription::HandshakeFailure
        ))));
        assert!(!refused_tls(&Error::from(ErrorKind::ConnectionRefused)));
    }

    /// A join token names the node that made it, and a joiner talks to that node alone: another node
    /// of the CA that answers at the --join address is refused in the handshake and asked nothing
    /// (not even for the CA), and the error says who was called and who answered. A token from
    /// before, which names no node, is still taken; what is sent is the token in its old form.
    #[tokio::test]
    async fn join_pinned_to_the_node_that_made_the_token() {
        let ca = pki::Ca::create().unwrap();
        let (a, x) = (node(&ca, "a"), node(&ca, "x"));
        let cluster = Cluster::new(a.clone(), Some(ca)).unwrap();
        let token = cluster
            .tokens
            .mint(&cluster.me.ca, Some(&cluster.me), pki::Lets::Control)
            .unwrap();
        let (secret, of_ca, maker) = pki::token_parts(&token).unwrap();
        let print = pki::print_of(&a.cert).unwrap();
        assert_eq!(maker, Some(("a", print.as_str())));
        let old_form = format!("kith1.{secret}.{of_ca}");
        let shared = shared_of("join-pinned", cluster, &[]).await;
        let home = serving(shared.clone(), &a).await;
        let (taken, to_x) = answering_as(&x).await;

        // (Refused at once: a refused certificate is not asked again for a minute.)
        let started = std::time::Instant::now();
        let said = request_join(&taken, &token, "joiner", 7000, None, false)
            .await
            .err()
            .unwrap();
        assert!(
            said.contains("node a was called, and a certificate naming x answered"),
            "{said}"
        );
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
        assert_eq!(
            to_x.load(Ordering::SeqCst),
            0,
            "the node in the middle was asked something"
        );

        // Nor one outside the CA that names itself after the maker.
        let (posing, to_posing) = answering_as(&node(&pki::Ca::create().unwrap(), "a")).await;
        let said = request_join(&posing, &token, "joiner", 7000, None, false)
            .await
            .err()
            .unwrap();
        assert!(
            said.contains("node a was called, and a certificate naming a answered, with another key"),
            "{said}"
        );
        assert_eq!(to_posing.load(Ordering::SeqCst), 0, "the impostor was asked something");

        // What is sent is the token as an admitting side from before reads one (`kith1.SECRET.CA`).
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_side = tcp.local_addr().unwrap().to_string();
        let listener = listen(tcp, pki::server_config(&a).unwrap()).unwrap();
        let (ca_pem, sent) = (a.ca.clone(), Arc::new(std::sync::Mutex::new(String::new())));
        let kept = sent.clone();
        let keep = move |Json(body): Json<serde_json::Value>| {
            *kept.lock().unwrap() = body["token"].as_str().unwrap_or_default().to_string();
            std::future::ready(StatusCode::FORBIDDEN)
        };
        let app = Router::new()
            .route("/v1/ca", get(move || std::future::ready(ca_pem)))
            .route("/v1/join", post(keep));
        tokio::spawn(async move { drop(axum::serve(listener, app.into_make_service()).await) });
        assert!(
            request_join(&old_side, &token, "joiner", 7000, None, false)
                .await
                .is_err()
        );
        assert_eq!(*sent.lock().unwrap(), old_form);

        // At its maker the token is taken (nothing of it reached anyone else).
        let joined = request_join(&home, &token, "joiner", 7000, None, false).await.unwrap();
        assert!(joined.ca == a.ca && shared.store.lock().unwrap().store.get("Node/joiner").is_some());
        // A token from before names no node, and is still taken.
        let cluster = shared.cluster.as_ref().unwrap();
        let old = cluster.tokens.mint(&cluster.me.ca, None, pki::Lets::Control).unwrap();
        assert_eq!(pki::token_parts(&old).unwrap().2, None);
        assert!(request_join(&home, &old, "other", 7000, None, false).await.is_ok());
    }

    /// Serves `node_router(shared)` on a loopback port, as the node `me`: the address.
    async fn serving(shared: Arc<Shared>, me: &Identity) -> String {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap().to_string();
        let listener = listen(tcp, pki::server_config(me).unwrap()).unwrap();
        let app = node_router(shared).into_make_service_with_connect_info::<Peer>();
        tokio::spawn(async move { drop(axum::serve(listener, app).await) });
        address
    }

    /// A call to `address` as `who`: its status, and what it said.
    async fn call_as(
        who: &Identity,
        request: impl FnOnce(&reqwest::Client) -> reqwest::RequestBuilder,
    ) -> (u16, String) {
        let client = client_for(&who.ca, Some(who), None).unwrap();
        let answer = request(&client).send().await.unwrap();
        (answer.status().as_u16(), answer.text().await.unwrap())
    }

    /// Serves, on a loopback port, as the voter `me`: `/v1/raft/stands` says what `words` has for
    /// the name asked, or `otherwise`, and is counted. `words` None is a build that has no such
    /// route (404 to all).
    async fn voter_saying(
        me: &Identity,
        words: Option<&'static [(&'static str, &'static str)]>,
        otherwise: &'static str,
    ) -> (String, Arc<AtomicUsize>) {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap().to_string();
        let listener = listen(tcp, pki::server_config(me).unwrap()).unwrap();
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        let app = match words {
            None => Router::new(),
            Some(words) => Router::new().route(
                "/v1/raft/stands",
                get(
                    move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let name = query.get("name").map(String::as_str);
                        let word = words.iter().find(|(of, _)| Some(*of) == name);
                        std::future::ready(Json(word.map_or(otherwise, |(_, word)| *word)))
                    },
                ),
            ),
        };
        tokio::spawn(async move { drop(axum::serve(listener, app.into_make_service()).await) });
        (address, asked)
    }

    use std::collections::HashMap;

    /// A node that was away is sent Raft's messages by nodes it has not heard of. It takes them
    /// once a voter it last knew says the node stands, and refuses them (403, and Raft never sees
    /// them) when one says it does not, or none says either: asked once per sender, the answer kept.
    #[tokio::test]
    async fn vouched_lets_in_a_joiner_and_not_a_deleted_node() {
        use kith_store::openraft::raft::VoteRequest;
        use kith_store::openraft::{BasicNode, Vote};
        let ca = pki::Ca::create().unwrap();
        let born = |name: &str| {
            let (cert, key) = ca.issue_born(name, 50).unwrap();
            Identity {
                name: name.into(),
                ca: ca.cert.clone(),
                cert,
                key,
            }
        };
        let (gamma, alpha, beta) = (node(&ca, "gamma"), node(&ca, "alpha"), node(&ca, "beta"));
        // alpha has heard of d and f, knows x was deleted, and has not caught up to n; beta is of a
        // build that has no such question, and carol does not answer.
        let words: &'static [_] = &[("d", "yes"), ("e", "yes"), ("f", "yes"), ("n", "not yet")];
        let (to_alpha, asked) = voter_saying(&alpha, Some(words), "no").await;
        let (to_beta, _) = voter_saying(&beta, None, "").await;
        let shared = shared_with("vouched", gamma.clone(), &[]).await;
        let id = kith_store::node_id;
        let members = std::collections::BTreeMap::from([
            (id("gamma"), BasicNode::new("")),
            (id("alpha"), BasicNode::new(&to_alpha)),
            (id("beta"), BasicNode::new(&to_beta)),
            (id("carol"), BasicNode::new("127.0.0.1:1")),
        ]);
        shared.raft.initialize(members).await.unwrap();
        let address = serving(shared.clone(), &gamma).await;
        let send = |who: Identity, what: &'static str| {
            let address = address.clone();
            async move {
                let vote = VoteRequest::new(Vote::new(1000, id(&who.name)), None);
                let body = if what == "vote" {
                    serde_json::to_value(vote).unwrap()
                } else {
                    serde_json::json!({})
                };
                call_as(&who, |client| {
                    client.post(format!("https://{address}/v1/raft/{what}")).json(&body)
                })
                .await
            }
        };
        let asked_now = || asked.load(Ordering::SeqCst);

        // A voter it knew says x is gone: refused, as evicted, and Raft never sees it (a body
        // that is not Raft's would be refused by Raft's own handler with another status).
        let (x, d) = (born("x"), born("d"));
        let (status, said) = send(x.clone(), "vote").await;
        assert!(status == 403 && said.contains(EVICTED), "{status} {said}");
        assert_eq!(asked_now(), 1);
        for what in ["append", "snapshot", "vote"] {
            let (status, said) = send(x.clone(), what).await;
            assert!(status == 403 && said.contains(EVICTED), "{what}: {status} {said}");
        }
        assert_eq!(asked_now(), 1, "the answer was not kept");

        // A joiner that leads by now: let in, after one asking however many messages it sends.
        let sent: Vec<_> = (0..5).map(|_| send(d.clone(), "vote")).collect();
        for (status, said) in futures_util::future::join_all(sent).await {
            assert_eq!(status, 200, "{said}");
        }
        assert_eq!(asked_now(), 2);

        // "Not yet", no such route, and no answer are no word: refused.
        let (status, said) = send(born("n"), "append").await;
        assert!(status == 403 && said.contains(EVICTED), "{status} {said}");
        assert_eq!(asked_now(), 3);

        // The answers kept are for 16 senders: then one that would be let in is not even asked.
        for n in 0..13 {
            let (status, _) = send(born(&format!("s{n}")), "append").await;
            assert_eq!(status, 403);
        }
        assert_eq!(asked_now(), 16);
        let (status, _) = send(born("f"), "vote").await;
        assert_eq!((status, asked_now()), (403, 16));
    }

    /// The forge route (a leader that appends what it was not asked for, forge.rs) is in a build
    /// with the cargo feature `forge` and in no other: a release has no `/v1/forge`, for an
    /// Identity or a node, and says no more of it than of any path it has not.
    #[tokio::test]
    async fn forge_is_in_no_release_build() {
        let forge = cfg!(feature = "forge");
        assert_eq!(crate::access::for_identities("/v1/forge"), forge);
        let ca = pki::Ca::create().unwrap();
        let alpha = node(&ca, "alpha");
        let shared = shared_with("forge-route", alpha.clone(), &[at("alpha", "127.0.0.1:1", None)]).await;
        let address = serving(shared, &alpha).await;
        let (status, said) = call_as(&alpha, |client| {
            client.post(format!("https://{address}/v1/forge")).json(&"Mark")
        })
        .await;
        // (Not found, as any path it has not; with the feature, the route is there: a node's
        // call does not pass for the admin's.)
        assert_eq!(status == 404, !forge, "{status} {said}");
        let (status, said) = call_as(&alpha, |client| {
            client.post(format!("https://{address}/v1/nope")).json(&"Mark")
        })
        .await;
        assert_eq!(status, 404, "{said}");
    }

    /// With the feature, the forge route appends what it is given to the log as the leader's own
    /// write, and says whether applying it here took: a Signed entry no node can check is not.
    #[cfg(feature = "forge")]
    #[tokio::test]
    async fn forge_appends_and_says_what_applying_it_came_to() {
        use axum::extract::State;
        let ca = pki::Ca::create().unwrap();
        let alpha = node(&ca, "alpha");
        let shared = shared_with("forge-append", alpha.clone(), &[]).await;
        let id = kith_store::node_id;
        let alone = kith_store::openraft::BasicNode::new("127.0.0.1:1");
        let members = std::collections::BTreeMap::from([(id("alpha"), alone)]);
        shared.raft.initialize(members).await.unwrap();
        let send = |entry: kith_store::Command| {
            let shared = shared.clone();
            async move {
                let sent = crate::forge::append(
                    State(shared),
                    axum::Extension(crate::access::Caller::Admin),
                    Json(entry),
                );
                sent.await.map(|Json(said)| said)
            }
        };
        let forged = kith_store::Command::Signed {
            header: "v1; who=local socket; target=*; expires=1; nonce=00; sig=AA==".into(),
            method: "POST".into(),
            path: "/v1/apply".into(),
            body: String::new(),
            command: Box::new(kith_store::Command::Mark),
        };
        // (A one-voter cluster elects itself: asked until it leads.)
        let mut said = None;
        for _ in 0..100 {
            match send(forged.clone()).await {
                Ok(answer) => {
                    said = Some(answer);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
        let said = said.expect("the node led within ten seconds");
        assert_eq!(said["applied"], false, "{said}");
        assert!(said["error"].as_str().unwrap().contains("signed entry"), "{said}");
        let said = send(kith_store::Command::Mark).await.ok().expect("a leader appends");
        assert_eq!(said["applied"], true, "{said}");
    }

    /// `/v1/raft/stands` says yes, no or not yet of a name and key, to a node of this cluster only.
    #[tokio::test]
    async fn stands_route_answers_only_a_node_that_stands() {
        let ca = pki::Ca::create().unwrap();
        let (alpha, d, x) = (node(&ca, "alpha"), node(&ca, "d"), node(&ca, "x"));
        let (print_d, print_x) = (pki::print_of(&d.cert).unwrap(), pki::print_of(&x.cert).unwrap());
        let nodes = [
            at("alpha", "127.0.0.1:1", None),
            at("d", "127.0.0.1:1", Some(print_d.clone())),
        ];
        let shared = shared_with("stands-route", alpha.clone(), &nodes).await;
        let address = serving(shared, &alpha).await;
        let ask = |who: &Identity, query: String| {
            let url = format!("https://{address}/v1/raft/stands?{query}");
            let who = who.clone();
            async move { call_as(&who, |client| client.get(url)).await }
        };
        for (query, word) in [
            (format!("name=d&key={print_d}"), "yes"),
            (format!("name=d&key={print_x}"), "no"),
            // Born after what this node has: it cannot know yet.
            (format!("name=x&key={print_x}&born=1000"), "not yet"),
            (format!("name=x&key={print_x}&born=0"), "no"),
            // No index, and this node has heard of itself: it would know.
            (format!("name=x&key={print_x}"), "no"),
        ] {
            assert_eq!(ask(&d, query.clone()).await, (200, format!("\"{word}\"")), "{query}");
        }
        // A node whose Node is not there (deleted), and an Identity: refused.
        let (status, said) = ask(&x, format!("name=d&key={print_d}")).await;
        assert!(status == 401 && said.contains(EVICTED), "{status} {said}");
        let (cert, key, _) = ca.issue_user("carol").unwrap();
        let carol = Identity {
            name: "carol".into(),
            ca: ca.cert.clone(),
            cert,
            key,
        };
        assert_eq!(ask(&carol, format!("name=d&key={print_d}")).await.0, 403);
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

    /// A node that restarts in the term it left (a leader comes back as leader at once, in the same
    /// term) has applied only up to its snapshot until Raft applies the log it holds past it: a Node
    /// deleted in that log is not to be put back on what the snapshot says.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_same_term_restart_does_not_bring_back_a_deleted_node() {
        // What a follower restarted in term 1 shows before Raft applies the 501 entries its log
        // holds past its snapshot (the delete of its Node among them): a leader, and an applied
        // entry of this term, which is the snapshot's. (A leader's restart in one term cannot be
        // held there by a test: Raft applies its log as it starts, before `replica` returns.)
        let at = |term, index| {
            Some(kith_store::openraft::LogId::new(
                kith_store::openraft::CommittedLeaderId::new(term, 1),
                index,
            ))
        };
        let mut m = kith_store::openraft::RaftMetrics::new_initial(1);
        (m.current_term, m.current_leader, m.last_log_index) = (1, Some(2), Some(505));
        m.last_applied = at(1, 4);
        assert!(
            !applied_what_it_holds(&m),
            "the snapshot's entry is of the term, with the log behind it"
        );
        m.last_applied = at(1, 505);
        assert!(applied_what_it_holds(&m));
        m.current_leader = None;
        assert!(!applied_what_it_holds(&m), "no leader known");
        (m.current_leader, m.current_term) = (Some(2), 2);
        assert!(
            !applied_what_it_holds(&m),
            "the entry applied is of a term before this one"
        );

        let ca = pki::Ca::create().unwrap();
        let a = pinned_peer::node(&ca, "a");
        let dir = std::env::temp_dir().join(format!("kithd-same-term-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        async fn put(shared: &Shared) -> Result<bool, kith_api::store::Error> {
            register_first(shared, "a", "127.0.0.1:1", 1, "p", serde_json::Value::Null).await
        }
        let open = |ca| async {
            let cluster = Cluster::new(a.clone(), Some(ca)).unwrap();
            crate::replica(Some(cluster), &dir, Duration::from_secs(300))
                .await
                .unwrap()
        };
        let shared = open(ca).await;
        assert!(put(&shared).await.unwrap());
        // Another Node, so the store is not empty (the one case where it is made again), a snapshot
        // that has both, and past it the delete of its own and a long run of writes.
        let other = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {name: b}\nspec: {}\n";
        let other = kith_api::Resource::from_source(other).unwrap().remove(0).unwrap();
        let apply = Command::Apply {
            resources: vec![other],
            at: kith_api::store::now(),
        };
        shared.submit(apply).await.unwrap();
        let at = shared.raft.metrics().borrow().last_applied.unwrap().index;
        shared.raft.trigger().snapshot().await.unwrap();
        let wait = shared.raft.wait(Some(Duration::from_secs(20)));
        let built = |m: &kith_store::openraft::RaftMetrics<_, _>| m.snapshot.is_some_and(|s| s.index >= at);
        wait.metrics(built, "a snapshot").await.unwrap();
        let delete = Command::Delete { key: "Node/a".into() };
        shared.submit(delete).await.unwrap();
        // (Fewer than the 1000 that make Raft snapshot by itself, which would take the delete in.)
        for n in 0..500 {
            let statuses = vec![(
                "Node/b".to_string(),
                serde_json::Map::from_iter([("n".into(), n.into())]),
            )];
            shared.submit(Command::Patch { statuses }).await.unwrap();
        }
        shared.raft.shutdown().await.unwrap();
        drop(shared);

        let shared = open(pki::Ca::create().unwrap()).await;
        assert!(!put(&shared).await.unwrap());
        assert!(shared.store.lock().unwrap().store.get("Node/a").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The barrier a follower asks of the leader before it decides (`register_first`): it comes
    /// back only once this node has applied the entry the barrier is at, which is past everything
    /// the leader had committed, and it changes nothing in the store.
    #[tokio::test]
    async fn a_barrier_comes_back_once_its_entry_is_applied() {
        use pinned_peer::{at, node, shared_of};
        let ca = pki::Ca::create().unwrap();
        let cluster = Cluster::new(node(&ca, "a"), Some(ca)).unwrap();
        let shared = shared_of("barrier-wait", cluster, &[at("b", "127.0.0.1:3", None)]).await;
        let before = shared.raft.metrics().borrow().last_applied.map_or(0, |l| l.index);
        let index = leader_barrier(&shared).await.unwrap();
        let applied = shared.raft.metrics().borrow().last_applied.map_or(0, |l| l.index);
        assert!(index > before && applied >= index, "{before} {index} {applied}");
        assert!(shared.store.lock().unwrap().store.get("Node/b").is_some());
    }

    #[test]
    fn an_evicted_nodes_key_stands_for_no_node() {
        let mut store = kith_api::store::Store::default();
        let stands = |store: &kith_api::store::Store, name: &str, key: &[u8]| stands(store, name, &pki::key_print(key));
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

    /// One voter's no outweighs any yes; "not yet", no answer and no such route are no word.
    /// A no is kept 30 seconds; a yes until this node is past the index its Node was there by.
    #[test]
    fn vouched_answers_are_weighed_and_kept_for_a_while() {
        let said = |words: &[Option<&str>]| verdict(&words.iter().map(|w| w.map(String::from)).collect::<Vec<_>>());
        assert_eq!(said(&[Some("yes"), None, Some("not yet")]), Some(true));
        assert_eq!(said(&[Some("yes"), Some("no")]), Some(false));
        assert_eq!(said(&[None, Some("not yet"), Some("maybe")]), None);
        assert_eq!(said(&[]), None);
        let now = std::time::Instant::now();
        let mut kept = std::collections::HashMap::new();
        let at = |word, until, born| Kept { word, until, born };
        kept.insert(("x".to_string(), "k".to_string()), at(Word::No, now + KEPT, Some(5)));
        kept.insert(("d".to_string(), "k".to_string()), at(Word::Yes, now + KEPT, Some(5)));
        keep(&mut kept, now + KEPT - Duration::from_secs(1), 4);
        assert_eq!(kept.len(), 2);
        keep(&mut kept, now, 5);
        assert!(kept.keys().all(|(name, _)| name == "x"), "a yes outlived the index");
        keep(&mut kept, now + KEPT, 0);
        assert!(kept.is_empty());
    }

    /// An asking that took longer than it was given was dropped, and another asked in its place:
    /// the late answer is not written over that one, nor over what it said.
    #[test]
    fn a_late_answer_is_not_kept_over_a_later_asking() {
        use futures_util::FutureExt;
        let asking = || Word::Asking(futures_util::future::ready(None).boxed().shared());
        let (now, id) = (std::time::Instant::now(), ("d".to_string(), "k".to_string()));
        let (first, second) = (now + 2 * ASKING, now + 5 * ASKING);
        let mut kept = std::collections::HashMap::new();
        let at = |word, until| Kept {
            word,
            until,
            born: None,
        };
        kept.insert(id.clone(), at(asking(), second));
        answered(&mut kept, &id, first, Some(true), now);
        assert!(matches!(kept[&id].word, Word::Asking(_)) && kept[&id].until == second);
        answered(&mut kept, &id, second, Some(false), now);
        assert!(matches!(kept[&id].word, Word::No) && kept[&id].until == now + KEPT);
        answered(&mut kept, &id, second, Some(true), now);
        assert!(matches!(kept[&id].word, Word::No), "an answer was kept over an answer");
        // No word at all is kept a short while; an id that was dropped stays dropped.
        kept.insert(id.clone(), at(asking(), first));
        answered(&mut kept, &id, first, None, now);
        assert!(matches!(kept[&id].word, Word::No) && kept[&id].until == now + QUIET);
        answered(&mut kept, &("e".to_string(), "k".to_string()), first, Some(true), now);
        assert_eq!(kept.len(), 1);
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

    /// What the web UI shows once: the token's answer, and a refusal of it, are kept by no cache;
    /// and an Identity with no right to apply Nodes, Roles and RoleBindings gets a 403 from the
    /// token and from netboot's PUT and DELETE (the page says the server's sentence as it is).
    #[tokio::test]
    async fn no_store_on_the_token_and_403_for_who_may_not() {
        use super::pinned_peer::{node, shared_of};
        let ca = pki::Ca::create().unwrap();
        let cluster = Cluster::new(node(&ca, "a"), Some(ca)).unwrap();
        let shared = shared_of("no-store", cluster, &[]).await;
        let kept = |answer: &Response| {
            answer.headers()[axum::http::header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .to_string()
        };
        let ask = |caller: Caller| token(State(shared.clone()), axum::Extension(caller), Query(BTreeMap::new()));
        let made = ask(Caller::Admin).await;
        assert_eq!(made.status(), StatusCode::OK);
        assert_eq!(kept(&made), "no-store");
        let body = axum::body::to_bytes(made.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("\"token\":\"kith1."));
        let refused = ask(Caller::Identity("carol".into())).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(kept(&refused), "no-store");
        for method in [axum::http::Method::PUT, axum::http::Method::DELETE] {
            let refused = netboot(
                State(shared.clone()),
                axum::Extension(Caller::Identity("carol".into())),
                method,
                Query(BTreeMap::new()),
                Body::empty(),
            )
            .await;
            assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        }
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
