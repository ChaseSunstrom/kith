//! A worker's view of the store (`docs/adr-workers.md`): a worker (`spec.trust: worker`)
//! keeps no replica of the store. A control node sends it what it needs to run what is placed
//! on it, and the Secrets and ConfigMaps of that alone; it keeps that in `view.json` in its
//! state directory, reads it as every node reads its store, and writes through the control
//! node it follows, which holds each write to a list (`crate::worker`).
//!
//! The sender decides what is in a view, never the worker: from its own store and the name
//! in the worker's certificate.

use crate::Shared;
use crate::cluster::Peer;
use crate::pki;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kith_api::Resource;
use kith_api::store::{Error, Store};
use kith_store::{Command, Done, Reply};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// The kinds a worker is sent whole: what it runs, and what the proxy, the claims, the seats,
/// the mesh and the resolver read of every node's. A kind that is not here is sent by what
/// names it ([`named`]) or not at all: a kind someone defines, an Identity, a Role.
const WHOLE: [&str; 21] = [
    "Cluster",
    "Node",
    "Namespace",
    "Workload",
    "NodeWorkload",
    "Job",
    "Service",
    "NetworkPolicy",
    "Volume",
    "VolumeClaim",
    "Share",
    "Blob",
    "Image",
    "Device",
    "Seat",
    "DeviceClaim",
    "DNSZone",
    "DNSRecord",
    "DNSBlockList",
    "OSRelease",
    "UpdatePlan",
];

fn kind(key: &str) -> &str {
    key.split('/').next().unwrap_or_default()
}

fn namespace(resource: &Resource) -> &str {
    resource.metadata.namespace.as_deref().unwrap_or("default")
}

/// The keys of what the worker `node` is sent because something names it: the Secrets and
/// ConfigMaps of the templates placed on it (in `env`, `envFrom` and files), the Backups of
/// the Volumes on it with the Secret each names, the ConfigMaps of the resolver's block
/// lists, and its own NodeKey. A Secret for control nodes (`trust: control`) is never among
/// them, whatever names it.
//
// ponytail: worked out again on every round that touches a kind in [`NAMES`] (a unit's report
// touches its Workload), by listing every template and reading those placed here: keep it
// per template when a store has thousands.
pub fn named(store: &Store, node: &str) -> BTreeSet<String> {
    let mut named = BTreeSet::from([format!("NodeKey/{node}")]);
    let mut secrets = BTreeSet::new();
    let templates = ["Workload", "NodeWorkload", "Job"]
        .into_iter()
        .flat_map(|kind| store.list(Some(kind)));
    for resource in templates.filter(|resource| crate::worker::on(resource, node)) {
        let Ok((template, _)) = crate::controller::template_of(resource) else {
            continue;
        };
        let at = namespace(resource);
        secrets.extend(template.secrets().map(|name| format!("Secret/{at}/{name}")));
        named.extend(template.config_maps().map(|name| format!("ConfigMap/{at}/{name}")));
    }
    let backups = store.list(Some("Backup"));
    for backup in backups.filter(|backup| crate::worker::of_its_volume(store, backup, node)) {
        named.insert(backup.key());
        let secret = backup.spec["s3"]["secret"].as_str();
        secrets.extend(secret.map(|secret| format!("Secret/{}/{secret}", namespace(backup))));
    }
    // The node an Exit names holds its tunnel: it alone is sent the Exit and the Secret of its key.
    for exit in store.list(Some("Exit")).filter(|exit| exit.spec["node"] == node) {
        named.insert(exit.key());
        let secret = exit.spec["secret"].as_str();
        secrets.extend(secret.map(|secret| format!("Secret/kith-system/{secret}")));
    }
    for list in store.list(Some("DNSBlockList")) {
        let map = list.spec["configMap"]["name"].as_str();
        named.extend(map.map(|map| format!("ConfigMap/kith-system/{map}")));
    }
    // A worker that serves ingress (the node that admitted it said so, from its token): the
    // certificate of each host exposed, and the thumbprint it answers challenges with.
    if serves_ingress(store, node) {
        let hosts = crate::ingress::exposed(store, std::net::Ipv6Addr::UNSPECIFIED).0;
        secrets.extend(hosts.iter().map(|(host, of)| crate::ingress::tls_secret(host, of)));
        named.insert(format!("ConfigMap/{}", crate::ingress::THUMBPRINT));
    }
    let for_control = |key: &String| store.get(key).is_some_and(|secret| secret.spec["trust"] == "control");
    // (The account key orders certificates: a control node's alone, whatever names it.)
    let sendable = |key: &String| !for_control(key) && key != crate::ingress::ACCOUNT;
    named.extend(secrets.into_iter().filter(sendable));
    named
}

/// Does the Node `node` say it is a worker that serves ingress (`spec.ingress`)?
pub fn serves_ingress(store: &Store, node: &str) -> bool {
    store
        .get(&format!("Node/{node}"))
        .is_some_and(|node| node.spec["ingress"] == true)
}

/// The kinds [`named`] reads: what it says changes only when one of these does, the
/// worker's own Node, or (for a worker that serves ingress) one of [`EXPOSES`].
const NAMES: [&str; 8] = [
    "Exit",
    "Workload",
    "NodeWorkload",
    "Job",
    "Backup",
    "Volume",
    "DNSBlockList",
    "Secret",
];

/// What says which hosts are exposed.
const EXPOSES: [&str; 2] = ["Service", "Namespace"];

fn sent(key: &str, named: &BTreeSet<String>) -> bool {
    WHOLE.contains(&kind(key)) || named.contains(key)
}

/// What a control node sends a worker, one to a line: everything of its view, then what
/// changed in it, each with the index of the store it is true at.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Sent {
    /// What is not in `resources` is not in the view.
    Whole { at: u64, resources: Vec<Resource> },
    Changed {
        at: u64,
        put: Vec<Resource>,
        gone: Vec<String>,
    },
}

/// What one worker was sent last: at which index, and which keys it was sent by name.
pub struct Last {
    at: u64,
    named: BTreeSet<String>,
}

/// What the worker `node`, which was sent `last`, is sent next: `None` while the store is
/// where it was. A worker that is further behind than the changed keys are kept for (or was
/// sent nothing yet) is sent everything.
pub fn round(state: &kith_store::State, node: &str, last: &mut Option<Last>) -> Option<Sent> {
    round_of(&state.store, state.index(), |after| state.touched(after), node, last)
}

/// [`round`], of a store at the index `at` that says with `touched` which keys changed after
/// an index (`None`: it does not know that far back).
fn round_of<'a>(
    store: &'a Store,
    at: u64,
    touched: impl FnOnce(u64) -> Option<BTreeSet<&'a str>>,
    node: &str,
    last: &mut Option<Last>,
) -> Option<Sent> {
    if last.as_ref().is_some_and(|last| last.at == at) {
        return None;
    }
    let changed = last.as_ref().and_then(|last| Some((last, touched(last.at)?)));
    let own = format!("Node/{node}");
    let names = |last: &Last, key: &str| {
        let ingress = last
            .named
            .contains(&format!("ConfigMap/{}", crate::ingress::THUMBPRINT));
        NAMES.contains(&kind(key)) || key == own || (ingress && EXPOSES.contains(&kind(key)))
    };
    let named = match &changed {
        Some((last, touched)) if !touched.iter().any(|key| names(last, key)) => last.named.clone(),
        _ => named(store, node),
    };
    let message = match changed {
        None => {
            let resources = store.list(None).filter(|resource| sent(&resource.key(), &named));
            Sent::Whole {
                at,
                resources: resources.cloned().collect(),
            }
        }
        Some((last, touched)) => {
            // What a command changed, and what a placement began or stopped naming.
            let moved = named.symmetric_difference(&last.named).map(String::as_str);
            let keys: BTreeSet<&str> = touched.into_iter().chain(moved).collect();
            let (mut put, mut gone) = (Vec::new(), Vec::new());
            for key in keys {
                match store.get(key).filter(|_| sent(key, &named)) {
                    Some(resource) => put.push(resource.clone()),
                    None if sent(key, &last.named) => gone.push(key.to_string()),
                    None => {}
                }
            }
            Sent::Changed { at, put, gone }
        }
    };
    *last = Some(Last { at, named });
    Some(message)
}

/// No more rounds a second than this for one worker, and a line this often when nothing
/// changes: a worker that hears nothing for [`SILENT`] calls another control node.
const PACE: Duration = Duration::from_millis(100);
const BEAT: Duration = Duration::from_secs(5);
const SILENT: Duration = Duration::from_secs(20);

struct Sender {
    shared: Arc<Shared>,
    node: String,
    key: Vec<u8>,
    generation: watch::Receiver<u64>,
    last: Option<Last>,
    wrote: Instant,
}

impl Sender {
    /// The next line, once there is one; `None` when this worker is sent no more: its Node
    /// is gone or no worker's any more, or kithd stops.
    async fn next(&mut self) -> Option<Bytes> {
        let mut stop = self.shared.stop.subscribe();
        loop {
            // (Seen before the store is read: a change after the reading wakes this again.)
            drop(self.generation.borrow_and_update());
            let follows = crate::cluster::admitted(&self.shared, &self.node, &self.key)
                && crate::access::worker(&self.shared, &self.node);
            if !follows || *stop.borrow() {
                return None;
            }
            let message = {
                let state = self.shared.store.lock().expect("a handler panicked holding the store");
                round(&state, &self.node, &mut self.last)
            };
            let beat = || {
                let at = self.last.as_ref().map_or(0, |last| last.at);
                let nothing = (Vec::new(), Vec::new());
                Sent::Changed {
                    at,
                    put: nothing.0,
                    gone: nothing.1,
                }
            };
            let message = message.or_else(|| (self.wrote.elapsed() >= BEAT).then(beat));
            if let Some(message) = message {
                self.wrote = Instant::now();
                let mut line = serde_json::to_vec(&message).expect("resources are JSON");
                line.push(b'\n');
                return Some(line.into());
            }
            tokio::select! {
                changed = self.generation.changed() => if changed.is_err() { return None },
                () = tokio::time::sleep(BEAT.saturating_sub(self.wrote.elapsed())) => {}
                _ = stop.wait_for(|stop| *stop) => return None,
            }
            tokio::time::sleep(PACE.saturating_sub(self.wrote.elapsed())).await;
        }
    }
}

/// `GET /v1/view`: a worker's view of this control node's store, for as long as the worker
/// stays connected. Only a worker that does not vote asks, and only a control node answers.
pub async fn serve(State(shared): State<Arc<Shared>>, ConnectInfo(peer): ConnectInfo<Peer>) -> Response {
    let refuse = |status, why: String| crate::cluster::refuse(status, why).into_response();
    let (Some(pki::Subject::Node(node, key, _)), Some(cluster)) = (&peer.subject, &shared.cluster) else {
        return refuse(StatusCode::FORBIDDEN, "a view is a worker node's".into());
    };
    let me = &cluster.me.name;
    let marked = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let store = &state.store;
        if shared.view.borrow().is_some() || crate::access::is_worker(store, me) {
            let why = format!("node {me} is a worker: ask a control node for a view");
            return refuse(StatusCode::FORBIDDEN, why);
        }
        if !crate::access::is_worker(store, node) {
            let why = format!("node {node} is a control node: it keeps the store, not a view of it");
            return refuse(StatusCode::FORBIDDEN, why);
        }
        let status = store.get(&format!("Node/{node}")).and_then(|node| node.status.as_ref());
        status.is_some_and(|status| status["view"] == true)
    };
    // (A worker hands its vote over first: one that votes is still sent the store.)
    if crate::cluster::votes(&shared, node) {
        let why = format!("node {node} still votes on the store: it is sent a view once it does not");
        return refuse(StatusCode::CONFLICT, why);
    }
    // Written down before the first line: the node that leads stops sending it the store.
    if !marked {
        let fields = serde_json::Map::from_iter([("view".to_string(), true.into())]);
        let statuses = vec![(format!("Node/{node}"), fields)];
        if let Err(e) = shared.write(Command::Patch { statuses }).await {
            return refuse(StatusCode::SERVICE_UNAVAILABLE, e.to_string());
        }
    }
    let sender = Sender {
        generation: shared.generation.subscribe(),
        shared,
        node: node.clone(),
        key: key.clone(),
        last: None,
        wrote: Instant::now(),
    };
    let lines = futures_util::stream::unfold(sender, |mut sender| async move {
        let line = sender.next().await?;
        Some((Ok::<_, std::io::Error>(line), sender))
    });
    Body::from_stream(lines).into_response()
}

/// The control node a worker follows: its name, where it is called, and the print of its key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Upstream {
    pub name: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

impl Upstream {
    /// The node a Node resource is, as it says it is called: none until it has an address.
    pub fn of(node: &Resource) -> Option<Upstream> {
        let status = node.status.as_ref()?;
        Some(Upstream {
            name: node.metadata.name.clone(),
            address: status["address"].as_str()?.to_string(),
            certificate: status["certificate"].as_str().map(str::to_string),
        })
    }
}

/// `view.json`: the view a worker runs from when no control node is in reach.
#[derive(Serialize, Deserialize)]
struct Saved {
    format: u32,
    /// The index of the store the view was true at.
    at: u64,
    /// The control node this worker joined through: called while its view names no other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first: Option<Upstream>,
    resources: Vec<Resource>,
}

pub fn path(state: &Path) -> PathBuf {
    state.join("view.json")
}

/// Write `view.json` whole, for kithd alone to read: a Secret placed here is in it.
fn save(state: &Path, at: u64, first: Option<&Upstream>, store: &Store) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let saved = Saved {
        format: 1,
        at,
        first: first.cloned(),
        resources: store.list(None).cloned().collect(),
    };
    let (path, new) = (path(state), state.join("view.json.new"));
    let written = || {
        let mut options = std::fs::OpenOptions::new();
        let mut file = options.write(true).create(true).truncate(true).mode(0o600).open(&new)?;
        file.write_all(&serde_json::to_vec(&saved).expect("resources are JSON"))?;
        file.sync_all()?;
        std::fs::rename(&new, &path)?;
        std::fs::File::open(state)?.sync_all()
    };
    written().map_err(|e| format!("writing {}: {e}", path.display()))
}

/// The view a node that joined as a worker starts from: nothing yet, and whom to ask.
pub fn begin(state: &Path, first: &Upstream) -> Result<(), String> {
    save(state, 0, Some(first), &Store::default())
}

/// The view this node keeps, if it runs from one: the store, its index, whom it joined through.
pub fn load(state: &Path) -> Result<Option<(Store, u64, Option<Upstream>)>, String> {
    let path = path(state);
    let text = match std::fs::read(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    let saved: Saved = serde_json::from_slice(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if saved.format != 1 {
        return Err(format!(
            "{} is of a newer kithd (format {}): update this node",
            path.display(),
            saved.format
        ));
    }
    let mut store = Store::default();
    saved.resources.into_iter().for_each(|resource| store.put(resource));
    Ok(Some((store, saved.at, saved.first)))
}

/// What follows a view on a worker: where `view.json` is, and what of it waits to be written.
struct Follower<'a> {
    shared: &'a Arc<Shared>,
    state: &'a Path,
    first: &'a Option<Upstream>,
    /// Statuses alone changed since `view.json` was written, and when it was.
    stale: bool,
    saved: Instant,
    /// The copy of the store this node kept until its first view is still to erase.
    kept: bool,
}

/// A view that only statuses changed in is written this often: a unit that reports does not
/// have the whole view written again each time.
const SAVE_EVERY: Duration = Duration::from_secs(30);

impl Follower<'_> {
    fn save(&mut self) -> Result<(), String> {
        // (Written with the store let go of: a slow disk does not hold up who reads it.)
        let (store, at) = {
            let state = self.shared.store.lock().expect("a handler panicked holding the store");
            (state.store.clone(), self.shared.view.borrow().unwrap_or(0))
        };
        save(self.state, at, self.first.as_ref(), &store)?;
        (self.stale, self.saved) = (false, Instant::now());
        Ok(())
    }

    /// Take one line of the view.
    async fn take(&mut self, sent: Sent) -> Result<(), String> {
        let shared = self.shared;
        // (The generation moves while the store is locked: who reads under the lock reads both.)
        let poke = || {
            shared.generation.send_modify(|generation| *generation += 1);
            shared.changed.notify_one();
        };
        match sent {
            Sent::Whole { at, resources } => {
                let mut store = Store::default();
                resources.into_iter().for_each(|resource| store.put(resource));
                // On this node's disk before anything of the store it had is let go.
                save(self.state, at, self.first.as_ref(), &store)?;
                if shared.view.borrow().is_none() {
                    // Until now this node was sent the whole store: Raft ends here (before the
                    // view is this node's store: nothing of Raft's is written into a view).
                    let _ = shared.raft.shutdown().await;
                    self.kept = true;
                }
                {
                    let mut state = shared.store.lock().expect("a handler panicked holding the store");
                    state.store = store;
                    shared.view.send_replace(Some(at));
                    poke();
                }
                (self.stale, self.saved) = (false, Instant::now());
                // And what it kept (the log, a snapshot: every Secret) is erased; one that
                // cannot be is tried again with the next whole view, and when kithd starts.
                if self.kept {
                    let raft = self.state.join("raft");
                    match std::fs::remove_dir_all(&raft) {
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                            return Err(format!("erasing {}: {e}", raft.display()));
                        }
                        _ => eprintln!("kithd: this node runs from a view now: its copy of the store is erased"),
                    }
                    self.kept = false;
                }
            }
            Sent::Changed { at, put, gone } => {
                let nothing = put.is_empty() && gone.is_empty();
                let statuses = {
                    let mut state = shared.store.lock().expect("a handler panicked holding the store");
                    let same = |new: &Resource| {
                        let old = state.store.get(&new.key());
                        old.is_some_and(|old| old.metadata == new.metadata && old.spec == new.spec)
                    };
                    let statuses = gone.is_empty() && put.iter().all(same);
                    put.into_iter().for_each(|resource| state.store.put(resource));
                    for key in &gone {
                        state.store.remove(key);
                    }
                    shared.view.send_replace(Some(at));
                    if !nothing {
                        poke();
                    }
                    statuses
                };
                self.stale |= !nothing;
                // What is gone (a Secret of what left this node) is off the disk at once.
                if self.stale && (!statuses || self.saved.elapsed() >= SAVE_EVERY) {
                    self.save()?;
                }
            }
        }
        Ok(())
    }
}

/// Is this node a worker that is sent the whole store and need not be: its Node says worker,
/// it does not vote, and if it serves ingress its Node says so (its view then holds the
/// certificates)?
fn due(shared: &Shared, me: &str, ingress: bool) -> bool {
    let said = || {
        serves_ingress(
            &shared.store.lock().expect("a handler panicked holding the store").store,
            me,
        )
    };
    crate::access::worker(shared, me) && !crate::cluster::votes(shared, me) && (!ingress || said())
}

/// The workers that are still sent the whole store to serve ingress: they joined with a token
/// from before ingress workers ran from a view, and their Node does not say `ingress`.
fn whole_for_ingress(store: &Store) -> Vec<String> {
    let whole = |node: &&Resource| {
        let status = node.status.as_ref();
        node.spec["trust"] == "worker"
            && node.spec["ingress"] != true
            && status.is_some_and(|status| status["view"] != true && status["serves"]["ingress"] == true)
    };
    let nodes = store.list(Some("Node")).filter(whole);
    nodes.map(|node| node.metadata.name.clone()).collect()
}

/// What to do about such a worker `node`.
fn rejoin(node: &str) -> String {
    format!(
        "worker {node} serves ingress from a copy of the whole store (every Secret): delete node {node} and join it \
         again with a token from `kith node token --worker --ingress` (its view then holds only the certificates), \
         or set `ingress: true` in its Node's spec"
    )
}

/// The control nodes this node knows of, by name.
fn control_nodes(shared: &Shared, me: &str) -> Vec<Upstream> {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let upstream = |node: &Resource| {
        let control = node.spec["trust"] != "worker" && node.metadata.name != me;
        control.then(|| Upstream::of(node)).flatten()
    };
    state.store.list(Some("Node")).filter_map(upstream).collect()
}

const OLDER: &str = "this control node is older than workers: update it";

/// Follow the view `upstream` sends until it ends. `Ok`: something of it was taken.
async fn stream(
    follower: &mut Follower<'_>,
    upstream: &Upstream,
    stopping: &mut watch::Receiver<bool>,
) -> Result<bool, String> {
    let shared = follower.shared;
    let cluster = shared.cluster.as_ref().expect("a worker is in a cluster");
    let failed = |e: reqwest::Error| crate::cluster::why(&e);
    // No other node's certificate is taken at that address: a worker cannot stand in for it.
    let client = cluster.to(upstream)?;
    let asked = client.get(format!("https://{}/v1/view", upstream.address));
    let mut reply = asked.send().await.map_err(failed)?;
    if reply.status() == StatusCode::NOT_FOUND {
        return Err(OLDER.into());
    }
    if !reply.status().is_success() {
        let refusal: serde_json::Value = reply.json().await.unwrap_or_default();
        return Err(refusal["error"]
            .as_str()
            .unwrap_or("it refused without saying why")
            .to_string());
    }
    *shared.upstream.lock().expect("nothing panics holding the upstream") = Some((upstream.address.clone(), client));
    let (mut buffer, mut heard) = (Vec::new(), false);
    loop {
        let chunk = tokio::select! {
            chunk = tokio::time::timeout(SILENT, reply.chunk()) => chunk,
            _ = stopping.changed() => return Ok(heard),
        };
        let ended = |why: String| if heard { Ok(true) } else { Err(why) };
        match chunk {
            Ok(Ok(Some(bytes))) => buffer.extend_from_slice(&bytes),
            Ok(Ok(None)) => return ended("it ended the view".into()),
            Ok(Err(e)) => return ended(e.to_string()),
            Err(_) => return ended("it went silent".into()),
        }
        while let Some(end) = buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = buffer.drain(..=end).collect();
            let sent = serde_json::from_slice(&line).map_err(|e| format!("a line of the view: {e}"))?;
            follower.take(sent).await?;
            heard = true;
        }
    }
}

/// On a node that is no control node: once its Node says worker, follow a control node's
/// view, for as long as kithd runs. A node that was sent the whole store until then lets go
/// of it when the first whole view is on its disk (`Follower::take`).
///
/// A worker still sent the whole store to serve ingress is not let go of it silently: it says
/// so as it starts, and each control node says so of it (once, while it is so).
pub async fn follow(shared: Arc<Shared>, state: PathBuf, ingress: bool, mut stopping: watch::Receiver<bool>) {
    let Some(cluster) = shared.cluster.as_ref() else {
        return;
    };
    let me = cluster.me.name.clone();
    let mut told = Vec::new();
    let first = load(&state).ok().flatten().and_then(|(.., first)| first);
    let mut follower = Follower {
        shared: &shared,
        state: &state,
        first: &first,
        stale: false,
        saved: Instant::now(),
        kept: false,
    };
    let (mut turn, mut said) = (0usize, String::new());
    while !*stopping.borrow() {
        let mut nodes = control_nodes(&shared, &me);
        if nodes.is_empty() {
            nodes.extend(first.clone());
        }
        let viewing = shared.view.borrow().is_some();
        let mut pause = Duration::from_secs(5);
        let whole = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            match crate::access::is_worker(&state.store, &me) {
                // (Who it is sent to: a worker, of itself.)
                true if ingress && !viewing && !serves_ingress(&state.store, &me) => vec![me.clone()],
                true => Vec::new(),
                false => whole_for_ingress(&state.store),
            }
        };
        for node in whole.iter().filter(|node| !told.contains(*node)) {
            eprintln!("kithd: {}", rejoin(node));
        }
        told = whole;
        // (The node that holds the cluster's key is a control node: it follows nobody.)
        if cluster.ca.is_none() && (viewing || due(&shared, &me, ingress)) && !nodes.is_empty() {
            let upstream = &nodes[turn % nodes.len()];
            match stream(&mut follower, upstream, &mut stopping).await {
                // (It was there: called again first, at once.)
                Ok(_) => pause = Duration::from_secs(1),
                Err(why) => {
                    turn += 1;
                    let why = format!("node {} ({}) sends no view: {why}", upstream.name, upstream.address);
                    if why != said {
                        eprintln!("kithd: {why}");
                        said = why;
                    }
                }
            }
            if follower.stale
                && let Err(e) = follower.save()
            {
                eprintln!("kithd: {e}");
            }
        }
        tokio::select! {
            () = tokio::time::sleep(pause) => {}
            _ = stopping.changed() => {}
        }
    }
}

/// How long a worker's write waits for a control node and for its own view to show it.
const PATIENCE: Duration = Duration::from_secs(10);

fn unavailable(why: impl std::fmt::Display) -> Error {
    Error::Io(format!(
        "this node is a worker, and its control node cannot take changes now: {why}"
    ))
}

/// A change this worker makes, through the control node it follows: the reply, and the index
/// of the store it is at, once this node's view has reached it.
pub async fn write(shared: &Shared, command: &Command) -> Result<(Done, u64), Error> {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let upstream = shared
            .upstream
            .lock()
            .expect("nothing panics holding the upstream")
            .clone();
        if let Some((address, client)) = upstream {
            let call = client.post(format!("https://{address}/v1/raft/write"));
            match call.timeout(PATIENCE).json(command).send().await {
                Ok(reply) if reply.status().is_success() => {
                    if let Ok(Some((reply, index))) = reply.json::<Option<(Reply, u64)>>().await {
                        // What this node writes, it reads: as a node waits on its own log.
                        let mut view = shared.view.subscribe();
                        let reached = view.wait_for(|at| at.is_some_and(|at| at >= index));
                        if tokio::time::timeout(PATIENCE, reached).await.is_err() {
                            let why = "the change was taken, and this node's view does not show it yet; look before trying again";
                            return Err(unavailable(why));
                        }
                        return reply.map(|done| (done, index));
                    }
                }
                // This worker wrote more than a worker may for now: sent again once it may.
                Ok(reply) if reply.status() == StatusCode::TOO_MANY_REQUESTS => {
                    let wait = crate::raft::wait_of(&reply);
                    if Instant::now() + wait > deadline {
                        let refusal: serde_json::Value = reply.json().await.unwrap_or_default();
                        return Err(unavailable(refusal["error"].as_str().unwrap_or("it asked to wait")));
                    }
                    tokio::time::sleep(wait).await;
                    continue;
                }
                Ok(reply) => {
                    let refusal: serde_json::Value = reply.json().await.unwrap_or_default();
                    return Err(unavailable(refusal["error"].as_str().unwrap_or("it refused")));
                }
                // Never reached it: nothing happened, and asking again is safe.
                Err(e) if e.is_connect() => {}
                Err(e) => {
                    return Err(unavailable(format!(
                        "{address} did not answer ({e}); look before trying again"
                    )));
                }
            }
        }
        if Instant::now() > deadline {
            return Err(unavailable("none is in reach"));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A control node `a` and a worker `w`. `web` (replica 0 on `w`) names the Secret `mine` in
    /// `env`, the Secret `guarded` (for control nodes) in `envFrom` and the ConfigMap `conf` as
    /// files; `api` (on `a`) names the Secret `other`. A Volume on `w` with a Backup that names
    /// the Secret `bucket`, and a block list that names a ConfigMap.
    const CLUSTER: &str = "\
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: w }
spec: { trust: worker }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: mine }
spec: { data: { password: one } }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: other }
spec: { data: { password: two } }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: guarded }
spec: { trust: control, data: { password: three } }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: bucket }
spec: { data: { accessKey: k, secretKey: s } }
---
apiVersion: kith.dev/v1
kind: ConfigMap
metadata: { name: conf }
spec: { data: { file: text } }
---
apiVersion: kith.dev/v1
kind: ConfigMap
metadata: { name: unnamed }
spec: { data: { file: text } }
---
apiVersion: kith.dev/v1
kind: ConfigMap
metadata: { name: blocked, namespace: kith-system }
spec: { data: { hosts: ads.example } }
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web }
spec:
  template:
    containers:
      - name: run
        image: img
        env: [{ name: PASSWORD, secret: { name: mine, key: password } }]
        envFrom: [{ secret: guarded }]
        volumeMounts: [{ path: /etc/conf, configMap: conf }]
---
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: api }
spec:
  template:
    containers:
      - name: run
        image: img
        env: [{ name: PASSWORD, secret: { name: other, key: password } }]
---
apiVersion: kith.dev/v1
kind: Volume
metadata: { name: here }
spec: { node: w, path: here }
---
apiVersion: kith.dev/v1
kind: Backup
metadata: { name: nightly }
spec: { volume: here, every: 1d, s3: { endpoint: 'https://s3.example', bucket: b, secret: bucket } }
---
apiVersion: kith.dev/v1
kind: DNSBlockList
metadata: { name: ads }
spec: { configMap: { name: blocked, key: hosts } }
---
apiVersion: kith.dev/v1
kind: Identity
metadata: { name: alice }
spec: {}
";

    fn store() -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(CLUSTER).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let key = json!({
            "apiVersion": "kith.dev/v1", "kind": "NodeKey", "metadata": { "name": "PLACE" }, "spec": {},
        });
        for node in ["a", "w"] {
            let key = key.to_string().replace("PLACE", node);
            store.put(serde_json::from_str(&key).unwrap());
        }
        place(&mut store, "web", "w");
        place(&mut store, "api", "a");
        store
    }

    fn place(store: &mut Store, workload: &str, node: &str) {
        let status = json!({ "nodes": { "0": node } });
        let key = format!("Workload/default/{workload}");
        store.set_status(&key, Some(status)).unwrap();
    }

    fn keys(resources: &[Resource]) -> Vec<String> {
        resources.iter().map(Resource::key).collect()
    }

    #[test]
    fn node_reads_a_secret_only_if_something_placed_on_it_names_it() {
        let mut store = store();
        let mut last = None;
        let none = |_: u64| -> Option<BTreeSet<&str>> { unreachable!("nothing was sent yet") };
        let Some(Sent::Whole { at: 7, resources }) = round_of(&store, 7, none, "w", &mut last) else {
            panic!("the first round sends everything");
        };
        let sent = keys(&resources);
        let has = |key: &str| sent.iter().any(|sent| sent == key);
        for key in [
            "Secret/default/mine",
            "Secret/default/bucket",
            "ConfigMap/default/conf",
            "ConfigMap/kith-system/blocked",
            "Backup/default/nightly",
            "NodeKey/w",
            "Node/a",
            "Workload/default/api",
        ] {
            assert!(has(key), "{key} is in the view: {sent:?}");
        }
        // Not what is placed elsewhere, nor a Secret for control nodes whatever names it, nor
        // another node's key, nor who may do what.
        for key in [
            "Secret/default/other",
            "Secret/default/guarded",
            "ConfigMap/default/unnamed",
            "NodeKey/a",
            "Identity/alice",
        ] {
            assert!(!has(key), "{key} is not in the view: {sent:?}");
        }
        // A control node is sent no view by this rule, and a node nothing is placed on gets no Secret.
        let secrets = |node: &str| {
            named(&store, node)
                .into_iter()
                .filter(|key| key.starts_with("Secret/"))
                .count()
        };
        assert_eq!((secrets("w"), secrets("nobody")), (2, 0));

        // The store is where it was: nothing is sent.
        assert_eq!(round_of(&store, 7, |_| Some(BTreeSet::new()), "w", &mut last), None);

        // `web` leaves the worker and `api` comes: one's Secret is taken back, the other's sent.
        // A Secret that changed and that nothing here names is not told of at all.
        place(&mut store, "web", "a");
        place(&mut store, "api", "w");
        let touched = BTreeSet::from(["Workload/default/web", "Workload/default/api", "Secret/default/guarded"]);
        let Some(Sent::Changed { at: 9, put, gone }) = round_of(&store, 9, |_| Some(touched), "w", &mut last) else {
            panic!("a round after the first sends what changed");
        };
        assert_eq!(
            keys(&put),
            ["Secret/default/other", "Workload/default/api", "Workload/default/web"]
        );
        assert_eq!(gone, ["ConfigMap/default/conf", "Secret/default/mine"]);

        // A Secret it is sent is made one for control nodes: it is taken back.
        let mut guarded = store.get("Secret/default/other").unwrap().clone();
        guarded.spec["trust"] = "control".into();
        store.put(guarded);
        let touched = BTreeSet::from(["Secret/default/other"]);
        let Some(Sent::Changed { put, gone, .. }) = round_of(&store, 10, |_| Some(touched), "w", &mut last) else {
            panic!("a round after the first sends what changed");
        };
        assert_eq!(
            (keys(&put), gone),
            (Vec::<String>::new(), vec!["Secret/default/other".to_string()])
        );

        // A kind it is sent whole that is deleted, and one it is not sent that is.
        store.remove("Volume/default/here");
        store.remove("Identity/alice");
        let touched = BTreeSet::from(["Volume/default/here", "Identity/alice"]);
        let Some(Sent::Changed { put, gone, .. }) = round_of(&store, 11, |_| Some(touched), "w", &mut last) else {
            panic!("a round after the first sends what changed");
        };
        // (The Volume's Backup and its Secret go with it: nothing on this node names them now.)
        assert_eq!(keys(&put), Vec::<String>::new());
        assert_eq!(
            gone,
            ["Backup/default/nightly", "Secret/default/bucket", "Volume/default/here"]
        );

        // Further behind than the store remembers: everything again.
        let whole = round_of(&store, 12, |_| None, "w", &mut last);
        assert!(matches!(whole, Some(Sent::Whole { at: 12, .. })));
    }

    /// An ingress worker `i` (its Node says `ingress`, as its join wrote it): the Secret of each
    /// host the cluster exposes, and the thumbprint challenges are answered with. Never the ACME
    /// account key, a host no Service exposes, or a Secret for control nodes.
    #[test]
    fn an_ingress_workers_view_holds_the_certificates_of_exposed_hosts_and_no_account_key() {
        let mut store = store();
        let source = "\
apiVersion: kith.dev/v1
kind: Node
metadata: { name: i }
spec: { trust: worker, ingress: true }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: shop, namespace: shop }
spec: { selector: { app: shop }, ports: [{ port: 80 }], expose: { host: shop.example.test, via: edge } }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: inner }
spec: { selector: { app: inner }, ports: [{ port: 80 }] }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: tls-shop.example.test, namespace: shop }
spec: { data: { tls.crt: c, tls.key: k } }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: tls-gone.example.test, namespace: shop }
spec: { data: { tls.crt: c, tls.key: k } }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: tls-blog.example.test }
spec: { trust: control, data: { tls.crt: c, tls.key: k } }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: tls-api.example.test }
spec: { data: { tls.crt: c, tls.key: k } }
---
apiVersion: kith.dev/v1
kind: Secret
metadata: { name: acme-account, namespace: kith-system }
spec: { data: { key: k } }
---
apiVersion: kith.dev/v1
kind: ConfigMap
metadata: { name: acme, namespace: kith-system }
spec: { data: { thumbprint: t } }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: blog }
spec: { selector: { app: blog }, ports: [{ port: 80 }], expose: { host: blog.example.test, via: edge } }
";
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let secrets = |node: &str| -> Vec<String> {
            let named = named(&store, node).into_iter();
            named.filter(|key| key.starts_with("Secret/")).collect()
        };
        assert_eq!(secrets("i"), ["Secret/shop/tls-shop.example.test"]);
        assert!(named(&store, "i").contains("ConfigMap/kith-system/acme"));
        // A worker that does not serve ingress, and a control node, are sent none of it.
        for node in ["w", "a"] {
            let named = named(&store, node);
            assert!(
                !named.iter().any(|key| key.contains("tls-") || key.contains("acme")),
                "{node}: {named:?}"
            );
        }

        // A Service that comes exposing a host: that host's Secret is sent with it, and the
        // account key never is, whatever changed.
        let mut last = None;
        let none = |_: u64| -> Option<BTreeSet<&str>> { unreachable!("nothing was sent yet") };
        let Some(Sent::Whole { resources, .. }) = round_of(&store, 20, none, "i", &mut last) else {
            panic!("the first round sends everything");
        };
        assert!(!keys(&resources).iter().any(|key| key.ends_with("acme-account")));
        let api = "\
apiVersion: kith.dev/v1
kind: Service
metadata: { name: api }
spec: { selector: { app: api }, ports: [{ port: 80 }], expose: { host: api.example.test, via: edge } }
";
        store
            .apply(Resource::from_source(api).unwrap().remove(0).unwrap())
            .unwrap();
        let touched = BTreeSet::from(["Service/default/api", "Secret/kith-system/acme-account"]);
        let Some(Sent::Changed { put, gone, .. }) = round_of(&store, 21, |_| Some(touched), "i", &mut last) else {
            panic!("a round after the first sends what changed");
        };
        assert_eq!(
            keys(&put),
            ["Secret/default/tls-api.example.test", "Service/default/api"]
        );
        assert!(gone.is_empty(), "{gone:?}");
        // Its Node no longer says ingress: every certificate is taken back.
        let mut node = store.get("Node/i").unwrap().clone();
        node.spec["ingress"] = serde_json::Value::Null;
        store.put(node);
        let touched = BTreeSet::from(["Node/i"]);
        let Some(Sent::Changed { gone, .. }) = round_of(&store, 22, |_| Some(touched), "i", &mut last) else {
            panic!("a round after the first sends what changed");
        };
        assert_eq!(
            gone,
            [
                "ConfigMap/kith-system/acme",
                "Secret/default/tls-api.example.test",
                "Secret/shop/tls-shop.example.test"
            ]
        );

        // It serves ingress again; then what made a host's Secret sent goes, while it still does.
        let mut node = store.get("Node/i").unwrap().clone();
        node.spec["ingress"] = true.into();
        store.put(node);
        let touched = BTreeSet::from(["Node/i"]);
        let Some(Sent::Changed { put, .. }) = round_of(&store, 23, |_| Some(touched), "i", &mut last) else {
            panic!("a round after the first sends what changed");
        };
        assert!(keys(&put).contains(&"Secret/default/tls-api.example.test".to_string()));
        // The Service that exposed the host is deleted: the host's Secret goes with it.
        store.delete("Service/default/api").unwrap();
        let touched = BTreeSet::from(["Service/default/api"]);
        let Some(Sent::Changed { gone, .. }) = round_of(&store, 24, |_| Some(touched), "i", &mut last) else {
            panic!("a round after the first sends what changed");
        };
        assert!(
            gone.contains(&"Secret/default/tls-api.example.test".to_string()),
            "{gone:?}"
        );
        // A host's Secret is made one for control nodes: it goes, though its host is exposed.
        let mut secret = store.get("Secret/shop/tls-shop.example.test").unwrap().clone();
        secret.spec["trust"] = "control".into();
        store.put(secret);
        let touched = BTreeSet::from(["Secret/shop/tls-shop.example.test"]);
        let Some(Sent::Changed { put, gone, .. }) = round_of(&store, 25, |_| Some(touched), "i", &mut last) else {
            panic!("a round after the first sends what changed");
        };
        assert_eq!(gone, ["Secret/shop/tls-shop.example.test"]);
        assert!(put.is_empty(), "{:?}", keys(&put));
    }

    /// Serve `app` on a loopback port with the node certificate of `me`; the port.
    async fn serve_as(me: &pki::Identity, app: axum::Router) -> u16 {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let listener = crate::cluster::listen(tcp, pki::server_config(me).unwrap()).unwrap();
        tokio::spawn(async move { drop(axum::serve(listener, app.into_make_service()).await) });
        port
    }

    #[tokio::test]
    async fn a_worker_follows_the_control_node_it_names_and_no_other() {
        use axum::routing::get;
        let dir = std::env::temp_dir().join(format!("kith-follow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = pki::Ca::create().unwrap();
        let node = |name: &str| {
            let (cert, key) = ca.issue(name).unwrap();
            pki::Identity {
                name: name.into(),
                ca: ca.cert.clone(),
                cert,
                key,
            }
        };
        let (a, w, taken) = (node("a"), node("w"), node("x"));
        let cluster = crate::cluster::Cluster::new(w, None).unwrap();
        let shared = crate::replica(Some(cluster), &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        // Until its first view it keeps what Raft keeps.
        assert!(dir.join("raft").exists() && shared.view.borrow().is_none());
        let whole = Sent::Whole {
            at: 5,
            resources: vec![store().get("Node/a").unwrap().clone()],
        };
        let line = format!("{}\n", serde_json::to_string(&whole).unwrap());
        let view = axum::Router::new().route("/v1/view", get(move || std::future::ready(line.clone())));
        let first = None;
        let mut follower = Follower {
            shared: &shared,
            state: &dir,
            first: &first,
            stale: false,
            saved: Instant::now(),
            kept: false,
        };
        let mut stopping = shared.stop.subscribe();
        let print = pki::print_of(&a.cert).unwrap();
        let at = |port: u16, certificate: &str| Upstream {
            name: "a".into(),
            address: format!("127.0.0.1:{port}"),
            certificate: Some(certificate.into()),
        };

        // Another node of the cluster answers where the control node is called: a worker that
        // is taken, with a certificate of the same CA. Nothing it sends is read.
        let port = serve_as(&taken, view.clone()).await;
        let said = stream(&mut follower, &at(port, &print), &mut stopping).await;
        assert!(said.is_err() && shared.view.borrow().is_none(), "{said:?}");
        // Nor the node of that name with another key than its Node names.
        let port = serve_as(&a, view.clone()).await;
        let other = pki::print_of(&taken.cert).unwrap();
        let said = stream(&mut follower, &at(port, &other), &mut stopping).await;
        assert!(said.is_err() && shared.view.borrow().is_none(), "{said:?}");
        // A control node from before views has no such route: said, and nothing is let go of.
        let older = serve_as(&a, axum::Router::new()).await;
        let said = stream(&mut follower, &at(older, &print), &mut stopping).await;
        assert_eq!(said, Err(OLDER.to_string()));
        assert!(dir.join("raft").exists() && !path(&dir).exists());

        // The control node itself: its view is taken, written down, and the store this node
        // was sent until now is erased.
        let said = stream(&mut follower, &at(port, &print), &mut stopping).await;
        assert_eq!(said, Ok(true));
        assert_eq!(*shared.view.borrow(), Some(5));
        assert!(shared.store.lock().unwrap().store.get("Node/a").is_some());
        assert!(!dir.join("raft").exists());
        let (kept, at, _) = load(&dir).unwrap().unwrap();
        assert!(at == 5 && kept.get("Node/a").is_some());
        // From here on a change is asked of the control node, and Raft's routes are not served.
        let write = shared.write(Command::Patch { statuses: Vec::new() }).await;
        assert!(write.unwrap_err().to_string().contains("this node is a worker"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_view_is_kept_whole_for_kithd_alone_and_read_back() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kith-view-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load(&dir).unwrap().is_none());
        let first = Upstream {
            name: "a".into(),
            address: "10.0.0.1:7443".into(),
            certificate: Some("print".into()),
        };
        begin(&dir, &first).unwrap();
        let (empty, at, through) = load(&dir).unwrap().unwrap();
        assert_eq!((empty, at, through.as_ref()), (Store::default(), 0, Some(&first)));
        let store = store();
        save(&dir, 41, Some(&first), &store).unwrap();
        let (kept, at, _) = load(&dir).unwrap().unwrap();
        assert_eq!(at, 41);
        // As it was sent: each resource with its status, and nothing of its history.
        let web = kept.get("Workload/default/web").unwrap();
        assert_eq!(Some(web), store.get("Workload/default/web"));
        assert_eq!(kept.history("Workload/default/web").unwrap().len(), 1);
        let mode = std::fs::metadata(path(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // A file of a kithd that is newer is not read as if it were this one's.
        std::fs::write(path(&dir), r#"{"format":2,"at":1,"resources":[]}"#).unwrap();
        assert!(load(&dir).unwrap_err().contains("newer kithd"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
