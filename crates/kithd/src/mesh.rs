//! The mesh (`--mesh`): this node's WireGuard interface, kept in step with the cluster's
//! Nodes. The node writes its public key, mesh address and port into its own Node's
//! status (`mesh`); every other Node that has done so is a peer, at the address the
//! cluster reaches it at. A peer that has not answered for three minutes is reached
//! through an edge node, and directly again once it answers. The addresses and the peers
//! are the `kith-mesh` crate's.
//
// ponytail: netlink is asked on the daemon's one thread (a few short system calls every
// ten seconds). An edge node has to be let pass traffic on by whoever runs it
// (net.ipv6.conf.all.forwarding): kithd says so and leaves the host's setting alone.

use crate::Shared;
use crate::root_part::{KeyStep, Told};
use kith_api::store::Store;
use kith_mesh::{Key, Member};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Notify, watch};

/// A peer silent for this long is not reached directly (WireGuard itself gives up on
/// keys this old).
const QUIET: Duration = Duration::from_secs(180);

pub struct Options {
    pub interface: String,
    pub port: u16,
    /// Where this node's private key is kept.
    pub key: PathBuf,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What this node says of itself under `status.mesh`. `kept`: its kithd keeps the connections
/// other nodes pass a Service's on by; `link`: it takes a link to another node's kithd, a
/// stream for each (services.rs). A node of before says neither, and is reached as it was.
fn says_of(public: &[u8], address: Ipv6Addr, port: u16) -> Value {
    let mut says =
        json!({ "key": hex(public), "address": address.to_string(), "port": port, "kept": true, "link": true });
    if crate::services::links_off() {
        says.as_object_mut().expect("an object").remove("link");
    }
    says
}

pub(crate) fn key_of(hex: &str) -> Option<Key> {
    let byte = |at: usize| u8::from_str_radix(hex.get(2 * at..2 * at + 2)?, 16).ok();
    let bytes: Vec<u8> = (0..32).map_while(byte).collect();
    bytes.try_into().ok().filter(|_| hex.len() == 64)
}

/// The cluster's /48, the same on every node of it.
pub fn prefix(ca: &str) -> Ipv6Addr {
    let print = crate::pki::fingerprint(ca);
    kith_mesh::prefix(print.as_deref().unwrap_or(ca).as_bytes())
}

/// The key in `path`.
pub(crate) fn read_key(path: &std::path::Path) -> std::io::Result<Key> {
    let text = std::fs::read_to_string(path)?;
    key_of(text.trim()).ok_or_else(|| std::io::Error::other(format!("{} is not a key", path.display())))
}

/// `key` written to `path`: whole or not at all (half a key file would be no key for good), for
/// its owner alone, and in the directory when this returns (so a power cut keeps it).
pub(crate) fn write_key(path: &std::path::Path, key: &Key) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let new = path.with_extension("new");
    let mut options = std::fs::OpenOptions::new();
    let mut file = options.write(true).create(true).truncate(true).mode(0o600).open(&new)?;
    file.write_all(hex(key).as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&new, path)?;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::File::open(dir)?.sync_all()
}

fn random_key() -> std::io::Result<Key> {
    let mut key = [0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key)
        .map_err(|_| std::io::Error::other("no random numbers"))?;
    Ok(key)
}

/// This node's private key: made the first time, and never anywhere but in its file.
pub(crate) fn private_key(path: &std::path::Path) -> std::io::Result<Key> {
    match read_key(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = random_key()?;
            write_key(path, &key).map(|()| key)
        }
        read => read,
    }
}

/// Where a key that is to replace the one in `key` waits until it does (`mesh.next` beside
/// `mesh.key`).
pub(crate) fn next_path(key: &std::path::Path) -> PathBuf {
    key.with_extension("next")
}

/// A new key, in `path` (one that was there is replaced).
pub(crate) fn make_key(path: &std::path::Path) -> std::io::Result<Key> {
    let key = random_key()?;
    write_key(path, &key).map(|()| key)
}

/// For a node about to join as one that roams: its interface, up before it is a member, and
/// the public key the cluster is to know it by (hex). The cluster's addresses come from its
/// CA, which the join `token` names.
pub fn key_before_joining(options: &Options, token: &str, name: &str) -> Result<String, String> {
    let (_, pinned, _) = crate::pki::token_parts(token)?;
    let prefix = kith_mesh::prefix(pinned.as_bytes());
    let address = kith_mesh::node_address(prefix, name);
    let up = told_root(options, name, prefix)
        .and_then(|()| crate::root_part::mesh_key(&crate::root_part::Direct::new(), &options.interface, address));
    let hint = "--roaming takes the mesh: the kernel's WireGuard and CAP_NET_ADMIN";
    up.map(|key| hex(&key)).map_err(|e| format!("no mesh: {e} ({hint})"))
}

/// The root part told what the node was started with: the interface, its port and key file, the
/// node's name, and the cluster's range.
fn told_root(options: &Options, name: &str, prefix: Ipv6Addr) -> Result<(), String> {
    crate::root_part::set_mesh(
        options.interface.clone(),
        options.port,
        options.key.clone(),
        name.to_string(),
    )?;
    crate::root_part::set_prefix(prefix)
}

/// Where the peers a roaming node was told of as it joined are kept: who to call before
/// the store (which comes over the mesh) has arrived.
pub fn first_peers(key: &std::path::Path) -> PathBuf {
    key.with_file_name("mesh-peers.json")
}

fn told(path: &std::path::Path) -> Vec<Member> {
    let read = std::fs::read(path)
        .ok()
        .and_then(|text| serde_json::from_slice::<Vec<Value>>(&text).ok());
    let member = |peer: Value| {
        Some(Member {
            name: peer["name"].as_str()?.to_string(),
            key: key_of(peer["key"].as_str()?)?,
            endpoint: peer["endpoint"].as_str()?.parse().ok(),
            edge: false,
            reached: true,
            direct_only: false,
            reaches: Vec::new(),
            seen: None,
        })
    };
    read.unwrap_or_default().into_iter().filter_map(member).collect()
}

/// Did this peer agree on keys with the interface lately?
fn shook_lately(shook: &BTreeMap<Key, Option<Duration>>, key: &Key) -> bool {
    shook.get(key).copied().flatten().is_some_and(|ago| ago < QUIET)
}

/// The names of the members this node shook hands with lately, in order: what it tells the
/// others it reaches (they pick the relay by it).
fn reaching(members: &[Member], shook: &BTreeMap<Key, Option<Duration>>) -> Vec<String> {
    let mut names: Vec<String> = members
        .iter()
        .filter(|member| shook_lately(shook, &member.key))
        .map(|member| member.name.clone())
        .collect();
    names.sort();
    names
}

/// Where this node saw each member it shook hands with lately, by name: what an edge node
/// tells the others, so two nodes behind NAT can call each other there (kith_mesh::wanted).
fn seeing(members: &[Member], shook: &BTreeMap<Key, Option<Duration>>, at: &BTreeMap<Key, SocketAddr>) -> Value {
    let seen = members.iter().filter(|member| shook_lately(shook, &member.key));
    let seen = seen.filter_map(|member| Some((member.name.clone(), json!(at.get(&member.key)?.to_string()))));
    Value::Object(seen.collect())
}

/// The other nodes as the mesh sees them. `shook` has, for the interface's peers, how
/// long ago each last agreed on keys; `known` remembers since when each has been a peer
/// (one that is new has its three minutes to answer).
fn members(
    store: &Store,
    shook: &BTreeMap<Key, Option<Duration>>,
    known: &mut BTreeMap<Key, Instant>,
    now: Instant,
) -> Vec<Member> {
    let edge = |node: &kith_api::Resource| {
        node.spec["roles"]
            .as_array()
            .is_some_and(|roles| roles.contains(&"edge".into()))
    };
    // Where each node was seen: by the first edge node, by name, that says so. (Only an edge
    // node's word is taken: the cluster's admin made it one.)
    let mut seen: BTreeMap<String, SocketAddr> = BTreeMap::new();
    for node in store.list(Some("Node")).filter(|node| edge(node)) {
        let said = node
            .status
            .as_ref()
            .and_then(|status| status["mesh"]["seen"].as_object());
        for (name, at) in said.into_iter().flatten() {
            if let Some(at) = at.as_str().and_then(|at| at.parse().ok()) {
                seen.entry(name.clone()).or_insert(at);
            }
        }
    }
    let member = |node: &kith_api::Resource| {
        let status = node.status.as_ref()?;
        // (A key of zeros or a port that is none would be refused by the kernel.)
        let key = key_of(status["mesh"]["key"].as_str()?).filter(|key| *key != [0; 32])?;
        let port = u16::try_from(status["mesh"]["port"].as_u64()?)
            .ok()
            .filter(|port| *port != 0)?;
        let at = status["address"].as_str().and_then(|at| at.parse::<SocketAddr>().ok());
        let since = *known.entry(key).or_insert(now);
        let fresh = shook_lately(shook, &key);
        let reaches = status["mesh"]["reaches"].as_array();
        Some(Member {
            name: node.metadata.name.clone(),
            key,
            // A node that roams is wherever it last called from: the interface keeps that
            // address by itself, and an address from the store would put it back where it was.
            endpoint: at
                .filter(|_| node.spec["roaming"] != true)
                .map(|at| SocketAddr::new(at.ip(), port)),
            edge: edge(node),
            reached: fresh || now.saturating_duration_since(since) < QUIET,
            direct_only: node.spec["mesh"]["relay"] == "never",
            reaches: reaches
                .into_iter()
                .flatten()
                .filter_map(|name| name.as_str().map(str::to_string))
                .collect(),
            seen: seen.get(&node.metadata.name).copied(),
        })
    };
    let mut members: Vec<Member> = store.list(Some("Node")).filter_map(member).collect();
    // One key is one node: of the nodes that say the same key, the first by name is the node and
    // the later ones are left out, so every node agrees on one peer for the key. (A copier named
    // before the real node still takes the key from it, as both were left out before: it cannot
    // read what is sent to the key, and a node writes only its own status, T-0649.)
    members.sort_by(|a, b| a.name.cmp(&b.name));
    let mut seen = BTreeSet::new();
    members.retain(|member| seen.insert(member.key));
    known.retain(|key, _| members.iter().any(|member| member.key == *key));
    members
}

/// Who `me` is to call at the Cluster's house endpoint (`spec.home.endpoint`, as written: a name
/// or an address with a port, the router's forward to the house address): the holder
/// (`status.home.holder`), and only when `me` roams, is not the holder, and has not shaken hands
/// with it for `QUIET` (a healthy tunnel does about every two minutes). Every other peer, and the
/// holder once it answers, stays where it was last called from.
fn home_endpoint(
    store: &Store,
    me: &str,
    members: &[Member],
    shook: &BTreeMap<Key, Option<Duration>>,
) -> Option<(String, String)> {
    let roaming = store
        .get(&format!("Node/{me}"))
        .is_some_and(|node| node.spec["roaming"] == true);
    // The Cluster whose house address every node takes (`home::configured_in`), not the first listed.
    let (key, _) = crate::home::configured_in(store)?;
    let cluster = store.get(&key)?;
    let holder = cluster.status.as_ref()?["home"]["holder"].as_str()?;
    let endpoint = cluster.spec["home"]["endpoint"].as_str()?.to_string();
    let holder = members.iter().find(|member| member.name == holder)?;
    (roaming && holder.name != me && !shook_lately(shook, &holder.key)).then(|| (holder.name.clone(), endpoint))
}

/// What the house endpoint resolved to the last time it was looked up (`found`: not yet looked up,
/// or the lookup's answer), when, how many lookups this endpoint has had, and whether one runs.
#[derive(Default)]
struct Lookup {
    endpoint: String,
    found: Option<Option<SocketAddr>>,
    tried: Option<Instant>,
    lookups: u32,
    running: bool,
}

/// The address of the house endpoint, from the last lookup, never waiting for one: a lookup (a
/// name may take seconds) runs in its own task when none is cached or the cached one is old (a
/// minute when it resolved, half of that when it did not), and wakes the loop when its answer
/// differs. The old answer is kept meanwhile. It logs when the outcome changes, not every try.
fn resolving(cache: &Arc<std::sync::Mutex<Lookup>>, endpoint: &str, wake: &Arc<Notify>) -> Option<SocketAddr> {
    let mut now = cache.lock().expect("nothing panics holding the lookup");
    if now.endpoint != endpoint {
        *now = Lookup {
            endpoint: endpoint.to_string(),
            ..Lookup::default()
        };
    }
    let after = Duration::from_secs(if now.found.flatten().is_some() { 60 } else { 30 });
    if !now.running && now.tried.is_none_or(|tried| tried.elapsed() >= after) {
        (now.running, now.tried, now.lookups) = (true, Some(Instant::now()), now.lookups + 1);
        let (cache, wake, endpoint) = (cache.clone(), wake.clone(), endpoint.to_string());
        tokio::spawn(async move {
            let found = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(&endpoint)).await;
            let at = found.ok().and_then(Result::ok).and_then(|mut found| found.next());
            let mut now = cache.lock().expect("nothing panics holding the lookup");
            now.running = false;
            if now.endpoint != endpoint || now.found == Some(at) {
                return;
            }
            now.found = Some(at);
            let shown: String = endpoint.chars().filter(|c| !c.is_control()).collect();
            match at {
                Some(at) => eprintln!("kithd: mesh: the house endpoint {shown} is {at}"),
                None => eprintln!("kithd: mesh: the house endpoint {shown} did not resolve"),
            }
            wake.notify_one();
        });
    }
    now.found.flatten()
}

/// A name for a rotation that is one: some text, not long, with nothing in it a log line would break on.
fn rotate_name(id: &str) -> bool {
    (1..=64).contains(&id.chars().count()) && !id.chars().any(char::is_control)
}

/// How long each of a key's two waits lasts (for the peers to take the new key, then for them to
/// shake hands on it) before the node goes back to the old key it never left the file of.
const ROTATE_WAIT: Duration = Duration::from_secs(120);

/// A rotation of this node's key under way (T-1017), as this node holds it. In memory only: a
/// node that stops in the middle has `mesh.key` still the old key and starts on it, and what it
/// says first leaves out the `next` it said.
struct Rotation {
    /// What `spec.mesh.rotate` said: made once for each name.
    id: String,
    next: Key,
    /// The peers (by name) that were reached when it began, and have to agree on the new key.
    need: Vec<String>,
    /// When the peers were asked to take the key, then when the interface was switched to it.
    since: Instant,
    switched: Option<Instant>,
}

/// What a rotation does next.
#[derive(Debug, PartialEq, Eq)]
enum Turn {
    Wait,
    /// Every peer has taken the key: the interface runs on it.
    Switch,
    /// Every peer has shaken hands on the new key: the file is the new key.
    Commit,
    /// Given up, and why: the old key is the node's still.
    Revert(&'static str),
}

/// Where a rotation stands, from what the peers say. `took`: who has taken the new key; `shook`:
/// how long ago each peer last shook hands (by name). One handshake since the switch is the
/// proof that the peer holds the new key: it is only the new key that could have made it.
fn turn(rotation: &Rotation, took: &BTreeSet<String>, shook: &BTreeMap<String, Duration>, now: Instant) -> Turn {
    let waited = |since: Instant| now.saturating_duration_since(since) >= ROTATE_WAIT;
    match rotation.switched {
        None if rotation.need.iter().all(|name| took.contains(name)) => Turn::Switch,
        None if waited(rotation.since) => Turn::Revert("the peers did not take the new key"),
        None => Turn::Wait,
        Some(at) => {
            // (A handshake is dated to the second, rounded down: it reads older than it was, never newer.)
            let since = now.saturating_duration_since(at);
            let after = |name: &String| shook.get(name).is_some_and(|ago| *ago < since);
            if rotation.need.iter().all(after) {
                Turn::Commit
            } else if waited(at) {
                Turn::Revert("no handshake on the new key")
            } else {
                Turn::Wait
            }
        }
    }
}

/// The keys other nodes say they are to take next (`status.mesh.next`), by node name. One is
/// taken only if it is a key, is no node's key (this node's `own` included) and is said by one
/// node alone: a node that says another's cannot make this node call that one by another key.
fn nexts(store: &Store, me: &str, own: &Key) -> BTreeMap<String, Key> {
    let say = |node: &kith_api::Resource, field: &str| {
        let status = node.status.as_ref()?;
        key_of(status["mesh"][field].as_str()?).filter(|key| *key != [0; 32])
    };
    let mut keys: BTreeSet<Key> = store.list(Some("Node")).filter_map(|node| say(node, "key")).collect();
    keys.insert(*own);
    let said: Vec<(String, Key)> = store
        .list(Some("Node"))
        .filter(|node| node.metadata.name != me)
        .filter_map(|node| Some((node.metadata.name.clone(), say(node, "next")?)))
        .collect();
    let alone = |key: &Key| said.iter().filter(|(_, other)| other == key).count() == 1;
    said.iter()
        .filter(|(_, key)| !keys.contains(key) && alone(key))
        .cloned()
        .collect()
}

/// The peers with the keys they are to take: each member that has a `next` has it as a peer
/// too, which answers its handshakes and has no addresses (so what it sends is not taken as
/// anyone's) until it has shaken hands: then it is the member's peer, and the old key is not.
fn standby(
    peers: &mut Vec<kith_mesh::Peer>,
    members: &[Member],
    nexts: &BTreeMap<String, Key>,
    shook: &BTreeMap<Key, Option<Duration>>,
) {
    for member in members {
        let Some(next) = nexts.get(&member.name) else { continue };
        let Some(old) = peers.iter_mut().find(|peer| peer.key == member.key) else {
            continue;
        };
        let mut new = kith_mesh::Peer {
            key: *next,
            endpoint: None,
            allowed: Vec::new(),
            keepalive: 0,
        };
        if shook_lately(shook, next) {
            new.endpoint = old.endpoint;
            new.allowed = std::mem::take(&mut old.allowed);
            new.keepalive = std::mem::replace(&mut old.keepalive, 0);
        }
        peers.push(new);
    }
}

/// Set `field` in the status of Node `node`: what this node says of itself under it, or null to take it back.
pub(crate) async fn say(shared: &Shared, node: &str, field: &str, value: Value) -> Result<(), String> {
    let fields = serde_json::Map::from_iter([(field.to_string(), value)]);
    let statuses = vec![(node.to_string(), fields)];
    let patch = shared.submit(kith_store::Command::Patch { statuses }).await;
    patch.map(drop).map_err(|e| e.to_string())
}

/// Keep the interface as the Nodes say, until stopped; then take it away.
pub async fn run(shared: Arc<Shared>, options: Options, mut stopping: watch::Receiver<bool>) {
    let Some(cluster) = &shared.cluster else {
        return eprintln!("kithd: --mesh is for a node of a cluster (--listen or --join): no mesh");
    };
    let me = cluster.me.name.as_str();
    let prefix = prefix(&cluster.me.ca);
    let address = kith_mesh::node_address(prefix, me);
    let root = crate::root_part::Direct::new();
    let up =
        told_root(&options, me, prefix).and_then(|()| crate::root_part::mesh_key(&root, &options.interface, address));
    let mut public = match up {
        Ok(public) => public,
        Err(e) => {
            let hint = "it takes the kernel's WireGuard and the right to set up interfaces, CAP_NET_ADMIN";
            return eprintln!("kithd: no mesh: {e} ({hint})");
        }
    };
    // What the root part was last asked for the interface: not asked again while it is the same.
    let mut asked = None;
    eprintln!("kithd: mesh address {address} on {}", options.interface);
    let mut base = says_of(&public, address, options.port);
    // A key's replacement under way, the rotation that was last given up, and the last one that was done.
    let (mut rotation, mut failed, mut done): (Option<Rotation>, Option<String>, Option<String>) = (None, None, None);
    let node = format!("Node/{me}");
    let first = told(&first_peers(&options.key));
    let mut known = BTreeMap::new();
    let mut generation = shared.generation.subscribe();
    let mut warned = false;
    let (lookup, wake) = (
        Arc::new(std::sync::Mutex::new(Lookup::default())),
        Arc::new(Notify::new()),
    );
    loop {
        // (Before the interface is asked: a handshake read after it is not newer than this.)
        let now = Instant::now();
        let peers = crate::root_part::mesh_seen(&root, &options.interface).unwrap_or_else(|e| {
            eprintln!("kithd: mesh: reading the peers of {}: {e}", options.interface);
            Vec::new()
        });
        let shook: BTreeMap<Key, Option<Duration>> = peers.iter().map(|peer| (peer.key, peer.handshake)).collect();
        let at: BTreeMap<Key, SocketAddr> = peers
            .iter()
            .filter_map(|peer| Some((peer.key, peer.endpoint?)))
            .collect();
        let (mut members, mine, said, edge, services, home, turns) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let own = state.store.get(&node);
            let mut members = members(&state.store, &shook, &mut known, Instant::now());
            // The key replacement: what this node's spec asks, what it has done, the keys the others are to
            // take, and who has taken this node's.
            let spec = own.and_then(|own| own.spec["mesh"]["rotate"].as_str());
            let spec = spec.filter(|id| rotate_name(id)).map(str::to_string);
            let rotated = done
                .clone()
                .or_else(|| own?.status.as_ref()?["mesh"]["rotated"].as_str().map(str::to_string));
            let nexts = nexts(&state.store, me, &public);
            let took: BTreeSet<String> = match &rotation {
                None => BTreeSet::new(),
                Some(rotation) => {
                    let next = hex(&rotation.next);
                    let takes = |node: &kith_api::Resource| {
                        let said = node.status.as_ref()?["mesh"]["takes"].as_array()?.clone();
                        said.contains(&next.clone().into()).then(|| node.metadata.name.clone())
                    };
                    state.store.list(Some("Node")).filter_map(takes).collect()
                }
            };
            // (Until the store says who the nodes are: those this node was told of as it joined.)
            // Once it does, they are forgotten: a node that has left since is not called for ever.
            let nobody = members.iter().all(|member| member.name == me);
            let more: Vec<Member> = first.iter().filter(|peer| nobody && peer.name != me).cloned().collect();
            members.extend(more);
            let edge = members.iter().any(|member| member.name == me && member.edge);
            // What this node says of itself (written only when it changed). An edge node
            // says who it reaches too, and where it saw them: it is asked when a relay is
            // picked and where to call a node behind NAT, the others are not.
            let mut mine = base.clone();
            if edge {
                mine["reaches"] = json!(reaching(&members, &shook));
                mine["seen"] = seeing(&members, &shook, &at);
            }
            // (`takes`: the keys it has as peers, as far as the interface was last asked.)
            let held = |key: &Key| {
                asked
                    .as_ref()
                    .is_some_and(|(peers, _): &Told| peers.iter().any(|p| p.key == *key))
            };
            let takes: Vec<String> = nexts.values().filter(|key| held(key)).map(|key| hex(key)).collect();
            if !takes.is_empty() {
                mine["takes"] = json!(takes);
            }
            if let Some(rotation) = &rotation {
                mine["next"] = json!(hex(&rotation.next));
            }
            if let Some(id) = &rotated {
                mine["rotated"] = json!(id);
            }
            if let Some(id) = &failed {
                mine["failed"] = json!(id);
            }
            let said = own.is_none_or(|own| own.status.as_ref().is_some_and(|status| status["mesh"] == mine));
            let services = crate::services::addresses(&state.store, prefix);
            let home = home_endpoint(&state.store, me, &members, &shook);
            let turns = (spec.filter(|id| rotated.as_ref() != Some(id)), took, nexts);
            (members, mine, said, edge, services.into_values().collect(), home, turns)
        };
        let (asking, took, nexts) = turns;
        // The key replacement goes a step on (the next pass, at once, says it).
        let waiting = !nexts.is_empty();
        let shook_by_name: BTreeMap<String, Duration> = members
            .iter()
            .filter(|member| member.name != me)
            .filter_map(|member| Some((member.name.clone(), shook.get(&member.key).copied().flatten()?)))
            .collect();
        let step = |step| crate::root_part::mesh_key_step(&root, &options.interface, step);
        let mut moved = true;
        match rotation.take() {
            None => match asking.filter(|id| failed.as_ref() != Some(id)) {
                // (One node at a time: two that switch together have no key to call each other by.)
                Some(_) if waiting => moved = false,
                Some(id) => {
                    let need: Vec<String> = members
                        .iter()
                        .filter(|member| member.name != me && shook_lately(&shook, &member.key))
                        .map(|member| member.name.clone())
                        .collect();
                    match (need.is_empty(), step(KeyStep::Make)) {
                        (false, Ok(Some(next))) => {
                            eprintln!(
                                "kithd: mesh: replacing this node's key ({id}): asking {} peers to take the new one",
                                need.len()
                            );
                            rotation = Some(Rotation {
                                id,
                                next,
                                need,
                                since: now,
                                switched: None,
                            });
                        }
                        (true, made) => {
                            if made.is_ok() {
                                let _ = step(KeyStep::Revert);
                            }
                            eprintln!(
                                "kithd: mesh: not replacing the key ({id}): no peer is reached to take the new one"
                            );
                            failed = Some(id);
                        }
                        (false, made) => {
                            let why = made.err().unwrap_or_default();
                            eprintln!("kithd: mesh: not replacing the key ({id}): {why}");
                            failed = Some(id);
                        }
                    }
                }
                None => moved = false,
            },
            Some(mut active) => {
                // Ok: whether it is done. Err: given up, and why.
                let went: Result<bool, String> = match turn(&active, &took, &shook_by_name, now) {
                    Turn::Wait => {
                        moved = false;
                        Ok(false)
                    }
                    Turn::Switch => match step(KeyStep::Use) {
                        Ok(Some(key)) if key == active.next => {
                            active.switched = Some(Instant::now());
                            Ok(false)
                        }
                        Ok(_) => Err("the interface did not answer with the new key".to_string()),
                        Err(e) => Err(e),
                    },
                    Turn::Commit => step(KeyStep::Commit).map(|_| true),
                    Turn::Revert(why) => Err(why.to_string()),
                };
                match went {
                    Ok(true) => {
                        eprintln!("kithd: mesh: this node's key is replaced ({})", active.id);
                        public = active.next;
                        base = says_of(&public, address, options.port);
                        done = Some(active.id);
                        failed = None;
                    }
                    Ok(false) => rotation = Some(active),
                    // (The old key back first: only once it is, the others are told to forget the new one.)
                    Err(why) => match step(KeyStep::Revert) {
                        Ok(_) => {
                            eprintln!(
                                "kithd: mesh: the key replacement {} is given up ({why}): this node keeps its old key",
                                active.id
                            );
                            failed = Some(active.id);
                        }
                        Err(e) => {
                            eprintln!("kithd: mesh: going back to the old key: {e}");
                            rotation = Some(active);
                            moved = false;
                        }
                    },
                }
            }
        }
        if moved {
            wake.notify_one();
        }
        // (Resolved beside the loop, not here: the endpoint may be a name. Until it is, the holder is called where it was.)
        if let Some((holder, endpoint)) = home
            && let Some(at) = resolving(&lookup, &endpoint, &wake)
            && let Some(member) = members.iter_mut().find(|member| member.name == holder)
        {
            member.endpoint = Some(at);
        }
        // (Its own Node may not be there yet, right after joining: next time round.)
        if !said && let Err(e) = say(&shared, &node, "mesh", mine).await {
            eprintln!("kithd: mesh: telling the cluster this node's key: {e}");
        }
        let forwards = || std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding");
        if edge && !warned && forwards().is_ok_and(|on| on.trim() == "0") {
            warned = true;
            eprintln!(
                "kithd: this node is an edge node, and the machine does not pass traffic on: \
                 set net.ipv6.conf.all.forwarding=1 for nodes to reach each other through it"
            );
        }
        let mut peers = kith_mesh::wanted(prefix, me, &members);
        standby(&mut peers, &members, &nexts, &shook);
        // Every node has every Service's address (crate::services listens on them).
        match crate::root_part::mesh(&root, &mut asked, &options.interface, peers.clone(), services) {
            // (A new key taken is said at once: the node that asked is waiting for it.)
            Ok(true) if !nexts.is_empty() => wake.notify_one(),
            Ok(_) => {}
            Err(e) => eprintln!("kithd: mesh: setting {}: {e}", options.interface),
        }
        // For `kith node status`.
        let path = |member: &Member| {
            let peer = peers.iter().find(|peer| peer.key == member.key)?;
            Some(json!({
                "node": member.name,
                "address": kith_mesh::node_address(prefix, &member.name).to_string(),
                "handshake": shook.get(&member.key).copied().flatten().map(|ago| ago.as_secs()),
                "relayed": peer.allowed.is_empty(),
                "reached": member.reached,
            }))
        };
        let paths: Vec<Value> = members.iter().filter_map(path).collect();
        *shared.mesh.lock().expect("nothing panics holding the mesh") = paths.into();
        tokio::select! {
            _ = generation.changed() => {}
            () = wake.notified() => {}
            () = tokio::time::sleep(Duration::from_secs(10)) => {}
            _ = stopping.changed() => break,
        }
    }
    // (What this node said of itself stays: it is back with the same key when kithd
    // starts again, and the others need not forget it for a restart. See `left`.)
    if let Err(e) = crate::root_part::mesh_down(&root, &options.interface) {
        eprintln!("kithd: mesh: removing {}: {e}", options.interface);
    }
}

/// A node started without the mesh (or without the people's device) that still says it is on
/// it has left: take back what it said under `field`, so the others stop calling it.
pub async fn left(shared: Arc<Shared>, field: &str, mut stopping: watch::Receiver<bool>) {
    let Some(cluster) = &shared.cluster else { return };
    let node = format!("Node/{}", cluster.me.name);
    loop {
        // (Not known until the store has this node: asked again until it does.)
        let says = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let own = state.store.get(&node).map(|own| own.status.as_ref());
            own.map(|status| status.is_some_and(|status| !status[field].is_null()))
        };
        match says {
            Some(false) => return,
            Some(true) => match say(&shared, &node, field, Value::Null).await {
                Ok(()) => return,
                Err(e) => eprintln!("kithd: mesh: taking back this node's mesh status: {e}"),
            },
            None => {}
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(10)) => {}
            _ = stopping.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `store` with what `node` says replaced.
    fn store_with_node(store: &Store, node: &str, status: Value) -> Store {
        let mut store = store.clone();
        store.set_status(node, Some(status)).unwrap();
        store
    }

    /// `store` with what Node c says replaced.
    fn store_with(store: &Store, status: Value) -> Store {
        store_with_node(store, "Node/c", status)
    }

    /// A node says it keeps connections and takes links, which is what the other nodes' kithds read
    /// before they open a stream on a link ([`crate::services`]) or keep a connection.
    #[test]
    fn a_node_says_it_takes_links_beside_keeping_connections() {
        let says = says_of(&[7; 32], Ipv6Addr::LOCALHOST, 4000);
        assert_eq!(
            (&says["kept"], &says["link"], &says["port"]),
            (&json!(true), &json!(true), &json!(4000))
        );
        assert_eq!(says["key"], "07".repeat(32));
    }

    #[test]
    fn members_come_from_the_nodes() {
        let mut store = Store::default();
        let node = |name: &str, roles: &str| {
            format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{ name: {name} }}\nspec: {{ roles: [{roles}] }}\n")
        };
        for (name, roles) in [("a", "worker"), ("b", "edge"), ("c", "")] {
            let resource = kith_api::Resource::from_source(&node(name, roles)).unwrap().remove(0);
            store.apply(resource.unwrap()).unwrap();
        }
        let key = |byte: u8| hex(&[byte; 32]);
        let mesh = |byte: u8| json!({ "key": key(byte), "port": 51820, "address": "fd00::1" });
        let said = [
            ("Node/a", json!({ "address": "10.0.0.1:7443", "mesh": mesh(1) })),
            ("Node/b", json!({ "address": "[2001:db8::2]:7443", "mesh": mesh(2) })),
            // c has no mesh (yet): not a member.
            ("Node/c", json!({ "address": "10.0.0.3:7443" })),
        ];
        for (node, status) in said {
            store.set_status(node, Some(status)).unwrap();
        }

        let start = Instant::now();
        let mut known = BTreeMap::new();
        let none = BTreeMap::new();
        let got = members(&store, &none, &mut known, start);
        let names: Vec<&str> = got.iter().map(|member| member.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        assert_eq!(got[0].endpoint, Some("10.0.0.1:51820".parse().unwrap()));
        assert_eq!(got[1].endpoint, Some("[2001:db8::2]:51820".parse().unwrap()));
        assert_eq!((got[0].edge, got[1].edge, got[0].key), (false, true, [1; 32]));
        // What a node says it reaches is its `reaches`; what this node says is the ones it shook hands with.
        assert!(got.iter().all(|member| member.reaches.is_empty()));
        let said = json!({ "address": "10.0.0.2:7443", "mesh": { "key": key(2), "port": 51820, "reaches": ["a", 3] } });
        let with = store_with_node(&store, "Node/b", said);
        assert_eq!(members(&with, &none, &mut BTreeMap::new(), start)[1].reaches, ["a"]);
        let heard = BTreeMap::from([([1; 32], Some(Duration::from_secs(20))), ([2; 32], Some(QUIET))]);
        assert_eq!(reaching(&got, &heard), ["a"]);
        // New peers have three minutes to answer; after that only one that shook hands
        // lately counts as reached.
        assert!(got.iter().all(|member| member.reached));
        let later = start + QUIET;
        let shook = BTreeMap::from([([1; 32], Some(Duration::from_secs(20))), ([2; 32], None)]);
        let got = members(&store, &shook, &mut known, later);
        assert_eq!((got[0].reached, got[1].reached), (true, false));
        let stale = BTreeMap::from([([1; 32], Some(QUIET))]);
        assert!(!members(&store, &stale, &mut known, later)[0].reached);
        // Where a node was seen is what an edge node says, and only an edge node: b's word on a
        // is taken; a's on b (a is no edge node) is not, nor an address that is none.
        let saw = |byte, seen: Value| json!({ "address": "10.0.0.1:7443", "mesh": { "key": key(byte), "port": 51820, "seen": seen } });
        let with = store_with_node(
            &store,
            "Node/b",
            saw(2, json!({ "a": "203.0.113.2:40001", "x": "nowhere" })),
        );
        let with = store_with_node(&with, "Node/a", saw(1, json!({ "b": "203.0.113.9:1" })));
        let got = members(&with, &none, &mut BTreeMap::new(), start);
        assert_eq!(got[0].seen, Some("203.0.113.2:40001".parse().unwrap()));
        assert_eq!(got[1].seen, None);
        // What an edge node says it saw: each member it shook hands with lately, where from.
        let at = BTreeMap::from([
            ([1; 32], "203.0.113.2:40001".parse().unwrap()),
            ([2; 32], "203.0.113.3:1".parse().unwrap()),
        ]);
        assert_eq!(seeing(&got, &heard, &at), json!({ "a": "203.0.113.2:40001" }));
        // A port that is none or a key of zeros: no member (a key two nodes say: the next test).
        let c = |mesh: Value| store_with(&store, json!({ "address": "10.0.0.3:7443", "mesh": mesh }));
        let named = |store: &Store| {
            let got = members(store, &none, &mut BTreeMap::new(), later);
            got.into_iter().map(|member| member.name).collect::<Vec<_>>()
        };
        assert_eq!(named(&c(mesh(3))), ["a", "b", "c"]);
        assert_eq!(named(&c(json!({ "key": key(3), "port": 65536 }))), ["a", "b"]);
        assert_eq!(named(&c(json!({ "key": key(3), "port": 0 }))), ["a", "b"]);
        assert_eq!(named(&c(mesh(0))), ["a", "b"]);
        // A node that left the mesh has its `mesh` cleared (null): no member.
        assert_eq!(named(&c(Value::Null)), ["a", "b"]);
        // c says a's key: c is the later name, so c is left out and a stays.
        assert_eq!(named(&c(mesh(1))), ["a", "b"]);
        // A key that is no key is no member, and a node that is gone is forgotten.
        assert_eq!(key_of("zz"), None);
        assert_eq!(key_of(&key(7)), Some([7; 32]));
        store.delete("Node/b").unwrap();
        members(&store, &none, &mut known, later);
        assert_eq!(known.len(), 1);
    }

    /// A roaming node unheard by the house's holder for as long as a peer is called silent (QUIET)
    /// calls it at the house endpoint, and no one else: not a node that stays put, not a holder
    /// heard lately, not another peer.
    #[test]
    fn home_endpoint_goes_to_the_holder_of_a_roaming_node_unheard_for_quiet() {
        let mut store = Store::default();
        let source = |kind: &str, name: &str, spec: &str| {
            format!("apiVersion: kith.dev/v1\nkind: {kind}\nmetadata: {{ name: {name} }}\nspec: {spec}\n")
        };
        let sources = [
            source("Node", "a", "{ roaming: true }"),
            source("Node", "b", "{}"),
            source("Node", "c", "{}"),
            source(
                "Cluster",
                "house",
                "{ home: { address: 10.9.0.100/24, endpoint: \"203.0.113.7:51820\" } }",
            ),
        ];
        for text in sources {
            store
                .apply(kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap())
                .unwrap();
        }
        for (byte, name) in [(1, "a"), (2, "b"), (3, "c")] {
            let mesh = json!({ "key": hex(&[byte; 32]), "port": 51820 });
            store
                .set_status(
                    &format!("Node/{name}"),
                    Some(json!({ "address": "10.0.0.1:7443", "mesh": mesh })),
                )
                .unwrap();
        }
        let holds = |store: &Store, holder: &str| {
            let mut store = store.clone();
            store
                .set_status(
                    "Cluster/house",
                    Some(json!({ "home": { "holder": holder, "since": "2026-01-01T00:00:00Z" } })),
                )
                .unwrap();
            store
        };
        let start = Instant::now();
        let got = |store: &Store, me: &str, shook: &BTreeMap<Key, Option<Duration>>| {
            let members = members(store, shook, &mut BTreeMap::new(), start);
            home_endpoint(store, me, &members, shook)
        };
        let none = BTreeMap::new();
        let at = Some(("b".to_string(), "203.0.113.7:51820".to_string()));
        // No one holds it yet: nothing to call.
        assert_eq!(got(&store, "a", &none), None);
        let store = holds(&store, "b");
        // Never heard, or not for as long as a silent peer is (QUIET): call the holder at the house endpoint.
        assert_eq!(got(&store, "a", &none), at);
        assert_eq!(got(&store, "a", &BTreeMap::from([([2; 32], None)])), at);
        assert_eq!(got(&store, "a", &BTreeMap::from([([2; 32], Some(QUIET))])), at);
        // Heard lately (a healthy tunnel shakes hands about every two minutes): it keeps the
        // address it called from. Another peer's silence is not the holder's.
        assert_eq!(
            got(
                &store,
                "a",
                &BTreeMap::from([([2; 32], Some(Duration::from_secs(120)))])
            ),
            None
        );
        assert_eq!(
            got(
                &store,
                "a",
                &BTreeMap::from([([2; 32], Some(QUIET - Duration::from_secs(1)))])
            ),
            None
        );
        assert_eq!(
            got(
                &store,
                "a",
                &BTreeMap::from([([2; 32], Some(QUIET)), ([3; 32], Some(Duration::ZERO))])
            ),
            at
        );
        // Two Clusters with a house: the one home.rs holds (the lowest address) is the one asked.
        let mut two = store.clone();
        let other = source(
            "Cluster",
            "aaa",
            "{ home: { address: 10.9.0.200/24, endpoint: \"198.51.100.1:1\" } }",
        );
        two.apply(kith_api::Resource::from_source(&other).unwrap().remove(0).unwrap())
            .unwrap();
        two.set_status(
            "Cluster/aaa",
            Some(json!({ "home": { "holder": "b", "since": "2026-01-01T00:00:00Z" } })),
        )
        .unwrap();
        assert_eq!(got(&two, "a", &none), at);
        // Only a node that roams (b and c stay put) and never the holder itself.
        assert_eq!(got(&store, "c", &none), None);
        assert_eq!(got(&holds(&store, "a"), "a", &none), None);
        // A Cluster that gives no endpoint gives none.
        let mut bare = store.clone();
        let text = source("Cluster", "house", "{ home: { address: 10.9.0.100/24 } }");
        bare.apply(kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap())
            .unwrap();
        assert_eq!(got(&bare, "a", &none), None);
    }

    /// The house endpoint is resolved beside the loop: a pass is never held for it (the first answer
    /// is nothing, and the loop is woken when the lookup is done), a settled answer is kept, and a
    /// name that does not resolve is not looked up again until its backoff is over.
    #[tokio::test]
    async fn home_endpoint_is_resolved_beside_the_loop_and_a_failure_waits_its_backoff() {
        let (cache, wake) = (
            Arc::new(std::sync::Mutex::new(Lookup::default())),
            Arc::new(Notify::new()),
        );
        let started = Instant::now();
        assert_eq!(resolving(&cache, "127.0.0.1:51820", &wake), None);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the first call does not wait for the lookup"
        );
        tokio::time::timeout(Duration::from_secs(5), wake.notified())
            .await
            .expect("the loop is woken");
        let at: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        assert_eq!(resolving(&cache, "127.0.0.1:51820", &wake), Some(at));
        assert_eq!(
            cache.lock().unwrap().lookups,
            1,
            "a settled answer is not looked up again at once"
        );
        // A name that does not resolve: one lookup, then the backoff holds the next.
        assert_eq!(resolving(&cache, "nowhere.invalid:1", &wake), None);
        tokio::time::timeout(Duration::from_secs(5), wake.notified())
            .await
            .expect("a failure wakes it too");
        assert_eq!(resolving(&cache, "nowhere.invalid:1", &wake), None);
        assert_eq!(
            cache.lock().unwrap().lookups,
            1,
            "the backoff holds the retry (a new endpoint starts the count)"
        );
    }

    /// Two Nodes that say one key (one copied the other): the earlier-named one stays a member
    /// and the later one is left out, whichever the store lists first.
    #[test]
    fn two_nodes_with_one_key_keep_only_the_earlier() {
        let mut store = Store::default();
        for name in ["zed", "amy", "bob"] {
            let source = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{ name: {name} }}\nspec: {{}}\n");
            let resource = kith_api::Resource::from_source(&source).unwrap().remove(0);
            store.apply(resource.unwrap()).unwrap();
        }
        let mesh = |byte: u8| json!({ "address": "10.0.0.1:7443", "mesh": { "key": hex(&[byte; 32]), "port": 51820 } });
        store.set_status("Node/zed", Some(mesh(1))).unwrap();
        store.set_status("Node/amy", Some(mesh(1))).unwrap();
        store.set_status("Node/bob", Some(mesh(2))).unwrap();
        let got = members(&store, &BTreeMap::new(), &mut BTreeMap::new(), Instant::now());
        let named: Vec<(&str, Key)> = got.iter().map(|member| (member.name.as_str(), member.key)).collect();
        assert_eq!(named, [("amy", [1; 32]), ("bob", [2; 32])]);
    }

    #[test]
    fn whole_torn_or_empty_first_peers_file_is_no_peers() {
        let dir = std::env::temp_dir().join(format!("kith-whole-mesh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = first_peers(&dir.join("mesh.key"));
        assert_eq!(path, dir.join("mesh-peers.json"));
        for torn in ["", "[{\"name\":\"b\",\"ke"] {
            crate::pki::write_whole(&path, torn.as_bytes()).unwrap();
            assert!(told(&path).is_empty(), "{torn:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn rotation(need: &[&str], since: Instant, switched: Option<Instant>) -> Rotation {
        let need = need.iter().map(|name| name.to_string()).collect();
        Rotation {
            id: "r".into(),
            next: [9; 32],
            need,
            since,
            switched,
        }
    }

    /// A rotation switches once every peer took the key, commits once every peer shook hands after
    /// the switch (a handshake from before it proves nothing), and gives the old key back when
    /// either wait runs out: it never commits on less.
    #[test]
    fn a_rotation_commits_only_on_a_handshake_after_the_switch() {
        let start = Instant::now();
        let both: BTreeSet<String> = ["a", "b"].iter().map(|name| name.to_string()).collect();
        let one: BTreeSet<String> = ["a"].iter().map(|name| name.to_string()).collect();
        let r = rotation(&["a", "b"], start, None);
        assert_eq!(
            turn(&r, &one, &BTreeMap::new(), start + Duration::from_secs(5)),
            Turn::Wait
        );
        assert_eq!(
            turn(&r, &both, &BTreeMap::new(), start + Duration::from_secs(5)),
            Turn::Switch
        );
        assert!(matches!(
            turn(&r, &one, &BTreeMap::new(), start + ROTATE_WAIT),
            Turn::Revert(_)
        ));
        // Switched 40 s ago: a handshake 50 s ago is the old key's; 10 s ago is the new one's.
        let now = start + Duration::from_secs(100);
        let r = rotation(&["a", "b"], start, Some(now - Duration::from_secs(40)));
        let ago = |a: u64, b: u64| {
            BTreeMap::from([
                ("a".to_string(), Duration::from_secs(a)),
                ("b".to_string(), Duration::from_secs(b)),
            ])
        };
        assert_eq!(turn(&r, &both, &ago(10, 50), now), Turn::Wait);
        assert_eq!(turn(&r, &both, &BTreeMap::new(), now), Turn::Wait);
        assert_eq!(turn(&r, &both, &ago(10, 20), now), Turn::Commit);
        let late = now + ROTATE_WAIT;
        assert!(matches!(turn(&r, &both, &ago(500, 500), late), Turn::Revert(_)));
        // A rotation with nobody to agree has nothing to wait for.
        assert_eq!(
            turn(&rotation(&[], start, None), &one, &BTreeMap::new(), start),
            Turn::Switch
        );
    }

    /// The keys other nodes say they take next: only a key that is none of the nodes' keys, not
    /// zeros, and said once.
    #[test]
    fn a_next_key_is_taken_only_if_it_is_new_and_the_only_one() {
        let mut store = Store::default();
        for name in ["a", "b", "c", "d", "e", "f", "g", "h"] {
            let source = format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{ name: {name} }}\nspec: {{}}\n");
            let resource = kith_api::Resource::from_source(&source).unwrap().remove(0);
            store.apply(resource.unwrap()).unwrap();
        }
        let status = |key: u8, next: Option<u8>| {
            let mut mesh = json!({ "key": hex(&[key; 32]), "port": 51820 });
            if let Some(next) = next {
                mesh["next"] = json!(hex(&[next; 32]));
            }
            json!({ "address": "10.9.0.1:7443", "mesh": mesh })
        };
        for (node, key, next) in [
            ("a", 1, Some(10)),
            ("b", 2, Some(11)),
            ("c", 3, Some(11)),
            ("d", 4, Some(2)),
        ] {
            store
                .set_status(&format!("Node/{node}"), Some(status(key, next)))
                .unwrap();
        }
        store.set_status("Node/e", Some(status(5, Some(0)))).unwrap();
        store.set_status("Node/f", Some(status(6, Some(1)))).unwrap();
        store.set_status("Node/g", Some(status(7, None))).unwrap();
        store.set_status("Node/h", Some(status(8, Some(12)))).unwrap();
        let got = nexts(&store, "h", &[9; 32]);
        // b and c say one key (neither is taken), d says b's key, e's is zeros, f says a's key.
        assert_eq!(got, BTreeMap::from([("a".to_string(), [10; 32])]));
        // This node's own key is not another's to take, and its own `next` is not one it takes.
        store.set_status("Node/a", Some(status(1, Some(9)))).unwrap();
        assert!(nexts(&store, "h", &[9; 32]).is_empty());
    }

    /// A peer that is to change keys has the new key beside the old, with no addresses (and no
    /// endpoint, no keepalive) until it shook hands on it; then it has the old peer's, and the old
    /// has none.
    #[test]
    fn a_standby_peer_has_nothing_until_it_shook_hands() {
        let old = kith_mesh::Peer {
            key: [1; 32],
            endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            allowed: vec![(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST), 128)],
            keepalive: 25,
        };
        let member = |name: &str, byte: u8| Member {
            name: name.into(),
            key: [byte; 32],
            endpoint: None,
            edge: false,
            reached: true,
            direct_only: false,
            reaches: Vec::new(),
            seen: None,
        };
        let members = [member("a", 1), member("b", 2)];
        let nexts = BTreeMap::from([("a".to_string(), [10; 32]), ("x".to_string(), [11; 32])]);
        let mut peers = vec![old.clone()];
        standby(&mut peers, &members, &nexts, &BTreeMap::new());
        let blank = kith_mesh::Peer {
            key: [10; 32],
            endpoint: None,
            allowed: Vec::new(),
            keepalive: 0,
        };
        assert_eq!(peers, [old.clone(), blank]);
        let mut peers = vec![old.clone()];
        let shook = BTreeMap::from([([10; 32], Some(Duration::from_secs(3)))]);
        standby(&mut peers, &members, &nexts, &shook);
        let flipped = kith_mesh::Peer {
            key: [10; 32],
            ..old.clone()
        };
        let inert = kith_mesh::Peer {
            allowed: Vec::new(),
            keepalive: 0,
            ..old
        };
        assert_eq!(peers, [inert, flipped]);
    }

    #[test]
    fn a_rotation_name_is_short_text_with_no_control_characters() {
        assert!(rotate_name("first") && rotate_name(&"x".repeat(64)));
        assert!(!rotate_name("") && !rotate_name(&"x".repeat(65)) && !rotate_name("a\nb"));
    }

    /// A key file is written whole, for its owner alone, with no half-written file left beside it;
    /// writing again replaces it, and `private_key` reads what is there and makes one if not.
    #[test]
    fn a_key_file_is_written_whole_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kith-key-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mesh.key");
        let made = private_key(&path).unwrap();
        assert_eq!(read_key(&path).unwrap(), made);
        assert_eq!(private_key(&path).unwrap(), made);
        let next = next_path(&path);
        assert_eq!(next, dir.join("mesh.next"));
        let new = make_key(&next).unwrap();
        assert_ne!(new, made);
        write_key(&path, &new).unwrap();
        assert_eq!(read_key(&path).unwrap(), new);
        for file in [&path, &next] {
            assert_eq!(std::fs::metadata(file).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let names: BTreeSet<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, BTreeSet::from(["mesh.key".to_string(), "mesh.next".to_string()]));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
