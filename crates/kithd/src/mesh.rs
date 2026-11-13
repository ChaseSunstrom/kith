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
use kith_api::store::Store;
use kith_mesh::{Device, Key, Member};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

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

/// This node's private key: made the first time, and never anywhere but in its file.
fn private_key(path: &std::path::Path) -> std::io::Result<Key> {
    use std::io::{Error, Write};
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let what = || Error::other(format!("{} is not a key", path.display()));
            return key_of(text.trim()).ok_or_else(what);
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }
    let mut key = [0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key)
        .map_err(|_| Error::other("no random numbers"))?;
    // Whole or not at all: half a key file would be no key for good.
    let new = path.with_extension("new");
    let mut options = std::fs::OpenOptions::new();
    let mut file = options.write(true).create(true).truncate(true).mode(0o600).open(&new)?;
    file.write_all(hex(&key).as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&new, path)?;
    Ok(key)
}

/// For a node about to join as one that roams: its interface, up before it is a member, and
/// the public key the cluster is to know it by (hex). The cluster's addresses come from its
/// CA, which the join `token` names.
pub fn key_before_joining(options: &Options, token: &str, name: &str) -> Result<String, String> {
    let (_, pinned) = crate::pki::token_parts(token)?;
    let address = kith_mesh::node_address(kith_mesh::prefix(pinned.as_bytes()), name);
    let up = private_key(&options.key).and_then(|key| {
        let mut device = Device::ensure(&options.interface, &key, options.port, address)?;
        device.public_key()
    });
    let hint = "--roaming takes the mesh: the kernel's WireGuard and CAP_NET_ADMIN";
    up.map(|key| hex(&key)).map_err(|e| format!("no mesh: {e} ({hint})"))
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

/// The other nodes as the mesh sees them. `shook` has, for the interface's peers, how
/// long ago each last agreed on keys; `known` remembers since when each has been a peer
/// (one that is new has its three minutes to answer).
fn members(
    store: &Store,
    shook: &BTreeMap<Key, Option<Duration>>,
    known: &mut BTreeMap<Key, Instant>,
    now: Instant,
) -> Vec<Member> {
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
        let roles = node.spec["roles"].as_array();
        Some(Member {
            name: node.metadata.name.clone(),
            key,
            // A node that roams is wherever it last called from: the interface keeps that
            // address by itself, and an address from the store would put it back where it was.
            endpoint: at
                .filter(|_| node.spec["roaming"] != true)
                .map(|at| SocketAddr::new(at.ip(), port)),
            edge: roles.is_some_and(|roles| roles.contains(&"edge".into())),
            reached: fresh || now.saturating_duration_since(since) < QUIET,
            direct_only: node.spec["mesh"]["relay"] == "never",
            reaches: reaches
                .into_iter()
                .flatten()
                .filter_map(|name| name.as_str().map(str::to_string))
                .collect(),
        })
    };
    let mut members: Vec<Member> = store.list(Some("Node")).filter_map(member).collect();
    // One key is one node: nodes that say the same key are left out, whoever copied whom.
    let keys: Vec<Key> = members.iter().map(|member| member.key).collect();
    members.retain(|member| keys.iter().filter(|key| **key == member.key).count() == 1);
    known.retain(|key, _| members.iter().any(|member| member.key == *key));
    members
}

/// Set `mesh` in the status of Node `node`: what this node says of itself, or null to take it back.
async fn say(shared: &Shared, node: &str, mesh: Value) -> Result<(), String> {
    let fields = serde_json::Map::from_iter([("mesh".to_string(), mesh)]);
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
    let up = private_key(&options.key).and_then(|key| {
        let mut device = Device::ensure(&options.interface, &key, options.port, address)?;
        Ok((device.public_key()?, device))
    });
    let (public, mut device) = match up {
        Ok(up) => up,
        Err(e) => {
            let hint = "it takes the kernel's WireGuard and the right to set up interfaces, CAP_NET_ADMIN";
            return eprintln!("kithd: no mesh: {e} ({hint})");
        }
    };
    eprintln!("kithd: mesh address {address} on {}", options.interface);
    let base = json!({ "key": hex(&public), "address": address.to_string(), "port": options.port });
    let node = format!("Node/{me}");
    let first = told(&first_peers(&options.key));
    let mut known = BTreeMap::new();
    let mut generation = shared.generation.subscribe();
    let mut warned = false;
    loop {
        let shook: BTreeMap<Key, Option<Duration>> = match device.peers() {
            Ok(peers) => peers.into_iter().map(|peer| (peer.key, peer.handshake)).collect(),
            Err(e) => {
                eprintln!("kithd: mesh: reading the peers of {}: {e}", options.interface);
                BTreeMap::new()
            }
        };
        let (members, mine, said, edge, services) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let own = state.store.get(&node);
            let mut members = members(&state.store, &shook, &mut known, Instant::now());
            // (Until the store says who the nodes are: those this node was told of as it joined.)
            // Once it does, they are forgotten: a node that has left since is not called for ever.
            let nobody = members.iter().all(|member| member.name == me);
            let more: Vec<Member> = first.iter().filter(|peer| nobody && peer.name != me).cloned().collect();
            members.extend(more);
            // What this node says of itself, with who it reaches (written only when it changed).
            let mut mine = base.clone();
            mine["reaches"] = json!(reaching(&members, &shook));
            let said = own.is_none_or(|own| own.status.as_ref().is_some_and(|status| status["mesh"] == mine));
            let edge = members.iter().any(|member| member.name == me && member.edge);
            let services = crate::services::addresses(&state.store, prefix);
            (members, mine, said, edge, services.into_values().collect())
        };
        // Every node has every Service's address (crate::services listens on them).
        if let Err(e) = device.set_addresses(&services) {
            eprintln!("kithd: mesh: the services' addresses on {}: {e}", options.interface);
        }
        // (Its own Node may not be there yet, right after joining: next time round.)
        if !said && let Err(e) = say(&shared, &node, mine).await {
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
        let peers = kith_mesh::wanted(prefix, me, &members);
        if let Err(e) = device.set_peers(&peers) {
            eprintln!("kithd: mesh: setting the peers of {}: {e}", options.interface);
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
            () = tokio::time::sleep(Duration::from_secs(10)) => {}
            _ = stopping.changed() => break,
        }
    }
    // Left: the others are not to keep calling a node that is not on the mesh.
    // ponytail: a few seconds' wait at most; a node that dies instead is dropped by the
    // others when it stops answering (and a stale `mesh` stays in its Node).
    let cleared = say(&shared, &node, Value::Null);
    match tokio::time::timeout(Duration::from_secs(3), cleared).await {
        Ok(Err(e)) => eprintln!("kithd: mesh: clearing this node's mesh status: {e}"),
        Err(_) => eprintln!("kithd: mesh: clearing this node's mesh status: no answer"),
        Ok(Ok(())) => {}
    }
    if let Err(e) = device.remove() {
        eprintln!("kithd: mesh: removing {}: {e}", options.interface);
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
        // A port that is none, a key of zeros or one that two nodes say: no members.
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
        assert_eq!(named(&c(mesh(1))), ["b"]);
        // A key that is no key is no member, and a node that is gone is forgotten.
        assert_eq!(key_of("zz"), None);
        assert_eq!(key_of(&key(7)), Some([7; 32]));
        store.delete("Node/b").unwrap();
        members(&store, &none, &mut known, later);
        assert_eq!(known.len(), 1);
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
}
