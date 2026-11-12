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

fn key_of(hex: &str) -> Option<Key> {
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
        let fresh = shook.get(&key).copied().flatten().is_some_and(|ago| ago < QUIET);
        let roles = node.spec["roles"].as_array();
        Some(Member {
            name: node.metadata.name.clone(),
            key,
            endpoint: at.map(|at| SocketAddr::new(at.ip(), port)),
            edge: roles.is_some_and(|roles| roles.contains(&"edge".into())),
            reached: fresh || now.saturating_duration_since(since) < QUIET,
        })
    };
    let mut members: Vec<Member> = store.list(Some("Node")).filter_map(member).collect();
    // One key is one node: nodes that say the same key are left out, whoever copied whom.
    let keys: Vec<Key> = members.iter().map(|member| member.key).collect();
    members.retain(|member| keys.iter().filter(|key| **key == member.key).count() == 1);
    known.retain(|key, _| members.iter().any(|member| member.key == *key));
    members
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
    let mine = json!({ "key": hex(&public), "address": address.to_string(), "port": options.port });
    let node = format!("Node/{me}");
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
        let (members, said, edge) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let own = state.store.get(&node);
            let said = own.is_none_or(|own| own.status.as_ref().is_some_and(|status| status["mesh"] == mine));
            let members = members(&state.store, &shook, &mut known, Instant::now());
            let edge = members.iter().any(|member| member.name == me && member.edge);
            (members, said, edge)
        };
        // (Its own Node may not be there yet, right after joining: next time round.)
        if !said {
            let fields = serde_json::Map::from_iter([("mesh".to_string(), mine.clone())]);
            let statuses = vec![(node.clone(), fields)];
            if let Err(e) = shared.submit(kith_store::Command::Patch { statuses }).await {
                eprintln!("kithd: mesh: telling the cluster this node's key: {e}");
            }
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
    if let Err(e) = device.remove() {
        eprintln!("kithd: mesh: removing {}: {e}", options.interface);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `store` with what Node c says replaced.
    fn store_with(store: &Store, status: Value) -> Store {
        let mut store = store.clone();
        store.set_status("Node/c", Some(status)).unwrap();
        store
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
        assert_eq!(named(&c(mesh(1))), ["b"]);
        // A key that is no key is no member, and a node that is gone is forgotten.
        assert_eq!(key_of("zz"), None);
        assert_eq!(key_of(&key(7)), Some([7; 32]));
        store.delete("Node/b").unwrap();
        members(&store, &none, &mut known, later);
        assert_eq!(known.len(), 1);
    }
}
