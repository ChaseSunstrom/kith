//! Exits: a node holds the WireGuard tunnel of each `Exit` that names it (kith-mesh's
//! `exit`), from the provider's `wg0.conf` in a Secret of `kith-system` that kithd reads
//! and no container mounts. A pod whose template names an exit is let in only from a
//! namespace the exit lists ([`admitted`]), placed on its node ([`pinned`]), and started
//! only there, with the tunnel up ([`ready`]): everywhere else it does not run.
//
// ponytail: an endpoint is an address, not a name (a name would be asked of the node's
// DNS, outside the tunnel, each time it changes); IPv4 only through the tunnel.

use crate::Shared;
use base64::Engine;
use kith_api::Resource;
use kith_api::kinds::ExitSpec;
use kith_api::store::Store;
use kith_mesh::exit::Tunnel;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// The tunnels this node holds, by Exit name, and why the others it should are not up.
#[derive(Default)]
pub struct Exits {
    up: BTreeMap<String, Up>,
    failed: BTreeMap<String, String>,
}

/// One tunnel up, and what it was made of: made again when that changes.
#[derive(Clone, PartialEq)]
struct Up {
    number: u16,
    tunnel: Tunnel,
    dns: Vec<Ipv4Addr>,
    namespaces: Vec<String>,
}

impl Up {
    /// Whether this one's tunnel is `held`'s (its DNS and namespaces aside).
    fn tunnel_of(&self, held: &Up) -> bool {
        (self.number, &self.tunnel) == (held.number, &held.tunnel)
    }
}

/// What a pod of `namespace` that leaves by the exit `name` is given here: the tunnel's
/// number and where it asks for names. `Err` (why) when it may not start on this node.
pub fn ready(shared: &Shared, name: &str, namespace: &str) -> Result<(u16, Vec<Ipv4Addr>), String> {
    if !nix::unistd::getuid().is_root() {
        return Err(format!("exit {name}: only a kithd that runs as root holds a tunnel"));
    }
    let exits = shared.exits.lock().expect("nothing panics holding the exits");
    if let Some(why) = exits.failed.get(name) {
        return Err(format!("exit {name}: {why}"));
    }
    let up = exits
        .up
        .get(name)
        .ok_or_else(|| format!("exit {name}: no tunnel of it on this node"))?;
    if !up.namespaces.iter().any(|listed| listed == namespace) {
        return Err(format!("exit {name} does not list namespace {namespace}"));
    }
    Ok((up.number, up.dns.clone()))
}

/// The exit `resource`'s template names, if any.
fn named(resource: &Resource) -> Option<String> {
    crate::controller::template_of(resource).ok()?.0.exit
}

fn spec(exit: &Resource) -> Option<ExitSpec> {
    serde_json::from_value(exit.spec.clone()).ok()
}

/// Whether `resources` may be applied: one whose pods name an exit only from a namespace
/// that exit (here, or in the store) lists.
pub fn admitted(store: &Store, resources: &[Resource]) -> Result<(), String> {
    for resource in resources {
        let Some(name) = named(resource) else { continue };
        let key = format!("Exit/{name}");
        let exit = resources
            .iter()
            .find(|other| other.key() == key)
            .or_else(|| store.get(&key));
        let spec = exit
            .and_then(spec)
            .ok_or_else(|| format!("{}: there is no Exit {name}", resource.key()))?;
        let namespace = resource.metadata.namespace.as_deref().unwrap_or_default();
        if !spec.namespaces.iter().any(|listed| listed == namespace) {
            return Err(format!(
                "{}: Exit {name} does not list namespace {namespace}",
                resource.key()
            ));
        }
    }
    Ok(())
}

/// Where `resource`'s replicas go, given where its claims and volumes put them (`node`):
/// to its exit's node, which has to be that one.
pub fn pinned(store: &Store, resource: &Resource, node: Option<String>) -> Result<Option<String>, String> {
    let Some(name) = named(resource) else { return Ok(node) };
    let exit = store.get(&format!("Exit/{name}")).and_then(spec);
    let exit = exit.ok_or_else(|| format!("there is no Exit {name}"))?;
    match node {
        Some(node) if node != exit.node => Err(format!(
            "its claims or volumes are on node {node}, and its Exit {name} on node {}",
            exit.node
        )),
        _ => Ok(Some(exit.node)),
    }
}

/// A provider's `wg0.conf`: the tunnel, and its `DNS` (IPv4).
pub fn parse(text: &str) -> Result<(Tunnel, Vec<Ipv4Addr>), String> {
    let key = |value: &str| -> Result<kith_mesh::Key, String> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(value.trim());
        let bytes = bytes.map_err(|_| "a key is not base64".to_string())?;
        bytes.try_into().map_err(|_| "a key is not 32 bytes".to_string())
    };
    let (mut section, mut peers) = (String::new(), 0);
    let (mut private, mut address, mut dns) = (None, None, Vec::new());
    let (mut public, mut shared, mut endpoint, mut keepalive) = (None, None, None, 0);
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = line.to_ascii_lowercase();
            peers += usize::from(section == "[peer]");
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!("`{line}` is not `Name = value`"));
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        let addresses = || {
            value
                .split(',')
                .map(|one| one.trim().split('/').next().unwrap_or_default().trim())
        };
        match (section.as_str(), name.as_str()) {
            ("[interface]", "privatekey") => private = Some(key(value)?),
            ("[interface]", "address") => address = addresses().find_map(|one| one.parse::<Ipv4Addr>().ok()),
            ("[interface]", "dns") => dns.extend(addresses().filter_map(|one| one.parse::<Ipv4Addr>().ok())),
            ("[peer]", "publickey") => public = Some(key(value)?),
            ("[peer]", "presharedkey") => shared = Some(key(value)?),
            ("[peer]", "endpoint") => {
                let at = value.parse::<SocketAddr>();
                endpoint = Some(at.map_err(|_| format!("Endpoint `{value}`: an address and port, not a name"))?);
            }
            ("[peer]", "persistentkeepalive") => keepalive = value.parse().map_err(|_| "PersistentKeepalive")?,
            _ => {}
        }
    }
    if peers != 1 {
        return Err(format!("it has {peers} [Peer] sections, and an exit has one"));
    }
    let tunnel = Tunnel {
        key: private.ok_or("no PrivateKey")?,
        address: address.ok_or("no IPv4 Address")?,
        peer: public.ok_or("no PublicKey")?,
        shared,
        endpoint: endpoint.ok_or("no Endpoint")?,
        keepalive,
    };
    Ok((tunnel, dns))
}

/// The tunnels this node should hold: each Exit that names it, as its Secret says.
fn wanted(shared: &Shared) -> BTreeMap<String, Result<Up, String>> {
    let state = shared.store.lock().expect("nothing panics holding the store");
    let me = shared.members.me();
    let mut wanted = BTreeMap::new();
    let mut numbers = BTreeMap::new();
    for exit in state.store.list(Some("Exit")) {
        let Some(spec) = spec(exit).filter(|spec| spec.node == me) else {
            continue;
        };
        let name = exit.metadata.name.clone();
        let number = kith_mesh::exit::number(&name);
        let up = (|| {
            if let Some(other) = numbers.insert(number, name.clone()) {
                return Err(format!("its number on this node is Exit {other}'s: name it otherwise"));
            }
            let secret = state.store.get(&format!("Secret/kith-system/{}", spec.secret));
            let secret = secret
                .and_then(|secret| serde_json::from_value::<kith_api::kinds::SecretSpec>(secret.spec.clone()).ok());
            let text = secret.and_then(|secret| secret.data.get("wg0.conf").cloned());
            let text = text.ok_or_else(|| format!("Secret kith-system/{} has no wg0.conf", spec.secret))?;
            let (tunnel, said) = parse(&text).map_err(|why| format!("wg0.conf: {why}"))?;
            let dns = match spec.dns.is_empty() {
                true => said,
                false => spec.dns.iter().filter_map(|one| one.parse().ok()).collect(),
            };
            if dns.is_empty() {
                return Err("no DNS: wg0.conf says none, nor does the Exit".into());
            }
            Ok(Up {
                number,
                tunnel,
                dns,
                namespaces: spec.namespaces.clone(),
            })
        })();
        wanted.insert(name, up);
    }
    wanted
}

/// Make, change and take away this node's tunnels as the Exits say, until kithd stops.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    if !nix::unistd::getuid().is_root() {
        return;
    }
    let mut generation = shared.generation.subscribe();
    loop {
        tend(&shared, wanted(&shared));
        tokio::select! {
            _ = generation.changed() => {}
            // (Again now and then: a tunnel someone took away by hand is made again.)
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = stopping.changed() => return,
        }
    }
}

fn tend(shared: &Shared, wanted: BTreeMap<String, Result<Up, String>>) {
    let mut exits = shared.exits.lock().expect("nothing panics holding the exits");
    let mut forget = false;
    // What goes, or changes: taken away, and its pods' connections forgotten.
    let held: Vec<(String, Up)> = exits.up.iter().map(|(name, up)| (name.clone(), up.clone())).collect();
    for (name, up) in held {
        let now = match wanted.get(&name) {
            Some(Ok(now)) if now.tunnel_of(&up) => Some(now),
            _ => None,
        };
        // (Whole: its link, its table's route and its rules, none taken away by hand.)
        let there = std::fs::exists(format!("/sys/class/net/{}", kith_mesh::exit::device(up.number)));
        let whole = there.unwrap_or(false) && kith_mesh::exit::whole(up.number, up.tunnel.address).unwrap_or(false);
        if let Some(now) = now.filter(|_| whole) {
            // (Its namespaces or DNS alone changed: the tunnel stays as it is.)
            exits.up.insert(name, now.clone());
            continue;
        }
        if now.is_some() {
            eprintln!("kithd: exit {name}: its tunnel, a rule or a route of it is gone: made again");
        }
        if let Err(e) = kith_mesh::exit::remove(up.number, Some(up.tunnel.address)) {
            eprintln!("kithd: exit {name}: taking its tunnel away: {e}");
        }
        exits.up.remove(&name);
        forget = true;
    }
    let was = std::mem::take(&mut exits.failed);
    for (name, up) in wanted {
        if exits.up.contains_key(&name) {
            continue;
        }
        let made = up.and_then(|up| match kith_mesh::exit::ensure(up.number, &up.tunnel) {
            Ok(()) => Ok(up),
            Err(e) => {
                let _ = kith_mesh::exit::remove(up.number, Some(up.tunnel.address));
                Err(format!("making its tunnel: {e}"))
            }
        });
        match made {
            Ok(up) => {
                eprintln!("kithd: exit {name}: tunnel {} up", kith_mesh::exit::device(up.number));
                exits.up.insert(name, up);
            }
            Err(why) => {
                // (Said once, not each time it is tried again.)
                if was.get(&name) != Some(&why) {
                    eprintln!("kithd: exit {name}: no tunnel: {why}");
                }
                exits.failed.insert(name, why);
            }
        }
    }
    if forget && let Err(e) = kith_mesh::exit::forget() {
        eprintln!("kithd: forgetting the connections of an exit's pods: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // pragma: allowlist secret

    fn conf(peer: &str) -> String {
        format!(
            "[Interface]\n# a comment\nPrivateKey = {KEY}\nAddress = 10.2.0.2/32, fd00::2/128\nDNS = 10.2.0.1\n\n{peer}"
        )
    }

    #[test]
    fn a_providers_file_is_read() {
        let peer = format!(
            "[Peer]\nPublicKey = {KEY}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.7:51820\nPersistentKeepalive = 25\n"
        );
        let (tunnel, dns) = parse(&conf(&peer)).unwrap();
        assert_eq!(tunnel.address, Ipv4Addr::new(10, 2, 0, 2));
        assert_eq!(tunnel.endpoint, "192.0.2.7:51820".parse().unwrap());
        assert_eq!((tunnel.keepalive, tunnel.shared), (25, None));
        assert_eq!(dns, [Ipv4Addr::new(10, 2, 0, 1)]);
        // Two peers, a name for the endpoint, no IPv4 address: refused.
        let two = parse(&conf(&format!("{peer}{peer}"))).unwrap_err();
        assert!(two.contains("2 [Peer]"), "{two}");
        let named = parse(&conf(&peer.replace("192.0.2.7", "vpn.example"))).unwrap_err();
        assert!(named.contains("not a name"), "{named}");
        let v6 = parse(&conf(&peer).replace("10.2.0.2/32, ", "")).unwrap_err();
        assert!(v6.contains("IPv4"), "{v6}");
        assert!(parse(&conf(&peer).replace(KEY, "short")).is_err());
    }

    #[test]
    fn a_tunnel_is_made_again_only_when_it_changes() {
        let peer = format!("[Peer]\nPublicKey = {KEY}\nEndpoint = 192.0.2.7:51820\n");
        let (tunnel, dns) = parse(&conf(&peer)).unwrap();
        let held = Up {
            number: 7,
            tunnel,
            dns,
            namespaces: vec!["media".into()],
        };
        // Another namespace or DNS: the same tunnel.
        let mut now = held.clone();
        now.namespaces.push("other".into());
        now.dns = vec![Ipv4Addr::new(10, 2, 0, 9)];
        assert!(now.tunnel_of(&held));
        // Another endpoint or number: another.
        now.tunnel.endpoint = "192.0.2.8:51820".parse().unwrap();
        assert!(!now.tunnel_of(&held));
        let mut moved = held.clone();
        moved.number = 8;
        assert!(!moved.tunnel_of(&held));
    }

    #[test]
    fn a_pod_names_an_exit_that_lists_its_namespace() {
        let exit: Resource = serde_json::from_value(serde_json::json!({
            "apiVersion": "kith.dev/v1", "kind": "Exit", "metadata": {"name": "vpn"},
            "spec": {"node": "n1", "secret": "vpn", "namespaces": ["media"]},
        }))
        .unwrap();
        let pod = |namespace: &str| -> Resource {
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kith.dev/v1", "kind": "Workload", "metadata": {"name": "dl", "namespace": namespace},
                "spec": {"template": {"pod": true, "exit": "vpn", "containers": [{"name": "c", "image": "x"}]}},
            }))
            .unwrap()
        };
        let store = Store::default();
        assert!(
            admitted(&store, &[pod("media")])
                .unwrap_err()
                .contains("there is no Exit vpn")
        );
        admitted(&store, &[exit.clone(), pod("media")]).unwrap();
        let other = admitted(&store, &[exit.clone(), pod("other")]).unwrap_err();
        assert!(other.contains("does not list namespace other"), "{other}");
        // (Placed on its node; where its volumes are elsewhere, nowhere.)
        let mut store = Store::default();
        store.apply(exit).unwrap();
        assert_eq!(pinned(&store, &pod("media"), None).unwrap().as_deref(), Some("n1"));
        assert!(pinned(&store, &pod("media"), Some("n2".into())).is_err());
    }
}
