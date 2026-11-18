//! The people's addresses (docs/adr-people.md, "Addresses come from the name"). Each RemotePeer
//! is given an IPv4 in `100.89.0.0/16` and an IPv6 in the cluster's people /64, both from its
//! name, and keeps them in its status once given. The leader writes them once its store has
//! applied its log. A later peer with a taken address is refused in status and named, and a public
//! key that two peers hold gives its address to one of them and refuses the rest, naming it. A
//! refusal names no address. An AccessLevel whose network lies over the mesh's /48 or the people
//! /64 is refused the same way.
//!
//! ponytail: 16 bits of a name's hash for the IPv4 address: about 7% of 100 peers collide, and
//! the later one is told to be named otherwise. No allocator.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{AccessLevelSpec, RemotePeerSpec};
use kith_api::store::Store;
use kith_store::Command;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// The people's IPv4 range. Its first two addresses and its last are never given.
pub const RANGE: Ipv4Addr = Ipv4Addr::new(100, 89, 0, 0);

/// The cluster's people /64: the first /64 of a ULA /48 made from its CA with another seed than
/// the mesh's (`mesh::prefix`), so the two never overlap. Its first two interface ids and its
/// last are never given.
pub fn prefix(ca: &str) -> Ipv6Addr {
    let print = crate::pki::fingerprint(ca);
    let seed = format!("people {}", print.as_deref().unwrap_or(ca));
    let mut bytes = kith_mesh::prefix(seed.as_bytes()).octets();
    bytes[8..].fill(0);
    bytes.into()
}

/// A RemotePeer as the leader reads it: its name, its public key, and the addresses its status holds.
pub struct Asked {
    pub name: String,
    pub key: String,
    pub held: Option<(Ipv4Addr, Ipv6Addr)>,
}

/// What the leader says of a RemotePeer: its two addresses, or why it has none. A refused one
/// keeps the addresses it held, if it held any, so that a refusal never frees one.
#[derive(Debug, PartialEq)]
pub enum Said {
    Given(Ipv4Addr, Ipv6Addr),
    Refused(String, Option<(Ipv4Addr, Ipv6Addr)>),
}

/// The IPv4 offset in [`RANGE`] (16 bits) and the interface id of the IPv6 address (64 bits) of
/// a name's hash.
fn drawn(name: &str) -> (u32, u64) {
    let hash = ring::digest::digest(&ring::digest::SHA256, name.as_bytes());
    let hash = hash.as_ref();
    let four = u16::from_be_bytes([hash[0], hash[1]]);
    let six = u64::from_be_bytes(hash[8..16].try_into().expect("a SHA-256 digest is 32 bytes"));
    (u32::from(four), six)
}

/// The addresses at an IPv4 offset in [`RANGE`] and an interface id in the people /64.
fn addresses(people: Ipv6Addr, offset: u32, iid: u64) -> (Ipv4Addr, Ipv6Addr) {
    let mut bytes = people.octets();
    bytes[8..].copy_from_slice(&iid.to_be_bytes());
    (Ipv4Addr::from(u32::from(RANGE) | offset), bytes.into())
}

/// The range's first two offsets and its last are never given.
fn reserved4(offset: u32) -> bool {
    matches!(offset, 0 | 1 | 0xffff)
}

/// The /64's first two interface ids and its last are never given.
fn reserved6(iid: u64) -> bool {
    matches!(iid, 0 | 1 | u64::MAX)
}

/// Is a held address one this people's range gives (a status a hand wrote may not be)?
fn ours(people: Ipv6Addr, (four, six): (Ipv4Addr, Ipv6Addr)) -> bool {
    let offset = u32::from(four) ^ u32::from(RANGE);
    let rest = u128::from(six) ^ u128::from(people);
    let iid = rest as u64;
    offset <= 0xffff && rest >> 64 == 0 && !reserved4(offset) && !reserved6(iid)
}

/// Who holds each address so far in a pass: the first to take one keeps it.
#[derive(Default)]
struct Held {
    four: BTreeMap<Ipv4Addr, String>,
    six: BTreeMap<Ipv6Addr, String>,
}

impl Held {
    fn take(&mut self, name: &str, (four, six): (Ipv4Addr, Ipv6Addr)) -> Result<(), String> {
        if let Some(other) = self.four.get(&four) {
            return Err(format!("its IPv4 address is {other}'s: name it otherwise"));
        }
        if let Some(other) = self.six.get(&six) {
            return Err(format!("its IPv6 address is {other}'s: name it otherwise"));
        }
        self.four.insert(four, name.to_string());
        self.six.insert(six, name.to_string());
        Ok(())
    }
}

/// The addresses a peer holds, when they are ours (a status a hand wrote may not be).
fn valid(people: Ipv6Addr, peer: &Asked) -> Option<(Ipv4Addr, Ipv6Addr)> {
    peer.held.filter(|&pair| ours(people, pair))
}

/// What each RemotePeer is given, by name. A public key on two or more peers gives its address
/// to one of them, the keeper: the one already holding an address of ours, else the smallest
/// name. The others are refused, naming the keeper. Held addresses are kept first, by name, the
/// refused peers' too; the others draw from their names, and a draw at the range's ends or one
/// taken is refused, naming the holder.
pub fn plan(asked: &[Asked], people: Ipv6Addr) -> BTreeMap<String, Said> {
    let mut by_key: BTreeMap<&str, Vec<&Asked>> = BTreeMap::new();
    for peer in asked {
        by_key.entry(peer.key.as_str()).or_default().push(peer);
    }
    let mut lot: Vec<(&Asked, Option<String>)> = Vec::new();
    for holders in by_key.values() {
        let Some(keeper) = holders
            .iter()
            .min_by_key(|peer| (valid(people, peer).is_none(), peer.name.as_str()))
        else {
            continue;
        };
        for &peer in holders {
            let why = (peer.name != keeper.name)
                .then(|| format!("publicKey: the same as {}'s: name it otherwise", keeper.name));
            lot.push((peer, why));
        }
    }
    // Keepers first: a refused peer's held address is kept only where no keeper holds it.
    // Keepers first: a refused peer's held address is kept only where no keeper holds it.
    lot.sort_by(|a, b| (a.1.is_some(), &a.0.name).cmp(&(b.1.is_some(), &b.0.name)));

    let mut said = BTreeMap::new();
    let mut held = Held::default();
    let mut draws = Vec::new();
    for (peer, why) in lot {
        match (valid(people, peer), why) {
            (Some(pair), why) => {
                let now = match (held.take(&peer.name, pair), why) {
                    (Ok(()), None) => Said::Given(pair.0, pair.1),
                    (Ok(()), Some(why)) => Said::Refused(why, Some(pair)),
                    (Err(err), None) => Said::Refused(err, None),
                    (Err(_), Some(why)) => Said::Refused(why, None),
                };
                said.insert(peer.name.clone(), now);
            }
            (None, Some(why)) => {
                said.insert(peer.name.clone(), Said::Refused(why, None));
            }
            (None, None) => draws.push(peer),
        }
    }
    for peer in draws {
        let (offset, iid) = drawn(&peer.name);
        let (four, six) = addresses(people, offset, iid);
        let now = if reserved4(offset) {
            let why = "its IPv4 address is the range's first two or last, never given: name it otherwise";
            Said::Refused(why.into(), None)
        } else if reserved6(iid) {
            let why = "its IPv6 address is the people /64's first two or last, never given: name it otherwise";
            Said::Refused(why.into(), None)
        } else {
            match held.take(&peer.name, (four, six)) {
                Ok(()) => Said::Given(four, six),
                Err(why) => Said::Refused(why, None),
            }
        };
        said.insert(peer.name.clone(), now);
    }
    said
}

/// Why an AccessLevel's network lies over the cluster's mesh /48 or its people /64: the first
/// `min` bits of the two agree. IPv4 networks are not these; the people's IPv4 ranges are kith-api's.
fn over(net: &str, mesh: Ipv6Addr, people: Ipv6Addr) -> Option<String> {
    let (address, length) = net.split_once('/')?;
    let IpAddr::V6(address) = address.parse::<IpAddr>().ok()? else {
        return None;
    };
    let length: u32 = length.parse().ok()?;
    let agree = |other: Ipv6Addr, bits: u32| {
        let mask = u128::MAX.checked_shl(128 - length.min(bits)).unwrap_or(0);
        (u128::from(address) & mask) == (u128::from(other) & mask)
    };
    if agree(mesh, 48) {
        Some(format!("networks: `{net}` overlaps the mesh's /48"))
    } else if agree(people, 64) {
        Some(format!("networks: `{net}` overlaps the people /64"))
    } else {
        None
    }
}

fn held(resource: &Resource) -> Option<(Ipv4Addr, Ipv6Addr)> {
    let addresses = resource.status.as_ref()?.get("addresses")?;
    let four = addresses.get("ipv4")?.as_str()?.parse().ok()?;
    let six = addresses.get("ipv6")?.as_str()?.parse().ok()?;
    Some((four, six))
}

/// The fields of a resource's status that `want` changes, under its key; nothing when none does.
fn changed(resource: &Resource, want: Vec<(&str, Value)>) -> Option<(String, Map<String, Value>)> {
    let now = resource.status.as_ref();
    let differ: Map<String, Value> = want
        .into_iter()
        .filter(|(field, value)| now.and_then(|s| s.get(*field)).unwrap_or(&Value::Null) != value)
        .map(|(field, value)| (field.to_string(), value))
        .collect();
    (!differ.is_empty()).then(|| (resource.key(), differ))
}

/// The `addresses` field of a RemotePeer's status: its two addresses, or none.
fn address_value(pair: Option<(Ipv4Addr, Ipv6Addr)>) -> Value {
    pair.map_or(
        Value::Null,
        |(four, six)| json!({"ipv4": four.to_string(), "ipv6": six.to_string()}),
    )
}

/// Has a store applied its leader's log? One that has not is planned from statuses it lacks, and
/// would overwrite the ones a leader before it gave.
fn caught_up(last_log: Option<u64>, applied: Option<u64>) -> bool {
    last_log.is_none_or(|last| applied.is_some_and(|index| index >= last))
}

/// The status fields to write now: a RemotePeer's `addresses` and `refused`, an AccessLevel's
/// `refused`. Nothing is written that the store already says, and nothing while the store has not
/// applied its log (`caught_up`).
pub fn statuses(store: &Store, mesh: Ipv6Addr, people: Ipv6Addr, caught_up: bool) -> Vec<(String, Map<String, Value>)> {
    if !caught_up {
        return Vec::new();
    }
    let mut asked = Vec::new();
    for resource in store.list(Some("RemotePeer")) {
        let Ok(spec) = serde_json::from_value::<RemotePeerSpec>(resource.spec.clone()) else {
            continue;
        };
        asked.push(Asked {
            name: resource.metadata.name.clone(),
            key: spec.public_key,
            held: held(resource),
        });
    }
    let said = plan(&asked, people);
    let mut out = Vec::new();
    for resource in store.list(Some("RemotePeer")) {
        let Some(now) = said.get(&resource.metadata.name) else {
            continue;
        };
        let want = match now {
            Said::Given(four, six) => {
                vec![
                    ("addresses", address_value(Some((*four, *six)))),
                    ("refused", Value::Null),
                ]
            }
            Said::Refused(why, kept) => {
                vec![("addresses", address_value(*kept)), ("refused", json!(why))]
            }
        };
        out.extend(changed(resource, want));
    }
    for resource in store.list(Some("AccessLevel")) {
        let Ok(spec) = serde_json::from_value::<AccessLevelSpec>(resource.spec.clone()) else {
            continue;
        };
        let why = spec.networks.iter().find_map(|net| over(net, mesh, people));
        out.extend(changed(
            resource,
            vec![("refused", why.map_or(Value::Null, Value::from))],
        ));
    }
    out
}

/// Keep the people's addresses as the store says, as long as this node leads it, until stopped.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let Some(cluster) = &shared.cluster else { return };
    let (mesh, people) = (crate::mesh::prefix(&cluster.me.ca), prefix(&cluster.me.ca));
    let mut generation = shared.generation.subscribe();
    loop {
        let metrics = shared.raft.metrics().borrow().clone();
        if metrics.current_leader == Some(metrics.id) {
            let applied = metrics.last_applied.map(|log| log.index);
            let statuses = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                statuses(&state.store, mesh, people, caught_up(metrics.last_log_index, applied))
            };
            if !statuses.is_empty()
                && let Err(e) = shared.submit(Command::Patch { statuses }).await
            {
                eprintln!("kithd: people: {e}");
            }
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = stopping.changed() => return,
        }
    }
}

/// The people's device made or found on `port`, up, with the people's table written first and no
/// peers (docs/adr-people.md, "Built"). Its key is `pki/people.key`, made the first time and kept.
/// Says the device's public key.
pub fn up(state: &Path, port: u16, interface: &str, people64: Ipv6Addr) -> std::io::Result<kith_mesh::Key> {
    up_with(state, port, people64, || {
        kith_mesh::people::send(people64, &[], &[], interface, &[]).map_err(no_masquerade)
    })
}

/// `up`, with the table made by `table` (the tests make theirs without masquerade: see `table_here`).
fn up_with(
    state: &Path,
    port: u16,
    people64: Ipv6Addr,
    table: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<kith_mesh::Key> {
    let key = crate::mesh::private_key(&state.join("pki").join("people.key"))?;
    table()?;
    Ok(kith_mesh::people::device(&key, port, people64)?.public_key)
}

/// A kernel with no nftables masquerade (CONFIG_NFT_MASQ) refuses the table's post chain: that
/// is said plainly, where a bare ENOENT would not say what is missing. Other errors pass as they are.
fn no_masquerade(e: std::io::Error) -> std::io::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        std::io::Error::new(
            e.kind(),
            "this kernel has no nftables masquerade (CONFIG_NFT_MASQ): --people needs it",
        )
    } else {
        e
    }
}

/// What this node says of its people's device in its status (`people`): the device's public key
/// (base64, as a RemotePeer's is), its port and its endpoint. Null without a device.
pub fn said(key: Option<&kith_mesh::Key>, port: u16, endpoint: Option<&str>) -> Value {
    use base64::Engine as _;
    match key {
        Some(key) => json!({
            "publicKey": base64::engine::general_purpose::STANDARD.encode(key),
            "port": port,
            "endpoint": endpoint,
        }),
        None => Value::Null,
    }
}

/// The people's device (see `up`), until stopped, then taken away with its table; `people` said in
/// this node's status while it is up. Without a port, what an earlier start left is taken away
/// now, and what this node said of it is taken back.
pub async fn device(
    shared: Arc<Shared>,
    state: PathBuf,
    port: Option<u16>,
    endpoint: Option<String>,
    interface: String,
    mut stopping: watch::Receiver<bool>,
) {
    let Some(port) = port else {
        // (Only root can take the device and table away: a start without root has nothing to say.)
        if nix::unistd::getuid().is_root()
            && let Err(e) = kith_mesh::people::remove()
        {
            eprintln!("kithd: people: taking away what an earlier start left: {e}");
        }
        return crate::mesh::left(shared, "people", stopping).await;
    };
    let Some(cluster) = &shared.cluster else {
        return eprintln!("kithd: --people is for a node of a cluster (--mesh): no people");
    };
    let node = format!("Node/{}", cluster.me.name);
    let people64 = prefix(&cluster.me.ca);
    let public = match up(&state, port, &interface, people64) {
        Ok(public) => public,
        Err(e) => {
            eprintln!("kithd: no people: {e} (it takes root)");
            // (No device, so what an earlier start said of one is taken back.)
            return crate::mesh::left(shared, "people", stopping).await;
        }
    };
    eprintln!("kithd: people on {}: UDP port {port}", kith_mesh::people::DEVICE);
    let status = said(Some(&public), port, endpoint.as_deref());
    let mut generation = shared.generation.subscribe();
    loop {
        // (Said again whenever the store does not have it: the Node may not be there yet.)
        let there = {
            let store = shared.store.lock().expect("nothing panics holding the store");
            let own = store.store.get(&node);
            own.is_some_and(|own| own.status.as_ref().is_some_and(|held| held["people"] == status))
        };
        if !there && let Err(e) = crate::mesh::say(&shared, &node, "people", status.clone()).await {
            eprintln!("kithd: people: telling the cluster: {e}");
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(10)) => {}
            _ = stopping.changed() => break,
        }
    }
    if let Err(e) = kith_mesh::people::remove() {
        eprintln!("kithd: people: taking away {}'s people: {e}", kith_mesh::people::DEVICE);
    }
    if let Err(e) = crate::mesh::say(&shared, &node, "people", Value::Null).await {
        eprintln!("kithd: people: taking back this node's people: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn people() -> Ipv6Addr {
        prefix("a cluster")
    }

    fn asked(name: &str, key: &str) -> Asked {
        Asked {
            name: name.into(),
            key: key.into(),
            held: None,
        }
    }

    fn given(said: &BTreeMap<String, Said>, name: &str) -> (Ipv4Addr, Ipv6Addr) {
        match said.get(name) {
            Some(Said::Given(four, six)) => (*four, *six),
            other => panic!("{name}: {other:?}"),
        }
    }

    fn refused(said: &BTreeMap<String, Said>, name: &str) -> String {
        match said.get(name) {
            Some(Said::Refused(why, _)) => why.clone(),
            other => panic!("{name}: {other:?}"),
        }
    }

    const KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn apply_peer(store: &mut Store, name: &str, key: &str) {
        let source = format!(
            "apiVersion: kith.dev/v1\nkind: RemotePeer\nmetadata: {{ name: {name} }}\nspec: {{ node: n1, level: family, publicKey: '{key}' }}\n"
        );
        for resource in Resource::from_source(&source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
    }

    fn status_of(store: &Store, key: &str, field: &str) -> Value {
        store
            .get(key)
            .and_then(|resource| resource.status.as_ref())
            .and_then(|status| status.get(field))
            .cloned()
            .unwrap_or(Value::Null)
    }

    /// Writes the statuses the leader would, as a leader that has applied its log does.
    fn settle(store: &mut Store, mesh: Ipv6Addr, people: Ipv6Addr) {
        let statuses = statuses(store, mesh, people, true);
        kith_store::run(store, Command::Patch { statuses }).unwrap();
    }

    #[test]
    fn address_comes_from_the_name() {
        let said = plan(&[asked("phone-1", "k1"), asked("phone-2", "k2")], people());
        let (four, six) = given(&said, "phone-1");
        assert_eq!(four.octets()[..2], [100, 89], "{four}");
        assert_eq!(six.octets()[..8], people().octets()[..8], "{six}");
        assert_eq!(
            given(&plan(&[asked("phone-1", "k1")], people()), "phone-1"),
            (four, six)
        );
        assert_ne!(given(&said, "phone-2"), (four, six));
    }

    #[test]
    fn the_range_ends_are_never_given() {
        // (A name whose draw lands on each of the range's first two addresses and its last.)
        for offset in [0, 1, 0xffff] {
            let name = (0u64..)
                .map(|i| format!("peer{i}"))
                .find(|name| drawn(name).0 == offset)
                .expect("some name draws each end");
            let said = plan(&[asked(&name, "k1")], people());
            assert!(
                refused(&said, &name).contains("name it otherwise"),
                "{offset}: {said:?}"
            );
        }
    }

    #[test]
    fn a_held_address_is_kept_not_drawn_again() {
        let held = addresses(people(), 0x0707, 0x1234_5678);
        let mut phone = asked("phone-1", "k1");
        phone.held = Some(held);
        assert_eq!(given(&plan(&[phone], people()), "phone-1"), held);
    }

    #[test]
    fn the_first_holder_keeps_a_taken_address() {
        // (Two names whose IPv4 draws collide, neither at a range's end.)
        let mut seen: BTreeMap<u32, String> = BTreeMap::new();
        let (first, second) = (0u64..)
            .find_map(|i| {
                let name = format!("peer{i}");
                let offset = drawn(&name).0;
                if reserved4(offset) {
                    return None;
                }
                seen.insert(offset, name.clone()).map(|other| (other, name))
            })
            .expect("16 bits collide among some names");
        let (holder, later) = if first < second {
            (first, second)
        } else {
            (second, first)
        };
        let said = plan(&[asked(&later, "k2"), asked(&holder, "k1")], people());
        let (offset, iid) = drawn(&holder);
        assert_eq!(given(&said, &holder), addresses(people(), offset, iid));
        let why = refused(&said, &later);
        assert!(why.contains(&format!("{holder}'s")), "{why}");
    }

    #[test]
    fn a_key_on_two_peers_gives_the_smallest_name_and_refuses_the_rest() {
        let said = plan(
            &[asked("phone-2", "K"), asked("phone-1", "K"), asked("phone-3", "J")],
            people(),
        );
        given(&said, "phone-1");
        assert!(refused(&said, "phone-2").contains("phone-1's"));
        given(&said, "phone-3");
    }

    #[test]
    fn a_key_on_two_peers_gives_the_one_already_holding_an_address() {
        let held = addresses(people(), 0x0707, 0x1234_5678);
        let mut holder = asked("phone-2", "K");
        holder.held = Some(held);
        let said = plan(&[asked("phone-1", "K"), holder], people());
        assert_eq!(given(&said, "phone-2"), held);
        assert!(refused(&said, "phone-1").contains("phone-2's"));
    }

    #[test]
    fn a_refused_peer_never_frees_its_address() {
        // (a1 and z1 share a key and z1 holds an address. A third peer q with z1's key comes and
        // goes: z1 keeps its address through all of it.)
        let (mesh, people) = (kith_mesh::prefix(b"a cluster"), people());
        let held = addresses(people, 0x0707, 0x1234_5678);
        let mut store = Store::default();
        apply_peer(&mut store, "a1", KEY);
        apply_peer(&mut store, "z1", KEY);
        store
            .set_status("RemotePeer/z1", Some(json!({"addresses": address_value(Some(held))})))
            .unwrap();
        settle(&mut store, mesh, people);
        assert!(
            status_of(&store, "RemotePeer/a1", "refused")
                .as_str()
                .is_some_and(|why| why.contains("z1's"))
        );
        assert_eq!(
            status_of(&store, "RemotePeer/z1", "addresses"),
            address_value(Some(held))
        );
        apply_peer(&mut store, "q", KEY);
        settle(&mut store, mesh, people);
        assert_eq!(
            status_of(&store, "RemotePeer/z1", "addresses"),
            address_value(Some(held))
        );
        store.delete("RemotePeer/q").unwrap();
        settle(&mut store, mesh, people);
        assert_eq!(
            status_of(&store, "RemotePeer/z1", "addresses"),
            address_value(Some(held))
        );
    }

    #[test]
    fn a_refused_peer_never_takes_a_keepers_address() {
        // (a0 keeps key J's address. a1, refused for that key, holds an address that z1, the keeper
        // of key K, holds too: z1 keeps it, and a1 keeps none.)
        let (x, y) = (addresses(people(), 0x0707, 0x1111), addresses(people(), 0x0909, 0x2222));
        let mut a0 = asked("a0", "J");
        a0.held = Some(y);
        let mut a1 = asked("a1", "J");
        a1.held = Some(x);
        let mut z1 = asked("z1", "K");
        z1.held = Some(x);
        let said = plan(&[a0, a1, z1], people());
        assert_eq!(given(&said, "z1"), x);
        assert_eq!(given(&said, "a0"), y);
        assert!(matches!(said.get("a1"), Some(Said::Refused(why, None)) if why.contains("a0's")));
    }

    #[test]
    fn the_leader_writes_only_once_its_store_has_applied_its_log() {
        let mut store = Store::default();
        apply_peer(&mut store, "phone-1", KEY);
        let (mesh, people) = (kith_mesh::prefix(b"a cluster"), people());
        assert!(statuses(&store, mesh, people, false).is_empty());
        assert!(!statuses(&store, mesh, people, true).is_empty());
        assert!(caught_up(None, None));
        assert!(!caught_up(Some(5), None));
        assert!(!caught_up(Some(5), Some(4)));
        assert!(caught_up(Some(5), Some(5)));
    }

    #[test]
    fn no_refusal_names_an_address() {
        let people = people();
        let stem = people.segments()[..4]
            .iter()
            .map(|segment| format!("{segment:x}"))
            .collect::<Vec<_>>()
            .join(":");
        let mut a1 = asked("k-a1", "k1");
        a1.held = Some(addresses(people, 0x0707, 0x1111));
        let mut a2 = asked("k-a2", "k2");
        a2.held = Some(addresses(people, 0x0707, 0x2222));
        let mut a3 = asked("k-a3", "k3");
        a3.held = Some(addresses(people, 0x0708, 0x1111));
        let end = (0u64..)
            .map(|i| format!("peer{i}"))
            .find(|name| drawn(name).0 == 0)
            .expect("some name draws the range's first address");
        let said = plan(
            &[a1, a2, a3, asked(&end, "k4"), asked("k-s1", "K"), asked("k-s2", "K")],
            people,
        );
        let refusals: Vec<&String> = said
            .values()
            .filter_map(|said| match said {
                Said::Refused(why, _) => Some(why),
                Said::Given(..) => None,
            })
            .collect();
        assert_eq!(refusals.len(), 4, "{said:?}");
        for why in refusals {
            assert!(!why.contains("100.89.") && !why.contains(&stem), "{why}");
        }
    }

    #[test]
    fn statuses_are_written_once_and_a_level_over_the_mesh_is_refused() {
        let source = "apiVersion: kith.dev/v1\nkind: RemotePeer\nmetadata: { name: phone-1 }\n\
            spec: { node: n1, level: family, publicKey: 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=' }\n---\n\
            apiVersion: kith.dev/v1\nkind: AccessLevel\nmetadata: { name: family }\n\
            spec: { networks: ['fd00::/8', 100.90.0.0/16] }\n";
        let mut store = Store::default();
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let mesh = kith_mesh::prefix(b"a cluster");
        let first = statuses(&store, mesh, people(), true);
        let peer = first
            .iter()
            .find(|(key, _)| key == "RemotePeer/phone-1")
            .expect("the peer is given");
        assert!(
            peer.1["addresses"]["ipv4"]
                .as_str()
                .is_some_and(|four| four.starts_with("100.89."))
        );
        let level = first
            .iter()
            .find(|(key, _)| key == "AccessLevel/family")
            .expect("the level is refused");
        assert!(
            level.1["refused"]
                .as_str()
                .is_some_and(|why| why.contains("overlaps the mesh's /48"))
        );
        kith_store::run(&mut store, Command::Patch { statuses: first }).unwrap();
        assert!(statuses(&store, mesh, people(), true).is_empty());
    }

    /// The table `up` writes, on a kernel with no masquerade here (this namespace): without its
    /// masquerade rules, and saying so (as kith-mesh's own tests do).
    fn table_here(people64: Ipv6Addr) -> std::io::Result<()> {
        match kith_mesh::people::send(people64, &[], &[], "kith0", &[]) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("this kernel has no masquerade here: without");
                kith_mesh::people::send_without_masquerade(people64, &[], &[], "kith0", &[])
            }
            done => done,
        }
    }

    /// The people device (docs/adr-people.md, "Built"), in a namespace of its own: with the flag,
    /// kwg0 holds this node's key, the port, its two addresses and no peers, behind the table, and
    /// its public key is said; a second start keeps the key and empties the peers. Without the
    /// flag, the start itself takes all of that away.
    #[tokio::test]
    async fn people_device() {
        use base64::Engine as _;
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: set KITH_E2E=1 under unshare -Urn");
        }
        let alone = std::fs::read_to_string("/proc/net/dev")
            .is_ok_and(|dev| dev.lines().skip(2).all(|line| line.trim_start().starts_with("lo:")));
        if !alone {
            return eprintln!("skipped: not in a network namespace of its own");
        }
        let state = std::env::temp_dir().join(format!("kithd-people-{}", std::process::id()));
        std::fs::create_dir_all(state.join("pki")).unwrap();
        let (port, people64) = (51821, people());
        let ca = crate::pki::Ca::create().unwrap();
        let me = crate::cluster::pinned_peer::node(&ca, "a");
        let shared = crate::cluster::pinned_peer::shared_with("people-device", me, &[]).await;

        let key = super::up_with(&state, port, people64, || table_here(people64)).expect("the device comes up");
        let peer = kith_mesh::Peer {
            key: [7; 32],
            endpoint: None,
            allowed: vec![(IpAddr::V4(Ipv4Addr::new(100, 89, 0, 2)), 32)],
            keepalive: 0,
        };
        kith_mesh::people::set_peers_for_tests(std::slice::from_ref(&peer)).expect("a peer is seeded");
        assert_eq!(
            kith_mesh::people::device_found().unwrap().unwrap().peers,
            1,
            "a peer is there"
        );
        assert_eq!(
            super::up_with(&state, port, people64, || table_here(people64)).unwrap(),
            key,
            "a start keeps the key"
        );
        let file = state.join("pki").join("people.key");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);

        assert!(kith_mesh::people::table_present().unwrap(), "the table is in place");
        let found = kith_mesh::people::device_found().unwrap().expect("kwg0 is up");
        assert_eq!(found.public_key, key);
        assert_eq!(found.port, port);
        assert_eq!(found.peers, 0);
        assert!(
            found
                .addresses
                .contains(&(IpAddr::V4(Ipv4Addr::new(100, 89, 0, 1)), 16))
        );
        let six = Ipv6Addr::from(u128::from(people64) | 1);
        assert!(found.addresses.contains(&(IpAddr::V6(six), 64)));

        let said = super::said(Some(&key), port, None);
        assert_eq!(said["port"].as_u64(), Some(u64::from(port)));
        assert!(said["endpoint"].is_null());
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        assert_eq!(said["publicKey"].as_str(), Some(encoded.as_str()));

        // Without the flag, the start itself takes what the last one left away (the peer too).
        let (stop, stopping) = tokio::sync::watch::channel(false);
        stop.send(true).unwrap();
        super::device(shared, state.clone(), None, None, "kith0".into(), stopping).await;
        assert!(kith_mesh::people::device_found().unwrap().is_none(), "kwg0 is gone");
        assert!(!kith_mesh::people::table_present().unwrap(), "the table is gone");
        assert!(super::said(None, port, None).is_null());
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A start whose device does not come up takes back what an earlier start said of it, so no
    /// status names a device that is not there. (No pki directory: the key cannot be made, so no
    /// netlink is reached and no root is needed.)
    #[tokio::test]
    async fn a_start_whose_device_fails_takes_back_its_status() {
        let ca = crate::pki::Ca::create().unwrap();
        let me = crate::cluster::pinned_peer::node(&ca, "a");
        let upstream = crate::view::Upstream {
            name: "a".into(),
            address: "127.0.0.1:1".into(),
            certificate: None,
        };
        let shared = crate::cluster::pinned_peer::shared_with("people-failed", me, &[upstream]).await;
        {
            // (Set in the store as `shared_of` sets a Node's status.)
            let said_before = super::said(Some(&[7; 32]), 51821, None);
            let mut state = shared.store.lock().expect("nothing panics holding the store");
            state
                .store
                .set_status("Node/a", Some(serde_json::json!({ "people": said_before })))
                .unwrap();
        }
        // (A leader of its own, as `leading` in raft.rs makes one: the take-back is a write.)
        let id = shared.raft.metrics().borrow().id;
        let one = std::collections::BTreeMap::from([(id, kith_store::openraft::BasicNode::new(""))]);
        shared.raft.initialize(one).await.unwrap();
        shared
            .raft
            .wait(Some(Duration::from_secs(30)))
            .current_leader(id, "leads")
            .await
            .unwrap();

        let state = std::env::temp_dir().join(format!("kithd-people-failed-{}", std::process::id()));
        let (_stop, stopping) = tokio::sync::watch::channel(false);
        super::device(shared.clone(), state, Some(51821), None, "kith0".into(), stopping).await;

        let store = shared.store.lock().expect("nothing panics holding the store");
        let status = store.store.get("Node/a").unwrap().status.as_ref().unwrap();
        assert!(status["people"].is_null(), "the status no longer names the device");
    }

    /// The masquerade message: a kernel with no nftables masquerade says so (CONFIG_NFT_MASQ), and
    /// any other error is passed on as it is.
    #[test]
    fn no_masquerade_says_why() {
        let missing = super::no_masquerade(std::io::ErrorKind::NotFound.into());
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(
            missing.to_string(),
            "this kernel has no nftables masquerade (CONFIG_NFT_MASQ): --people needs it"
        );
        let other = super::no_masquerade(std::io::Error::other("elsewhere"));
        assert_eq!(other.to_string(), "elsewhere");
    }
}
