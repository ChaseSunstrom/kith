//! The people's addresses (docs/adr-people.md, "Addresses come from the name"). Each RemotePeer
//! is given an IPv4 in `100.89.0.0/16` and an IPv6 in the cluster's people /64, both from its
//! name, and keeps them in its status once given. The leader writes them: a later peer with a
//! taken address, or a public key that two peers hold, is refused in status and named. An
//! AccessLevel whose network lies over the mesh's /48 or the people /64 is refused the same way.
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

/// What the leader says of a RemotePeer: its two addresses, or why it has none.
#[derive(Debug, PartialEq)]
pub enum Said {
    Given(Ipv4Addr, Ipv6Addr),
    Refused(String),
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
            return Err(format!("{four} is {other}'s: name it otherwise"));
        }
        if let Some(other) = self.six.get(&six) {
            return Err(format!("{six} is {other}'s: name it otherwise"));
        }
        self.four.insert(four, name.to_string());
        self.six.insert(six, name.to_string());
        Ok(())
    }
}

/// What each RemotePeer is given, by name. A public key on two or more peers refuses each of
/// them, naming another. The addresses already held are kept first, by name; the others draw
/// from their names, and a draw at the range's ends or one taken is refused, naming the holder.
pub fn plan(asked: &[Asked], people: Ipv6Addr) -> BTreeMap<String, Said> {
    let mut said = BTreeMap::new();
    let mut by_key: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for peer in asked {
        by_key.entry(peer.key.as_str()).or_default().push(peer.name.as_str());
    }
    let mut order: Vec<&Asked> = Vec::new();
    for peer in asked {
        let holders = &by_key[peer.key.as_str()];
        match holders.iter().copied().find(|other| *other != peer.name.as_str()) {
            Some(other) => {
                let why = format!("publicKey: the same as {other}'s: name it otherwise");
                said.insert(peer.name.clone(), Said::Refused(why));
            }
            None => order.push(peer),
        }
    }
    order.sort_by(|a, b| a.name.cmp(&b.name));

    let mut held = Held::default();
    let mut draws = Vec::new();
    for peer in order {
        match peer.held.filter(|&pair| ours(people, pair)) {
            Some(pair) => {
                let now = match held.take(&peer.name, pair) {
                    Ok(()) => Said::Given(pair.0, pair.1),
                    Err(why) => Said::Refused(why),
                };
                said.insert(peer.name.clone(), now);
            }
            None => draws.push(peer),
        }
    }
    for peer in draws {
        let (offset, iid) = drawn(&peer.name);
        let (four, six) = addresses(people, offset, iid);
        let now = if reserved4(offset) || reserved6(iid) {
            Said::Refused(format!(
                "{four} is the range's first two or last, never given: name it otherwise"
            ))
        } else {
            match held.take(&peer.name, (four, six)) {
                Ok(()) => Said::Given(four, six),
                Err(why) => Said::Refused(why),
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

/// The status fields to write now: a RemotePeer's `addresses` and `refused`, an AccessLevel's
/// `refused`. Nothing is written that the store already says.
pub fn statuses(store: &Store, mesh: Ipv6Addr, people: Ipv6Addr) -> Vec<(String, Map<String, Value>)> {
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
                    ("addresses", json!({"ipv4": four.to_string(), "ipv6": six.to_string()})),
                    ("refused", Value::Null),
                ]
            }
            Said::Refused(why) => vec![("addresses", Value::Null), ("refused", json!(why))],
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
            let statuses = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                statuses(&state.store, mesh, people)
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
            Some(Said::Refused(why)) => why.clone(),
            other => panic!("{name}: {other:?}"),
        }
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
    fn a_key_on_two_peers_refuses_both_naming_the_other() {
        let said = plan(
            &[asked("phone-1", "K"), asked("phone-2", "K"), asked("phone-3", "J")],
            people(),
        );
        assert!(refused(&said, "phone-1").contains("phone-2"));
        assert!(refused(&said, "phone-2").contains("phone-1"));
        given(&said, "phone-3");
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
        let first = statuses(&store, mesh, people());
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
        assert!(statuses(&store, mesh, people()).is_empty());
    }
}
