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

// ── A phone gets in (docs/adr-people.md, "How a configuration is shown once") ──────────

/// The body of `POST /v1/peers`: a name, the node that ends the tunnel, and the AccessLevel.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Add {
    pub name: String,
    pub node: String,
    pub level: String,
}

/// `POST /v1/peers`: makes a WireGuard key, applies a RemotePeer holding its public half as the
/// caller, and answers the peer's configuration once, which holds the private half and is kept
/// nowhere here. No cache may keep the answer.
pub async fn add(
    axum::extract::State(shared): axum::extract::State<Arc<Shared>>,
    axum::Extension(caller): axum::Extension<crate::access::Caller>,
    axum::Json(body): axum::Json<Add>,
) -> axum::response::Response {
    answer(&shared, &caller, body, kith_mesh::public_of).await
}

/// `add`, with the public half of a private key made by `derive` (the kernel's, but for a test).
pub(crate) async fn answer(
    shared: &Arc<Shared>,
    caller: &crate::access::Caller,
    body: Add,
    derive: impl FnOnce(&kith_mesh::Key) -> std::io::Result<kith_mesh::Key>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let said = match added(shared, caller, body, derive).await {
        Ok(said) => axum::Json(said).into_response(),
        Err(refused) => refused,
    };
    crate::cluster::no_store(said)
}

#[allow(clippy::result_large_err)] // the refusal is the answer itself, built once and returned
async fn added(
    shared: &Arc<Shared>,
    caller: &crate::access::Caller,
    body: Add,
    derive: impl FnOnce(&kith_mesh::Key) -> std::io::Result<kith_mesh::Key>,
) -> Result<Value, axum::response::Response> {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use base64::Engine as _;
    let refuse = |status: StatusCode, why: String| crate::cluster::refuse(status, why).into_response();
    let b64 = &base64::engine::general_purpose::STANDARD;
    let Some(cluster) = &shared.cluster else {
        let why = "this kithd is not part of a cluster (start it with --listen)".to_string();
        return Err(refuse(StatusCode::NOT_FOUND, why));
    };
    let kind = |_: &Store| vec![("RemotePeer".to_string(), None)];
    crate::api::permit(shared, caller, kith_api::kinds::Verb::Apply, kind).map_err(IntoResponse::into_response)?;
    let people64 = prefix(&cluster.me.ca);
    // (A name or a level that is no name is refused before anything is looked up or made.)
    peer_of(None, &body, "").map_err(|why| refuse(StatusCode::UNPROCESSABLE_ENTITY, why))?;

    // What is asked of the store: the node's word of its device, the level, and the other peers.
    let (people, level, mut asked, existing) = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let store = &state.store;
        let not_found = |what: &str, name: &str| refuse(StatusCode::NOT_FOUND, format!("no {what} {name}"));
        let node = store
            .get(&format!("Node/{}", body.node))
            .ok_or_else(|| not_found("Node", &body.node))?;
        let level = store
            .get(&format!("AccessLevel/{}", body.level))
            .ok_or_else(|| not_found("AccessLevel", &body.level))?;
        let people = node.status.as_ref().and_then(|status| status.get("people"));
        let Some(people) = people.filter(|people| people.is_object()) else {
            let why = format!(
                "{} says nothing of a people device: start it with --people and --people-endpoint, and ask again",
                body.node
            );
            return Err(refuse(StatusCode::CONFLICT, why));
        };
        if let Some(why) = level.status.as_ref().and_then(|status| status["refused"].as_str()) {
            return Err(refuse(
                StatusCode::CONFLICT,
                format!("AccessLevel {}: {why}", body.level),
            ));
        }
        let spec = serde_json::from_value::<AccessLevelSpec>(level.spec.clone());
        let spec = spec.map_err(|e| {
            refuse(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("AccessLevel {}: {e}", body.level),
            )
        })?;
        let mut asked = Vec::new();
        for peer in store
            .list(Some("RemotePeer"))
            .filter(|peer| peer.metadata.name != body.name)
        {
            if let Ok(spec) = serde_json::from_value::<RemotePeerSpec>(peer.spec.clone()) {
                asked.push(Asked {
                    name: peer.metadata.name.clone(),
                    key: spec.public_key,
                    held: held(peer),
                });
            }
        }
        let existing = store.get(&format!("RemotePeer/{}", body.name)).cloned();
        (people.clone(), spec, asked, existing)
    };

    // The key is made here, shown once and kept by nothing: only its public half goes on.
    let mut private = [0u8; 32];
    let random = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut private);
    random.map_err(|_| {
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no random numbers to make a key from".into(),
        )
    })?;
    private[0] &= 248;
    private[31] = (private[31] & 127) | 64;
    let public = derive(&private).map_err(|e| {
        let why = format!("making the public key of the new key took the kernel's WireGuard, and root: {e}");
        refuse(StatusCode::INTERNAL_SERVER_ERROR, why)
    })?;

    // Its addresses are the ones the leader's plan gives it: refused here, no key is applied.
    asked.push(Asked {
        name: body.name.clone(),
        key: b64.encode(public),
        held: existing.as_ref().and_then(held),
    });
    let pair = match plan(&asked, people64).remove(&body.name) {
        Some(Said::Given(four, six)) => (four, six),
        Some(Said::Refused(why, _)) => return Err(refuse(StatusCode::CONFLICT, format!("{}: {why}", body.name))),
        None => {
            return Err(refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the plan has no word of the peer".into(),
            ));
        }
    };
    let text = config(
        &private,
        pair,
        &level,
        &people,
        crate::mesh::prefix(&cluster.me.ca),
        people64,
    )
    .map_err(|why| refuse(StatusCode::CONFLICT, format!("{}'s people: {why}", body.node)))?;

    let resource =
        peer_of(existing, &body, &b64.encode(public)).map_err(|why| refuse(StatusCode::UNPROCESSABLE_ENTITY, why))?;
    crate::api::applied(shared, caller, vec![resource])
        .await
        .map_err(IntoResponse::into_response)?;
    Ok(json!({
        "name": body.name,
        "node": body.node,
        "level": body.level,
        "publicKey": b64.encode(public),
        "addresses": {"ipv4": pair.0.to_string(), "ipv6": pair.1.to_string()},
        "config": text,
    }))
}

/// The RemotePeer `body` asks for, with `public` (base64) as its key: the one already there with
/// its labels kept, or a new one. Validated. An empty `public` is a stand-in key, for the name's check.
fn peer_of(existing: Option<Resource>, body: &Add, public: &str) -> Result<Resource, String> {
    use base64::Engine as _;
    let stand_in = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    let mut metadata = existing.map_or_else(
        || kith_api::Metadata {
            name: body.name.clone(),
            namespace: None,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            revision: None,
        },
        |old| old.metadata,
    );
    metadata.revision = None;
    Resource {
        api_version: kith_api::API_VERSION.to_string(),
        kind: "RemotePeer".to_string(),
        metadata,
        spec: json!({
            "node": body.node,
            "level": body.level,
            "publicKey": if public.is_empty() { &stand_in } else { public },
        }),
        status: None,
    }
    .validated()
}

/// Is this `host:port` a place to send to: an IPv4 address, a bracketed IPv6 one or a DNS name
/// (letters, digits, `-` and `.`), and a port of 1 to 65535? Nothing else is let into a line of
/// a configuration, whatever a node says of itself.
fn reachable(endpoint: &str) -> bool {
    if endpoint.parse::<std::net::SocketAddr>().is_ok_and(|at| at.port() != 0) {
        return true;
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return false;
    };
    let name = !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        && !host.starts_with(['-', '.'])
        && !host.ends_with(['-', '.']);
    let number = !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit());
    name && number && port.parse::<u16>().is_ok_and(|port| port != 0)
}

/// A range of a level's `networks`, as the configuration writes it: an address and a length.
fn range(net: &str) -> Result<String, String> {
    let wrong = || format!("the level's network {net:?} is not an address and a length");
    let (address, length) = net.split_once('/').ok_or_else(wrong)?;
    let address: IpAddr = address.parse().map_err(|_| wrong())?;
    let most = if address.is_ipv4() { 32 } else { 128 };
    let digits = !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit());
    match length.parse::<u8>() {
        Ok(length) if digits && length <= most => Ok(format!("{address}/{length}")),
        _ => Err(wrong()),
    }
}

/// The configuration a phone takes in (WireGuard's own format, docs/adr-people.md): the peer's
/// addresses and level's resolver, and the node's people device, which it sends everything to for
/// a level with the internet or an Exit, and otherwise the level's ranges, its Services' /80 and
/// the node's own people addresses (and the resolver, if none of them is it). `node` is the
/// node's `people` status; each value of it and of the level is checked and written again, so that
/// no line of the configuration is another's.
fn config(
    private: &kith_mesh::Key,
    (four, six): (Ipv4Addr, Ipv6Addr),
    level: &AccessLevelSpec,
    node: &Value,
    mesh: Ipv6Addr,
    people: Ipv6Addr,
) -> Result<String, String> {
    use base64::Engine as _;
    let b64 = &base64::engine::general_purpose::STANDARD;
    let public = node
        .get("publicKey")
        .and_then(Value::as_str)
        .and_then(|text| b64.decode(text).ok());
    let public = public
        .filter(|key| key.len() == 32)
        .ok_or("its people key is not a WireGuard key")?;
    let endpoint = node.get("endpoint").and_then(Value::as_str);
    let endpoint = endpoint.ok_or("it has no --people-endpoint: the phone would have nowhere to send to")?;
    if !reachable(endpoint) {
        return Err(format!("its --people-endpoint {endpoint:?} is not host:port"));
    }
    let dns = match level.dns.as_deref() {
        Some(text) => Some(
            text.parse::<IpAddr>()
                .map_err(|_| format!("the level's dns {text:?} is not an address"))?,
        ),
        None => None,
    };
    let mut allowed = level
        .networks
        .iter()
        .map(|net| range(net))
        .collect::<Result<Vec<_>, _>>()?;
    if level.internet == Some(true) || level.exit.is_some() {
        allowed = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
    } else {
        if !level.services.is_empty() {
            let mut services = kith_mesh::service_address(mesh, "", "").octets();
            services[10..].fill(0);
            allowed.push(format!("{}/80", Ipv6Addr::from(services)));
        }
        allowed.push(format!("{}/32", Ipv4Addr::from(u32::from(RANGE) | 1)));
        allowed.push(format!("{}/128", Ipv6Addr::from(u128::from(people) | 1)));
        if let Some(dns) = dns {
            let own = format!("{dns}/{}", if dns.is_ipv4() { 32 } else { 128 });
            if !allowed.contains(&own) {
                allowed.push(own);
            }
        }
    }
    let dns = dns.map_or(String::new(), |dns| format!("DNS = {dns}\n"));
    Ok(format!(
        "[Interface]\nPrivateKey = {}\nAddress = {four}/32, {six}/128\n{dns}\n[Peer]\nPublicKey = {}\nEndpoint = {endpoint}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
        b64.encode(private),
        b64.encode(public),
        allowed.join(", "),
    ))
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

    // ── POST /v1/peers (docs/adr-people.md, "How a configuration is shown once") ──────────

    use crate::access::Caller;
    use axum::http::StatusCode;
    use base64::Engine as _;

    /// What the kernel would say of a private key, for a test with no root: any fixed map of it.
    fn derive(key: &kith_mesh::Key) -> std::io::Result<kith_mesh::Key> {
        Ok(key.map(|byte| byte ^ 0x5a))
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The people key n1 says it has.
    const NODE_KEY: kith_mesh::Key = [9; 32];

    fn level(spec: Value) -> AccessLevelSpec {
        serde_json::from_value(spec).unwrap()
    }

    fn n1_says() -> Value {
        said(Some(&NODE_KEY), 51821, Some("127.0.0.1:51821"))
    }

    fn pair() -> (Ipv4Addr, Ipv6Addr) {
        addresses(people(), 0x0203, 0x5e6f)
    }

    fn mesh64() -> Ipv6Addr {
        crate::mesh::prefix("a cluster")
    }

    /// The value of the line `name = ...` of a configuration.
    fn line<'a>(config: &'a str, name: &str) -> &'a str {
        let found = config.lines().find_map(|line| line.strip_prefix(&format!("{name} = ")));
        found.unwrap_or_else(|| panic!("no {name} line in {config}"))
    }

    /// The configuration, for a peer of the address pair above and the private key `[1; 32]`.
    fn config_of(level_spec: Value, node: &Value) -> Result<String, String> {
        config(&[1; 32], pair(), &level(level_spec), node, mesh64(), people())
    }

    #[test]
    fn peers_config_of_a_level_with_internet_sends_everything() {
        let text = config_of(json!({"internet": true, "dns": "10.1.0.53"}), &n1_says()).unwrap();
        let (four, six) = pair();
        let want = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {four}/32, {six}/128\nDNS = 10.1.0.53\n\n[Peer]\nPublicKey = {}\nEndpoint = 127.0.0.1:51821\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
            b64(&[1; 32]),
            b64(&NODE_KEY),
        );
        assert_eq!(text, want);
        assert_eq!(four, Ipv4Addr::new(100, 89, 2, 3));
        // An Exit is the internet too, and a level of neither is not.
        let exit = config_of(json!({"exit": "home", "dns": "fd00::53"}), &n1_says()).unwrap();
        assert_eq!(line(&exit, "AllowedIPs"), "0.0.0.0/0, ::/0");
        assert_eq!(line(&exit, "DNS"), "fd00::53");
        let none = config_of(json!({"internet": false, "dns": "10.1.0.53"}), &n1_says()).unwrap();
        assert_ne!(line(&none, "AllowedIPs"), "0.0.0.0/0, ::/0");
    }

    #[test]
    fn peers_config_of_a_level_without_it_names_ranges_services_and_the_node() {
        let spec = json!({"networks": ["192.168.0.0/16", "fd12::/16"], "services": ["web/api"], "dns": "10.1.0.53"});
        let text = config_of(spec, &n1_says()).unwrap();
        // (The Services' /80 of the mesh's /48: every Service is in it.)
        let mut services = mesh64().octets();
        services[6..10].fill(0xff);
        services[10..].fill(0);
        let node6 = Ipv6Addr::from(u128::from(people()) | 1);
        let want = format!(
            "192.168.0.0/16, fd12::/16, {}/80, 100.89.0.1/32, {node6}/128, 10.1.0.53/32",
            Ipv6Addr::from(services)
        );
        assert_eq!(line(&text, "AllowedIPs"), want);
        // No Service named: no /80. The level's resolver is there whatever else is (once).
        let spec = json!({"networks": ["10.1.0.53/32"], "dns": "10.1.0.53"});
        let text = config_of(spec, &n1_says()).unwrap();
        assert_eq!(
            line(&text, "AllowedIPs"),
            format!("10.1.0.53/32, 100.89.0.1/32, {node6}/128")
        );
        // A level with no resolver gives no DNS line.
        let text = config_of(json!({"networks": ["10.0.0.0/8"]}), &n1_says()).unwrap();
        assert!(!text.contains("DNS"), "{text}");
    }

    #[test]
    fn peers_config_is_made_of_nothing_a_node_could_smuggle_in() {
        let said = |people: Value| config_of(json!({"internet": true, "dns": "10.1.0.53"}), &people);
        for endpoint in [
            "x.example:51821\nPostUp = reboot",
            "x.example:51821 ",
            "x.example",
            "x.example:0",
            "x.example:70000",
            "[::1]:",
            "a b:1",
            "",
        ] {
            let mut people = n1_says();
            people["endpoint"] = json!(endpoint);
            assert!(said(people).is_err(), "{endpoint:?}");
        }
        for key in ["short", "", &b64(&[1; 33])] {
            let mut people = n1_says();
            people["publicKey"] = json!(key);
            assert!(said(people).is_err(), "{key:?}");
        }
        for dns in ["10.1.0.53\nPostUp = reboot", "not an address", "10.1.0.53/32"] {
            let spec = json!({"internet": true, "dns": dns});
            assert!(config_of(spec, &n1_says()).is_err(), "{dns:?}");
        }
        let spec = json!({"networks": ["10.0.0.0/8\nPostUp = reboot"], "dns": "10.1.0.53"});
        assert!(config_of(spec, &n1_says()).is_err());
        // A host name and a bracketed IPv6 address are an endpoint.
        for endpoint in ["vpn.example.net:51821", "[fd00::1]:51821", "127.0.0.1:1"] {
            let mut people = n1_says();
            people["endpoint"] = json!(endpoint);
            let text = said(people).unwrap();
            assert_eq!(line(&text, "Endpoint"), endpoint);
        }
        // A node that states none gives none to send to.
        let mut people = n1_says();
        people["endpoint"] = Value::Null;
        assert!(said(people).unwrap_err().contains("people-endpoint"));
    }

    const LEVELS: &str = "
apiVersion: kith.dev/v1
kind: AccessLevel
metadata: {name: family}
spec: {internet: true, dns: 10.1.0.53}
---
apiVersion: kith.dev/v1
kind: AccessLevel
metadata: {name: friends}
spec: {networks: [192.168.0.0/16], services: ['*'], dns: 10.1.0.53}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: bob}
spec: {}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: peers}
spec:
  rules:
    - {kinds: [RemotePeer], verbs: [apply]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: bob-peers}
spec: {role: peers, subjects: [bob]}
";

    /// n1 of a one-node cluster that leads itself, saying `people` of its device, with the
    /// levels above and an Identity, bob, who may apply RemotePeers.
    async fn leader(tag: &str, people: Value) -> Arc<Shared> {
        let ca = crate::pki::Ca::create().unwrap();
        let me = crate::cluster::pinned_peer::node(&ca, "n1");
        let up = crate::view::Upstream {
            name: "n1".into(),
            address: "127.0.0.1:1".into(),
            certificate: None,
        };
        let cluster = crate::cluster::Cluster::new(me, Some(ca)).unwrap();
        let shared = crate::cluster::pinned_peer::shared_of(tag, cluster, &[up]).await;
        {
            let mut state = shared.store.lock().unwrap();
            let mut status = state.store.get("Node/n1").unwrap().status.clone().unwrap();
            status["people"] = people;
            state.store.set_status("Node/n1", Some(status)).unwrap();
            for resource in Resource::from_source(LEVELS).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        let id = shared.raft.metrics().borrow().id;
        let leads = shared.raft.wait(Some(Duration::from_secs(30)));
        leads.current_leader(id, "leads").await.unwrap();
        shared
    }

    /// POST /v1/peers as `caller`: the status, the Cache-Control, and the JSON of the answer.
    async fn ask(
        shared: &Arc<Shared>,
        caller: Caller,
        name: &str,
        node: &str,
        level: &str,
    ) -> (StatusCode, String, Value) {
        let body = Add {
            name: name.into(),
            node: node.into(),
            level: level.into(),
        };
        let answer = super::answer(shared, &caller, body, derive).await;
        let kept = answer.headers().get(axum::http::header::CACHE_CONTROL);
        let kept = kept.map(|kept| kept.to_str().unwrap().to_string()).unwrap_or_default();
        let status = answer.status();
        let bytes = axum::body::to_bytes(answer.into_body(), 1 << 20).await.unwrap();
        (status, kept, serde_json::from_slice(&bytes).unwrap())
    }

    fn private_of(answer: &Value) -> kith_mesh::Key {
        let text = line(answer["config"].as_str().unwrap(), "PrivateKey");
        let bytes = base64::engine::general_purpose::STANDARD.decode(text).unwrap();
        bytes.try_into().unwrap()
    }

    fn found_in(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|window| window == needle)
    }

    /// The private key is in no store, revision, audit line or file under the data directory
    /// (the raft log, the units' logs, the audit file), in text or as bytes.
    fn nowhere(shared: &Shared, tag: &str, private: &kith_mesh::Key) {
        let needles = [b64(private).into_bytes(), hex(private).into_bytes(), private.to_vec()];
        let mut hay: Vec<Vec<u8>> = Vec::new();
        {
            let state = shared.store.lock().unwrap();
            for resource in state.store.list(None) {
                hay.push(serde_json::to_vec(resource).unwrap());
                hay.push(serde_json::to_vec(state.store.history(&resource.key()).unwrap()).unwrap());
            }
        }
        hay.push(serde_json::to_vec(&shared.audit.tail(1000).unwrap()).unwrap());
        let mut dirs = vec![std::env::temp_dir().join(format!("kithd-pinned-{tag}-{}", std::process::id()))];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                match entry.path() {
                    path if path.is_dir() => dirs.push(path),
                    path => hay.extend(std::fs::read(path)),
                }
            }
        }
        assert!(hay.len() > 3, "the store and the data directory were read");
        for needle in &needles {
            assert!(!hay.iter().any(|hay| found_in(hay, needle)), "the private key was kept");
        }
    }

    /// The answer is kept by no cache, holds the configuration with the private key once, and
    /// the RemotePeer stored holds only the public half, which the kernel gives of that key.
    #[tokio::test]
    async fn peers_route_answers_once_and_keeps_only_the_public_key() {
        let shared = leader("peers-route", n1_says()).await;
        let (status, kept, answer) = ask(&shared, Caller::Admin, "phone", "n1", "family").await;
        assert_eq!((status, kept.as_str()), (StatusCode::OK, "no-store"), "{answer}");
        let private = private_of(&answer);
        assert_ne!(private, [0; 32]);
        let (name, node, level) = (&answer["name"], &answer["node"], &answer["level"]);
        assert_eq!((name, node, level), (&json!("phone"), &json!("n1"), &json!("family")));
        let config = answer["config"].as_str().unwrap();
        assert_eq!(line(config, "PublicKey"), b64(&NODE_KEY));

        let public = b64(&derive(&private).unwrap());
        assert_eq!(answer["publicKey"], json!(public));
        assert_ne!(public, b64(&private));
        {
            let state = shared.store.lock().unwrap();
            let stored = state.store.get("RemotePeer/phone").expect("the RemotePeer is applied");
            assert_eq!(
                stored.spec,
                json!({"node": "n1", "level": "family", "publicKey": public})
            );
            // The addresses it was told are the ones the leader's plan gives it.
            let (four, six) = (
                answer["addresses"]["ipv4"].as_str(),
                answer["addresses"]["ipv6"].as_str(),
            );
            let (offset, iid) = drawn("phone");
            let (want4, want6) = addresses(prefix(&shared.cluster.as_ref().unwrap().me.ca), offset, iid);
            assert_eq!(
                (four, six),
                (Some(want4.to_string().as_str()), Some(want6.to_string().as_str()))
            );
            assert!(line(config, "Address").starts_with(&format!("{want4}/32, {want6}/128")));
        }
        // Applied as the caller: the audit line says who and what, and no key.
        let audit = shared.audit.tail(50).unwrap();
        let line = audit
            .iter()
            .find(|line| line["what"].to_string().contains("RemotePeer/phone"));
        assert_eq!(line.expect("an audit line")["verb"], json!("apply"));
        nowhere(&shared, "peers-route", &private);
    }

    /// An Identity with no right to apply RemotePeers gets a 403 (kept by no cache) and nothing
    /// is made; one with the right is let in, and its name is on what it made.
    #[tokio::test]
    async fn peers_route_refuses_an_identity_that_may_not_apply_remote_peers() {
        let shared = leader("peers-route-403", n1_says()).await;
        let (status, kept, answer) = ask(&shared, Caller::Identity("carol".into()), "phone", "n1", "family").await;
        assert_eq!((status, kept.as_str()), (StatusCode::FORBIDDEN, "no-store"), "{answer}");
        assert!(answer["error"].as_str().unwrap().contains("carol"), "{answer}");
        assert!(!answer.to_string().contains("PrivateKey"));
        assert!(shared.store.lock().unwrap().store.get("RemotePeer/phone").is_none());
        let (status, _, answer) = ask(&shared, Caller::Identity("bob".into()), "phone", "n1", "family").await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert!(shared.store.lock().unwrap().store.get("RemotePeer/phone").is_some());
    }

    /// Asked again for a name, a new key replaces the old one: the RemotePeer holds the new
    /// public key only, and the old configuration's key is no longer anywhere.
    #[tokio::test]
    async fn peers_route_asked_again_replaces_the_key() {
        let shared = leader("peers-route-again", n1_says()).await;
        let (_, _, first) = ask(&shared, Caller::Admin, "phone", "n1", "family").await;
        let (status, _, second) = ask(&shared, Caller::Admin, "phone", "n1", "friends").await;
        assert_eq!(status, StatusCode::OK, "{second}");
        let (old, new) = (private_of(&first), private_of(&second));
        assert_ne!(old, new);
        assert_eq!(first["addresses"], second["addresses"], "a name keeps its addresses");
        {
            let state = shared.store.lock().unwrap();
            assert_eq!(state.store.list(Some("RemotePeer")).count(), 1);
            let stored = state.store.get("RemotePeer/phone").unwrap();
            assert_eq!(stored.spec["publicKey"], json!(b64(&derive(&new).unwrap())));
            assert_eq!(stored.spec["level"], json!("friends"));
        }
        // (The first key is in the history as a public key only: its private half is nowhere.)
        nowhere(&shared, "peers-route-again", &old);
        nowhere(&shared, "peers-route-again", &new);
    }

    /// A node with no people status (no `--people`, or no device), or none that is a key, gives
    /// no configuration and nothing is applied: the answer says why.
    #[tokio::test]
    async fn peers_config_refused_for_a_node_with_no_people() {
        let shared = leader("peers-config-none", Value::Null).await;
        let (status, kept, answer) = ask(&shared, Caller::Admin, "phone", "n1", "family").await;
        assert_eq!((status, kept.as_str()), (StatusCode::CONFLICT, "no-store"), "{answer}");
        let why = answer["error"].as_str().unwrap();
        assert!(why.contains("n1") && why.contains("--people"), "{why}");
        assert!(answer.get("config").is_none());
        assert!(shared.store.lock().unwrap().store.get("RemotePeer/phone").is_none());
        // A node or a level that is not there is not found.
        let (status, ..) = ask(&shared, Caller::Admin, "phone", "n9", "family").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, ..) = ask(&shared, Caller::Admin, "phone", "n1", "gone").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // A name that is not a name is refused, whoever asks.
        let (status, ..) = ask(&shared, Caller::Admin, "Not A Name", "n1", "family").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A peer the leader would refuse (its address is another peer's) gets no configuration: the
    /// answer says what the status would, and no key is made into the store.
    #[tokio::test]
    async fn peers_config_refused_for_a_peer_the_leader_would_refuse() {
        let shared = leader("peers-config-refused", n1_says()).await;
        {
            let mut state = shared.store.lock().unwrap();
            apply_peer(&mut state.store, "squatter", KEY);
            let (offset, iid) = drawn("phone");
            let (four, six) = addresses(prefix(&shared.cluster.as_ref().unwrap().me.ca), offset, iid);
            let held = json!({"addresses": {"ipv4": four.to_string(), "ipv6": six.to_string()}});
            state.store.set_status("RemotePeer/squatter", Some(held)).unwrap();
        }
        let (status, kept, answer) = ask(&shared, Caller::Admin, "phone", "n1", "family").await;
        assert_eq!((status, kept.as_str()), (StatusCode::CONFLICT, "no-store"), "{answer}");
        let why = answer["error"].as_str().unwrap();
        assert!(why.contains("squatter") && why.contains("name it otherwise"), "{why}");
        assert!(answer.get("config").is_none());
        assert!(shared.store.lock().unwrap().store.get("RemotePeer/phone").is_none());
    }

    /// The kernel's own public key (RFC 7748, 6.1: Alice's), through a link made for the one
    /// call and taken away again: in a network namespace of its own, as `people_device` is.
    #[test]
    fn peers_route_real_kernel_gives_the_public_key() {
        if std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: set KITH_E2E=1 under unshare -Urn");
        }
        let unhex = |text: &str| -> kith_mesh::Key {
            let byte = |at: usize| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap();
            std::array::from_fn(byte)
        };
        let private = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let public = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(kith_mesh::public_of(&private).unwrap(), public);
        // (Twice: the link of the first is gone.)
        assert_eq!(kith_mesh::public_of(&private).unwrap(), public);
        let links = std::fs::read_to_string("/proc/net/dev").unwrap();
        assert!(!links.contains("wgk"), "{links}");
    }
}
