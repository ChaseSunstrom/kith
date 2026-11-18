//! Copies of a volume on other nodes, one of which takes over when its node is lost.
//!
//! GET /v1/volume-copy/NS/NAME[?have=HASH]   the volume as a tar, or 304      nodes only
//!
//! A Volume with `replicas: N` is on N nodes: the one that has it now (`status.primary`,
//! its `spec.node` to begin with) and N-1 the leader picks (`status.replicas`). Every
//! `sync` (5m unless said) each replica asks the primary for an archive of the directory,
//! unpacks it beside its own copy and puts it in its place, and writes when in
//! `status.synced`. When the primary is not heard from for as long as a lost node's
//! workloads wait (`--lost-after`), the leader makes the replica that synced last the
//! primary: workloads that mount the volume are placed there, on the copy as it was then.
//!
//! What was written after the last sync is not on the replica: a failover loses it.
//
// ponytail: each sync reads the whole volume on the primary and sends all of it when
// anything changed. For data of modest size; send what changed (rsync's way, or a
// filesystem's snapshots) when volumes are large.

use crate::Shared;
use crate::blobs::Incoming;
use crate::cluster::Peer;
use crate::volumes::Dir;
use axum::extract::{ConnectInfo, Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kith_api::store::Store;
use kith_store::Command;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// What a Volume's status says of its copies (kept when the rest of it is worked out again).
pub const FIELDS: [&str; 3] = ["primary", "replicas", "synced"];
/// How often a node looks at what it should bring up to date.
const ROUND: Duration = Duration::from_secs(5);
/// How often a copy is brought up to date, when the Volume does not say.
const SYNC: u64 = 300;
/// A primary that sends nothing for this long is given up on, for this time.
const QUIET: Duration = Duration::from_secs(30);

fn names(value: &Value) -> Vec<String> {
    let names = value.as_array().into_iter().flatten().filter_map(Value::as_str);
    names.map(String::from).collect()
}

/// The leader's part: for each replicated Volume whose `primary` or `replicas` should be
/// other than its status says, what they should be. `lost`: for how long a node has not been
/// heard from (none: it is there).
pub fn writes(
    store: &Store,
    lost: &dyn Fn(&str) -> Option<Duration>,
    grace: Duration,
) -> Vec<(String, Map<String, Value>)> {
    let nodes: Vec<String> = store
        .list(Some("Node"))
        .map(|node| node.metadata.name.clone())
        .collect();
    let there = |node: &str| nodes.iter().any(|name| name == node) && lost(node).is_none();
    let gone = |node: &str| !nodes.iter().any(|name| name == node) || lost(node).is_some_and(|lost| lost >= grace);
    let mut writes = Vec::new();
    for (key, dir, copies) in crate::volumes::replicated(store) {
        let status = store
            .get(&key)
            .and_then(|volume| volume.status.clone())
            .unwrap_or_default();
        let (mut primary, mut replicas) = (dir.node.clone(), names(&status["replicas"]));
        replicas.retain(|node| *node != primary);
        if gone(&primary) {
            // The copy brought up to date last, of those on nodes that are there.
            let synced = |node: &&String| status["synced"][node.as_str()].as_u64();
            let ready = replicas
                .iter()
                .filter(|node| there(node))
                .filter(|node| synced(node).is_some());
            // A worker's copy only when no control node has one, whatever time it says: when
            // it synced is the worker's own word.
            let trusted = |node: &&String| (!crate::access::is_worker(store, node), synced(node));
            if let Some(next) = ready.max_by_key(trusted).cloned() {
                replicas.retain(|node| *node != next);
                primary = next;
            }
        }
        // A replica that is gone gives way to a node that is there, picked the same way
        // whoever leads; one that is only quiet for a moment stays.
        replicas.retain(|node| !gone(node));
        let free: Vec<&str> = nodes.iter().map(String::as_str).filter(|node| there(node)).collect();
        let free: Vec<&str> = free
            .into_iter()
            .filter(|node| *node != primary && !replicas.iter().any(|r| r == node))
            .collect();
        let short = (copies as usize - 1).saturating_sub(replicas.len());
        if short > 0 && !free.is_empty() {
            replicas.extend(crate::blobs::holders(&key, &free, short).into_iter().map(String::from));
        }
        replicas.truncate(copies as usize - 1);
        replicas.sort();
        let mut was = names(&status["replicas"]);
        was.sort();
        // (When a node synced counts only while it is a replica: one picked again starts over.)
        let mut synced = status["synced"].as_object().cloned().unwrap_or_default();
        let before = synced.len();
        synced.retain(|node, _| replicas.contains(node));
        if status["primary"].as_str() != Some(&primary) || was != replicas || synced.len() != before {
            let fields = json!({ "primary": primary, "replicas": replicas, "synced": synced });
            writes.push((key, fields.as_object().expect("an object").clone()));
        }
    }
    writes
}

/// Where this node keeps what it last synced of each volume it is a replica of: a file per
/// volume with the archive's hash in it. None: what is in the volume's directory here is not
/// a copy the primary sent (it was the primary's own, once), and is set aside, not replaced.
fn marker(state: &Path, dir: &Dir) -> PathBuf {
    state.join("replicas").join(&dir.namespace).join(&dir.name)
}

/// Puts the directory at `new` in the place of `dir`. What was in `dir` goes, unless it is
/// not a copy this node was sent (`aside`): then it is kept beside it as `NAME.was-AT`.
fn swap(new: &Path, dir: &Path, aside: Option<u64>) -> std::io::Result<()> {
    let mut old = dir.as_os_str().to_owned();
    old.push(aside.map_or(".old".to_string(), |at| format!(".was-{at}")));
    let old = PathBuf::from(old);
    // (One left here makes the rename below fail, so it is said.)
    if let Err(e) = crate::controller::storage::remove_tree(&old, &|| false)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("kithd: removing {}: {e}", old.display());
    }
    let empty = std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none());
    match std::fs::rename(dir, &old) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Err(e) = std::fs::rename(new, dir) {
        let _ = std::fs::rename(&old, dir);
        return Err(e);
    }
    if (aside.is_none() || empty)
        && let Err(e) = crate::controller::storage::remove_tree(&old, &|| false)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("kithd: removing {}: {e}", old.display());
    }
    Ok(())
}

#[derive(serde::Deserialize)]
pub struct Have {
    have: Option<String>,
}

/// Does the store name `node` among the replicas of the Volume `key`?
fn replica_of(store: &Store, key: &str, node: &str) -> bool {
    let status = store.get(key).and_then(|volume| volume.status.as_ref());
    status.is_some_and(|status| names(&status["replicas"]).iter().any(|replica| replica == node))
}

/// `GET /v1/volume-copy/NS/NAME` (members only): the volume as it is now, if this node has it.
pub async fn copy(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    UrlPath((namespace, name)): UrlPath<(String, String)>,
    Query(have): Query<Have>,
) -> Response {
    let key = format!("Volume/{namespace}/{name}");
    let dir = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        // Only a node the store names among its replicas has a use for the whole of it.
        let asks = match &peer.subject {
            Some(crate::pki::Subject::Node(node, ..)) => node.as_str(),
            _ => "",
        };
        if !replica_of(&state.store, &key, asks) {
            drop(state);
            let why = format!("node {asks} is no replica of {key}");
            let who = crate::access::Caller::Node(asks.to_string());
            let what = vec![format!("/v1/volume-copy/{namespace}/{name}")];
            shared.audit.record(&who, "GET", what, Err(why.clone()));
            return (StatusCode::FORBIDDEN, why).into_response();
        }
        let mine = |(_, dir, _): &(String, Dir, u32)| dir.node == shared.members.me();
        crate::volumes::replicated(&state.store)
            .into_iter()
            .filter(|(k, ..)| *k == key)
            .find(mine)
    };
    let (Some((_, dir, _)), Some(state)) = (dir, shared.logs.parent()) else {
        return (StatusCode::NOT_FOUND, "this node does not have that volume").into_response();
    };
    let state = state.to_path_buf();
    // ponytail: one archive at a time on a node, each of the whole volume even when the
    // answer is that nothing changed; see the top of this file.
    static SENDING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _one = SENDING.lock().await;
    let archived = tokio::task::spawn_blocking(move || {
        let from = crate::volumes::host_dir(&state, &dir)?;
        let temp = state.join("replicas/.sending");
        let (hash, _) = crate::backups::archive(&from, &temp)?;
        // (Read through the open file, which has no name any more: nothing is left behind.)
        let file = std::fs::File::open(temp.join(&hash)).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(temp.join(&hash));
        Ok::<_, String>((hash, file))
    });
    match archived.await.map_err(|e| e.to_string()).and_then(|archived| archived) {
        Ok((hash, _)) if have.have.as_deref() == Some(&hash) => StatusCode::NOT_MODIFIED.into_response(),
        Ok((_, file)) => {
            let size = file.metadata().map_or(0, |file| file.len());
            let body = axum::body::Body::from_stream(crate::blobs::chunks(file));
            ([(axum::http::header::CONTENT_LENGTH, size)], body).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// Whether `me` is a replica of the volume `dir` was (and not the node that has it).
fn replica(store: &Store, dir: &Dir, me: &str) -> bool {
    let now = crate::volumes::dir(store, &dir.namespace, &dir.name);
    let key = format!("Volume/{}/{}", dir.namespace, dir.name);
    let replicas = store
        .get(&key)
        .and_then(|volume| Some(names(&volume.status.as_ref()?["replicas"])));
    now.is_some_and(|now| now.node != me) && replicas.is_some_and(|replicas| replicas.iter().any(|r| r == me))
}

/// How many bytes a sync of `dir` may take: its Volume's size, or no end where it says none.
/// A Volume that is gone, or whose spec does not parse, is not synced at all.
fn cap_of(store: &Store, dir: &Dir) -> Result<u64, String> {
    let size = crate::volumes::size_of(store, &dir.namespace, &dir.name).map_err(|e| format!("{e}: not synced"))?;
    Ok(size.unwrap_or(u64::MAX))
}

/// What was taken in, unpacked beside `into` (to at most `cap` bytes) and then given to
/// `finish`, which puts it in its place: the archive's hash. The archive does not stay, and
/// when it unpacks to more than `cap` the copy in `into` is as it was.
fn place(
    incoming: Incoming,
    temp: &Path,
    into: &Path,
    cap: u64,
    finish: impl FnOnce(PathBuf) -> Result<(), String>,
) -> Result<String, String> {
    let (hash, _) = incoming.keep(None)?;
    let archive = temp.join(&hash);
    // (From this cluster's own node, as it is there: modes and all.)
    let placed = crate::backups::unpack_beside(&archive, into, 0, cap).and_then(finish);
    let _ = std::fs::remove_file(&archive);
    placed.map(|()| hash)
}

/// Puts the unpacked copy `new` in place of `into`, unless this node was made the primary
/// while it came: what is here is the volume itself then, in use, and stays, and `new` is
/// given to `remove`. The store is held for the two renames only: that is decided under it,
/// and the removal runs after it is let go. (Nothing leans on `new` being gone before the
/// store is let go: syncs run one at a time from `run`, and this one does not return before
/// the removal is done, so the next sync of the Volume finds the directory gone.)
#[allow(clippy::too_many_arguments)]
fn put_in(
    store: &std::sync::Mutex<kith_store::State>,
    dir: &Dir,
    me: &str,
    new: &Path,
    into: &Path,
    marker: &Path,
    aside: Option<u64>,
    remove: impl FnOnce(&Path),
) -> Result<(), String> {
    let held = store.lock().expect("a handler panicked holding the store");
    if !replica(&held.store, dir, me) {
        drop(held);
        remove(new);
        return Err("this node is not a replica of it any more".to_string());
    }
    // (No marker while the two are changing places: a crash there starts over.)
    let _ = std::fs::remove_file(marker);
    swap(new, into, aside).map_err(|e| format!("{}: {e}", into.display()))
}

/// Brings this node's copy of `dir` up to date from the node at `address`. The hash of what
/// it has now.
async fn sync(
    shared: &Arc<Shared>,
    client: &reqwest::Client,
    address: &str,
    state: &Path,
    dir: &Dir,
    now: u64,
) -> Result<String, String> {
    let marker = marker(state, dir);
    let have = std::fs::read_to_string(&marker).ok();
    let have = have.as_deref().map(str::trim).filter(|have| crate::blobs::named(have));
    let query = have.map_or(String::new(), |have| format!("?have={have}"));
    let url = format!("https://{address}/v1/volume-copy/{}/{}{query}", dir.namespace, dir.name);
    let slow = |_| format!("nothing came for {} s", QUIET.as_secs());
    let asked = tokio::time::timeout(QUIET * 20, client.get(url).send())
        .await
        .map_err(slow)?;
    let mut answer = asked
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| crate::cluster::why(&e))?;
    if let (StatusCode::NOT_MODIFIED, Some(have)) = (answer.status(), have) {
        return Ok(have.to_string());
    }
    let temp = state.join("replicas/.receiving");
    // (No more than the Volume may hold, where it says: what is sent is another node's say.)
    let cap = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        cap_of(&state.store, dir)?
    };
    let mut incoming = Incoming::new(&temp).map_err(|e| e.to_string())?;
    crate::backups::receive(&mut answer, &mut incoming, QUIET, crate::backups::download_cap(cap)).await?;
    let (state, dir, aside) = (state.to_path_buf(), dir.clone(), have.is_none().then_some(now));
    let shared = shared.clone();
    let placed = tokio::task::spawn_blocking(move || {
        let into = crate::volumes::host_dir(&state, &dir)?;
        let marker = self::marker(&state, &dir);
        let hash = place(incoming, &temp, &into, cap, |new| {
            let me = shared.members.me();
            put_in(&shared.store, &dir, me, &new, &into, &marker, aside, |new| {
                crate::backups::remove_unpacked(new);
            })
        })?;
        let wrote =
            std::fs::create_dir_all(marker.parent().unwrap_or(&state)).and_then(|()| std::fs::write(&marker, &hash));
        wrote.map_err(|e| format!("{}: {e}", marker.display()))?;
        Ok::<_, String>(hash)
    });
    placed.await.map_err(|e| e.to_string())?
}

/// Removes what a stop in the middle of a sync left: a volume's files, which a container wrote.
fn clear_unfinished(state: &Path) {
    for left in [".sending", ".receiving"] {
        // (Levels a failed removal leaves are `scratch.*` in `replicas/`: `files::sweep` removes them.)
        let path = state.join("replicas").join(left);
        if let Err(e) = crate::controller::storage::remove_tree(&path, &|| false)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("kithd: removing {}: {e}", path.display());
        }
    }
}

/// Keeps this node's copies of other nodes' volumes up to date.
pub async fn run(shared: Arc<Shared>, state: PathBuf, mut stopping: watch::Receiver<bool>) {
    let me = shared.members.me().to_string();
    // (When each was last tried, so that one that fails is not asked for every round.)
    let mut tried: BTreeMap<String, u64> = BTreeMap::new();
    // (And what went wrong with each, said once and not every round.)
    let mut said: BTreeMap<String, String> = BTreeMap::new();
    // (What a stop in the middle of a sync left behind.)
    clear_unfinished(&state);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let Some(cluster) = &shared.cluster else { continue };
        let now = kith_api::store::now();
        let (due, mine) = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            let store = &state.store;
            let (mut due, mut mine) = (Vec::new(), Vec::new());
            for (key, dir, _) in crate::volumes::replicated(store) {
                if dir.node == me {
                    mine.push(dir);
                    continue;
                }
                let Some(volume) = store.get(&key) else { continue };
                let status = volume.status.clone().unwrap_or_default();
                if !names(&status["replicas"]).contains(&me) {
                    continue;
                }
                let every = volume.spec["sync"]
                    .as_str()
                    .and_then(kith_api::kinds::every)
                    .unwrap_or(SYNC);
                let last = status["synced"][&me].as_u64().max(tried.get(&key).copied());
                let there = store.get(&format!("Node/{}", dir.node));
                let there = there.and_then(crate::view::Upstream::of);
                if let (true, Some(there)) = (last.is_none_or(|last| now >= last + every), there) {
                    due.push((key, dir, there));
                }
            }
            (due, mine)
        };
        // What this node has as the primary is its own: were it a replica again one day,
        // what is in it then is not a copy it was sent.
        for dir in mine {
            let _ = std::fs::remove_file(marker(&state, &dir));
        }
        for (key, dir, there) in due {
            tried.insert(key.clone(), now);
            // (The node that has the Volume, and not another at its address: its files are its own.)
            let synced = match cluster.to(&there) {
                Ok(client) => sync(&shared, &client, &there.address, &state, &dir, now).await,
                Err(why) => Err(why),
            };
            match synced {
                Ok(_) => {
                    said.remove(&key);
                    // ponytail: each replica writes the whole `synced` with its own time in;
                    // two that write at once can put the other's back by one sync, which its
                    // next sync puts right (a takeover then may pick a copy one sync older).
                    // A status field per node, or a merging Patch, would close it.
                    let synced = {
                        let state = shared.store.lock().expect("a handler panicked holding the store");
                        let was = state
                            .store
                            .get(&key)
                            .and_then(|volume| volume.status.as_ref()?["synced"].as_object().cloned());
                        let mut synced = was.unwrap_or_default();
                        synced.insert(me.clone(), now.into());
                        synced
                    };
                    let fields = json!({ "synced": synced });
                    let statuses = vec![(key.clone(), fields.as_object().expect("an object").clone())];
                    if let Err(e) = shared.submit(Command::Patch { statuses }).await {
                        eprintln!("kithd: volume {key}: that its copy is up to date was not said: {e}");
                    }
                }
                Err(e) => {
                    let saying = format!("not brought up to date from node {}: {e}", dir.node);
                    if said.get(&key) != Some(&saying) {
                        eprintln!("kithd: volume {key}: the copy here was {saying}");
                        said.insert(key, saying);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A volume's files left by a stop in a sync, a chain 2,000 directories deep (more than
    /// `remove_dir_all` holds descriptors for), are freed, and no level is left beside them.
    #[test]
    fn a_deep_chain_left_by_a_stopped_sync_is_freed() {
        crate::controller::storage::tests::few_files(
            concat!(module_path!(), "::a_deep_chain_left_by_a_stopped_sync_is_freed"),
            || {
                let state = std::env::temp_dir().join(format!("kith-replica-deep-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&state);
                let replicas = state.join("replicas");
                for left in [".sending", ".receiving"] {
                    std::fs::create_dir_all(replicas.join(left)).unwrap();
                    crate::controller::storage::tests::chain(&replicas.join(left), 2000);
                }
                clear_unfinished(&state);
                let left: Vec<_> = std::fs::read_dir(&replicas)
                    .unwrap()
                    .flatten()
                    .map(|e| e.file_name())
                    .collect();
                let _ = std::fs::remove_dir_all(&state);
                assert!(left.is_empty(), "{left:?}");
            },
        );
    }

    fn store(status: Value) -> Store {
        let mut store = Store::default();
        let node = |name: &str| json!({ "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": name }, "spec": {} });
        let volume = json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "data" },
            "spec": { "node": "a", "path": "d", "replicas": 2 } });
        let alone = json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "alone" },
            "spec": { "node": "a", "path": "e" } });
        let resources = [node("a"), node("b"), node("c"), volume, alone];
        let resources = resources
            .into_iter()
            .map(|r| serde_json::from_value(r).unwrap())
            .collect();
        kith_store::run(&mut store, Command::Apply { resources, at: 0 }).unwrap();
        let statuses = vec![("Volume/default/data".to_string(), status.as_object().unwrap().clone())];
        kith_store::run(&mut store, Command::Patch { statuses }).unwrap();
        store
    }

    const KEY: &str = "Volume/default/data";
    const GRACE: Duration = Duration::from_secs(60);

    fn decided(store: &Store, lost: &[(&str, u64)]) -> Option<(String, Vec<String>)> {
        let lost = |node: &str| {
            lost.iter()
                .find(|(name, _)| *name == node)
                .map(|(_, secs)| Duration::from_secs(*secs))
        };
        let mut writes = writes(store, &lost, GRACE);
        assert!(writes.len() <= 1, "only the volume with replicas is written of");
        let (key, fields) = writes.pop()?;
        assert_eq!(key, KEY);
        Some((
            fields["primary"].as_str().unwrap().to_string(),
            names(&fields["replicas"]),
        ))
    }

    #[test]
    fn a_volumes_replica_is_another_node_that_is_there_and_stays_the_same() {
        let (primary, replicas) = decided(&store(json!({})), &[]).unwrap();
        assert_eq!((primary.as_str(), replicas.len()), ("a", 1));
        assert!(replicas[0] == "b" || replicas[0] == "c");
        // Written once: nothing more to say when the status says it.
        let said = store(json!({ "primary": "a", "replicas": replicas }));
        assert_eq!(decided(&said, &[]), None);
        // Never on a node that is not there, never the primary itself.
        let other = if replicas[0] == "b" { "c" } else { "b" };
        let (_, without) = decided(&store(json!({})), &[(&replicas[0], 0)]).unwrap();
        assert_eq!(without, [other]);
        assert_eq!(
            decided(&store(json!({})), &[("b", 0), ("c", 0)]).unwrap().1,
            Vec::<String>::new()
        );
        // A replica quiet for a moment stays; one gone for the grace gives way to another.
        assert_eq!(decided(&said, &[(&replicas[0], 59)]), None);
        assert_eq!(decided(&said, &[(&replicas[0], 60)]).unwrap().1, [other]);
    }

    #[test]
    fn the_replica_synced_last_takes_over_when_the_primary_is_lost_for_the_grace() {
        let synced = store(json!({ "primary": "a", "replicas": ["b"], "synced": { "b": 100 } }));
        assert_eq!(decided(&synced, &[("a", 59)]), None);
        // b has it now; the copy that is short is made on c (a is not there to be one).
        assert_eq!(
            decided(&synced, &[("a", 60)]).unwrap(),
            ("b".to_string(), vec!["c".to_string()])
        );
        // When a node that is no replica any more synced is forgotten: picked again, it starts over.
        let stale = store(json!({ "primary": "a", "replicas": ["b"], "synced": { "b": 100, "c": 50 } }));
        let (_, fields) = writes(&stale, &|_| None, GRACE).pop().unwrap();
        assert_eq!(fields["synced"], json!({ "b": 100 }));
        // A replica that never had a copy takes nothing over: the volume waits for its node.
        let never = store(json!({ "primary": "a", "replicas": ["b"] }));
        assert_eq!(decided(&never, &[("a", 600)]), None);
        // Of two, the one synced last; of those, only one that is there.
        let mut two = store(json!({ "primary": "a", "replicas": ["b", "c"], "synced": { "b": 100, "c": 200 } }));
        let more = json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "data" },
            "spec": { "node": "a", "path": "d", "replicas": 3 } });
        let resources = vec![serde_json::from_value(more).unwrap()];
        kith_store::run(&mut two, Command::Apply { resources, at: 1 }).unwrap();
        assert_eq!(
            decided(&two, &[("a", 60)]).unwrap(),
            ("c".to_string(), vec!["b".to_string()])
        );
        assert_eq!(decided(&two, &[("a", 60), ("c", 0)]).unwrap().0, "b");
        // A worker's copy takes over only when no control node has one, whatever time it says.
        let worker = json!({ "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": "c" },
            "spec": { "trust": "worker" } });
        let resources = vec![serde_json::from_value(worker).unwrap()];
        kith_store::run(&mut two, Command::Apply { resources, at: 2 }).unwrap();
        assert_eq!(decided(&two, &[("a", 60)]).unwrap().0, "b");
        assert_eq!(decided(&two, &[("a", 60), ("b", 0)]).unwrap().0, "c");
    }

    #[test]
    fn a_volumes_copy_is_for_its_replicas() {
        let said = store(json!({ "primary": "a", "replicas": ["b"], "synced": { "b": 100 } }));
        assert!(replica_of(&said, KEY, "b"));
        // Not a node that is none, not one with no name, not for a Volume with no replicas.
        for (key, node) in [
            (KEY, "c"),
            (KEY, ""),
            ("Volume/default/alone", "b"),
            ("Volume/default/gone", "b"),
        ] {
            assert!(!replica_of(&said, key, node), "{key} {node}");
        }
    }

    #[test]
    fn a_volume_is_where_its_replica_took_over_and_its_status_keeps_saying_so() {
        let moved = store(json!({ "primary": "b", "replicas": ["c"], "synced": { "c": 5 } }));
        assert_eq!(crate::volumes::dir(&moved, "default", "data").unwrap().node, "b");
        // The rest of the status is worked out again each round: what is said of the copies stays.
        let again = crate::volumes::resolve(&moved).status;
        assert_eq!(
            again[KEY],
            Some(json!({ "primary": "b", "replicas": ["c"], "synced": { "c": 5 } }))
        );
        // With `replicas` lowered again it stays where it took over, and says only that:
        // never back, by itself, to the old copy on the node it was made on.
        let mut lowered = moved;
        let one = |node: &str| {
            let volume = json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "data" },
                "spec": { "node": node, "path": "d" } });
            let resources = vec![serde_json::from_value(volume).unwrap()];
            Command::Apply { resources, at: 2 }
        };
        kith_store::run(&mut lowered, one("a")).unwrap();
        assert_eq!(crate::volumes::dir(&lowered, "default", "data").unwrap().node, "b");
        assert_eq!(
            crate::volumes::resolve(&lowered).status[KEY],
            Some(json!({ "primary": "b" }))
        );
        assert!(!replica(
            &lowered,
            &crate::volumes::dir(&lowered, "default", "data").unwrap(),
            "b"
        ));
        // Until its `node` names where it is: then nothing more is said.
        kith_store::run(&mut lowered, one("b")).unwrap();
        assert_eq!(crate::volumes::resolve(&lowered).status[KEY], None);
    }

    #[test]
    fn a_replica_swaps_in_what_it_was_sent_and_sets_aside_what_it_was_not() {
        let root = std::env::temp_dir().join(format!("kith-replica-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (dir, new) = (root.join("d"), root.join(".d.restoring"));
        let fill = |at: &Path, text: &str| {
            std::fs::create_dir_all(at).unwrap();
            std::fs::write(at.join("file"), text).unwrap();
        };
        // The first copy, where there was nothing; then the next, in its place.
        fill(&new, "one");
        swap(&new, &dir, Some(7)).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("file")).unwrap(), "one");
        fill(&new, "two");
        swap(&new, &dir, None).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("file")).unwrap(), "two");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        // What was this node's own (it was the primary) is kept beside the copy.
        fill(&new, "three");
        swap(&new, &dir, Some(9)).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("file")).unwrap(), "three");
        assert_eq!(std::fs::read_to_string(root.join("d.was-9/file")).unwrap(), "two");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// What a primary sends: a tar of one file of `size` bytes, as bytes taken in.
    fn sent(temp: &Path, size: usize) -> Incoming {
        let mut tar = tar::Builder::new(Incoming::new(temp).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(size as u64);
        header.set_mode(0o644);
        tar.append_data(&mut header, "big", &vec![5u8; size][..]).unwrap();
        tar.into_inner().unwrap()
    }

    #[test]
    fn replica_put_in_removes_a_copy_it_was_not_to_keep_after_it_lets_go_of_the_store() {
        let root = std::env::temp_dir().join(format!("kith-replica-putin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (into, new, marker) = (root.join("d"), root.join(".d.restoring"), root.join("marker"));
        std::fs::create_dir_all(&new).unwrap();
        let mut state = kith_store::State::default();
        state.store = store(json!({}));
        let state = std::sync::Mutex::new(state);
        let dir = Dir {
            namespace: "default".into(),
            name: "data".into(),
            path: String::new(),
            node: "a".into(),
            encrypted: false,
        };
        // (This node, "a", has the Volume: it is no replica of it, and the copy goes.)
        let (running, running_in) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (state, dir, new, into, marker) = (&state, &dir, &new, &into, &marker);
        std::thread::scope(|scope| {
            let put = scope.spawn(move || {
                put_in(state, dir, "a", new, into, marker, None, |new| {
                    running.send(()).unwrap();
                    released.recv().unwrap();
                    std::fs::remove_dir_all(new).unwrap();
                })
            });
            // The removal is running and held: the store answers.
            running_in.recv().unwrap();
            assert!(state.try_lock().is_ok(), "the store is held while a copy is removed");
            assert!(new.exists());
            release.send(()).unwrap();
            let refused = put.join().unwrap().unwrap_err();
            assert!(refused.contains("not a replica"), "{refused}");
        });
        assert!(!new.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replica_capped_keeps_the_copy_it_had_when_what_is_sent_unpacks_past_the_size() {
        let root = std::env::temp_dir().join(format!("kith-replica-capped-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (temp, into) = (root.join("temp"), root.join("d"));
        std::fs::create_dir_all(&into).unwrap();
        std::fs::write(into.join("old"), "before").unwrap();
        let swapped = |new: PathBuf| swap(&new, &into, None).map_err(|e| e.to_string());
        let refused = place(sent(&temp, 98_304), &temp, &into, 98_303, swapped).unwrap_err();
        assert!(refused.contains("more than 98303 bytes"), "{refused}");
        // The copy as it was, nothing beside it and no archive left.
        assert_eq!(std::fs::read_to_string(into.join("old")).unwrap(), "before");
        assert!(!root.join(".d.restoring").exists() && !root.join("d.old").exists());
        assert_eq!(std::fs::read_dir(&temp).unwrap().count(), 0);
        // As much as the volume holds: the copy.
        place(sent(&temp, 98_304), &temp, &into, 98_304, swapped).unwrap();
        assert_eq!(std::fs::metadata(into.join("big")).unwrap().len(), 98_304);
        assert!(!into.join("old").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replica_capped_does_not_sync_a_volume_that_is_gone_or_unreadable() {
        let mut store = store(json!({}));
        let dir = |name: &str| Dir {
            namespace: "default".into(),
            name: name.into(),
            path: String::new(),
            node: "a".into(),
            encrypted: false,
        };
        // No size: no cap, as before.
        assert_eq!(cap_of(&store, &dir("data")), Ok(u64::MAX));
        let gone = cap_of(&store, &dir("nope")).unwrap_err();
        assert!(gone.contains("Volume default/nope is gone"), "{gone}");
        // (A spec that does not parse cannot be applied, so only a gone one is tried.)
        let sized = json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "sized" },
            "spec": { "node": "a", "path": "f", "size": "1Mi" } });
        let resources = vec![serde_json::from_value(sized).unwrap()];
        kith_store::run(&mut store, Command::Apply { resources, at: 0 }).unwrap();
        assert_eq!(cap_of(&store, &dir("sized")), Ok(1 << 20));
    }

    #[tokio::test]
    async fn replica_capped_stops_a_primary_that_sends_more_than_the_volume_may_hold() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let serve = || async {
            let chunks = (0..400).map(|_| Ok::<_, std::io::Error>(vec![1u8; 10_000]));
            axum::body::Body::from_stream(futures_util::stream::iter(chunks))
        };
        tokio::spawn(async move { axum::serve(listener, axum::Router::new().fallback(serve)).await });
        let temp = std::env::temp_dir().join(format!("kith-replica-sent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut answer = reqwest::get(url).await.unwrap();
        let mut incoming = Incoming::new(&temp).unwrap();
        // (A volume of 1 MB is sent as much as 3 MB and a bit: 4 MB are more.)
        let most = crate::backups::download_cap(1_000_000);
        let said = crate::backups::receive(&mut answer, &mut incoming, QUIET, most).await;
        assert!(said.unwrap_err().contains("more than 3048576 bytes"));
        drop(incoming);
        assert_eq!(std::fs::read_dir(&temp).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&temp);
    }
}
