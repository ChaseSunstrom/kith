//! The blob store: bytes kept by what they are.
//!
//! PUT /v1/blobs?namespace=NS&copies=N   the body -> {name, size}; makes the Blob
//! GET /v1/blobs/NS/NAME                 the bytes, from here or from a node that has them
//! GET /v1/blob-copy/NAME                the bytes if they are here                nodes only
//!
//! A blob is a file `<state>/blobs/NAME`, NAME being the first 62 hex digits of the BLAKE3
//! hash of its bytes (a resource's name is at most 63 long), so the same bytes are kept
//! once whoever puts them and in whichever namespace. A `Blob` resource says the bytes
//! are wanted, how many there are and on how many nodes (`copies`, 2 unless said). Each
//! node works out the same holders from the name and the nodes it hears from, fetches
//! what it should hold from a node that says it has it, and says in the Blob's
//! `status.nodes` that it holds it. Nothing gets a blob's name before its bytes hashed to
//! it: an upload cut short or a copy that is not the same bytes leaves no file.
//!
//! A node that holds a blob it need not hold keeps it until the nodes that should all
//! say they have it. A file no Blob names is removed once it is ten minutes old.

use crate::Shared;
use crate::access::Caller;
use crate::api::{ApiError, permit};
use axum::Json;
use axum::body::Body;
use axum::extract::{Extension, Path as UrlPath, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use kith_api::kinds::Verb;
use kith_api::store::Error;
use kith_store::Command;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::watch;

/// On how many nodes, when the Blob does not say.
const COPIES: usize = 2;
/// How often a node looks at what it should hold.
const ROUND: Duration = Duration::from_secs(3);
/// A node not heard from for this long is not given blobs to hold.
const AWAY: Duration = Duration::from_secs(60);
/// A node that sends nothing of a blob for this long is given up on.
const QUIET: Duration = Duration::from_secs(30);
/// A file no Blob names is left alone this long: its Blob may be on its way.
const UNNAMED: Duration = Duration::from_secs(600);

/// Where this node's blobs are.
pub fn dir(shared: &Shared) -> PathBuf {
    shared.logs.with_file_name("blobs")
}

/// Is `name` one a blob can have? (Asked before a name is ever part of a path.)
pub fn named(name: &str) -> bool {
    name.len() == 62 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Bytes on their way into the store: they get their name when all of them are there.
pub struct Incoming {
    file: std::fs::File,
    path: PathBuf,
    hasher: blake3::Hasher,
    size: u64,
}

impl Incoming {
    pub fn new(dir: &Path) -> std::io::Result<Incoming> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::fs::create_dir_all(dir)?;
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = dir.join(format!("in-{}-{next}", std::process::id()));
        let file = std::fs::File::create(&path)?;
        Ok(Incoming {
            file,
            path,
            hasher: blake3::Hasher::new(),
            size: 0,
        })
    }

    // ponytail: written on the async thread, a chunk at a time, as the logs are read;
    // move to the blocking pool if blobs land on slow disks.
    pub fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.hasher.update(bytes);
        self.size += bytes.len() as u64;
        self.file.write_all(bytes)
    }

    /// The file under its name, on disk. `expected`: the name the bytes must hash to.
    pub fn keep(self, expected: Option<&str>) -> Result<(String, u64), String> {
        let name = self.hasher.finalize().to_hex()[..62].to_string();
        if expected.is_some_and(|expected| expected != name) {
            return Err(format!("the bytes are those of {name}"));
        }
        let to = self.path.with_file_name(&name);
        // (The same bytes are there already: nothing to do, and the file in the way goes.)
        let kept = match std::fs::File::options().write(true).open(&to) {
            // (Its age is what keeps a file no Blob names yet from being removed.)
            Ok(there) => there.set_modified(SystemTime::now()),
            Err(_) => self.file.sync_all().and_then(|()| std::fs::rename(&self.path, &to)),
        };
        kept.map_err(|e| format!("{}: {e}", to.display()))?;
        Ok((name, self.size))
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        // (Renamed if it was kept: then there is nothing here to remove.)
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The `copies` of `nodes` that should hold `name`: every node that sees the same nodes
/// picks the same ones, and a node that comes or goes moves only the blobs that were its.
pub fn holders<'a>(name: &str, nodes: &[&'a str], copies: usize) -> Vec<&'a str> {
    let score = |node: &&str| *blake3::hash(format!("{name}/{node}").as_bytes()).as_bytes();
    let mut nodes = nodes.to_vec();
    nodes.sort_by_key(score);
    nodes.truncate(copies.max(1));
    nodes
}

/// A new Blob comes of putting its bytes, never of an apply: whoever could write one for
/// a name it has only heard of could read, through it, bytes put in a namespace it may
/// not read.
pub fn put_first(store: &kith_api::store::Store, resources: &[kith_api::Resource]) -> Result<(), String> {
    let new = |resource: &&kith_api::Resource| resource.kind == "Blob" && store.get(&resource.key()).is_none();
    match resources.iter().find(new) {
        Some(blob) => Err(format!(
            "{}: a Blob is made by putting its bytes: kith blob put FILE",
            blob.key()
        )),
        None => Ok(()),
    }
}

/// What the Blobs of one name ask for.
#[derive(Default, Debug, PartialEq)]
struct Want {
    copies: usize,
    /// (key, the nodes its status says hold it)
    keys: Vec<(String, BTreeSet<String>)>,
}

/// Every blob some Blob names. (A Blob whose name is none a blob can have asks nothing.)
fn wants(store: &kith_api::store::Store) -> BTreeMap<String, Want> {
    let mut wants: BTreeMap<String, Want> = BTreeMap::new();
    for blob in store.list(Some("Blob")).filter(|blob| named(&blob.metadata.name)) {
        let want = wants.entry(blob.metadata.name.clone()).or_default();
        let copies = blob.spec["copies"].as_u64().map_or(COPIES, |copies| copies as usize);
        want.copies = want.copies.max(copies);
        let says = blob.status.as_ref().and_then(|status| status["nodes"].as_array());
        let says = says.into_iter().flatten().filter_map(Value::as_str);
        want.keys.push((blob.key(), says.map(String::from).collect()));
    }
    wants
}

/// What `me`, holding `have`, does this round: (fetch NAME from one of NODES, remove NAME).
fn plan(
    wants: &BTreeMap<String, Want>,
    have: &BTreeSet<String>,
    me: &str,
    live: &[&str],
) -> (Vec<(String, Vec<String>)>, Vec<String>) {
    let (mut fetch, mut remove) = (Vec::new(), Vec::new());
    for (name, want) in wants {
        let should = holders(name, live, want.copies);
        let say = |node: &str| want.keys.iter().all(|(_, says)| says.contains(node));
        let said: BTreeSet<&String> = want.keys.iter().flat_map(|(_, says)| says).collect();
        match (have.contains(name), should.contains(&me)) {
            (false, true) => {
                let from: Vec<String> = said.into_iter().filter(|node| *node != me).cloned().collect();
                if !from.is_empty() {
                    fetch.push((name.clone(), from));
                }
            }
            // (Not while one that should hold it has yet to say it does.)
            (true, false) if should.iter().all(|node| say(node)) => remove.push(name.clone()),
            _ => {}
        }
    }
    (fetch, remove)
}

/// The blobs in `dir`, and the files there no blob would be called, each with its age.
fn held(dir: &Path) -> (BTreeSet<String>, Vec<(PathBuf, Duration)>) {
    let (mut blobs, mut others) = (BTreeSet::new(), Vec::new());
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let changed = entry.metadata().and_then(|file| file.modified()).ok();
        let age = changed.and_then(|at| SystemTime::now().duration_since(at).ok());
        let age = age.unwrap_or_default();
        if named(&name) {
            blobs.insert(name);
        } else {
            others.push((entry.path(), age));
        }
    }
    (blobs, others)
}

/// `name` from the node at `address`, into `dir` under its name if its bytes are its.
async fn fetch(client: &reqwest::Client, address: &str, name: &str, dir: &Path) -> Result<(), String> {
    // (A node that stops answering halfway must not hold up every other blob.)
    let slow = |_| format!("nothing came for {} s", QUIET.as_secs());
    let asked = client.get(format!("https://{address}/v1/blob-copy/{name}")).send();
    let asked = tokio::time::timeout(QUIET, asked).await.map_err(slow)?;
    let mut answer = asked
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| e.to_string())?;
    let mut incoming = Incoming::new(dir).map_err(|e| e.to_string())?;
    loop {
        let chunk = tokio::time::timeout(QUIET, answer.chunk()).await.map_err(slow)?;
        let Some(chunk) = chunk.map_err(|e| e.to_string())? else {
            break;
        };
        incoming.write(&chunk).map_err(|e| e.to_string())?;
    }
    incoming.keep(Some(name)).map(drop)
}

/// Keeps what this node should hold, lets go of what it need not, and says which it has.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let (dir, me) = (dir(&shared), shared.members.me().to_string());
    let mut said = String::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let (wants, addresses) = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            let address = |node: &kith_api::Resource| {
                let address = node.status.as_ref()?["address"].as_str()?;
                Some((node.metadata.name.clone(), address.to_string()))
            };
            let addresses: BTreeMap<String, String> = state.store.list(Some("Node")).filter_map(address).collect();
            (wants(&state.store), addresses)
        };
        let (have, others) = held(&dir);
        if wants.is_empty() && have.is_empty() && others.is_empty() {
            continue;
        }
        let now = Instant::now();
        let here = |node: &&str| shared.members.lost_for(node, now).is_some_and(|gone| gone < AWAY);
        let mut live: Vec<&str> = addresses.keys().map(String::as_str).filter(here).collect();
        if !live.contains(&me.as_str()) {
            live.push(&me);
        }
        let (fetches, removes) = plan(&wants, &have, &me, &live);
        // (Let go of at once: what the nodes said of themselves is as fresh as it gets.)
        for name in removes {
            let _ = std::fs::remove_file(dir.join(name));
        }
        let mut saying = String::new();
        // ponytail: one blob at a time; fetch several at once when there are many to move.
        for (name, from) in fetches {
            let Some(cluster) = &shared.cluster else { break };
            let mut failed = String::new();
            for node in &from {
                let Some(address) = addresses.get(node) else { continue };
                match fetch(&cluster.client, address, &name, &dir).await {
                    Ok(()) => {
                        failed.clear();
                        break;
                    }
                    Err(e) => failed = format!("blob {name} was not copied from node {node}: {e}"),
                }
            }
            if !failed.is_empty() {
                saying = failed;
            }
        }
        // Read again, and nothing awaited from here to the removals: a Blob put while this
        // node was fetching is seen, and so is what the others said meanwhile.
        let wants = self::wants(&shared.store.lock().expect("a handler panicked holding the store").store);
        let old = |path: &Path| {
            let age = std::fs::metadata(path).and_then(|file| file.modified()).ok();
            let age = age.and_then(|at| SystemTime::now().duration_since(at).ok());
            age.is_some_and(|age| age > UNNAMED)
        };
        let (have, others) = held(&dir);
        let unnamed = have
            .iter()
            .filter(|name| !wants.contains_key(*name))
            .map(|name| dir.join(name));
        for path in unnamed.chain(others.into_iter().map(|(path, _)| path)) {
            if old(&path) {
                let _ = std::fs::remove_file(path);
            }
        }
        let (have, _) = held(&dir);
        // ponytail: each node writes the whole list with itself in or out; two that write
        // at once lose one of the two, which its node puts right the next round.
        let mut statuses = Vec::new();
        for (name, want) in &wants {
            for (key, says) in &want.keys {
                if says.contains(&me) != have.contains(name) {
                    let mut nodes = says.clone();
                    if !nodes.remove(&me) {
                        nodes.insert(me.clone());
                    }
                    let fields = json!({ "nodes": nodes });
                    statuses.push((key.clone(), fields.as_object().expect("an object").clone()));
                }
            }
        }
        if !statuses.is_empty()
            && let Err(e) = shared.submit(Command::Patch { statuses }).await
        {
            saying = format!("which blobs this node holds was not said: {e}");
        }
        if saying != said {
            if !saying.is_empty() {
                eprintln!("kithd: {saying}");
            }
            said = saying;
        }
    }
}

/// The file as a reply that says how long it is (the CLI reads no chunked replies).
fn file_reply(path: &Path) -> std::io::Result<Response> {
    let file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    // ponytail: read on the async thread 64 KiB at a time, as the logs are.
    let chunks = futures_util::stream::unfold(file, |mut file| async move {
        let mut chunk = vec![0; 64 << 10];
        match file.read(&mut chunk) {
            Ok(0) => None,
            Ok(n) => {
                chunk.truncate(n);
                Some((Ok(chunk), file))
            }
            Err(e) => Some((Err(e), file)),
        }
    });
    Ok(([(header::CONTENT_LENGTH, size)], Body::from_stream(chunks)).into_response())
}

fn io(what: String) -> ApiError {
    ApiError::Store(Error::Io(what))
}

#[derive(serde::Deserialize)]
pub struct Put {
    namespace: Option<String>,
    copies: Option<u32>,
}

/// `PUT /v1/blobs`: the body is kept under its name, and a Blob says it is wanted.
pub async fn put(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Query(put): Query<Put>,
    body: Body,
) -> Result<Json<Value>, ApiError> {
    let namespace = put.namespace.unwrap_or_else(|| "default".into());
    permit(&shared, &caller, Verb::Apply, |_| {
        vec![("Blob".into(), Some(namespace.clone()))]
    })?;
    // ponytail: no limit on a blob's size but the disk; a quota per namespace when
    // callers who may put are not all trusted with the disk.
    let mut incoming = Incoming::new(&dir(&shared)).map_err(|e| io(format!("the blob store: {e}")))?;
    let mut chunks = body.into_data_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|e| ApiError::Store(Error::Invalid(format!("the upload ended early: {e}"))))?;
        incoming.write(&chunk).map_err(|e| io(format!("the blob store: {e}")))?;
    }
    let kept = tokio::task::spawn_blocking(move || incoming.keep(None)).await;
    let (name, size) = kept.map_err(|e| io(e.to_string()))?.map_err(io)?;
    let mut spec = json!({ "size": size });
    if let Some(copies) = put.copies {
        spec["copies"] = copies.into();
    }
    let blob = json!({
        "apiVersion": "kith.dev/v1", "kind": "Blob",
        "metadata": { "name": name, "namespace": namespace }, "spec": spec,
    });
    let resources = vec![serde_json::from_value(blob).map_err(|e| io(e.to_string()))?];
    let at = kith_api::store::now();
    let applied = shared.write(Command::Apply { resources, at }).await;
    let what = vec![format!("Blob/{namespace}/{name}")];
    let said = applied.as_ref().map(drop).map_err(|e| e.to_string());
    shared.audit.record(&caller, "apply", what, said);
    applied.map_err(|e| io(e.to_string()))?;
    Ok(Json(json!({ "name": name, "namespace": namespace, "size": size })))
}

/// `GET /v1/blobs/NS/NAME`: the bytes, for who may read the Blob.
pub async fn get(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    UrlPath((namespace, name)): UrlPath<(String, String)>,
) -> Result<Response, ApiError> {
    permit(&shared, &caller, Verb::Get, |_| {
        vec![("Blob".into(), Some(namespace.clone()))]
    })?;
    let key = format!("Blob/{namespace}/{name}");
    let missing = || ApiError::Store(Error::NotFound(key.clone()));
    let me = shared.members.me();
    let (size, elsewhere) = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let blob = state.store.get(&key).filter(|_| named(&name)).ok_or_else(missing)?;
        let nodes = blob.status.as_ref().and_then(|status| status["nodes"].as_array());
        let nodes = nodes.into_iter().flatten().filter_map(Value::as_str);
        let address = |node: &str| {
            let there = state.store.get(&format!("Node/{node}"))?.status.as_ref()?;
            Some(there["address"].as_str()?.to_string())
        };
        let elsewhere: Vec<String> = nodes.filter(|node| *node != me).filter_map(address).collect();
        (blob.spec["size"].as_u64(), elsewhere)
    };
    if let Ok(reply) = file_reply(&dir(&shared).join(&name)) {
        return Ok(reply);
    }
    let mut failed = format!("no node says it holds blob {name} yet");
    for address in elsewhere {
        let Some(cluster) = &shared.cluster else { break };
        let asked = cluster.client.get(format!("https://{address}/v1/blob-copy/{name}"));
        match asked.send().await.and_then(reqwest::Response::error_for_status) {
            // (Passed on as it comes: the node it comes from checked the bytes when it took them.)
            Ok(answer) => {
                let size = answer.content_length().or(size).unwrap_or_default();
                let chunks = futures_util::stream::unfold(answer, |mut answer| async move {
                    answer.chunk().await.transpose().map(|chunk| (chunk, answer))
                });
                return Ok(([(header::CONTENT_LENGTH, size)], Body::from_stream(chunks)).into_response());
            }
            Err(e) => failed = format!("asking {address} for blob {name}: {e}"),
        }
    }
    Err(io(failed))
}

/// `GET /v1/blob-copy/NAME` (members only): the bytes if they are here.
pub async fn copy(State(shared): State<Arc<Shared>>, UrlPath(name): UrlPath<String>) -> Response {
    let found = named(&name).then(|| file_reply(&dir(&shared).join(&name)));
    match found {
        Some(Ok(reply)) => reply,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kith-blob-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn put(dir: &Path, bytes: &[u8], expected: Option<&str>) -> Result<(String, u64), String> {
        let mut incoming = Incoming::new(dir).unwrap();
        incoming.write(bytes).unwrap();
        incoming.keep(expected)
    }

    #[test]
    fn a_blob_is_kept_once_under_its_hash_and_never_under_another() {
        let dir = temp("store");
        let (name, size) = put(&dir, b"the same bytes", None).unwrap();
        // (What `b3sum` prints for these bytes, less its last two digits.)
        assert_eq!(name, blake3::hash(b"the same bytes").to_hex()[..62]);
        assert!(named(&name) && size == 14);
        assert_eq!(put(&dir, b"the same bytes", Some(&name)).unwrap().0, name);
        let refused = put(&dir, b"other bytes", Some(&name)).unwrap_err();
        assert!(refused.starts_with("the bytes are those of "), "{refused}");
        // One file: the second put added none, the refused one left none.
        let (blobs, others) = held(&dir);
        assert_eq!((blobs.len(), others.len()), (1, 0));
        assert_eq!(std::fs::read(dir.join(&name)).unwrap(), b"the same bytes");
        // An upload that never ends leaves no file either.
        drop(Incoming::new(&dir).unwrap());
        assert_eq!(held(&dir).1.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_blob_name_is_62_hex_digits_and_nothing_else() {
        let name = "ab".repeat(31);
        assert!(named(&name));
        for bad in [
            "",
            "../../etc/passwd",
            &name[1..],
            &format!("{name}a"),
            &name.to_uppercase(),
        ] {
            assert!(!named(bad), "{bad}");
        }
        assert!(!named(&format!("{}/.", &name[2..])));
    }

    #[test]
    fn blob_holders_are_the_same_whatever_order_the_nodes_come_in() {
        let name = "ab".repeat(31);
        let two = holders(&name, &["a", "b", "c", "d"], 2);
        assert_eq!(two.len(), 2);
        assert_eq!(holders(&name, &["d", "c", "b", "a"], 2), two);
        // A node that is no holder going away moves nothing.
        let left: Vec<&str> = ["a", "b", "c", "d"].into_iter().filter(|n| two.contains(n)).collect();
        let mut again = holders(&name, &left, 2);
        again.sort_unstable();
        let mut sorted = two.clone();
        sorted.sort_unstable();
        assert_eq!(again, sorted);
        // Fewer nodes than copies: all of them. No copies asked: still one.
        assert_eq!(holders(&name, &["a"], 3), ["a"]);
        assert_eq!(holders(&name, &["a", "b"], 0).len(), 1);
    }

    #[test]
    fn a_blob_is_fetched_by_who_should_hold_it_and_let_go_only_when_the_holders_have_it() {
        let name = "cd".repeat(31);
        let live = ["a", "b", "c"];
        let should = holders(&name, &live, 2);
        let other = *live.iter().find(|n| !should.contains(n)).unwrap();
        let want = |says: &[&str]| {
            let says = says.iter().map(|s| s.to_string()).collect();
            BTreeMap::from([(
                name.clone(),
                Want {
                    copies: 2,
                    keys: vec![(format!("Blob/default/{name}"), says)],
                },
            )])
        };
        let (none, has) = (BTreeSet::new(), BTreeSet::from([name.clone()]));
        // Put on the node that need not hold it: the holders fetch it from there...
        let (fetch, remove) = plan(&want(&[other]), &none, should[0], &live);
        assert_eq!(fetch, [(name.clone(), vec![other.to_string()])]);
        assert!(remove.is_empty());
        // ...and it keeps its copy while one of them has yet to say it holds it.
        assert_eq!(plan(&want(&[other, should[0]]), &has, other, &live), (vec![], vec![]));
        let all = [other, should[0], should[1]];
        assert_eq!(plan(&want(&all), &has, other, &live).1, std::slice::from_ref(&name));
        // A holder never lets go, and nobody fetches what no node says it has.
        assert_eq!(plan(&want(&all), &has, should[0], &live), (vec![], vec![]));
        assert_eq!(plan(&want(&[]), &none, should[0], &live), (vec![], vec![]));
    }

    #[test]
    fn blobs_wanted_are_read_from_the_store_and_a_bad_name_asks_nothing() {
        let name = "ef".repeat(31);
        let mut store = kith_api::store::Store::default();
        let blob = |namespace: &str, name: &str, copies: u64| {
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Blob",
                "metadata": { "name": name, "namespace": namespace },
                "spec": { "size": 1, "copies": copies },
            }))
            .unwrap()
        };
        let resources = vec![
            blob("default", &name, 1),
            blob("other", &name, 3),
            blob("default", "not-a-hash", 2),
        ];
        kith_store::run(&mut store, Command::Apply { resources, at: 0 }).unwrap();
        let nodes = json!({ "nodes": ["a"] }).as_object().unwrap().clone();
        let statuses = vec![(format!("Blob/other/{name}"), nodes)];
        kith_store::run(&mut store, Command::Patch { statuses }).unwrap();
        // An apply may change a Blob that is there (its copies), and never make one.
        let again = vec![blob("other", &name, 2), blob("third", &name, 2)];
        assert!(put_first(&store, &again[..1]).is_ok());
        let refused = put_first(&store, &again).unwrap_err();
        assert!(
            refused.starts_with(&format!("Blob/third/{name}: a Blob is made by putting")),
            "{refused}"
        );
        let wants = wants(&store);
        assert_eq!(wants.len(), 1);
        let want = &wants[&name];
        assert_eq!((want.copies, want.keys.len()), (3, 2));
        assert_eq!(want.keys[1].1, BTreeSet::from(["a".to_string()]));
    }
}
