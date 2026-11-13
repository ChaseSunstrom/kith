//! The resource API, v1.
//!
//! ```text
//! POST   /v1/apply[?dryRun=true]     [Resource]  -> [Change]   all or nothing
//! GET    /v1/resources[?kind=Kind]               -> [Resource]
//! GET    /v1/resources/<key>                     -> Resource
//! DELETE /v1/resources/<key>                     -> Resource
//! GET    /v1/history/<key>                       -> [Revision]
//! POST   /v1/rollback/<key>?to=N                 -> Change
//! GET    /v1/logs/<key>[?unit=&replica=&stderr=true&previous=true&offset=N|tail=LINES]
//!                                                -> {data, next, more}
//! GET    /v1/watch[?after=G&kind=Kind&wait=S]    -> {generation, resources}
//! GET    /v1/audit[?tail=LINES]                  -> [{at, who, verb, what, ok, error}]
//! POST   /v1/run {on, via?, argv}                -> 101, then a byte tunnel (see `run.rs`)
//! ```
//! Every handler takes the [`Caller`] and asks what it may do (`access.rs`): an
//! Identity gets 403 with the reason, and lists only what it may see. Changes, and
//! refusals, go in the audit log (`audit.rs`); reading that takes `get` on `Audit`.
//! Logs: `data` is output from byte `offset` on (or the last `tail` lines), `next`
//! the offset to ask for next, `more` whether the unit may still write. Following
//! is asking again; `previous` reads the file that was moved aside at the size cap.
//! `<key>` is `Kind/namespace/name` or `Kind/name`. Errors are `{"error": "..."}`.
//!
//! Changes go through Raft (see `raft.rs`); reads are this node's copy of the store.
//!
//! `watch` is a long-poll. `generation` counts changes to the store (status
//! included) and is only comparable within one kithd run. With `after=G` it
//! replies at once if the generation is not G (newer, or a restarted kithd's),
//! otherwise it waits up to `wait` seconds (default and cap 25) for a change
//! and replies with the current resources either way: compare, then ask again
//! with the new generation. Without `after` it replies at once.

pub(crate) mod run;

use crate::Shared;
use crate::access::{self, Caller, Certificate, Grants};
use axum::Extension;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use kith_api::Resource;
use kith_api::kinds::Verb;
use kith_api::store::{Change, Error, Revision, Store};
use kith_store::{Command, Done};
use serde::Deserialize;
use std::sync::Arc;

pub fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/v1/apply", post(apply))
        .route("/v1/watch", get(watch))
        .route("/v1/resources", get(list))
        .route("/v1/resources/{*key}", get(get_one).delete(delete))
        .route("/v1/history/{*key}", get(history))
        .route("/v1/rollback/{*key}", post(rollback))
        .route("/v1/logs/{*key}", get(logs))
        .route("/v1/blobs", axum::routing::put(crate::blobs::put))
        .route("/v1/backups/{namespace}/{name}/restore", post(crate::backups::restore))
        .route("/v1/blobs/{namespace}/{name}", get(crate::blobs::get))
        .route("/v1/packages/push", post(push))
        .route("/v1/packages/pull", post(pull))
        .route("/v1/audit", get(audit))
        .route("/v1/run", post(run::run))
        .route("/v1/tokens", post(crate::cluster::token))
        .route("/v1/lock/{name}", post(crate::crypt::set))
        .route("/v1/seats/{name}/activity", post(crate::seats::activity))
        // (The network boot file is 40 MB.)
        .route(
            "/v1/netboot",
            get(crate::cluster::netboot)
                .delete(crate::cluster::netboot)
                .put(crate::cluster::netboot)
                .layer(axum::extract::DefaultBodyLimit::max(96 << 20)),
        )
        .merge(crate::ui::router())
        // (A package is 4 MB of files at most, and JSON makes them longer.)
        .layer(axum::extract::DefaultBodyLimit::max(16 << 20))
        .with_state(shared)
}

pub enum ApiError {
    Store(Error),
    /// The caller may not: why.
    Refused(String),
    /// The certificate no longer stands for its Identity: why.
    Unauthorized(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, why) = match self {
            ApiError::Refused(why) => (StatusCode::FORBIDDEN, why),
            ApiError::Unauthorized(why) => (StatusCode::UNAUTHORIZED, why),
            ApiError::Store(e) => {
                let status = match e {
                    Error::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
                    Error::NotFound(_) => StatusCode::NOT_FOUND,
                    Error::Conflict(_) => StatusCode::CONFLICT,
                    Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, e.to_string())
            }
        };
        (status, Json(serde_json::json!({ "error": why }))).into_response()
    }
}

pub(crate) type Reply<T> = Result<Json<T>, ApiError>;

/// A command answered with another command's kind of reply: a bug, said as an error.
fn odd() -> ApiError {
    ApiError::Store(Error::Io(
        "the store gave an answer that does not fit the request".into(),
    ))
}

fn read<T>(shared: &Shared, look: impl FnOnce(&Store) -> Result<T, Error>) -> Reply<T> {
    look(&shared.store.lock().expect("a handler panicked holding the store").store)
        .map(Json)
        .map_err(ApiError::Store)
}

fn word(verb: &Verb) -> String {
    format!("{verb:?}").to_lowercase()
}

/// Where a resource is, or would be once applied: its namespace, or none.
fn place(store: &Store, resource: &Resource) -> Option<String> {
    let namespaced = || match kith_api::kind(&resource.kind) {
        Some(kind) => kind.namespaced,
        // A kind nobody has defined (yet) is taken to be in no namespace: only a rule for everywhere covers it.
        None => store
            .definition(&resource.kind)
            .is_some_and(|definition| definition.spec["namespaced"] != false),
    };
    let default = || namespaced().then(|| kith_api::DEFAULT_NAMESPACE.to_string());
    resource.metadata.namespace.clone().or_else(default)
}

/// The kind and namespace a key is of: `Kind/namespace/name`, or `Kind/name`.
fn place_of(key: &str) -> (String, Option<String>) {
    let mut parts = key.split('/');
    let kind = parts.next().unwrap_or_default().to_string();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(namespace), Some(_), None) => (kind, Some(namespace.to_string())),
        _ => (kind, None),
    }
}

/// A refusal, with the reason, unless `caller` may do `verb` to each of `targets` (a
/// kind and where). The refusal goes in the audit log.
pub(crate) fn permit(
    shared: &Shared,
    caller: &Caller,
    verb: Verb,
    targets: impl FnOnce(&Store) -> Vec<(String, Option<String>)>,
) -> Result<(), ApiError> {
    let refused = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let grants = Grants::of(caller, &state.store);
        let mut targets = targets(&state.store).into_iter();
        targets.find(|(kind, namespace)| !grants.may(&verb, kind, namespace.as_deref()))
    };
    let Some((kind, namespace)) = refused else {
        return Ok(());
    };
    let verb = word(&verb);
    let place = namespace.map_or(String::new(), |namespace| format!(" in namespace {namespace}"));
    let why = format!("{caller} may not {verb} {kind}{place}: no Role bound to it allows that");
    shared
        .audit
        .record(caller, &verb, vec![format!("{kind}{place}")], Err(why.clone()));
    Err(ApiError::Refused(why))
}

/// For `list` and `watch`: a refusal if `caller` may see nothing of the kind anywhere.
/// What it may see of it is then picked resource by resource ([`seen`]).
fn sight(shared: &Shared, caller: &Caller, verb: Verb, kind: Option<&str>) -> Result<(), ApiError> {
    let any = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        Grants::of(caller, &state.store).anywhere(&verb, kind)
    };
    if any {
        return Ok(());
    }
    let (verb, kind) = (word(&verb), kind.unwrap_or("anything"));
    let why = format!("{caller} may not {verb} {kind}: no Role bound to it allows that");
    shared.audit.record(caller, &verb, vec![kind.into()], Err(why.clone()));
    Err(ApiError::Refused(why))
}

fn seen<'a>(
    store: &'a Store,
    caller: &Caller,
    verb: Verb,
    kind: Option<&'a str>,
) -> impl Iterator<Item = &'a Resource> {
    let grants = Grants::of(caller, store);
    let may = move |resource: &&Resource| grants.may(&verb, &resource.kind, resource.metadata.namespace.as_deref());
    store.list(kind).filter(may)
}

/// Make a change, and write down who did and how it went. On a task of its own: a
/// caller that hangs up while the store works neither stops the change nor escapes the log.
async fn change(
    shared: &Arc<Shared>,
    caller: &Caller,
    verb: &'static str,
    what: Vec<String>,
    command: Command,
) -> Result<Done, ApiError> {
    let (shared, caller) = (shared.clone(), caller.clone());
    let done = tokio::spawn(async move {
        let done = shared.submit(command).await;
        let said = done.as_ref().map(drop).map_err(Error::to_string);
        shared.audit.record(&caller, verb, what, said);
        done
    });
    let stopped = |e| ApiError::Store(Error::Io(format!("the change stopped: {e}")));
    done.await.map_err(stopped)?.map_err(ApiError::Store)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyOptions {
    #[serde(default)]
    dry_run: bool,
}

/// What a resource reaches into besides itself, which whoever writes it must be allowed too.
fn reach(shared: &Shared, caller: &Caller, resources: &[Resource]) -> Result<(), ApiError> {
    let placed = |store: &Store| -> Vec<(String, Option<String>)> {
        let placed = |resource: &Resource| (resource.kind.clone(), place(store, resource));
        resources.iter().map(placed).collect()
    };
    let written = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        placed(&state.store)
    };
    reach_of(shared, caller, &written)
}

/// [`reach`], of resources known by kind and namespace alone (a revision gone back to).
fn reach_of(shared: &Shared, caller: &Caller, written: &[(String, Option<String>)]) -> Result<(), ApiError> {
    let of = |kind: &str, into: &[&str]| -> Vec<(String, Option<String>)> {
        let of = written.iter().filter(|(written, _)| written == kind);
        of.flat_map(|(_, place)| into.iter().map(|kind| (kind.to_string(), place.clone())))
            .collect()
    };
    // A Backup sends a Volume's files where it says, signed with a Secret's keys: whoever
    // writes one must be allowed to read both.
    permit(shared, caller, Verb::Get, |_| of("Backup", &["Volume", "Secret"]))?;
    // A Share gives a Volume's files, to read and to write, to whom it names: whoever
    // writes one must be allowed to write the Volume.
    permit(shared, caller, Verb::Apply, |_| of("Share", &["Volume"]))
}

/// What applying `resources` would do, if `caller` may: a dry run.
pub(crate) async fn plan(
    shared: &Arc<Shared>,
    caller: &Caller,
    resources: Vec<Resource>,
) -> Result<Vec<Change>, ApiError> {
    permit(shared, caller, Verb::Apply, |store| {
        let target = |resource: &Resource| (resource.kind.clone(), place(store, resource));
        resources.iter().map(target).collect()
    })?;
    reach(shared, caller, &resources)?;
    // (Never closed.) Waiters queue: the page's checks, one per edit, are each worth an answer.
    let _turn = shared.dry_runs.acquire().await.expect("dry_runs is never closed");
    let claimed = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let put = crate::blobs::put_first(&state.store, &resources);
        put.and_then(|()| crate::releases::claims(&state.store, &resources))
    };
    claimed.map_err(|why| ApiError::Store(Error::Invalid(why)))?;
    // (Admission is asked as it would be: a dry run that passes where the apply is refused says nothing.)
    let resources = shared.admitted(resources).await.map_err(ApiError::Store)?;
    // Applied to the live store and taken back, under its lock: a copy of it cost 18 ms
    // at 10 000 resources and as much memory as the store.
    let changes = shared
        .store
        .lock()
        .expect("a handler panicked holding the store")
        .store
        .dry_run(resources);
    changes
        .map(|changes| veiled(shared, caller, changes))
        .map_err(ApiError::Store)
}

/// `changes` as `caller` may know them: what a resource was before is for those who may
/// `get` it (one who may only apply is told what happened, not what was there).
fn veiled(shared: &Shared, caller: &Caller, mut changes: Vec<Change>) -> Vec<Change> {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let grants = Grants::of(caller, &state.store);
    for change in &mut changes {
        let (kind, namespace) = place_of(&change.after.key());
        if !grants.may(&Verb::Get, &kind, namespace.as_deref()) {
            change.before = None;
        }
    }
    changes
}

async fn apply(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Query(options): Query<ApplyOptions>,
    Json(resources): Json<Vec<Resource>>,
) -> Reply<Vec<Change>> {
    if options.dry_run {
        return plan(&shared, &caller, resources).await.map(Json);
    }
    // Each resource of the body is asked about: one that is not allowed refuses them all.
    permit(&shared, &caller, Verb::Apply, |store| {
        let target = |resource: &Resource| (resource.kind.clone(), place(store, resource));
        resources.iter().map(target).collect()
    })?;
    reach(&shared, &caller, &resources)?;
    let keys: Vec<String> = resources.iter().map(Resource::key).collect();
    let claimed = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        crate::releases::claims(&state.store, &resources)
    };
    if let Err(why) = claimed {
        shared.audit.record(&caller, "apply", keys, Err(why.clone()));
        return Err(ApiError::Store(Error::Invalid(why)));
    }
    let at = kith_api::store::now();
    match change(&shared, &caller, "apply", keys, Command::Apply { resources, at }).await? {
        Done::Changes(changes) => Ok(Json(veiled(&shared, &caller, changes))),
        _ => Err(odd()),
    }
}

#[derive(Deserialize)]
struct ListOptions {
    kind: Option<String>,
}

async fn list(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Query(options): Query<ListOptions>,
) -> Reply<Vec<Resource>> {
    let kind = options.kind.as_deref();
    sight(&shared, &caller, Verb::List, kind)?;
    read(&shared, |store| {
        Ok(seen(store, &caller, Verb::List, kind).cloned().collect())
    })
}

/// The longest a `watch` holds a request, whatever `wait` asks for.
const MAX_WATCH_SECS: u64 = 25;

#[derive(Deserialize)]
struct WatchOptions {
    after: Option<u64>,
    kind: Option<String>,
    wait: Option<u64>,
}

async fn watch(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    certificate: Option<Extension<Certificate>>,
    Query(options): Query<WatchOptions>,
) -> Reply<serde_json::Value> {
    let kind = options.kind.as_deref();
    sight(&shared, &caller, Verb::Watch, kind)?;
    if let Some(after) = options.after {
        let secs = options.wait.unwrap_or(MAX_WATCH_SECS).min(MAX_WATCH_SECS);
        let (mut generation, mut stop) = (shared.generation.subscribe(), shared.stop.subscribe());
        // A timeout is not an error, nor is kithd stopping: the client gets the current state either way.
        tokio::select! {
            _ = generation.wait_for(|g| *g != after) => {}
            _ = stop.wait_for(|stop| *stop) => {}
            () = tokio::time::sleep(std::time::Duration::from_secs(secs)) => {}
        }
    }
    // The wait may have been long: an Identity deleted, or given another key, meanwhile is
    // told no more, and that is written down.
    // (An Identity with no certificate on record is not taken on trust.)
    if let Caller::Identity(name) = &caller
        && !certificate.is_some_and(|Extension(Certificate(der))| access::stands(&shared, name, &der))
    {
        let why = format!("this certificate does not stand for an Identity {name} any more");
        shared
            .audit
            .record(&caller, "watch", vec![format!("Identity/{name}")], Err(why.clone()));
        return Err(ApiError::Unauthorized(why));
    }
    read(&shared, |store| {
        Ok(serde_json::json!({
            "generation": *shared.generation.borrow(),
            // (What it may see is asked again here: the wait may have been long.)
            "resources": seen(store, &caller, Verb::Watch, kind).collect::<Vec<_>>(),
        }))
    })
}

async fn get_one(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
) -> Reply<Resource> {
    permit(&shared, &caller, Verb::Get, |_| vec![place_of(&key)])?;
    read(&shared, |store| store.get(&key).cloned().ok_or(Error::NotFound(key)))
}

async fn delete(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
) -> Reply<Resource> {
    permit(&shared, &caller, Verb::Delete, |_| vec![place_of(&key)])?;
    match change(&shared, &caller, "delete", vec![key.clone()], Command::Delete { key }).await? {
        Done::Deleted(resource) => Ok(Json(*resource)),
        _ => Err(odd()),
    }
}

async fn history(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
) -> Reply<Vec<Revision>> {
    permit(&shared, &caller, Verb::Get, |_| vec![place_of(&key)])?;
    read(&shared, |store| store.history(&key).map(<[Revision]>::to_vec))
}

#[derive(Deserialize)]
struct RollbackOptions {
    to: u64,
}

async fn rollback(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    Query(options): Query<RollbackOptions>,
) -> Reply<Change> {
    permit(&shared, &caller, Verb::Apply, |_| vec![place_of(&key)])?;
    reach_of(&shared, &caller, &[place_of(&key)])?;
    let (to, at) = (options.to, kith_api::store::now());
    let what = vec![format!("{key} to revision {to}")];
    match change(&shared, &caller, "rollback", what, Command::Rollback { key, to, at }).await? {
        Done::Changes(mut changes) if changes.len() == 1 => Ok(Json(changes.remove(0))),
        _ => Err(odd()),
    }
}

#[derive(Deserialize)]
struct LogOptions {
    /// A container or exec unit of the template; the first one when left out.
    unit: Option<String>,
    #[serde(default)]
    replica: u32,
    #[serde(default)]
    stderr: bool,
    #[serde(default)]
    previous: bool,
    offset: Option<u64>,
    tail: Option<u64>,
    /// Asked by another node: answer from this node's files, or not at all.
    #[serde(default)]
    here: bool,
}

/// Most bytes of output in one reply.
const LOG_CHUNK: u64 = 256 << 10;

async fn logs(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    Query(options): Query<LogOptions>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Reply<serde_json::Value> {
    // What a unit wrote is read by who may read the resource that runs it.
    permit(&shared, &caller, Verb::Get, |_| vec![place_of(&key)])?;
    // A replica that runs on another node: its output is there.
    let elsewhere = shared.cluster.as_ref().filter(|_| !options.here).and_then(|cluster| {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let status = state.store.get(&key)?.status.as_ref()?;
        let node = status["nodes"][options.replica.to_string()].as_str()?;
        let there = state.store.get(&format!("Node/{node}"))?.status.as_ref()?;
        let address = there["address"].as_str().filter(|_| node != cluster.me.name)?;
        // (Whatever the caller said of `here`, the other node is asked for its own.)
        let query = query.unwrap_or_default();
        let query: Vec<&str> = query.split('&').filter(|pair| !pair.starts_with("here")).collect();
        let query = query.join("&");
        Some((
            node.to_string(),
            format!("https://{address}/v1/logs/{key}?{query}&here=true"),
        ))
    });
    if let (Some((node, url)), Some(cluster)) = (elsewhere, &shared.cluster) {
        let failed = |e: reqwest::Error| ApiError::Store(Error::Io(format!("asking node {node} for the output: {e}")));
        let asked = cluster
            .client
            .get(url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;
        let answer = asked.and_then(reqwest::Response::error_for_status).map_err(failed)?;
        return answer.json().await.map(Json).map_err(failed);
    }
    // `more` is read before the file: when it says the unit is done, the file is complete.
    let Json((id, more)) = read(&shared, |store| {
        let resource = store.get(&key).ok_or(Error::NotFound(key.clone()))?;
        crate::controller::log_of(resource, options.unit.as_deref(), options.replica)
    })?;
    let stream = if options.stderr { "err" } else { "out" };
    let old = if options.previous { ".1" } else { "" };
    let path = shared.logs.join(format!("{id}.{stream}{old}"));
    // ponytail: read on the async thread; a chunk is small and local. Move to spawn_blocking if logs land on slow disks.
    let (data, next) = log_chunk(&path, options.offset, options.tail)
        .map_err(|e| ApiError::Store(Error::Io(format!("reading {}: {e}", path.display()))))?;
    Ok(Json(
        serde_json::json!({ "data": data, "next": next, "more": more && !options.previous }),
    ))
}

#[derive(Deserialize)]
struct AuditOptions {
    tail: Option<u64>,
}

/// The last entries of this node's audit log (100, or `tail`), oldest first.
async fn audit(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Query(options): Query<AuditOptions>,
) -> Reply<Vec<serde_json::Value>> {
    permit(&shared, &caller, Verb::Get, |_| vec![("Audit".into(), None)])?;
    let entries = shared.audit.tail(options.tail.unwrap_or(100));
    entries
        .map(Json)
        .map_err(|e| ApiError::Store(Error::Io(format!("reading the audit log: {e}"))))
}

/// Up to [`LOG_CHUNK`] bytes of a log file as text, and the offset just after them.
pub(crate) fn log_chunk(
    path: &std::path::Path,
    offset: Option<u64>,
    tail: Option<u64>,
) -> std::io::Result<(String, u64)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        // Nothing written yet (or nothing was moved aside).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((String::new(), 0)),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    let start = match (offset, tail) {
        // Past the end: the file was moved aside since, and a new one began.
        (Some(offset), _) => {
            if offset <= len {
                offset
            } else {
                0
            }
        }
        (None, Some(lines)) => {
            // ponytail: looks at the last megabyte only; longer tails start there.
            let from = len.saturating_sub(1 << 20);
            let mut end = Vec::new();
            file.seek(SeekFrom::Start(from))?;
            file.read_to_end(&mut end)?;
            // The newline that ends the last line does not start another.
            let body = end.strip_suffix(b"\n").unwrap_or(&end);
            let newlines = body.iter().rposition(|b| *b == b'\n');
            let mut cut = newlines.map(|at| at + 1).filter(|_| lines > 0);
            // Never more turns than there are lines: `tail` is whatever the caller sent.
            for _ in 1..lines.min(body.len() as u64 + 1) {
                if cut.is_none() {
                    break;
                }
                cut = cut.and_then(|at| body[..at - 1].iter().rposition(|b| *b == b'\n').map(|at| at + 1));
            }
            match (lines, cut) {
                (0, _) => len,
                (_, Some(at)) => from + at as u64,
                (_, None) => from,
            }
        }
        (None, None) => 0,
    };
    let mut bytes = Vec::new();
    file.seek(SeekFrom::Start(start))?;
    file.take(LOG_CHUNK).read_to_end(&mut bytes)?;
    // Never cut a character in half: what is incomplete at the end comes with the next chunk.
    if let Err(e) = std::str::from_utf8(&bytes)
        && e.error_len().is_none()
    {
        bytes.truncate(e.valid_up_to());
    }
    let next = start + bytes.len() as u64;
    Ok((String::from_utf8_lossy(&bytes).into_owned(), next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use std::time::Duration;

    /// Writing a Share or a Backup takes more than leave to write that kind: a Share gives
    /// a Volume away (leave to write it), a Backup reads a Volume and a Secret.
    #[tokio::test]
    async fn a_share_or_a_backup_reaches_no_further_than_its_writer_may() {
        let dir = std::env::temp_dir().join(format!("kithd-reach-{}", std::process::id()));
        let shared = crate::replica(None, &dir).await.unwrap();
        let roles = "
apiVersion: kith.dev/v1
kind: Role
metadata: {name: sharer}
spec:
  rules:
    - {kinds: [Share, Backup], verbs: [apply]}
    - {kinds: [Volume], verbs: [get]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: bob-sharer}
spec: {role: sharer, subjects: [bob]}
";
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(roles).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        let one = |text: &str| -> Vec<Resource> {
            let read = kith_api::Resource::from_source(text).unwrap();
            read.into_iter().map(Result::unwrap).collect()
        };
        let share = one("apiVersion: kith.dev/v1\nkind: Share\nmetadata: {name: s}\nspec: {volume: v, users: [bob]}\n");
        let backup = one("apiVersion: kith.dev/v1\nkind: Backup\nmetadata: {name: b}\nspec: {volume: v, every: 1d}\n");
        let bob = Caller::Identity("bob".into());
        assert!(reach(&shared, &bob, &share).is_err(), "bob may not write Volumes");
        assert!(reach(&shared, &bob, &backup).is_err(), "bob may not read Secrets");
        assert!(reach(&shared, &Caller::Admin, &share).is_ok());
        assert!(reach(&shared, &Caller::Admin, &backup).is_ok());
        // Going back to a revision of one is writing it.
        assert!(reach_of(&shared, &bob, &[place_of("Share/default/s")]).is_err());
        assert!(reach_of(&shared, &bob, &[place_of("ConfigMap/default/c")]).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A watch ends (401) once its Identity is deleted or given another key while it waits,
    /// and what it ended for is written down.
    #[tokio::test]
    async fn a_watch_ends_when_its_identity_no_longer_stands() {
        let dir = std::env::temp_dir().join(format!("kithd-watch-identity-{}", std::process::id()));
        let shared = crate::replica(None, &dir).await.unwrap();
        let ca = crate::pki::Ca::create().unwrap();
        let (_, _, public) = ca.issue_user("alice").unwrap();
        let (_, _, given) = ca.issue_user("alice").unwrap();
        let key = |pem: &str| {
            let spki = rustls::pki_types::SubjectPublicKeyInfoDer::from_pem_slice(pem.as_bytes());
            spki.unwrap().as_ref().to_vec()
        };
        let identity = |pem: &str| -> kith_api::Resource {
            let new = serde_json::json!({
                "apiVersion": kith_api::API_VERSION, "kind": "Identity",
                "metadata": {"name": "alice"}, "spec": {"publicKey": pem},
            });
            serde_json::from_value(new).unwrap()
        };
        let reader = "
apiVersion: kith.dev/v1
kind: Role
metadata: {name: reader}
spec:
  rules:
    - {kinds: ['*'], verbs: [get, list, watch]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: alice-reader}
spec: {role: reader, subjects: [alice]}
";
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(reader).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
            state.store.apply(identity(&public)).unwrap();
        }
        let outcome = |reply: Reply<serde_json::Value>| match reply {
            Ok(_) => "ok".to_string(),
            Err(ApiError::Unauthorized(_)) => "unauthorized".to_string(),
            Err(ApiError::Refused(why)) => format!("refused: {why}"),
            Err(ApiError::Store(e)) => format!("store: {e}"),
        };
        let watch_as_alice = |shared: &Arc<Shared>, der: &[u8]| {
            let after = *shared.generation.borrow() + 1;
            let options = WatchOptions {
                after: Some(after),
                kind: None,
                wait: Some(0),
            };
            watch(
                State(shared.clone()),
                Extension(Caller::Identity("alice".into())),
                Some(Extension(Certificate(der.to_vec()))),
                Query(options),
            )
        };
        assert!(watch_as_alice(&shared, &key(&public)).await.is_ok());

        // Given another key: the certificate it showed no longer stands.
        shared.store.lock().unwrap().store.apply(identity(&given)).unwrap();
        let ended = watch_as_alice(&shared, &key(&public)).await;
        assert_eq!(outcome(ended), "unauthorized");
        assert!(watch_as_alice(&shared, &key(&given)).await.is_ok());

        // Deleted while a watch waits: that watch is told no more once the wait is over. The
        // watch is polled first, so it has passed the Roles check before the delete runs.
        let after = *shared.generation.borrow();
        let options = WatchOptions {
            after: Some(after),
            kind: None,
            wait: Some(30),
        };
        let watching = watch(
            State(shared.clone()),
            Extension(Caller::Identity("alice".into())),
            Some(Extension(Certificate(key(&given)))),
            Query(options),
        );
        let deleting = async {
            shared.store.lock().unwrap().store.delete("Identity/alice").unwrap();
            shared.generation.send_modify(|g| *g += 1);
        };
        let (ended, ()) = tokio::join!(watching, deleting);
        assert_eq!(outcome(ended), "unauthorized");
        // Asked afresh, with no Identity to be bound to, it is refused by the Roles check.
        let fresh = outcome(watch_as_alice(&shared, &key(&given)).await);
        assert!(fresh.starts_with("refused"), "{fresh}");
        let entries = shared.audit.tail(10).unwrap();
        let refused = entries
            .iter()
            .filter(|e| e["who"] == "alice" && e["ok"] == false)
            .count();
        assert!(refused >= 2, "{entries:?}");
        assert!(
            entries
                .iter()
                .any(|e| e["verb"] == "watch" && e["what"][0] == "Identity/alice")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// With the four turns taken a fifth dry run waits (it is not refused), goes on when one
    /// is given back, and changes nothing in the store.
    #[tokio::test]
    async fn dry_runs_wait_for_one_of_four() {
        let dir = std::env::temp_dir().join(format!("kithd-dry-{}", std::process::id()));
        let shared = crate::replica(None, &dir).await.unwrap();
        let resource = serde_json::from_value::<Resource>(serde_json::json!({
            "apiVersion": "kith.dev/v1", "kind": "ConfigMap", "metadata": { "name": "c" }, "spec": {}
        }))
        .unwrap();
        let dry = || plan(&shared, &Caller::Admin, vec![resource.clone()]);
        let mut held: Vec<_> = Vec::new();
        for _ in 0..crate::DRY_RUNS {
            held.push(shared.dry_runs.acquire().await.unwrap());
        }
        assert!(tokio::time::timeout(Duration::from_millis(300), dry()).await.is_err());
        held.pop();
        let changes = tokio::time::timeout(Duration::from_secs(10), dry())
            .await
            .unwrap()
            .ok()
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].action, kith_api::store::Action::Created);
        assert_eq!(shared.dry_runs.available_permits(), 1);
        assert!(shared.store.lock().unwrap().store.get("ConfigMap/default/c").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_chunks() {
        let path = std::env::temp_dir().join(format!("kithd-chunk-{}", std::process::id()));
        assert_eq!(log_chunk(&path, None, None).unwrap(), (String::new(), 0));
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        let chunk = |offset, tail| log_chunk(&path, offset, tail).unwrap();
        assert_eq!(chunk(None, None), ("one\ntwo\nthree\n".into(), 14));
        assert_eq!(chunk(Some(4), None), ("two\nthree\n".into(), 14));
        assert_eq!(chunk(Some(14), None), (String::new(), 14));
        // An offset from before the file was moved aside starts over.
        assert_eq!(chunk(Some(99), None).1, 14);
        assert_eq!(chunk(None, Some(0)), (String::new(), 14));
        assert_eq!(chunk(None, Some(1)), ("three\n".into(), 14));
        assert_eq!(chunk(None, Some(2)), ("two\nthree\n".into(), 14));
        assert_eq!(chunk(None, Some(9)), ("one\ntwo\nthree\n".into(), 14));
        // However many lines are asked for, it is the file that bounds the work.
        assert_eq!(chunk(None, Some(u64::MAX)), ("one\ntwo\nthree\n".into(), 14));
        // Half a character waits for its other half.
        std::fs::write(&path, [b'a', 0xC3]).unwrap();
        assert_eq!(chunk(None, None), ("a".into(), 1));
        std::fs::remove_file(&path).unwrap();
    }
}

#[derive(Deserialize)]
struct Push {
    /// The repository: `oci://HOST/PATH`.
    to: String,
    files: std::collections::BTreeMap<String, String>,
    signature: Option<String>,
    /// Not a package but files for a Source to sync: the name and tag to push them as.
    source: Option<(String, String)>,
}

/// Put a package (or a Source's files) in a registry, from here: kithd has what it
/// takes to talk to one, and `kith` does not. The signature is made by whoever asks;
/// no key comes here.
// Reaching a registry through kithd, either way, takes `apply` on `Package`.
async fn push(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Json(asked): Json<Push>,
) -> Reply<String> {
    permit(&shared, &caller, Verb::Apply, |_| vec![("Package".into(), None)])?;
    let invalid = |e| ApiError::Store(Error::Invalid(e));
    let (name, version, blob) = match asked.source {
        Some((name, tag)) => {
            kith_packages::artifact::plain(&asked.files).map_err(invalid)?;
            (name, tag, serde_json::to_vec(&asked.files).expect("text by text"))
        }
        None => {
            let package = kith_packages::Package::from_files(asked.files).map_err(invalid)?;
            let blob = package.blob();
            (package.meta.name, package.meta.version, blob)
        }
    };
    let what = vec![format!("{name}:{version} to {}", asked.to)];
    let pushed = crate::registry::push(&asked.to, &name, &version, blob, asked.signature).await;
    shared
        .audit
        .record(&caller, "push", what, pushed.as_ref().map(drop).map_err(String::clone));
    pushed.map(Json).map_err(|e| ApiError::Store(Error::Io(e)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pull {
    from: String,
    name: String,
    version: String,
    /// The key the package must be signed with; none: it is taken as it comes.
    public_key: Option<String>,
}

/// A package's files from a registry, its signature checked when a key is given.
async fn pull(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Json(asked): Json<Pull>,
) -> Reply<std::collections::BTreeMap<String, String>> {
    permit(&shared, &caller, Verb::Apply, |_| vec![("Package".into(), None)])?;
    // (An Identity names any registry it likes: only outside ones, as a namespace's Source.)
    let outward = matches!(caller, Caller::Identity(_));
    let fetched = crate::registry::pull(&asked.from, &asked.name, &asked.version, outward).await;
    let (blob, signature) = fetched.map_err(|e| ApiError::Store(Error::Io(e)))?;
    let package = crate::registry::checked(
        &blob,
        signature.as_deref(),
        asked.public_key.as_deref(),
        &asked.name,
        &asked.version,
    );
    package
        .map(|package| Json(package.files))
        .map_err(|e| ApiError::Store(Error::Invalid(e)))
}
