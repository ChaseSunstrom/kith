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
        .route(
            "/v1/volumes/{namespace}/{name}/files",
            get(crate::volume_files::get).put(crate::volume_files::put),
        )
        .route("/v1/packages/push", post(push))
        .route("/v1/packages/pull", post(pull))
        .route("/v1/audit", get(audit))
        .route("/v1/run", post(run::run))
        .route("/v1/tokens", post(crate::cluster::token))
        .route("/v1/lock", get(crate::crypt::warned))
        .route("/v1/lock/{name}", post(crate::crypt::set))
        .route("/v1/lock/{name}/passphrase", post(crate::crypt::pass))
        .route("/v1/lock/{name}/recovery", post(crate::crypt::recovery))
        .route("/v1/duress", post(crate::crypt::duress_all))
        .route("/v1/seats/{name}/activity", post(crate::seats::activity))
        .route("/v1/drain/{name}", get(drain_plan).post(drain_set))
        // (The network boot file is 40 MB.)
        .route(
            "/v1/netboot",
            get(crate::cluster::netboot)
                .delete(crate::cluster::netboot)
                .put(crate::cluster::netboot)
                .layer(axum::extract::DefaultBodyLimit::max(96 << 20)),
        )
        .merge(crate::ui::router())
        .merge(crate::kube::router())
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

pub(crate) fn word(verb: &Verb) -> String {
    format!("{verb:?}").to_lowercase()
}

/// Where a resource is, or would be once applied: its namespace, or none.
pub(crate) fn place(store: &Store, resource: &Resource) -> Option<String> {
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
pub(crate) fn place_of(key: &str) -> (String, Option<String>) {
    let mut parts = key.split('/');
    let kind = parts.next().unwrap_or_default().to_string();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(namespace), Some(_), None) => (kind, Some(namespace.to_string())),
        _ => (kind, None),
    }
}

/// A right asked for: to do a verb to a kind, in a namespace (or in none).
pub(crate) type Right = (Verb, String, Option<String>);

/// What writing `resources` takes: the right to apply each, and to whatever each reaches
/// into besides itself. The API asks it of whoever applies them, and the Release and Source
/// controllers of whoever applied the Release or Source that renders them.
pub(crate) fn takes(store: &Store, resources: &[Resource]) -> Vec<Right> {
    let applied = resources
        .iter()
        .map(|resource| (Verb::Apply, resource.kind.clone(), place(store, resource)));
    applied.chain(beyond(store, resources)).collect()
}

/// What `resources` reach into besides themselves.
fn beyond(store: &Store, resources: &[Resource]) -> Vec<Right> {
    // A claim that says `provision` has a Volume made for it on a node: whoever writes
    // one must be allowed to write a Volume there.
    let asks = |resource: &&Resource| resource.kind == "VolumeClaim" && resource.spec["provision"] == true;
    let made = resources.iter().filter(asks);
    let made = made.map(|resource| (Verb::Apply, "Volume".to_string(), place(store, resource)));
    let written: Vec<_> = resources
        .iter()
        .map(|resource| (resource.kind.clone(), place(store, resource)))
        .collect();
    made.chain(reached(&written)).collect()
}

/// What resources known by kind and namespace alone reach into besides themselves.
fn reached(written: &[(String, Option<String>)]) -> Vec<Right> {
    let mut rights = Vec::new();
    for (kind, place) in written {
        let into: &[(Verb, &str)] = match kind.as_str() {
            // A Backup sends a Volume's files where it says, signed with a Secret's keys:
            // whoever writes one must be allowed to read both.
            "Backup" => &[(Verb::Get, "Volume"), (Verb::Get, "Secret")],
            // A CronJob's Jobs are made for it by the cluster, as it says them: whoever
            // writes one must be allowed to write a Job.
            "CronJob" => &[(Verb::Apply, "Job")],
            // An Image is a Volume's files, for every process of every node to read.
            "Image" => &[(Verb::Get, "Volume")],
            // A Share gives a Volume's files, to read and to write, to whom it names:
            // whoever writes one must be allowed to write the Volume.
            "Share" => &[(Verb::Apply, "Volume")],
            _ => &[],
        };
        rights.extend(
            into.iter()
                .map(|(verb, into)| (verb.clone(), into.to_string(), place.clone())),
        );
    }
    rights
}

/// A refusal, with the reason, unless `caller` may do `verb` to each of `targets` (a
/// kind and where). The refusal goes in the audit log.
pub(crate) fn permit(
    shared: &Shared,
    caller: &Caller,
    verb: Verb,
    targets: impl FnOnce(&Store) -> Vec<(String, Option<String>)>,
) -> Result<(), ApiError> {
    allowed(shared, caller, |store| {
        let targets = targets(store).into_iter();
        targets
            .map(|(kind, namespace)| (verb.clone(), kind, namespace))
            .collect()
    })
}

/// A refusal, with the reason, unless `caller` has each of `rights`. The refusal goes in
/// the audit log.
fn allowed(shared: &Shared, caller: &Caller, rights: impl FnOnce(&Store) -> Vec<Right>) -> Result<(), ApiError> {
    let refused = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let grants = Grants::of(caller, &state.store);
        let mut rights = rights(&state.store).into_iter();
        rights.find(|(verb, kind, namespace)| !grants.may(verb, kind, namespace.as_deref()))
    };
    let Some((verb, kind, namespace)) = refused else {
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
pub(crate) fn sight(shared: &Shared, caller: &Caller, verb: Verb, kind: Option<&str>) -> Result<(), ApiError> {
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
        // Who asked goes with the write: an Identity's is decided again where it is put in the log.
        let done = shared.submit_as(command, Some(&caller)).await;
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

/// What going back to revision `to` of `key` takes: what applying that revision would
/// ([`takes`]: a claim that provisions asks for its Volume there too). Of a revision that is
/// not there, what its kind and namespace alone say.
fn back_takes(store: &Store, key: &str, to: u64) -> Vec<Right> {
    let history = store.history(key).ok();
    let was = history.and_then(|history| history.iter().find(|was| was.resource.metadata.revision == Some(to)));
    match was {
        Some(was) => takes(store, std::slice::from_ref(&was.resource)),
        None => {
            let (kind, namespace) = place_of(key);
            let mut asks = vec![(Verb::Apply, kind.clone(), namespace.clone())];
            asks.extend(reached(&[(kind, namespace)]));
            asks
        }
    }
}

/// Why `caller` may not write `command`, as the store now stands: the asking of [`applied`],
/// [`deleted`] and `rollback` made again where the write is put in the log (`raft.rs`), so
/// that a Role taken away while the write was on its way still stops it. Any other command
/// with an Identity's name on it is refused.
///
/// Not every route an Identity reaches is decided here. Seat activity (`seats.rs`), `/v1/lock`
/// and the duress routes (`crypt.rs`), blobs, volume files, backups and the node routes of
/// `cluster.rs` ask [`permit`] as the request arrives and then `submit` or `write` with no
/// caller: they are decided once, and a Role taken away meanwhile does not stop them (T-0555).
/// Before a caller is passed with them, this must learn their commands: seat activity writes a
/// Status, which it would refuse, and `unlock` of a forgotten NodeKey sends a Delete after
/// `permit` asked for Apply, which it would ask as Delete.
pub(crate) fn refused(store: &Store, caller: &Caller, command: &Command) -> Option<String> {
    let asks = match command {
        Command::Apply { resources, .. } => takes(store, resources),
        Command::Rollback { key, to, .. } => back_takes(store, key, *to),
        Command::Delete { key } => {
            let (kind, namespace) = place_of(key);
            vec![(Verb::Delete, kind, namespace)]
        }
        _ => {
            return Some(format!(
                "{caller} may not write this to the store: it is not an apply, a delete or a rollback"
            ));
        }
    };
    let grants = Grants::of(caller, store);
    let (verb, kind, namespace) = asks
        .into_iter()
        .find(|(verb, kind, namespace)| !grants.may(verb, kind, namespace.as_deref()))?;
    let place = namespace.map_or(String::new(), |namespace| format!(" in namespace {namespace}"));
    let verb = word(&verb);
    Some(format!(
        "{caller} may not {verb} {kind}{place} (decided again as the write was put in the log): no Role bound to it allows that now"
    ))
}

/// Who `caller` is as a writer of a Release or a Source: whoever a node passed on, not the node.
fn writer(caller: &Caller) -> &Caller {
    match caller {
        Caller::Via(_, who) | Caller::Checked(_, who) => writer(who),
        caller => caller,
    }
}

/// `resources` with each Release and Source written down as `caller`'s, and, for an
/// Identity, the print of the key it has in `store`: what the client said of either is
/// not taken. (None, as the local socket's: it acts for no key.)
fn stamped(store: &Store, caller: &Caller, mut resources: Vec<Resource>) -> Vec<Resource> {
    let who = writer(caller);
    let print = match who {
        Caller::Identity(name) => crate::releases::print_of(store, name),
        _ => None,
    };
    for resource in &mut resources {
        if matches!(resource.kind.as_str(), "Release" | "Source") {
            let annotations = &mut resource.metadata.annotations;
            annotations.insert(crate::releases::WRITER.into(), who.to_string());
            match &print {
                Some(print) => annotations.insert(crate::releases::KEY.into(), print.clone()),
                None => annotations.remove(crate::releases::KEY),
            };
        }
    }
    resources
}

/// [`stamped`] by the key the writer has in the store now.
fn stamped_by(shared: &Shared, caller: &Caller, resources: Vec<Resource>) -> Vec<Resource> {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    stamped(&state.store, caller, resources)
}

/// What applying `resources` would do, if `caller` may: a dry run.
pub(crate) async fn plan(
    shared: &Arc<Shared>,
    caller: &Caller,
    resources: Vec<Resource>,
) -> Result<Vec<Change>, ApiError> {
    let resources = stamped_by(shared, caller, resources);
    allowed(shared, caller, |store| takes(store, &resources))?;
    // (Never closed.) Waiters queue: the page's checks, one per edit, are each worth an answer.
    let _turn = shared.dry_runs.acquire().await.expect("dry_runs is never closed");
    let claimed = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let put = crate::blobs::put_first(&state.store, &resources);
        put.and_then(|()| crate::releases::claims(&state.store, &resources))
            .and_then(|()| crate::exits::admitted(&state.store, &resources))
            .and_then(|()| crate::pods::unshared(&state.store, &resources))
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
    applied(&shared, &caller, resources).await.map(Json)
}

/// Apply `resources` as `caller`, if it may: what `/v1/apply` does, for whoever else takes
/// resources in (the Kubernetes API's paths).
pub(crate) async fn applied(
    shared: &Arc<Shared>,
    caller: &Caller,
    resources: Vec<Resource>,
) -> Result<Vec<Change>, ApiError> {
    let resources = stamped_by(shared, caller, resources);
    // Each resource of the body is asked about: one that is not allowed refuses them all.
    allowed(shared, caller, |store| takes(store, &resources))?;
    let keys: Vec<String> = resources.iter().map(Resource::key).collect();
    let claimed = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let nodes = resources.iter().filter(|resource| resource.kind == "Node");
        let nodes: Vec<_> = nodes
            .map(|node| (node.metadata.name.as_str(), Some(&node.spec)))
            .collect();
        access::control_stays(&state.store, &nodes)
            .and_then(|()| crate::releases::claims(&state.store, &resources))
            .and_then(|()| crate::exits::admitted(&state.store, &resources))
            .and_then(|()| crate::pods::unshared(&state.store, &resources))
    };
    if let Err(why) = claimed {
        shared.audit.record(caller, "apply", keys, Err(why.clone()));
        return Err(ApiError::Store(Error::Invalid(why)));
    }
    let at = kith_api::store::now();
    match change(shared, caller, "apply", keys, Command::Apply { resources, at }).await? {
        Done::Changes(changes) => Ok(veiled(shared, caller, changes)),
        _ => Err(odd()),
    }
}

#[derive(Deserialize)]
struct DrainOptions {
    /// `drain` or `undrain`.
    #[serde(rename = "do")]
    step: String,
}

/// A worker runs from a view of the store: it has neither every Workload nor the other nodes'
/// load, so its plan would be short without saying so. A control node plans and drains.
fn drains_here(shared: &Shared) -> Result<(), ApiError> {
    match shared.view.borrow().is_some() {
        true => Err(ApiError::Refused(
            "this node is a worker and runs from a view of the store: ask a control node to drain a node".into(),
        )),
        false => Ok(()),
    }
}

/// What `kith node drain` would do to what runs on the node (`GET /v1/drain/NAME`): one line
/// per Workload, Job and NodeWorkload with a copy there, for whoever may get those kinds.
async fn drain_plan(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
) -> Reply<Vec<serde_json::Value>> {
    permit(&shared, &caller, Verb::Get, |_| vec![("Node".to_string(), None)])?;
    drains_here(&shared)?;
    let seen = crate::sched::seen_at(&shared, std::time::Instant::now());
    let grace = shared.lost_after;
    read(&shared, |store| {
        // A name that is no node's is not a node with nothing on it.
        let key = format!("Node/{name}");
        store.get(&key).ok_or(Error::NotFound(key))?;
        let grants = Grants::of(&caller, store);
        let lines = crate::sched::drain_lines(store, &seen, grace, &name);
        let may = |line: &serde_json::Value| {
            let kind = line["kind"].as_str().unwrap_or_default();
            grants.may(&Verb::Get, kind, line["namespace"].as_str())
        };
        Ok(lines.into_iter().filter(may).collect())
    })
}

/// Drains or undrains the node (`POST /v1/drain/NAME?do=drain|undrain`): an apply of the Node
/// through `applied()`, so whoever may apply Nodes may drain them, and it is audited as one.
async fn drain_set(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
    Query(options): Query<DrainOptions>,
) -> Reply<Vec<Change>> {
    permit(&shared, &caller, Verb::Apply, |_| vec![("Node".to_string(), None)])?;
    drains_here(&shared)?;
    let key = format!("Node/{name}");
    let Json(mut node) = read(&shared, |store| {
        store.get(&key).cloned().ok_or(Error::NotFound(key.clone()))
    })?;
    match options.step.as_str() {
        "drain" => crate::sched::drain_on(&mut node.spec),
        "undrain" => crate::sched::drain_off(&mut node.spec),
        other => {
            return Err(ApiError::Store(Error::Invalid(format!(
                "do is drain or undrain, not {other}"
            ))));
        }
    }
    applied(&shared, &caller, vec![node]).await.map(Json)
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
    if let (Caller::Node(name), Some(Extension(Certificate(der)))) = (&caller, &certificate)
        && !crate::cluster::admitted(&shared, name, der)
    {
        return Err(ApiError::Unauthorized(crate::cluster::EVICTED.into()));
    }
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
    deleted(&shared, &caller, key).await.map(Json)
}

/// Delete the resource at `key` as `caller`, if it may: what `DELETE /v1/resources` does.
pub(crate) async fn deleted(shared: &Arc<Shared>, caller: &Caller, key: String) -> Result<Resource, ApiError> {
    permit(shared, caller, Verb::Delete, |_| vec![place_of(&key)])?;
    if let Some(node) = key.strip_prefix("Node/") {
        let Json(()) = read(shared, |store| {
            access::control_stays(store, &[(node, None)]).map_err(Error::Invalid)
        })?;
    }
    match change(shared, caller, "delete", vec![key.clone()], Command::Delete { key }).await? {
        Done::Deleted(resource) => Ok(*resource),
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
    allowed(&shared, &caller, |store| back_takes(store, &key, options.to))?;
    let (to, at) = (options.to, kith_api::store::now());
    // (What the cluster has forgotten or wiped is in the versions before it.)
    if key.starts_with("NodeKey/") {
        let why = "a NodeKey is not rolled back: `kith node lock`, `unlock`, `seal` and `wipe` change it";
        return Err(ApiError::Store(Error::Invalid(why.into())));
    }
    // Going back to a Release's or a Source's revision is applying it: as whoever goes back.
    if key.starts_with("Release/") || key.starts_with("Source/") {
        let Json(was) = read(&shared, |store| {
            let history = store.history(&key)?;
            let was = history.iter().find(|was| was.resource.metadata.revision == Some(to));
            let mut was = was
                .ok_or_else(|| Error::NotFound(format!("{key} revision {to}")))?
                .resource
                .clone();
            was.metadata.revision = None;
            Ok(was)
        })?;
        let mut changes = applied(&shared, &caller, vec![was]).await?;
        return changes.pop().map(Json).ok_or_else(odd);
    }
    if let Some(node) = key.strip_prefix("Node/") {
        let Json(()) = read(&shared, |store| {
            let was = store
                .history(&key)?
                .iter()
                .find(|was| was.resource.metadata.revision == Some(to));
            let after = was.map(|was| (node, Some(&was.resource.spec)));
            access::control_stays(store, after.as_slice()).map_err(Error::Invalid)
        })?;
    }
    let what = vec![format!("{key} to revision {to}")];
    match change(&shared, &caller, "rollback", what, Command::Rollback { key, to, at }).await? {
        Done::Changes(mut changes) if changes.len() == 1 => Ok(Json(changes.remove(0))),
        _ => Err(odd()),
    }
}

#[derive(Deserialize, Default)]
pub(crate) struct LogOptions {
    /// A container or exec unit of the template; the first one when left out.
    pub unit: Option<String>,
    #[serde(default)]
    pub replica: u32,
    #[serde(default)]
    pub stderr: bool,
    #[serde(default)]
    pub previous: bool,
    pub offset: Option<u64>,
    pub tail: Option<u64>,
    /// Asked by another node: answer from this node's files, or not at all.
    #[serde(default)]
    pub here: bool,
}

/// Most bytes of output in one reply.
const LOG_CHUNK: u64 = 256 << 10;

async fn logs(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    Query(options): Query<LogOptions>,
) -> Reply<serde_json::Value> {
    // What a unit wrote is read by who may read the resource that runs it.
    permit(&shared, &caller, Verb::Get, |_| vec![place_of(&key)])?;
    output(&shared, &caller, &key, &options).await
}

/// A chunk of what a unit of the resource at `key` wrote, from whichever node it runs on.
/// (Whether `caller` may read it is asked before, and by the other node of the one it is passed to.)
pub(crate) async fn output(
    shared: &Arc<Shared>,
    caller: &Caller,
    key: &str,
    options: &LogOptions,
) -> Reply<serde_json::Value> {
    // A replica that runs on another node: its output is there.
    let elsewhere = shared.cluster.as_ref().filter(|_| !options.here).and_then(|cluster| {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let status = state.store.get(key)?.status.as_ref()?;
        // (A Job is run by one node, all of its runs.)
        let replica = if key.starts_with("Job/") { 0 } else { options.replica };
        let node = status["nodes"][replica.to_string()].as_str()?;
        let there = crate::view::Upstream::of(state.store.get(&format!("Node/{node}"))?);
        let there = there.filter(|_| node != cluster.me.name)?;
        let address = &there.address;
        // (Whatever the caller said of `here`, the other node is asked for its own.)
        let mut query = format!(
            "replica={}&stderr={}&previous={}&here=true",
            options.replica, options.stderr, options.previous
        );
        for (name, value) in [("offset", options.offset), ("tail", options.tail)] {
            query.extend(value.map(|value| format!("&{name}={value}")));
        }
        let mut url = reqwest::Url::parse(&format!("https://{address}/v1/logs/{key}?{query}")).ok()?;
        if let Some(unit) = &options.unit {
            url.query_pairs_mut().append_pair("unit", unit);
        }
        Some((node.to_string(), there, url))
    });
    if let (Some((node, there, url)), Some(cluster)) = (elsewhere, &shared.cluster) {
        let failed = |e: reqwest::Error| {
            let e = crate::cluster::why(&e);
            ApiError::Store(Error::Io(format!("asking node {node} for the output: {e}")))
        };
        // (That node, and no other at its address: the output of a unit may hold secrets.)
        let client = cluster.to(&there).map_err(|e| ApiError::Store(Error::Io(e)))?;
        let asked = client
            .get(url)
            .header(crate::access::FOR, caller.to_string())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;
        let answer = asked.and_then(reqwest::Response::error_for_status).map_err(failed)?;
        return answer.json().await.map(Json).map_err(failed);
    }
    // `more` is read before the file: when it says the unit is done, the file is complete.
    let Json((id, more)) = read(shared, |store| {
        let resource = store.get(key).ok_or(Error::NotFound(key.to_string()))?;
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

    /// What a resource reaches into besides itself, which whoever writes it must be allowed too.
    fn reach(shared: &Shared, caller: &Caller, resources: &[Resource]) -> Result<(), ApiError> {
        allowed(shared, caller, |store| beyond(store, resources))
    }

    /// Writing a Share or a Backup takes more than leave to write that kind: a Share gives
    /// a Volume away (leave to write it), a Backup reads a Volume and a Secret.
    #[tokio::test]
    async fn a_share_or_a_backup_reaches_no_further_than_its_writer_may() {
        let dir = std::env::temp_dir().join(format!("kithd-reach-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
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
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: bob}
spec: {}
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
        // An Image gives a Volume's files to every process of every node: leave to read it.
        let image = one("apiVersion: kith.dev/v1\nkind: Image\nmetadata: {name: i}\nspec: {volume: v}\n");
        assert!(reach(&shared, &bob, &image).is_ok(), "bob may read Volumes");
        assert!(reach(&shared, &Caller::Identity("eve".into()), &image).is_err());
        // A CronJob is the Jobs made of it, and a claim that asks for a volume is that Volume.
        let cron = "apiVersion: kith.dev/v1\nkind: CronJob\nmetadata: {name: c}\nspec: {schedule: '* * * * *', job: {template: {exec: [{name: a, command: ['true']}]}}}\n";
        assert!(reach(&shared, &bob, &one(cron)).is_err(), "bob may not write Jobs");
        assert!(reach(&shared, &Caller::Admin, &one(cron)).is_ok());
        let claim = |more: &str| {
            one(&format!(
                "apiVersion: kith.dev/v1\nkind: VolumeClaim\nmetadata: {{name: k}}\nspec: {{size: 1Gi{more}}}\n"
            ))
        };
        assert!(reach(&shared, &bob, &claim("")).is_ok());
        assert!(
            reach(&shared, &bob, &claim(", provision: true")).is_err(),
            "bob may not write Volumes"
        );
        // Going back to a revision of one is writing it (one not there: by its kind alone).
        let back = |key: &str| allowed(&shared, &bob, |store| back_takes(store, key, 1));
        assert!(back("Share/default/s").is_err(), "bob may not write Volumes");
        assert!(back("Backup/default/b").is_err(), "bob may not read Secrets");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Going back to a revision takes what applying that revision would: a claim that
    /// provisioned asks for its Volume again, at the API and where the leader decides.
    #[tokio::test]
    async fn rollback_takes_what_applying_the_revision_would() {
        let dir = std::env::temp_dir().join(format!("kithd-back-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        let all = "
apiVersion: kith.dev/v1
kind: Role
metadata: {name: claimer}
spec: {rules: [{kinds: [VolumeClaim], verbs: [apply]}]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: carol-claimer}
spec: {role: claimer, subjects: [carol]}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: carol}
spec: {}
---
apiVersion: kith.dev/v1
kind: VolumeClaim
metadata: {name: k}
spec: {size: 1Gi, provision: true}
---
apiVersion: kith.dev/v1
kind: VolumeClaim
metadata: {name: k}
spec: {size: 1Gi}
";
        let key = "VolumeClaim/default/k";
        let (provisioned, plain) = {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(all).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
            let history = state.store.history(key).unwrap();
            let of = |provision: bool| {
                let was = history
                    .iter()
                    .find(|was| (was.resource.spec["provision"] == true) == provision);
                was.unwrap().resource.metadata.revision.unwrap()
            };
            (of(true), of(false))
        };
        let carol = Caller::Identity("carol".into());
        let back = |caller: &Caller, to: u64| allowed(&shared, caller, |store| back_takes(store, key, to));
        assert!(back(&carol, provisioned).is_err(), "carol may not write Volumes");
        assert!(back(&carol, plain).is_ok());
        assert!(back(&Caller::Admin, provisioned).is_ok());
        // And the leader, as it puts the write in the log.
        let state = shared.store.lock().unwrap();
        let command = |to: u64| Command::Rollback {
            key: key.into(),
            to,
            at: 0,
        };
        let said = refused(&state.store, &carol, &command(provisioned)).unwrap();
        assert!(said.contains("may not apply Volume in namespace default"), "{said}");
        assert_eq!(refused(&state.store, &carol, &command(plain)), None);
        drop(state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Whoever applies a Release or a Source is written down on it by the server, whatever
    /// the client sent: a dry run shows it, one passed on by a node is who asked it, and
    /// going back to a revision is applying it.
    #[tokio::test]
    async fn release_rights_and_source_rights_are_whoever_applied_them() {
        use crate::releases::WRITER;
        let dir = std::env::temp_dir().join(format!("kithd-writer-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        let roles = "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {name: bob}\nspec: {}\n---\n\
                     apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: shop}\n\
                     spec: {rules: [{kinds: [Release, Source], verbs: [apply], namespaces: [shop]}]}\n---\n\
                     apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: bob-shop}\nspec: {role: shop, subjects: [bob]}\n";
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(roles).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        let sent = "apiVersion: kith.dev/v1\nkind: Release\n\
                    metadata: {name: r, namespace: shop, annotations: {'kith.dev/written-by': 'local socket'}}\n\
                    spec: {package: {name: maps}}\n---\n\
                    apiVersion: kith.dev/v1\nkind: Source\n\
                    metadata: {name: s, namespace: shop, annotations: {'kith.dev/written-by': 'local socket'}}\n\
                    spec: {git: {url: 'https://example.org/a.git'}}\n";
        let sent: Vec<Resource> = kith_api::Resource::from_source(sent)
            .unwrap()
            .into_iter()
            .map(Result::unwrap)
            .collect();
        let bob = Caller::Identity("bob".into());
        let written = |key: &str| {
            let state = shared.store.lock().unwrap();
            state.store.get(key).unwrap().metadata.annotations.get(WRITER).cloned()
        };
        let planned = plan(&shared, &bob, sent.clone()).await.ok().unwrap();
        let stamps: Vec<_> = planned
            .iter()
            .map(|change| change.after.metadata.annotations.get(WRITER))
            .collect();
        assert_eq!(stamps, [Some(&"bob".to_string()); 2]);

        let within = Duration::from_secs(30);
        let first = tokio::time::timeout(within, applied(&shared, &Caller::Admin, sent.clone()));
        first.await.unwrap().ok().unwrap();
        assert_eq!(written("Release/shop/r").as_deref(), Some("local socket"));
        let via = Caller::Via("n1".into(), Box::new(bob.clone()));
        let again = tokio::time::timeout(within, applied(&shared, &via, sent.clone()));
        again.await.unwrap().ok().unwrap();
        assert_eq!(written("Release/shop/r").as_deref(), Some("bob"));
        assert_eq!(written("Source/shop/s").as_deref(), Some("bob"));

        // Back to what the local socket wrote: bob's, as bob goes back to it.
        let back = rollback(
            State(shared.clone()),
            Extension(bob.clone()),
            Path("Release/shop/r".to_string()),
            Query(RollbackOptions { to: 1 }),
        );
        let Json(back) = tokio::time::timeout(within, back).await.unwrap().ok().unwrap();
        // (Revision 1 written down as bob's is revision 2: nothing changes.)
        assert_eq!(back.after.metadata.revision, Some(2));
        assert_eq!(
            back.after.metadata.annotations.get(WRITER).map(String::as_str),
            Some("bob")
        );
        assert_eq!(written("Release/shop/r").as_deref(), Some("bob"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The print of the writer Identity's key is written beside its name, whatever the
    /// client sent for it: through a node too, in a dry run and in an apply; the local
    /// socket's has none (T-0551).
    #[tokio::test]
    async fn writer_print_the_server_writes_the_identitys_key_whatever_the_client_sent() {
        use crate::releases::{KEY, bob_is, bobs_key};
        let dir = std::env::temp_dir().join(format!("kithd-writer-print-{}", std::process::id()));
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        bob_is(&mut shared.store.lock().unwrap().store, 0);
        let sent = "apiVersion: kith.dev/v1\nkind: Release\n\
                    metadata: {name: r, namespace: shop, annotations: {'kith.dev/written-by': 'local socket', 'kith.dev/written-key': 'forged'}}\n\
                    spec: {package: {name: maps}}\n---\n\
                    apiVersion: kith.dev/v1\nkind: Source\n\
                    metadata: {name: s, namespace: shop}\n\
                    spec: {git: {url: 'https://example.org/a.git'}}\n";
        let sent: Vec<Resource> = Resource::from_source(sent)
            .unwrap()
            .into_iter()
            .map(Result::unwrap)
            .collect();
        let prints = |changes: &[Change]| -> Vec<Option<String>> {
            changes
                .iter()
                .map(|change| change.after.metadata.annotations.get(KEY).cloned())
                .collect()
        };
        let bob = Caller::Via("n1".into(), Box::new(Caller::Identity("bob".into())));
        let planned = plan(&shared, &Caller::Admin, sent.clone()).await.ok().unwrap();
        assert_eq!(
            prints(&planned),
            [None, None],
            "the local socket has no key; what was sent is not kept"
        );
        let within = Duration::from_secs(30);
        let made = tokio::time::timeout(within, applied(&shared, &Caller::Admin, sent.clone()));
        assert_eq!(prints(&made.await.unwrap().ok().unwrap()), [None, None]);
        // (As bob, who has no Role here: the stamp is the point, not the rights.)
        let state = shared.store.lock().unwrap();
        let print = Some(bobs_key(0).1);
        for resource in stamped(&state.store, &bob, sent) {
            assert_eq!(
                resource.metadata.annotations.get(KEY),
                print.as_ref(),
                "{}",
                resource.key()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A watch ends (401) once its Identity is deleted or given another key while it waits,
    /// and what it ended for is written down.
    #[tokio::test]
    async fn a_watch_ends_when_its_identity_no_longer_stands() {
        let dir = std::env::temp_dir().join(format!("kithd-watch-identity-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
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
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
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

    /// A drain is an apply of the Node: who may not apply Nodes drains none, who may only
    /// read sees the plan and changes nothing, both are in the audit log; a node that does
    /// not exist is not an empty node, and a worker's view is not asked for a plan.
    #[tokio::test]
    async fn drain_is_an_apply_of_the_node_by_who_may_and_is_audited() {
        let dir = std::env::temp_dir().join(format!("kithd-drain-may-{}", std::process::id()));
        let shared = crate::replica(None, &dir, std::time::Duration::from_secs(300))
            .await
            .unwrap();
        let source = "
apiVersion: kith.dev/v1
kind: Node
metadata: {name: n1}
spec: {}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: looker}
spec:
  rules:
    - {kinds: [Node], verbs: [get]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: bob-looker}
spec: {role: looker, subjects: [bob]}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: bob}
spec: {}
---
apiVersion: kith.dev/v1
kind: Identity
metadata: {name: eve}
spec: {}
";
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(source).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        let who = |name: &str| Extension(Caller::Identity(name.into()));
        let plan =
            |caller: Extension<Caller>, node: &str| drain_plan(State(shared.clone()), caller, Path(node.to_string()));
        let set = |caller: Extension<Caller>, step: &str| {
            let options = Query(DrainOptions { step: step.into() });
            drain_set(State(shared.clone()), caller, Path("n1".to_string()), options)
        };
        let status = |e: ApiError| e.into_response().status().as_u16();
        let spec = || shared.store.lock().unwrap().store.get("Node/n1").unwrap().spec.clone();

        // Who has no right on Nodes: neither the plan nor the drain.
        assert_eq!(plan(who("eve"), "n1").await.map(drop).map_err(status), Err(403));
        assert_eq!(set(who("eve"), "drain").await.map(drop).map_err(status), Err(403));
        // Who may read Nodes: the plan, not the drain.
        assert!(plan(who("bob"), "n1").await.is_ok());
        assert_eq!(set(who("bob"), "drain").await.map(drop).map_err(status), Err(403));
        assert!(
            spec()["taints"].is_null() && spec()["unschedulable"].is_null(),
            "{}",
            spec()
        );
        // A node that is not there is not a node with nothing on it.
        assert_eq!(
            plan(Extension(Caller::Admin), "n2").await.map(drop).map_err(status),
            Err(404)
        );
        // Who may apply Nodes: drained, then undrained, each written down.
        assert!(set(Extension(Caller::Admin), "drain").await.is_ok());
        assert_eq!(spec()["unschedulable"], true);
        assert!(spec()["taints"].to_string().contains("kith.dev/drain"), "{}", spec());
        assert!(set(Extension(Caller::Admin), "undrain").await.is_ok());
        assert!(!spec().to_string().contains("kith.dev/drain"), "{}", spec());
        let entries = shared.audit.tail(20).unwrap();
        let about = |ok: bool, who: &str| {
            let is = |e: &&serde_json::Value| e["ok"] == ok && e["who"] == who && e.to_string().contains("Node");
            entries.iter().filter(is).count()
        };
        assert!(about(false, "eve") >= 2 && about(false, "bob") >= 1, "{entries:?}");
        assert!(
            entries
                .iter()
                .filter(|e| e["ok"] == true && e.to_string().contains("Node/n1"))
                .count()
                >= 2,
            "{entries:?}"
        );
        // A worker runs from a view: what it has of the store is short, so it plans nothing.
        shared.view.send_replace(Some(1));
        assert_eq!(
            plan(Extension(Caller::Admin), "n1").await.map(drop).map_err(status),
            Err(403)
        );
        assert_eq!(
            set(Extension(Caller::Admin), "drain").await.map(drop).map_err(status),
            Err(403)
        );
        let _ = std::fs::remove_dir_all(&dir);
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
    // (As a pull: an Identity names only registries outside this node and its networks.)
    let outward = !matches!(caller, Caller::Admin);
    let pushed = crate::registry::push(&asked.to, &name, &version, blob, asked.signature, outward).await;
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
    let outward = !matches!(caller, Caller::Admin);
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
