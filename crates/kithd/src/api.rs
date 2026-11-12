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
//! ```
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

use crate::Shared;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use kith_api::Resource;
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
        .with_state(shared)
}

pub struct ApiError(pub Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            Error::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::Conflict(_) => StatusCode::CONFLICT,
            Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(serde_json::json!({ "error": self.0.to_string() }))).into_response()
    }
}

type Reply<T> = Result<Json<T>, ApiError>;

/// A command answered with another command's kind of reply: a bug, said as an error.
fn odd() -> ApiError {
    ApiError(Error::Io(
        "the store gave an answer that does not fit the request".into(),
    ))
}

fn read<T>(shared: &Shared, look: impl FnOnce(&Store) -> Result<T, Error>) -> Reply<T> {
    look(&shared.store.lock().expect("a handler panicked holding the store").store)
        .map(Json)
        .map_err(ApiError)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyOptions {
    #[serde(default)]
    dry_run: bool,
}

async fn apply(
    State(shared): State<Arc<Shared>>,
    Query(options): Query<ApplyOptions>,
    Json(resources): Json<Vec<Resource>>,
) -> Reply<Vec<Change>> {
    if options.dry_run {
        return read(&shared, |store| store.clone().apply_all(resources));
    }
    let at = kith_api::store::now();
    match shared.submit(Command::Apply { resources, at }).await {
        Ok(Done::Changes(changes)) => Ok(Json(changes)),
        Ok(_) => Err(odd()),
        Err(e) => Err(ApiError(e)),
    }
}

#[derive(Deserialize)]
struct ListOptions {
    kind: Option<String>,
}

async fn list(State(shared): State<Arc<Shared>>, Query(options): Query<ListOptions>) -> Reply<Vec<Resource>> {
    read(&shared, |store| {
        Ok(store.list(options.kind.as_deref()).cloned().collect())
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

async fn watch(State(shared): State<Arc<Shared>>, Query(options): Query<WatchOptions>) -> Reply<serde_json::Value> {
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
    read(&shared, |store| {
        Ok(serde_json::json!({
            "generation": *shared.generation.borrow(),
            "resources": store.list(options.kind.as_deref()).collect::<Vec<_>>(),
        }))
    })
}

async fn get_one(State(shared): State<Arc<Shared>>, Path(key): Path<String>) -> Reply<Resource> {
    read(&shared, |store| store.get(&key).cloned().ok_or(Error::NotFound(key)))
}

async fn delete(State(shared): State<Arc<Shared>>, Path(key): Path<String>) -> Reply<Resource> {
    match shared.submit(Command::Delete { key }).await {
        Ok(Done::Deleted(resource)) => Ok(Json(*resource)),
        Ok(_) => Err(odd()),
        Err(e) => Err(ApiError(e)),
    }
}

async fn history(State(shared): State<Arc<Shared>>, Path(key): Path<String>) -> Reply<Vec<Revision>> {
    read(&shared, |store| store.history(&key).map(<[Revision]>::to_vec))
}

#[derive(Deserialize)]
struct RollbackOptions {
    to: u64,
}

async fn rollback(
    State(shared): State<Arc<Shared>>,
    Path(key): Path<String>,
    Query(options): Query<RollbackOptions>,
) -> Reply<Change> {
    let (to, at) = (options.to, kith_api::store::now());
    match shared.submit(Command::Rollback { key, to, at }).await {
        Ok(Done::Changes(mut changes)) if changes.len() == 1 => Ok(Json(changes.remove(0))),
        Ok(_) => Err(odd()),
        Err(e) => Err(ApiError(e)),
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
    Path(key): Path<String>,
    Query(options): Query<LogOptions>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Reply<serde_json::Value> {
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
        let failed = |e: reqwest::Error| ApiError(Error::Io(format!("asking node {node} for the output: {e}")));
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
        .map_err(|e| ApiError(Error::Io(format!("reading {}: {e}", path.display()))))?;
    Ok(Json(
        serde_json::json!({ "data": data, "next": next, "more": more && !options.previous }),
    ))
}

/// Up to [`LOG_CHUNK`] bytes of a log file as text, and the offset just after them.
fn log_chunk(path: &std::path::Path, offset: Option<u64>, tail: Option<u64>) -> std::io::Result<(String, u64)> {
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
    use super::log_chunk;

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
