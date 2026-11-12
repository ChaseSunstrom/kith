//! The resource API, v1.
//!
//! ```text
//! POST   /v1/apply[?dryRun=true]     [Resource]  -> [Change]   all or nothing
//! GET    /v1/resources[?kind=Kind]               -> [Resource]
//! GET    /v1/resources/<key>                     -> Resource
//! DELETE /v1/resources/<key>                     -> Resource
//! GET    /v1/history/<key>                       -> [Revision]
//! POST   /v1/rollback/<key>?to=N                 -> Change
//! ```
//! `<key>` is `Kind/namespace/name` or `Kind/name`. Errors are `{"error": "..."}`.

use crate::Shared;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use kith_api::Resource;
use kith_api::store::{Change, Error, Revision, Store};
use serde::Deserialize;
use std::sync::Arc;

pub fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/v1/apply", post(apply))
        .route("/v1/resources", get(list))
        .route("/v1/resources/{*key}", get(get_one).delete(delete))
        .route("/v1/history/{*key}", get(history))
        .route("/v1/rollback/{*key}", post(rollback))
        .with_state(shared)
}

struct ApiError(Error);

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

/// Change the store and persist it; if it cannot be saved, nothing changed.
fn write<T>(shared: &Shared, change: impl FnOnce(&mut Store) -> Result<T, Error>) -> Result<T, ApiError> {
    let mut file_store = shared.store.lock().expect("a handler panicked holding the store");
    let before = file_store.store.clone();
    let result = change(&mut file_store.store).and_then(|value| file_store.save().map(|()| value));
    if result.is_err() {
        file_store.store = before;
    }
    drop(file_store);
    shared.changed.notify_one();
    result.map_err(ApiError)
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
    write(&shared, |store| store.apply_all(resources)).map(Json)
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

async fn get_one(State(shared): State<Arc<Shared>>, Path(key): Path<String>) -> Reply<Resource> {
    read(&shared, |store| store.get(&key).cloned().ok_or(Error::NotFound(key)))
}

async fn delete(State(shared): State<Arc<Shared>>, Path(key): Path<String>) -> Reply<Resource> {
    write(&shared, |store| store.delete(&key)).map(Json)
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
    write(&shared, |store| store.rollback(&key, options.to)).map(Json)
}
