//! A leader that writes what it was not asked to: only in a kithd built with the cargo
//! feature `forge` (the access VM test's, `ci/musl.sh` with `KITHD_FEATURES=forge`; a release
//! has no such route, `cluster::tests::forge_is_in_no_release_build` keeps it so).
//! `POST /v1/forge` takes one [`Command`] as JSON and proposes it to the log as it is, the way
//! a leader's own writes are (`Raft::client_write`), with none of the checks a request gets
//! before it is written: what a taken leader could do. Every node applies it after, and
//! `access_sign::hook` is the only thing between it and the stores.

use crate::Shared;
use crate::access::Caller;
use crate::api::ApiError;
use axum::extract::State;
use axum::{Extension, Json};
use kith_api::kinds::Verb;
use kith_api::store::Error;
use kith_store::Command;
use std::sync::Arc;

/// Appends `entry` to the log if this node leads, and says what applying it here came to.
/// Only a caller that may apply a RoleBinding is let ask (the route is the cluster admin's).
pub async fn append(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Json(entry): Json<Command>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::api::permit(&shared, &caller, Verb::Apply, |_| vec![("RoleBinding".into(), None)])?;
    // (A follower does not forward it: the entry is the leader's own, so the test asks the leader.)
    let written = shared.raft.client_write(entry).await;
    let written = written.map_err(|e| ApiError::Store(Error::Invalid(format!("not appended: {e}"))))?;
    Ok(Json(match written.data {
        Ok(_) => serde_json::json!({ "index": written.log_id.index, "applied": true }),
        Err(e) => serde_json::json!({ "index": written.log_id.index, "applied": false, "error": e.to_string() }),
    }))
}
