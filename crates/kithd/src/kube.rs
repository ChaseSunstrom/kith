//! The Kubernetes API's paths, answered from kith's own store, so that `kubectl` and
//! `helm` work as they are. Nothing of Kubernetes runs here: what a client sends is read
//! as the kith resources it means (kith-kube), applied as the caller by the rules `/v1`
//! has, and given back as it was sent with what kith knows of it (its revision, its status).

use crate::Shared;
use crate::access::Caller;
use crate::api::{self, ApiError};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use kith_api::Resource;
use kith_api::kinds::Verb;
use kith_api::store::{Error, Store, rfc3339};
use serde_json::{Value, json};
use std::sync::Arc;

/// The annotation a resource made here carries: the object as the client sent it. What
/// `kubectl apply` works its next change out from is in it, so it is given back whole.
const SENT: &str = "kube.kith.dev/sent";

pub fn router() -> Router<Arc<Shared>> {
    let deployments = "/apis/apps/v1/namespaces/{namespace}/deployments";
    Router::new()
        .route(
            "/version",
            get(|| async { Json(json!({ "major": "1", "minor": "34", "gitVersion": "v1.34.0" })) }),
        )
        .route(
            "/api",
            get(|| async { Json(json!({ "kind": "APIVersions", "versions": ["v1"] })) }),
        )
        .route("/apis", get(groups))
        .route("/api/v1", get(|| async { resources("v1", &[]) }))
        .route(
            "/apis/apps/v1",
            get(|| async { resources("apps/v1", &[("deployments", "Deployment", "deploy")]) }),
        )
        .route(
            "/openapi/v3",
            get(|| async {
                Json(json!({ "paths": { "apis/apps/v1": { "serverRelativeURL": "/openapi/v3/apis/apps/v1" } } }))
            }),
        )
        .route(
            "/openapi/v3/apis/apps/v1",
            get(|| async { checked("apps", "v1", &[("deployments", "Deployment")]) }),
        )
        .route(deployments, get(list).post(create))
        .route(&format!("{deployments}/{{name}}"), get(one))
}

async fn groups() -> Json<Value> {
    let apps = json!({ "groupVersion": "apps/v1", "version": "v1" });
    Json(json!({
        "kind": "APIGroupList", "apiVersion": "v1",
        "groups": [{ "name": "apps", "versions": [apps], "preferredVersion": apps }],
    }))
}

/// What a group has: each resource's plural, its kind and its short name.
fn resources(group: &str, has: &[(&str, &str, &str)]) -> Json<Value> {
    let resource = |(name, kind, short): &(&str, &str, &str)| {
        json!({
            "name": name, "singularName": kind.to_lowercase(), "kind": kind, "namespaced": true,
            "verbs": ["create", "get", "list"], "shortNames": [short],
        })
    };
    let has: Vec<Value> = has.iter().map(resource).collect();
    Json(json!({ "kind": "APIResourceList", "apiVersion": "v1", "groupVersion": group, "resources": has }))
}

/// What kubectl asks before it sends an object: whether the server checks the fields
/// itself (`fieldValidation`). It does (what is not carried over is said, or refused), so
/// kubectl needs no schema of every kind to check them against: none is served.
fn checked(group: &str, version: &str, has: &[(&str, &str)]) -> Json<Value> {
    let path = |(plural, kind): &(&str, &str)| {
        let at = format!("/apis/{group}/{version}/namespaces/{{namespace}}/{plural}/{{name}}");
        let patch = json!({
            "x-kubernetes-group-version-kind": { "group": group, "version": version, "kind": kind },
            "parameters": [{ "name": "fieldValidation", "in": "query" }],
        });
        (at, json!({ "patch": patch }))
    };
    let paths: serde_json::Map<String, Value> = has.iter().map(path).collect();
    Json(json!({ "openapi": "3.0.0", "paths": paths }))
}

/// An error as Kubernetes says one: kubectl prints `message`, and reads `reason`.
fn status(code: StatusCode, reason: &str, message: String) -> Response {
    let said = json!({
        "kind": "Status", "apiVersion": "v1", "status": "Failure",
        "message": message, "reason": reason, "code": code.as_u16(),
    });
    (code, Json(said)).into_response()
}

fn refusal(e: ApiError) -> Response {
    match e {
        ApiError::Refused(why) => status(StatusCode::FORBIDDEN, "Forbidden", why),
        ApiError::Unauthorized(why) => status(StatusCode::UNAUTHORIZED, "Unauthorized", why),
        ApiError::Store(e) => {
            let (code, reason) = match e {
                Error::Invalid(_) => (StatusCode::UNPROCESSABLE_ENTITY, "Invalid"),
                Error::NotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
                Error::Conflict(_) => (StatusCode::CONFLICT, "Conflict"),
                Error::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
            };
            status(code, reason, e.to_string())
        }
    }
}

/// The object a client sent, as it is now: with the revision kith keeps (Kubernetes'
/// `resourceVersion` and `generation` both) and the status kith's controllers wrote, said
/// in a Deployment's words. None for a resource that was not made here.
fn object(store: &Store, resource: &Resource) -> Option<Value> {
    let mut sent: Value = serde_json::from_str(resource.metadata.annotations.get(SENT)?).ok()?;
    let revision = resource.metadata.revision.unwrap_or(1);
    let made = store
        .history(&resource.key())
        .ok()
        .and_then(|all| all.first())
        .map(|first| first.at);
    let metadata = sent.get_mut("metadata")?.as_object_mut()?;
    metadata.insert("resourceVersion".into(), revision.to_string().into());
    metadata.insert("generation".into(), revision.into());
    metadata.insert("creationTimestamp".into(), rfc3339(made.unwrap_or_default()).into());
    let (replicas, ready) = match &resource.status {
        Some(status) => (status["replicas"].as_u64(), status["ready"].as_u64()),
        None => (None, None),
    };
    let (replicas, ready) = (replicas.unwrap_or(0), ready.unwrap_or(0));
    sent["status"] = json!({
        "observedGeneration": revision, "replicas": replicas, "updatedReplicas": replicas,
        "readyReplicas": ready, "availableReplicas": ready,
    });
    Some(sent)
}

async fn create(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(namespace): Path<String>,
    Json(mut sent): Json<Value>,
) -> Response {
    let invalid = |why: String| status(StatusCode::UNPROCESSABLE_ENTITY, "Invalid", why);
    let Some(metadata) = sent.get_mut("metadata").and_then(Value::as_object_mut) else {
        return invalid("the object has no metadata".into());
    };
    // The path says where; an object that says elsewhere is not put there.
    let said = metadata.entry("namespace").or_insert_with(|| namespace.clone().into());
    if said.as_str() != Some(&namespace) {
        return invalid(format!("the object's namespace is not the request's ({namespace})"));
    }
    let (mut resources, left) = kith_kube::translate(vec![sent.clone()]);
    let Some(first) = resources.first_mut() else {
        return invalid(left.join("; "));
    };
    let key = first.key();
    if shared
        .store
        .lock()
        .expect("a handler panicked holding the store")
        .store
        .get(&key)
        .is_some()
    {
        return status(StatusCode::CONFLICT, "AlreadyExists", format!("{key} already exists"));
    }
    first.metadata.annotations.insert(SENT.into(), sent.to_string());
    if let Err(e) = api::applied(&shared, &caller, resources).await {
        return refusal(e);
    }
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let made = state
        .store
        .get(&key)
        .and_then(|resource| object(&state.store, resource));
    // What was not carried over is said, as Kubernetes says what it took and will not use:
    // kubectl prints each as a warning.
    let warnings = left
        .iter()
        .map(|left| format!("299 - \"{}\"", left.replace(['"', '\\'], "'")));
    let mut reply = (StatusCode::CREATED, Json(made.unwrap_or(sent))).into_response();
    for warning in warnings.filter_map(|warning| warning.parse().ok()) {
        reply.headers_mut().append("warning", warning);
    }
    reply
}

async fn one(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path((namespace, name)): Path<(String, String)>,
) -> Response {
    let place = ("Workload".to_string(), Some(namespace.clone()));
    if let Err(e) = api::permit(&shared, &caller, Verb::Get, |_| vec![place]) {
        return refusal(e);
    }
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let found = state.store.get(&format!("Workload/{namespace}/{name}"));
    match found.and_then(|resource| object(&state.store, resource)) {
        Some(object) => Json(object).into_response(),
        None => {
            let why = format!("deployments.apps \"{name}\" not found");
            status(StatusCode::NOT_FOUND, "NotFound", why)
        }
    }
}

async fn list(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Path(namespace): Path<String>,
) -> Response {
    let place = ("Workload".to_string(), Some(namespace.clone()));
    if let Err(e) = api::permit(&shared, &caller, Verb::List, |_| vec![place]) {
        return refusal(e);
    }
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let here = |resource: &&Resource| resource.metadata.namespace.as_deref() == Some(&namespace);
    let all = state.store.list(Some("Workload")).filter(here);
    let items: Vec<Value> = all.filter_map(|resource| object(&state.store, resource)).collect();
    Json(json!({ "kind": "DeploymentList", "apiVersion": "apps/v1", "metadata": {}, "items": items })).into_response()
}
