//! The Kubernetes API's paths, answered from kith's own store, so that `kubectl` and
//! `helm` work as they are. Nothing of Kubernetes runs here: what a client sends is read
//! as the kith resources it means (kith-kube), applied as the caller by the rules `/v1`
//! has, and given back as it was sent with what kith knows of it (its revision, its status).
//!
//! Every kind is a row of [`KINDS`], held one of three ways ([`Held`]): as the kith
//! resource it means, with the object as it was sent beside it in an annotation; as a
//! `KubeObject`, kept and given back, for what nothing in kith reads; or not at all, made
//! up from its owner's status when asked for (a pod, a ReplicaSet). A kith resource that
//! was not made through these paths is not shown on them.
//!
//! `resourceVersion`: of a list, the store's generation; of an object, its kith revision
//! and what its status hashes to. A watch starts from a list's version or is told `410`
//! (the client lists again): the store keeps no log of what changed between two generations.
//
// ponytail: one field manager. A server-side apply replaces what was sent before, whoever
// sent it; managedFields, and a conflict between two managers, would be a table of who
// set which field.
// ponytail: a watch keeps the name and version of every object it has told of, and looks
// at them all on each change of the store. A log of changes per kind would make that one read.

use crate::Shared;
use crate::access::{self, Caller, Certificate, Grants};
use crate::api::{self, ApiError, LogOptions};
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use kith_api::kinds::Verb;
use kith_api::store::{Action, Error, Store, now, rfc3339};
use kith_api::{Metadata, Resource};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

/// The annotation a resource made here carries: the object as the client sent it. What
/// `kubectl apply` works its next change out from is in it, so it is given back whole.
pub const SENT: &str = "kube.kith.dev/sent";
/// And when it was made (seconds): Kubernetes's `creationTimestamp`, and part of its `uid`.
const MADE: &str = "kube.kith.dev/made";

/// The longest a watch is kept open: the client asks again from where it was.
const WATCH_SECS: u64 = 300;

/// How kith holds a kind of Kubernetes object.
#[derive(Clone, Copy, PartialEq)]
enum Held {
    /// As the kith resource of this kind that it means, the object as sent beside it.
    As(&'static str),
    /// As a `KubeObject`: kept and given back, read by nothing in kith. What is said of that.
    Kept(&'static str),
    /// Not held: made up from what the store says of its owner. Read only.
    Made,
}

struct Kind {
    /// Empty for the core group. Every group is at `v1`.
    group: &'static str,
    plural: &'static str,
    kind: &'static str,
    short: &'static str,
    namespaced: bool,
    held: Held,
}

const fn kind(
    group: &'static str,
    plural: &'static str,
    kind: &'static str,
    short: &'static str,
    namespaced: bool,
    held: Held,
) -> Kind {
    Kind {
        group,
        plural,
        kind,
        short,
        namespaced,
        held,
    }
}

const ACCESS: &str =
    "is kept and gives nothing: who may do what in kith is its own Roles', and a pod has no Kubernetes API to ask";
const BUDGET: &str = "is kept and not read yet: kith drains a node without asking it";
const CLASS: &str = "is kept and not read: kith's edge is the one way in";

/// Every kind these paths know, group by group. One that is not here is not found, as
/// Kubernetes says of a kind it does not have.
/// (A `static`: a kind is known by where its row is.)
static KINDS: &[Kind] = &[
    kind("", "pods", "Pod", "po", true, Held::Made),
    kind("", "services", "Service", "svc", true, Held::As("Service")),
    kind("", "configmaps", "ConfigMap", "cm", true, Held::As("ConfigMap")),
    kind("", "secrets", "Secret", "", true, Held::As("Secret")),
    kind(
        "",
        "persistentvolumeclaims",
        "PersistentVolumeClaim",
        "pvc",
        true,
        Held::As("VolumeClaim"),
    ),
    kind("", "namespaces", "Namespace", "ns", false, Held::As("Namespace")),
    kind("", "nodes", "Node", "no", false, Held::Made),
    kind("", "events", "Event", "ev", true, Held::Made),
    kind("", "serviceaccounts", "ServiceAccount", "sa", true, Held::Kept(ACCESS)),
    kind(
        "apps",
        "deployments",
        "Deployment",
        "deploy",
        true,
        Held::As("Workload"),
    ),
    kind("apps", "statefulsets", "StatefulSet", "sts", true, Held::As("Workload")),
    kind("apps", "daemonsets", "DaemonSet", "ds", true, Held::As("NodeWorkload")),
    kind("apps", "replicasets", "ReplicaSet", "rs", true, Held::Made),
    kind("batch", "jobs", "Job", "", true, Held::As("Job")),
    kind("batch", "cronjobs", "CronJob", "cj", true, Held::As("CronJob")),
    kind("networking.k8s.io", "ingresses", "Ingress", "ing", true, Held::Kept("")),
    kind(
        "networking.k8s.io",
        "ingressclasses",
        "IngressClass",
        "",
        false,
        Held::Kept(CLASS),
    ),
    kind(
        "policy",
        "poddisruptionbudgets",
        "PodDisruptionBudget",
        "pdb",
        true,
        Held::Kept(BUDGET),
    ),
    kind(
        "rbac.authorization.k8s.io",
        "roles",
        "Role",
        "",
        true,
        Held::Kept(ACCESS),
    ),
    kind(
        "rbac.authorization.k8s.io",
        "rolebindings",
        "RoleBinding",
        "",
        true,
        Held::Kept(ACCESS),
    ),
    kind(
        "rbac.authorization.k8s.io",
        "clusterroles",
        "ClusterRole",
        "",
        false,
        Held::Kept(ACCESS),
    ),
    kind(
        "rbac.authorization.k8s.io",
        "clusterrolebindings",
        "ClusterRoleBinding",
        "",
        false,
        Held::Kept(ACCESS),
    ),
];

/// What Kubernetes fills in where an object does not say, for the fields its clients read
/// without asking whether they are there (Helm waits by them).
const DEFAULTS: &[(&str, &str, &str)] = &[
    ("Deployment", "/spec/replicas", "1"),
    ("StatefulSet", "/spec/replicas", "1"),
    ("StatefulSet", "/spec/updateStrategy/type", "\"RollingUpdate\""),
    ("DaemonSet", "/spec/updateStrategy/type", "\"RollingUpdate\""),
    (
        "DaemonSet",
        "/spec/updateStrategy/rollingUpdate",
        r#"{"maxUnavailable":1,"maxSurge":0}"#,
    ),
    ("Job", "/spec/completions", "1"),
    ("Job", "/spec/parallelism", "1"),
    ("Job", "/spec/backoffLimit", "6"),
    ("Service", "/spec/type", "\"ClusterIP\""),
];

/// The lists a strategic merge patch merges item by item, and the field that names an
/// item (Kubernetes's types say which; `ports` is by `containerPort` in a container and by
/// `port` in a Service). Any other list is replaced whole.
const MERGED: &[(&str, &str)] = &[
    ("containers", "name"),
    ("initContainers", "name"),
    ("env", "name"),
    ("volumes", "name"),
    ("volumeMounts", "mountPath"),
    ("imagePullSecrets", "name"),
    ("hostAliases", "ip"),
];

pub fn router() -> Router<Arc<Shared>> {
    let version =
        || async { Json(json!({ "major": "1", "minor": "37", "gitVersion": "v1.37.0", "platform": "linux/amd64" })) };
    Router::new()
        .route("/version", get(version))
        .route(
            "/api",
            get(|| async { Json(json!({ "kind": "APIVersions", "versions": ["v1"] })) }),
        )
        .route("/apis", get(groups))
        .route("/api/v1", get(|| async { resources("") }))
        .route(
            "/apis/{group}/v1",
            get(|Path(group): Path<String>| async move { resources(&group) }),
        )
        .route("/openapi/v3", get(openapi))
        // (What kubectl checks a kind against that the server does not check for it: of a
        // kind that is not here nothing is known, so nothing: an empty document, as protobuf
        // has one. kubectl then says the kind has no match, not that it could not ask.)
        .route(
            "/openapi/v2",
            get(|| async {
                [(
                    header::CONTENT_TYPE,
                    "application/com.github.proto-openapi.spec.v2.v1.0+protobuf",
                )]
            }),
        )
        .route("/openapi/v3/{*of}", get(checked))
        .route("/api/v1/{*rest}", any(core))
        .route("/apis/{group}/v1/{*rest}", any(grouped))
}

/// `v1`, or `group/v1`.
fn version_of(group: &str) -> String {
    match group {
        "" => "v1".into(),
        group => format!("{group}/v1"),
    }
}

/// The groups there are, but for the core one.
fn named() -> Vec<&'static str> {
    let mut names: Vec<&str> = KINDS.iter().map(|kind| kind.group).filter(|g| !g.is_empty()).collect();
    names.dedup();
    names
}

async fn groups() -> Json<Value> {
    let group = |name: &&str| {
        let version = json!({ "groupVersion": version_of(name), "version": "v1" });
        json!({ "name": name, "versions": [version], "preferredVersion": version })
    };
    let groups: Vec<Value> = named().iter().map(group).collect();
    Json(json!({ "kind": "APIGroupList", "apiVersion": "v1", "groups": groups }))
}

fn scales(kind: &Kind) -> bool {
    matches!(kind.kind, "Deployment" | "StatefulSet")
}

/// What a group has: each kind's plural, its names and what can be done to it.
fn resources(group: &str) -> Response {
    let mut has = Vec::new();
    for kind in KINDS.iter().filter(|kind| kind.group == group) {
        let verbs: &[&str] = match kind.held {
            Held::Made => &["get", "list", "watch"],
            _ => &["create", "delete", "get", "list", "patch", "update", "watch"],
        };
        let mut one = json!({
            "name": kind.plural, "singularName": kind.kind.to_lowercase(), "kind": kind.kind,
            "namespaced": kind.namespaced, "verbs": verbs,
        });
        if !kind.short.is_empty() {
            one["shortNames"] = json!([kind.short]);
        }
        // (`kubectl get all`.)
        if matches!(kind.group, "apps" | "batch") || matches!(kind.kind, "Pod" | "Service") {
            one["categories"] = json!(["all"]);
        }
        has.push(one);
        let part = |part: &str, verbs: &[&str]| json!({ "name": format!("{}/{part}", kind.plural), "singularName": "", "namespaced": true, "kind": kind.kind, "verbs": verbs });
        // (`kubectl scale` looks for this to know what a scale of the kind is.)
        if scales(kind) {
            let mut scale = part("scale", &["get", "patch", "update"]);
            for (field, value) in [("group", "autoscaling"), ("version", "v1"), ("kind", "Scale")] {
                scale[field] = value.into();
            }
            has.push(scale);
        }
        if kind.kind == "Pod" {
            has.push(part("log", &["get"]));
        }
    }
    if has.is_empty() {
        return missing().into_response();
    }
    Json(json!({ "kind": "APIResourceList", "apiVersion": "v1", "groupVersion": version_of(group), "resources": has }))
        .into_response()
}

async fn openapi() -> Json<Value> {
    let path = |at: String| (at.clone(), json!({ "serverRelativeURL": format!("/openapi/v3/{at}") }));
    let groups = named().into_iter().map(|group| format!("apis/{group}/v1"));
    let paths: serde_json::Map<String, Value> = std::iter::once("api/v1".to_string()).chain(groups).map(path).collect();
    Json(json!({ "paths": paths }))
}

/// What kubectl and helm ask before they send an object: whether the server checks the
/// fields itself (`fieldValidation`). It does (what is not carried over is said, or refused),
/// so they need no schema of every kind to check them against: none is served.
async fn checked(Path(of): Path<String>) -> Response {
    let group = match of.split('/').collect::<Vec<_>>()[..] {
        ["api", "v1"] => "",
        ["apis", group, "v1"] => group,
        _ => return missing().into_response(),
    };
    let path = |kind: &Kind| {
        let patch = json!({
            "x-kubernetes-group-version-kind": { "group": kind.group, "version": "v1", "kind": kind.kind },
            "parameters": [{ "name": "fieldValidation", "in": "query" }],
        });
        (format!("/{of}/{}/{{name}}", kind.plural), json!({ "patch": patch }))
    };
    let written = KINDS
        .iter()
        .filter(|kind| kind.group == group && kind.held != Held::Made);
    let paths: serde_json::Map<String, Value> = written.map(path).collect();
    Json(json!({ "openapi": "3.0.0", "paths": paths })).into_response()
}

/// A refusal, as Kubernetes says one: kubectl prints `why`, and reads `reason`.
struct No {
    code: StatusCode,
    reason: &'static str,
    why: String,
}

impl IntoResponse for No {
    fn into_response(self) -> Response {
        let said = json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "message": self.why, "reason": self.reason, "code": self.code.as_u16(),
        });
        (self.code, Json(said)).into_response()
    }
}

fn status(code: StatusCode, reason: &'static str, why: String) -> No {
    No { code, reason, why }
}

fn missing() -> No {
    let why = "the server could not find the requested resource";
    status(StatusCode::NOT_FOUND, "NotFound", why.into())
}

fn not_found(kind: &Kind, name: &str) -> No {
    let of = match kind.group {
        "" => kind.plural.to_string(),
        group => format!("{}.{group}", kind.plural),
    };
    status(StatusCode::NOT_FOUND, "NotFound", format!("{of} \"{name}\" not found"))
}

fn invalid(why: String) -> No {
    status(StatusCode::UNPROCESSABLE_ENTITY, "Invalid", why)
}

fn refusal(e: ApiError) -> No {
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

/// A UUID's shape, from what names a thing: the same thing has the same one.
fn uid(of: &str) -> String {
    let hex = blake3::hash(of.as_bytes()).to_hex();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn short_hash(of: &str) -> String {
    blake3::hash(of.as_bytes()).to_hex()[..10].to_string()
}

/// An object's `resourceVersion`: its kith revision, and under it what its status hashes
/// to, so that it changes when either does and a writer is held to the revision alone.
fn version(resource: &Resource) -> u64 {
    let status = resource.status.as_ref().map(Value::to_string).unwrap_or_default();
    let hash = blake3::hash(status.as_bytes());
    let low = u32::from_le_bytes(hash.as_bytes()[..4].try_into().expect("four bytes"));
    resource.metadata.revision.unwrap_or(0) << 32 | u64::from(low)
}

fn made_at(resource: &Resource) -> u64 {
    let made = resource.metadata.annotations.get(MADE);
    made.and_then(|made| made.parse().ok()).unwrap_or(0)
}

/// Sets what is at `path` (`/a/b`) of `at`, making the mappings on the way; nothing where
/// something that is not a mapping is in the way.
fn set(mut at: &mut Value, path: &str, value: Value) {
    for part in path.split('/').skip(1) {
        if at.is_null() {
            *at = json!({});
        }
        let Some(map) = at.as_object_mut() else { return };
        at = map.entry(part).or_insert(Value::Null);
    }
    *at = value;
}

/// The kith kind that holds a kind (none for one that is made up).
fn holder(kind: &Kind) -> &'static str {
    match kind.held {
        Held::As(holder) => holder,
        Held::Kept(_) => "KubeObject",
        Held::Made => "",
    }
}

/// The name of the `KubeObject` that keeps an object: its kind's plural and its name, or
/// what the name hashes to where kith could not have it as a name (`system:reader`).
fn kept_name(kind: &Kind, name: &str) -> String {
    let plain = format!("{}.{name}", kind.plural);
    let letter = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let fits = plain.len() <= 63
        && name.bytes().all(|b| letter(b) || b == b'-' || b == b'.')
        && name.bytes().last().is_some_and(letter);
    match fits {
        true => plain,
        false => format!("{}.{}", kind.plural, &blake3::hash(name.as_bytes()).to_hex()[..32]),
    }
}

/// The store key of what holds the object of `kind` named `name`. (A kind that is in no
/// namespace and is kept is kept in `default`: a `KubeObject` is in one.)
fn key(kind: &Kind, namespace: Option<&str>, name: &str) -> String {
    let namespace = namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE);
    match kind.held {
        Held::As("Namespace") => format!("Namespace/{name}"),
        Held::As(holder) => format!("{holder}/{namespace}/{name}"),
        _ => format!("KubeObject/{namespace}/{}", kept_name(kind, name)),
    }
}

/// The object a resource holds as it was sent, and its kind; none for a resource that was
/// not made here. What kith holds elsewhere is put back: a Secret's and a ConfigMap's data
/// are the kith resource's, kept once.
fn raw(resource: &Resource) -> Option<(&'static Kind, Value)> {
    let mut object: Value = match (resource.kind.as_str(), resource.metadata.annotations.get(SENT)) {
        ("KubeObject", _) => resource.spec.get("object")?.clone(),
        (_, Some(sent)) => serde_json::from_str(sent).ok()?,
        // A namespace is there however it was made.
        ("Namespace", None) => json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": { "name": resource.metadata.name, "labels": resource.metadata.labels },
        }),
        _ => return None,
    };
    let kind = KINDS
        .iter()
        .find(|kind| object["kind"] == kind.kind && holder(kind) == resource.kind)?;
    let data = resource.spec.get("data").and_then(Value::as_object);
    if let (Some(data), Some(object)) = (data, object.as_object_mut()) {
        use base64::Engine;
        let coded =
            |value: &Value| base64::engine::general_purpose::STANDARD.encode(value.as_str().unwrap_or_default());
        let data: serde_json::Map<String, Value> = match kind.kind {
            "Secret" => data.iter().map(|(k, v)| (k.clone(), coded(v).into())).collect(),
            _ => data.clone(),
        };
        object.insert("data".into(), data.into());
    }
    Some((kind, object))
}

/// The object a resource holds as it is now: as it was sent, with what the server says of
/// an object (its `uid`, versions and age), what Kubernetes would have filled in, and the
/// status kith's controllers wrote, said in the kind's own words.
fn served(resource: &Resource) -> Option<(&'static Kind, Value)> {
    let (kind, mut object) = raw(resource)?;
    let (made, revision) = (made_at(resource), resource.metadata.revision.unwrap_or(1));
    let meta = object.get_mut("metadata")?.as_object_mut()?;
    meta.insert("uid".into(), uid(&format!("{} {made}", resource.key())).into());
    meta.insert("resourceVersion".into(), version(resource).to_string().into());
    meta.insert("generation".into(), revision.into());
    if made > 0 {
        meta.insert("creationTimestamp".into(), rfc3339(made).into());
    }
    for (_, at, value) in DEFAULTS.iter().filter(|(of, ..)| *of == kind.kind) {
        if object.pointer(at).is_none() {
            set(&mut object, at, serde_json::from_str(value).expect("a default is JSON"));
        }
    }
    let live = resource.status.as_ref();
    let said = |field: &str| live.and_then(|live| live[field].as_str());
    match kind.kind {
        // Its address on the mesh; with none it is found by its name alone, which is what
        // Kubernetes calls a Service with `None` here. (Helm waits for this field to say something.)
        "Service" if object.pointer("/spec/clusterIP").is_none() => {
            let address = said("address").unwrap_or("None");
            set(&mut object, "/spec/clusterIP", address.into());
            set(&mut object, "/spec/clusterIPs", json!([address]));
        }
        "PersistentVolumeClaim" => {
            if let Some(volume) = said("volume") {
                set(&mut object, "/spec/volumeName", volume.into());
            }
        }
        // (`kubectl logs job/NAME` finds the pods by this, as Kubernetes writes it.)
        "Job" if object.pointer("/spec/selector").is_none() => {
            let name = resource.metadata.name.as_str();
            set(
                &mut object,
                "/spec/selector",
                json!({ "matchLabels": { "job-name": name } }),
            );
        }
        _ => {}
    }
    if let Some(status) = status_of(kind.kind, &object, resource) {
        set(&mut object, "/status", status);
    }
    Some((kind, object))
}

/// Of the replicas a status tells of: how many there are, how many run what the resource
/// now says, how many are ready, and how many are both.
fn counts(resource: &Resource) -> [u64; 4] {
    let mut replicas: BTreeMap<u64, (bool, bool)> = BTreeMap::new();
    let units = resource
        .status
        .as_ref()
        .and_then(|status| status["containers"].as_array());
    for unit in units.into_iter().flatten() {
        let Some(replica) = unit["replica"].as_u64() else {
            continue;
        };
        let is = replicas.entry(replica).or_insert((true, true));
        is.0 &= unit["revision"].as_u64() == resource.metadata.revision;
        is.1 &= unit["ready"] == true;
    }
    let count = |of: fn(&(bool, bool)) -> bool| replicas.values().filter(|is| of(is)).count() as u64;
    [
        replicas.len() as u64,
        count(|is| is.0),
        count(|is| is.1),
        count(|is| is.0 && is.1),
    ]
}

fn condition(kind: &str, is: bool, reason: &str) -> Value {
    json!({ "type": kind, "status": if is { "True" } else { "False" }, "reason": reason })
}

/// kith's status of a resource, as the status of the Kubernetes object it holds.
fn status_of(kind: &str, object: &Value, resource: &Resource) -> Option<Value> {
    let live = resource.status.as_ref();
    let revision = resource.metadata.revision.unwrap_or(1);
    let [all, new, ready, both] = counts(resource);
    let wanted = object["spec"]["replicas"].as_u64().unwrap_or(1);
    let number = |field: &str| live.and_then(|live| live[field].as_u64()).unwrap_or(0);
    Some(match kind {
        "Deployment" => {
            let done = all == wanted && both == wanted;
            let moving = if done {
                "NewReplicaSetAvailable"
            } else {
                "ReplicaSetUpdated"
            };
            json!({
                "observedGeneration": revision, "replicas": all, "updatedReplicas": new,
                "readyReplicas": ready, "availableReplicas": ready,
                "conditions": [
                    condition("Available", ready >= wanted, "MinimumReplicasAvailable"),
                    condition("Progressing", true, moving),
                ],
            })
        }
        "StatefulSet" => {
            let name = &resource.metadata.name;
            let current = if new == all {
                revision
            } else {
                revision.saturating_sub(1)
            };
            json!({
                "observedGeneration": revision, "replicas": all, "readyReplicas": ready,
                "availableReplicas": ready, "currentReplicas": new, "updatedReplicas": new,
                "currentRevision": format!("{name}-{current}"), "updateRevision": format!("{name}-{revision}"),
            })
        }
        "DaemonSet" => json!({
            "observedGeneration": revision, "desiredNumberScheduled": number("replicas"),
            "currentNumberScheduled": all, "updatedNumberScheduled": new, "numberReady": ready,
            "numberAvailable": ready, "numberMisscheduled": 0,
        }),
        "Job" => {
            // (What an earlier revision's run came to is not this one's.)
            let live = live.filter(|live| live["observedRevision"].as_u64() == Some(revision));
            let state = live.and_then(|live| live["state"].as_str());
            let number = |field: &str| live.and_then(|live| live[field].as_u64()).unwrap_or(0);
            let mut status = json!({
                "succeeded": number("succeeded"), "failed": number("failed"),
                "active": if state == Some("running") { all } else { 0 }, "ready": ready,
            });
            if live.is_some() {
                status["startTime"] = object["metadata"]["creationTimestamp"].clone();
            }
            match state {
                Some("succeeded") => status["conditions"] = json!([condition("Complete", true, "Completed")]),
                Some("failed") => {
                    let mut failed = condition("Failed", true, "BackoffLimitExceeded");
                    failed["message"] = live.map(|live| live["message"].clone()).unwrap_or_default();
                    status["conditions"] = json!([failed]);
                }
                _ => {}
            }
            status
        }
        "CronJob" => match live.map(|live| &live["last"]) {
            Some(last) if last.is_string() => json!({ "lastScheduleTime": last }),
            _ => json!({}),
        },
        "PersistentVolumeClaim" => {
            let bound = live.is_some_and(|live| live["volume"].is_string());
            json!({ "phase": if bound { "Bound" } else { "Pending" } })
        }
        "Namespace" => json!({ "phase": "Active" }),
        "Service" => json!({ "loadBalancer": {} }),
        _ => return None,
    })
}

fn owner_of(owner: &Value) -> Value {
    json!([{
        "apiVersion": owner["apiVersion"], "kind": owner["kind"], "name": owner["metadata"]["name"],
        "uid": owner["metadata"]["uid"], "controller": true, "blockOwnerDeletion": true,
    }])
}

/// What a Job made for `cron` holds beside it, where the CronJob was sent here: the Job
/// its `jobTemplate` is, by which the Job is shown as one. (Nothing for kith's own.)
pub fn job_of(cron: &Resource, name: &str) -> BTreeMap<String, String> {
    let Some((_, owner)) = served(cron).filter(|(kind, _)| kind.kind == "CronJob") else {
        return BTreeMap::new();
    };
    let template = &owner["spec"]["jobTemplate"];
    let mut job = json!({ "apiVersion": "batch/v1", "kind": "Job", "spec": template["spec"] });
    set(&mut job, "/metadata/labels", template["metadata"]["labels"].clone());
    set(&mut job, "/metadata/name", name.into());
    set(&mut job, "/metadata/namespace", owner["metadata"]["namespace"].clone());
    set(&mut job, "/metadata/ownerReferences", owner_of(&owner));
    BTreeMap::from([(SENT.into(), job.to_string()), (MADE.into(), now().to_string())])
}

/// The one ReplicaSet of a Deployment made here: a Deployment's pods are a ReplicaSet's in
/// Kubernetes, and Helm waits for the one that has the Deployment's template. Made up.
fn replica_set(deployment: &Value, resource: &Resource) -> Value {
    let mut template = deployment["spec"]["template"].clone();
    let hash = short_hash(&template.to_string());
    set(
        &mut template,
        "/metadata/labels/pod-template-hash",
        hash.as_str().into(),
    );
    let [_, new, _, both] = counts(resource);
    let meta = &deployment["metadata"];
    json!({
        "apiVersion": "apps/v1", "kind": "ReplicaSet",
        "metadata": {
            "name": format!("{}-{hash}", resource.metadata.name), "namespace": meta["namespace"],
            "labels": template["metadata"]["labels"], "ownerReferences": owner_of(deployment),
            "uid": uid(&format!("{} {hash}", meta["uid"])), "resourceVersion": meta["resourceVersion"],
            "generation": 1, "creationTimestamp": meta["creationTimestamp"],
            "annotations": { "deployment.kubernetes.io/revision": meta["generation"].to_string() },
        },
        "spec": { "replicas": deployment["spec"]["replicas"], "selector": deployment["spec"]["selector"], "template": template },
        "status": {
            "observedGeneration": 1, "replicas": new, "fullyLabeledReplicas": new,
            "readyReplicas": both, "availableReplicas": both,
        },
    })
}

/// The pods of what `owner` runs: one for each replica its status tells of, named by the
/// owner and the replica's number. Made up: a pod is not a resource of kith's.
fn pods(owner: &Value, resource: &Resource) -> Vec<Value> {
    let (template, meta) = (&owner["spec"]["template"], &owner["metadata"]);
    let mut replicas: BTreeMap<u64, Vec<&Value>> = BTreeMap::new();
    let units = resource
        .status
        .as_ref()
        .and_then(|status| status["containers"].as_array());
    // A Job that is over runs nothing more, and what its runs wrote is still theirs to be
    // asked for (`kubectl logs job/NAME` asks the Job's pods): a pod for each run that ended.
    //
    // ponytail: the runs that succeeded are counted here, not named, so with `parallelism`
    // a failed Job's pods may be numbered otherwise than its runs were; and the code a
    // failed run exited with is not kept.
    let over = resource.status.as_ref().filter(|status| {
        let ended = matches!(status["state"].as_str(), Some("succeeded" | "failed"));
        owner["kind"] == "Job" && ended && units.is_none_or(|units| units.is_empty())
    });
    let mut ended = Vec::new();
    if let Some(status) = over {
        let succeeded = status["succeeded"].as_u64().unwrap_or(0);
        let runs = succeeded + u64::from(status["state"] == "failed");
        let names = template["spec"]["containers"].as_array();
        for run in 0..runs {
            let code = if run < succeeded { json!(0) } else { Value::Null };
            ended.extend(names.into_iter().flatten().map(|container| {
                json!({
                    "name": container["name"], "replica": run, "state": "exited", "exitCode": code,
                    "ready": false, "restarts": 0, "node": status["nodes"]["0"],
                })
            }));
        }
    }
    for unit in units.into_iter().flatten().chain(&ended) {
        if let Some(replica) = unit["replica"].as_u64() {
            replicas.entry(replica).or_default().push(unit);
        }
    }
    let mut labels = template["metadata"]["labels"].clone();
    let owned = match owner["kind"].as_str() {
        Some("Deployment") => {
            let set_of = replica_set(owner, resource);
            labels = set_of["metadata"]["labels"].clone();
            owner_of(&set_of)
        }
        kind => {
            if kind == Some("Job") {
                set(&mut labels, "/job-name", meta["name"].clone());
            }
            owner_of(owner)
        }
    };
    let state = |unit: &Value| unit["state"].as_str().unwrap_or("pending").to_string();
    let pod = |(replica, units): (u64, Vec<&Value>)| {
        let ready = units.iter().all(|unit| unit["ready"] == true);
        let phase = if units.iter().all(|unit| state(unit) == "exited") {
            match units.iter().all(|unit| unit["exitCode"] == 0) {
                true => "Succeeded",
                false => "Failed",
            }
        } else if units.iter().any(|unit| state(unit) == "running") {
            "Running"
        } else {
            "Pending"
        };
        let container = |unit: &&Value| {
            let containers = template["spec"]["containers"].as_array();
            let mut containers = containers.into_iter().flatten();
            let image = containers
                .find(|c| c["name"] == unit["name"])
                .map(|c| c["image"].clone());
            let is = match state(unit).as_str() {
                "running" => json!({ "running": {} }),
                "exited" => {
                    let reason = if unit["exitCode"] == 0 { "Completed" } else { "Error" };
                    json!({ "terminated": { "exitCode": unit["exitCode"], "reason": reason } })
                }
                _ => {
                    let again = unit["restarts"].as_u64().is_some_and(|restarts| restarts > 0);
                    let reason = if again { "CrashLoopBackOff" } else { "ContainerCreating" };
                    json!({ "waiting": { "reason": reason, "message": unit["message"] } })
                }
            };
            json!({
                "name": unit["name"], "image": image, "imageID": "", "ready": unit["ready"],
                "started": state(unit) == "running", "restartCount": unit["restarts"], "state": is,
            })
        };
        let mut spec = template["spec"].clone();
        let (node, address) = (&units[0]["node"], &units[0]["address"]);
        if !node.is_null() {
            set(&mut spec, "/nodeName", node.clone());
        }
        let mut status = json!({
            "phase": phase, "startTime": meta["creationTimestamp"],
            "conditions": [
                condition("Initialized", true, ""), condition("PodScheduled", true, ""),
                condition("ContainersReady", ready, ""), condition("Ready", ready, ""),
            ],
            "containerStatuses": units.iter().map(container).collect::<Vec<_>>(),
        });
        if !address.is_null() {
            status["podIP"] = address.clone();
            status["podIPs"] = json!([{ "ip": address }]);
        }
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {
                "name": format!("{}-{replica}", resource.metadata.name), "namespace": meta["namespace"],
                "labels": labels, "ownerReferences": owned, "uid": uid(&format!("{} {replica}", meta["uid"])),
                "resourceVersion": meta["resourceVersion"], "creationTimestamp": meta["creationTimestamp"],
            },
            "spec": spec, "status": status,
        })
    };
    replicas.into_iter().map(pod).collect()
}

/// The objects of a kind that is not held, made up from what the store says: `caller` sees
/// those of the resources it may see.
fn made(
    store: &Store,
    kind: &Kind,
    namespace: Option<&str>,
    name: Option<&str>,
    may: &dyn Fn(&&Resource) -> bool,
) -> Vec<Value> {
    let within = |resource: &&Resource| namespace.is_none_or(|ns| resource.metadata.namespace.as_deref() == Some(ns));
    let mut found = Vec::new();
    let owners: &[&str] = match kind.kind {
        "Pod" | "ReplicaSet" => &["Workload", "NodeWorkload", "Job"],
        "Node" => &["Node"],
        _ => &[],
    };
    for resource in owners
        .iter()
        .flat_map(|owner| store.list(Some(*owner)))
        .filter(within)
        .filter(may)
    {
        // (A pod's name, and a ReplicaSet's, begin with their owner's.)
        if name.is_some_and(|name| !name.starts_with(&resource.metadata.name)) {
            continue;
        }
        if kind.kind == "Node" {
            let said = |field: &str| resource.status.as_ref().and_then(|status| status[field].as_str());
            let address = said("address").and_then(|address| address.rsplit_once(':'));
            let address = address.map(|(host, _)| host.trim_matches(['[', ']']));
            found.push(json!({
                "apiVersion": "v1", "kind": "Node",
                "metadata": {
                    "name": resource.metadata.name, "labels": resource.metadata.labels,
                    "uid": uid(&resource.key()), "resourceVersion": version(resource).to_string(),
                },
                "spec": {},
                "status": {
                    "conditions": [condition("Ready", said("state") != Some("unreachable"), "KithdReady")],
                    "addresses": [{ "type": "InternalIP", "address": address }],
                    "nodeInfo": { "kubeletVersion": concat!("kith-", env!("CARGO_PKG_VERSION")) },
                },
            }));
            continue;
        }
        let Some((_, owner)) = served(resource) else { continue };
        match kind.kind {
            "Pod" => found.extend(pods(&owner, resource)),
            _ if owner["kind"] == "Deployment" => found.push(replica_set(&owner, resource)),
            _ => {}
        }
    }
    found.retain(|object| name.is_none_or(|name| object["metadata"]["name"] == name));
    found
}

/// Every object of `kind` there is (in `namespace`, named `name`) that `grants` let be seen.
fn objects(
    store: &Store,
    kind: &'static Kind,
    namespace: Option<&str>,
    name: Option<&str>,
    grants: &Grants,
    verb: &Verb,
) -> Vec<Value> {
    let may = |resource: &&Resource| grants.may(verb, &resource.kind, resource.metadata.namespace.as_deref());
    let of_kind = |(of, object): (&'static Kind, Value)| std::ptr::eq(of, kind).then_some(object);
    match (kind.held, name) {
        (Held::Made, _) => made(store, kind, namespace, name, &may),
        // A namespace is there when it is said to be, and when anything is in it.
        (Held::As("Namespace"), _) => {
            if !grants.may(verb, "Namespace", None) {
                return Vec::new();
            }
            let mut names: BTreeSet<&str> = store
                .list(None)
                .filter_map(|r| r.metadata.namespace.as_deref())
                .collect();
            names.insert(kith_api::DEFAULT_NAMESPACE);
            names.extend(store.list(Some("Namespace")).map(|r| r.metadata.name.as_str()));
            let object = |name: &str| {
                let said = store.get(&format!("Namespace/{name}")).and_then(served);
                said.map(|(_, object)| object).unwrap_or_else(|| {
                    json!({
                        "apiVersion": "v1", "kind": "Namespace",
                        "metadata": { "name": name, "uid": uid(name), "resourceVersion": "1" },
                        "status": { "phase": "Active" },
                    })
                })
            };
            let asked = names.into_iter().filter(|found| name.is_none_or(|name| name == *found));
            asked.map(object).collect()
        }
        (_, Some(name)) => {
            let found = store.get(&key(kind, namespace, name)).filter(may);
            found.and_then(served).and_then(of_kind).into_iter().collect()
        }
        (_, None) => {
            let within = |r: &&Resource| namespace.is_none_or(|ns| r.metadata.namespace.as_deref() == Some(ns));
            // (Of what is kept, only this kind's are read.)
            let this = |r: &&Resource| r.kind != "KubeObject" || r.spec["object"]["kind"] == kind.kind;
            let held = store.list(Some(holder(kind))).filter(within).filter(may).filter(this);
            held.filter_map(served).filter_map(of_kind).collect()
        }
    }
}

/// Does `object` fit what a request selects: its `labelSelector` (`a=b,c!=d,e,!f,g in
/// (h,i),j notin (k)`) and its `fieldSelector` (`metadata.name=x,status.phase!=Running`)?
fn selected(object: &Value, asked: &Asked) -> bool {
    let labels = &object["metadata"]["labels"];
    let label = |term: &str| {
        let has = |key: &str| labels.get(key.trim()).and_then(Value::as_str);
        let among = |key: &str, set: &str| {
            let set = set.trim().trim_start_matches('(').trim_end_matches(')');
            has(key).is_some_and(|value| set.split(',').any(|one| one.trim() == value))
        };
        if let Some((key, set)) = term.split_once(" notin ") {
            !among(key, set)
        } else if let Some((key, set)) = term.split_once(" in ") {
            among(key, set)
        } else if let Some((key, value)) = term.split_once("!=") {
            has(key) != Some(value.trim())
        } else if let Some((key, value)) = term.split_once("==").or(term.split_once('=')) {
            has(key) == Some(value.trim())
        } else {
            match term.strip_prefix('!') {
                Some(key) => has(key).is_none(),
                None => has(term).is_some(),
            }
        }
    };
    let field = |term: &str| {
        let (path, value, same) = match term.split_once("!=") {
            Some((path, value)) => (path, value, false),
            None => {
                let (path, value) = term.split_once("==").or(term.split_once('=')).unwrap_or((term, ""));
                (path, value, true)
            }
        };
        let found = path.trim().split('.').fold(object, |at, part| &at[part]);
        let found = match found {
            Value::String(text) => text.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        (found == value.trim()) == same
    };
    // (A comma inside `in (a,b)` is not between two terms.)
    let terms = |selector: Option<&String>| {
        let mut depth = 0;
        let between = |c: char| {
            depth += i32::from(c == '(') - i32::from(c == ')');
            c == ',' && depth == 0
        };
        let all = selector.map(String::as_str).unwrap_or_default().split(between);
        all.map(str::trim)
            .filter(|term| !term.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    terms(asked.get("labelSelector")).iter().all(|term| label(term))
        && terms(asked.get("fieldSelector")).iter().all(|term| field(term))
}

/// The seconds since 1970 of a time as [`rfc3339`] writes one.
fn seconds(at: &str) -> Option<u64> {
    let n = |range: std::ops::Range<usize>| at.get(range)?.parse::<u64>().ok();
    let (year, month, day) = (n(0..4)?, n(5..7)?, n(8..10)?);
    // Days from the civil date, as Howard Hinnant's algorithms have it.
    let (year, shifted) = if month <= 2 {
        (year.checked_sub(1)?, month + 9)
    } else {
        (year, month.checked_sub(3)?)
    };
    let of_era = year % 400;
    let days = year / 400 * 146_097 + of_era * 365 + of_era / 4 - of_era / 100 + (153 * shifted + 2) / 5 + day - 1;
    Some(days.checked_sub(719_468)? * 86400 + n(11..13)? * 3600 + n(14..16)? * 60 + n(17..19)?)
}

/// What `kubectl get` shows of an object: each column's name and what is in it.
fn row(kind: &str, object: &Value) -> Vec<(&'static str, Value)> {
    let at = |path: &str| object.pointer(path).cloned().unwrap_or(Value::Null);
    let n = |path: &str| object.pointer(path).and_then(Value::as_u64).unwrap_or(0);
    let of = |have: u64, all: u64| Value::from(format!("{have}/{all}"));
    let list = |path: &str| {
        object
            .pointer(path)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let size = |path: &str| {
        object
            .pointer(path)
            .and_then(Value::as_object)
            .map_or(0, |data| data.len())
    };
    let mut row = vec![("Name", at("/metadata/name"))];
    match kind {
        "Pod" => {
            let units = list("/status/containerStatuses");
            let ready = units.iter().filter(|unit| unit["ready"] == true).count() as u64;
            let restarts: u64 = units.iter().filter_map(|unit| unit["restartCount"].as_u64()).sum();
            let waiting = units.iter().find_map(|unit| unit.pointer("/state/waiting/reason"));
            let is = match (waiting, at("/status/phase")) {
                (Some(reason), _) => reason.clone(),
                (None, phase) if phase == "Succeeded" => "Completed".into(),
                (None, phase) => phase,
            };
            row.extend([
                ("Ready", of(ready, units.len() as u64)),
                ("Status", is),
                ("Restarts", restarts.into()),
                ("IP", at("/status/podIP")),
                ("Node", at("/spec/nodeName")),
            ]);
        }
        "Deployment" => row.extend([
            ("Ready", of(n("/status/readyReplicas"), n("/spec/replicas"))),
            ("Up-to-date", at("/status/updatedReplicas")),
            ("Available", at("/status/availableReplicas")),
        ]),
        "StatefulSet" => row.push(("Ready", of(n("/status/readyReplicas"), n("/spec/replicas")))),
        "DaemonSet" => row.extend([
            ("Desired", at("/status/desiredNumberScheduled")),
            ("Current", at("/status/currentNumberScheduled")),
            ("Ready", at("/status/numberReady")),
            ("Up-to-date", at("/status/updatedNumberScheduled")),
        ]),
        "ReplicaSet" => row.extend([
            ("Desired", at("/spec/replicas")),
            ("Current", at("/status/replicas")),
            ("Ready", at("/status/readyReplicas")),
        ]),
        "Job" => {
            let is = at("/status/conditions/0/type");
            let is = if is.is_null() { "Running".into() } else { is };
            let done = of(n("/status/succeeded"), n("/spec/completions"));
            row.extend([("Status", is), ("Completions", done)]);
        }
        "CronJob" => row.extend([
            ("Schedule", at("/spec/schedule")),
            ("Last schedule", at("/status/lastScheduleTime")),
        ]),
        "Service" => {
            let port = |port: &Value| format!("{}/{}", port["port"], port["protocol"].as_str().unwrap_or("TCP"));
            let ports: Vec<String> = list("/spec/ports").iter().map(port).collect();
            row.extend([
                ("Type", at("/spec/type")),
                ("Cluster-IP", at("/spec/clusterIP")),
                ("Port(s)", ports.join(",").into()),
            ]);
        }
        "Ingress" => {
            let hosts: Vec<Value> = list("/spec/rules").iter().map(|rule| rule["host"].clone()).collect();
            let hosts: Vec<&str> = hosts.iter().filter_map(Value::as_str).collect();
            row.push(("Hosts", hosts.join(",").into()));
        }
        "PersistentVolumeClaim" => row.extend([
            ("Status", at("/status/phase")),
            ("Volume", at("/spec/volumeName")),
            ("Capacity", at("/spec/resources/requests/storage")),
        ]),
        "Secret" => row.extend([("Type", at("/type")), ("Data", size("/data").into())]),
        "ConfigMap" => row.push(("Data", size("/data").into())),
        "Namespace" => row.push(("Status", at("/status/phase"))),
        "Node" => {
            let ready = at("/status/conditions/0/status") == "True";
            let is = if ready { "Ready" } else { "NotReady" };
            row.push(("Status", is.into()));
        }
        _ => {}
    }
    let made = object.pointer("/metadata/creationTimestamp").and_then(Value::as_str);
    let age = made.and_then(seconds).map(|made| match now().saturating_sub(made) {
        secs @ 0..120 => format!("{secs}s"),
        secs @ 120..7200 => format!("{}m", secs / 60),
        secs @ 7200..172_800 => format!("{}h", secs / 3600),
        secs => format!("{}d", secs / 86400),
    });
    row.push(("Age", age.into()));
    row
}

/// Objects as the table `kubectl get` prints: the server says the columns.
fn table(kind: &Kind, objects: &[Value], at: u64) -> Value {
    let column = |(name, _): &(&str, Value)| {
        let wide = matches!(*name, "IP" | "Node");
        let format = if *name == "Name" { "name" } else { "" };
        json!({ "name": name, "type": "string", "format": format, "description": "", "priority": i32::from(wide) })
    };
    let columns: Vec<Value> = row(kind.kind, &Value::Null).iter().map(column).collect();
    let line = |object: &Value| {
        let cells: Vec<Value> = row(kind.kind, object).into_iter().map(|(_, cell)| cell).collect();
        let of =
            json!({ "kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": object["metadata"] });
        json!({ "cells": cells, "object": of })
    };
    json!({
        "kind": "Table", "apiVersion": "meta.k8s.io/v1", "metadata": { "resourceVersion": at.to_string() },
        "columnDefinitions": columns, "rows": objects.iter().map(line).collect::<Vec<_>>(),
    })
}

/// The field that names an item of the list `list`, where a strategic patch merges it.
fn merge_key(list: &str, item: &Value) -> Option<&'static str> {
    match list {
        "ports" if item.get("containerPort").is_some() => Some("containerPort"),
        "ports" => Some("port"),
        list => MERGED.iter().find(|(of, _)| *of == list).map(|(_, by)| *by),
    }
}

/// `patch` laid over `live`: a JSON merge patch, or with `strategic` Kubernetes's own (the
/// lists of [`MERGED`] item by item, and its `$` directives).
fn patched(live: &mut Value, patch: Value, strategic: bool) {
    let Value::Object(patch) = patch else {
        *live = patch;
        return;
    };
    if !live.is_object() || (strategic && patch.get("$patch").is_some_and(|how| how == "replace")) {
        *live = json!({});
    }
    let Some(into) = live.as_object_mut() else { return };
    let (mut orders, mut keep) = (Vec::new(), None);
    for (field, value) in patch {
        // A `$` field of a strategic patch says how to merge, and is not itself merged in.
        if let Some(directive) = field.strip_prefix('$').filter(|_| strategic) {
            match (directive.split_once('/'), value) {
                (None, Value::Array(keys)) if directive == "retainKeys" => keep = Some(keys),
                (Some(("setElementOrder", list)), Value::Array(order)) => orders.push((list.to_string(), order)),
                (Some(("deleteFromPrimitiveList", list)), Value::Array(gone)) => {
                    if let Some(Value::Array(have)) = into.get_mut(list) {
                        have.retain(|value| !gone.contains(value));
                    }
                }
                _ => {}
            }
            continue;
        }
        let by = value.as_array().and_then(|items| merge_key(&field, items.first()?));
        match (value, by.filter(|_| strategic)) {
            (Value::Null, _) => drop(into.remove(&field)),
            (Value::Array(items), Some(by)) => merged(into.entry(field).or_insert(Value::Null), items, by),
            (Value::Object(part), _) if strategic && part.get("$patch").is_some_and(|how| how == "delete") => {
                into.remove(&field);
            }
            (part @ Value::Object(_), _) => patched(into.entry(field).or_insert(Value::Null), part, strategic),
            (value, _) => drop(into.insert(field, value)),
        }
    }
    for (list, order) in orders {
        if let Some(Value::Array(have)) = into.get_mut(&list)
            && let Some(by) = have.first().and_then(|first| merge_key(&list, first))
        {
            let place = |item: &Value| order.iter().position(|named| named[by] == item[by]);
            have.sort_by_key(|item| place(item).unwrap_or(usize::MAX));
        }
    }
    if let Some(keep) = keep {
        into.retain(|field, _| keep.iter().any(|kept| kept == field));
    }
}

/// The list of a strategic patch merged into the list that is there: each item into the
/// one that has its `by`, or added; `$patch: delete` takes one out, `replace` them all.
fn merged(have: &mut Value, items: Vec<Value>, by: &str) {
    if !have.is_array() || items.iter().any(|item| item["$patch"] == "replace") {
        *have = json!([]);
    }
    let Some(have) = have.as_array_mut() else { return };
    for item in items {
        let at = have.iter().position(|had| !item[by].is_null() && had[by] == item[by]);
        match (item["$patch"].as_str().map(|how| how == "delete"), at) {
            (Some(true), Some(at)) => drop(have.remove(at)),
            // (`replace` is of the list, and was done; what is to go and is not there is gone.)
            (Some(_), _) => {}
            (None, Some(at)) => patched(&mut have[at], item, true),
            (None, None) => {
                let mut new = Value::Null;
                patched(&mut new, item, true);
                have.push(new);
            }
        }
    }
}

type Asked = HashMap<String, String>;

/// One request: who asks, and what its query says.
struct Call {
    shared: Arc<Shared>,
    caller: Caller,
    certificate: Option<Certificate>,
    asked: Asked,
    /// `kubectl get` asks for the rows of its table, not the objects.
    table: bool,
}

/// How an object is written.
#[derive(Clone, Copy, PartialEq)]
enum How {
    Create,
    Replace,
    /// A patch of what is there: a JSON merge patch, or Kubernetes's strategic one.
    Patch {
        strategic: bool,
    },
    /// A server-side apply: what is sent is the object, made if it is not there.
    Apply,
}

async fn core(
    State(shared): State<Arc<Shared>>,
    parts: Parts,
    Path(rest): Path<String>,
    Query(asked): Query<Asked>,
    body: Bytes,
) -> Response {
    let served = serve(shared, parts, "", &rest, asked, &body).await;
    served.unwrap_or_else(No::into_response)
}

async fn grouped(
    State(shared): State<Arc<Shared>>,
    parts: Parts,
    Path((group, rest)): Path<(String, String)>,
    Query(asked): Query<Asked>,
    body: Bytes,
) -> Response {
    let served = serve(shared, parts, &group, &rest, asked, &body).await;
    served.unwrap_or_else(No::into_response)
}

/// `[namespaces/NAMESPACE/]PLURAL[/NAME[/PART]]` of a group, and what is done to it.
async fn serve(
    shared: Arc<Shared>,
    parts: Parts,
    group: &str,
    rest: &str,
    asked: Asked,
    body: &[u8],
) -> Result<Response, No> {
    let said = |name| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    };
    let Some(caller) = parts.extensions.get::<Caller>().cloned() else {
        return Err(status(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "who asks is not known".into(),
        ));
    };
    let call = Call {
        shared,
        caller,
        certificate: parts.extensions.get::<Certificate>().cloned(),
        asked,
        table: said(header::ACCEPT).contains("as=Table"),
    };
    let path: Vec<&str> = rest.split('/').collect();
    let (namespace, path) = match path[..] {
        ["namespaces", namespace, plural, ..] if !matches!(plural, "status" | "finalize") => {
            (Some(namespace), &path[2..])
        }
        _ => (None, &path[..]),
    };
    let found = KINDS
        .iter()
        .find(|kind| kind.group == group && Some(&kind.plural) == path.first());
    let (name, part) = (path.get(1).copied(), path.get(2).copied());
    // (A kind that is in namespaces is named in one; one that is in none is asked for in none.)
    let placed = |kind: &&Kind| match (kind.namespaced, namespace) {
        (true, None) => name.is_none(),
        (false, Some(_)) => false,
        _ => true,
    };
    let Some(kind) = found.filter(placed).filter(|_| path.len() <= 3) else {
        return Err(missing());
    };
    // What is sent: JSON, and an apply may be YAML; `kubectl create` and Helm send a kind
    // Kubernetes itself has in its binary encoding.
    let sent = || -> Result<Value, No> {
        let read = match body.starts_with(crate::kubeproto::MAGIC) {
            true => crate::kubeproto::object(body),
            false => serde_json::from_slice(body).map_err(|e| e.to_string()).or_else(|e| {
                let text = std::str::from_utf8(body).map_err(|_| e)?;
                let mut documents = kith_kube::documents("the request", text)?;
                let one = documents.pop().filter(|_| documents.is_empty());
                one.ok_or("not one object".to_string())
            }),
        };
        let unread = |e| {
            status(
                StatusCode::BAD_REQUEST,
                "BadRequest",
                format!("the body cannot be read: {e}"),
            )
        };
        read.map_err(unread)
    };
    let watching = call
        .asked
        .get("watch")
        .is_some_and(|watch| watch == "true" || watch == "1");
    Ok(match (parts.method.as_str(), name, part) {
        ("GET", None, None) if watching => watch(call, kind, namespace.map(str::to_string))?,
        ("GET", None, None) => list(&call, kind, namespace)?,
        ("GET", Some(name), None | Some("status")) => one(&call, kind, namespace, name, false)?,
        ("GET", Some(name), Some("scale")) if scales(kind) => one(&call, kind, namespace, name, true)?,
        ("GET", Some(name), Some("log")) if kind.kind == "Pod" => {
            log(&call, namespace.unwrap_or_default(), name).await?
        }
        ("POST", None, None) => write(&call, kind, namespace, None, How::Create, sent()?)
            .await?
            .into_response(),
        ("PUT", Some(name), None) => {
            let written = write(&call, kind, namespace, Some(name), How::Replace, sent()?).await?;
            written.into_response()
        }
        ("PATCH", Some(name), None) => {
            let how = match said(header::CONTENT_TYPE).split(';').next().unwrap_or_default().trim() {
                "application/strategic-merge-patch+json" => How::Patch { strategic: true },
                "application/merge-patch+json" => How::Patch { strategic: false },
                "application/apply-patch+yaml" => How::Apply,
                other => {
                    let why = format!(
                        "a patch as {other} is not read: send a merge patch, a strategic merge patch or an apply"
                    );
                    return Err(status(StatusCode::UNSUPPORTED_MEDIA_TYPE, "UnsupportedMediaType", why));
                }
            };
            write(&call, kind, namespace, Some(name), how, sent()?)
                .await?
                .into_response()
        }
        // A scale is the one number, whichever way it comes.
        ("PUT" | "PATCH", Some(name), Some("scale")) if scales(kind) => {
            let Some(replicas) = sent()?["spec"]["replicas"].as_u64() else {
                return Err(invalid("spec.replicas: a scale says how many".into()));
            };
            let (how, replicas) = (
                How::Patch { strategic: false },
                json!({ "spec": { "replicas": replicas } }),
            );
            let Written(code, object, said) = write(&call, kind, namespace, Some(name), how, replicas).await?;
            Written(code, object.as_ref().map(scale_of), said).into_response()
        }
        ("DELETE", Some(name), None) => {
            let options = if body.is_empty() { Value::Null } else { sent()? };
            delete(&call, kind, namespace, name, &options).await?
        }
        (_, Some(_), Some("exec" | "attach" | "portforward")) => {
            let why = "exec, attach and port-forward are not answered here: `kith run` runs a command in a replica";
            return Err(status(StatusCode::NOT_IMPLEMENTED, "NotImplemented", why.into()));
        }
        (method, ..) => {
            let why = format!("{method} is not done to {rest}");
            return Err(status(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", why));
        }
    })
}

impl Call {
    /// A refusal unless the caller may `verb` what holds `kind` there. (What is made up is
    /// picked object by object, by who may see what it is made up from.)
    fn allowed(&self, kind: &Kind, namespace: Option<&str>, verb: Verb) -> Result<(), No> {
        let place = match (kind.held, kind.namespaced, namespace) {
            (Held::Made, ..) => return Ok(()),
            // Everywhere: whoever may see some of them, sees those.
            (_, true, None) => {
                let seen = api::sight(&self.shared, &self.caller, verb, Some(holder(kind)));
                return seen.map_err(refusal);
            }
            (Held::As("Namespace"), ..) => None,
            (_, _, namespace) => Some(namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE).to_string()),
        };
        let held = vec![(holder(kind).to_string(), place)];
        api::permit(&self.shared, &self.caller, verb, |_| held).map_err(refusal)
    }

    /// What `verb` lets the caller see of `kind`, and the store's generation with it.
    fn seen(&self, kind: &'static Kind, namespace: Option<&str>, name: Option<&str>, verb: Verb) -> (Vec<Value>, u64) {
        let state = self.shared.store.lock().expect("a handler panicked holding the store");
        let grants = Grants::of(&self.caller, &state.store);
        let mut found = objects(&state.store, kind, namespace, name, &grants, &verb);
        found.retain(|object| selected(object, &self.asked));
        // (Read under the store's lock: a change and its generation come together.)
        (found, *self.shared.generation.borrow())
    }
}

fn one(call: &Call, kind: &'static Kind, namespace: Option<&str>, name: &str, scale: bool) -> Result<Response, No> {
    call.allowed(kind, namespace, Verb::Get)?;
    let (mut found, at) = call.seen(kind, namespace, Some(name), Verb::Get);
    let object = found.pop().ok_or_else(|| not_found(kind, name))?;
    Ok(Json(match (scale, call.table) {
        (true, _) => scale_of(&object),
        (_, true) => table(kind, &[object], at),
        _ => object,
    })
    .into_response())
}

fn list(call: &Call, kind: &'static Kind, namespace: Option<&str>) -> Result<Response, No> {
    call.allowed(kind, namespace, Verb::List)?;
    let (items, at) = call.seen(kind, namespace, None, Verb::List);
    if call.table {
        return Ok(Json(table(kind, &items, at)).into_response());
    }
    let list = json!({
        "kind": format!("{}List", kind.kind), "apiVersion": version_of(kind.group),
        "metadata": { "resourceVersion": at.to_string() }, "items": items,
    });
    Ok(Json(list).into_response())
}

/// What `kubectl scale` reads and writes of a Deployment or a StatefulSet.
fn scale_of(object: &Value) -> Value {
    let labels = object.pointer("/spec/selector/matchLabels").and_then(Value::as_object);
    let label = |(key, value): (&String, &Value)| Some(format!("{key}={}", value.as_str()?));
    let selector: Vec<String> = labels.into_iter().flatten().filter_map(label).collect();
    json!({
        "kind": "Scale", "apiVersion": "autoscaling/v1", "metadata": object["metadata"],
        "spec": { "replicas": object["spec"]["replicas"] },
        "status": { "replicas": object["status"]["replicas"], "selector": selector.join(",") },
    })
}

/// The Ingresses of a namespace as they were sent, and with `services` its Services, but
/// for the one held at `but`: an Ingress is its hosts on the Services behind it, so a
/// Service is read with the Ingresses, and an Ingress with them all.
fn exposed(store: &Store, namespace: &str, but: &str, services: bool) -> Vec<Value> {
    let here = |resource: &&Resource| resource.metadata.namespace.as_deref() == Some(namespace);
    let wanted = |kind: &Kind| kind.kind == "Ingress" || (services && kind.kind == "Service");
    let sent = |resource: &Resource| raw(resource).filter(|(kind, _)| wanted(kind));
    let all = ["Service", "KubeObject"]
        .into_iter()
        .flat_map(|kind| store.list(Some(kind)));
    let objects = all
        .filter(here)
        .filter(|resource| resource.key() != but)
        .filter_map(sent);
    objects.map(|(_, object)| object).collect()
}

/// The kith resources `objects` come to, each with the object it holds beside it as `sent`
/// has it (the one being written) or as the store does; and what is said of them.
fn translated(store: &Store, objects: Vec<Value>, sent: Option<(&str, &Value)>) -> kith_kube::Taken {
    let mut taken = kith_kube::take(objects, false);
    for resource in &mut taken.resources {
        let key = resource.key();
        let live = store.get(&key).map(|live| &live.metadata.annotations);
        let beside = match sent {
            Some((primary, sent)) if primary == key => {
                let mut sent = sent.clone();
                // (A Secret's data is not kept twice, nor a ConfigMap's.)
                if let Some(sent) = sent.as_object_mut().filter(|_| resource.spec.get("data").is_some()) {
                    sent.remove("data");
                    sent.remove("stringData");
                }
                Some(sent.to_string())
            }
            _ => live.and_then(|live| live.get(SENT)).cloned(),
        };
        let made = live.and_then(|live| live.get(MADE)).cloned();
        let notes = &mut resource.metadata.annotations;
        // (What is noted here is this layer's to say: an object that came with such a note has it taken off.)
        notes.retain(|note, _| !note.starts_with("kube.kith.dev/"));
        notes.extend(beside.map(|beside| (SENT.to_string(), beside)));
        notes.insert(MADE.into(), made.unwrap_or_else(|| now().to_string()));
    }
    taken
}

/// The kith resources an object of `kind` comes to (what holds it among them), and what is
/// said of it; or why it is refused.
fn held_as(
    store: &Store,
    kind: &Kind,
    namespace: Option<&str>,
    name: &str,
    sent: &Value,
) -> Result<(Vec<Resource>, Vec<String>), Vec<String>> {
    let primary = key(kind, namespace, name);
    let who = format!("{}/{name}:", kind.kind);
    let place = namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE);
    let live = store.get(&primary);
    let made = live.and_then(|live| live.metadata.annotations.get(MADE)).cloned();
    let noted = |sent: Option<String>| -> BTreeMap<String, String> {
        let made = (MADE.to_string(), made.clone().unwrap_or_else(|| now().to_string()));
        std::iter::once(made)
            .chain(sent.map(|sent| (SENT.to_string(), sent)))
            .collect()
    };
    let resource = |holder: &str, name: String, namespace, labels, annotations, spec| Resource {
        api_version: kith_api::API_VERSION.into(),
        kind: holder.into(),
        metadata: Metadata {
            name,
            namespace,
            labels,
            annotations,
            revision: None,
        },
        spec,
        status: None,
    };
    let (mut resources, others) = match kind.held {
        Held::Made => {
            let why = match kind.kind {
                "Pod" => "a pod is run by what owns it: send a Deployment, a StatefulSet, a DaemonSet or a Job",
                _ => "is not an object that is written: kith makes it up from what it runs",
            };
            return Err(vec![format!("{who} {why}")]);
        }
        // A namespace kith knows more of (its quota, its hosts) keeps that.
        Held::As("Namespace") => {
            let labels = sent["metadata"]["labels"].as_object().into_iter().flatten();
            let labels = labels.filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_string())));
            let spec = live.map_or_else(|| json!({}), |live| live.spec.clone());
            let annotations = noted(Some(sent.to_string()));
            let held = resource("Namespace", name.into(), None, labels.collect(), annotations, spec);
            return Ok((vec![held], Vec::new()));
        }
        Held::Kept(said) => {
            let spec = json!({ "object": sent });
            let within = Some(place.to_string());
            let kept = resource(
                "KubeObject",
                kept_name(kind, name),
                within,
                BTreeMap::new(),
                noted(None),
                spec,
            );
            match kind.kind {
                "Ingress" => (vec![kept], exposed(store, place, &primary, true)),
                _ => {
                    let said = (!said.is_empty()).then(|| format!("{who} {said}"));
                    return Ok((vec![kept], said.into_iter().collect()));
                }
            }
        }
        Held::As(_) if kind.kind == "Service" => (Vec::new(), exposed(store, place, &primary, false)),
        Held::As(_) => (Vec::new(), Vec::new()),
    };
    let objects = others.into_iter().chain([sent.clone()]).collect();
    let taken = translated(store, objects, Some((&primary, sent)));
    let mine =
        |lines: Vec<String>| -> Vec<String> { lines.into_iter().filter(|line| line.starts_with(&who)).collect() };
    let refused = mine(taken.refused);
    if !refused.is_empty() {
        return Err(refused);
    }
    resources.extend(taken.resources);
    // A StatefulSet's claims are objects of their own in Kubernetes: each is shown as its template says.
    for template in sent["spec"]["volumeClaimTemplates"].as_array().into_iter().flatten() {
        let claim = format!("{}-{name}-0", template["metadata"]["name"].as_str().unwrap_or_default());
        let held = resources
            .iter_mut()
            .find(|held| held.kind == "VolumeClaim" && held.metadata.name == claim);
        if let Some(held) = held.filter(|held| !held.metadata.annotations.contains_key(SENT)) {
            let mut object = json!({
                "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": { "name": claim, "namespace": place }, "spec": template["spec"],
            });
            if let Some(labels) = template.pointer("/metadata/labels") {
                set(&mut object, "/metadata/labels", labels.clone());
            }
            held.metadata.annotations.insert(SENT.into(), object.to_string());
        }
    }
    match resources.iter().any(|resource| resource.key() == primary) {
        true => Ok((resources, mine(taken.hints))),
        false => Err(vec![format!("{who} comes to nothing kith can hold")]),
    }
}

/// Whether `version` (an object's `apiVersion`) is one of Kubernetes's that is taken here.
pub fn speaks(version: &str) -> bool {
    KINDS.iter().any(|kind| version_of(kind.group) == version)
}

/// What a set of Kubernetes manifests comes to, for a Source that has them in its files:
/// the kith resources `kubectl apply` of each in turn would leave (an object that names
/// no namespace is in `home`), and what is said of them; or why one is refused.
pub fn from_files(objects: Vec<Value>, home: &str) -> Result<(Vec<Resource>, Vec<String>), String> {
    let (mut store, mut said) = (Store::default(), Vec::new());
    // (A stack, so that a List's items come in their order.)
    let mut objects: Vec<Value> = objects.into_iter().rev().collect();
    while let Some(mut object) = objects.pop() {
        let text = |at: &str| {
            object
                .pointer(at)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let (version, named, name) = (text("/apiVersion"), text("/kind"), text("/metadata/name"));
        if let Some(items) = object["items"].as_array().filter(|_| named.ends_with("List")) {
            objects.extend(items.iter().rev().cloned());
            continue;
        }
        let is = |kind: &&Kind| kind.kind == named && version_of(kind.group) == version;
        let Some(kind) = KINDS.iter().find(is) else {
            return Err(format!("{named}/{name}: {version} has no kind {named} here"));
        };
        let namespace = kind.namespaced.then(|| text("/metadata/namespace"));
        let namespace = namespace.map(|said| if said.is_empty() { home.to_string() } else { said });
        if let Some(namespace) = &namespace {
            set(&mut object, "/metadata/namespace", namespace.as_str().into());
        }
        let held = held_as(&store, kind, namespace.as_deref(), &name, &object);
        let (resources, hints) = held.map_err(|refused| refused.join("; "))?;
        said.extend(hints);
        for resource in resources {
            store.apply(resource).map_err(|e| format!("{named}/{name}: {e}"))?;
        }
    }
    // (When it was made is the store's to know, not the files': each fetch would say another.)
    let plain = |resource: &Resource| {
        let mut resource = resource.clone();
        resource.metadata.annotations.remove(MADE);
        resource
    };
    Ok((store.list(None).map(plain).collect(), said))
}

/// What a write came to: its HTTP status, the object as it now is, and what is said of it.
struct Written(StatusCode, Option<Value>, Vec<String>);

impl IntoResponse for Written {
    fn into_response(self) -> Response {
        let mut reply = (self.0, Json(self.1.unwrap_or_default())).into_response();
        // What was taken and changes nothing is said, as Kubernetes says what it took and
        // will not use: kubectl prints each as a warning.
        for hint in self.2 {
            let plain = |c: char| {
                if c.is_control() || c == '"' || c == '\\' {
                    ' '
                } else {
                    c
                }
            };
            let plain: String = hint.chars().map(plain).collect();
            if let Ok(warning) = format!("299 - \"{plain}\"").parse() {
                reply.headers_mut().append("warning", warning);
            }
        }
        reply
    }
}

async fn write(
    call: &Call,
    kind: &'static Kind,
    namespace: Option<&str>,
    name: Option<&str>,
    how: How,
    body: Value,
) -> Result<Written, No> {
    let said = body.pointer("/metadata/name").and_then(Value::as_str);
    let Some(name) = name.or(said).map(str::to_string) else {
        let why = "metadata.name: an object needs a name (kith gives none: `generateName` is not done)";
        return Err(invalid(why.into()));
    };
    // Who may not write here is told that, and nothing of what is there; and a change
    // of what is there (a patch is answered with all of it) is for who may read it.
    call.allowed(kind, namespace, Verb::Apply)?;
    if matches!(how, How::Patch { .. }) {
        call.allowed(kind, namespace, Verb::Get)?;
    }
    let primary = key(kind, namespace, &name);
    let exists = || {
        status(
            StatusCode::CONFLICT,
            "AlreadyExists",
            format!("{} \"{name}\" already exists", kind.plural),
        )
    };
    let read = {
        let state = call.shared.store.lock().expect("a handler panicked holding the store");
        let live = state.store.get(&primary);
        let before = live.and_then(raw).filter(|(of, _)| std::ptr::eq(*of, kind));
        // What is there and was not made here, or not as this kind, is not written over.
        if live.is_some() && before.is_none() {
            let why = format!(
                "{primary} is there, and was not made as a {} through this API",
                kind.kind
            );
            return Err(status(StatusCode::CONFLICT, "AlreadyExists", why));
        }
        let revision = live.and_then(|live| live.metadata.revision);
        let mut sent = match (how, before) {
            (How::Create, Some(_)) => return Err(exists()),
            (How::Create | How::Apply, _) | (How::Replace, Some(_)) => body,
            (_, None) => return Err(not_found(kind, &name)),
            (How::Patch { strategic }, Some((_, mut before))) => {
                patched(&mut before, body, strategic);
                before
            }
        };
        // A change of what was read is held to it: the revision, whatever its status did since.
        let based = sent.pointer("/metadata/resourceVersion").and_then(Value::as_str);
        let based = based
            .and_then(|based| based.parse::<u64>().ok())
            .filter(|_| how == How::Replace);
        if based.is_some_and(|based| Some(based >> 32) != revision) {
            let why = format!("{primary} has been changed since: read it again, and change that");
            return Err(status(StatusCode::CONFLICT, "Conflict", why));
        }
        let Some(root) = sent.as_object_mut() else {
            return Err(invalid("the object is not a mapping".into()));
        };
        if root.get("kind").is_some_and(|said| said != kind.kind) {
            return Err(invalid(format!("kind: this is where a {} is sent", kind.kind)));
        }
        root.insert("apiVersion".into(), version_of(kind.group).into());
        root.insert("kind".into(), kind.kind.into());
        root.remove("status");
        let meta = root.entry("metadata").or_insert_with(|| json!({}));
        let Some(meta) = meta.as_object_mut() else {
            return Err(invalid("metadata: should be a mapping".into()));
        };
        // What the server says of an object is not the client's to send, and the path says where it is.
        for theirs in [
            "resourceVersion",
            "generation",
            "uid",
            "creationTimestamp",
            "managedFields",
            "selfLink",
        ] {
            meta.remove(theirs);
        }
        let place = namespace.filter(|_| kind.namespaced);
        for (field, said) in [("name", Some(name.as_str())), ("namespace", place)] {
            let other = |sent: &Value| !sent.is_null() && sent.as_str() != said;
            if meta.get(field).is_some_and(other) {
                return Err(invalid(format!("metadata.{field}: is not the request's")));
            }
            match said {
                Some(said) => meta.insert(field.into(), said.into()),
                None => meta.remove(field),
            };
        }
        held_as(&state.store, kind, place, &name, &sent).map(|held| (held, revision))
    };
    let ((mut resources, hints), revision) = read.map_err(|refused| invalid(refused.join("; ")))?;
    // Made only if it is not there, changed only as it was read: the store holds to that.
    for resource in resources.iter_mut().filter(|resource| resource.key() == primary) {
        resource.metadata.revision = match how {
            How::Create => Some(0),
            How::Apply => None,
            _ => revision,
        };
    }
    let done = match call.asked.contains_key("dryRun") {
        true => api::plan(&call.shared, &call.caller, resources).await,
        false => api::applied(&call.shared, &call.caller, resources).await,
    };
    let changes = done.map_err(|e| match e {
        ApiError::Store(Error::Conflict(_)) if how == How::Create => exists(),
        e => refusal(e),
    })?;
    let change = changes.into_iter().find(|change| change.after.key() == primary);
    let code = match change.as_ref().map(|change| change.action) {
        Some(Action::Created) => StatusCode::CREATED,
        _ => StatusCode::OK,
    };
    let object = change
        .and_then(|change| served(&change.after))
        .map(|(_, object)| object);
    Ok(Written(code, object, hints))
}

async fn delete(
    call: &Call,
    kind: &'static Kind,
    namespace: Option<&str>,
    name: &str,
    options: &Value,
) -> Result<Response, No> {
    if options["propagationPolicy"] == "Orphan" || options["orphanDependents"] == true {
        return Err(invalid(
            "propagationPolicy: Orphan: a replica is not an object that can be left behind".into(),
        ));
    }
    let mut hints = Vec::new();
    if !options["gracePeriodSeconds"].is_null() {
        let kind = kind.kind;
        hints.push(format!(
            "{kind}/{name}: gracePeriodSeconds is taken and changes nothing: what it runs is stopped as kith stops it"
        ));
    }
    // (Asked first: who may not delete here is not told what is there.)
    call.allowed(kind, namespace, Verb::Delete)?;
    let dry = call.asked.contains_key("dryRun") || options["dryRun"].is_array();
    let primary = key(kind, namespace, name);
    let (keys, said, stay) = {
        let state = call.shared.store.lock().expect("a handler panicked holding the store");
        let store = &state.store;
        let live = store
            .get(&primary)
            .and_then(served)
            .filter(|(of, _)| std::ptr::eq(*of, kind));
        let said = live.as_ref().map(|(_, object)| object["metadata"]["uid"].clone());
        // Asked to delete this one only as it was seen: another by its name, or it changed, stays.
        // (Looked at here and deleted below: a change in between is not seen.)
        for field in ["uid", "resourceVersion"] {
            let (wanted, live) = (&options["preconditions"][field], live.as_ref());
            let is = live.map_or(&Value::Null, |(_, object)| &object["metadata"][field]);
            if !wanted.is_null() && live.is_some() && wanted != is {
                let why = format!("preconditions.{field}: {primary} is not {wanted} but {is}");
                return Err(status(StatusCode::CONFLICT, "Conflict", why));
            }
        }
        match (kind.kind, live.is_some()) {
            // A namespace goes with all that was made in it here; what kith's own files put there stays.
            ("Namespace", there) => {
                let within = |resource: &&Resource| resource.metadata.namespace.as_deref() == Some(name);
                let (ours, theirs): (Vec<_>, Vec<_>) = store.list(None).filter(within).partition(|r| raw(r).is_some());
                if ours.is_empty() && !there {
                    return Err(not_found(kind, name));
                }
                let mut keys: Vec<String> = ours.into_iter().map(Resource::key).collect();
                keys.extend(there.then(|| primary.clone()));
                (keys, said, theirs.len())
            }
            (_, false) => return Err(not_found(kind, name)),
            (_, true) => (vec![primary.clone()], said, 0),
        }
    };
    if !dry {
        // (All of a namespace or none of it: who may not delete one kind in it deletes nothing.)
        let places = |_: &Store| {
            let place = |key: &String| {
                let parts: Vec<&str> = key.split('/').collect();
                let namespace = (parts.len() == 3).then(|| parts[1].to_string());
                (parts[0].to_string(), namespace)
            };
            keys.iter().map(place).collect()
        };
        api::permit(&call.shared, &call.caller, Verb::Delete, places).map_err(refusal)?;
        for key in keys {
            api::deleted(&call.shared, &call.caller, key).await.map_err(refusal)?;
        }
        // The Services an Ingress exposed are read again without it.
        if kind.kind == "Ingress" {
            let place = namespace.unwrap_or(kith_api::DEFAULT_NAMESPACE);
            let left = {
                let state = call.shared.store.lock().expect("a handler panicked holding the store");
                translated(&state.store, exposed(&state.store, place, "", true), None).resources
            };
            api::applied(&call.shared, &call.caller, left).await.map_err(refusal)?;
        }
    }
    let done = json!({
        "kind": "Status", "apiVersion": "v1", "status": "Success",
        "details": { "name": name, "group": kind.group, "kind": kind.plural, "uid": said },
    });
    let stay = (stay > 0).then(|| {
        format!("Namespace/{name}: {stay} resources in it were not made through this API, and stay: `kith delete` removes them")
    });
    hints.extend(stay);
    Ok(Written(StatusCode::OK, Some(done), hints).into_response())
}

/// What a watch has told its client, and what is still to tell.
struct Watch {
    call: Call,
    kind: &'static Kind,
    namespace: Option<String>,
    generation: tokio::sync::watch::Receiver<u64>,
    /// Each object told of: its version, and enough of it to say it is gone.
    known: BTreeMap<String, (Value, Value)>,
    /// Events not sent yet, a line each.
    due: Vec<u8>,
    until: tokio::time::Instant,
    over: bool,
}

impl Watch {
    fn event(&mut self, event: &str, object: &Value, at: u64) {
        let line = match self.call.table && event != "BOOKMARK" {
            true => json!({ "type": event, "object": table(self.kind, std::slice::from_ref(object), at) }),
            false => json!({ "type": event, "object": object }),
        };
        serde_json::to_writer(&mut self.due, &line).expect("JSON into memory");
        self.due.push(b'\n');
    }

    /// Lines up an event for each object of `found` that is new or changed since the last
    /// look, and for each that is gone (none with `quiet`: the client has them from its
    /// list). Then a bookmark, where the client takes them: the generation it is told up to.
    fn tell(&mut self, found: Vec<Value>, at: u64, quiet: bool, first: bool) {
        let mut gone: BTreeSet<String> = self.known.keys().cloned().collect();
        let mut told = false;
        for object in found {
            let meta = &object["metadata"];
            let id = format!("{}/{}", meta["namespace"], meta["name"]);
            gone.remove(&id);
            let event = match self.known.get(&id) {
                None => "ADDED",
                Some((version, _)) if *version != meta["resourceVersion"] => "MODIFIED",
                Some(_) => continue,
            };
            let last = json!({
                "apiVersion": object["apiVersion"], "kind": object["kind"],
                "metadata": {
                    "name": meta["name"], "namespace": meta["namespace"], "uid": meta["uid"],
                    "resourceVersion": meta["resourceVersion"],
                },
            });
            self.known.insert(id, (meta["resourceVersion"].clone(), last));
            if !quiet {
                self.event(event, &object, at);
                told = true;
            }
        }
        for id in gone {
            if let Some((_, last)) = self.known.remove(&id) {
                self.event("DELETED", &last, at);
                told = true;
            }
        }
        let asked = |name: &str| self.call.asked.get(name).is_some_and(|value| value == "true");
        let (bookmarks, ends) = (asked("allowWatchBookmarks"), first && asked("sendInitialEvents"));
        if (told || first || self.over) && bookmarks {
            let mut mark = json!({
                "apiVersion": version_of(self.kind.group), "kind": self.kind.kind,
                "metadata": { "resourceVersion": at.to_string() },
            });
            // (A client that asked for what is there as events is told where they end.)
            if ends {
                mark["metadata"]["annotations"] = json!({ "k8s.io/initial-events-end": "true" });
            }
            self.event("BOOKMARK", &mark, at);
        }
    }

    /// Does the caller's certificate still stand for it? (A watch is long: an Identity
    /// deleted, or given another key, meanwhile is told no more.)
    fn stands(&self) -> bool {
        match (&self.call.caller, &self.call.certificate) {
            (Caller::Identity(name), Some(Certificate(der))) => access::stands(&self.call.shared, name, der),
            (Caller::Identity(_), None) => false,
            _ => true,
        }
    }
}

fn watch(call: Call, kind: &'static Kind, namespace: Option<String>) -> Result<Response, No> {
    call.allowed(kind, namespace.as_deref(), Verb::Watch)?;
    let asked = |name: &str| call.asked.get(name).map(String::as_str);
    let seconds = asked("timeoutSeconds").and_then(|seconds| seconds.parse().ok());
    let seconds = seconds.unwrap_or(WATCH_SECS).min(WATCH_SECS);
    let from = asked("resourceVersion").filter(|from| !from.is_empty() && *from != "0");
    let from = from.map(str::to_string);
    let events = asked("sendInitialEvents") == Some("true");
    // (Marked as seen before the store is read: a change after the reading wakes the watch.)
    let mut generation = call.shared.generation.subscribe();
    drop(generation.borrow_and_update());
    let (found, at) = call.seen(kind, namespace.as_deref(), None, Verb::Watch);
    // From a list's version, only what changes after it is told; and only from the newest:
    // what changed between an older one and now is not kept anywhere.
    if let Some(from) = from.as_ref().filter(|from| **from != at.to_string() && !events) {
        let why = format!("too old resource version: {from} ({at})");
        return Err(status(StatusCode::GONE, "Expired", why));
    }
    let mut watch = Watch {
        generation,
        call,
        kind,
        namespace,
        known: BTreeMap::new(),
        due: Vec::new(),
        until: tokio::time::Instant::now() + Duration::from_secs(seconds),
        over: false,
    };
    watch.tell(found, at, from.is_some() && !events, true);
    let events = futures_util::stream::unfold(watch, |mut watch| async move {
        loop {
            if !watch.due.is_empty() {
                let due = std::mem::take(&mut watch.due);
                return Some((Ok::<_, std::io::Error>(Bytes::from(due)), watch));
            }
            if watch.over {
                return None;
            }
            let mut stop = watch.call.shared.stop.subscribe();
            tokio::select! {
                changed = watch.generation.changed() => watch.over = changed.is_err(),
                _ = stop.wait_for(|stop| *stop) => watch.over = true,
                () = tokio::time::sleep_until(watch.until) => watch.over = true,
            }
            if !watch.stands() {
                return None;
            }
            drop(watch.generation.borrow_and_update());
            let namespace = watch.namespace.clone();
            let (found, at) = watch.call.seen(watch.kind, namespace.as_deref(), None, Verb::Watch);
            watch.tell(found, at, false, false);
        }
    });
    Ok(([(header::CONTENT_TYPE, "application/json")], Body::from_stream(events)).into_response())
}

/// A reading of what a pod's units wrote, and where in each file it has come to.
struct Reading {
    shared: Arc<Shared>,
    /// The resource that runs the pod, and which replica of it the pod is.
    key: String,
    replica: u32,
    unit: Option<String>,
    tail: Option<u64>,
    at: [Option<u64>; 2],
}

impl Reading {
    /// What was written to stdout and to stderr since the last reading, and whether more may come.
    async fn more(&mut self) -> Result<(String, bool), ApiError> {
        let (mut text, mut more) = (String::new(), false);
        for stream in 0..2 {
            let options = LogOptions {
                unit: self.unit.clone(),
                replica: self.replica,
                stderr: stream == 1,
                offset: self.at[stream],
                tail: self.tail.filter(|_| self.at[stream].is_none()),
                ..LogOptions::default()
            };
            let Json(read) = api::output(&self.shared, &self.key, &options).await?;
            text.push_str(read["data"].as_str().unwrap_or_default());
            self.at[stream] = read["next"].as_u64();
            more |= read["more"] == true;
        }
        Ok((text, more))
    }
}

/// What the units of a pod wrote, as `kubectl logs` reads it: plain text, what was
/// written to stdout and then what was written to stderr, and with `follow` what comes after.
//
// ponytail: the two are two files here, so they are not in the order they were written;
// one file with both would be a change of every unit's log.
async fn log(call: &Call, namespace: &str, pod: &str) -> Result<Response, No> {
    let not_kept = ["sinceSeconds", "sinceTime", "timestamps", "previous", "limitBytes"];
    if let Some(asked) = not_kept.iter().find(|asked| call.asked.contains_key(**asked)) {
        let why = format!("{asked}: a unit's output is kept as it was written, all its runs in one file and not when");
        return Err(status(StatusCode::BAD_REQUEST, "BadRequest", why));
    }
    // Which replica of what: a pod's name is its owner's and the replica's number.
    let owner = pod.rsplit_once('-').and_then(|(owner, replica)| {
        let replica: u32 = replica.parse().ok()?;
        let state = call.shared.store.lock().expect("a handler panicked holding the store");
        let keys = ["Workload", "NodeWorkload", "Job"].map(|holder| format!("{holder}/{namespace}/{owner}"));
        let made_here = |key: &String| state.store.get(key).is_some_and(|owner| raw(owner).is_some());
        Some((keys.into_iter().find(made_here)?, replica))
    });
    let (key, replica) = owner.ok_or_else(|| not_found(&KINDS[0], pod))?;
    // What a unit wrote is read by who may read the resource that runs it.
    let holder = key.split('/').next().unwrap_or_default().to_string();
    let place = vec![(holder, Some(namespace.to_string()))];
    api::permit(&call.shared, &call.caller, Verb::Get, |_| place).map_err(refusal)?;
    let follow = call.asked.get("follow").is_some_and(|follow| follow == "true");
    let mut reading = Reading {
        shared: call.shared.clone(),
        key,
        replica,
        unit: call.asked.get("container").cloned(),
        tail: call.asked.get("tailLines").and_then(|lines| lines.parse().ok()),
        at: [None; 2],
    };
    // (The first reading here, so that what cannot be read is said as an error.)
    let (first, _) = reading.more().await.map_err(refusal)?;
    let chunks = futures_util::stream::unfold((reading, Some(first)), move |(mut reading, first)| async move {
        if let Some(first) = first.filter(|first| !first.is_empty()) {
            return Some((Ok::<_, std::io::Error>(Bytes::from(first)), (reading, None)));
        }
        loop {
            let (text, more) = reading.more().await.ok()?;
            if !text.is_empty() {
                return Some((Ok(Bytes::from(text)), (reading, None)));
            }
            if !follow || !more || *reading.shared.stop.borrow() {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
    Ok(([(header::CONTENT_TYPE, "text/plain")], Body::from_stream(chunks)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Who may write a kind and not read it is not answered with what is there by a
    /// change of it, and who may do neither is not told whether it is there.
    #[tokio::test]
    async fn a_write_is_asked_for_before_anything_is_said_of_what_is_there() {
        let dir = std::env::temp_dir().join(format!("kithd-kube-write-{}", std::process::id()));
        let shared = crate::replica(None, &dir).await.unwrap();
        let held = "
apiVersion: kith.dev/v1
kind: Role
metadata: {name: writer}
spec:
  rules:
    - {kinds: [Secret], verbs: [apply]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: carol-writer}
spec: {role: writer, subjects: [carol]}
";
        let call = |who: &str| Call {
            shared: shared.clone(),
            caller: Caller::Identity(who.into()),
            certificate: None,
            asked: Asked::new(),
            table: false,
        };
        {
            let mut state = shared.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(held).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
        }
        let secrets = KINDS.iter().find(|kind| kind.kind == "Secret").unwrap();
        let kept = json!({ "metadata": { "name": "kept" }, "stringData": { "password": "hunter2" } }); // pragma: allowlist secret
        let admin = Call {
            caller: Caller::Admin,
            ..call("root")
        };
        let made = write(&admin, secrets, Some("default"), None, How::Create, kept).await;
        assert!(made.is_ok_and(|made| made.0 == StatusCode::CREATED));
        let label = || json!({ "metadata": { "labels": { "a": "b" } } });
        let patch = How::Patch { strategic: false };
        let code = |done: Result<Written, No>| done.err().map(|no| no.code);
        let carol = call("carol");
        let done = write(&carol, secrets, Some("default"), Some("kept"), patch, label()).await;
        assert_eq!(
            code(done),
            Some(StatusCode::FORBIDDEN),
            "a patch is answered with all of it"
        );
        // What is there and what is not are the same to who may not ask.
        let eve = call("eve");
        for name in ["kept", "nothing"] {
            let done = write(&eve, secrets, Some("default"), Some(name), patch, label()).await;
            assert_eq!(code(done), Some(StatusCode::FORBIDDEN), "{name}");
            let gone = delete(&eve, secrets, Some("default"), name, &json!({})).await;
            assert_eq!(gone.err().map(|no| no.code), Some(StatusCode::FORBIDDEN), "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_strategic_patch_merges_lists_by_name_and_a_merge_patch_replaces_them() {
        let live = json!({ "spec": { "replicas": 2, "template": { "spec": { "containers": [
            { "name": "web", "image": "nginx:1", "env": [{ "name": "A", "value": "1" }, { "name": "B", "value": "2" }] },
            { "name": "side", "image": "busybox" },
        ] } } } });
        let patch = json!({ "spec": { "replicas": null, "template": { "spec": {
            "$setElementOrder/containers": [{ "name": "side" }, { "name": "web" }],
            "containers": [
                { "name": "web", "image": "nginx:2", "env": [{ "name": "A", "$patch": "delete" }, { "name": "C", "value": "3" }] },
            ],
        } } } });
        let mut strategic = live.clone();
        patched(&mut strategic, patch.clone(), true);
        let want = json!({ "spec": { "template": { "spec": { "containers": [
            { "name": "side", "image": "busybox" },
            { "name": "web", "image": "nginx:2", "env": [{ "name": "B", "value": "2" }, { "name": "C", "value": "3" }] },
        ] } } } });
        assert_eq!(strategic, want);
        let mut merge = live.clone();
        patched(
            &mut merge,
            json!({ "spec": { "template": { "spec": { "containers": [{ "name": "one" }] } } } }),
            false,
        );
        assert_eq!(
            merge["spec"]["template"]["spec"]["containers"],
            json!([{ "name": "one" }])
        );
        assert_eq!(merge["spec"]["replicas"], 2);
        // What a client sends is never trusted to be the shape it should: none of these panics.
        for odd in [
            json!([1]),
            json!("x"),
            json!({ "spec": [{ "$patch": "replace" }] }),
            json!({ "$retainKeys": 3 }),
        ] {
            patched(&mut live.clone(), odd.clone(), true);
            patched(&mut json!(7), odd, true);
        }
    }

    #[test]
    fn selectors_pick_by_labels_and_fields() {
        let object = json!({ "metadata": { "name": "web", "labels": { "app": "shop", "tier": "front" } }, "status": { "phase": "Running" } });
        let picks = |labels: &str, fields: &str| {
            let asked = [("labelSelector", labels), ("fieldSelector", fields)];
            selected(
                &object,
                &asked.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            )
        };
        for yes in [
            "",
            "app=shop",
            "app==shop,tier!=back",
            "app in (shop, bank),tier",
            "!gone,app notin (bank)",
        ] {
            assert!(picks(yes, ""), "{yes}");
        }
        for no in ["app=bank", "gone", "!app", "app notin (shop)", "tier in (back)"] {
            assert!(!picks(no, ""), "{no}");
        }
        assert!(picks("", "metadata.name=web,status.phase!=Pending"));
        assert!(!picks("", "metadata.name=other"));
    }

    /// `kubectl logs job/NAME` after `kubectl wait --for=condition=complete`: the Job runs
    /// nothing any more, and its pod is still there to be asked what it wrote.
    #[test]
    fn a_job_that_is_over_still_has_the_pods_of_its_runs() {
        let job = json!({
            "kind": "Job", "metadata": { "name": "ask", "namespace": "default" },
            "spec": { "template": { "spec": { "containers": [{ "name": "ask", "image": "a" }] } } },
        });
        let held = |status: Value| -> Resource {
            let meta = json!({ "name": "ask", "namespace": "default" });
            serde_json::from_value(json!({
                "apiVersion": "kith.dev/v1", "kind": "Job", "metadata": meta, "spec": {}, "status": status,
            }))
            .unwrap()
        };
        let nodes = json!({ "0": "n2" });
        let said = |status: Value| -> Vec<(Value, Value, Value)> {
            let pods = pods(&job, &held(status));
            let of = |pod: &Value| {
                assert_eq!(pod["metadata"]["labels"]["job-name"], "ask", "{pod}");
                let code = &pod["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"];
                (
                    pod["metadata"]["name"].clone(),
                    pod["status"]["phase"].clone(),
                    code.clone(),
                )
            };
            pods.iter().map(of).collect()
        };
        let running = json!({ "state": "running", "succeeded": 0, "containers": [], "nodes": nodes });
        assert!(said(running).is_empty());
        let done = json!({ "state": "succeeded", "succeeded": 1, "containers": [], "nodes": nodes });
        assert_eq!(said(done.clone()), [("ask-0".into(), "Succeeded".into(), 0.into())]);
        assert_eq!(pods(&job, &held(done))[0]["spec"]["nodeName"], "n2");
        let failed = json!({ "state": "failed", "succeeded": 1, "failed": 1, "containers": [], "nodes": nodes });
        assert_eq!(
            said(failed),
            [
                ("ask-0".into(), "Succeeded".into(), 0.into()),
                ("ask-1".into(), "Failed".into(), Value::Null)
            ]
        );
    }

    #[test]
    fn a_time_is_read_back_and_a_name_kith_cannot_hold_is_hashed() {
        for at in [0, 951_782_400, 1_709_251_199, 1_794_614_400] {
            assert_eq!(seconds(&rfc3339(at)), Some(at));
        }
        assert_eq!(seconds("not a time"), None);
        let roles = KINDS.iter().find(|kind| kind.plural == "clusterroles").unwrap();
        assert_eq!(kept_name(roles, "reader"), "clusterroles.reader");
        let hashed = kept_name(roles, "system:reader");
        assert!(hashed.len() == 45 && !hashed.contains(':'), "{hashed}");
        assert_ne!(hashed, kept_name(roles, "system:writer"));
    }
}
