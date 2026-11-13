//! What a `KindDefinition`'s WASM modules are run for (PLAN.md 4.10). Both are plain
//! functions over JSON, run in `wasm.rs`'s sandbox:
//!
//! - **admission** (`kith_admit`), before a resource of the kind is written, on the node
//!   that takes the write: given `{resource, old}`, it answers `null` (as it is), the
//!   resource changed (its spec, labels and annotations), or an error: the refusal.
//!   Every apply passes here ([`Shared::admitted`], from `submit`): the API's, a
//!   Source's, a Release's, a controller's. A module that fails refuses the write; the
//!   `KindDefinition` itself is never asked about, so a bad module can be replaced.
//! - **controller** (`kith_reconcile`), on the node that leads the store, whenever a
//!   resource of the kind, the module or something the resource owns changes: given
//!   `{resource, owned}`, it answers `{status, resources}`. The resources are applied
//!   as the resource's own (in its namespace, annotated like a Release's, removed when
//!   no longer answered and when their owner goes) and the status fields are recorded,
//!   with `resources` (what it owns) and `controller` (how the last run went).
//
// ponytail: a delete is not asked about; a rollback is asked, but comes back as it was. A module sees one resource and what it owns: one that has
// to look further is a Workload on the watch API.

use crate::releases::{self, OWNER, Step};
use crate::{Shared, wasm};
use base64::Engine;
use kith_api::Resource;
use kith_api::store::{Error, Store};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// The module a definition carries for `role` (`controller`, `admission`), if any.
fn module(definition: &Resource, role: &str) -> Option<Result<Vec<u8>, String>> {
    let text = definition.spec[role]["wasm"].as_str()?;
    let read = base64::engine::general_purpose::STANDARD.decode(text);
    Some(read.map_err(|e| format!("{role}.wasm is not base64: {e}")))
}

/// What to ask a module, worked out under the store's lock and run outside it.
enum Check {
    /// Is this a module at all? (Of a `KindDefinition` being applied.)
    Module(String, Vec<u8>),
    /// May `resources[at]` be written?
    Admit { at: usize, wasm: Vec<u8>, input: Value },
}

fn checks(store: &Store, resources: &mut [Resource]) -> Result<Vec<Check>, String> {
    let mut checks = Vec::new();
    for at in 0..resources.len() {
        if resources[at].kind == "KindDefinition" {
            for role in ["controller", "admission"] {
                if let Some(wasm) = module(&resources[at], role) {
                    checks.push(Check::Module(format!("{}: {role}", resources[at].key()), wasm?));
                }
            }
            continue;
        }
        if kith_api::kind(&resources[at].kind).is_some() {
            continue;
        }
        // The definition as it will be: one that comes in the same apply counts.
        let kind = resources[at].kind.clone();
        let coming = |other: &&Resource| other.kind == "KindDefinition" && other.spec["kind"] == kind.as_str();
        let definition = resources[..at].iter().rfind(coming).or_else(|| store.definition(&kind));
        let Some((definition, wasm)) = definition.and_then(|d| Some((d, module(d, "admission")?))) else {
            continue;
        };
        let wasm = wasm.map_err(|e| format!("{}: {e}", definition.key()))?;
        // (As the store will have it, so that the module sees where the resource is.)
        let namespaced = definition.spec["namespaced"] != false;
        let resource = &mut resources[at];
        if namespaced && resource.metadata.namespace.is_none() {
            resource.metadata.namespace = Some(kith_api::DEFAULT_NAMESPACE.into());
        }
        let input = json!({ "resource": resource, "old": store.get(&resource.key()) });
        checks.push(Check::Admit { at, wasm, input });
    }
    Ok(checks)
}

/// What the module made of `resource`: only its spec, labels and annotations are its to change.
fn changed(resource: &Resource, answer: Value) -> Result<Resource, String> {
    let mut changed: Resource =
        serde_json::from_value(answer).map_err(|e| format!("what it answered is not the resource: {e}"))?;
    let what = |r: &Resource| {
        (
            r.api_version.clone(),
            r.kind.clone(),
            r.metadata.name.clone(),
            r.metadata.namespace.clone(),
        )
    };
    if what(&changed) != what(resource) {
        return Err("it may change the spec, labels and annotations, not which resource this is".into());
    }
    changed.metadata.revision = resource.metadata.revision;
    changed.status = None;
    Ok(changed)
}

impl Shared {
    /// `resources` as their kinds' admission modules let them be written, or the refusal.
    pub async fn admitted(&self, mut resources: Vec<Resource>) -> Result<Vec<Resource>, Error> {
        let checks = {
            let state = self.store.lock().expect("a handler panicked holding the store");
            checks(&state.store, &mut resources).map_err(Error::Invalid)?
        };
        // (Nearly every apply: nothing to ask, and no thread to ask it on.)
        if checks.is_empty() {
            return Ok(resources);
        }
        let asked = self.wasm.run(move |modules| {
            for check in checks {
                match check {
                    Check::Module(of, wasm) => {
                        modules.module(&wasm).map_err(|e| format!("{of}.wasm: {e}"))?;
                    }
                    Check::Admit { at, wasm, input } => {
                        let resource = &resources[at];
                        let refused =
                            |e: String| format!("{}: refused by {}'s admission: {e}", resource.key(), resource.kind);
                        match modules.call(&wasm, "kith_admit", &input).map_err(refused)? {
                            Value::Null => {}
                            answer => resources[at] = changed(resource, answer).map_err(refused)?,
                        }
                    }
                }
            }
            Ok(resources)
        });
        asked.await.and_then(|asked| asked).map_err(Error::Invalid)
    }

    /// May revision `to` of `key` come back? Its kind's admission is asked as for an apply;
    /// what it would change is not changed (a rollback restores what was), what it refuses is.
    pub async fn restorable(&self, key: &str, to: u64) -> Result<(), Error> {
        let was = {
            let state = self.store.lock().expect("a handler panicked holding the store");
            let history = state.store.history(key).unwrap_or_default();
            let was = history.iter().find(|was| was.resource.metadata.revision == Some(to));
            was.map(|was| was.resource.clone())
        };
        match was {
            // (A KindDefinition's own modules ran when they were set: it comes back as it was.)
            Some(was) if was.kind != "KindDefinition" => self.admitted(vec![was]).await.map(drop),
            // (No such revision: the store says so.)
            _ => Ok(()),
        }
    }
}

/// What a run answered for: the resource's revision, the module, and the revision of
/// each thing it owns. The same again is not asked again.
type Stamp = (releases::Stamp, [u8; 32], Vec<(String, Option<u64>)>);

struct Job {
    key: String,
    stamp: Stamp,
    wasm: Vec<u8>,
    input: Value,
}

/// The runs that are due: resources of a kind with a controller, not yet asked about as they are.
fn due(store: &Store, seen: &BTreeMap<String, Stamp>) -> Vec<Job> {
    let mut jobs = Vec::new();
    for definition in store.list(Some("KindDefinition")) {
        // (A module that is not base64 was refused when it was applied through kithd.)
        let Some(Ok(wasm)) = module(definition, "controller") else {
            continue;
        };
        let digest = wasm::digest(&wasm);
        for resource in store.list(definition.spec["kind"].as_str()) {
            let key = resource.key();
            let recorded = releases::recorded(resource);
            let mine = |owned: &&Resource| releases::owner(owned) == Some(key.as_str());
            let owned = recorded.iter().filter_map(|owned| store.get(owned));
            let owned: Vec<&Resource> = owned.filter(mine).collect();
            let revision = |owned: &&str| {
                let revision = store.get(owned).and_then(|owned| owned.metadata.revision);
                (owned.to_string(), revision)
            };
            let stamp = (
                // (With when it was applied: one deleted and made again is not the same one.)
                releases::stamp(store, resource),
                digest,
                recorded.iter().map(revision).collect(),
            );
            if seen.get(&key) != Some(&stamp) {
                let input = json!({ "resource": resource, "owned": owned });
                jobs.push(Job {
                    key,
                    stamp,
                    wasm: wasm.clone(),
                    input,
                });
            }
        }
    }
    jobs
}

/// What a controller may not make: what installs things, and kinds themselves.
const KEPT: [&str; 3] = ["Release", "Source", "KindDefinition"];
/// The most resources one resource's controller may answer.
const ANSWERED: usize = 64;

/// The resources a controller answered, as `owner`'s own: in its namespace, marked.
fn desired(store: &Store, owner: &Resource, answer: &Value) -> Result<Vec<Resource>, String> {
    let mut resources = Vec::new();
    let answered = answer["resources"].as_array().map_or(&[][..], Vec::as_slice);
    if answered.len() > ANSWERED {
        return Err(format!("it answered {} resources: {ANSWERED} at most", answered.len()));
    }
    for resource in answered {
        let mut resource: Resource =
            serde_json::from_value(resource.clone()).map_err(|e| format!("a resource it answered: {e}"))?;
        let namespaced = match kith_api::kind(&resource.kind) {
            Some(kind) => kind.namespaced,
            None => store
                .definition(&resource.kind)
                .is_some_and(|definition| definition.spec["namespaced"] != false),
        };
        if !namespaced || KEPT.contains(&resource.kind.as_str()) {
            return Err(format!("a controller cannot make a {}", resource.kind));
        }
        if (resource.kind.as_str(), resource.metadata.name.as_str()) == ("ConfigMap", releases::SHARED) {
            return Err("a controller does not get to set the values releases are given".into());
        }
        let home = owner.metadata.namespace.clone();
        let home = home.unwrap_or_else(|| kith_api::DEFAULT_NAMESPACE.into());
        // (One that is in no namespace itself may say where; any other makes things where it is.)
        let asked = resource.metadata.namespace.get_or_insert_with(|| home.clone());
        if owner.metadata.namespace.is_some() && *asked != home {
            return Err(format!(
                "{} would be in namespace {asked}: a controller makes things in its resource's own, {home}",
                resource.kind
            ));
        }
        resource.metadata.annotations.insert(OWNER.into(), owner.key());
        resource.status = None;
        resources.push(resource);
    }
    Ok(resources)
}

/// What to do to the store for one run's answer. `None`: the resource is gone.
fn step(store: &Store, key: &str, answered: Result<Value, String>) -> Option<Step> {
    let owner = store.get(key)?;
    let mut step = Step {
        release: key.to_string(),
        apply: Vec::new(),
        delete: Vec::new(),
        status: None,
    };
    let done = answered.and_then(|answer| {
        let resources = desired(store, owner, &answer)?;
        let done = releases::reconcile(store, key, &releases::recorded(owner), &resources, true)?;
        Ok((answer, done))
    });
    let revision = owner.metadata.revision;
    let mut status = Map::new();
    match done {
        // (What it made before stays as it is.)
        Err(e) => {
            let said = json!({ "state": "error", "message": e, "observedRevision": revision });
            status.insert("controller".into(), said);
        }
        Ok((answer, done)) => {
            if let Some(Value::Object(fields)) = answer.get("status") {
                status.extend(fields.clone());
            }
            let kept: Vec<&String> = done.kept.iter().collect();
            status.insert("resources".into(), json!(kept));
            status.insert(
                "controller".into(),
                json!({ "state": "ok", "observedRevision": revision }),
            );
            (step.apply, step.delete) = (done.apply, done.delete);
        }
    }
    // Said once: a status written again would wake every watcher for nothing.
    let live = owner.status.as_ref();
    let news = status
        .iter()
        .any(|(field, value)| live.and_then(|live| live.get(field)) != Some(value));
    step.status = news.then_some(status);
    Some(step)
}

/// Do what the runs asked for. What cannot be applied (an admission module's refusal,
/// say) is said in the resource's status like any other failure of its controller.
/// (What a resource that is gone owned goes with the Releases' leftovers.)
/// Returns the resources whose run has to be made again.
async fn carry_out(shared: &Shared, steps: Vec<Step>) -> Vec<String> {
    use kith_store::Command;
    let (mut statuses, mut again) = (Vec::new(), Vec::new());
    for step in steps {
        let mut status = step.status;
        let mut done = Ok(());
        if !step.apply.is_empty() {
            let (resources, at) = (step.apply, kith_api::store::now());
            done = shared.submit(Command::Apply { resources, at }).await.map(drop);
        }
        for key in step.delete {
            if done.is_ok() {
                done = match shared.submit(Command::Delete { key }).await {
                    Ok(_) | Err(Error::NotFound(_)) => Ok(()),
                    Err(e) => Err(e),
                };
            }
        }
        if let Err(e) = done {
            // The store could not take it just now: that says nothing of the answer. Asked again later.
            if matches!(e, Error::Io(_)) {
                again.push(step.release);
                continue;
            }
            let said = json!({ "state": "error", "message": e.to_string() });
            status = Some(Map::from_iter([("controller".to_string(), said)]));
        }
        statuses.extend(status.map(|status| (step.release, status)));
    }
    if !statuses.is_empty()
        && let Err(e) = shared.submit(Command::Patch { statuses }).await
    {
        eprintln!("kithd: controllers: {e}");
    }
    again
}

/// Run the controllers, as long as this node leads the store, until told to stop.
pub async fn run(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let mut seen: BTreeMap<String, Stamp> = BTreeMap::new();
    let mut generation = shared.generation.subscribe();
    loop {
        let metrics = shared.raft.metrics().borrow().clone();
        if metrics.current_leader == Some(metrics.id) {
            let jobs = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                seen.retain(|key, _| state.store.get(key).is_some());
                due(&state.store, &seen)
            };
            let mut steps = Vec::new();
            // (One at a time, off the threads everything else waits on: a module is someone else's code.)
            for job in jobs {
                let (wasm, input) = (job.wasm, job.input);
                let answered = shared
                    .wasm
                    .run(move |modules| modules.call(&wasm, "kith_reconcile", &input));
                let answered = answered.await.and_then(|answered| answered);
                let state = shared.store.lock().expect("nothing panics holding the store");
                steps.extend(step(&state.store, &job.key, answered));
                seen.insert(job.key, job.stamp);
            }
            for key in carry_out(&shared, steps).await {
                seen.remove(&key);
            }
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = stopping.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(source: &str) -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        store
    }

    const KIND: &str = "apiVersion: kith.dev/v1\nkind: KindDefinition\nmetadata: { name: gameserver }\n\
        spec: { group: games.example.com, version: v1, kind: GameServer, schema: { type: object } }\n---\n\
        apiVersion: games.example.com/v1\nkind: GameServer\nmetadata: { name: one, namespace: play }\nspec: { map: dust }\n";

    #[test]
    fn wasm_controller_answers_become_owned_resources() {
        let mut store = store(KIND);
        let key = "GameServer/play/one";
        let map = |name: &str, namespace: Option<&str>| {
            json!({ "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
                "metadata": { "name": name, "namespace": namespace }, "spec": { "data": { "map": "dust" } } })
        };
        let answer = json!({ "status": { "state": "ready" }, "resources": [map("one-config", None)] });
        let first = step(&store, key, Ok(answer.clone())).unwrap();
        // In the owner's namespace, marked as its own; the status says what it owns and how it went.
        assert_eq!(first.apply.len(), 1);
        assert_eq!(first.apply[0].key(), "ConfigMap/play/one-config");
        assert_eq!(first.apply[0].metadata.annotations[OWNER], key);
        let status = first.status.clone().unwrap();
        assert_eq!(status["state"], "ready");
        assert_eq!(status["resources"], json!(["ConfigMap/play/one-config"]));
        assert_eq!(status["controller"]["state"], "ok");

        // Done: the same answer asks for nothing more.
        store.apply(first.apply[0].clone()).unwrap();
        store.set_status(key, Some(status.into())).unwrap();
        let again = step(&store, key, Ok(answer)).unwrap();
        assert!(again.apply.is_empty() && again.delete.is_empty() && again.status.is_none());

        // Not a controller's to make: the values releases are given, or things without end.
        for (bad, why) in [
            (vec![map("kith-values", None)], "the values releases are given"),
            (vec![map("many", None); ANSWERED + 1], "at most"),
        ] {
            let refused = step(&store, key, Ok(json!({ "resources": bad }))).unwrap();
            let said = refused.status.unwrap()["controller"]["message"].to_string();
            assert!(refused.apply.is_empty() && said.contains(why), "{said}");
        }

        // No longer answered: it goes. A failure: said, and nothing touched.
        let none = step(&store, key, Ok(json!({ "resources": [] }))).unwrap();
        assert_eq!(none.delete, ["ConfigMap/play/one-config"]);
        let failed = step(&store, key, Err("out of fuel".into())).unwrap();
        assert!(failed.apply.is_empty() && failed.delete.is_empty());
        assert_eq!(failed.status.unwrap()["controller"]["message"], "out of fuel");

        // Not elsewhere, not what is in no namespace, not what installs things, not someone else's.
        for (resource, why) in [
            (map("x", Some("other")), "in its resource's own"),
            (
                json!({ "apiVersion": "kith.dev/v1", "kind": "Namespace", "metadata": { "name": "x" }, "spec": {} }),
                "cannot make a Namespace",
            ),
        ] {
            let said = step(&store, key, Ok(json!({ "resources": [resource] }))).unwrap();
            let said = said.status.unwrap()["controller"]["message"].to_string();
            assert!(said.contains(why), "{said}");
        }
        store
            .apply(serde_json::from_value(map("taken", Some("play"))).unwrap())
            .unwrap();
        let said = step(&store, key, Ok(json!({ "resources": [map("taken", None)] }))).unwrap();
        let said = said.status.unwrap()["controller"]["message"].to_string();
        assert!(said.contains("is there already"), "{said}");
        assert!(step(&store, "GameServer/play/gone", Err("x".into())).is_none());
    }

    #[test]
    fn wasm_admission_keeps_the_resource_what_it_is() {
        let store = store(KIND);
        let resource = store.get("GameServer/play/one").unwrap();
        let mut answer = serde_json::to_value(resource).unwrap();
        answer["spec"]["players"] = 8.into();
        let new = changed(resource, answer.clone()).unwrap();
        assert_eq!(
            (new.spec["players"].as_u64(), new.metadata.revision),
            (Some(8), resource.metadata.revision)
        );
        answer["metadata"]["name"] = "two".into();
        assert!(changed(resource, answer).unwrap_err().contains("not which resource"));
        assert!(
            changed(resource, json!("yes"))
                .unwrap_err()
                .contains("not the resource")
        );
    }
}
