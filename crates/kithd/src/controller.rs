//! The Workload controller: makes the containers on this node match the
//! `Workload`s in the store, restarts them when they exit, and reports what it
//! sees in each Workload's status.
//!
// ponytail: one node and containers only. Not handled yet, each said so in the
// status where it matters: `exec` units, volumes, ports (containers share the
// host's network), probes (ready means running), rolling updates (a changed
// Workload is stopped, then started) and restarting on a changed Secret or
// ConfigMap. Images are pulled one at a time.

use crate::Shared;
use kith_api::kinds::{ConfigMapSpec, Container, EnvVar, PullPolicy, RestartPolicy, SecretSpec, WorkloadSpec};
use kith_runtime::{Handle, Runtime, Unit};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

/// How long a container must have run for its next restart to be immediate again.
const SETTLED: Duration = Duration::from_secs(60);
/// With nothing else to wake it, the controller still looks around this often.
const TICK: Duration = Duration::from_secs(10);

/// One container of one replica of one Workload.
struct Slot {
    /// Store key of the Workload.
    workload: String,
    namespace: String,
    replica: u32,
    container: Container,
    policy: RestartPolicy,
    handle: Option<Handle>,
    state: &'static str,
    restarts: u32,
    /// Failures in a row, for the backoff.
    failures: u32,
    exit_code: Option<i32>,
    message: Option<String>,
    started: Instant,
    /// When to (re)start it; `None` when it is running or done for good.
    start_at: Option<Instant>,
}

pub async fn run(
    shared: std::sync::Arc<Shared>,
    runtime: kith_runtime::Result<Runtime>,
    logs: PathBuf,
    mut stopping: watch::Receiver<bool>,
) {
    let runtime = match runtime.and_then(|rt| rt.cleanup().map(|old| (rt, old))) {
        Ok((runtime, old)) => {
            if old > 0 {
                eprintln!("kithd: removed {old} container(s) left by an earlier run");
            }
            runtime
        }
        Err(e) => {
            // The API still works, so resources can be inspected and edited.
            eprintln!("kithd: workloads will not run: {e}");
            let _ = stopping.changed().await;
            return;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&logs) {
        eprintln!("kithd: creating {}: {e}", logs.display());
    }
    let mut exited = signal(SignalKind::child()).expect("installing a signal handler");
    let mut slots: BTreeMap<String, Slot> = BTreeMap::new();
    loop {
        let wake = reconcile(&shared, &runtime, &logs, &mut slots, &stopping).await;
        tokio::select! {
            _ = shared.changed.notified() => {}
            _ = exited.recv() => {}
            _ = tokio::time::sleep(wake) => {}
            _ = stopping.changed() => break,
        }
    }
    for (id, slot) in slots {
        stop(&id, slot.handle);
    }
}

fn stop(id: &str, handle: Option<Handle>) {
    if let Some(Err(e)) = handle.map(Handle::delete) {
        eprintln!("kithd: {id}: {e}");
    }
}

/// `1s, 2s, 4s … 60s`.
fn backoff(failures: u32) -> Duration {
    Duration::from_secs(1 << failures.min(6)).min(Duration::from_secs(60))
}

/// Ids become file and cgroup names. `_` cannot appear in a resource name, so it separates the parts.
fn container_id(namespace: &str, workload: &str, replica: u32, container: &str) -> Result<String, String> {
    let ok = !container.is_empty()
        && container
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    match ok {
        true => Ok(format!("{namespace}_{workload}_{replica}_{container}")),
        false => Err(format!(
            "container name `{container}`: use letters, digits, `-` and `.`"
        )),
    }
}

/// One pass: returns how long the controller may sleep if nothing happens.
async fn reconcile(
    shared: &Shared,
    runtime: &Runtime,
    logs: &Path,
    slots: &mut BTreeMap<String, Slot>,
    stopping: &watch::Receiver<bool>,
) -> Duration {
    // 1. What should run, from a snapshot of the store.
    let workloads: Vec<_> = {
        let file_store = shared.store.lock().expect("a handler panicked holding the store");
        file_store.store.list(Some("Workload")).cloned().collect()
    };
    let mut wanted: BTreeMap<String, Slot> = BTreeMap::new();
    // Per Workload key: things to say in its status that belong to no container.
    let mut notes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for resource in workloads {
        let key = resource.key();
        let note = notes.entry(key.clone()).or_default();
        let spec: WorkloadSpec = match serde_json::from_value(resource.spec) {
            Ok(spec) => spec,
            Err(e) => {
                note.push(format!("cannot read this Workload: {e}"));
                continue;
            }
        };
        let meta = resource.metadata;
        if !spec.template.exec.is_empty() {
            note.push("exec units are not run yet".into());
        }
        let namespace = meta.namespace.unwrap_or_default();
        for replica in 0..spec.replicas.unwrap_or(1) {
            for container in &spec.template.containers {
                if !container.volume_mounts.is_empty() && replica == 0 {
                    note.push(format!("{}: volumes are not mounted yet", container.name));
                }
                match container_id(&namespace, &meta.name, replica, &container.name) {
                    Err(e) => note.push(e),
                    Ok(id) => drop(wanted.insert(
                        id,
                        Slot {
                            workload: key.clone(),
                            namespace: namespace.clone(),
                            replica,
                            container: container.clone(),
                            policy: spec.template.restart_policy.clone().unwrap_or(RestartPolicy::Always),
                            handle: None,
                            state: "pending",
                            restarts: 0,
                            failures: 0,
                            exit_code: None,
                            message: None,
                            started: Instant::now(),
                            start_at: Some(Instant::now()),
                        },
                    )),
                }
            }
        }
    }

    // 2. Stop what is no longer wanted, or whose own definition changed. Scaling or
    // relabelling a Workload leaves its running containers alone.
    let stale: Vec<String> = slots
        .iter()
        .filter(|(id, slot)| {
            wanted
                .get(*id)
                .is_none_or(|w| w.container != slot.container || w.policy != slot.policy)
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in stale {
        stop(&id, slots.remove(&id).and_then(|slot| slot.handle));
    }
    for (id, slot) in wanted {
        slots.entry(id).or_insert(slot);
    }

    // 3. Notice exits, then start whatever is due.
    for (id, slot) in slots.iter_mut() {
        if *stopping.borrow() {
            return TICK; // the caller stops everything
        }
        if let Some(handle) = &mut slot.handle {
            let code = match handle.try_wait() {
                Ok(None) => continue,
                Ok(Some(code)) => code,
                Err(e) => {
                    slot.message = Some(e.to_string());
                    -1
                }
            };
            stop(id, slot.handle.take());
            slot.exit_code = Some(code);
            slot.failures = if slot.started.elapsed() >= SETTLED {
                0
            } else {
                slot.failures + 1
            };
            let again = match slot.policy {
                RestartPolicy::Always => true,
                RestartPolicy::OnFailure => code != 0,
                RestartPolicy::Never => false,
            };
            slot.state = if again { "waiting" } else { "exited" };
            slot.start_at = again.then(|| Instant::now() + backoff(slot.failures.saturating_sub(1)));
            if again {
                slot.restarts += 1;
            }
        }
        if slot.start_at.is_some_and(|at| at <= Instant::now()) {
            let mut stop_now = stopping.clone();
            let started = tokio::select! {
                started = start(shared, runtime, logs, id, slot) => started,
                // A pull can take minutes; shutting down does not wait for it.
                _ = stop_now.changed() => return TICK,
            };
            // A cached image starts without ever waiting; let the API answer between starts.
            tokio::task::yield_now().await;
            match started {
                Ok(handle) => {
                    slot.handle = Some(handle);
                    (slot.state, slot.message, slot.start_at, slot.started) = ("running", None, None, Instant::now());
                }
                Err(message) => {
                    (slot.state, slot.message) = ("failed", Some(message));
                    slot.start_at = Some(Instant::now() + backoff(slot.failures));
                    slot.failures += 1;
                }
            }
        }
    }

    // 4. Report.
    let mut file_store = shared.store.lock().expect("a handler panicked holding the store");
    let mut dirty = false;
    for (key, notes) in notes {
        let mine: Vec<&Slot> = slots.values().filter(|slot| slot.workload == key).collect();
        let replicas = mine.iter().map(|slot| slot.replica + 1).max().unwrap_or(0);
        let ready = (0..replicas)
            .filter(|r| mine.iter().filter(|s| s.replica == *r).all(|s| s.state == "running"))
            .count();
        let containers: Vec<Value> = mine
            .iter()
            .map(|slot| {
                let mut c = json!({ "name": slot.container.name, "replica": slot.replica, "state": slot.state, "restarts": slot.restarts });
                if let Some(code) = slot.exit_code {
                    c["exitCode"] = json!(code);
                }
                if let Some(message) = &slot.message {
                    c["message"] = json!(message);
                }
                c
            })
            .collect();
        let mut status = json!({ "replicas": replicas, "ready": ready, "containers": containers });
        if !notes.is_empty() {
            status["notes"] = json!(notes);
        }
        // The Workload may have been deleted while this pass ran; the next pass stops its containers.
        if file_store
            .store
            .get(&key)
            .is_some_and(|live| live.status.as_ref() != Some(&status))
        {
            dirty |= file_store.store.set_status(&key, Some(status)).is_ok();
        }
    }
    if dirty {
        shared.bump();
    }
    if dirty && let Err(e) = file_store.save() {
        eprintln!("kithd: saving status: {e}");
    }

    let next = slots.values().filter_map(|slot| slot.start_at).min();
    next.map_or(TICK, |at| at.saturating_duration_since(Instant::now()).min(TICK))
}

/// The value of one environment variable, looked up in the store if it is a reference.
fn env_value(shared: &Shared, namespace: &str, var: &EnvVar) -> Result<String, String> {
    if let Some(value) = &var.value {
        return Ok(value.clone());
    }
    let (kind, key_ref) = match (&var.secret, &var.config_map) {
        (Some(key_ref), _) => ("Secret", key_ref),
        (_, Some(key_ref)) => ("ConfigMap", key_ref),
        _ => return Err(format!("env `{}` has no value", var.name)),
    };
    let key = format!("{kind}/{namespace}/{}", key_ref.name);
    let file_store = shared.store.lock().expect("a handler panicked holding the store");
    let spec = file_store
        .store
        .get(&key)
        .map(|r| r.spec.clone())
        .ok_or(format!("env `{}`: {key} does not exist", var.name))?;
    // Both kinds are `data: {key: value}`.
    let data = match kind {
        "Secret" => serde_json::from_value::<SecretSpec>(spec).map(|s| s.data),
        _ => serde_json::from_value::<ConfigMapSpec>(spec).map(|s| s.data),
    };
    let mut data = data.map_err(|e| format!("env `{}`: {key}: {e}", var.name))?;
    data.remove(&key_ref.key)
        .ok_or(format!("env `{}`: {key} has no key `{}`", var.name, key_ref.key))
}

async fn start(shared: &Shared, runtime: &Runtime, logs: &Path, id: &str, slot: &Slot) -> Result<Handle, String> {
    let c = &slot.container;
    let mut unit = Unit {
        command: c.command.clone(),
        args: c.args.clone(),
        working_dir: c.working_dir.clone(),
        ..Unit::default()
    };
    for var in &c.env {
        unit.env
            .push((var.name.clone(), env_value(shared, &slot.namespace, var)?));
    }
    if let Some(resources) = &c.resources {
        unit.memory_bytes = resources.memory.as_ref().map(|q| q.value() as u64);
        unit.cpu_millis = resources.cpu.as_ref().map(|q| (q.value() * 1000.0).round() as u64);
    }
    let policy = match c.pull_policy {
        None | Some(PullPolicy::IfNotPresent) => kith_runtime::PullPolicy::IfNotPresent,
        Some(PullPolicy::Always) => kith_runtime::PullPolicy::Always,
        Some(PullPolicy::Never) => kith_runtime::PullPolicy::Never,
    };
    let image = runtime.images.pull(&c.image, policy).await.map_err(|e| e.to_string())?;
    let log = |ext: &str| {
        let path = logs.join(format!("{id}.{ext}"));
        File::options()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("opening {}: {e}", path.display()))
    };
    let mut handle = runtime
        .create(id, &image, &unit, log("out")?, log("err")?)
        .map_err(|e| e.to_string())?;
    match handle.start() {
        Ok(()) => Ok(handle),
        Err(e) => {
            stop(id, Some(handle));
            Err(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_backoff() {
        assert_eq!(
            container_id("default", "web.v2", 1, "app").unwrap(),
            "default_web.v2_1_app"
        );
        for bad in ["", "a/b", "..\\x", "a_b", "a b"] {
            assert!(container_id("default", "web", 0, bad).is_err(), "{bad:?}");
        }
        assert_eq!(backoff(0), Duration::from_secs(1));
        assert_eq!(backoff(3), Duration::from_secs(8));
        assert_eq!(backoff(40), Duration::from_secs(60));
    }
}
