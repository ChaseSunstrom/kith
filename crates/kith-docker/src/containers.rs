//! Docker's containers as kith resources (T-1258): `docker run -d`, `ps`, `inspect`, `stop`, `start`,
//! `restart`, `kill`, `rm` and `wait` against them. A container is a Workload, or a Job when its
//! restart policy is `no` or `on-failure`, in namespace `docker`, labelled `kith.dev/docker=NAME`.
//! A created container is a Workload at zero replicas until it starts; a stopped one stays one.
//! Nothing here reads or writes kithd directly: the store is the seam (the CLI implements it).

use super::stream::{Carrier, Event, Input, Kind, LogFrom, Session, Writer};
use super::{Clocked, Reply, broken, container_id, hung_up, json_reply, message, sha256_hex};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use super::stream::LogChunk;

pub const NAMESPACE: &str = "docker";
pub const LABEL: &str = "kith.dev/docker";

/// The resources a container is made of, as their JSON documents (`apiVersion`, `kind`,
/// `metadata`, `spec`, `status`). `key` is "Kind/namespace/name".
pub trait Store: Send + Sync {
    /// The document at `key`, status included, or None.
    fn get(&self, key: &str) -> Result<Option<Value>, String>;
    /// Every document of `kind` in `namespace`.
    fn list(&self, kind: &str, namespace: &str) -> Result<Vec<Value>, String>;
    /// Create the document, or replace the one with its key (its metadata and spec).
    fn apply(&self, doc: Value) -> Result<(), String>;
    /// Remove the document at `key`, if there is one.
    fn delete(&self, key: &str) -> Result<(), String>;
    /// What the container at `key` (its first unit, its first copy) wrote to stdout, or to stderr,
    /// from `from`: at most a chunk of it; empty when nothing more is written yet.
    fn logs(&self, key: &str, stderr: bool, from: LogFrom) -> Result<LogChunk, String> {
        let _ = (key, stderr, from);
        Err("this store keeps no logs".into())
    }
    /// Run `command` in the pod `pod`, with a terminal when `tty`, and with stdin when `stdin`.
    fn exec(&self, pod: &str, command: &[String], tty: bool, stdin: bool) -> Result<Session, String> {
        let _ = (pod, command, tty, stdin);
        Err("this store cannot run a command in a container".into())
    }
}

/// An exec the client made and may start, and what became of it.
struct Exec {
    container: String,
    pod: String,
    command: Vec<String>,
    tty: bool,
    stdin: bool,
    started: bool,
    exit: Option<i64>,
    /// A window size told before the command was running.
    size: Option<(u16, u16)>,
    /// The way to the running command, for the window.
    input: Option<mpsc::Sender<Input>>,
}

/// The execs a front remembers at most (the ones that ended go first).
const MAX_EXECS: usize = 1024;

/// The container calls, answered from a store.
pub struct Containers {
    store: Box<dyn Store>,
    /// One change at a time (create, start, stop, remove): a name is checked and then taken.
    lock: Mutex<()>,
    execs: Mutex<HashMap<String, Exec>>,
    made: AtomicU64,
}

impl Containers {
    pub fn new(store: Box<dyn Store>) -> Containers {
        Containers {
            store,
            lock: Mutex::new(()),
            execs: Mutex::new(HashMap::new()),
            made: AtomicU64::new(0),
        }
    }

    /// The reply to a container call, or None when the call is not one (the caller says 501).
    /// `gone` says whether the client has hung up: a `wait` stops looking when it has.
    pub(crate) fn route(
        &self,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
        gone: &mut dyn FnMut() -> bool,
    ) -> Option<Reply> {
        let parts: Vec<&str> = path.split('/').collect();
        let answer = match (method, parts.as_slice()) {
            ("POST", ["", "containers", "create"]) => self.create(query, body),
            ("GET", ["", "containers", "json"]) => self.list(query),
            ("GET", ["", "containers", id, "json"]) => self.inspect(id),
            ("POST", ["", "containers", id, "wait"]) => self.wait(id, query, gone),
            // (Nothing here has a terminal of its own to resize: the main process runs without one.)
            ("POST", ["", "containers", id, "resize"]) => self.find(id).map(|_| empty(200)),
            ("POST", ["", "containers", id, "exec"]) => self.exec_create(id, body),
            ("POST", ["", "exec", id, "resize"]) => self.exec_resize(id, query),
            ("GET", ["", "exec", id, "json"]) => self.exec_inspect(id),
            ("POST", ["", "containers", id, action @ ("start" | "stop" | "restart" | "kill")]) => {
                self.act(id, action, query)
            }
            ("DELETE", ["", "containers", id]) => self.remove(id, query),
            _ => return None,
        };
        Some(answer.unwrap_or_else(|failed| failed))
    }

    /// The calls that answer with a stream (`logs`, `attach`, an exec's `start`) and so write to the
    /// connection themselves: None when the call is not one. `Ok` says the stream was written and
    /// the connection is done; `Err` is a reply to send in its place (nothing was written yet).
    pub(crate) fn stream(
        &self,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
        reader: &mut BufReader<Clocked>,
    ) -> Option<Result<(), Reply>> {
        let parts: Vec<&str> = path.split('/').collect();
        Some(match (method, parts.as_slice()) {
            ("GET", ["", "containers", id, "logs"]) => self.logs(id, query, reader),
            ("POST", ["", "containers", id, "attach"]) => self.attach(id, query, reader),
            ("POST", ["", "exec", id, "start"]) => self.exec_start(id, body, reader),
            // (The one `wait` that answers its head first: the client waits for the head before it starts the container.)
            ("POST", ["", "containers", id, "wait"]) if param(query, "condition") == Some("next-exit") => {
                self.wait_next(id, reader)
            }
            _ => return None,
        })
    }

    fn lock(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn execs(&self) -> MutexGuard<'_, HashMap<String, Exec>> {
        self.execs.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn get(&self, key: &str) -> Result<Option<Value>, Reply> {
        self.store.get(key).map_err(store_failed)
    }

    /// Apply `doc`. Its status and revision belong to the store, so neither is sent.
    fn put(&self, mut doc: Value) -> Result<(), String> {
        if let Some(object) = doc.as_object_mut() {
            object.remove("status");
        }
        if let Some(metadata) = doc["metadata"].as_object_mut() {
            metadata.remove("revision");
        }
        self.store.apply(doc)
    }

    /// Every container: the Workloads and Jobs of namespace `docker` that carry their own name as label.
    fn records(&self) -> Result<Vec<Value>, Reply> {
        let mut found = Vec::new();
        for kind in ["Workload", "Job"] {
            for doc in self.store.list(kind, NAMESPACE).map_err(store_failed)? {
                if ours(&doc).is_some() {
                    found.push(doc);
                }
            }
        }
        Ok(found)
    }

    /// The container named `id`, or whose ID starts with `id` (hex, and only one of them). A name
    /// is two single-key reads; only an ID prefix lists. Where both a Job and a Workload of that name
    /// are ours (a crash in the middle of a conversion), the Job is the one found: it is the one made
    /// last when a container starts, and the one `halt` takes away last.
    fn find(&self, id: &str) -> Result<Value, Reply> {
        for kind in ["Job", "Workload"] {
            if let Some(doc) = self.get(&key(kind, id))?.filter(|doc| ours(doc) == Some(id)) {
                return Ok(doc);
            }
        }
        let all = self.records()?;
        if let Some(doc) = all.iter().find(|doc| ours(doc) == Some(id)) {
            return Ok(doc.clone());
        }
        let hex = !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit());
        let matching: Vec<&Value> = all
            .iter()
            .filter(|doc| hex && ours(doc).is_some_and(|name| container_id(NAMESPACE, name).starts_with(id)))
            .collect();
        match matching.as_slice() {
            [doc] => Ok((*doc).clone()),
            [] => Err(message(404, format!("No such container: {id}"))),
            _ => Err(message(409, format!("multiple containers start with {id}"))),
        }
    }

    /// `POST /containers/create`: a Workload at zero replicas, labelled with its name.
    fn create(&self, query: &str, body: &[u8]) -> Out {
        let config: Value = if body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(body).map_err(|e| message(400, format!("kith: the create body is not JSON: {e}")))?
        };
        if config["Image"].as_str().unwrap_or("").is_empty() {
            return Err(message(400, "config.Image cannot be empty in the create config"));
        }
        let name = match param(query, "name") {
            Some(name) => {
                check_name(name)?;
                name.to_string()
            }
            None => generated_name(),
        };
        let host = &config["HostConfig"];
        refuse_host(host)?;
        refuse_streams(&config)?;
        refuse_config(&config)?;
        if set(&config["Volumes"]) {
            return Err(message(501, "kith: volumes are not supported yet"));
        }
        let restart = restart_of(host)?;
        let retries = host["RestartPolicy"]["MaximumRetryCount"].as_u64().unwrap_or(0);
        let container = container_of(&config, &name)?;
        let _held = self.lock();
        for kind in ["Workload", "Job"] {
            if self.get(&key(kind, &name))?.is_some() {
                return Err(message(
                    409,
                    format!("Conflict. The container name \"/{name}\" is already in use"),
                ));
            }
        }
        let mut own = vec![
            (ANN_STATE, "created".to_string()),
            (ANN_RESTART, restart.to_string()),
            (ANN_RETRIES, retries.to_string()),
            (ANN_CREATED, now().to_string()),
        ];
        if config["Tty"].as_bool() == Some(true) {
            own.push((ANN_TTY, "1".to_string()));
        }
        let annotations = annotations(&own);
        let doc = resource(
            "Workload",
            &name,
            labels_of(&config, &name),
            annotations,
            json!({"replicas": 0, "template": template(container, "always")}),
        );
        self.put(doc).map_err(|e| message(400, e))?;
        Ok(json_reply(
            201,
            json!({"Id": container_id(NAMESPACE, &name), "Warnings": []}).to_string(),
        ))
    }

    /// `GET /containers/json`: the running ones, or all with `all=1`.
    fn list(&self, query: &str) -> Out {
        if param(query, "filters").is_some_and(|f| !f.is_empty()) {
            return Err(message(501, "kith: container filters are not answered yet"));
        }
        let all = flag(query, "all");
        let items: Vec<Value> = self
            .records()?
            .iter()
            .filter(|doc| all || state(doc).running)
            .map(list_item)
            .collect();
        Ok(json_reply(200, Value::Array(items).to_string()))
    }

    /// `GET /containers/{id}/json`.
    fn inspect(&self, id: &str) -> Out {
        let doc = self.find(id)?;
        Ok(json_reply(200, inspect_json(&doc).to_string()))
    }

    /// `POST /containers/{id}/wait`: blocks until the container is not running, as Docker's does.
    fn wait(&self, id: &str, query: &str, gone: &mut dyn FnMut() -> bool) -> Out {
        if param(query, "condition") == Some("removed") {
            return Err(message(
                501,
                "kith: waiting for a container to be removed is not supported",
            ));
        }
        let name = name_of(&self.find(id)?).to_string();
        let code = self.exit_of(&name, None, gone)?;
        Ok(json_reply(200, wait_json(code)))
    }

    /// The code `name` stops with: once it is not running, and, with `after`, has been started since
    /// that many starts. A container removed meanwhile stopped with 137 (removed with force).
    fn exit_of(&self, name: &str, after: Option<u64>, gone: &mut dyn FnMut() -> bool) -> Result<i64, Reply> {
        loop {
            if gone() {
                return Err(message(499, "kith: the client hung up"));
            }
            let doc = match self.find(name) {
                Ok(doc) => doc,
                Err(not_found) if not_found.status == 404 => return Ok(137),
                Err(other) => return Err(other),
            };
            let st = state(&doc);
            if !st.running && after.is_none_or(|n| starts(&doc) > n) {
                return Ok(st.exit);
            }
            std::thread::sleep(WAIT_POLL);
        }
    }

    /// `start`, `stop`, `restart` and `kill`. 304 when there was nothing to do.
    fn act(&self, id: &str, action: &str, query: &str) -> Out {
        let _held = self.lock();
        let doc = self.find(id)?;
        let name = name_of(&doc).to_string();
        let changed = match action {
            "start" => self.start(doc)?,
            "stop" => self.halt(&doc, 143)?,
            "kill" => {
                if !state(&doc).running {
                    return Err(message(409, format!("Container {name} is not running")));
                }
                self.halt(&doc, signal_exit(query))?
            }
            // (The route passes only these four actions: this is restart.)
            _ => {
                self.halt(&doc, 143)?;
                self.start(self.find(&name)?)?
            }
        };
        Ok(empty(if changed { 204 } else { 304 }))
    }

    /// `DELETE /containers/{id}`: a running container goes only with `force=1`.
    fn remove(&self, id: &str, query: &str) -> Out {
        let _held = self.lock();
        let doc = self.find(id)?;
        let name = name_of(&doc).to_string();
        if state(&doc).running {
            if !flag(query, "force") {
                return Err(message(
                    409,
                    format!(
                        "You cannot remove a running container {name}. Stop the container before attempting removal or force remove"
                    ),
                ));
            }
            self.halt(&doc, 137)?;
        }
        // (Both kinds: after a crash in a conversion, both may be ours, and neither is left behind.)
        for kind in ["Job", "Workload"] {
            let at = key(kind, &name);
            if self.get(&at)?.is_some_and(|doc| ours(&doc).is_some()) {
                self.store.delete(&at).map_err(store_failed)?;
            }
        }
        Ok(empty(204))
    }

    /// Start a container: a Workload goes to one replica; a parked Job is made; a finished Job runs
    /// again. False: it was running already.
    fn start(&self, doc: Value) -> Result<bool, Reply> {
        if state(&doc).running {
            return Ok(false);
        }
        let mut doc = doc;
        let count = (starts(&doc) + 1).to_string();
        set_annotation(&mut doc, ANN_STARTS, &count);
        if doc["kind"] == "Job" {
            self.restart_job(doc)?;
        } else if is_job(annotation(&doc, ANN_RESTART)) {
            self.convert("Workload", job_from(&doc))?;
        } else {
            doc["spec"]["replicas"] = json!(1);
            unset_annotation(&mut doc, ANN_STATE);
            self.put(doc).map_err(store_failed)?;
        }
        Ok(true)
    }

    /// A finished Job runs again. An apply keeps a Job's old status, so the Job has to go and be made
    /// anew; the stopped Workload is made first and taken away last, so every step leaves a
    /// container, and a failure says which one is left.
    fn restart_job(&self, doc: Value) -> Result<(), Reply> {
        let name = name_of(&doc).to_string();
        let (job_key, parked_key) = (key("Job", &name), key("Workload", &name));
        let failed = |e: String, left: &str| {
            message(
                500,
                format!("kith: restarting {name} failed ({e}); it is left as {left}"),
            )
        };
        self.not_foreign(&parked_key)?;
        self.put(parked(&doc)).map_err(|e| failed(e, &job_key))?;
        // (Whatever is at the Job's key now must still be ours: it is read again before it goes.)
        self.not_foreign(&job_key)?;
        let both = format!("{job_key} and {parked_key}");
        self.store.delete(&job_key).map_err(|e| failed(e, &both))?;
        self.put(doc).map_err(|e| failed(e, &parked_key))?;
        self.store
            .delete(&parked_key)
            .map_err(|e| failed(e, &format!("{job_key}, running, with {parked_key} left over")))
    }

    /// Stop a running container with `exit` as its code. A Workload goes to zero replicas; a Job is
    /// taken away and parked as a Workload, so it stays listed and can start again. False: it was
    /// not running.
    fn halt(&self, doc: &Value, exit: i64) -> Result<bool, Reply> {
        if !state(doc).running {
            return Ok(false);
        }
        let mut doc = doc.clone();
        let job = doc["kind"] == "Job";
        if job {
            doc = parked(&doc);
        }
        doc["spec"]["replicas"] = json!(0);
        set_annotation(&mut doc, ANN_EXIT, &exit.to_string());
        if job {
            self.convert("Job", doc)?;
        } else {
            self.put(doc).map_err(store_failed)?;
        }
        Ok(true)
    }

    /// 409 when a resource that is not this front's is at `key`; absent or ours is fine. Every write
    /// that may land on a key the caller did not just read goes through this.
    fn not_foreign(&self, key: &str) -> Result<(), Reply> {
        if self.get(key)?.is_some_and(|there| ours(&there).is_none()) {
            return Err(message(
                409,
                format!("Conflict. {key} is not a container of this front: it is left as it is"),
            ));
        }
        Ok(())
    }

    /// Make `new` (a container of the other kind than the one at `old_kind`) and then take the old
    /// one away, so a failure in between leaves a container, not none. A resource at the new key that
    /// is not this front's is never written over (409).
    fn convert(&self, old_kind: &str, new: Value) -> Result<(), Reply> {
        let name = name_of(&new).to_string();
        let new_key = key(new["kind"].as_str().unwrap_or(""), &name);
        self.not_foreign(&new_key)?;
        self.put(new).map_err(store_failed)?;
        if let Err(e) = self.store.delete(&key(old_kind, &name)) {
            let _ = self.store.delete(&new_key);
            return Err(store_failed(e));
        }
        Ok(())
    }
}

/// What a call answers: its reply, or the reply that says why not.
type Out = Result<Reply, Reply>;

mod live;

fn wait_json(code: i64) -> String {
    json!({"StatusCode": code, "Error": null}).to_string()
}

/// The annotations a container keeps for itself: its state while created, the code it stopped with,
/// when it was created (Unix seconds), its restart policy and its retries.
const ANN_STATE: &str = "kith.dev/docker-state";
const ANN_EXIT: &str = "kith.dev/docker-exit";
const ANN_CREATED: &str = "kith.dev/docker-created";
const ANN_RESTART: &str = "kith.dev/docker-restart";
const ANN_RETRIES: &str = "kith.dev/docker-retries";
/// How many times it was started (a `wait` for the next exit counts from the number it found), and
/// whether it was made with a terminal (`1`): what its streams look like to `docker logs`.
const ANN_STARTS: &str = "kith.dev/docker-starts";
const ANN_TTY: &str = "kith.dev/docker-tty";
/// How often `wait` looks again.
const WAIT_POLL: Duration = Duration::from_millis(200);
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

fn store_failed(e: String) -> Reply {
    message(500, e)
}

fn empty(status: u16) -> Reply {
    Reply {
        status,
        content_type: "text/plain; charset=utf-8",
        body: Vec::new(),
    }
}

fn key(kind: &str, name: &str) -> String {
    format!("{kind}/{NAMESPACE}/{name}")
}

fn name_of(doc: &Value) -> &str {
    doc["metadata"]["name"].as_str().unwrap_or("")
}

/// The name of a container this front made: its label says so. Anything else is not one.
fn ours(doc: &Value) -> Option<&str> {
    let name = doc["metadata"]["name"].as_str()?;
    (doc["metadata"]["labels"][LABEL].as_str() == Some(name)).then_some(name)
}

fn annotation<'a>(doc: &'a Value, key: &str) -> &'a str {
    doc["metadata"]["annotations"][key].as_str().unwrap_or("")
}

fn set_annotation(doc: &mut Value, key: &str, value: &str) {
    doc["metadata"]["annotations"][key] = json!(value);
}

fn unset_annotation(doc: &mut Value, key: &str) {
    if let Some(annotations) = doc["metadata"]["annotations"].as_object_mut() {
        annotations.remove(key);
    }
}

fn annotations(pairs: &[(&str, String)]) -> Value {
    Value::Object(pairs.iter().map(|(k, v)| (k.to_string(), json!(v))).collect())
}

fn resource(kind: &str, name: &str, labels: Value, annotations: Value, spec: Value) -> Value {
    json!({
        "apiVersion": "kith.dev/v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": labels, "annotations": annotations},
        "spec": spec,
    })
}

fn template(container: Value, restart_policy: &str) -> Value {
    json!({"containers": [container], "restartPolicy": restart_policy})
}

/// The label of a container as made: the create body's labels, and its own name.
fn labels_of(config: &Value, name: &str) -> Value {
    let mut labels: Map<String, Value> = config["Labels"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), json!(v))))
        .collect();
    labels.insert(LABEL.to_string(), json!(name));
    Value::Object(labels)
}

/// `no` and `on-failure` run as Jobs once started; the rest as Workloads.
fn is_job(restart: &str) -> bool {
    matches!(restart, "no" | "on-failure")
}

/// The restart policy of a Job's template, as kith names it.
fn job_policy(restart: &str) -> &'static str {
    match restart {
        "no" => "never",
        "on-failure" => "onFailure",
        _ => "always",
    }
}

fn restart_of(host: &Value) -> Result<&'static str, Reply> {
    match host["RestartPolicy"]["Name"].as_str().unwrap_or("") {
        "" | "no" => Ok("no"),
        "always" => Ok("always"),
        "unless-stopped" => Ok("unless-stopped"),
        "on-failure" => Ok("on-failure"),
        other => Err(message(
            400,
            format!("kith: restart policy {other} is not known: no, always, unless-stopped or on-failure"),
        )),
    }
}

/// The Workload a Job becomes when stopped, or when it is created: no replicas, its template kept.
fn parked(job: &Value) -> Value {
    let mut template = job["spec"]["template"].clone();
    template["restartPolicy"] = json!("always");
    let mut doc = job.clone();
    doc["kind"] = json!("Workload");
    doc["spec"] = json!({"replicas": 0, "template": template});
    // (The code the Job last ended with, which a Job's status holds and a Workload's annotation does.)
    set_annotation(&mut doc, ANN_EXIT, &state(job).exit.to_string());
    doc
}

/// The Job a parked Workload becomes when it starts: its template under the policy its restart
/// names, with the retries it was created with.
fn job_from(parked: &Value) -> Value {
    let mut template = parked["spec"]["template"].clone();
    template["restartPolicy"] = json!(job_policy(annotation(parked, ANN_RESTART)));
    let retries: u32 = annotation(parked, ANN_RETRIES).parse().unwrap_or(0);
    let mut spec = json!({"template": template});
    if retries > 0 {
        spec["retries"] = json!(retries);
    }
    let mut doc = parked.clone();
    doc["kind"] = json!("Job");
    doc["spec"] = spec;
    unset_annotation(&mut doc, ANN_STATE);
    doc
}

/// The code `kill` stops with: 143 for TERM, 137 for KILL (and anything else).
fn signal_exit(query: &str) -> i64 {
    match param(query, "signal") {
        Some("SIGTERM" | "TERM" | "15") => 143,
        _ => 137,
    }
}

/// Where a container is: created and never started, running, or exited with its code.
struct State {
    status: &'static str,
    running: bool,
    exit: i64,
}

fn state(doc: &Value) -> State {
    let exited = |exit| State {
        status: "exited",
        running: false,
        exit,
    };
    if doc["kind"] == "Job" {
        return match doc["status"]["state"].as_str() {
            Some("succeeded") => exited(0),
            Some("failed") => exited(
                doc["status"]["containers"]
                    .as_array()
                    .and_then(|c| c.iter().find_map(|c| c["exitCode"].as_i64()))
                    .unwrap_or(1),
            ),
            _ => State {
                status: "running",
                running: true,
                exit: 0,
            },
        };
    }
    if doc["spec"]["replicas"].as_u64().unwrap_or(1) > 0 {
        // The status says what the units are doing: every one waiting to start again or exited is
        // a restart in progress, which Docker counts as running too. (No status yet: just started.)
        let units = doc["status"]["containers"].as_array().filter(|u| !u.is_empty());
        let restarting = units.is_some_and(|u| {
            u.iter()
                .all(|u| matches!(u["state"].as_str(), Some("waiting" | "exited")))
        });
        return State {
            status: if restarting { "restarting" } else { "running" },
            running: true,
            exit: 0,
        };
    }
    if annotation(doc, ANN_STATE) == "created" {
        return State {
            status: "created",
            running: false,
            exit: 0,
        };
    }
    exited(annotation(doc, ANN_EXIT).parse().unwrap_or(0))
}

fn created(doc: &Value) -> i64 {
    annotation(doc, ANN_CREATED).parse().unwrap_or(0)
}

fn starts(doc: &Value) -> u64 {
    annotation(doc, ANN_STARTS).parse().unwrap_or(0)
}

fn retries(doc: &Value) -> u64 {
    annotation(doc, ANN_RETRIES).parse().unwrap_or(0)
}

/// The command as Docker lists it: the entrypoint, then the arguments.
fn argv(container: &Value) -> Vec<String> {
    container["command"]
        .as_array()
        .into_iter()
        .chain(container["args"].as_array())
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

fn list_item(doc: &Value) -> Value {
    let st = state(doc);
    let name = name_of(doc);
    let c = &doc["spec"]["template"]["containers"][0];
    let status = match st.status {
        "running" => "Up".to_string(),
        "restarting" => "Restarting".to_string(),
        "exited" => format!("Exited ({})", st.exit),
        _ => "Created".to_string(),
    };
    json!({
        "Id": container_id(NAMESPACE, name),
        "Names": [format!("/{name}")],
        "Image": c["image"],
        "ImageID": "",
        "Command": argv(c).join(" "),
        "Created": created(doc),
        "Ports": [],
        "Labels": doc["metadata"]["labels"],
        "State": st.status,
        "Status": status,
        "HostConfig": {"NetworkMode": "default"},
        "NetworkSettings": {"Networks": {}},
        "Mounts": [],
    })
}

fn inspect_json(doc: &Value) -> Value {
    let st = state(doc);
    let name = name_of(doc);
    let c = &doc["spec"]["template"]["containers"][0];
    let mut words = argv(c);
    let path = if words.is_empty() {
        String::new()
    } else {
        words.remove(0)
    };
    let started = if st.running {
        rfc3339(created(doc))
    } else {
        ZERO_TIME.to_string()
    };
    let env: Vec<String> = c["env"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|e| {
            format!(
                "{}={}",
                e["name"].as_str().unwrap_or(""),
                e["value"].as_str().unwrap_or("")
            )
        })
        .collect();
    json!({
        "Id": container_id(NAMESPACE, name),
        "Created": rfc3339(created(doc)),
        "Path": path,
        "Args": words,
        "State": {
            "Status": st.status,
            "Running": st.running,
            "Paused": false,
            "Restarting": st.status == "restarting",
            "OOMKilled": false,
            "Dead": false,
            "Pid": 0,
            "ExitCode": st.exit,
            "Error": "",
            "StartedAt": started,
            "FinishedAt": ZERO_TIME,
        },
        "Image": c["image"],
        "Name": format!("/{name}"),
        "RestartCount": 0,
        "Config": {
            "Image": c["image"],
            "Cmd": c["args"],
            "Entrypoint": c["command"],
            "Env": env,
            "WorkingDir": c["workingDir"],
            "User": c["runAsUser"].as_u64().map(|u| u.to_string()).unwrap_or_default(),
            "Labels": doc["metadata"]["labels"],
            "Tty": annotation(doc, ANN_TTY) == "1",
            "OpenStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
        },
        "HostConfig": {
            "RestartPolicy": {"Name": annotation(doc, ANN_RESTART), "MaximumRetryCount": retries(doc)},
            "Privileged": false,
            "NetworkMode": "default",
            "Binds": null,
            "PortBindings": {},
        },
        "Mounts": [],
        "NetworkSettings": {"Networks": {}},
    })
}

/// The container a create body asks for, as kith's container: the entrypoint is `command`, the
/// command is `args`; environment and working directory as given; the user must be a number.
fn container_of(config: &Value, name: &str) -> Result<Value, Reply> {
    let mut c = Map::new();
    c.insert("name".into(), json!(name));
    c.insert("image".into(), config["Image"].clone());
    let entrypoint = string_list(&config["Entrypoint"], "Entrypoint")?;
    let command = string_list(&config["Cmd"], "Cmd")?;
    if !entrypoint.is_empty() {
        c.insert("command".into(), json!(entrypoint));
    }
    if !command.is_empty() {
        c.insert("args".into(), json!(command));
    }
    let env = env_of(&config["Env"])?;
    if !env.is_empty() {
        c.insert("env".into(), Value::Array(env));
    }
    if let Some(dir) = config["WorkingDir"].as_str().filter(|d| !d.is_empty()) {
        c.insert("workingDir".into(), json!(dir));
    }
    if let Some(user) = config["User"].as_str().filter(|u| !u.is_empty()) {
        let uid = user.split(':').next().unwrap_or("");
        let uid: u32 = uid
            .parse()
            .map_err(|_| message(400, format!("kith: user {user} must be a number, uid or uid:gid")))?;
        c.insert("runAsUser".into(), json!(uid));
    }
    let drop: Vec<String> = string_list(&config["HostConfig"]["CapDrop"], "CapDrop")?
        .into_iter()
        .map(|cap| {
            if cap.eq_ignore_ascii_case("all") {
                "all".to_string()
            } else {
                cap.to_ascii_uppercase()
            }
        })
        .collect();
    if !drop.is_empty() {
        c.insert("dropCapabilities".into(), json!(drop));
    }
    Ok(Value::Object(c))
}

fn string_list(v: &Value, field: &str) -> Result<Vec<String>, Reply> {
    let refused = || message(400, format!("kith: {field} must be a list of strings"));
    match v {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string).ok_or_else(refused))
            .collect(),
        _ => Err(refused()),
    }
}

fn env_of(v: &Value) -> Result<Vec<Value>, Reply> {
    string_list(v, "Env")?
        .iter()
        .map(|entry| -> Result<Value, Reply> {
            let (name, value) = entry
                .split_once('=')
                .ok_or_else(|| message(400, format!("kith: env {entry} needs a value: NAME=VALUE")))?;
            Ok(json!({"name": name, "value": value}))
        })
        .collect()
}

/// The longest container name: a Workload's units are NAME-0, and a kith name is at most 63.
const MAX_NAME: usize = 61;

/// A container's name is a kith name: lowercase letters, digits, `-` and `.` (Docker's names, made
/// stricter: no capitals or `_`), at most MAX_NAME characters, starting and ending with a letter or digit.
fn check_name(name: &str) -> Result<(), Reply> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(message(
            400,
            format!(
                "kith: invalid container name ({name}): use lowercase letters, digits, - and ., starting and ending with a letter or digit, at most {MAX_NAME} characters"
            ),
        ))
    }
}

/// A name for a container created without one, as Docker makes one.
fn generated_name() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let (n, p) = (nanos.to_le_bytes(), std::process::id().to_le_bytes());
    format!("c-{}", &sha256_hex(&[&n[..], &p[..]])[..12])
}

/// A field that is set: true, a non-zero number, or a non-empty string, list or object.
fn set(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|x| x != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// What would let the container change the node or see more of it than kith gives it. Refused (400),
/// or not made yet (501).
fn refuse_host(host: &Value) -> Result<(), Reply> {
    for field in [
        "Privileged",
        "CapAdd",
        "SecurityOpt",
        "Devices",
        "DeviceRequests",
        "Sysctls",
        "Binds",
        "Mounts",
        "GroupAdd",
    ] {
        if set(&host[field]) {
            return Err(message(
                400,
                format!("kith: HostConfig.{field} is refused: it changes what the container may do on the node"),
            ));
        }
    }
    for field in ["PidMode", "IpcMode", "UsernsMode", "UTSMode", "CgroupnsMode"] {
        let mode = host[field].as_str().unwrap_or("");
        if !matches!(mode, "" | "default" | "private") {
            return Err(message(
                400,
                format!("kith: HostConfig.{field} is {mode}: refused, it shares the node's namespace"),
            ));
        }
    }
    let network = host["NetworkMode"].as_str().unwrap_or("");
    if network == "host" || network.starts_with("container:") {
        return Err(message(
            400,
            format!("kith: NetworkMode {network} is refused: it shares the node's network"),
        ));
    }
    if !matches!(network, "" | "default" | "bridge") {
        return Err(message(
            501,
            format!("kith: NetworkMode {network} is not supported yet: the default bridge is"),
        ));
    }
    let not_yet = [
        "PortBindings",
        "Ulimits",
        "Tmpfs",
        "VolumesFrom",
        "ReadonlyRootfs",
        "Runtime",
        // Fields the mapping would otherwise drop without a word.
        "Dns",
        "DnsSearch",
        "DnsOptions",
        "ExtraHosts",
        "Links",
        "PublishAllPorts",
        "Init",
        "OomKillDisable",
        "CpusetCpus",
        "CpusetMems",
        "StorageOpt",
        "Isolation",
        "Cgroup",
    ]
    .iter()
    .any(|f| set(&host[*f]))
        || host["AutoRemove"].as_bool() == Some(true)
        || host["LogConfig"]["Type"]
            .as_str()
            .is_some_and(|t| !t.is_empty() && t != "json-file")
        || [
            "Memory",
            "MemorySwap",
            "MemoryReservation",
            "NanoCpus",
            "CpuShares",
            "CpuQuota",
            "CpuPeriod",
            "PidsLimit",
            "ShmSize",
            "BlkioWeight",
        ]
        .iter()
        .any(|f| host[*f].as_i64().is_some_and(|n| n > 0));
    if not_yet {
        return Err(message(
            501,
            "kith: published ports, ulimits, --rm, resource limits, DNS settings, extra hosts, links, init, log drivers, volumes, tmpfs, read-only roots and runtimes are not supported yet",
        ));
    }
    Ok(())
}

/// Create-body fields outside HostConfig that the mapping has no place for: refused, not dropped.
fn refuse_config(config: &Value) -> Result<(), Reply> {
    let ignored = [
        "Hostname",
        "Domainname",
        "ExposedPorts",
        "Healthcheck",
        "StopSignal",
        "Shell",
        "MacAddress",
    ]
    .iter()
    .any(|f| set(&config[*f]))
        || config["NetworkDisabled"].as_bool() == Some(true)
        || config["StopTimeout"].as_i64().is_some_and(|n| n > 0);
    if ignored {
        return Err(message(
            501,
            "kith: a hostname, exposed ports, a health check, a stop signal or timeout and a MAC address are not supported yet",
        ));
    }
    Ok(())
}

/// Output to the client is fine (`docker run`, `docker logs`); stdin to the container's main process
/// is not: kithd starts it with its input closed, and has no way to attach to one that runs.
fn refuse_streams(config: &Value) -> Result<(), Reply> {
    if ["AttachStdin", "OpenStdin"].iter().any(|f| set(&config[*f])) {
        return Err(message(
            501,
            "kith: stdin to a container's main process is not supported (kithd starts it with no input and cannot attach to it): leave out -i, or give a command its input with docker exec -i",
        ));
    }
    Ok(())
}

/// A query parameter's value (`key=value` among `&`s); a key with no `=` has none.
fn param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .find_map(|pair| pair.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))
}

/// A flag parameter: `1` or `true`.
fn flag(query: &str, key: &str) -> bool {
    matches!(param(query, key), Some("1" | "true"))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `secs` since the epoch as an RFC 3339 UTC time.
fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400) + 719_468;
    let rem = secs.rem_euclid(86_400);
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// The store the tests look at: documents by "Kind/namespace/name".
    #[derive(Default, Clone)]
    struct MemStore(Arc<Mutex<BTreeMap<String, Value>>>);

    fn key_of(doc: &Value) -> String {
        format!(
            "{}/{}/{}",
            doc["kind"].as_str().unwrap_or(""),
            doc["metadata"]["namespace"].as_str().unwrap_or(""),
            doc["metadata"]["name"].as_str().unwrap_or("")
        )
    }

    impl Store for MemStore {
        fn get(&self, key: &str) -> Result<Option<Value>, String> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn list(&self, kind: &str, namespace: &str) -> Result<Vec<Value>, String> {
            let prefix = format!("{kind}/{namespace}/");
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v.clone())
                .collect())
        }
        fn apply(&self, doc: Value) -> Result<(), String> {
            self.0.lock().unwrap().insert(key_of(&doc), doc);
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// A store that refuses the operations it is told to ("apply Job/docker/once", "delete
    /// Workload/docker/once") and logs the ones it took, in order.
    struct Failing {
        mem: MemStore,
        refuse: &'static [&'static str],
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Failing {
        fn refused(&self, op: &str, key: &str) -> Result<(), String> {
            let line = format!("{op} {key}");
            if self.refuse.contains(&line.as_str()) {
                return Err(format!("refused: {line}"));
            }
            self.log.lock().unwrap().push(line);
            Ok(())
        }
    }

    impl Store for Failing {
        fn get(&self, key: &str) -> Result<Option<Value>, String> {
            self.mem.get(key)
        }
        fn list(&self, kind: &str, namespace: &str) -> Result<Vec<Value>, String> {
            self.mem.list(kind, namespace)
        }
        fn apply(&self, doc: Value) -> Result<(), String> {
            self.refused("apply", &key_of(&doc))?;
            self.mem.apply(doc)
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            self.refused("delete", key)?;
            self.mem.delete(key)
        }
    }

    fn failing(refuse: &'static [&'static str]) -> (MemStore, Arc<Mutex<Vec<String>>>, Containers) {
        let (mem, log) = (MemStore::default(), Arc::new(Mutex::new(Vec::new())));
        let store = Failing {
            mem: mem.clone(),
            refuse,
            log: log.clone(),
        };
        (mem, log, Containers::new(Box::new(store)))
    }

    /// One call as `docker` makes it: the status, and the body as JSON (Null when there is none).
    fn call(c: &Containers, method: &str, target: &str, body: &str) -> (u16, Value) {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let reply = c
            .route(method, path, query, body.as_bytes(), &mut || false)
            .expect("the front answers this call");
        let json = if reply.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&reply.body).unwrap_or(Value::Null)
        };
        (reply.status, json)
    }

    fn fixture() -> (MemStore, Containers) {
        let mem = MemStore::default();
        let c = Containers::new(Box::new(mem.clone()));
        (mem, c)
    }

    const WEB: &str = r#"{"Image":"alpine","Cmd":["sleep","1"],"Labels":{"team":"a"},"HostConfig":{"RestartPolicy":{"Name":"always"}}}"#;

    #[test]
    fn a_create_body_is_a_workload_labelled_with_its_labels_kept() {
        let (mem, c) = fixture();
        let (status, reply) = call(&c, "POST", "/containers/create?name=web", WEB);
        assert_eq!(status, 201);
        assert_eq!(reply["Id"], json!(container_id(NAMESPACE, "web")));
        let w = mem.get("Workload/docker/web").unwrap().expect("a Workload named web");
        assert_eq!(w["metadata"]["labels"][LABEL], "web");
        assert_eq!(w["metadata"]["labels"]["team"], "a");
        assert_eq!(w["spec"]["replicas"], 0, "created, not started");
        assert_eq!(w["spec"]["template"]["containers"][0]["image"], "alpine");
        assert_eq!(w["spec"]["template"]["containers"][0]["args"], json!(["sleep", "1"]));
        assert_eq!(w["spec"]["template"]["restartPolicy"], "always");
    }

    #[test]
    fn restart_no_and_on_failure_run_as_jobs_once_started() {
        let (mem, c) = fixture();
        call(
            &c,
            "POST",
            "/containers/create?name=once",
            r#"{"Image":"alpine","HostConfig":{"RestartPolicy":{"Name":"no"}}}"#,
        );
        assert!(
            mem.get("Job/docker/once").unwrap().is_none(),
            "a created container is not a Job yet"
        );
        assert_eq!(call(&c, "POST", "/containers/once/start", "").0, 204);
        let j = mem.get("Job/docker/once").unwrap().expect("a Job named once");
        assert_eq!(j["metadata"]["labels"][LABEL], "once");
        assert_eq!(j["spec"]["template"]["restartPolicy"], "never");
        assert!(
            mem.get("Workload/docker/once").unwrap().is_none(),
            "the parked Workload is gone"
        );

        call(
            &c,
            "POST",
            "/containers/create?name=retry",
            r#"{"Image":"alpine","HostConfig":{"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":3}}}"#,
        );
        call(&c, "POST", "/containers/retry/start", "");
        let r = mem.get("Job/docker/retry").unwrap().expect("a Job named retry");
        assert_eq!(r["spec"]["template"]["restartPolicy"], "onFailure");
        assert_eq!(r["spec"]["retries"], 3);

        assert_eq!(call(&c, "POST", "/containers/retry/stop", "").0, 204);
        assert!(
            mem.get("Job/docker/retry").unwrap().is_none(),
            "a stopped Job is taken away"
        );
        let (_, inspect) = call(&c, "GET", "/containers/retry/json", "");
        assert_eq!(inspect["State"]["Status"], "exited");
        assert_eq!(inspect["State"]["ExitCode"], 143);
    }

    #[test]
    fn a_kind_change_never_writes_over_a_resource_that_is_not_ours() {
        let (mem, c) = fixture();
        call(
            &c,
            "POST",
            "/containers/create?name=once",
            r#"{"Image":"alpine","HostConfig":{"RestartPolicy":{"Name":"no"}}}"#,
        );
        // Someone else's Job of that name (no kith.dev/docker label).
        let theirs = json!({"kind":"Job","metadata":{"name":"once","namespace":"docker"},"spec":{}});
        mem.apply(theirs.clone()).unwrap();
        let (status, reply) = call(&c, "POST", "/containers/once/start", "");
        assert_eq!(status, 409, "{reply}");
        assert_eq!(
            mem.get("Job/docker/once").unwrap(),
            Some(theirs),
            "their Job is as it was"
        );
        assert!(
            mem.get("Workload/docker/once").unwrap().is_some(),
            "the container is kept, not lost"
        );
    }

    #[test]
    fn a_name_fits_a_workloads_unit_names() {
        let (_mem, c) = fixture();
        let ok = "a".repeat(MAX_NAME);
        let (status, _) = call(&c, "POST", &format!("/containers/create?name={ok}"), WEB);
        assert_eq!(status, 201);
        let long = "a".repeat(MAX_NAME + 1);
        let (status, reply) = call(&c, "POST", &format!("/containers/create?name={long}"), WEB);
        assert_eq!(status, 400, "{reply}");
        assert!(reply["message"].as_str().unwrap().contains("at most 61"), "{reply}");
    }

    #[test]
    fn volumes_tmpfs_read_only_roots_and_runtimes_are_refused_not_dropped() {
        let (mem, c) = fixture();
        for body in [
            r#"{"Image":"alpine","Volumes":{"/data":{}},"HostConfig":{}}"#,
            r#"{"Image":"alpine","HostConfig":{"Tmpfs":{"/tmp":""}}}"#,
            r#"{"Image":"alpine","HostConfig":{"VolumesFrom":["other"]}}"#,
            r#"{"Image":"alpine","HostConfig":{"ReadonlyRootfs":true}}"#,
            r#"{"Image":"alpine","HostConfig":{"Runtime":"runsc"}}"#,
        ] {
            let (status, reply) = call(&c, "POST", "/containers/create?name=x", body);
            assert_eq!(status, 501, "{body}: {reply}");
        }
        assert!(mem.0.lock().unwrap().is_empty(), "nothing was made");
    }

    #[test]
    fn fields_the_mapping_would_drop_are_refused_with_a_501() {
        let (mem, c) = fixture();
        for body in [
            r#"{"Image":"alpine","HostConfig":{"Dns":["1.1.1.1"]}}"#,
            r#"{"Image":"alpine","HostConfig":{"ExtraHosts":["a:1.2.3.4"]}}"#,
            r#"{"Image":"alpine","HostConfig":{"PidsLimit":10}}"#,
            r#"{"Image":"alpine","HostConfig":{"MemorySwap":1000}}"#,
            r#"{"Image":"alpine","HostConfig":{"LogConfig":{"Type":"syslog"}}}"#,
            r#"{"Image":"alpine","Hostname":"box"}"#,
            r#"{"Image":"alpine","ExposedPorts":{"80/tcp":{}}}"#,
            r#"{"Image":"alpine","Healthcheck":{"Test":["CMD","true"]}}"#,
            r#"{"Image":"alpine","StopSignal":"SIGINT"}"#,
        ] {
            let (status, reply) = call(&c, "POST", "/containers/create?name=x", body);
            assert_eq!(status, 501, "{body}: {reply}");
        }
        // What the docker CLI sends when nothing was asked for is not refused.
        let plain = r#"{"Image":"alpine","Hostname":"","ExposedPorts":null,"HostConfig":{"Dns":[],"MemorySwap":0,"PidsLimit":null,"LogConfig":{"Type":"","Config":{}},"Init":null}}"#;
        assert_eq!(call(&c, "POST", "/containers/create?name=x", plain).0, 201);
        assert_eq!(mem.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_finished_job_that_cannot_be_made_again_stays_a_stopped_container() {
        let (mem, _log, c) = failing(&["apply Job/docker/once"]);
        mem.apply(finished_job("once", 3)).unwrap();
        let (status, reply) = call(&c, "POST", "/containers/once/start", "");
        assert_eq!(status, 500);
        let said = reply["message"].as_str().unwrap();
        assert!(
            said.contains("Workload/docker/once"),
            "the error says what is left: {said}"
        );
        let (_, inspect) = call(&c, "GET", "/containers/once/json", "");
        assert_eq!(inspect["State"]["Status"], "exited", "the container is kept");
        assert_eq!(
            inspect["State"]["ExitCode"], 3,
            "with the code the Job had finished with"
        );
    }

    /// A finished Job of the front's, as a store keeps it.
    fn finished_job(name: &str, exit: i64) -> Value {
        json!({"apiVersion": "kith.dev/v1", "kind": "Job",
            "metadata": {"name": name, "namespace": "docker", "labels": {LABEL: name}},
            "spec": {"template": {"containers": [{"name": name, "image": "alpine"}], "restartPolicy": "never"}},
            "status": {"state": if exit == 0 { "succeeded" } else { "failed" },
                "containers": [{"name": name, "exitCode": exit}]}})
    }

    #[test]
    fn a_job_restart_makes_the_stopped_workload_first_and_takes_it_away_last() {
        let (mem, log, c) = failing(&[]);
        mem.apply(finished_job("once", 0)).unwrap();
        assert_eq!(call(&c, "POST", "/containers/once/start", "").0, 204);
        assert_eq!(
            *log.lock().unwrap(),
            [
                "apply Workload/docker/once",
                "delete Job/docker/once",
                "apply Job/docker/once",
                "delete Workload/docker/once"
            ],
            "there is a container at every step"
        );
        assert!(mem.get("Workload/docker/once").unwrap().is_none());
        assert!(mem.get("Job/docker/once").unwrap().is_some());
    }

    #[test]
    fn a_job_restart_that_fails_at_any_step_keeps_the_container_and_names_where() {
        for (refused, left) in [
            ("apply Workload/docker/once", "Job/docker/once"),
            ("delete Job/docker/once", "Job/docker/once"),
            ("apply Job/docker/once", "Workload/docker/once"),
            ("delete Workload/docker/once", "Job/docker/once"),
        ] {
            let refuse: &'static [&'static str] = Box::leak(Box::new([refused]));
            let (mem, _log, c) = failing(refuse);
            mem.apply(finished_job("once", 0)).unwrap();
            let (status, reply) = call(&c, "POST", "/containers/once/start", "");
            assert_eq!(status, 500, "{refused}: {reply}");
            let said = reply["message"].as_str().unwrap();
            assert!(said.contains(refused), "{refused}: the error names the step: {said}");
            assert!(said.contains(left), "{refused}: the error names what is left: {said}");
            assert!(
                mem.get(left).unwrap().is_some(),
                "{refused}: {left} is still there: {:?}",
                mem.0.lock().unwrap().keys().collect::<Vec<_>>()
            );
            assert_eq!(call(&c, "GET", "/containers/once/json", "").0, 200, "{refused}");
        }
    }

    #[test]
    fn a_job_that_is_no_longer_ours_at_the_restart_is_not_deleted() {
        let (mem, c) = fixture();
        mem.apply(finished_job("once", 0)).unwrap();
        let mut theirs = finished_job("once", 0);
        theirs["metadata"]["labels"] = json!({});
        // The doc `start` was handed is ours; by the time it deletes, the Job at the key is not.
        let doc = mem.get("Job/docker/once").unwrap().unwrap();
        mem.apply(theirs.clone()).unwrap();
        let _held = c.lock();
        let reply = c.start(doc).unwrap_err();
        assert_eq!(reply.status, 409);
        assert_eq!(
            mem.get("Job/docker/once").unwrap(),
            Some(theirs),
            "their Job is as it was"
        );
    }

    #[test]
    fn both_a_workload_and_a_job_of_ours_read_as_the_job_and_go_together() {
        let (mem, c) = fixture();
        call(&c, "POST", "/containers/create?name=once", r#"{"Image":"alpine"}"#);
        // A crash between the two writes of a conversion leaves both.
        mem.apply(finished_job("once", 5)).unwrap();
        let (_, inspect) = call(&c, "GET", "/containers/once/json", "");
        assert_eq!(inspect["State"]["ExitCode"], 5, "the Job is the one that is read");
        assert_eq!(call(&c, "DELETE", "/containers/once", "").0, 204);
        assert!(mem.get("Job/docker/once").unwrap().is_none());
        assert!(mem.get("Workload/docker/once").unwrap().is_none());
        assert_eq!(call(&c, "GET", "/containers/once/json", "").0, 404);
    }

    #[test]
    fn a_wait_on_a_container_that_is_removed_meanwhile_answers_as_a_kill() {
        let (mem, c) = fixture();
        call(&c, "POST", "/containers/create?name=web", WEB);
        call(&c, "POST", "/containers/web/start", "");
        let mut polls = 0;
        let reply = c
            .route("POST", "/containers/web/wait", "", b"", &mut || {
                polls += 1;
                if polls == 2 {
                    mem.delete("Workload/docker/web").unwrap();
                }
                false
            })
            .expect("answered");
        assert_eq!(reply.status, 200);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body, json!({"StatusCode": 137, "Error": null}));
        // (Before the wait starts, a container that is not there is Docker's 404.)
        assert_eq!(call(&c, "POST", "/containers/web/wait", "").0, 404);
    }

    #[test]
    fn a_foreign_workload_survives_a_failing_job_restart_untouched() {
        let (mem, _log, c) = failing(&["apply Job/docker/once"]);
        let job = finished_job("once", 0);
        mem.apply(job.clone()).unwrap();
        let theirs = json!({"apiVersion": "kith.dev/v1", "kind": "Workload",
            "metadata": {"name": "once", "namespace": "docker"},
            "spec": {"template": {"containers": [{"name": "once", "image": "nginx"}]}}});
        mem.apply(theirs.clone()).unwrap();
        let (status, reply) = call(&c, "POST", "/containers/once/start", "");
        assert_eq!(status, 409, "{reply}");
        assert_eq!(
            mem.get("Workload/docker/once").unwrap(),
            Some(theirs),
            "their Workload is as it was"
        );
        assert_eq!(
            mem.get("Job/docker/once").unwrap(),
            Some(job),
            "the store was left alone"
        );
    }

    #[test]
    fn a_wait_stops_when_the_client_has_hung_up() {
        let (_mem, c) = fixture();
        call(&c, "POST", "/containers/create?name=web", WEB);
        call(&c, "POST", "/containers/web/start", "");
        let mut polls = 0;
        let reply = c
            .route("POST", "/containers/web/wait", "", b"", &mut || {
                polls += 1;
                polls > 2
            })
            .expect("answered");
        assert_eq!(reply.status, 499);
        assert!(polls > 2, "it asked the client again and again");
    }

    #[test]
    fn a_workload_whose_units_are_all_waiting_or_exited_is_restarting() {
        let (mem, c) = fixture();
        call(&c, "POST", "/containers/create?name=web", WEB);
        call(&c, "POST", "/containers/web/start", "");
        let mut w = mem.get("Workload/docker/web").unwrap().unwrap();
        w["status"] = json!({"replicas":1,"containers":[{"name":"web-0","state":"running"}]});
        mem.apply(w.clone()).unwrap();
        let (_, inspect) = call(&c, "GET", "/containers/web/json", "");
        assert_eq!(inspect["State"]["Status"], "running");
        w["status"] = json!({"replicas":1,"containers":[{"name":"web-0","state":"waiting"}]});
        mem.apply(w).unwrap();
        let (_, inspect) = call(&c, "GET", "/containers/web/json", "");
        assert_eq!(inspect["State"]["Status"], "restarting");
        assert_eq!(inspect["State"]["Restarting"], true);
    }

    #[test]
    fn start_and_stop_move_replicas_and_keep_the_exit_code() {
        let (mem, c) = fixture();
        call(&c, "POST", "/containers/create?name=web", WEB);
        assert_eq!(call(&c, "POST", "/containers/web/start", "").0, 204);
        let w = mem.get("Workload/docker/web").unwrap().unwrap();
        assert_eq!(w["spec"]["replicas"], 1);
        assert_eq!(call(&c, "POST", "/containers/web/start", "").0, 304, "already running");
        assert_eq!(call(&c, "POST", "/containers/web/stop", "").0, 204);
        let w = mem.get("Workload/docker/web").unwrap().unwrap();
        assert_eq!(w["spec"]["replicas"], 0);
        assert_eq!(w["metadata"]["annotations"]["kith.dev/docker-exit"], "143");
        assert_eq!(call(&c, "POST", "/containers/web/stop", "").0, 304, "already stopped");
        let (_, inspect) = call(&c, "GET", "/containers/web/json", "");
        assert_eq!(inspect["State"]["Status"], "exited");
        assert_eq!(inspect["State"]["Running"], false);
        assert_eq!(inspect["State"]["ExitCode"], 143);
        let (status, waited) = call(&c, "POST", "/containers/web/wait", "");
        assert_eq!(status, 200);
        assert_eq!(waited, json!({"StatusCode": 143, "Error": null}));
    }

    #[test]
    fn list_and_inspect_answer_in_docker_shape() {
        let (_mem, c) = fixture();
        call(&c, "POST", "/containers/create?name=web", WEB);
        call(&c, "POST", "/containers/web/start", "");
        call(&c, "POST", "/containers/create?name=idle", r#"{"Image":"alpine"}"#);
        let (status, running) = call(&c, "GET", "/containers/json", "");
        assert_eq!(status, 200);
        assert_eq!(
            running.as_array().unwrap().len(),
            1,
            "without all, only the running ones"
        );
        assert_eq!(running[0]["Names"], json!(["/web"]));
        assert_eq!(running[0]["State"], "running");
        assert_eq!(running[0]["Image"], "alpine");
        assert_eq!(running[0]["Id"].as_str().unwrap().len(), 64);
        let (_, all) = call(&c, "GET", "/containers/json?all=1", "");
        assert_eq!(all.as_array().unwrap().len(), 2);
        let idle = all
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["Names"] == json!(["/idle"]))
            .unwrap();
        assert_eq!(idle["State"], "created");
        let (_, by_name) = call(&c, "GET", "/containers/web/json", "");
        assert_eq!(by_name["Name"], "/web");
        assert_eq!(by_name["State"]["Status"], "running");
        assert_eq!(by_name["State"]["Running"], true);
        assert_eq!(by_name["Config"]["Image"], "alpine");
        assert_eq!(by_name["Config"]["Labels"][LABEL], "web");
        assert_eq!(by_name["HostConfig"]["RestartPolicy"]["Name"], "always");
        let id = container_id(NAMESPACE, "web");
        let (_, by_id) = call(&c, "GET", &format!("/containers/{id}/json"), "");
        assert_eq!(by_id["Name"], "/web");
        let (_, by_prefix) = call(&c, "GET", &format!("/containers/{}/json", &id[..12]), "");
        assert_eq!(by_prefix["Name"], "/web");
    }

    #[test]
    fn bad_names_are_refused_in_docker_shape() {
        let (mem, c) = fixture();
        for name in ["Web", "web_1", "-web", &"a".repeat(64)] {
            let (status, reply) = call(&c, "POST", &format!("/containers/create?name={name}"), WEB);
            assert_eq!(status, 400, "name {name}");
            assert!(
                reply["message"].as_str().unwrap().contains("container name"),
                "name {name}"
            );
        }
        assert!(mem.list("Workload", NAMESPACE).unwrap().is_empty());
        let (status, reply) = call(&c, "POST", "/containers/create", WEB);
        assert_eq!(status, 201, "no name: docker makes one");
        assert_eq!(reply["Id"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn security_changing_host_config_fields_are_refused() {
        let (mem, c) = fixture();
        let cases = [
            r#"{"Privileged":true}"#,
            r#"{"CapAdd":["SYS_ADMIN"]}"#,
            r#"{"Binds":["/:/host"]}"#,
            r#"{"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}"#,
            r#"{"SecurityOpt":["seccomp=unconfined"]}"#,
            r#"{"PidMode":"host"}"#,
            r#"{"IpcMode":"host"}"#,
            r#"{"UsernsMode":"host"}"#,
            r#"{"NetworkMode":"host"}"#,
            r#"{"NetworkMode":"container:other"}"#,
            r#"{"Devices":[{"PathOnHost":"/dev/sda"}]}"#,
            r#"{"Sysctls":{"net.ipv4.ip_forward":"1"}}"#,
        ];
        for host_config in cases {
            let body = format!(r#"{{"Image":"alpine","HostConfig":{host_config}}}"#);
            let (status, reply) = call(&c, "POST", "/containers/create?name=web", &body);
            assert_eq!(status, 400, "{host_config}");
            assert!(reply["message"].is_string(), "{host_config}");
        }
        assert!(mem.list("Workload", NAMESPACE).unwrap().is_empty(), "nothing was made");
    }

    #[test]
    fn another_resource_in_the_docker_namespace_is_not_touched() {
        let (mem, c) = fixture();
        mem.apply(json!({"apiVersion": "kith.dev/v1", "kind": "Workload",
            "metadata": {"name": "web", "namespace": "docker"},
            "spec": {"template": {"containers": [{"name": "web", "image": "nginx"}]}}}))
            .unwrap();
        let (status, reply) = call(&c, "POST", "/containers/create?name=web", WEB);
        assert_eq!(status, 409);
        assert!(reply["message"].is_string());
        assert_eq!(call(&c, "POST", "/containers/web/start", "").0, 404);
        assert_eq!(call(&c, "GET", "/containers/web/json", "").0, 404);
        assert_eq!(call(&c, "DELETE", "/containers/web", "").0, 404);
        let kept = mem.get("Workload/docker/web").unwrap().expect("still there");
        assert_eq!(kept["spec"]["template"]["containers"][0]["image"], "nginx");
        mem.apply(json!({"apiVersion": "kith.dev/v1", "kind": "Workload",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {"template": {"containers": [{"name": "api", "image": "nginx"}]}}}))
            .unwrap();
        assert_eq!(
            call(&c, "POST", "/containers/create?name=api", WEB).0,
            201,
            "another namespace is not in the way"
        );
    }

    #[test]
    fn rm_refuses_a_running_container_unless_forced() {
        let (mem, c) = fixture();
        call(&c, "POST", "/containers/create?name=web", WEB);
        call(&c, "POST", "/containers/web/start", "");
        let (status, reply) = call(&c, "DELETE", "/containers/web", "");
        assert_eq!(status, 409);
        assert!(reply["message"].as_str().unwrap().contains("running"));
        assert_eq!(call(&c, "DELETE", "/containers/web?force=1", "").0, 204);
        assert!(mem.list("Workload", NAMESPACE).unwrap().is_empty());
    }

    #[test]
    fn a_finished_jobs_status_is_its_exit_code() {
        let (mem, c) = fixture();
        let job = |name: &str, status: Value| {
            json!({"apiVersion": "kith.dev/v1", "kind": "Job",
                "metadata": {"name": name, "namespace": "docker", "labels": {LABEL: name}},
                "spec": {"template": {"containers": [{"name": name, "image": "alpine"}], "restartPolicy": "never"}},
                "status": status})
        };
        mem.apply(job(
            "ok",
            json!({"state": "succeeded", "containers": [{"name": "ok", "exitCode": 0}]}),
        ))
        .unwrap();
        mem.apply(job(
            "bad",
            json!({"state": "failed", "containers": [{"name": "bad", "exitCode": 3}]}),
        ))
        .unwrap();
        mem.apply(job("busy", json!({"state": "running", "containers": []})))
            .unwrap();
        let (_, ok) = call(&c, "GET", "/containers/ok/json", "");
        assert_eq!(
            (ok["State"]["Status"].as_str(), ok["State"]["ExitCode"].as_i64()),
            (Some("exited"), Some(0))
        );
        let (_, bad) = call(&c, "GET", "/containers/bad/json", "");
        assert_eq!(
            (bad["State"]["Status"].as_str(), bad["State"]["ExitCode"].as_i64()),
            (Some("exited"), Some(3))
        );
        let (_, busy) = call(&c, "GET", "/containers/busy/json", "");
        assert_eq!(busy["State"]["Status"], "running");
        assert_eq!(busy["State"]["Running"], true);
    }

    #[test]
    fn calls_and_options_that_are_not_here_are_not_answered_here() {
        let (_mem, c) = fixture();
        // (The streams are answered by `stream`, not `route`.)
        assert!(c.route("GET", "/containers/web/logs", "", b"", &mut || false).is_none());
        assert!(
            c.route("POST", "/containers/web/attach", "", b"", &mut || false)
                .is_none()
        );
        assert!(c.route("GET", "/images/json", "", b"", &mut || false).is_none());
        let stdin = r#"{"Image":"alpine","AttachStdin":true,"OpenStdin":true,"HostConfig":{}}"#;
        let (status, reply) = call(&c, "POST", "/containers/create?name=web", stdin);
        assert_eq!(status, 501, "docker run -i: stdin to a main process is refused");
        assert!(reply["message"].as_str().unwrap().contains("docker exec -i"), "{reply}");
        let attached = r#"{"Image":"alpine","AttachStdout":true,"AttachStderr":true,"Tty":true,"HostConfig":{}}"#;
        let (status, _) = call(&c, "POST", "/containers/create?name=web", attached);
        assert_eq!(
            status, 201,
            "docker run without -d is a create that asks for the output"
        );
        let (_, reply) = call(&c, "GET", "/containers/web/json", "");
        assert_eq!(reply["Config"]["Tty"], true);
        let (status, _) = call(&c, "GET", "/containers/json?filters=%7B%7D", "");
        assert_eq!(status, 501, "filters are not answered yet");
    }

    /// A store with logs and exec: what each of the two outputs holds, and the session the next exec gets.
    struct Live {
        mem: MemStore,
        out: Arc<Mutex<[Vec<u8>; 2]>>,
        session: Mutex<Option<Session>>,
        ran: Arc<Mutex<Vec<(String, Vec<String>, bool, bool)>>>,
    }

    impl Store for Live {
        fn get(&self, key: &str) -> Result<Option<Value>, String> {
            self.mem.get(key)
        }
        fn list(&self, kind: &str, namespace: &str) -> Result<Vec<Value>, String> {
            self.mem.list(kind, namespace)
        }
        fn apply(&self, doc: Value) -> Result<(), String> {
            self.mem.apply(doc)
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            self.mem.delete(key)
        }
        fn logs(&self, key: &str, stderr: bool, from: LogFrom) -> Result<LogChunk, String> {
            // (kithd reads the logs of a resource that is there, by its kind: a Job is not its Workload.)
            if self.mem.get(key)?.is_none() {
                return Err(format!("{key} not found"));
            }
            let all = self.out.lock().unwrap()[usize::from(stderr)].clone();
            let at = match from {
                LogFrom::Start => 0,
                LogFrom::Offset(n) => n as usize,
                LogFrom::Tail(n) => {
                    let lines: Vec<&[u8]> = all.split_inclusive(|b| *b == b'\n').collect();
                    all.len() - lines[lines.len().saturating_sub(n as usize)..].concat().len()
                }
            };
            Ok(LogChunk {
                data: all[at.min(all.len())..].to_vec(),
                next: all.len() as u64,
            })
        }
        fn exec(&self, pod: &str, command: &[String], tty: bool, stdin: bool) -> Result<Session, String> {
            self.ran
                .lock()
                .unwrap()
                .push((pod.to_string(), command.to_vec(), tty, stdin));
            self.session
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| "no session".to_string())
        }
    }

    struct Rig {
        mem: MemStore,
        c: Containers,
        out: Arc<Mutex<[Vec<u8>; 2]>>,
        ran: Arc<Mutex<Vec<(String, Vec<String>, bool, bool)>>>,
    }

    /// Containers over a `Live` store; `session` is what the first exec is given.
    fn live(session: Option<Session>) -> Rig {
        let mem = MemStore::default();
        let (out, ran) = (
            Arc::new(Mutex::new([Vec::new(), Vec::new()])),
            Arc::new(Mutex::new(Vec::new())),
        );
        let store = Live {
            mem: mem.clone(),
            out: out.clone(),
            session: Mutex::new(session),
            ran: ran.clone(),
        };
        Rig {
            mem,
            c: Containers::new(Box::new(store)),
            out,
            ran,
        }
    }

    /// A stream call as `docker` makes it: what the server wrote until it let go of the connection.
    fn streamed(c: &Containers, method: &str, target: &str, body: &str, sent: &[u8]) -> (Result<(), Reply>, Vec<u8>) {
        streamed_with(c, method, target, body, sent, false)
    }

    /// `streamed`; with `half_close` the client shuts its sending side at once and goes on reading (as `docker exec` without `-i` does).
    fn streamed_with(
        c: &Containers,
        method: &str,
        target: &str,
        body: &str,
        sent: &[u8],
        half_close: bool,
    ) -> (Result<(), Reply>, Vec<u8>) {
        use std::io::Write as _;
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(sent).unwrap();
        if half_close {
            client.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let mut got = Vec::new();
        let result = std::thread::scope(|scope| {
            let call = scope.spawn(move || {
                let mut reader = BufReader::new(Clocked {
                    stream: server,
                    until: Instant::now() + Duration::from_secs(60),
                });
                c.stream(method, path, query, body.as_bytes(), &mut reader)
                    .expect("a stream call")
            });
            let result = call.join().unwrap();
            client.read_to_end(&mut got).unwrap();
            result
        });
        (result, got)
    }

    fn after_head(raw: &[u8]) -> &[u8] {
        let at = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a head");
        &raw[at + 4..]
    }

    const RUNNING: &str = r#"{"Image":"alpine","Cmd":["sleep","1"],"HostConfig":{"RestartPolicy":{"Name":"always"}}}"#;

    fn running(rig: &Rig, name: &str, config: &str) {
        assert_eq!(
            call(&rig.c, "POST", &format!("/containers/create?name={name}"), config).0,
            201
        );
        assert_eq!(call(&rig.c, "POST", &format!("/containers/{name}/start"), "").0, 204);
    }

    #[test]
    fn logs_are_chunked_frames_of_what_each_output_holds() {
        let rig = live(None);
        running(&rig, "web", RUNNING);
        *rig.out.lock().unwrap() = [b"one\ntwo\n".to_vec(), b"oops\n".to_vec()];
        let (result, raw) = streamed(&rig.c, "GET", "/containers/web/logs?stdout=1&stderr=1", "", b"");
        result.unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("Transfer-Encoding: chunked"));
        assert!(raw.ends_with(b"0\r\n\r\n"), "the zero chunk ends it");
        assert_eq!(
            unframe(&dechunk(after_head(&raw))),
            [(1, "one\ntwo\n".to_string()), (2, "oops\n".to_string())]
        );
        // --tail 1 of stdout only.
        let (_, raw) = streamed(&rig.c, "GET", "/containers/web/logs?stdout=1&tail=1", "", b"");
        assert_eq!(unframe(&dechunk(after_head(&raw))), [(1, "two\n".to_string())]);
        // Neither output is a mistake; times and ranges are not kept.
        let (status, _) = streamed(&rig.c, "GET", "/containers/web/logs?timestamps=1&stdout=1", "", b"");
        assert_eq!(status.unwrap_err().status, 501);
        let (status, _) = streamed(&rig.c, "GET", "/containers/web/logs?since=5&stdout=1", "", b"");
        assert_eq!(status.unwrap_err().status, 501);
        let (status, _) = streamed(&rig.c, "GET", "/containers/web/logs", "", b"");
        assert_eq!(status.unwrap_err().status, 400);
        let (status, _) = streamed(&rig.c, "GET", "/containers/nope/logs?stdout=1", "", b"");
        assert_eq!(status.unwrap_err().status, 404);
    }

    #[test]
    fn a_followed_log_ends_when_the_container_does_and_has_its_last_words() {
        let rig = live(None);
        assert_eq!(
            call(
                &rig.c,
                "POST",
                "/containers/create?name=once",
                r#"{"Image":"alpine","HostConfig":{"RestartPolicy":{"Name":"no"}}}"#
            )
            .0,
            201
        );
        assert_eq!(call(&rig.c, "POST", "/containers/once/start", "").0, 204);
        *rig.out.lock().unwrap() = [b"a\n".to_vec(), Vec::new()];
        let (mem, out) = (rig.mem.clone(), rig.out.clone());
        let ender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            out.lock().unwrap()[0].extend(b"b\n");
            let mut job = mem.get("Job/docker/once").unwrap().unwrap();
            job["status"] = json!({"state": "succeeded"});
            mem.apply(job).unwrap();
        });
        let (result, raw) = streamed(&rig.c, "GET", "/containers/once/logs?stdout=1&follow=1", "", b"");
        ender.join().unwrap();
        result.unwrap();
        let said: String = unframe(&dechunk(after_head(&raw)))
            .into_iter()
            .map(|(_, s)| s)
            .collect();
        assert_eq!(said, "a\nb\n", "what it said when it stopped is not lost");
    }

    #[test]
    fn attach_waits_for_the_start_then_sends_only_what_is_written_after() {
        let rig = live(None);
        assert_eq!(
            call(
                &rig.c,
                "POST",
                "/containers/create?name=once",
                r#"{"Image":"alpine","AttachStdout":true,"HostConfig":{"RestartPolicy":{"Name":"no"}}}"#
            )
            .0,
            201
        );
        let (c, mem, out) = (&rig.c, rig.mem.clone(), rig.out.clone());
        let (_, raw) = std::thread::scope(|scope| {
            let starter = scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(400));
                assert_eq!(call(c, "POST", "/containers/once/start", "").0, 204);
                out.lock().unwrap()[0].extend(b"hello\n");
                std::thread::sleep(Duration::from_millis(400));
                let mut job = mem.get("Job/docker/once").unwrap().unwrap();
                job["status"] = json!({"state": "succeeded"});
                mem.apply(job).unwrap();
            });
            let got = streamed(c, "POST", "/containers/once/attach?stream=1&stdout=1&stderr=1", "", b"");
            starter.join().unwrap();
            got
        });
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert!(text.starts_with("HTTP/1.1 101 UPGRADED\r\n"), "{text}");
        assert!(text.contains("Upgrade: tcp"));
        assert_eq!(unframe(after_head(&raw)), [(1, "hello\n".to_string())]);
        // Stdin is refused, with the reason.
        let (refused, _) = streamed(c, "POST", "/containers/once/attach?stream=1&stdin=1&stdout=1", "", b"");
        let refused = refused.unwrap_err();
        assert_eq!(refused.status, 501);
        assert!(String::from_utf8_lossy(&refused.body).contains("docker exec -i"));
    }

    #[test]
    fn a_wait_for_the_next_exit_answers_its_head_at_once_and_the_code_after_the_start() {
        let rig = live(None);
        assert_eq!(
            call(
                &rig.c,
                "POST",
                "/containers/create?name=once",
                r#"{"Image":"alpine","HostConfig":{"RestartPolicy":{"Name":"no"}}}"#
            )
            .0,
            201
        );
        let (c, mem) = (&rig.c, rig.mem.clone());
        let (result, raw) = std::thread::scope(|scope| {
            let ender = scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(400));
                assert_eq!(call(c, "POST", "/containers/once/start", "").0, 204);
                std::thread::sleep(Duration::from_millis(400));
                let mut job = mem.get("Job/docker/once").unwrap().unwrap();
                job["status"] = json!({"state": "failed", "containers": [{"exitCode": 7}]});
                mem.apply(job).unwrap();
            });
            let got = streamed(c, "POST", "/containers/once/wait?condition=next-exit", "", b"");
            ender.join().unwrap();
            got
        });
        result.unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        let body: Value = serde_json::from_slice(after_head(&raw)).unwrap();
        assert_eq!(body["StatusCode"], 7);
    }

    #[test]
    fn an_exec_is_created_resized_started_and_inspected_with_its_code() {
        let (events, ev_in) = mpsc::channel();
        let (input, sent) = mpsc::channel();
        let rig = live(Some(Session { events: ev_in, input }));
        running(&rig, "web", RUNNING);
        let (status, reply) = call(
            &rig.c,
            "POST",
            "/containers/web/exec",
            r#"{"Cmd":["ls","/"],"AttachStdout":true,"AttachStderr":true}"#,
        );
        assert_eq!(status, 201, "{reply}");
        let id = reply["Id"].as_str().unwrap().to_string();
        assert_eq!(call(&rig.c, "POST", &format!("/exec/{id}/resize?h=24&w=80"), "").0, 200);
        let (_, before) = call(&rig.c, "GET", &format!("/exec/{id}/json"), "");
        assert_eq!(
            (before["Running"].clone(), before["ExitCode"].clone()),
            (json!(false), json!(0))
        );
        events.send(Event::Out(b"bin\n".to_vec())).unwrap();
        events.send(Event::Err(b"warn\n".to_vec())).unwrap();
        events.send(Event::Done(3)).unwrap();
        let (result, raw) = streamed(
            &rig.c,
            "POST",
            &format!("/exec/{id}/start"),
            r#"{"Detach":false,"Tty":false}"#,
            b"",
        );
        result.unwrap();
        assert!(String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 101 UPGRADED\r\n"));
        assert_eq!(
            unframe(after_head(&raw)),
            [(1, "bin\n".to_string()), (2, "warn\n".to_string())]
        );
        let (_, after) = call(&rig.c, "GET", &format!("/exec/{id}/json"), "");
        assert_eq!(
            (after["Running"].clone(), after["ExitCode"].clone()),
            (json!(false), json!(3))
        );
        assert_eq!(
            *rig.ran.lock().unwrap(),
            [(
                "web-0".to_string(),
                vec!["ls".to_string(), "/".to_string()],
                false,
                false
            )]
        );
        // The size asked for before the start went in with it, and the end of the session is told.
        let inputs: Vec<Input> = sent.try_iter().collect();
        assert!(matches!(inputs.first(), Some(Input::Resize(80, 24))));
        assert!(matches!(inputs.last(), Some(Input::Close)));
        // Started once.
        let (again, _) = streamed(&rig.c, "POST", &format!("/exec/{id}/start"), "{}", b"");
        assert_eq!(again.unwrap_err().status, 409);
    }

    #[test]
    fn an_exec_without_stdin_keeps_running_when_the_client_half_closes_at_once() {
        let (events, ev_in) = mpsc::channel();
        let (input, sent) = mpsc::channel();
        let rig = live(Some(Session { events: ev_in, input }));
        running(&rig, "web", RUNNING);
        let (_, reply) = call(
            &rig.c,
            "POST",
            "/containers/web/exec",
            r#"{"Cmd":["sh","-c","sleep 1; echo hi"],"AttachStdout":true}"#,
        );
        let id = reply["Id"].as_str().unwrap().to_string();
        let feed = std::thread::spawn(move || {
            // The command is still running: its end of input must not have been closed.
            std::thread::sleep(Duration::from_millis(400));
            let closed = sent.try_iter().any(|i| matches!(i, Input::Close));
            events.send(Event::Out(b"hi\n".to_vec())).unwrap();
            events.send(Event::Done(0)).unwrap();
            closed
        });
        let (result, raw) = streamed_with(&rig.c, "POST", &format!("/exec/{id}/start"), "{}", b"", true);
        assert!(!feed.join().unwrap(), "a half-close is not a hang-up: the command is not killed");
        result.unwrap();
        assert_eq!(unframe(after_head(&raw)), [(1, "hi\n".to_string())]);
        let (_, after) = call(&rig.c, "GET", &format!("/exec/{id}/json"), "");
        assert_eq!(after["ExitCode"], json!(0));
    }

    #[test]
    fn an_exec_with_a_terminal_and_stdin_is_raw_and_passes_what_the_client_types() {
        let (events, ev_in) = mpsc::channel();
        let (input, sent) = mpsc::channel();
        let rig = live(Some(Session { events: ev_in, input }));
        running(&rig, "web", RUNNING);
        let (_, reply) = call(
            &rig.c,
            "POST",
            "/containers/web/exec",
            r#"{"Cmd":["sh"],"AttachStdin":true,"AttachStdout":true,"Tty":true}"#,
        );
        let id = reply["Id"].as_str().unwrap().to_string();
        events.send(Event::Out(b"$ ".to_vec())).unwrap();
        let feed = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            events.send(Event::Done(0)).unwrap();
        });
        let (result, raw) = streamed(&rig.c, "POST", &format!("/exec/{id}/start"), r#"{"Tty":true}"#, b"ls\n");
        feed.join().unwrap();
        result.unwrap();
        assert_eq!(after_head(&raw), b"$ ");
        assert!(String::from_utf8_lossy(&raw).contains("application/vnd.docker.raw-stream"));
        let typed: Vec<u8> = sent
            .try_iter()
            .filter_map(|i| if let Input::Data(d) = i { Some(d) } else { None })
            .flatten()
            .collect();
        assert_eq!(typed, b"ls\n");
        assert!(rig.ran.lock().unwrap()[0].2 && rig.ran.lock().unwrap()[0].3);
    }

    #[test]
    fn an_exec_that_cannot_be_made_says_why() {
        let rig = live(None);
        assert_eq!(
            call(&rig.c, "POST", "/containers/nope/exec", r#"{"Cmd":["ls"]}"#).0,
            404
        );
        assert_eq!(call(&rig.c, "POST", "/containers/create?name=idle", RUNNING).0, 201);
        let (status, _) = call(&rig.c, "POST", "/containers/idle/exec", r#"{"Cmd":["ls"]}"#);
        assert_eq!(status, 409, "not running");
        running(&rig, "web", RUNNING);
        assert_eq!(
            call(
                &rig.c,
                "POST",
                "/containers/web/exec",
                r#"{"Cmd":["ls"],"Env":["A=1"]}"#
            )
            .0,
            501
        );
        assert_eq!(call(&rig.c, "POST", "/containers/web/exec", r#"{"Cmd":[]}"#).0, 400);
        assert_eq!(call(&rig.c, "GET", "/exec/nothing/json", "").0, 404);
        assert_eq!(call(&rig.c, "POST", "/exec/nothing/resize?h=1&w=1", "").0, 404);
        let (status, _) = call(&rig.c, "POST", "/containers/web/exec", r#"{"Cmd":["ls"]}"#);
        assert_eq!(status, 201);
        // No session to be had: the start says so and the exec can be started again.
        let id = {
            let execs = rig.c.execs();
            execs.keys().next().unwrap().clone()
        };
        let (result, _) = streamed(&rig.c, "POST", &format!("/exec/{id}/start"), "{}", b"");
        assert_eq!(result.unwrap_err().status, 500);
        assert!(!rig.c.execs()[&id].started);
    }

    /// The body of a chunked answer, put together.
    fn dechunk(mut body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let eol = body.windows(2).position(|w| w == b"\r\n").expect("a chunk size");
            let size = usize::from_str_radix(std::str::from_utf8(&body[..eol]).unwrap(), 16).unwrap();
            if size == 0 {
                return out;
            }
            out.extend(&body[eol + 2..eol + 2 + size]);
            body = &body[eol + 2 + size + 2..];
        }
    }

    /// Docker's 8-byte-header frames as (stream, text), the frames of one stream put together.
    fn unframe(mut bytes: &[u8]) -> Vec<(u8, String)> {
        let mut out: Vec<(u8, String)> = Vec::new();
        while !bytes.is_empty() {
            let size = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
            let text = String::from_utf8_lossy(&bytes[8..8 + size]).into_owned();
            match out.last_mut() {
                Some((kind, so_far)) if *kind == bytes[0] => so_far.push_str(&text),
                _ => out.push((bytes[0], text)),
            }
            bytes = &bytes[8 + size..];
        }
        out
    }

    #[test]
    fn times_are_rfc3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
