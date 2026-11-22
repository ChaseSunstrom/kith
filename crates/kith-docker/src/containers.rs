//! Docker's containers as kith resources (T-1258): `docker run -d`, `ps`, `inspect`, `stop`, `start`,
//! `restart`, `kill`, `rm` and `wait` against them. A container is a Workload, or a Job when its
//! restart policy is `no` or `on-failure`, in namespace `docker`, labelled `kith.dev/docker=NAME`.
//! A created container is a Workload at zero replicas until it starts; a stopped one stays one.
//! Nothing here reads or writes kithd directly: the store is the seam (the CLI implements it).

use super::{Reply, container_id, json_reply, message, sha256_hex};
use serde_json::{Map, Value, json};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
}

/// The container calls, answered from a store.
pub struct Containers {
    store: Box<dyn Store>,
    /// One change at a time (create, start, stop, remove): a name is checked and then taken.
    lock: Mutex<()>,
}

impl Containers {
    pub fn new(store: Box<dyn Store>) -> Containers {
        Containers {
            store,
            lock: Mutex::new(()),
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
            ("POST", ["", "containers", id, "wait"]) => self.wait(id, gone),
            ("POST", ["", "containers", id, action @ ("start" | "stop" | "restart" | "kill")]) => {
                self.act(id, action, query)
            }
            ("DELETE", ["", "containers", id]) => self.remove(id, query),
            _ => return None,
        };
        Some(answer.unwrap_or_else(|failed| failed))
    }

    fn lock(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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
    /// is two single-key reads; only an ID prefix lists.
    fn find(&self, id: &str) -> Result<Value, Reply> {
        for kind in ["Workload", "Job"] {
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
        let annotations = annotations(&[
            (ANN_STATE, "created".to_string()),
            (ANN_RESTART, restart.to_string()),
            (ANN_RETRIES, retries.to_string()),
            (ANN_CREATED, now().to_string()),
        ]);
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
    fn wait(&self, id: &str, gone: &mut dyn FnMut() -> bool) -> Out {
        let name = name_of(&self.find(id)?).to_string();
        loop {
            if gone() {
                return Err(message(499, "kith: the client hung up"));
            }
            let doc = self.find(&name)?;
            let st = state(&doc);
            if !st.running {
                return Ok(json_reply(
                    200,
                    json!({"StatusCode": st.exit, "Error": null}).to_string(),
                ));
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
        let doc = self.find(&name)?;
        self.store
            .delete(&key(doc["kind"].as_str().unwrap_or("Workload"), &name))
            .map_err(store_failed)?;
        Ok(empty(204))
    }

    /// Start a container: a Workload goes to one replica; a parked Job is made; a finished Job runs
    /// again. False: it was running already.
    fn start(&self, doc: Value) -> Result<bool, Reply> {
        if state(&doc).running {
            return Ok(false);
        }
        let name = name_of(&doc).to_string();
        if doc["kind"] == "Job" {
            // (A finished Job runs again: its status goes with it, so it is taken away first.)
            // (A kept status cannot be cleared by an apply, so delete comes first: if the new Job
            // is refused, the container goes back as a stopped one rather than being lost.)
            // The parked Workload must be ours to write, so that is checked before anything goes.
            let parked_key = key("Workload", &name);
            self.not_foreign(&parked_key)?;
            self.store.delete(&key("Job", &name)).map_err(store_failed)?;
            if let Err(e) = self.put(doc.clone()) {
                if self.not_foreign(&parked_key).is_ok() {
                    let _ = self.put(parked(&doc));
                }
                return Err(store_failed(e));
            }
        } else if is_job(annotation(&doc, ANN_RESTART)) {
            self.convert("Workload", job_from(&doc))?;
        } else {
            let mut doc = doc;
            doc["spec"]["replicas"] = json!(1);
            unset_annotation(&mut doc, ANN_STATE);
            self.put(doc).map_err(store_failed)?;
        }
        Ok(true)
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

/// The annotations a container keeps for itself: its state while created, the code it stopped with,
/// when it was created (Unix seconds), its restart policy and its retries.
const ANN_STATE: &str = "kith.dev/docker-state";
const ANN_EXIT: &str = "kith.dev/docker-exit";
const ANN_CREATED: &str = "kith.dev/docker-created";
const ANN_RESTART: &str = "kith.dev/docker-restart";
const ANN_RETRIES: &str = "kith.dev/docker-retries";
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
            "Tty": false,
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

/// Attaching to the container's streams, or a terminal, is `docker run` without -d: not yet.
fn refuse_streams(config: &Value) -> Result<(), Reply> {
    if ["AttachStdin", "AttachStdout", "AttachStderr", "OpenStdin", "Tty"]
        .iter()
        .any(|f| set(&config[*f]))
    {
        return Err(message(
            501,
            "kith: attaching to a container's streams is not supported yet: start it with docker run -d",
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
        struct Refusing(MemStore);
        impl Store for Refusing {
            fn get(&self, key: &str) -> Result<Option<Value>, String> {
                self.0.get(key)
            }
            fn list(&self, kind: &str, namespace: &str) -> Result<Vec<Value>, String> {
                self.0.list(kind, namespace)
            }
            fn apply(&self, doc: Value) -> Result<(), String> {
                if doc["kind"] == "Job" {
                    return Err("refused".into());
                }
                self.0.apply(doc)
            }
            fn delete(&self, key: &str) -> Result<(), String> {
                self.0.delete(key)
            }
        }
        let mem = MemStore::default();
        let c = Containers::new(Box::new(Refusing(mem.clone())));
        mem.apply(json!({"apiVersion": "kith.dev/v1", "kind": "Job",
            "metadata": {"name": "once", "namespace": "docker", "labels": {LABEL: "once"}},
            "spec": {"template": {"containers": [{"name": "once", "image": "alpine"}], "restartPolicy": "never"}},
            "status": {"state": "succeeded", "containers": [{"name": "once", "exitCode": 0}]}}))
            .unwrap();
        assert_eq!(call(&c, "POST", "/containers/once/start", "").0, 500);
        assert_eq!(
            call(&c, "GET", "/containers/once/json", "").1["State"]["Status"],
            "exited",
            "the container is kept"
        );
    }

    #[test]
    fn a_foreign_workload_survives_a_failing_job_restart_untouched() {
        struct Refusing(MemStore);
        impl Store for Refusing {
            fn get(&self, key: &str) -> Result<Option<Value>, String> {
                self.0.get(key)
            }
            fn list(&self, kind: &str, namespace: &str) -> Result<Vec<Value>, String> {
                self.0.list(kind, namespace)
            }
            fn apply(&self, doc: Value) -> Result<(), String> {
                if doc["kind"] == "Job" {
                    return Err("refused".into());
                }
                self.0.apply(doc)
            }
            fn delete(&self, key: &str) -> Result<(), String> {
                self.0.delete(key)
            }
        }
        let mem = MemStore::default();
        let c = Containers::new(Box::new(Refusing(mem.clone())));
        let job = json!({"apiVersion": "kith.dev/v1", "kind": "Job",
            "metadata": {"name": "once", "namespace": "docker", "labels": {LABEL: "once"}},
            "spec": {"template": {"containers": [{"name": "once", "image": "alpine"}], "restartPolicy": "never"}},
            "status": {"state": "succeeded", "containers": [{"name": "once", "exitCode": 0}]}});
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
        assert!(c.route("GET", "/containers/web/logs", "", b"", &mut || false).is_none());
        assert!(
            c.route("POST", "/containers/web/attach", "", b"", &mut || false)
                .is_none()
        );
        assert!(c.route("GET", "/images/json", "", b"", &mut || false).is_none());
        let attached = r#"{"Image":"alpine","AttachStdout":true,"HostConfig":{}}"#;
        let (status, reply) = call_refusal(&c, "POST", "/containers/create?name=web", attached);
        assert_eq!(status, 501, "docker run without -d needs attach: not yet");
        assert!(reply["message"].is_string());
        let (status, _) = call_refusal(&c, "GET", "/containers/json?filters=%7B%7D", "");
        assert_eq!(status, 501, "filters are not answered yet");
    }

    fn call_refusal(c: &Containers, method: &str, target: &str, body: &str) -> (u16, Value) {
        call(c, method, target, body)
    }

    #[test]
    fn times_are_rfc3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
