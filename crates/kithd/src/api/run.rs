//! Remote apps: `POST /v1/run` opens a byte tunnel to an app that runs on a node.
//!
//! ```text
//! POST /v1/run      {on, via?, argv, namespace?}            -> 101, then bytes both ways   caller that may apply Jobs
//! POST /v1/run-hop  {on, via?, argv, namespace?, caller}    -> 101, then bytes both ways   nodes only
//! ```
//! `on` is a node's name, or `key=value[,key=value]` for the first ready Node (by name)
//! with those labels. The first node checks the caller (it may apply a Job in
//! `namespace`), writes the audit entry and, when the app is to run elsewhere, passes
//! the tunnel to that node's `run-hop` over the cluster's mutual TLS: the hop is for
//! members only, so a client token cannot call it and skip the check. The node that runs
//! the app starts `VIA --socket S server -- ARGV…` (VIA is `waypipe` unless said) with S
//! in a private directory, and joins S to the tunnel; the `kith` command runs
//! `VIA --socket L client` on its side. `argv` is an array end to end, never a shell line.

use super::{ApiError, permit};
use crate::Shared;
use crate::access::Caller;
use crate::cluster::{Peer, refuse};
use crate::pki::{self, Subject};
use axum::Extension;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use kith_api::kinds::Verb;
use kith_api::store::Error;
use kith_api::{DEFAULT_NAMESPACE, Resource};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::future::Future;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::sync::watch;

/// How long the app has to connect to its socket, and the second node to answer.
const START: Duration = Duration::from_secs(30);
const HOP: Duration = Duration::from_secs(15);
const PROTOCOL: &str = "kith-run";

#[derive(Serialize, Deserialize)]
pub struct Spec {
    pub on: String,
    pub via: Option<String>,
    pub argv: Vec<String>,
    pub namespace: Option<String>,
    /// On the hop only: who asked the first node.
    #[serde(default)]
    pub caller: String,
}

fn say(status: StatusCode, why: impl Display) -> Response {
    refuse(status, why).into_response()
}

fn invalid(why: String) -> ApiError {
    ApiError::Store(Error::Invalid(why))
}

/// The request's upgrade, and what it asks for. The body is read to its end before anything
/// is answered, which is what lets the connection be taken over afterwards.
async fn take(mut request: Request) -> Result<(Spec, OnUpgrade), (StatusCode, String)> {
    if request.headers().get(header::UPGRADE).is_none_or(|v| v != PROTOCOL) {
        return Err((StatusCode::BAD_REQUEST, format!("ask with `Upgrade: {PROTOCOL}`")));
    }
    let upgrade = hyper::upgrade::on(&mut request);
    let bytes = to_bytes(request.into_body(), 64 << 10)
        .await
        .map_err(|e| (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()))?;
    let spec: Spec = serde_json::from_slice(&bytes).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if spec.argv.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "argv names no program".into()));
    }
    Ok((spec, upgrade))
}

/// The node to run on, and where to reach it (`None`: this one). `on` is a node's name, or
/// `key=value[,key=value]`: the first Node, by name, that is ready and has all these labels.
// ponytail: labels by equality only; no set-based selectors, no choosing by load.
fn resolve(shared: &Shared, on: &str) -> Result<(String, Option<String>), ApiError> {
    let me = shared.cluster.as_ref().map_or("local", |c| c.me.name.as_str());
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let ready = |node: &Resource| node.status.as_ref().is_some_and(|s| s["state"] == "ready");
    let node = if on.contains('=') {
        let wants = on.split(',').map(|pair| {
            pair.split_once('=')
                .ok_or_else(|| invalid(format!("{pair:?} in {on:?} is not key=value")))
        });
        let wants = wants.collect::<Result<Vec<_>, _>>()?;
        let has = |node: &Resource| {
            wants
                .iter()
                .all(|(k, v)| node.metadata.labels.get(*k).is_some_and(|l| l == v))
        };
        let mut nodes = state.store.list(Some("Node"));
        nodes
            .find(|node| ready(node) && has(node))
            .ok_or_else(|| ApiError::Store(Error::NotFound(format!("no ready Node has the labels {on}"))))?
    } else if on == me {
        return Ok((me.into(), None));
    } else {
        let node = state.store.get(&format!("Node/{on}"));
        let node = node.ok_or_else(|| ApiError::Store(Error::NotFound(format!("there is no node {on}"))))?;
        if !ready(node) {
            return Err(invalid(format!("node {on} is unreachable")));
        }
        node
    };
    let name = node.metadata.name.clone();
    if name == me {
        return Ok((name, None));
    }
    match node.status.as_ref().and_then(|s| s["address"].as_str()) {
        Some(address) => Ok((name, Some(address.into()))),
        None => Err(invalid(format!("node {name} has no address"))),
    }
}

fn audit(shared: &Shared, who: &impl Display, node: &str, spec: &Spec, outcome: Result<(), String>) {
    let via = spec.via.as_deref().unwrap_or("waypipe");
    let what = [format!("node {node}"), format!("via {via}")];
    shared.audit.record(
        who,
        "run",
        what.into_iter().chain(spec.argv.iter().cloned()).collect(),
        outcome,
    );
}

/// `POST /v1/run`: the first node. Checks the caller, writes it down, and runs the app
/// here or has the node it is for run it.
pub async fn run(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    request: Request,
) -> Response {
    let (spec, upgrade) = match take(request).await {
        Ok(taken) => taken,
        Err((status, why)) => return say(status, why),
    };
    let namespace = spec.namespace.clone().unwrap_or_else(|| DEFAULT_NAMESPACE.into());
    if let Err(refused) = permit(&shared, &caller, Verb::Apply, |_| vec![("Job".into(), Some(namespace))]) {
        return refused.into_response();
    }
    let (node, address) = match resolve(&shared, &spec.on) {
        Ok(found) => found,
        Err(e) => return e.into_response(),
    };
    let Some(address) = address else {
        return start(&shared, &caller, &node, spec, upgrade);
    };
    forward(&shared, &caller, &node, &address, spec, upgrade).await
}

/// Passes the tunnel to `address`'s `run-hop`, as this node.
async fn forward(
    shared: &Arc<Shared>,
    caller: &Caller,
    node: &str,
    address: &str,
    spec: Spec,
    upgrade: OnUpgrade,
) -> Response {
    let Some(cluster) = &shared.cluster else {
        return say(StatusCode::UNPROCESSABLE_ENTITY, "this kithd is not part of a cluster");
    };
    audit(shared, caller, node, &spec, Ok(()));
    let failed = |status, why: String| {
        audit(shared, caller, node, &spec, Err(why.clone()));
        say(status, why)
    };
    let hop = Spec {
        caller: caller.to_string(),
        on: spec.on.clone(),
        via: spec.via.clone(),
        argv: spec.argv.clone(),
        namespace: spec.namespace.clone(),
    };
    let send = cluster
        .client
        .post(format!("https://{address}/v1/run-hop"))
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, PROTOCOL)
        .json(&hop)
        .send();
    let reply = match tokio::time::timeout(HOP, send).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(e)) => return failed(StatusCode::BAD_GATEWAY, format!("node {node} did not answer: {e}")),
        Err(_) => {
            return failed(
                StatusCode::GATEWAY_TIMEOUT,
                format!("node {node} did not answer in time"),
            );
        }
    };
    if reply.status() != StatusCode::SWITCHING_PROTOCOLS {
        let status = reply.status();
        let said = reply.text().await.unwrap_or_default();
        audit(
            shared,
            caller,
            node,
            &spec,
            Err(format!("node {node} said {status}: {said}")),
        );
        return (status, [(header::CONTENT_TYPE, "application/json")], said).into_response();
    }
    let Ok(far) = reply.upgrade().await else {
        return failed(StatusCode::BAD_GATEWAY, format!("node {node} did not give the tunnel"));
    };
    let stop = shared.stop.subscribe();
    switch(upgrade, move |near| join(stop, near, far))
}

/// `POST /v1/run-hop`: the node the app is for, asked by the first node (members only).
pub async fn hop(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: Request,
) -> Response {
    let Some(Subject::Node(from)) = peer.subject else {
        return say(StatusCode::FORBIDDEN, "this is for the cluster's nodes");
    };
    let (spec, upgrade) = match take(request).await {
        Ok(taken) => taken,
        Err((status, why)) => return say(status, why),
    };
    let me = shared
        .cluster
        .as_ref()
        .map_or("local", |c| c.me.name.as_str())
        .to_string();
    let who = format!("{} via node {from}", spec.caller);
    start(&shared, &who, &me, spec, upgrade)
}

/// Writes the run down, starts the app, and joins it to the tunnel once it is up.
fn start(shared: &Arc<Shared>, who: &impl Display, node: &str, spec: Spec, upgrade: OnUpgrade) -> Response {
    audit(shared, who, node, &spec, Ok(()));
    let app = match App::start(node, &spec) {
        Ok(app) => app,
        Err(why) => {
            audit(shared, who, node, &spec, Err(why.clone()));
            return say(StatusCode::UNPROCESSABLE_ENTITY, why);
        }
    };
    let stop = shared.stop.subscribe();
    switch(upgrade, move |tunnel| app.serve(stop, tunnel))
}

/// Answers 101 and, once the connection is ours, does `work` with it.
fn switch<F: Future<Output = ()> + Send + 'static>(
    upgrade: OnUpgrade,
    work: impl FnOnce(TokioIo<Upgraded>) -> F + Send + 'static,
) -> Response {
    tokio::spawn(async move {
        if let Ok(upgraded) = upgrade.await {
            work(TokioIo::new(upgraded)).await;
        }
    });
    let mut reply = Response::new(Body::empty());
    *reply.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    reply
        .headers_mut()
        .insert(header::CONNECTION, "upgrade".parse().expect("a header value"));
    reply
        .headers_mut()
        .insert(header::UPGRADE, PROTOCOL.parse().expect("a header value"));
    reply
}

/// Copies both ways until both ends are done, either fails, or kithd is told to stop.
async fn join(
    mut stop: watch::Receiver<bool>,
    mut a: impl AsyncRead + AsyncWrite + Unpin,
    mut b: impl AsyncRead + AsyncWrite + Unpin,
) {
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut a, &mut b) => {}
        _ = stop.wait_for(|stopped| *stopped) => {}
    }
}

/// A directory only kithd's user can enter, with a name nobody can guess, gone when dropped.
struct Dir(PathBuf);

impl Dir {
    fn make() -> Result<Dir, String> {
        let mut random = [0u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| "no random numbers".to_string())?;
        let path = std::env::temp_dir().join(format!("kith-run-{}", pki::hex(&random)));
        let made = std::fs::DirBuilder::new().mode(0o700).create(&path);
        made.map_err(|e| format!("cannot make {}: {e}", path.display()))?;
        Ok(Dir(path))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// `VIA --socket S server -- ARGV…`, started and waiting for the tunnel's other end.
struct App {
    child: Child,
    listener: UnixListener,
    _dir: Dir,
}

impl App {
    // ponytail: one tunnel carries one connection of the app to VIA; the `kith` command
    // starts VIA's client for it, so an app that opens a second Wayland connection through
    // another VIA process needs its own `kith run`.
    // ponytail: VIA and the app run as kithd's user; whoever may apply a Job may already
    // run anything as it. A grandchild that outlives VIA's kill (VIA's own app) is not hunted.
    fn start(node: &str, spec: &Spec) -> Result<App, String> {
        let via = spec.via.as_deref().unwrap_or("waypipe");
        let dir = Dir::make()?;
        let socket = dir.0.join("s");
        let listener =
            UnixListener::bind(&socket).map_err(|e| format!("cannot listen on {}: {e}", socket.display()))?;
        let mut command = Command::new(via);
        command
            .arg("--socket")
            .arg(&socket)
            .args(["server", "--"])
            .args(&spec.argv)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true);
        let child = command.spawn().map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => format!("{via} is not installed on node {node} (kith does not ship it)"),
            _ => format!("cannot start {via} on node {node}: {e}"),
        })?;
        Ok(App {
            child,
            listener,
            _dir: dir,
        })
    }

    /// Waits for VIA to connect, joins it to `tunnel`, and when either end is done kills VIA
    /// and waits for it.
    async fn serve(mut self, mut stop: watch::Receiver<bool>, tunnel: impl AsyncRead + AsyncWrite + Unpin) {
        let connected = tokio::select! {
            accepted = self.listener.accept() => accepted.ok(),
            _ = self.child.wait() => None,
            _ = tokio::time::sleep(START) => None,
            _ = stop.wait_for(|stopped| *stopped) => None,
        };
        if let Some((connection, _)) = connected {
            join(stop, tunnel, connection).await;
        }
        drop(self.child.kill().await);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{self, Cluster};
    use crate::pki::{Ca, Identity};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::OnceLock;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    /// What waypipe would be: `--socket S server -- APP…` joins APP's input and output
    /// to the socket S, and tells APP where S is.
    const STAND_IN: &str = r#"#!/usr/bin/env python3
import os, socket, subprocess, sys
args = sys.argv[1:]
if args[0] != "--socket" or args[2:4] != ["server", "--"]:
    sys.exit(3)
s = socket.socket(socket.AF_UNIX)
s.connect(args[1])
os.environ["KITH_TEST_SOCKET"] = args[1]
sys.exit(subprocess.run(args[4:], stdin=s, stdout=s).returncode)
"#;

    fn stand_in() -> &'static str {
        static PATH: OnceLock<String> = OnceLock::new();
        PATH.get_or_init(|| {
            let path = std::env::temp_dir().join(format!("kith-run-on-stand-in-{}", std::process::id()));
            std::fs::write(&path, STAND_IN).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.display().to_string()
        })
    }

    /// Two kithds in this process, `a` and `b`, each serving the node API on a loopback
    /// port with its own certificate from one CA. Only `a` has Identities and Nodes.
    struct World {
        a: Arc<Shared>,
        b: Arc<Shared>,
        a_port: u16,
        b_port: u16,
        ca: Ca,
    }

    const ROLES: &str = "
apiVersion: kith.dev/v1
kind: Role
metadata: {name: jobber}
spec:
  rules:
    - {kinds: [Job], verbs: [apply]}
---
apiVersion: kith.dev/v1
kind: Role
metadata: {name: other-jobber}
spec:
  rules:
    - {kinds: [Job], verbs: [apply], namespaces: [other]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: alice-jobber}
spec: {role: jobber, subjects: [alice]}
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: {name: carol-other}
spec: {role: other-jobber, subjects: [carol]}
";

    impl World {
        async fn new(tag: &str) -> World {
            let dir = std::env::temp_dir().join(format!("kithd-run-on-{tag}-{}", std::process::id()));
            let ca = Ca::create().unwrap();
            let mut nodes = Vec::new();
            for name in ["a", "b"] {
                let (cert, key) = ca.issue(name).unwrap();
                let me = Identity {
                    name: name.into(),
                    ca: ca.cert.clone(),
                    cert,
                    key,
                };
                let shared = crate::replica(Some(Cluster::new(me.clone(), None).unwrap()), &dir.join(name)).await;
                let shared = shared.unwrap();
                let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = tcp.local_addr().unwrap().port();
                let listener = cluster::listen(tcp, pki::server_config(&me).unwrap()).unwrap();
                let app = cluster::node_router(shared.clone()).into_make_service_with_connect_info::<Peer>();
                tokio::spawn(async move { drop(axum::serve(listener, app).await) });
                nodes.push((shared, port));
            }
            let [(a, a_port), (b, b_port)] = <[_; 2]>::try_from(nodes).ok().unwrap();
            let world = World {
                a,
                b,
                a_port,
                b_port,
                ca,
            };
            let source = |name: &str, labels: &str| {
                format!(
                    "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}, labels: {{{labels}}}}}\nspec: {{}}\n"
                )
            };
            world.node("a", "", Some(a_port));
            world.node("b", "role: display", Some(b_port));
            let _ = source;
            let mut state = world.a.store.lock().unwrap();
            for resource in kith_api::Resource::from_source(ROLES).unwrap() {
                state.store.apply(resource.unwrap()).unwrap();
            }
            drop(state);
            world
        }

        /// A Node of `a`'s store: ready, and at `port` unless it is not (`None`: unreachable).
        fn node(&self, name: &str, labels: &str, port: Option<u16>) {
            let text = format!(
                "apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{name: {name}, labels: {{{labels}}}}}\nspec: {{}}\n"
            );
            let resource = kith_api::Resource::from_source(&text).unwrap().remove(0).unwrap();
            let status = match port {
                Some(port) => json!({"address": format!("127.0.0.1:{port}"), "state": "ready"}),
                None => json!({"address": "127.0.0.1:1", "state": "unreachable"}),
            };
            let mut state = self.a.store.lock().unwrap();
            state.store.apply(resource).unwrap();
            state.store.set_status(&format!("Node/{name}"), Some(status)).unwrap();
        }

        /// A client that shows the certificate of the Identity `name` (made now, on `a`).
        fn user(&self, name: &str) -> reqwest::Client {
            let (cert, key, public) = self.ca.issue_user(name).unwrap();
            let identity = json!({
                "apiVersion": kith_api::API_VERSION, "kind": "Identity",
                "metadata": {"name": name}, "spec": {"publicKey": public},
            });
            let identity = serde_json::from_value(identity).unwrap();
            self.a.store.lock().unwrap().store.apply(identity).unwrap();
            let me = Identity {
                name: name.into(),
                ca: self.ca.cert.clone(),
                cert,
                key,
            };
            Self::client(pki::client_config(&me.ca, Some(&me)).unwrap())
        }

        fn client(config: rustls::ClientConfig) -> reqwest::Client {
            reqwest::Client::builder()
                .use_preconfigured_tls(config)
                .no_proxy()
                .build()
                .unwrap()
        }
    }

    /// Asks for a tunnel: the byte stream, or why not.
    async fn tunnel(
        client: &reqwest::Client,
        port: u16,
        path: &str,
        spec: serde_json::Value,
    ) -> Result<reqwest::Upgraded, (u16, String)> {
        let reply = client
            .post(format!("https://127.0.0.1:{port}{path}"))
            .header(reqwest::header::CONNECTION, "upgrade")
            .header(reqwest::header::UPGRADE, "kith-run")
            .json(&spec)
            .send()
            .await
            .unwrap();
        let status = reply.status().as_u16();
        if status != 101 {
            let said: serde_json::Value = reply.json().await.unwrap_or_default();
            return Err((status, said["error"].as_str().unwrap_or_default().to_string()));
        }
        Ok(reply.upgrade().await.unwrap())
    }

    async fn gone(path: &str) -> bool {
        for _ in 0..100 {
            if !Path::new(path).exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// An app that says what it was given and where its socket is, answers one line, and
    /// then waits for the tunnel to close. Through `on`, as alice.
    async fn tunnel_to(on: &str) {
        let world = World::new(&format!("tunnel-{on}")).await;
        let alice = world.user("alice");
        let line = "echo \"$1:$PPID:$KITH_TEST_SOCKET\"; read line; echo \"$1:$line\"; read line";
        let argv = ["sh", "-c", line, "sh", "two words; $(touch pwned)"];
        let spec = json!({"on": on, "via": stand_in(), "argv": argv});
        let tunnel = tunnel(&alice, world.a_port, "/v1/run", spec).await.unwrap();
        let mut tunnel = BufReader::new(tunnel);
        let mut first = String::new();
        tunnel.read_line(&mut first).await.unwrap();
        let parts: Vec<&str> = first.trim_end().splitn(3, ':').collect();
        let [arg, pid, socket] = parts.as_slice() else {
            panic!("the app said {first:?}")
        };
        // argv is an array: nothing of it went through a shell.
        assert_eq!(*arg, "two words; $(touch pwned)");
        assert!(!std::env::current_dir().unwrap().join("pwned").exists());
        // The socket is in a private directory with a name nobody can guess.
        let dir = Path::new(socket).parent().unwrap();
        let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{}", dir.display());
        assert!(dir.file_name().unwrap().len() > 32, "{}", dir.display());
        tunnel.get_mut().write_all(b"ping\n").await.unwrap();
        let mut second = String::new();
        tunnel.read_line(&mut second).await.unwrap();
        assert_eq!(second, "two words; $(touch pwned):ping\n");

        // The audit entry names alice and the node; on another node it carries alice's name over.
        let (here, there) = (world.a.audit.tail(10).unwrap(), world.b.audit.tail(10).unwrap());
        let ran = |entries: &[serde_json::Value]| entries.iter().find(|entry| entry["verb"] == "run").cloned();
        let entry = ran(&here).expect("no run entry on the first node");
        assert_eq!((&entry["who"], &entry["ok"]), (&json!("alice"), &json!(true)));
        assert_eq!(entry["what"][0], format!("node {on}"));
        assert_eq!(entry["what"][2], "sh");
        if on == "b" {
            assert_eq!(ran(&there).unwrap()["who"], "alice via node a");
        }

        // Either end closing ends the app, which is waited for, and the directory goes.
        drop(tunnel);
        assert!(gone(&dir.display().to_string()).await, "the directory stays");
        assert!(gone(&format!("/proc/{pid}")).await, "the program stays");
    }

    #[tokio::test]
    async fn run_on_another_node_joins_the_tunnel_to_the_app_there() {
        tunnel_to("b").await;
    }

    #[tokio::test]
    async fn run_on_this_node_needs_no_second_hop() {
        tunnel_to("a").await;
    }

    #[tokio::test]
    async fn run_on_refuses_a_caller_who_may_not_apply_jobs_before_anything_starts() {
        let world = World::new("refused").await;
        let spec = json!({"on": "b", "via": stand_in(), "argv": ["true"]});
        let bob = world.user("bob");
        let (status, why) = tunnel(&bob, world.a_port, "/v1/run", spec.clone()).await.unwrap_err();
        assert_eq!(status, 403);
        assert!(why.contains("bob may not apply Job"), "{why}");
        // Carol may apply Jobs in `other`, not in `default`.
        let carol = world.user("carol");
        let (status, _) = tunnel(&carol, world.a_port, "/v1/run", spec.clone()).await.unwrap_err();
        assert_eq!(status, 403);
        let there = json!({"on": "b", "via": "/nonexistent/waypipe", "argv": ["true"], "namespace": "other"});
        let (status, _) = tunnel(&carol, world.a_port, "/v1/run", there).await.unwrap_err();
        assert_eq!(
            status, 422,
            "carol passes the check in her namespace and fails on the program"
        );
        // The refusals are written down on the first node; the second never heard of them.
        let entries = world.a.audit.tail(10).unwrap();
        let refused: Vec<_> = entries.iter().filter(|entry| entry["ok"] == false).collect();
        assert_eq!(refused[0]["who"], "bob");
        assert_eq!(refused[1]["who"], "carol");
        // The second node heard only of carol's allowed one (written, then failed on the program).
        let there = world.b.audit.tail(10).unwrap();
        assert!(
            there.iter().all(|entry| entry["who"] == "carol via node a"),
            "{there:?}"
        );
        assert_eq!(there.len(), 2);
    }

    #[tokio::test]
    async fn run_on_names_a_program_that_is_not_there_and_writes_the_audit_first() {
        let world = World::new("missing").await;
        let alice = world.user("alice");
        let spec = json!({"on": "b", "via": "/nonexistent/waypipe", "argv": ["true"]});
        let (status, why) = tunnel(&alice, world.a_port, "/v1/run", spec).await.unwrap_err();
        assert_eq!(status, 422);
        assert!(why.contains("/nonexistent/waypipe") && why.contains("node b"), "{why}");
        // Written before the program was started (ok), and again with what went wrong.
        let entries = world.b.audit.tail(10).unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(
            (&entries[0]["who"], &entries[0]["ok"]),
            (&json!("alice via node a"), &json!(true))
        );
        assert_eq!(entries[1]["ok"], false);
    }

    #[tokio::test]
    async fn run_on_the_hop_is_for_nodes_not_for_a_client_token() {
        let world = World::new("hop").await;
        let spec = json!({"on": "b", "via": stand_in(), "argv": ["true"], "caller": "root"});
        // Alice may apply Jobs, and still cannot ask the second node herself.
        let alice = world.user("alice");
        let (status, why) = tunnel(&alice, world.b_port, "/v1/run-hop", spec.clone())
            .await
            .unwrap_err();
        assert_eq!((status, why.contains("not for an Identity")), (403, true), "{why}");
        // Nor can a certificate that is no one's, or none.
        let none = World::client(pki::client_config(&world.ca.cert, None).unwrap());
        let (status, _) = tunnel(&none, world.b_port, "/v1/run-hop", spec).await.unwrap_err();
        assert_eq!(status, 401);
        assert!(
            world
                .b
                .audit
                .tail(10)
                .map_or(true, |entries| entries.iter().all(|e| e["verb"] != "run"))
        );
        // And the first node does not open the hop to Identities either.
        let spec = json!({"on": "a", "via": stand_in(), "argv": ["true"], "caller": "root"});
        let (status, _) = tunnel(&alice, world.a_port, "/v1/run-hop", spec).await.unwrap_err();
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn run_on_a_selector_is_the_first_ready_node_with_the_labels() {
        let world = World::new("selector").await;
        world.node("aa", "role: display", None);
        world.node("c", "role: display, zone: x", Some(1));
        let said = |on: &str| resolve(&world.a, on).map_err(|e| e.into_response().status().as_u16());
        let at = |port: u16| Some(format!("127.0.0.1:{port}"));
        assert_eq!(said("role=display"), Ok(("b".into(), at(world.b_port))));
        assert_eq!(said("role=display,zone=x"), Ok(("c".into(), at(1))));
        assert_eq!(said("a"), Ok(("a".into(), None)));
        assert_eq!(said("b"), Ok(("b".into(), at(world.b_port))));
        assert_eq!(said("role=nothing"), Err(404));
        assert_eq!(said("nobody"), Err(404));
        assert_eq!(said("aa"), Err(422));
        assert_eq!(said("role=display,oops"), Err(422));
    }
}
