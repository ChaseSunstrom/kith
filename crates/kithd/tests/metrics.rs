//! `GET /v1/metrics` over two kithd on one machine (127.0.0.1 only). Opt-in like the other e2e tests:
//!
//! ```sh
//! KITH_E2E=1 cargo test -p kithd --test metrics
//! ```

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    // (The first point is one 10 s tick after start, and a loaded host is given room.)
    let deadline = Instant::now() + Duration::from_secs(90);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

struct Node {
    child: Child,
    dir: PathBuf,
    port: u16,
}

impl Node {
    fn start(test: &str, name: &str, args: &[&str]) -> Node {
        let built = Command::new(env!("CARGO"))
            .args(["build", "--quiet", "-p", "kith-cli"])
            .status()
            .unwrap();
        assert!(built.success());
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_kithd"))
            .current_dir(&dir)
            .args(["--state", "state", "--socket", "kithd.sock", "--name", name])
            .args(["--listen", &format!("127.0.0.1:{port}"), "--registry-port", "0"])
            .args(args)
            .stdin(Stdio::null())
            .stderr(std::fs::File::create(dir.join("kithd.log")).unwrap())
            .spawn()
            .unwrap();
        let mut node = Node { child, dir, port };
        wait_for("kithd to serve", || {
            assert!(node.child.try_wait().unwrap().is_none(), "kithd exited early");
            node.dir.join("kithd.sock").exists()
        });
        node
    }

    fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn ok(&self, args: &[&str]) -> String {
        let kith = Path::new(env!("CARGO_BIN_EXE_kithd")).with_file_name("kith");
        let out = Command::new(kith)
            .args(args)
            .current_dir(&self.dir)
            .env("KITH_SOCKET", "kithd.sock")
            .env_remove("KITH_STORE")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "kith {args:?}: {err}");
        String::from_utf8(out.stdout).unwrap()
    }

    /// The status and body of `path` asked on the local socket, as the admin.
    fn get(&self, path: &str) -> (u16, serde_json::Value) {
        let out = Command::new("curl")
            .current_dir(&self.dir)
            .args([
                "-s",
                "--max-time",
                "20",
                "--unix-socket",
                "kithd.sock",
                "-w",
                "\n%{http_code}",
            ])
            .arg(format!("http://localhost{path}"))
            .output()
            .unwrap();
        parse(&String::from_utf8(out.stdout).unwrap())
    }

    /// The same over the TLS port, as the Identity whose certificate is in `dir`.
    fn get_as(&self, dir: &str, name: &str, path: &str) -> (u16, serde_json::Value) {
        let file = |file: String| self.dir.join(dir).join(file);
        let out = Command::new("curl")
            .args(["-sk", "--max-time", "20", "-w", "\n%{http_code}"])
            .arg("--cert")
            .arg(file(format!("{name}.crt")))
            .arg("--key")
            .arg(file(format!("{name}.key")))
            .arg(format!("https://{}{path}", self.address()))
            .output()
            .unwrap();
        parse(&String::from_utf8(out.stdout).unwrap())
    }

    fn stop(&mut self) {
        let _ = Command::new("kill")
            .arg(self.child.id().to_string())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
        if std::thread::panicking() {
            let log = std::fs::read_to_string(self.dir.join("kithd.log")).unwrap_or_default();
            eprintln!("--- console of {} ---\n{log}", self.dir.display());
        }
    }
}

fn parse(out: &str) -> (u16, serde_json::Value) {
    let (body, status) = out.rsplit_once('\n').unwrap_or_default();
    (
        status.parse().unwrap_or(0),
        serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
    )
}

/// A series is as long as the range says, and holds numbers or nulls.
fn series(value: &serde_json::Value, len: usize) -> Vec<Option<f64>> {
    let all = value.as_array().unwrap_or_else(|| panic!("not an array: {value}"));
    assert_eq!(all.len(), len, "{value}");
    all.iter().map(|point| point.as_f64()).collect()
}

#[test]
fn metrics_series_of_a_cluster_with_a_stopped_node_and_an_identity() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "metrics";
    let alpha = Node::start(test, "alpha", &[]);
    let token = alpha.ok(&["node", "token"]);
    let mut beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);

    // Both nodes' series come from alpha: its own, and beta's over the node-to-node connection.
    let mut answer = serde_json::Value::Null;
    wait_for("a point from each node", || {
        let (status, body) = alpha.get("/v1/metrics?range=15m");
        let has = |node: &str| {
            let cpu = &body["nodes"][node]["cpu"];
            cpu.as_array()
                .is_some_and(|cpu| cpu.iter().any(|point| point.is_number()))
        };
        let ready = status == 200 && has("alpha") && has("beta");
        answer = body;
        ready
    });
    assert_eq!(answer["range"], "15m");
    assert_eq!(answer["step"], 10);
    assert_eq!(answer["end"].as_u64().unwrap() % 10, 0, "{answer}");
    for name in ["alpha", "beta"] {
        let node = &answer["nodes"][name];
        assert!(node.get("missing").is_none(), "{name}: {node}");
        for field in ["cpu", "mem", "disk", "diskRead", "diskWrite", "rx", "tx", "load1"] {
            series(&node[field], 90);
        }
        assert!(node["cpus"].as_u64().unwrap() > 0, "{node}");
        assert!(node["memTotal"].as_u64().unwrap() > 0, "{node}");
        assert!(node["diskTotal"].as_u64().unwrap() > 0, "{node}");
        let cpu = series(&node["cpu"], 90);
        assert!(cpu.iter().flatten().all(|c| (0.0..=1.0).contains(c)), "{cpu:?}");
        // Oldest first: what has been sampled is at the end, the gap before it is null.
        assert!(cpu[89].is_some() || cpu[88].is_some(), "{cpu:?}");
        assert!(cpu[0].is_none(), "{cpu:?}");
    }
    assert!(answer["workloads"].is_object(), "{answer}");

    // Other ranges are as long as they say; one that is not a range is refused.
    let (status, body) = alpha.get("/v1/metrics?range=24h");
    assert_eq!((status, body["step"].as_u64()), (200, Some(300)), "{body}");
    series(&body["nodes"]["alpha"]["cpu"], 288);
    let (status, body) = alpha.get("/v1/metrics?range=2d");
    assert_eq!(status, 422, "{body}");

    // An Identity is let in by the right to read Nodes, and by nothing less.
    std::fs::create_dir_all(alpha.dir.join("alice")).unwrap();
    alpha.ok(&["identity", "cert", "alice", "--out", "alice"]);
    let (status, body) = alpha.get_as("alice", "alice", "/v1/metrics?range=15m");
    assert_eq!(status, 403, "{body}");
    let roles = "apiVersion: kith.dev/v1
kind: Role
metadata: { name: configs }
spec: { rules: [{ kinds: [ConfigMap], verbs: [get, list] }] }
---
apiVersion: kith.dev/v1
kind: RoleBinding
metadata: { name: alice-configs }
spec: { role: configs, subjects: [alice] }
";
    std::fs::write(alpha.dir.join("roles.yaml"), roles).unwrap();
    alpha.ok(&["apply", "-f", "roles.yaml"]);
    // (A Role for ConfigMaps is no right to Nodes.)
    let (status, body) = alpha.get_as("alice", "alice", "/v1/metrics?range=15m");
    assert_eq!(status, 403, "{body}");
    let nodes = roles
        .replace("ConfigMap", "Node")
        .replace("alice-configs", "alice-nodes");
    std::fs::write(alpha.dir.join("roles.yaml"), nodes).unwrap();
    alpha.ok(&["apply", "-f", "roles.yaml"]);
    wait_for("alice to read the metrics", || {
        alpha.get_as("alice", "alice", "/v1/metrics?range=15m").0 == 200
    });

    // The nodes' own route (every Workload's series, unfiltered) is for nodes, not for an Identity.
    let (status, body) = alpha.get_as("alice", "alice", "/v1/node-metrics?range=15m");
    assert_ne!(status, 200, "{body}");
    assert!(body.get("workloads").is_none(), "{body}");

    // A node that does not answer is marked missing, and the others still come back, in time.
    beta.stop();
    let started = Instant::now();
    let (status, body) = alpha.get("/v1/metrics?range=1h");
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["nodes"]["beta"]["missing"], true, "{body}");
    series(&body["nodes"]["beta"]["cpu"], 360);
    assert!(body["nodes"]["alpha"].get("missing").is_none(), "{body}");
    assert!(series(&body["nodes"]["alpha"]["cpu"], 360).iter().any(Option::is_some));
}
