//! Several kithd on one machine, as a cluster. Opt-in like the other e2e tests:
//!
//! ```sh
//! KITH_E2E=1 cargo test -p kithd --test cluster
//! ```

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
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
    /// Start a kithd named `name` with its state under `test`, plus `args`.
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
        let node = Node {
            child: Node::spawn(&dir, name, port, args),
            dir,
            port,
        };
        wait_for("kithd to serve", || node.dir.join("kithd.sock").exists());
        node
    }

    fn spawn(dir: &Path, name: &str, port: u16, args: &[&str]) -> Child {
        Command::new(env!("CARGO_BIN_EXE_kithd"))
            .current_dir(dir)
            .args(["--state", "state", "--socket", "kithd.sock", "--name", name])
            .args(["--listen", &format!("127.0.0.1:{port}")])
            .args(args)
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Run `kith` against this node; returns (exit code, stdout, stderr).
    fn kith(&self, args: &[&str]) -> (i32, String, String) {
        let kith = Path::new(env!("CARGO_BIN_EXE_kithd")).with_file_name("kith");
        let out = Command::new(kith)
            .args(args)
            .current_dir(&self.dir)
            .env("KITH_SOCKET", self.dir.join("kithd.sock"))
            .env_remove("KITH_STORE")
            .output()
            .unwrap();
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
        (out.status.code().unwrap(), text(out.stdout), text(out.stderr))
    }

    fn ok(&self, args: &[&str]) -> String {
        let (code, out, err) = self.kith(args);
        assert_eq!(code, 0, "kith {args:?}: {err}");
        out
    }

    /// The name and address of every Node this node lists.
    fn nodes(&self) -> Vec<(String, String)> {
        let nodes: serde_json::Value = serde_json::from_str(&self.ok(&["get", "node", "-o", "json"])).unwrap();
        let name_and_address = |node: &serde_json::Value| {
            let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_string();
            (text(&node["metadata"]["name"]), text(&node["status"]["address"]))
        };
        nodes.as_array().unwrap().iter().map(name_and_address).collect()
    }

    fn stop(&mut self) {
        let _ = Command::new("kill").arg(self.child.id().to_string()).status();
        let _ = self.child.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Run a kithd that is expected to give up; returns what it said.
fn kithd_fails(dir: &Path, args: &[&str]) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_kithd"))
        .current_dir(dir)
        .args(["--state", "state", "--socket", "kithd.sock", "--listen", "127.0.0.1:0"])
        .args(args)
        .output()
        .unwrap();
    assert!(!out.status.success(), "kithd {args:?} was expected to fail");
    String::from_utf8(out.stderr).unwrap()
}

/// A raw HTTPS request with no client certificate; returns the status code.
fn status_without_certificate(address: &str, path: &str) -> String {
    let out = Command::new("curl")
        .args(["-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5"])
        .arg(format!("https://{address}{path}"))
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn nodes_join_over_mutual_tls() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "join";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    assert_eq!(alpha.nodes(), [("alpha".to_string(), alpha.address())]);

    // Without a certificate only the CA can be read: no resources, and no joining without a token.
    assert_eq!(status_without_certificate(&alpha.address(), "/v1/ca"), "200");
    assert_eq!(status_without_certificate(&alpha.address(), "/v1/resources"), "401");
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test);
    let join = |dir: &str, name: &str, token: &str| {
        let args = ["--name", name, "--join", &alpha.address(), "--token", token];
        let _ = std::fs::remove_dir_all(scratch.join(dir));
        kithd_fails(&scratch.join(dir), &args)
    };
    let zeros = "0".repeat(64);
    let said = join("x1", "x1", &format!("kith1.{zeros}.{zeros}"));
    assert!(said.contains("its CA does not match the token"), "{said}");

    let token = alpha.ok(&["node", "token"]);
    let token = token.trim();
    // A token for this cluster, but not one alpha made.
    let said = join(
        "x2",
        "x2",
        &format!("kith1.{zeros}.{}", token.rsplit('.').next().unwrap()),
    );
    assert!(said.contains("the join token is wrong"), "{said}");
    // A name that is taken does not spend the token.
    let said = join("x3", "alpha", token);
    assert!(said.contains("already in the cluster"), "{said}");

    let mut beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token]);
    let both = [
        ("alpha".to_string(), alpha.address()),
        ("beta".to_string(), beta.address()),
    ];
    assert_eq!(alpha.nodes(), both);
    // beta is sent the store, and a change made through beta is seen on alpha.
    wait_for("beta to have the store", || beta.nodes() == both);
    let config = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: shared }\nspec: { data: { a: b } }\n";
    std::fs::write(beta.dir.join("cm.yaml"), config).unwrap();
    beta.ok(&["apply", "-f", "cm.yaml"]);
    assert!(alpha.ok(&["get", "ConfigMap/shared"]).contains("shared"));
    // beta's own port is for members only too.
    assert_eq!(status_without_certificate(&beta.address(), "/v1/resources"), "401");
    // Only the node with the CA key admits nodes, and beta says so.
    let (code, _, err) = beta.kith(&["node", "token"]);
    assert!(code != 0 && err.contains("the one the cluster was started on"), "{err}");
    // A state directory that holds a store is not thrown away by joining.
    std::fs::create_dir_all(scratch.join("x5/state/raft")).unwrap();
    let args = ["--name", "x5", "--join", &alpha.address(), "--token", token];
    let said = kithd_fails(&scratch.join("x5"), &args);
    assert!(said.contains("already holds a store"), "{said}");

    // The token was good once.
    let said = join("x4", "gamma", token);
    assert!(said.contains("the join token is wrong"), "{said}");

    // beta is still a member after a restart, with no token.
    beta.stop();
    beta.child = Node::spawn(&beta.dir, "beta", beta.port, &[]);
    wait_for("beta to answer again", || beta.kith(&["get", "node"]).0 == 0);
    assert_eq!(beta.nodes(), both);
    assert!(beta.ok(&["get", "ConfigMap/shared"]).contains("shared"));
}

#[test]
fn the_store_survives_its_leader() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "raft";
    let mut alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let join = |name: &str| {
        let token = alpha.ok(&["node", "token"]);
        Node::start(test, name, &["--join", &alpha.address(), "--token", token.trim()])
    };
    let (beta, gamma) = (join("beta"), join("gamma"));
    // With three nodes all three vote, and alpha, where it started, still leads.
    let status = |node: &Node| node.ok(&["node", "status"]);
    wait_for("three voters", || {
        [&alpha, &beta, &gamma]
            .iter()
            .all(|node| status(node).contains("voters:    alpha, beta, gamma"))
    });
    assert!(status(&gamma).contains("leader:    alpha"), "{}", status(&gamma));
    // The nodes hear from each other, and the leader writes that down.
    let states = |node: &Node| {
        let nodes: serde_json::Value = serde_json::from_str(&node.ok(&["get", "node", "-o", "json"])).unwrap();
        let state = |node: &serde_json::Value| node["status"]["state"].as_str().unwrap_or("-").to_string();
        nodes.as_array().unwrap().iter().map(state).collect::<Vec<_>>()
    };
    wait_for("three ready nodes", || states(&gamma) == ["ready", "ready", "ready"]);

    // A change made through a node that does not lead is on every node.
    let config = |name: &str| {
        format!(
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{ name: {name} }}\nspec: {{ data: {{ a: b }} }}\n"
        )
    };
    std::fs::write(gamma.dir.join("before.yaml"), config("before")).unwrap();
    gamma.ok(&["apply", "-f", "before.yaml"]);
    assert!(gamma.ok(&["get", "ConfigMap/before"]).contains("before"));
    wait_for("the change on beta", || beta.kith(&["get", "ConfigMap/before"]).0 == 0);

    // The leader dies without a word: the two that are left pick one of themselves and go on.
    let _ = Command::new("kill")
        .args(["-9", &alpha.child.id().to_string()])
        .status();
    let _ = alpha.child.wait();
    std::fs::write(beta.dir.join("after.yaml"), config("after")).unwrap();
    wait_for("a change without alpha", || {
        beta.kith(&["apply", "-f", "after.yaml"]).0 == 0
    });
    wait_for("that change on gamma", || {
        gamma.kith(&["get", "ConfigMap/after"]).0 == 0
    });
    assert!(!status(&beta).contains("leader:    alpha"), "{}", status(&beta));
    // Nobody hears from alpha any more: after ten seconds the new leader says so.
    wait_for("alpha to be called unreachable", || {
        states(&beta) == ["unreachable", "ready", "ready"]
    });
    assert!(beta.ok(&["get", "node"]).contains("unreachable"));

    // alpha comes back with what it had, and is sent what it missed.
    alpha.child = Node::spawn(&alpha.dir, "alpha", alpha.port, &[]);
    wait_for("alpha to catch up", || alpha.kith(&["get", "ConfigMap/after"]).0 == 0);
    assert!(alpha.ok(&["get", "ConfigMap/before"]).contains("before"));
    assert_eq!(alpha.nodes().len(), 3);
    wait_for("alpha to be ready again", || {
        states(&alpha) == ["ready", "ready", "ready"]
    });
}

#[test]
fn a_node_that_is_down_is_not_made_a_voter() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "down";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let join = |name: &str| {
        let token = alpha.ok(&["node", "token"]);
        Node::start(test, name, &["--join", &alpha.address(), "--token", token.trim()])
    };
    // beta joins and is gone before there is a third node; then gamma joins.
    let mut beta = join("beta");
    wait_for("beta to have the store", || beta.nodes().len() == 2);
    beta.stop();
    let gamma = join("gamma");
    wait_for("gamma to have the store", || gamma.nodes().len() == 3);
    // Three nodes, but voting with beta would leave alpha unable to agree with anyone
    // should gamma go too: alpha goes on alone, and changes still go through.
    std::thread::sleep(Duration::from_secs(8));
    assert!(alpha.ok(&["node", "status"]).contains("voters:    alpha\n"));
    let config = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: still }\nspec: { data: { a: b } }\n";
    std::fs::write(gamma.dir.join("cm.yaml"), config).unwrap();
    gamma.ok(&["apply", "-f", "cm.yaml"]);

    // beta is back: now all three vote, and beta has what it missed.
    beta.child = Node::spawn(&beta.dir, "beta", beta.port, &[]);
    wait_for("three voters", || {
        alpha.ok(&["node", "status"]).contains("voters:    alpha, beta, gamma")
    });
    wait_for("beta to catch up", || beta.kith(&["get", "ConfigMap/still"]).0 == 0);
}
