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
    /// The address it listens on.
    host: String,
}

impl Node {
    /// Start a kithd named `name` with its state under `test`, plus `args`.
    fn start(test: &str, name: &str, args: &[&str]) -> Node {
        Node::start_in(None, "127.0.0.1", free_port(), test, name, args)
    }

    /// The same, listening on `host:port`, in the network namespace `ns` if there is one.
    fn start_in(ns: Option<&str>, host: &str, port: u16, test: &str, name: &str, args: &[&str]) -> Node {
        let built = Command::new(env!("CARGO"))
            .args(["build", "--quiet", "-p", "kith-cli"])
            .status()
            .unwrap();
        assert!(built.success());
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let node = Node {
            child: Node::spawn_in(ns, host, &dir, name, port, args),
            dir,
            port,
            host: host.to_string(),
        };
        wait_for("kithd to serve", || node.dir.join("kithd.sock").exists());
        node
    }

    fn spawn(dir: &Path, name: &str, port: u16, args: &[&str]) -> Child {
        Node::spawn_in(None, "127.0.0.1", dir, name, port, args)
    }

    fn spawn_in(ns: Option<&str>, host: &str, dir: &Path, name: &str, port: u16, args: &[&str]) -> Child {
        let kithd = env!("CARGO_BIN_EXE_kithd");
        let mut command = match ns {
            // (nsenter, not `ip netns exec`: that hides the cgroups kithd puts its units in.)
            Some(ns) => {
                let mut command = Command::new("nsenter");
                command.arg(format!("--net=/run/netns/{ns}")).arg(kithd);
                command
            }
            None => Command::new(kithd),
        };
        command
            .current_dir(dir)
            .args(["--state", "state", "--socket", "kithd.sock", "--name", name])
            .args(["--listen", &format!("{host}:{port}")])
            .args(args)
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
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
    // A token that names no node (as tokens from before did) is sent to whoever answers.
    let said = join("x1", "x1", &format!("kith1.{zeros}.{zeros}"));
    assert!(said.contains("its CA does not match the token"), "{said}");
    assert!(said.contains("this token names no node"), "{said}");

    let token = alpha.ok(&["node", "token"]);
    let token = token.trim();
    // A token for this cluster, but not one alpha made.
    let said = join(
        "x2",
        "x2",
        &format!("kith1.{zeros}.{}", token.split('.').nth(2).unwrap()),
    );
    assert!(said.contains("the join token is wrong"), "{said}");
    assert!(said.contains("this token names no node"), "{said}");
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
    // A token of alpha's taken to another node of the cluster: beta is sent nothing, and
    // the joiner says who it called and who answered.
    let elsewhere = alpha.ok(&["node", "token"]);
    let args = ["--name", "x6", "--join", &beta.address(), "--token", elsewhere.trim()];
    let _ = std::fs::remove_dir_all(scratch.join("x6"));
    let said = kithd_fails(&scratch.join("x6"), &args);
    assert!(said.contains("node alpha was called, and node beta answered"), "{said}");
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

/// A raw HTTPS request with the node certificate kept in `dir`; returns the status code.
fn status_as_node(address: &str, dir: &Path, method: &str, path: &str) -> String {
    let out = Command::new("curl")
        .args([
            "-sk",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "5",
            "-X",
            method,
        ])
        .arg("--cert")
        .arg(dir.join("node.crt"))
        .arg("--key")
        .arg(dir.join("node.key"))
        .arg(format!("https://{address}{path}"))
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()
}

/// (Not behind KITH_E2E: it pulls nothing, and a test that is skipped proves nothing.)
#[test]
fn an_evicted_nodes_certificate_is_refused_at_once_and_stays_refused() {
    let test = "evicted";
    let mut alpha = Node::start(test, "alpha", &[]);
    let address = alpha.address();
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    // A join goes through the check: beta is sent the store, and writes through alpha.
    let token = alpha.ok(&["node", "token"]);
    let mut beta = Node::start(test, "beta", &["--join", &address, "--token", token.trim()]);
    wait_for("beta to have the store", || beta.nodes().len() == 2);
    let config = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: shared }\nspec: { data: { a: b } }\n";
    std::fs::write(beta.dir.join("cm.yaml"), config).unwrap();
    beta.ok(&["apply", "-f", "cm.yaml"]);

    // The certificate beta was given, as whoever took the machine would have it.
    let taken = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test).join("taken");
    let _ = std::fs::remove_dir_all(&taken);
    std::fs::create_dir_all(&taken).unwrap();
    for file in ["node.crt", "node.key"] {
        std::fs::copy(beta.dir.join("state/pki").join(file), taken.join(file)).unwrap();
    }
    let api = || status_as_node(&address, &taken, "GET", "/v1/resources");
    // (A node route: what is posted is not a write, and a member is told so.)
    let route = || status_as_node(&address, &taken, "POST", "/v1/raft/write");
    // (403, not 401: it is taken for the node it is, and a node has no right of its own on the API.)
    assert_eq!(api(), "403");
    assert!(!["401", "403"].contains(&route().as_str()), "{}", route());

    // Deleted: refused by the next request, with alpha never restarted.
    alpha.ok(&["delete", "node/beta"]);
    assert_eq!((api(), route()), ("401".to_string(), "401".to_string()));
    beta.stop();
    // A Node of that name made by hand admits nobody: it never joined.
    let node = "apiVersion: kith.dev/v1\nkind: Node\nmetadata: { name: beta }\nspec: {}\n";
    std::fs::write(alpha.dir.join("node.yaml"), node).unwrap();
    alpha.ok(&["apply", "-f", "node.yaml"]);
    assert_eq!((api(), route()), ("401".to_string(), "401".to_string()));
    alpha.ok(&["delete", "node/beta"]);

    // A node that joins under the name has a certificate of its own; the old one stays out.
    let token = alpha.ok(&["node", "token"]);
    let beta = Node::start(test, "beta", &["--join", &address, "--token", token.trim()]);
    wait_for("the new beta to have the store", || beta.nodes().len() == 2);
    assert_eq!(
        status_as_node(&address, &beta.dir.join("state/pki"), "GET", "/v1/resources"),
        "403"
    );
    assert_eq!((api(), route()), ("401".to_string(), "401".to_string()));
    assert!(beta.ok(&["get", "ConfigMap/shared"]).contains("shared"));
    // The new node refuses it too, by the store it was sent.
    assert_eq!(status_as_node(&beta.address(), &taken, "GET", "/v1/resources"), "401");
    assert_eq!(status_as_node(&beta.address(), &taken, "POST", "/v1/raft/write"), "401");

    // For a cluster locked out of itself: a node started with the switch takes it again.
    alpha.stop();
    alpha.child = Node::spawn(&alpha.dir, "alpha", alpha.port, &["--admit-deleted-nodes"]);
    wait_for("alpha to answer again", || alpha.kith(&["get", "node"]).0 == 0);
    wait_for("the old certificate to be taken", || api() == "403");
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
fn a_blob_put_on_one_node_is_held_by_two_and_read_through_any() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "blob";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let join = |name: &str| {
        let token = alpha.ok(&["node", "token"]);
        Node::start(test, name, &["--join", &alpha.address(), "--token", token.trim()])
    };
    let (beta, gamma) = (join("beta"), join("gamma"));
    let nodes = [&alpha, &beta, &gamma];
    wait_for("three nodes with addresses", || {
        nodes
            .iter()
            .all(|node| node.nodes().iter().filter(|(_, at)| !at.is_empty()).count() == 3)
    });

    // Not text, and long enough to come in more than one piece.
    let bytes: Vec<u8> = (0..300_000u32)
        .flat_map(|n| n.wrapping_mul(2_654_435_761).to_be_bytes())
        .collect();
    std::fs::write(alpha.dir.join("in"), &bytes).unwrap();
    let name = alpha.ok(&["blob", "put", "in"]).trim().to_string();
    assert_eq!(name.len(), 62, "{name}");
    // The same bytes again, through another node: the same name, and still one Blob.
    std::fs::write(gamma.dir.join("in"), &bytes).unwrap();
    assert_eq!(gamma.ok(&["blob", "put", "in"]).trim(), name);

    // Two nodes hold it in the end, whichever it was put on, and say so.
    let has = |node: &Node| node.dir.join("state/blobs").join(&name).exists();
    let holders = |node: &Node| {
        let blob: serde_json::Value = serde_json::from_str(&node.ok(&["get", "blob", &name, "-o", "json"])).unwrap();
        let blob = blob.as_array().map_or(blob.clone(), |found| found[0].clone());
        let nodes = blob["status"]["nodes"].as_array().cloned().unwrap_or_default();
        nodes
            .iter()
            .map(|node| node.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    wait_for("two nodes to hold the blob", || {
        nodes.iter().filter(|node| has(node)).count() == 2 && holders(&beta).len() == 2
    });
    for node in nodes {
        let named = node.dir.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(holders(&beta).contains(&named), has(node), "{named}");
        // Read through every node: the one that holds none passes on another's.
        node.ok(&["blob", "get", &name, "-o", "out"]);
        assert!(std::fs::read(node.dir.join("out")).unwrap() == bytes, "through {named}");
    }

    // Knowing a blob's name is not having its bytes: a Blob for it in another namespace
    // cannot be applied, so nothing reads them through one.
    let stolen = format!(
        "apiVersion: kith.dev/v1\nkind: Namespace\nmetadata: {{ name: other }}\n---\napiVersion: kith.dev/v1\nkind: Blob\nmetadata: {{ name: {name}, namespace: other }}\nspec: {{ size: 1 }}\n"
    );
    std::fs::write(beta.dir.join("stolen.yaml"), stolen).unwrap();
    let (code, _, err) = beta.kith(&["apply", "-f", "stolen.yaml"]);
    assert!(
        code != 0 && err.contains("a Blob is made by putting its bytes"),
        "{err}"
    );
    assert!(beta.kith(&["blob", "get", &name, "-n", "other"]).0 != 0);

    // Bytes on a node's disk that are not the blob's are never taken for it.
    let (code, _, err) = alpha.kith(&["blob", "get", &"0".repeat(62)]);
    assert!(code != 0 && err.contains("not found"), "{err}");
    let (code, _, err) = alpha.kith(&["blob", "get", "../../kithd.sock"]);
    assert!(code != 0, "{err}");
}

#[test]
fn a_backup_of_a_volume_is_held_by_two_nodes_and_restored_through_another() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "backup";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("two nodes with addresses", || {
        alpha.nodes().iter().filter(|(_, at)| !at.is_empty()).count() == 2
    });

    // What is in the volume on beta before there is a Backup of it.
    let data = beta.dir.join("state/volumes/default/data/d");
    std::fs::create_dir_all(data.join("deep")).unwrap();
    std::fs::write(data.join("deep/file"), b"what must not be lost").unwrap();
    let yaml = "apiVersion: kith.dev/v1\nkind: Volume\nmetadata: { name: data }\nspec: { node: beta, path: d }\n---\n\
                apiVersion: kith.dev/v1\nkind: Backup\nmetadata: { name: often }\nspec: { volume: data, every: 1d, keep: 2 }\n";
    std::fs::write(alpha.dir.join("backup.yaml"), yaml).unwrap();
    alpha.ok(&["apply", "-f", "backup.yaml"]);

    // Beta makes it; the blob it is in is held by both nodes.
    let status = |node: &Node, kind: &str, name: &str| {
        let found: serde_json::Value = serde_json::from_str(&node.ok(&["get", kind, name, "-o", "json"])).unwrap();
        found.as_array().map_or(found.clone(), |found| found[0].clone())["status"].clone()
    };
    wait_for("the backup to be made", || {
        status(&alpha, "backup", "often")["backups"][0]["blob"].is_string()
    });
    let made = status(&alpha, "backup", "often")["backups"][0].clone();
    let blob = made["blob"].as_str().unwrap().to_string();
    wait_for("both nodes to hold the backup", || {
        status(&alpha, "blob", &blob)["nodes"]
            .as_array()
            .is_some_and(|nodes| nodes.len() == 2)
    });
    assert!(alpha.dir.join("state/blobs").join(&blob).exists());

    // Over what is there: refused. The volume lost and made again: restored, asked through alpha.
    let (code, _, err) = alpha.kith(&["backup", "restore", "often"]);
    assert!(code != 0 && err.contains("restored into an empty volume"), "{err}");
    std::fs::remove_dir_all(&data).unwrap();
    let said = alpha.ok(&["backup", "restore", "often", "--at", &made["at"].to_string()]);
    assert!(said.contains("is back in volume data on node beta"), "{said}");
    assert_eq!(std::fs::read(data.join("deep/file")).unwrap(), b"what must not be lost");
    let (code, _, err) = alpha.kith(&["backup", "restore", "often", "--at", "1"]);
    assert!(code != 0 && err.contains("no such backup"), "{err}");
}

#[test]
fn volume_files_go_in_and_come_out_through_another_node() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "volume-files";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("two nodes with addresses", || {
        alpha.nodes().iter().filter(|(_, at)| !at.is_empty()).count() == 2
    });
    let yaml = "apiVersion: kith.dev/v1\nkind: Volume\nmetadata: { name: data }\nspec: { node: beta, path: d }\n---\n\
                apiVersion: kith.dev/v1\nkind: Volume\nmetadata: { name: copy }\nspec: { node: alpha, path: c }\n";
    std::fs::write(alpha.dir.join("volume.yaml"), yaml).unwrap();
    alpha.ok(&["apply", "-f", "volume.yaml"]);

    // A directory on alpha's machine, one file of it longer than anything is held in at once.
    let src = alpha.dir.join("src");
    let long: Vec<u8> = (0..3_000_000u32).map(|n| (n % 251) as u8).collect();
    std::fs::create_dir_all(src.join("deep")).unwrap();
    std::fs::write(src.join("deep/file"), b"what a guest kept").unwrap();
    std::fs::write(src.join("long"), &long).unwrap();
    std::os::unix::fs::symlink("/etc", src.join("out")).unwrap();
    let data = beta.dir.join("state/volumes/default/data/d");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("there"), b"before").unwrap();

    // In through alpha: on beta, beside what was there, less the link that points out.
    let (code, said, err) = alpha.kith(&["volume", "put", "data", "src"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(said.trim(), "2 files (3000017 bytes) are in volume data on node beta");
    assert!(
        err.contains("left out, a link that points out of the volume: out -> /etc"),
        "{err}"
    );
    assert_eq!(std::fs::read(data.join("deep/file")).unwrap(), b"what a guest kept");
    assert!(std::fs::read(data.join("long")).unwrap() == long);
    assert_eq!(std::fs::read(data.join("there")).unwrap(), b"before");
    assert!(std::fs::symlink_metadata(data.join("out")).is_err() && !data.join(".kith-put").exists());
    // One file goes in under its name.
    alpha.ok(&["volume", "put", "data", "src/deep/file"]);
    assert_eq!(std::fs::read(data.join("file")).unwrap(), b"what a guest kept");

    // Out through alpha, into a directory there.
    alpha.ok(&["volume", "get", "data", "back"]);
    let back = alpha.dir.join("back");
    assert_eq!(std::fs::read(back.join("deep/file")).unwrap(), b"what a guest kept");
    assert!(std::fs::read(back.join("long")).unwrap() == long);
    assert_eq!(std::fs::read(back.join("there")).unwrap(), b"before");

    // As a tar, out of one Volume and into another, with no tar program between.
    let kith = Path::new(env!("CARGO_BIN_EXE_kithd")).with_file_name("kith");
    let piped = format!("{0} volume get data - | {0} volume put copy -", kith.display());
    let piped = Command::new("sh")
        .args(["-c", &piped])
        .env("KITH_SOCKET", beta.dir.join("kithd.sock"))
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&piped.stdout);
    assert!(said.contains("are in volume copy on node alpha"), "{said} {piped:?}");
    assert!(std::fs::read(alpha.dir.join("state/volumes/default/copy/c/long")).unwrap() == long);

    // A stream that is refused at its first entry says why, though far more was to come.
    let evil = "import io, sys, tarfile\n\
                tar = tarfile.open(fileobj=sys.stdout.buffer, mode='w|')\n\
                for name, size in (('../evil', 1), ('long', 50_000_000)):\n\
                \x20   entry = tarfile.TarInfo(name)\n\
                \x20   entry.size = size\n\
                \x20   tar.addfile(entry, io.BytesIO(bytes(size)))\n\
                tar.close()\n";
    std::fs::write(alpha.dir.join("evil.py"), evil).unwrap();
    let piped = format!("python3 evil.py | {} volume put data -", kith.display());
    let piped = Command::new("sh")
        .args(["-c", &piped])
        .current_dir(&alpha.dir)
        .env("KITH_SOCKET", alpha.dir.join("kithd.sock"))
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&piped.stderr);
    assert!(
        !piped.status.success() && err.contains("../evil: a path that leaves the volume"),
        "{err}"
    );
    assert!(!data.join(".kith-put").exists() && !beta.dir.join("state/volumes/default/data/evil").exists());

    // What cannot be: said, and nothing done.
    let (code, _, err) = alpha.kith(&["volume", "put", "nope", "src"]);
    assert!(code != 0 && err.contains("Volume/default/nope"), "{err}");
    let (code, _, err) = alpha.kith(&["volume", "put", "data", "missing"]);
    assert!(code != 0 && err.contains("missing"), "{err}");
    std::fs::remove_file(data.join("there")).unwrap();
    std::fs::create_dir(data.join("long.d")).unwrap();
    std::fs::rename(src.join("long"), src.join("long.d")).unwrap();
    let (code, _, err) = alpha.kith(&["volume", "put", "data", "src"]);
    assert!(code != 0 && err.contains("long.d: a directory in the volume"), "{err}");
    assert!(!data.join(".kith-put").exists());
}

#[test]
fn relays_reach_the_node_they_name() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "relays";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let mut beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("two nodes with addresses", || {
        alpha.nodes().iter().filter(|(_, at)| !at.is_empty()).count() == 2
    });
    let yaml = "apiVersion: kith.dev/v1\nkind: Volume\nmetadata: { name: data }\nspec: { node: beta, path: d }\n";
    std::fs::write(alpha.dir.join("volume.yaml"), yaml).unwrap();
    alpha.ok(&["apply", "-f", "volume.yaml"]);
    // (Beta is asked about the Volume by alpha's relay: it has to have heard of it.)
    wait_for("beta to have the Volume", || beta.kith(&["get", "Volume/data"]).0 == 0);
    let src = alpha.dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("file"), b"for beta and no other").unwrap();
    let data = beta.dir.join("state/volumes/default/data/d");
    std::fs::create_dir_all(&data).unwrap();

    // The node the Volume is on gets what is sent to it, through alpha.
    alpha.ok(&["volume", "put", "data", "src"]);
    assert_eq!(std::fs::read(data.join("file")).unwrap(), b"for beta and no other");

    // Beta is gone, and another node of the cluster answers at its address: the CA signed it, and
    // it is not beta. What alpha relays for beta is not sent to it.
    let (port, token) = (beta.port, alpha.ok(&["node", "token"]));
    beta.stop();
    let gamma = Node::start_in(
        None,
        "127.0.0.1",
        port,
        test,
        "gamma",
        &["--join", &alpha.address(), "--token", token.trim()],
    );
    wait_for("gamma to be listed", || {
        alpha.nodes().iter().any(|(name, _)| name == "gamma")
    });
    for args in [
        &["volume", "put", "data", "src"][..],
        &["volume", "get", "data", "back"],
    ] {
        let (code, _, err) = alpha.kith(args);
        assert!(
            code != 0 && err.contains("node beta was called, and node gamma answered"),
            "{args:?}: {err}"
        );
    }
    assert!(std::fs::read_dir(alpha.dir.join("back")).is_ok_and(|mut back| back.next().is_none()));
    assert!(!gamma.dir.join("state/volumes/default/data").exists());
}

#[test]
fn a_volumes_replica_has_its_files_and_takes_over_when_its_node_is_lost() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "replica";
    let mut alpha = Node::start(test, "alpha", &["--lost-after", "3"]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let join = |name: &str| {
        let token = alpha.ok(&["node", "token"]);
        let args = ["--join", &alpha.address(), "--token", token.trim(), "--lost-after", "3"];
        Node::start(test, name, &args)
    };
    let (beta, gamma) = (join("beta"), join("gamma"));
    wait_for("three voters", || {
        beta.ok(&["node", "status"]).contains("voters:    alpha, beta, gamma")
    });

    let data = |node: &Node| node.dir.join("state/volumes/default/data/d");
    std::fs::create_dir_all(data(&alpha)).unwrap();
    std::fs::write(data(&alpha).join("file"), "first").unwrap();
    let yaml = "apiVersion: kith.dev/v1\nkind: Volume\nmetadata: { name: data }\nspec: { node: alpha, path: d, replicas: 2, sync: 10s }\n";
    std::fs::write(beta.dir.join("volume.yaml"), yaml).unwrap();
    beta.ok(&["apply", "-f", "volume.yaml"]);

    // One of the other two is picked, and has the file; then what the file became.
    let status = |node: &Node| {
        let found: serde_json::Value =
            serde_json::from_str(&node.ok(&["get", "volume", "data", "-o", "json"])).unwrap();
        found.as_array().map_or(found.clone(), |found| found[0].clone())["status"].clone()
    };
    wait_for("a replica to be picked", || status(&beta)["replicas"][0].is_string());
    assert_eq!(status(&beta)["primary"], "alpha");
    let picked = status(&beta)["replicas"][0].as_str().unwrap().to_string();
    let (replica, other) = if picked == "beta" {
        (&beta, &gamma)
    } else {
        (&gamma, &beta)
    };
    let has = |node: &Node, text: &str| std::fs::read_to_string(data(node).join("file")).is_ok_and(|file| file == text);
    wait_for("the replica to have the file", || has(replica, "first"));
    std::fs::write(data(&alpha).join("file"), "second").unwrap();
    wait_for("the replica to have what the file became", || has(replica, "second"));
    assert!(!data(other).exists(), "a node that is no replica has no copy");

    // The volume's node is lost: the replica has the volume now, and the third node the copy.
    alpha.stop();
    wait_for("the replica to take over", || {
        other.kith(&["get", "node"]).0 == 0 && status(other)["primary"] == picked.as_str()
    });
    assert!(has(replica, "second"));
    let third = other.dir.file_name().unwrap().to_string_lossy().into_owned();
    wait_for("the third node to be the replica", || {
        status(other)["replicas"][0] == third.as_str()
    });
    wait_for("the third node to have the file", || has(other, "second"));
}

/// A worker (`spec.trust`, said by whoever made its join token) never votes however much of
/// the store it has, a control node made one stops, the CA key stays where the cluster was
/// started, and the last control node is not made a worker.
#[test]
fn ca_key_stays_with_the_control_nodes_and_a_worker_never_votes() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "trust";
    let mut alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let address = alpha.address();
    let join = |alpha: &Node, name: &str, token: &[&str]| {
        let token = alpha.ok(&[&["node", "token"], token].concat());
        Node::start(test, name, &["--join", &address, "--token", token.trim()])
    };
    let beta = join(&alpha, "beta", &["--worker"]);
    let gamma = join(&alpha, "gamma", &["--worker"]);
    wait_for("the workers to have the store", || {
        beta.nodes().len() == 3 && gamma.nodes().len() == 3
    });
    let listed: serde_json::Value = serde_json::from_str(&alpha.ok(&["get", "node", "-o", "json"])).unwrap();
    let trusts: Vec<_> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|node| node["spec"]["trust"].clone())
        .collect();
    assert_eq!(
        serde_json::json!(trusts),
        serde_json::json!([null, "worker", "worker"]),
        "{listed}"
    );
    // Three nodes that have the store, and one voter: the workers only receive it.
    std::thread::sleep(Duration::from_secs(8));
    assert!(alpha.ok(&["node", "status"]).contains("voters:    alpha\n"));
    // Neither was handed the CA key, and neither can let a node in.
    for worker in [&beta, &gamma] {
        let mut kept = Vec::new();
        let mut dirs = vec![worker.dir.clone()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                match entry.file_type().unwrap().is_dir() {
                    true => dirs.push(entry.path()),
                    false => kept.push(entry.file_name().to_string_lossy().into_owned()),
                }
            }
        }
        assert!(
            kept.contains(&"ca.crt".to_string()) && !kept.contains(&"ca.key".to_string()),
            "{kept:?}"
        );
        let (code, _, err) = worker.kith(&["node", "token"]);
        assert!(code != 0 && err.contains("the one the cluster was started on"), "{err}");
    }
    // The node that holds the CA key is not made a worker: it lets every other node in.
    let trust = |alpha: &Node, name: &str, trust: &str| {
        let node =
            format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{ name: {name} }}\nspec: {{ trust: {trust} }}\n");
        std::fs::write(alpha.dir.join("node.yaml"), node).unwrap();
        alpha.kith(&["apply", "-f", "node.yaml"])
    };
    let (code, _, err) = trust(&alpha, "alpha", "worker");
    assert!(code != 0 && err.contains("holds the cluster's CA key"), "{err}");
    // Two more control nodes: three voters, the workers left out.
    let delta = join(&alpha, "delta", &[]);
    let epsilon = join(&alpha, "epsilon", &[]);
    wait_for("three control nodes to vote", || {
        alpha
            .ok(&["node", "status"])
            .contains("voters:    alpha, delta, epsilon")
    });
    // Another node leads (alpha is gone for a moment), and is then made a worker: the others
    // stop following it at once, one of them leads, and it no longer votes.
    let said = |node: &Node, what: &str| {
        let (code, status, _) = node.kith(&["node", "status"]);
        let line = status.lines().find(|line| line.starts_with(what));
        line.filter(|_| code == 0)
            .map(|line| line[what.len()..].trim().to_string())
    };
    alpha.stop();
    wait_for("delta or epsilon to lead", || {
        said(&delta, "leader:").is_some_and(|leader| leader == "delta" || leader == "epsilon")
    });
    let leader = said(&delta, "leader:").unwrap();
    alpha.child = Node::spawn(&alpha.dir, "alpha", alpha.port, &[]);
    wait_for("alpha to answer again", || alpha.kith(&["get", "node"]).0 == 0);
    wait_for("the leader to be made a worker", || {
        trust(&alpha, &leader, "worker").0 == 0
    });
    wait_for("a control node to lead and the worker to stop voting", || {
        let leads = said(&alpha, "leader:").is_some_and(|now| now != leader && now != "none");
        leads && said(&alpha, "voters:").is_some_and(|voters| !voters.contains(&leader))
    });
    // A change still goes through, and the worker still has it.
    // (A kind a worker is sent whole: it runs from a view of the store now.)
    let config = "apiVersion: kith.dev/v1\nkind: Namespace\nmetadata: { name: after }\nspec: {}\n";
    std::fs::write(alpha.dir.join("ns.yaml"), config).unwrap();
    wait_for("a change to go through", || {
        alpha.kith(&["apply", "-f", "ns.yaml"]).0 == 0
    });
    let demoted = if leader == "delta" { &delta } else { &epsilon };
    wait_for("the worker to have the change", || {
        demoted.kith(&["get", "Namespace/after"]).0 == 0
    });
    // It was sent the whole store until it was made a worker: that copy is erased, and the
    // node that leads sends it no more of it.
    wait_for("the worker to run from a view", || {
        demoted.dir.join("state/view.json").exists() && !demoted.dir.join("state/raft/snapshot.json").exists()
    });
    wait_for("the store to be sent to control nodes only", || {
        let sent = |what: &str| said(&alpha, what).is_some_and(|nodes| nodes.contains(&leader));
        said(&alpha, "receiving:").is_some() && !sent("receiving:") && !sent("voters:")
    });
}

/// A raw HTTPS request with the node certificate kept in `dir`, and `body` as JSON if there
/// is one; returns the status code and what was answered.
fn ask_as_node(address: &str, dir: &Path, method: &str, path: &str, body: Option<&str>) -> (String, String) {
    let mut curl = Command::new("curl");
    curl.args(["-sk", "-w", "\n%{http_code}", "--max-time", "15", "-X", method]);
    if let Some(body) = body {
        curl.args(["-H", "content-type: application/json", "-d", body]);
    }
    curl.arg("--cert").arg(dir.join("node.crt"));
    curl.arg("--key").arg(dir.join("node.key"));
    let out = curl.arg(format!("https://{address}{path}")).output().unwrap();
    let out = String::from_utf8_lossy(&out.stdout).into_owned();
    let (said, code) = out.rsplit_once('\n').unwrap_or(("", &out));
    (code.to_string(), said.to_string())
}

/// A worker's own units are still said to run, and what is not a worker's to write is
/// refused on the route nodes write by, whatever its certificate is admitted to; the other
/// node routes hand it no blob nothing on it names and no Volume it is no replica of.
#[test]
fn a_worker_writes_only_what_it_says_of_itself() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    use serde_json::json;
    let test = "wlist";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token", "--worker"]);
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("two ready nodes", || {
        alpha.kith(&["get", "node"]).1.matches("ready at").count() == 2
    });
    // What it says of itself goes through: its copy of a NodeWorkload runs and is said to.
    let agent = "apiVersion: kith.dev/v1\nkind: NodeWorkload\nmetadata: { name: agent }\nspec:\n  \
        template:\n    exec: [{ name: run, command: [sh, -c, 'echo up; exec sleep 300'] }]\n";
    std::fs::write(alpha.dir.join("agent.yaml"), agent).unwrap();
    alpha.ok(&["apply", "-f", "agent.yaml"]);
    wait_for("the worker's copy to be said to run", || {
        let agent = alpha.ok(&["get", "nodeworkload/agent", "-o", "json"]);
        let agent: serde_json::Value = serde_json::from_str(&agent).unwrap();
        let units = agent["status"]["containers"].as_array().cloned().unwrap_or_default();
        units
            .iter()
            .any(|unit| unit["node"] == "beta" && unit["state"] == "running")
    });
    let (alphas, betas) = (alpha.dir.join("state/pki"), beta.dir.join("state/pki"));
    // The route nodes write by, with the worker's certificate, for what is not its to write.
    let write = |command: serde_json::Value| {
        let body = command.to_string();
        let (code, said) = ask_as_node(&alpha.address(), &betas, "POST", "/v1/raft/write", Some(&body));
        format!("{code} {said}")
    };
    let forged = json!({ "apiVersion": "kith.dev/v1", "kind": "ConfigMap", "metadata": { "name": "forged" },
        "spec": { "data": { "a": "b" } } });
    for forged in [
        json!({ "Apply": { "resources": [forged], "at": 0 } }),
        json!({ "Delete": { "key": "Node/alpha" } }),
        json!({ "Patch": { "statuses": [["Node/alpha", { "address": "127.0.0.1:1" }]] } }),
        json!({ "Patch": { "statuses": [["Node/beta", { "certificate": "x" }]] } }),
        json!({ "Report": { "node": "alpha", "statuses": [["NodeWorkload/default/agent", null]] } }),
    ] {
        let said = write(forged.clone());
        assert!(
            said.contains("a worker writes only what it says of itself"),
            "{forged}: {said}"
        );
    }
    assert!(alpha.kith(&["get", "ConfigMap/forged"]).0 != 0);
    assert_eq!(alpha.nodes().len(), 2);
    // Through the worker's own API too: a change is asked of a control node.
    let config = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: here }\nspec: { data: { a: b } }\n";
    std::fs::write(beta.dir.join("cm.yaml"), config).unwrap();
    let (code, _, err) = beta.kith(&["apply", "-f", "cm.yaml"]);
    let why = "ConfigMap/default/here: it is not a worker's to apply: ask a control node";
    assert!(code != 0 && err.contains(why), "{err}");
    // A blob nothing on the worker names is not sent to it, and it is never made a holder.
    std::fs::write(alpha.dir.join("in"), b"bytes a worker has only heard the name of").unwrap();
    let name = alpha.ok(&["blob", "put", "in"]).trim().to_string();
    let copy = format!("/v1/blob-copy/{name}");
    assert_eq!(ask_as_node(&alpha.address(), &alphas, "GET", &copy, None).0, "200");
    let (code, said) = ask_as_node(&alpha.address(), &betas, "GET", &copy, None);
    assert!(
        code == "403" && said.contains("nothing on worker beta names"),
        "{code} {said}"
    );
    // (Three rounds of the blobs' loop: a node that should hold it would have it by now.)
    std::thread::sleep(Duration::from_secs(10));
    assert!(!beta.dir.join("state/blobs").join(&name).exists());
    // Nor a Volume it is no replica of.
    let (code, said) = ask_as_node(&alpha.address(), &betas, "GET", "/v1/volume-copy/default/data", None);
    assert!(code == "403" && said.contains("is no replica"), "{code} {said}");
    // The worker's refused writes are in the control node's audit log, by its name.
    let audit = alpha.ok(&["audit"]);
    assert!(
        audit.contains("beta") && audit.contains("a worker writes only"),
        "{audit}"
    );
}

/// Every file under `dir` that has `text` in it.
fn files_with(dir: &Path, text: &str) -> Vec<PathBuf> {
    let (mut found, mut dirs) = (Vec::new(), vec![dir.to_path_buf()]);
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => dirs.push(path),
                Ok(kind) if kind.is_file() => {
                    let bytes = std::fs::read(&path).unwrap_or_default();
                    if bytes.windows(text.len()).any(|window| window == text.as_bytes()) {
                        found.push(path);
                    }
                }
                _ => {}
            }
        }
    }
    found
}

/// A worker keeps a view of the store, not the store: the Secret of what is placed on it and
/// no other, on its disk and in what it answers; it lets go of that Secret when the Workload
/// leaves, comes back up from its view with no control node in reach, and follows another
/// control node when the one it followed is gone.
#[test]
fn worker_holds_no_secret_that_nothing_placed_on_it_names() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "view";
    let (mine, other) = ("the-word-of-what-runs-on-the-worker", "the-word-of-what-runs-elsewhere");
    let mut alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    // Whether a worker is sent the store is its token's maker's to say, never the node's:
    // one that says it cannot run from a view (it serves ingress) is not let in.
    let token = alpha.ok(&["node", "token", "--worker"]);
    let (address, token) = (alpha.address(), token.trim());
    let args = [
        "--name",
        "refused",
        "--join",
        &address,
        "--token",
        token,
        "--ingress",
        "--mesh",
    ];
    // (With nothing an earlier run left: a node with a certificate does not join again.)
    let refused = alpha.dir.with_file_name("refused");
    let _ = std::fs::remove_dir_all(&refused);
    let said = kithd_fails(&refused, &args);
    assert!(said.contains("kith node token --worker --ingress"), "{said}");
    assert_eq!(alpha.nodes().len(), 1, "a node that was refused is no Node");
    let apply = |node: &Node, text: &str| {
        std::fs::write(node.dir.join("apply.yaml"), text).unwrap();
        node.ok(&["apply", "-f", "apply.yaml"]);
    };
    let workload = |name: &str, trust: &str| {
        format!(
            "apiVersion: kith.dev/v1\nkind: Secret\nmetadata: {{ name: {name} }}\nspec: {{ data: {{ word: {} }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Workload\nmetadata: {{ name: {name} }}\nspec:\n  \
             placement: {{ require: {{ kith.dev/trust: {trust} }} }}\n  template:\n    exec:\n      \
             - name: run\n        command: [sh, -c, 'echo said $WORD; exec sleep 300']\n        \
             env: [{{ name: WORD, secret: {{ name: {name}, key: word }} }}]\n",
            if name == "mine" { mine } else { other }
        )
    };
    // Both Secrets are in the store before the worker joins: it is never sent the store.
    apply(&alpha, &workload("other", "control"));
    apply(&alpha, &workload("mine", "worker"));
    let token = alpha.ok(&["node", "token", "--worker"]);
    let mut beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("the worker to have its view", || beta.nodes().len() == 2);
    // Its Node says so, the store is not sent to it, and it says whom it follows.
    let node: serde_json::Value = serde_json::from_str(&alpha.ok(&["get", "node/beta", "-o", "json"])).unwrap();
    assert_eq!(node["status"]["view"], true, "{node}");
    let status = alpha.ok(&["node", "status"]);
    assert!(status.contains("receiving: \n"), "{status}");
    let status = beta.ok(&["node", "status"]);
    let follows = "a worker: its view of the store is at change";
    assert!(
        status.contains(follows) && status.contains(&alpha.address()),
        "{status}"
    );

    // What is placed on it runs with its Secret, and its output is read through a control node.
    wait_for("the worker's unit to say its word", || {
        alpha.kith(&["logs", "workload/mine"]).1.contains(mine)
    });
    wait_for("the other to run on the control node", || {
        alpha.kith(&["logs", "workload/other"]).1.contains(other)
    });
    // The Secret of what runs elsewhere is nowhere on the worker, and it does not answer with it.
    assert_eq!(files_with(&beta.dir, other), Vec::<PathBuf>::new());
    assert!(files_with(&beta.dir, mine).contains(&beta.dir.join("state/view.json")));
    assert_eq!(beta.kith(&["get", "secret/mine"]).0, 0);
    let (code, _, err) = beta.kith(&["get", "secret/other"]);
    assert!(code != 0 && err.contains("not found"), "{err}");
    // Nothing of Raft's is its to take, and it sends no view itself.
    let alphas = alpha.dir.join("state/pki");
    let (code, said) = ask_as_node(&beta.address(), &alphas, "POST", "/v1/raft/vote", Some("{}"));
    assert!(code == "403" && said.contains("takes no part in it"), "{code} {said}");
    let (code, said) = ask_as_node(&beta.address(), &alphas, "GET", "/v1/view", None);
    assert!(
        code == "403" && said.contains("ask a control node for a view"),
        "{code} {said}"
    );
    // A control node is sent no view, and a person is answered by a control node.
    let (code, said) = ask_as_node(&alpha.address(), &alphas, "GET", "/v1/view", None);
    assert!(code == "403" && said.contains("it keeps the store"), "{code} {said}");
    std::fs::create_dir_all(alpha.dir.join("alice")).unwrap();
    alpha.ok(&["identity", "cert", "alice", "--out", "alice"]);
    for (from, to) in [("alice.crt", "node.crt"), ("alice.key", "node.key")] {
        std::fs::copy(alpha.dir.join("alice").join(from), alpha.dir.join("alice").join(to)).unwrap();
    }
    let alice = alpha.dir.join("alice");
    let (code, said) = ask_as_node(&beta.address(), &alice, "GET", "/v1/resources/Node", None);
    let why = format!(
        "answers no one by their rights: ask a control node ({})",
        alpha.address()
    );
    assert!(code == "403" && said.contains(&why), "{code} {said}");

    // The Workload leaves the worker: its Secret is taken back, off the worker's disk too.
    alpha.ok(&["delete", "workload/mine"]);
    wait_for("the worker to let go of the Secret", || {
        beta.kith(&["get", "secret/mine"]).0 != 0 && files_with(&beta.dir.join("state"), mine).is_empty()
    });

    // With no control node in reach it comes back up from its view.
    beta.stop();
    alpha.stop();
    beta.child = Node::spawn(&beta.dir, "beta", beta.port, &[]);
    wait_for("the worker to answer from its view", || {
        beta.kith(&["get", "node"]).0 == 0 && beta.nodes().len() == 2
    });
    assert_eq!(files_with(&beta.dir.join("state"), other), Vec::<PathBuf>::new());
    // The control node is back, and a second one joins: the worker hears of it.
    alpha.child = Node::spawn(&alpha.dir, "alpha", alpha.port, &[]);
    wait_for("alpha to answer again", || alpha.kith(&["get", "node"]).0 == 0);
    let token = alpha.ok(&["node", "token"]);
    let gamma = Node::start(test, "gamma", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("the worker to hear of the new control node", || beta.nodes().len() == 3);
    wait_for("gamma to have the store", || gamma.nodes().len() == 3);
    // The one it follows goes away: it follows the other.
    alpha.stop();
    wait_for("the worker to follow the other control node", || {
        beta.kith(&["node", "status"]).1.contains(&gamma.address())
    });
    assert_eq!(files_with(&beta.dir.join("state"), other), Vec::<PathBuf>::new());
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

/// A node that was away while another joined is led by that one when it is back: it has not
/// heard of it, asks the voters it last knew, and is told it stands. (A kithd from before the
/// asking took any node it had not heard of, and passes this too: it keeps the asking from
/// shutting a joiner out. That a deleted node is refused is
/// `vouched_lets_in_a_joiner_and_not_a_deleted_node`, in cluster.rs, against voters made up.)
#[test]
fn away_during_a_join_catches_up_from_the_joiner() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "away";
    let mut alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let join = |alpha: &Node, name: &str| {
        let token = alpha.ok(&["node", "token"]);
        Node::start(test, name, &["--join", &alpha.address(), "--token", token.trim()])
    };
    let said = |node: &Node, what: &str| {
        let (code, status, _) = node.kith(&["node", "status"]);
        let line = status.lines().find(|line| line.starts_with(what));
        line.filter(|_| code == 0)
            .map(|line| line[what.len()..].trim().to_string())
    };
    let (mut beta, mut epsilon) = (join(&alpha, "beta"), join(&alpha, "epsilon"));
    wait_for("three voters", || {
        said(&alpha, "voters:").as_deref() == Some("alpha, beta, epsilon")
    });
    // gamma knows alpha, beta and epsilon as voters, and goes away.
    let mut gamma = join(&alpha, "gamma");
    wait_for("gamma to have the store", || gamma.nodes().len() == 4);
    gamma.stop();
    let (state, away) = (gamma.dir.join("state"), gamma.dir.join("away"));
    let copied = Command::new("cp").arg("-a").arg(&state).arg(&away).status().unwrap();
    assert!(copied.success());
    // Meanwhile delta joins and epsilon is deleted: delta votes in its place.
    let delta = join(&alpha, "delta");
    alpha.ok(&["delete", "node/epsilon"]);
    epsilon.stop();
    wait_for("delta to vote", || {
        said(&alpha, "voters:").as_deref() == Some("alpha, beta, delta")
    });
    for attempt in 0.. {
        // Until delta leads: whoever else does is stopped a moment. (Until all three name it: one
        // just back that has not heard from the leader yet would ask for votes, and might lead.)
        let mut fresh = false;
        for round in 0.. {
            let mut leader = None;
            wait_for("all three to name one leader", || {
                leader = said(&delta, "leader:").filter(|leader| leader != "none");
                leader.is_some() && [&alpha, &beta].iter().all(|node| said(node, "leader:") == leader)
            });
            let leader = leader.unwrap();
            if leader == "delta" && fresh {
                break;
            }
            assert!(round < 12, "delta never led");
            if leader == "delta" {
                // A leader stopped and started again leads its old term a moment, and gamma, on
                // an older one still, would take what it sends: alpha and beta start afresh.
                for (node, name) in [(&mut alpha, "alpha"), (&mut beta, "beta")] {
                    node.stop();
                    node.child = Node::spawn(&node.dir, name, node.port, &[]);
                    wait_for("it to answer again", || node.kith(&["get", "node"]).0 == 0);
                }
                fresh = true;
                continue;
            }
            fresh = false;
            let node = if leader == "alpha" { &mut alpha } else { &mut beta };
            node.stop();
            wait_for("another to lead", || {
                said(&delta, "leader:").is_some_and(|now| now != leader && now != "none")
            });
            node.child = Node::spawn(&node.dir, &leader, node.port, &[]);
            wait_for("it to answer again", || node.kith(&["get", "node"]).0 == 0);
        }
        // gamma is back as it went away: it is sent the store by delta, which it has not heard
        // of, and follows it.
        let _ = std::fs::remove_dir_all(&state);
        let copied = Command::new("cp").arg("-a").arg(&away).arg(&state).status().unwrap();
        assert!(copied.success());
        gamma.child = Node::spawn(&gamma.dir, "gamma", gamma.port, &[]);
        // Had another led a moment (a loaded machine misses heartbeats), gamma could take the
        // store from it and prove nothing: that try is let go and gamma starts over. (Another
        // leads for an election's timeout at least, a second or more: the voters are asked often.)
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut led = None;
        while led.is_none() {
            assert!(Instant::now() < deadline, "gamma never caught up from delta");
            std::thread::sleep(Duration::from_millis(50));
            let another = |node: &Node| said(node, "leader:").is_some_and(|it| it != "delta" && it != "none");
            if [&delta, &alpha, &beta].into_iter().any(another) {
                led = Some(false);
            } else if said(&gamma, "leader:").as_deref() == Some("delta") {
                let names: Vec<_> = gamma.nodes().into_iter().map(|(name, _)| name).collect();
                let caught_up = names.contains(&"delta".to_string()) && !names.contains(&"epsilon".to_string());
                led = caught_up.then_some(true);
            }
        }
        if led == Some(true) {
            break;
        }
        assert!(attempt < 5, "another kept leading gamma");
        gamma.stop();
    }
}

#[test]
fn workloads_move_off_a_lost_node() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "failover";
    // Lost is lost after ten seconds without a word, whatever smaller number is given.
    let quick = ["--lost-after", "1"];
    let alpha = Node::start(test, "alpha", &quick);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let join = |name: &str| {
        let token = alpha.ok(&["node", "token"]);
        let args = ["--join", &alpha.address(), "--token", token.trim(), quick[0], quick[1]];
        Node::start(test, name, &args)
    };
    let (beta, mut gamma) = (join("beta"), join("gamma"));
    // (A node gets replicas once the leader has heard what it has.)
    wait_for("three ready nodes", || {
        alpha.kith(&["get", "node"]).1.matches("ready at").count() == 3
    });

    let web = "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: web }\nspec:\n  replicas: 3\n  template:\n    \
        exec: [{ name: run, command: [sh, -c, 'echo up; exec sleep 300'] }]\n";
    std::fs::write(beta.dir.join("web.yaml"), web).unwrap();
    beta.ok(&["apply", "-f", "web.yaml"]);
    let status = |node: &Node| -> serde_json::Value {
        let web = node.ok(&["get", "workload/web", "-o", "json"]);
        serde_json::from_str::<serde_json::Value>(&web).unwrap()["status"].take()
    };
    // Where the replicas are, and which nodes say they run one.
    let bound = |status: &serde_json::Value| {
        let nodes = status["nodes"].as_object().cloned().unwrap_or_default();
        let mut nodes: Vec<String> = nodes.values().map(|node| node.as_str().unwrap().to_string()).collect();
        nodes.sort();
        nodes
    };
    let running = |status: &serde_json::Value| {
        let units = status["containers"].as_array().cloned().unwrap_or_default();
        let mut nodes: Vec<String> = units
            .iter()
            .map(|unit| unit["node"].as_str().unwrap().to_string())
            .collect();
        nodes.sort();
        nodes
    };

    // One replica on each node, each run by the node it is bound to, all in one status.
    wait_for("three ready replicas", || status(&alpha)["ready"] == 3);
    let spread = status(&alpha);
    assert_eq!(bound(&spread), ["alpha", "beta", "gamma"], "{spread}");
    assert_eq!(running(&spread), ["alpha", "beta", "gamma"], "{spread}");
    assert!(alpha.ok(&["get", "workload"]).contains("3/3 ready"));
    // The output of every replica can be read from any node.
    for replica in ["0", "1", "2"] {
        wait_for("the replica's output", || {
            alpha
                .kith(&["logs", "workload/web", "--replica", replica])
                .1
                .contains("up")
        });
    }

    // gamma goes: once it is lost, its replica is started on a node that is left.
    gamma.stop();
    wait_for("the replica to move", || {
        let now = status(&alpha);
        let gamma = "gamma".to_string();
        !bound(&now).contains(&gamma) && !running(&now).contains(&gamma) && now["ready"] == 3
    });
    let moved = status(&alpha);
    assert_eq!(bound(&moved).len(), 3, "{moved}");

    // gamma comes back and runs nothing of it: its replica has a home.
    gamma.child = Node::spawn(&gamma.dir, "gamma", gamma.port, &quick);
    wait_for("gamma to be ready again", || {
        gamma.kith(&["get", "node"]).1.matches("ready at").count() == 3
    });
    assert_eq!(bound(&status(&alpha)), bound(&moved));
    assert_eq!(status(&alpha)["ready"], 3);
    // (What gamma reads is its own copy, which catches up.)
    wait_for("gamma to have caught up", || status(&gamma) == status(&alpha));
}

/// (Not behind KITH_E2E: it pulls nothing.)
#[test]
fn a_node_says_what_it_serves_and_a_start_without_the_flag_takes_it_off() {
    let test = "serves";
    let dns = free_port();
    let mut alpha = Node::start(test, "alpha", &["--dns", &format!("127.0.0.1:{dns}")]);
    let said = format!("serves dns {dns}");
    wait_for("alpha to say it answers DNS", || {
        alpha.kith(&["get", "node"]).1.contains(&said)
    });
    alpha.stop();
    alpha.child = Node::spawn(&alpha.dir, "alpha", alpha.port, &[]);
    wait_for("alpha, started without --dns, to take it off", || {
        let (code, nodes, _) = alpha.kith(&["get", "node"]);
        code == 0 && nodes.contains("ready at") && !nodes.contains("serves")
    });
}

#[test]
fn a_drain_moves_what_can_move_and_undrain_lets_a_replica_back() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "drain";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    // (Kept alive to the end: a Node stops its kithd when it is dropped.)
    let _beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("two ready nodes", || {
        alpha.kith(&["get", "node"]).1.matches("ready at").count() == 2
    });
    let status = |key: &str| -> serde_json::Value {
        let text = alpha.ok(&["get", key, "-o", "json"]);
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["status"].take()
    };
    let drained = |node: &str| alpha.ok(&["get", &format!("node/{node}"), "-o", "json"]);

    // web (an exec Workload) runs on one node; a Volume made on that node, and db which mounts
    // it, are pinned there.
    let web = "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: web }\nspec:\n  replicas: 1\n  template:\n    \
        exec: [{ name: run, command: [sh, -c, 'echo up; exec sleep 300'] }]\n";
    std::fs::write(alpha.dir.join("web.yaml"), web).unwrap();
    alpha.ok(&["apply", "-f", "web.yaml"]);
    wait_for("web to run", || status("workload/web")["ready"] == 1);
    let home = status("workload/web")["nodes"]["0"].as_str().unwrap().to_string();
    let away = if home == "alpha" { "beta" } else { "alpha" };
    let volume = format!(
        "apiVersion: kith.dev/v1\nkind: Volume\nmetadata: {{ name: data }}\nspec: {{ node: {home}, path: d }}\n"
    );
    std::fs::write(alpha.dir.join("volume.yaml"), volume).unwrap();
    alpha.ok(&["apply", "-f", "volume.yaml"]);
    let db = "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: db }\nspec:\n  replicas: 1\n  template:\n    \
        containers: [{ name: run, image: img, volumeMounts: [{ volume: data, path: /data }] }]\n";
    std::fs::write(alpha.dir.join("db.yaml"), db).unwrap();
    alpha.ok(&["apply", "-f", "db.yaml"]);
    wait_for("db to be placed where its Volume is", || {
        status("workload/db")["nodes"]["0"] == home.as_str()
    });

    // The dry run says what would happen, and changes nothing.
    let (code, said, _) = alpha.kith(&["node", "drain", home.as_str(), "--dry-run"]);
    assert_eq!(code, 0, "{said}");
    assert!(said.contains(&format!("web#0 moves to {away}")), "{said}");
    assert!(said.contains(&format!("db#0 stays on {home}: pinned here")), "{said}");
    assert_eq!(status("workload/web")["nodes"]["0"], home.as_str());
    assert!(!drained(&home).contains("kith.dev/drain"));

    // The drain: web moves to the other node, and db stays with its Volume.
    alpha.ok(&["node", "drain", home.as_str()]);
    assert!(drained(&home).contains("kith.dev/drain"));
    wait_for("web to move off the drained node", || {
        status("workload/web")["nodes"]["0"] == away
    });
    wait_for("web to run on the other node", || status("workload/web")["ready"] == 1);
    assert_eq!(status("workload/db")["nodes"]["0"], home.as_str());

    // Undrain takes the drain off, and a replica placed after that may go back there.
    alpha.ok(&["node", "undrain", home.as_str()]);
    assert!(!drained(&home).contains("kith.dev/drain"));
    std::fs::write(alpha.dir.join("web.yaml"), web.replace("replicas: 1", "replicas: 2")).unwrap();
    alpha.ok(&["apply", "-f", "web.yaml"]);
    wait_for("a web replica placed on the node again", || {
        status("workload/web")["nodes"]
            .as_object()
            .is_some_and(|nodes| nodes.values().any(|node| node.as_str() == Some(home.as_str())))
    });
}

#[test]
fn node_workload_runs_on_every_matching_node() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    // (A short name: a socket's path has to fit in 107 bytes.)
    let test = "everynode";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let join = |name: &str| {
        let token = alpha.ok(&["node", "token"]);
        Node::start(test, name, &["--join", &alpha.address(), "--token", token.trim()])
    };
    let (_beta, gamma) = (join("beta"), join("gamma"));
    wait_for("three ready nodes", || {
        alpha.kith(&["get", "node"]).1.matches("ready at").count() == 3
    });
    // Give a node labels: fetch it, change it, apply it.
    let label = |name: &str, labels: serde_json::Value| {
        let node = alpha.ok(&["get", &format!("node/{name}"), "-o", "json"]);
        let mut node: serde_json::Value = serde_json::from_str(&node).unwrap();
        node["metadata"]["labels"] = labels;
        std::fs::write(alpha.dir.join("node.json"), node.to_string()).unwrap();
        alpha.ok(&["apply", "-f", "node.json"]);
    };
    label("beta", serde_json::json!({ "role": "edge" }));
    label("gamma", serde_json::json!({ "role": "edge" }));

    let agent = "apiVersion: kith.dev/v1\nkind: NodeWorkload\nmetadata: { name: agent }\nspec:\n  \
        selector: { role: edge }\n  template:\n    exec: [{ name: run, command: [sh, -c, 'echo up; exec sleep 300'] }]\n";
    std::fs::write(gamma.dir.join("agent.yaml"), agent).unwrap();
    gamma.ok(&["apply", "-f", "agent.yaml"]);
    let status = || -> serde_json::Value {
        let agent = alpha.ok(&["get", "nodeworkload/agent", "-o", "json"]);
        serde_json::from_str::<serde_json::Value>(&agent).unwrap()["status"].take()
    };
    // The nodes that bind a copy, and the nodes that say they run one.
    let names = |nodes: Vec<&serde_json::Value>| {
        let mut nodes: Vec<String> = nodes
            .iter()
            .map(|node| node.as_str().unwrap_or_default().to_string())
            .collect();
        nodes.sort();
        nodes
    };
    let bound = |status: &serde_json::Value| {
        names(
            status["nodes"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(_, n)| n)
                .collect(),
        )
    };
    let running = |status: &serde_json::Value| {
        names(
            status["containers"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|u| &u["node"])
                .collect(),
        )
    };

    // One copy on each node that matches, run by that node, and none on alpha.
    wait_for("two ready copies", || status()["ready"] == 2);
    let both = status();
    assert_eq!(bound(&both), ["beta", "gamma"], "{both}");
    assert_eq!(running(&both), ["beta", "gamma"], "{both}");
    assert_eq!(both["replicas"], 2);
    assert!(alpha.ok(&["get", "nodeworkload"]).contains("2/2 ready"));
    for replica in ["0", "1"] {
        wait_for("the copy's output", || {
            alpha
                .kith(&["logs", "nodeworkload/agent", "--replica", replica])
                .1
                .contains("up")
        });
    }

    // beta loses its label: its copy stops, gamma's goes on.
    label("beta", serde_json::json!({}));
    wait_for("beta's copy to stop", || {
        let now = status();
        bound(&now) == ["gamma"] && running(&now) == ["gamma"] && now["ready"] == 1
    });
    // alpha gets the label: it takes up a copy.
    label("alpha", serde_json::json!({ "role": "edge" }));
    wait_for("alpha's copy", || {
        let now = status();
        bound(&now) == ["alpha", "gamma"] && running(&now) == ["alpha", "gamma"] && now["ready"] == 2
    });
}

/// A node that joins as one that roams (a laptop): the cluster is told its mesh key as it
/// joins and writes it down at its mesh address, it is told who to call, and the store then
/// comes to it over the mesh, not at the address it happened to join from.
#[test]
fn roaming_node_is_sent_the_store_over_the_mesh() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    if std::env::var_os("KITH_IN_NAMESPACE").is_none() {
        let unshare = |args: &[&str]| Command::new("unshare").arg("-Urn").args(args).status();
        if !unshare(&["true"]).is_ok_and(|status| status.success()) {
            return eprintln!("skipped: no unprivileged user namespaces here (unshare -Urn)");
        }
        let me = std::env::current_exe().unwrap();
        let again = "ip link set lo up && KITH_IN_NAMESPACE=1 exec \"$0\" --exact roaming_node_is_sent_the_store_over_the_mesh --nocapture";
        let status = unshare(&["sh", "-c", again, me.to_str().unwrap()]).unwrap();
        assert!(status.success(), "the test failed inside its namespace");
        return;
    }
    let ports = (free_port().to_string(), free_port().to_string());
    let alpha = Node::start(
        "roaming",
        "alpha",
        &["--mesh", &ports.0, "--mesh-interface", "kith-alpha"],
    );
    wait_for("alpha to lead", || alpha.kith(&["get", "node"]).0 == 0);
    // (Nobody on the mesh yet, nobody to call: said, not left to time out.)
    wait_for("alpha to be on the mesh", || {
        alpha.ok(&["get", "node/alpha", "-o", "json"]).contains("\"mesh\"")
    });
    let token = alpha.ok(&["node", "token"]);
    let join = ["--join", &alpha.address(), "--token", token.trim(), "--roaming"];
    let mesh = ["--mesh", &ports.1, "--mesh-interface", "kith-roam"];
    let args = [&join[..], &mesh[..]].concat();
    let laptop = Node::start_in(None, "[::]", free_port(), "roaming", "laptop", &args);

    // It has the store: sent to its mesh address, which is where its Node says it is.
    wait_for("the laptop to be sent the store", || {
        laptop.kith(&["get", "node"]).0 == 0 && laptop.nodes().len() == 2
    });
    let node: serde_json::Value = serde_json::from_str(&alpha.ok(&["get", "node/laptop", "-o", "json"])).unwrap();
    assert_eq!(node["spec"]["roaming"], true, "{node}");
    let address = node["status"]["address"].as_str().unwrap();
    assert!(
        address.starts_with("[fd") && address.ends_with(&format!("]:{}", laptop.port)),
        "{address}"
    );
    let status = alpha.ok(&["node", "status"]);
    let line = status.lines().find(|line| line.starts_with("mesh:      laptop at fd"));
    assert!(line.is_some_and(|line| line.ends_with(", direct")), "{status}");
    // And goes on having it: a change made on alpha arrives.
    let made = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: seen }\nspec: { data: { a: b } }\n";
    std::fs::write(alpha.dir.join("seen.yaml"), made).unwrap();
    alpha.ok(&["apply", "-f", "seen.yaml"]);
    wait_for("the change to reach the laptop", || {
        laptop.kith(&["get", "configmap/seen"]).0 == 0
    });
    // It does not vote, though it has all of the store.
    let cluster = alpha.ok(&["node", "status"]);
    assert!(
        !cluster
            .lines()
            .any(|line| line.starts_with("voters") && line.contains("laptop")),
        "{cluster}"
    );
    // A node that comes with the laptop's mesh key is refused: two with one key would
    // both be cut off.
    let twin = Path::new(env!("CARGO_TARGET_TMPDIR")).join("roaming").join("twin");
    let _ = std::fs::remove_dir_all(&twin);
    std::fs::create_dir_all(twin.join("state/pki")).unwrap();
    let key = "state/pki/mesh.key";
    std::fs::copy(laptop.dir.join(key), twin.join(key)).unwrap();
    let mesh = ["--mesh", &free_port().to_string(), "--mesh-interface", "kith-twin"];
    let args = [&join[..], &mesh[..]].concat();
    let mut child = Node::spawn_in(None, "[::]", &twin, "twin", free_port(), &args);
    assert!(
        !child.wait().unwrap().success(),
        "a second node with the laptop's key joined"
    );
    assert_ne!(alpha.kith(&["get", "node/twin"]).0, 0);
}

/// Two nodes with the mesh on, in a network namespace of their own (this test runs itself
/// again inside one, where it may make interfaces): each learns the other's key from the
/// store, they shake hands, and a node that stops takes its interface with it.
#[test]
fn nodes_mesh() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    if std::env::var_os("KITH_IN_NAMESPACE").is_none() {
        let unshare = |args: &[&str]| Command::new("unshare").arg("-Urn").args(args).status();
        if !unshare(&["true"]).is_ok_and(|status| status.success()) {
            return eprintln!("skipped: no unprivileged user namespaces here (unshare -Urn)");
        }
        let me = std::env::current_exe().unwrap();
        let again = "ip link set lo up && KITH_IN_NAMESPACE=1 exec \"$0\" --exact nodes_mesh --nocapture";
        let status = unshare(&["sh", "-c", again, me.to_str().unwrap()]).unwrap();
        assert!(status.success(), "the test failed inside its namespace");
        return;
    }
    let ports = (free_port().to_string(), free_port().to_string());
    let alpha = Node::start("mesh", "alpha", &["--mesh", &ports.0, "--mesh-interface", "kith-alpha"]);
    wait_for("alpha to lead", || alpha.kith(&["get", "node"]).0 == 0);
    let token = alpha.ok(&["node", "token"]);
    let join = ["--join", &alpha.address(), "--token", token.trim()];
    let mesh = ["--mesh", &ports.1, "--mesh-interface", "kith-beta"];
    let mut beta = Node::start("mesh", "beta", &[join, mesh].concat());

    let shook = |node: &Node, other: &str| {
        let status = node.ok(&["node", "status"]);
        let line = status
            .lines()
            .find(|line| line.starts_with(&format!("mesh:      {other} at fd")));
        line.is_some_and(|line| line.contains(", handshake ") && !line.contains("edge node"))
    };
    wait_for("the two to shake hands", || {
        shook(&alpha, "beta") && shook(&beta, "alpha")
    });
    // Each Node says where it is on the mesh, and nothing of its private key.
    let nodes = alpha.ok(&["get", "node", "-o", "json"]);
    let nodes: serde_json::Value = serde_json::from_str(&nodes).unwrap();
    let key = std::fs::read_to_string(beta.dir.join("state/pki/mesh.key")).unwrap();
    assert!(key.len() == 64 && !nodes.to_string().contains(&key));
    assert!(
        nodes[1]["status"]["mesh"]["address"]
            .as_str()
            .unwrap()
            .starts_with("fd")
    );

    // A node that stops takes its interface away; the other's stays.
    let there = |name: &str| {
        Command::new("ip")
            .args(["link", "show", name])
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(there("kith-beta") && there("kith-alpha"));
    beta.stop();
    assert!(!there("kith-beta") && there("kith-alpha"));
}

// The rig: a network namespace for each node, and the namespace the test itself runs in
// as the router between them. Node N is on a link of its own (`r<N>` on the router's side,
// `e0` on its), which `cut` and `heal` take down and up. A node is public (10.0.N.2) or
// behind a NAT (192.168.N.2): out of the NAT everything leaves as 10.0.0.N, in through it
// only TCP to the node's API port, as with a router that forwards one port. Nothing here
// needs root: `unshare -Urnm`, and `ip`, `iptables` and `nsenter` in what it makes.
// Run by hand: `KITH_E2E=1 cargo test -p kithd --test cluster rig_`.
const RIG_PORT: u16 = 7443;

/// Run a command, given as words, and say what it said if it fails.
fn sh(command: &str) {
    let words: Vec<&str> = command.split_whitespace().collect();
    let out = Command::new(words[0]).args(&words[1..]).output().unwrap();
    assert!(
        out.status.success(),
        "{command}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Run this test again in new user, network and mount namespaces, where it may make
/// interfaces and namespaces; true in that second run. False when that was it, or
/// the test is skipped (the reason is on stderr).
fn in_rig(test: &str) -> bool {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return false;
    }
    if std::env::var_os("KITH_IN_NAMESPACE").is_some() {
        return true;
    }
    let unshare = |args: &[&str]| Command::new("unshare").arg("-Urnm").args(args).status();
    if !unshare(&["true"]).is_ok_and(|status| status.success()) {
        eprintln!("skipped: no unprivileged user namespaces here (unshare -Urnm)");
        return false;
    }
    for tool in ["ip", "iptables", "nsenter"] {
        if Command::new(tool).arg("--version").output().is_err() {
            eprintln!("skipped: no {tool}");
            return false;
        }
    }
    let me = std::env::current_exe().unwrap();
    // (A tmpfs on /run: `ip netns add` writes there.)
    let again = format!(
        "mount -t tmpfs none /run && ip link set lo up && KITH_IN_NAMESPACE=1 exec \"$0\" --exact {test} --nocapture"
    );
    let status = unshare(&["sh", "-c", &again, me.to_str().unwrap()]).unwrap();
    assert!(status.success(), "the test failed inside its namespaces");
    false
}

struct Rig {
    /// The nodes in order, and whether each is behind a NAT.
    nodes: Vec<(String, bool)>,
}

impl Rig {
    fn new(nodes: &[(&str, bool)]) -> Rig {
        sh("sysctl -qw net.ipv4.ip_forward=1");
        for (n, (name, nat)) in (1..).zip(nodes) {
            let net = if *nat {
                format!("192.168.{n}")
            } else {
                format!("10.0.{n}")
            };
            sh(&format!("ip netns add {name}"));
            sh(&format!("ip -n {name} link set lo up"));
            sh(&format!("ip link add r{n} type veth peer name e0 netns {name}"));
            sh(&format!("ip addr add {net}.1/24 dev r{n}"));
            sh(&format!("ip link set r{n} up"));
            sh(&format!("ip -n {name} addr add {net}.2/24 dev e0"));
            sh(&format!("ip -n {name} link set e0 up"));
            sh(&format!("ip -n {name} route add default via {net}.1"));
            if !nat {
                continue;
            }
            let public = format!("10.0.0.{n}");
            sh(&format!("ip addr add {public}/32 dev lo"));
            sh(&format!(
                "iptables -t nat -A POSTROUTING -s {net}.0/24 ! -o r{n} -j SNAT --to-source {public}"
            ));
            let dnat = format!("-d {public} -p tcp --dport {RIG_PORT} -j DNAT --to-destination {net}.2");
            sh(&format!("iptables -t nat -A PREROUTING {dnat}"));
            // Nothing else goes in, not even from a neighbour that knows the private address.
            sh(&format!(
                "iptables -A FORWARD -o r{n} -m conntrack --ctstate NEW -m conntrack ! --ctstate DNAT -j DROP"
            ));
        }
        let nodes = nodes.iter().map(|(name, nat)| (name.to_string(), *nat));
        Rig { nodes: nodes.collect() }
    }

    fn number(&self, name: &str) -> usize {
        1 + self.nodes.iter().position(|(node, _)| node == name).unwrap()
    }

    /// The address a node listens on, in its namespace, and the one others reach it at.
    fn addresses(&self, name: &str) -> (String, String) {
        let n = self.number(name);
        match self.nodes[n - 1].1 {
            true => (format!("192.168.{n}.2"), format!("10.0.0.{n}")),
            false => (format!("10.0.{n}.2"), format!("10.0.{n}.2")),
        }
    }

    /// Start the node `name` in its namespace; with `join`, in the cluster of that node.
    fn start(&self, test: &str, name: &str, join: Option<&Node>, args: &[&str]) -> Node {
        let (host, public) = self.addresses(name);
        let advertise = format!("{public}:{RIG_PORT}");
        let mut all = vec!["--advertise", &advertise];
        let token = join.map(|node| node.ok(&["node", "token"]));
        let join = join.map(|node| node.address());
        if let (Some(join), Some(token)) = (&join, &token) {
            all.extend(["--join", join, "--token", token.trim()]);
        }
        all.extend(args);
        Node::start_in(Some(name), &host, RIG_PORT, test, name, &all)
    }

    fn cut(&self, name: &str) {
        sh(&format!("ip link set r{} down", self.number(name)));
    }

    fn heal(&self, name: &str) {
        sh(&format!("ip link set r{} up", self.number(name)));
    }

    /// Latency on a node's link where the kernel has netem; says so where it has not.
    fn delay(&self, name: &str, ms: u32) {
        let link = format!("r{}", self.number(name));
        let tc = format!("tc qdisc add dev {link} root netem delay {ms}ms");
        let words: Vec<&str> = tc.split_whitespace().collect();
        let out = Command::new(words[0]).args(&words[1..]).output();
        if !out.is_ok_and(|out| out.status.success()) {
            eprintln!("skipped: no netem (`tc qdisc add ... netem` fails here), so no added latency");
        }
    }

    /// Whether `from` can reach this address (one ping).
    fn pings(&self, from: &str, address: &str) -> bool {
        let net = format!("--net=/run/netns/{from}");
        let ping = Command::new("nsenter")
            .args([&net, "ping", "-c1", "-W1", address])
            .output();
        ping.unwrap().status.success()
    }
}

/// Three nodes, one behind a NAT. The leader's link is cut: the others pick another leader
/// and go on, and when the link is back the old leader follows, with what it missed.
#[test]
fn rig_partition_moves_the_leader() {
    if !in_rig("rig_partition_moves_the_leader") {
        return;
    }
    // (A short test name: a socket's path may be 107 bytes, and the state sits deep in a worktree.)
    let test = "rig_cut";
    let rig = Rig::new(&[("alpha", false), ("beta", false), ("gamma", true)]);
    let alpha = rig.start(test, "alpha", None, &[]);
    wait_for("alpha to lead", || alpha.kith(&["get", "node"]).0 == 0);
    let beta = rig.start(test, "beta", Some(&alpha), &[]);
    let gamma = rig.start(test, "gamma", Some(&alpha), &[]);
    let status = |node: &Node| node.kith(&["node", "status"]).1;
    wait_for("three voters", || {
        [&alpha, &beta, &gamma]
            .iter()
            .all(|node| status(node).contains("voters:    alpha, beta, gamma"))
    });
    assert!(status(&gamma).contains("leader:    alpha"), "{}", status(&gamma));
    // Latency where the kernel has netem; the rest runs with it.
    rig.delay("beta", 20);

    // alpha is cut off. The others agree on a leader and a change made through one of
    // them reaches the other; alpha hears nothing.
    rig.cut("alpha");
    let config = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: after }\nspec: { data: { a: b } }\n";
    std::fs::write(beta.dir.join("after.yaml"), config).unwrap();
    wait_for("a change without alpha", || {
        beta.kith(&["apply", "-f", "after.yaml"]).0 == 0
    });
    wait_for("that change on gamma", || {
        gamma.kith(&["get", "ConfigMap/after"]).0 == 0
    });
    let leader = status(&beta);
    assert!(
        leader.contains("leader:    beta") || leader.contains("leader:    gamma"),
        "{leader}"
    );
    assert!(
        alpha.kith(&["get", "ConfigMap/after"]).0 != 0,
        "alpha has a change made while it was cut off"
    );

    // The link is back: alpha has the change, and no longer leads.
    rig.heal("alpha");
    wait_for("alpha to catch up", || alpha.kith(&["get", "ConfigMap/after"]).0 == 0);
    wait_for("alpha to follow", || !status(&alpha).contains("leader:    alpha"));
    assert!(
        status(&alpha).contains("voters:    alpha, beta, gamma"),
        "{}",
        status(&alpha)
    );
}

/// A node behind a NAT, with no way in but its API port, joins and takes part in the mesh:
/// it dials out, shakes hands with both others, and they with it, though neither can
/// reach its mesh port or its private address.
///
/// Not covered: the relay through an edge node. A member silent for three minutes
/// (`QUIET` in mesh.rs, not a flag) is routed through an edge node, and a test of that would
/// wait three minutes; the choice of the relay has its unit tests in kith-mesh.
#[test]
fn rig_nat_node_joins_and_meshes() {
    if !in_rig("rig_nat_node_joins_and_meshes") {
        return;
    }
    let rig = Rig::new(&[("alpha", false), ("beta", false), ("gamma", true)]);
    let test = "rig_nat";
    let mesh = ["--mesh", "51820"];
    let alpha = rig.start(test, "alpha", None, &mesh);
    wait_for("alpha to lead", || alpha.kith(&["get", "node"]).0 == 0);
    let beta = rig.start(test, "beta", Some(&alpha), &mesh);
    let gamma = rig.start(test, "gamma", Some(&alpha), &mesh);
    let shook = |node: &Node, other: &str| {
        let status = node.kith(&["node", "status"]).1;
        let line = status
            .lines()
            .find(|line| line.starts_with(&format!("mesh:      {other} at fd")));
        line.is_some_and(|line| line.contains(", handshake ") && !line.contains("edge node"))
    };
    wait_for("gamma and the others to shake hands", || {
        shook(&gamma, "alpha") && shook(&gamma, "beta") && shook(&alpha, "gamma") && shook(&beta, "gamma")
    });
    // No private address reaches in from outside the NAT.
    assert!(!rig.pings("alpha", "192.168.3.2") && !rig.pings("beta", "192.168.3.2"));
    assert!(rig.pings("gamma", "10.0.1.2"));
}

/// A laptop behind a NAT, with nothing let in to it: it joins as a node that roams, is sent
/// the store through the tunnel it opened, and still is after it moves (another address
/// behind the NAT, another one in front of it).
#[test]
fn roaming_laptop_behind_nat_keeps_the_store_when_it_moves() {
    if !in_rig("roaming_laptop_behind_nat_keeps_the_store_when_it_moves") {
        return;
    }
    let rig = Rig::new(&[("alpha", false), ("laptop", true)]);
    let test = "roaming_nat";
    let alpha = rig.start(test, "alpha", None, &["--mesh", "51820"]);
    wait_for("alpha to lead", || alpha.kith(&["get", "node"]).0 == 0);
    wait_for("alpha to be on the mesh", || {
        alpha.ok(&["get", "node/alpha", "-o", "json"]).contains("\"mesh\"")
    });
    let token = alpha.ok(&["node", "token"]);
    // (Not the port the rig lets in to a node behind its NAT: nothing reaches this one.)
    let args = [
        "--join",
        &alpha.address(),
        "--token",
        token.trim(),
        "--mesh",
        "51820",
        "--roaming",
    ];
    let laptop = Node::start_in(Some("laptop"), "[::]", RIG_PORT + 1, test, "laptop", &args);
    wait_for("the laptop to be sent the store", || {
        laptop.kith(&["get", "node"]).0 == 0 && laptop.nodes().len() == 2
    });
    let address = &alpha.nodes()[1].1;
    assert!(address.starts_with("[fd"), "{address}");

    // It moves: its own address changes, and so does the one the world sees it at.
    sh("ip -n laptop addr add 192.168.2.7/24 dev e0");
    sh("ip -n laptop addr del 192.168.2.2/24 dev e0");
    sh("ip -n laptop route replace default via 192.168.2.1");
    sh("ip addr add 10.0.0.9/32 dev lo");
    sh("iptables -t nat -R POSTROUTING 1 -s 192.168.2.0/24 ! -o r2 -j SNAT --to-source 10.0.0.9");
    let made = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: later }\nspec: { data: { a: b } }\n";
    std::fs::write(alpha.dir.join("later.yaml"), made).unwrap();
    alpha.ok(&["apply", "-f", "later.yaml"]);
    wait_for("a change made after the move to reach the laptop", || {
        laptop.kith(&["get", "configmap/later"]).0 == 0
    });
    let status = alpha.ok(&["node", "status"]);
    let line = status.lines().find(|line| line.starts_with("mesh:      laptop at fd"));
    assert!(line.is_some_and(|line| line.ends_with(", direct")), "{status}");
}
