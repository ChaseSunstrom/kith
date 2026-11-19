//! Several kithd on one machine, as a cluster. Opt-in like the other e2e tests:
//!
//! ```sh
//! KITH_E2E=1 cargo test -p kithd --test cluster
//! ```

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How many times its base a deadline is given: the 1-minute load average over the CPU count,
/// at least 1 and at most 4 (a host loaded past that is not waited on for ever).
fn patience(load: f64, cpus: usize) -> f64 {
    // (clamp passes a NaN through.)
    if load.is_nan() {
        return 1.0;
    }
    (load / cpus.max(1) as f64).clamp(1.0, 4.0)
}

#[test]
fn deadlines_grow_with_the_load_within_bounds() {
    assert_eq!(patience(0.5, 16), 1.0);
    assert_eq!(patience(32.0, 16), 2.0);
    assert_eq!(patience(105.0, 16), 4.0);
    assert_eq!(patience(f64::NAN, 16), 1.0);
    assert_eq!(patience(1000.0, 0), 4.0);
}

/// The base deadline of a wait, grown by the load the host has now.
fn deadline_for(base: Duration) -> Duration {
    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| text.split(' ').next()?.parse().ok())
        .unwrap_or(0.0);
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    base.mul_f64(patience(load, cpus))
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + deadline_for(Duration::from_secs(30));
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
        // free_port gives the port back before kithd binds it, and these tests run in parallel
        // (and beside other builds): another node can take it in between ("Address already in
        // use", kithd exits 1). A port nobody else holds comes from asking again.
        let mut last = String::new();
        for _ in 0..4 {
            match Node::try_start_in(None, "127.0.0.1", free_port(), test, name, args) {
                Ok(node) => return node,
                Err(why) => last = why,
            }
        }
        panic!("{last}")
    }

    /// The same, listening on `host:port`, in the network namespace `ns` if there is one.
    fn start_in(ns: Option<&str>, host: &str, port: u16, test: &str, name: &str, args: &[&str]) -> Node {
        Node::try_start_in(ns, host, port, test, name, args).unwrap_or_else(|why| panic!("{why}"))
    }

    /// `start_in`, giving the reason when kithd exits before it serves.
    fn try_start_in(
        ns: Option<&str>,
        host: &str,
        port: u16,
        test: &str,
        name: &str,
        args: &[&str],
    ) -> Result<Node, String> {
        let built = Command::new(env!("CARGO"))
            .args(["build", "--quiet", "-p", "kith-cli"])
            .status()
            .unwrap();
        assert!(built.success());
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut node = Node {
            child: Node::spawn_in(ns, host, &dir, name, port, args),
            dir,
            port,
            host: host.to_string(),
        };
        // Fail at once if kithd exited (a socket path it could not bind, say), not after the wait.
        let mut exited = None;
        wait_for("kithd to serve", || {
            if let Some(status) = node.child.try_wait().unwrap() {
                exited = Some(format!(
                    "kithd exited ({status}) before serving {}",
                    node.dir.join("kithd.sock").display()
                ));
                return true;
            }
            node.dir.join("kithd.sock").exists()
        });
        match exited {
            Some(why) => Err(why),
            None => Ok(node),
        }
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
            // (No registry unless a test names one: every node would else try port 5000.)
            .args(if args.contains(&"--registry-port") {
                Vec::new()
            } else {
                vec!["--registry-port", "0"]
            })
            .args(args)
            .stdin(Stdio::null())
            // (To a file the test can read: [`Node::console`].)
            .stderr(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dir.join("kithd.log"))
                    .unwrap(),
            )
            .spawn()
            .unwrap()
    }

    /// What this node has said on its console since it was first started.
    fn console(&self) -> String {
        std::fs::read_to_string(self.dir.join("kithd.log")).unwrap_or_default()
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
            // Relative: a Unix socket's path holds 107 bytes, and a test's under a worktree's
            // target (as a lane's landing check runs it) is longer.
            .env("KITH_SOCKET", "kithd.sock")
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
        // (Its console is in a file, not the terminal: a failing test still shows it.)
        if std::thread::panicking() {
            eprintln!("--- console of {} ---\n{}", self.dir.display(), self.console());
        }
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
    assert!(
        said.contains("node alpha was called, and a certificate naming beta answered"),
        "{said}"
    );
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
    // The switch is set before the node port is served: the first answer on it is the answer.
    // (curl says 000 while the port does not answer; a loaded host takes long to get there.)
    let mut said = String::new();
    wait_for("alpha's node port to answer", || {
        said = api();
        said != "000"
    });
    assert_eq!(
        said, "403",
        "the old certificate, at the first answer of a node started with --admit-deleted-nodes"
    );
}

/// The node the cluster started on, deleted and started again, does not put its Node back.
#[test]
fn deleted_first_node_is_not_made_again_by_its_restart() {
    let test = "deleted_first_node";
    let mut alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let mut beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("beta to have the store", || beta.nodes().len() == 2);
    let taken = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test).join("taken");
    let _ = std::fs::remove_dir_all(&taken);
    std::fs::create_dir_all(&taken).unwrap();
    for file in ["node.crt", "node.key"] {
        std::fs::copy(alpha.dir.join("state/pki").join(file), taken.join(file)).unwrap();
    }
    beta.ok(&["delete", "node/alpha"]);
    wait_for("alpha to be refused", || {
        status_as_node(&beta.address(), &taken, "GET", "/v1/resources") == "401"
    });
    // beta takes a deleted node's certificate again (as for a cluster that locked itself out), so that
    // what alpha writes at its start could commit: only alpha's own guard keeps its Node out.
    beta.stop();
    beta.child = Node::spawn(&beta.dir, "beta", beta.port, &["--admit-deleted-nodes"]);
    wait_for("beta to answer again", || beta.kith(&["get", "node"]).0 == 0);
    alpha.stop();
    alpha.child = Node::spawn(&alpha.dir, "alpha", alpha.port, &[]);
    wait_for("alpha to answer again", || alpha.kith(&["get", "node"]).0 == 0);
    // (Its registration ran at the start: given time, it would have put the Node back.)
    std::thread::sleep(Duration::from_secs(8));
    let names: Vec<_> = beta.nodes().into_iter().map(|(name, _)| name).collect();
    assert_eq!(names, ["beta"]);
}

/// A node starts, and answers, in a folder whose path is longer than a Unix socket's address holds
/// (107 bytes): a lane's checks run under its worktree's target, and that path is longer still.
#[test]
fn a_node_starts_and_answers_under_a_path_longer_than_a_socket_holds() {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let padding = 160usize.saturating_sub(base.as_os_str().len() + "/alpha".len());
    let test = format!("a_node_starts_under_a_long_path_{}", "p".repeat(padding));
    let alpha = Node::start(&test, "alpha", &[]);
    assert!(alpha.dir.as_os_str().len() > 150, "{}", alpha.dir.display());
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    assert_eq!(alpha.nodes(), [("alpha".to_string(), alpha.address())]);
}

/// Whether a stopped node's store holds `text` anywhere: its snapshot or a log entry.
fn store_holds(node: &Node, text: &str) -> bool {
    let raft = node.dir.join("state/raft");
    let snapshot = std::fs::read_to_string(raft.join("snapshot.json")).unwrap_or_default();
    snapshot.contains(text) || log_entries(&raft.join("log.redb")).unwrap().contains(text)
}

/// The entries the Raft log in `file` gives back, as JSON.
fn log_entries(file: &Path) -> Result<String, String> {
    use kith_store::openraft::RaftLogReader;
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let mut log = kith_store::Log::open(file)?;
    let entries = runtime
        .block_on(log.try_get_log_entries(..))
        .map_err(|e| e.to_string())?;
    Ok(serde_json::to_string(&entries).unwrap())
}

/// The same of a running node, read from a copy of its log (kithd holds the file's lock):
/// `None` while the copy, taken in the middle of a write, does not read. A copy of a live
/// file can be torn, so a wait on this is retried and proves nothing alone: the proof is
/// [`store_holds`], read once the nodes have stopped.
fn running_log_entries(node: &Node) -> Option<String> {
    let copy = node.dir.join("log-copy.redb");
    let _ = std::fs::remove_file(&copy);
    std::fs::copy(node.dir.join("state/raft/log.redb"), &copy).ok()?;
    log_entries(&copy).ok()
}

/// Every member's kithd reads store format 4, and says so with each answer to Raft's calls:
/// the leader marks the store (format 2, then 3, then 4), every control node's log holds the three
/// marks (and so says format 4), and a node started again on that state serves. (Not behind KITH_E2E: it pulls nothing.)
#[test]
fn the_store_is_marked_once_every_member_reads_its_format() {
    let test = "mark";
    let mut alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let mut beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    let mark = r#""payload":{"Normal":"Mark"}"#;
    let signing = r#""payload":{"Normal":"MarkSigned"}"#;
    let checked = r#""payload":{"Normal":"MarkChecked"}"#;
    let marks = [mark, signing, checked];
    let marked = |node: &Node| running_log_entries(node).is_some_and(|log| marks.iter().all(|m| log.contains(m)));
    wait_for("both logs to hold the marks", || marked(&alpha) && marked(&beta));
    // Each answers Raft's calls with the format its kithd reads: what a leader waits to hear
    // from every member before it marks. (Asked as beta, of alpha, and the other way.)
    let says = |of: &Node, by: &Node| {
        let pki = by.dir.join("state/pki");
        let mut curl = Command::new("curl");
        curl.args(["-sk", "-D", "-", "-o", "/dev/null", "--max-time", "15"]);
        curl.arg("--cert").arg(pki.join("node.crt"));
        curl.arg("--key").arg(pki.join("node.key"));
        let asked = curl.arg(format!("https://{}/v1/raft/stands", of.address()));
        String::from_utf8_lossy(&asked.output().unwrap().stdout).to_ascii_lowercase()
    };
    for (of, by) in [(&alpha, &beta), (&beta, &alpha)] {
        let said = says(of, by);
        assert!(said.contains("x-kith-store: 4"), "{said}");
    }
    // What is made now is of its entry in the log: both nodes answer, and agree.
    let config = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: after }\nspec: { data: { a: '1' } }\n";
    std::fs::write(alpha.dir.join("after.yaml"), config).unwrap();
    alpha.ok(&["apply", "-f", "after.yaml"]);
    wait_for("beta to have it", || beta.kith(&["get", "configmap/after"]).0 == 0);
    alpha.stop();
    beta.stop();
    for node in [&alpha, &beta] {
        assert!(marks.iter().all(|m| store_holds(node, m)), "{}", node.dir.display());
        let snapshot = std::fs::read_to_string(node.dir.join("state/raft/snapshot.json")).unwrap_or_default();
        assert!(
            snapshot.is_empty() || snapshot.starts_with(r#"{"format":4,"#),
            "{snapshot:.80}"
        );
    }
    // Started again on the marked state, each serves what it had.
    alpha.child = Node::spawn(&alpha.dir, "alpha", alpha.port, &[]);
    beta.child = Node::spawn(&beta.dir, "beta", beta.port, &[]);
    wait_for("both to answer again", || {
        [&alpha, &beta]
            .iter()
            .all(|node| node.kith(&["get", "configmap/after"]).0 == 0)
    });
}

/// The cluster's duress code typed at one disk: no control node keeps either key it held,
/// in its snapshot or its log, and `kith node unlock` has it hold a key again.
/// (Not behind KITH_E2E: it pulls nothing.)
#[test]
fn forgotten_key_is_on_no_control_nodes_disk() {
    use ring::signature::KeyPair;
    // (Short: the socket's path is under it, and a socket's path has 107 bytes at most.)
    let test = "forgot";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let join = |name: &str| {
        let token = alpha.ok(&["node", "token"]);
        Node::start(test, name, &["--join", &alpha.address(), "--token", token.trim()])
    };
    let (beta, gamma) = (join("beta"), join("gamma"));
    let mut nodes = [alpha, beta, gamma];
    wait_for("three voters", || {
        nodes
            .iter()
            .all(|node| node.ok(&["node", "status"]).contains("voters:    alpha, beta, gamma"))
    });

    let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let code = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let all = hex(code.public_key().as_ref());
    let (one, other) = ("a1".repeat(32), "b2".repeat(32));
    let (first, second, again) = ("5ea1ed01".repeat(8), "5ea1ed02".repeat(8), "5ea1ed03".repeat(8)); // pragma: allowlist secret
    let key = |name: &str, id: &str, wrapped: &str| {
        format!(
            "---\napiVersion: kith.dev/v1\nkind: NodeKey\nmetadata: {{ name: {name} }}\nspec: {{ id: {id}, wrapped: {wrapped}, duressAll: {all} }}\n"
        )
    };
    let keys = key("disk-a", &one, &first) + &key("disk-b", &other, &second);
    std::fs::write(nodes[0].dir.join("keys.yaml"), keys).unwrap();
    nodes[0].ok(&["apply", "-f", "keys.yaml"]);
    let pki = |node: &Node| node.dir.join("state/pki");
    let handed = |node: &Node, id: &str| {
        let body = format!("{{\"id\":\"{id}\"}}");
        ask_as_node(&node.address(), &pki(node), "POST", "/v1/unlock", Some(&body)).1
    };
    wait_for("gamma to hand out disk-b's key", || {
        handed(&nodes[2], &other).contains(&second)
    });

    // The cluster's code, typed at disk-a: disk-a is wiped and disk-b forgotten.
    let (status, said) = forget_signed(&nodes[1], &code, &one);
    assert_eq!(status, "200", "{said}");
    // Every control node snapshots the store as it is now.
    for node in &nodes {
        let snapshot = node.dir.join("state/raft/snapshot.json");
        wait_for("a snapshot with the keys forgotten", || {
            let held = std::fs::read_to_string(&snapshot).unwrap_or_default();
            held.contains("forgotten") && !held.contains(&first) && !held.contains(&second)
        });
        // And drops its log up to there (a leader once no node it sends to reads it still).
        wait_for("the log dropped up to the forget", || {
            running_log_entries(node).is_some_and(|log| !log.contains(&first) && !log.contains(&second))
        });
    }
    assert!(!handed(&nodes[2], &other).contains(&second));

    // disk-b, opened with its recovery key, gives the cluster its key to hold again.
    nodes[2].ok(&["node", "unlock", "disk-b"]);
    std::fs::write(nodes[2].dir.join("again.yaml"), key("disk-b", &other, &again)).unwrap();
    nodes[2].ok(&["apply", "-f", "again.yaml"]);
    wait_for("alpha to hand out disk-b's new key", || {
        handed(&nodes[0], &other).contains(&again)
    });

    for node in &mut nodes {
        node.stop();
    }
    for node in &nodes {
        assert!(
            !store_holds(node, &first) && !store_holds(node, &second),
            "{}",
            node.dir.display()
        );
        assert!(store_holds(node, &again), "{}", node.dir.display());
        // And no file of its state holds them, whatever kithd keeps there (the imported
        // store was such a file once): each read whole, as bytes.
        // (But for the log's file: its entries were read above, and its freed pages keep
        // what they held until something writes over them, as SECURITY.md says.)
        let mut held = files_holding(&node.dir.join("state"), &[&first, &second]);
        held.retain(|file| !file.ends_with("raft/log.redb"));
        assert!(held.is_empty(), "a forgotten key is still in {held:?}");
        // (The walk reads what is there: the key the cluster holds again is found.)
        assert!(
            !files_holding(&node.dir.join("state"), &[&again]).is_empty(),
            "{}",
            node.dir.display()
        );
    }
}

/// The files under `dir` whose bytes hold one of `texts`.
fn files_holding(dir: &Path, texts: &[&str]) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            found.extend(files_holding(&path, texts));
        } else if let Ok(bytes) = std::fs::read(&path) {
            let holds = |text: &&str| bytes.windows(text.len()).any(|part| part == text.as_bytes());
            if texts.iter().any(holds) {
                found.push(path);
            }
        }
    }
    found
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
        .stderr(Stdio::null())
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

/// A forget of key `id` typed at `at`, signed with `code` (the cluster's duress code): the nonce
/// it gives, then the signature over `kith-forget <id> <nonce bytes>`. The answer to the second call.
fn forget_signed(at: &Node, code: &ring::signature::Ed25519KeyPair, id: &str) -> (String, String) {
    let pki = at.dir.join("state/pki");
    let ask = |body: String| ask_as_node(&at.address(), &pki, "POST", "/v1/forget", Some(&body));
    let (_, said) = ask(format!("{{\"id\":\"{id}\"}}"));
    let said: serde_json::Value = serde_json::from_str(&said).unwrap();
    let nonce = said["nonce"].as_str().unwrap();
    let bytes: Vec<u8> = (0..nonce.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&nonce[at..at + 2], 16).unwrap())
        .collect();
    let signed = code.sign(&[b"kith-forget ", id.as_bytes(), b" ", &bytes].concat());
    let signature: String = signed.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    ask(format!(
        "{{\"id\":\"{id}\",\"nonce\":\"{nonce}\",\"signature\":\"{signature}\"}}"
    ))
}

/// The leader's own-write deny list (`own_writes`) says so on the console when it refuses a
/// control node's write: no node of `nodes` said it. And a control check that it would say it:
/// `sender` (a control node that does not lead) writes a Namespace as itself to `leader`, which
/// is refused, and `leader`'s console says so by `sender`'s name.
fn assert_no_own_write_refused(sender: &Node, leader: &Node, nodes: &[&Node]) {
    for node in nodes {
        let said = node.console();
        assert!(
            !said.contains("refused a control node's own write"),
            "{}: {said}",
            node.dir.display()
        );
    }
    let forged = serde_json::json!({ "Apply": { "at": 0, "resources": [
        { "apiVersion": "kith.dev/v1", "kind": "Namespace", "metadata": { "name": "forged" }, "spec": {} }
    ] } });
    let (_, said) = ask_as_node(
        &leader.address(),
        &sender.dir.join("state/pki"),
        "POST",
        "/v1/raft/write",
        Some(&forged.to_string()),
    );
    let refused = format!(
        "refused a control node's own write: {}",
        sender.dir.file_name().unwrap().to_string_lossy()
    );
    let said_by_leader = leader.console();
    assert!(
        said_by_leader.contains(&refused),
        "no `{refused}` after {said}: {said_by_leader}"
    );
}

/// What `kithd` writes for the Identity or Admin that asked, made at a node that does not
/// lead (T-0746): the follower passes each on to the leader as the caller's, never as its own
/// write, which the leader's deny list would refuse. `kith node lock`, `unlock`, `duress`,
/// `duress --all` and a forget typed at the follower land at the leader, and neither log says
/// a control node's own write was refused. (Not behind KITH_E2E: it pulls nothing.)
#[test]
fn crypt_writes_at_a_follower() {
    use ring::signature::KeyPair;
    let test = "cryptfol";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("beta to follow alpha", || {
        beta.kith(&["node", "status"]).1.contains("leader:    alpha") && beta.nodes().len() == 2
    });

    // beta's own NodeKey, as its disk would give it, and the recovery key shown (what only the node
    // itself says of its key: as itself, to the leader).
    let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let code = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let all = hex(code.public_key().as_ref());
    let (id, wrapped) = ("a1".repeat(32), "5ea1ed01".repeat(8)); // pragma: allowlist secret
    let key = |duress: &str| {
        format!(
            "apiVersion: kith.dev/v1\nkind: NodeKey\nmetadata: {{ name: beta }}\nspec: {{ id: {id}, wrapped: {wrapped}{duress} }}\n"
        )
    };
    std::fs::write(alpha.dir.join("key.yaml"), key("")).unwrap();
    alpha.ok(&["apply", "-f", "key.yaml"]);
    let betas = beta.dir.join("state/pki");
    let seen = r#"{"Status":{"statuses":[["NodeKey/beta",{"recoverySeen":true}]]}}"#;
    // (A 200 says little: a node that does not lead, or a refused write, answers 200 too. What
    // counts is the NodeKey showing it, below.)
    ask_as_node(&alpha.address(), &betas, "POST", "/v1/raft/write", Some(seen));

    // A NodeKey as `node` holds it, if it holds one: beta writes from its own copy (crypt's `set`
    // and `forget` read the local store), so each step waits for beta to have what the last made.
    let named_at = |node: &Node, name: &str| -> Option<serde_json::Value> {
        let (code, said, _) = node.kith(&["get", &format!("NodeKey/{name}"), "-o", "json"]);
        (code == 0).then(|| serde_json::from_str(&said).ok()).flatten()
    };
    let key_at = |node: &Node| named_at(node, "beta");
    let spec_at = |node: &Node| key_at(node).map(|key| key["spec"].clone());
    // The spec of beta's NodeKey, as the leader holds it.
    let held = || spec_at(&alpha).unwrap();
    let synced = || {
        wait_for("beta to hold the key the leader does", || {
            spec_at(&beta) == spec_at(&alpha)
        })
    };
    wait_for("beta's recovery key to show on both nodes", || {
        [&alpha, &beta]
            .iter()
            .all(|node| key_at(node).is_some_and(|key| key["status"]["recoverySeen"] == true))
    });

    beta.ok(&["node", "lock", "beta"]);
    assert_eq!(held()["locked"], true);
    synced();
    beta.ok(&["node", "unlock", "beta"]);
    assert!(held().get("locked").is_none(), "{}", held());
    synced();
    let shown = beta.ok(&["node", "duress", "beta"]);
    assert!(shown.contains("A duress code for beta"), "{shown}");
    assert!(
        held()["duress"].as_str().is_some_and(|public| public.len() == 64),
        "{}",
        held()
    );
    synced();
    beta.ok(&["node", "duress", "beta", "--off"]);
    assert!(held().get("duress").is_none(), "{}", held());
    synced();

    // One code for the cluster: written to every NodeKey, and taken away again.
    let shown = beta.ok(&["node", "duress", "--all"]);
    assert!(shown.contains("A duress code for the whole cluster"), "{shown}");
    assert!(
        held()["duressAll"].as_str().is_some_and(|public| public.len() == 64),
        "{}",
        held()
    );
    synced();
    beta.ok(&["node", "duress", "--all", "--off"]);
    assert!(held().get("duressAll").is_none(), "{}", held());
    synced();

    // A forget typed at beta (the cluster's code, here one the test holds the key of): the
    // leader forgets the key, as the admin.
    // (A second key, `other`: the one typed at is wiped, any other is forgotten.)
    let other = format!(
        "---\napiVersion: kith.dev/v1\nkind: NodeKey\nmetadata: {{ name: other }}\nspec: {{ id: {}, wrapped: {}, duressAll: {all} }}\n",
        "b2".repeat(32),
        "5ea1ed02".repeat(8) // pragma: allowlist secret
    );
    std::fs::write(alpha.dir.join("key.yaml"), key(&format!(", duressAll: {all}")) + &other).unwrap();
    alpha.ok(&["apply", "-f", "key.yaml"]);
    synced();
    wait_for("beta to hold the other key", || named_at(&beta, "other").is_some());
    assert_eq!(held()["duressAll"], all.as_str());
    let (status, said) = forget_signed(&beta, &code, &id);
    assert_eq!(status, "200", "{said}");
    assert!(held().get("wrapped").is_none() && held()["wiped"] == true, "{}", held());
    synced();

    // Forgotten, the other key goes when asked to be unlocked: a Delete, at the leader, as the admin.
    let forgotten = |node: &Node| named_at(node, "other").is_some_and(|key| key["spec"]["forgotten"] == true);
    wait_for("beta to see the other key forgotten", || forgotten(&beta));
    assert!(forgotten(&alpha));
    beta.ok(&["node", "unlock", "other"]);
    assert!(named_at(&alpha, "other").is_none(), "{:?}", named_at(&alpha, "other"));

    // beta followed alpha throughout: it was a follower that wrote.
    assert!(beta.kith(&["node", "status"]).1.contains("leader:    alpha"));
    assert_no_own_write_refused(&beta, &alpha, &[&alpha, &beta]);
}

/// A CA node that does not lead still admits a node and gives out certificates: the token it
/// made lets a fourth node join, which the CA node writes to the log (as its own, a Node it
/// admits) through the leader, and `kith identity cert` makes an Identity as the admin there.
/// (Not behind KITH_E2E: it pulls nothing.)
#[test]
fn join_when_the_ca_node_does_not_lead() {
    let test = "cafol";
    let mut alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let join = |name: &str, at: &Node| {
        let token = at.ok(&["node", "token"]);
        Node::start(test, name, &["--join", &at.address(), "--token", token.trim()])
    };
    let (beta, gamma) = (join("beta", &alpha), join("gamma", &alpha));
    let status = |node: &Node| node.kith(&["node", "status"]).1;
    wait_for("three voters", || {
        [&alpha, &beta, &gamma]
            .iter()
            .all(|node| status(node).contains("voters:    alpha, beta, gamma"))
    });

    // alpha goes: another leads. alpha, back, follows it.
    alpha.stop();
    wait_for("another to lead", || {
        let said = status(&beta);
        said.contains("leader:    beta") || said.contains("leader:    gamma")
    });
    alpha.child = Node::spawn(&alpha.dir, "alpha", alpha.port, &[]);
    let follows = |alpha: &Node| {
        let said = status(alpha);
        said.contains("leader:    beta") || said.contains("leader:    gamma")
    };
    wait_for("alpha to follow", || follows(&alpha));

    // The token alpha makes now, taken to alpha: delta joins through a node that does not lead
    // (checked on both sides of it: if alpha won the lead back, this tests nothing).
    assert!(follows(&alpha), "alpha leads again before the join: {}", status(&alpha));
    let delta = join("delta", &alpha);
    wait_for("delta in every list", || {
        [&alpha, &beta, &gamma, &delta]
            .iter()
            .all(|node| node.nodes().len() == 4)
    });
    assert!(follows(&alpha), "alpha led during the join: {}", status(&alpha));
    // An Identity's certificate is made there too.
    alpha.ok(&["identity", "cert", "carol", "--out", "."]);
    assert!(alpha.dir.join("carol.crt").exists());
    wait_for("carol on the leader's side", || {
        beta.kith(&["get", "Identity/carol"]).0 == 0 && gamma.kith(&["get", "Identity/carol"]).0 == 0
    });

    let leader = if status(&alpha).contains("leader:    beta") {
        &beta
    } else {
        &gamma
    };
    assert!(follows(&alpha), "alpha led during the certificate: {}", status(&alpha));
    assert_no_own_write_refused(&alpha, leader, &[&alpha, &beta, &gamma, &delta]);
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
        .current_dir(&beta.dir)
        .env("KITH_SOCKET", "kithd.sock")
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
        .env("KITH_SOCKET", "kithd.sock")
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
    ask_as_node_with(address, dir, method, path, &[], body)
}

/// The same, with `headers`.
fn ask_as_node_with(
    address: &str,
    dir: &Path,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (String, String) {
    let mut curl = Command::new("curl");
    curl.arg("--cert").arg(dir.join("node.crt"));
    curl.arg("--key").arg(dir.join("node.key"));
    ask(curl, method, &format!("https://{address}{path}"), headers, body)
}

/// `curl` (its own arguments given) asked `method url`; returns the status code and what was
/// answered.
fn ask(mut curl: Command, method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>) -> (String, String) {
    curl.args(["-sk", "-w", "\n%{http_code}", "--max-time", "15", "-X", method]);
    for (name, value) in headers {
        curl.arg("-H").arg(format!("{name}: {value}"));
    }
    if let Some(body) = body {
        curl.args(["-H", "content-type: application/json", "-d", body]);
    }
    let out = curl.arg(url).output().unwrap();
    let out = String::from_utf8_lossy(&out.stdout).into_owned();
    let (said, code) = out.rsplit_once('\n').unwrap_or(("", &out));
    (code.to_string(), said.to_string())
}

/// The admin's `x-kith-signed` (the key of seed [7; 32]) over `method path body`, for the node
/// `target` of the cluster `id`, with nonce number `nonce` (docs/adr-taken-node.md).
fn signed_by_admin(id: &str, target: &str, method: &str, path: &str, body: &[u8], nonce: u32) -> String {
    use base64::Engine;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let (expires, nonce) = (now.as_secs() + 120, format!("{nonce:032x}"));
    let body = hex(ring::digest::digest(&ring::digest::SHA256, body).as_ref());
    let who = "local socket";
    let message = format!("kith-signed-v1\n{id}\n{target}\n{method}\n{path}\n{body}\n{who}\n{expires}\n{nonce}\n");
    let sig = admin_key().sign(message.as_bytes());
    let sig = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());
    format!("v1; who={who}; target={target}; expires={expires}; nonce={nonce}; sig={sig}")
}

fn admin_key() -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}

/// Under the Cluster's `spec.signing: required` a node's word for who asked stands only with
/// their signature, made for the node it reaches (docs/adr-taken-node.md). The test plays a
/// taken beta with beta's certificate, and the admin with the key of seed [7; 32].
#[test]
fn signed_hops_alone_stand_once_signing_is_required() {
    use ring::signature::KeyPair;
    let (test, signed, by) = ("signed_hop", "x-kith-signed", "x-kith-for");
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    // (The cluster's id, as a signer has it: the print of its CA, the token's third part.)
    let id = token.trim().split('.').nth(2).unwrap().to_string();
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("beta to have the store", || beta.nodes().len() == 2);
    let betas = beta.dir.join("state/pki");
    let logs = "/v1/logs/Workload/default/none?here=true";
    let hop = |headers: &[(&str, &str)]| ask_as_node_with(&alpha.address(), &betas, "GET", logs, headers, None);
    // Open: a node's word, as before.
    let (open, said) = hop(&[(by, "local socket")]);
    assert_ne!(open, "403", "{said}");

    // The admin's key is written unsigned once (trust on first use); then neither another key
    // nor `required` is, unsigned.
    let key = admin_key()
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let cluster = |key: &str, more: &str| {
        format!(
            "apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {key}{more} }}\n"
        )
    };
    std::fs::write(alpha.dir.join("cluster.yaml"), cluster(&key, "")).unwrap();
    alpha.ok(&["apply", "-f", "cluster.yaml"]);
    let other = "ab".repeat(32);
    for (key, more) in [(key.as_str(), ", signing: required"), (other.as_str(), "")] {
        std::fs::write(alpha.dir.join("cluster.yaml"), cluster(key, more)).unwrap();
        let (code, _, err) = alpha.kith(&["apply", "-f", "cluster.yaml"]);
        assert!(
            code != 0 && err.contains("changed only by a write the admin signed"),
            "{err}"
        );
    }
    // Signed at the local socket, it is; and that signature is good once.
    let body = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": "home" },
        "spec": { "adminKey": key, "signing": "required" } }])
    .to_string();
    let header = signed_by_admin(&id, "alpha", "POST", "/v1/apply", body.as_bytes(), 1);
    let local = || {
        let mut curl = Command::new("curl");
        curl.current_dir(&alpha.dir).args(["--unix-socket", "kithd.sock"]);
        ask(curl, "POST", "http://kithd/v1/apply", &[(signed, &header)], Some(&body))
    };
    let (code, said) = local();
    assert_eq!(code, "200", "{said}");
    let (code, said) = local();
    assert!(code == "401" && said.contains("used already"), "{code} {said}");

    // Now a node's word alone is refused, naming the node.
    let (code, said) = hop(&[(by, "local socket")]);
    assert!(
        code == "403" && said.contains("an unsigned caller passed on by node beta"),
        "{code} {said}"
    );
    // A node asking for itself, naming no one, signs nothing yet (layers 2 and 3 hold what it
    // may write): pinned, so a later layer changes it on purpose.
    let (code, said) = hop(&[]);
    assert!(!said.contains("unsigned caller"), "{code} {said}");
    // With the admin's signature for alpha it stands, once.
    let header = signed_by_admin(&id, "alpha", "GET", logs, b"", 2);
    let (code, said) = hop(&[(by, "local socket"), (signed, &header)]);
    assert_eq!(code, open, "{said}");
    let (code, said) = hop(&[(by, "local socket"), (signed, &header)]);
    assert!(code == "403" && said.contains("used already"), "{code} {said}");
    // Signed for beta, for another cluster, over another request, or passed on for someone else:
    // refused.
    let zeros = "0".repeat(64);
    for (header, named, why) in [
        (
            signed_by_admin(&id, "beta", "GET", logs, b"", 3),
            "local socket",
            "signed for beta, not for alpha",
        ),
        (
            signed_by_admin(&zeros, "alpha", "GET", logs, b"", 4),
            "local socket",
            "not local socket's over this request",
        ),
        (
            signed_by_admin(&id, "alpha", "GET", "/v1/logs/Workload/default/other?here=true", b"", 5),
            "local socket",
            "not local socket's",
        ),
        (
            signed_by_admin(&id, "alpha", "GET", logs, b"", 6),
            "someone",
            "and passed on a signature by",
        ),
    ] {
        let (code, said) = hop(&[(by, named), (signed, &header)]);
        assert!(code == "403" && said.contains(why), "{why}: {code} {said}");
    }

    // A write passed on for an Identity, unsigned: refused where the log is led.
    let write = serde_json::json!({ "Apply": { "resources": [{ "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
        "metadata": { "name": "forged" }, "spec": { "data": { "a": "b" } } }], "at": 0 } });
    let write = write.to_string();
    let (code, said) = ask_as_node_with(
        &alpha.address(),
        &betas,
        "POST",
        "/v1/raft/write",
        &[(by, "someone")],
        Some(&write),
    );
    assert!(
        said.contains("an unsigned caller passed on by node beta"),
        "{code} {said}"
    );

    // The local socket reads, and a write it makes with a passphrase that is not the admin's is
    // refused: kith signs with the passphrase it is given (none here).
    assert!(alpha.ok(&["get", "cluster/home"]).contains("home"));
    let (code, _, err) = alpha.kith(&["apply", "-f", "cluster.yaml"]);
    assert!(
        code != 0 && err.contains("not local socket's over this request"),
        "{err}"
    );
}

/// A signed write made at a follower reaches the leader as the admin signed it: the follower
/// passes the request on as it came (its path, its body, its signature), and the leader checks
/// that signature over it. The follower refuses the same signature again; the leader refuses a
/// write a node passes on without one.
#[test]
fn a_signed_write_through_a_follower_is_taken_as_signed() {
    use ring::signature::KeyPair;
    let (test, signed, by) = ("signed_relay", "x-kith-signed", "x-kith-for");
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let id = token.trim().split('.').nth(2).unwrap().to_string();
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("beta to have the store", || beta.nodes().len() == 2);
    let key = admin_key()
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    // The admin's key is written unsigned once (trust on first use), at alpha.
    let cluster =
        format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {key} }}\n");
    std::fs::write(alpha.dir.join("cluster.yaml"), cluster).unwrap();
    alpha.ok(&["apply", "-f", "cluster.yaml"]);
    // Beta verifies the signature against the key it holds, so wait until its store has the key.
    wait_for("beta to hold the admin's key", || {
        beta.kith(&["get", "cluster/home", "-o", "json"]).1.contains(&key)
    });

    // Signed at beta's local socket for the cluster, the change is taken by the leader alpha.
    let at_beta = |header: &str, body: &str| {
        let mut curl = Command::new("curl");
        curl.current_dir(&beta.dir).args(["--unix-socket", "kithd.sock"]);
        ask(curl, "POST", "http://kithd/v1/apply", &[(signed, header)], Some(body))
    };
    let body = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": "home" },
        "spec": { "adminKey": key, "signing": "required" } }])
    .to_string();
    let header = signed_by_admin(&id, "*", "POST", "/v1/apply", body.as_bytes(), 1);
    let (code, said) = at_beta(&header, &body);
    assert_eq!(code, "200", "{said}");
    let held = alpha.ok(&["get", "cluster/home", "-o", "json"]);
    assert!(held.contains("\"signing\": \"required\""), "{held}");

    // Replayed at beta: refused there, as the signature was used already.
    let (code, said) = at_beta(&header, &body);
    assert!(code == "401" && said.contains("used already"), "{code} {said}");

    // A write beta passes on with no signature, for the local socket: refused where the leader is.
    let betas = beta.dir.join("state/pki");
    let (code, said) = ask_as_node_with(
        &alpha.address(),
        &betas,
        "POST",
        "/v1/apply",
        &[(by, "local socket")],
        Some(&body),
    );
    assert!(
        code == "403" && said.contains("an unsigned caller passed on by node beta"),
        "{code} {said}"
    );

    // Another signed write, through beta, is taken too.
    let config =
        serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "ConfigMap", "metadata": { "name": "relayed" },
        "spec": { "data": { "a": "b" } } }])
        .to_string();
    let header = signed_by_admin(&id, "*", "POST", "/v1/apply", config.as_bytes(), 2);
    let (code, said) = at_beta(&header, &config);
    assert_eq!(code, "200", "{said}");
    assert!(alpha.ok(&["get", "configmap/relayed"]).contains("relayed"));
}

/// Under `spec.signing: required` at format 4 every node refuses a bare write that changes access:
/// a signed one made at the follower is relayed as it came, written Signed by the leader and
/// applied alike on both; the certificate route (at the leader, the CA's node) writes its Identity
/// Signed; an unsigned one, at either local socket or passed on by a node, is refused.
#[test]
fn signed_access_writes_are_applied_alike_and_bare_ones_are_refused_under_required() {
    use ring::signature::KeyPair;
    let (test, signed, by) = ("signed_access", "x-kith-signed", "x-kith-for");
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let id = token.trim().split('.').nth(2).unwrap().to_string();
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("beta to have the store", || beta.nodes().len() == 2);
    let key = admin_key()
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let cluster =
        format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {key} }}\n");
    std::fs::write(alpha.dir.join("cluster.yaml"), cluster).unwrap();
    alpha.ok(&["apply", "-f", "cluster.yaml"]);
    wait_for("beta to hold the admin's key", || {
        beta.kith(&["get", "cluster/home", "-o", "json"]).1.contains(&key)
    });
    // Every member reads format 4 (a signed write is wrapped as Signed only from there).
    let checked = r#""payload":{"Normal":"MarkChecked"}"#;
    wait_for("both logs to hold the format 4 mark", || {
        [&alpha, &beta]
            .iter()
            .all(|node| running_log_entries(node).is_some_and(|log| log.contains(checked)))
    });

    let at = |node: &Node, method: &str, path: &str, target: &str, nonce: u32, body: &str| {
        let header = signed_by_admin(&id, target, method, path, body.as_bytes(), nonce);
        let mut curl = Command::new("curl");
        curl.current_dir(&node.dir).args(["--unix-socket", "kithd.sock"]);
        let body = (!body.is_empty()).then_some(body);
        ask(curl, method, &format!("http://kithd{path}"), &[(signed, &header)], body)
    };
    let bare_at = |node: &Node, body: &str| {
        let mut curl = Command::new("curl");
        curl.current_dir(&node.dir).args(["--unix-socket", "kithd.sock"]);
        ask(curl, "POST", "http://kithd/v1/apply", &[], Some(body))
    };
    let required = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": "home" },
        "spec": { "adminKey": key, "signing": "required" } }])
    .to_string();
    let (code, said) = at(&beta, "POST", "/v1/apply", "*", 1, &required);
    assert_eq!(code, "200", "{said}");

    // A signed Role, written at the follower: the leader and the follower both hold it.
    let role = |name: &str| {
        serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Role", "metadata": { "name": name },
            "spec": { "rules": [{ "kinds": ["ConfigMap"], "verbs": ["get"] }] } }])
        .to_string()
    };
    let (code, said) = at(&beta, "POST", "/v1/apply", "*", 2, &role("signed-role"));
    assert_eq!(code, "200", "{said}");
    for node in [&alpha, &beta] {
        wait_for("both to hold the signed Role", || {
            node.kith(&["get", "role/signed-role"]).0 == 0
        });
    }
    // Written Signed: the leader's log holds the entry with its path.
    wait_for("the leader's log to hold the Signed entry", || {
        running_log_entries(&alpha).is_some_and(|log| log.contains("\"Signed\""))
    });

    // Bare: at either local socket (no signature), and passed on by beta for the local socket.
    for node in [&alpha, &beta] {
        let (code, said) = bare_at(node, &role("bare-role"));
        assert!(
            code == "403" && said.contains("requires the admin's signature"),
            "{code} {said}"
        );
    }
    let betas = beta.dir.join("state/pki");
    let (code, said) = ask_as_node_with(
        &alpha.address(),
        &betas,
        "POST",
        "/v1/apply",
        &[(by, "local socket")],
        Some(&role("bare-role")),
    );
    assert!(
        code == "403" && said.contains("an unsigned caller passed on by node beta"),
        "{code} {said}"
    );
    for node in [&alpha, &beta] {
        assert!(node.kith(&["get", "role/bare-role"]).0 != 0, "a bare Role was written");
    }

    // The certificate route at the leader writes the Identity Signed, and both hold its key.
    let path = "/v1/identities/carol/certificate";
    let (code, said) = at(&alpha, "POST", path, "alpha", 3, "");
    assert_eq!(code, "200", "{said}");
    let public = |node: &Node| {
        let said = node.kith(&["get", "identity/carol", "-o", "json"]).1;
        let (begin, end) = ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
        let from = said.find(begin)?;
        said.find(end).map(|to| said[from..to].to_string())
    };
    wait_for("both to hold carol's key", || {
        let (one, two) = (public(&alpha), public(&beta));
        one.is_some() && one == two
    });
    wait_for("the leader's log to hold the certificate's Signed entry", || {
        running_log_entries(&alpha).is_some_and(|log| log.contains(path))
    });
    // Replayed, it is refused (its nonce was taken in the log).
    let (code, said) = at(&alpha, "POST", path, "alpha", 3, "");
    assert!(code == "401" && said.contains("used already"), "{code} {said}");
}

/// A signed delete and a signed rollback made at a follower reach the leader as the admin signed
/// them, as an apply does: the follower passes each on as it came (its method, path and
/// signature). A delete a node passes on with no signature is refused where the leader is.
#[test]
fn signed_delete_and_rollback_through_a_follower_are_taken_as_signed() {
    use ring::signature::KeyPair;
    let (test, signed, by) = ("signed_delete", "x-kith-signed", "x-kith-for");
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let id = token.trim().split('.').nth(2).unwrap().to_string();
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("beta to have the store", || beta.nodes().len() == 2);
    let key = admin_key()
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let cluster =
        format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {key} }}\n");
    std::fs::write(alpha.dir.join("cluster.yaml"), cluster).unwrap();
    alpha.ok(&["apply", "-f", "cluster.yaml"]);
    wait_for("beta to hold the admin's key", || {
        beta.kith(&["get", "cluster/home", "-o", "json"]).1.contains(&key)
    });

    // A signed request at beta's local socket, as the admin signed it.
    let at_beta = |method: &str, path: &str, nonce: u32, body: &str| {
        let header = signed_by_admin(&id, "*", method, path, body.as_bytes(), nonce);
        let mut curl = Command::new("curl");
        curl.current_dir(&beta.dir).args(["--unix-socket", "kithd.sock"]);
        let body = (!body.is_empty()).then_some(body);
        ask(curl, method, &format!("http://kithd{path}"), &[(signed, &header)], body)
    };
    let config = |name: &str, data: &str| {
        serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "ConfigMap", "metadata": { "name": name },
            "spec": { "data": { "a": data } } }])
        .to_string()
    };
    let required = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": "home" },
        "spec": { "adminKey": key, "signing": "required" } }])
    .to_string();
    let (code, said) = at_beta("POST", "/v1/apply", 1, &required);
    assert_eq!(code, "200", "{said}");
    assert!(
        alpha
            .ok(&["get", "cluster/home", "-o", "json"])
            .contains("\"signing\": \"required\"")
    );

    // Two revisions of `kept`, then a signed rollback to the first, made at beta.
    let (code, said) = at_beta("POST", "/v1/apply", 2, &config("kept", "one"));
    assert_eq!(code, "200", "{said}");
    let (code, said) = at_beta("POST", "/v1/apply", 3, &config("kept", "two"));
    assert_eq!(code, "200", "{said}");
    let (code, said) = at_beta("POST", "/v1/rollback/ConfigMap/default/kept?to=1", 4, "");
    assert_eq!(code, "200", "{said}");
    let kept = alpha.ok(&["get", "configmap/kept", "-o", "json"]);
    assert!(kept.contains("\"one\"") && !kept.contains("\"two\""), "{kept}");
    let audit = alpha.ok(&["audit", "--tail", "1000"]);
    assert!(
        audit
            .lines()
            .any(|line| line.contains("rollback") && line.contains("local socket via node beta")),
        "{audit}"
    );

    // A signed delete made at beta removes the ConfigMap at the leader.
    let (code, said) = at_beta("POST", "/v1/apply", 5, &config("gone", "bye"));
    assert_eq!(code, "200", "{said}");
    let (code, said) = at_beta("DELETE", "/v1/resources/ConfigMap/default/gone", 6, "");
    assert_eq!(code, "200", "{said}");
    assert!(
        alpha.kith(&["get", "configmap/gone"]).0 != 0,
        "the delete did not reach the leader"
    );
    // The leader took it as the admin's, passed on by beta: its audit names the signer via beta.
    let audit = alpha.ok(&["audit"]);
    assert!(
        audit
            .lines()
            .any(|line| line.contains("delete") && line.contains("local socket via node beta")),
        "{audit}"
    );

    // A delete beta passes on with no signature is refused where the leader is, and removes nothing.
    let betas = beta.dir.join("state/pki");
    let (code, said) = ask_as_node_with(
        &alpha.address(),
        &betas,
        "DELETE",
        "/v1/resources/ConfigMap/default/kept",
        &[(by, "local socket")],
        None,
    );
    assert!(
        code == "403" && said.contains("an unsigned caller passed on by node beta"),
        "{code} {said}"
    );
    assert!(alpha.ok(&["get", "configmap/kept"]).contains("kept"));
}

/// A signed rollback of a Release made at a follower reaches the leader as the admin signed it,
/// as a ConfigMap's does: the leader's audit names the signer via the follower, and the leader
/// does not take it as the follower's own write. A rollback signed for another query is refused
/// where the leader is, and changes nothing.
#[test]
fn signed_release_rollback_through_a_follower_is_taken_as_the_admins() {
    use ring::signature::KeyPair;
    let (test, signed, by) = ("signed_release", "x-kith-signed", "x-kith-for");
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let id = token.trim().split('.').nth(2).unwrap().to_string();
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("beta to have the store", || beta.nodes().len() == 2);
    let key = admin_key()
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let cluster =
        format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {key} }}\n");
    std::fs::write(alpha.dir.join("cluster.yaml"), cluster).unwrap();
    alpha.ok(&["apply", "-f", "cluster.yaml"]);
    wait_for("beta to hold the admin's key", || {
        beta.kith(&["get", "cluster/home", "-o", "json"]).1.contains(&key)
    });

    // A signed request at beta's local socket, as the admin signed it.
    let at_beta = |method: &str, path: &str, nonce: u32, body: &str| {
        let header = signed_by_admin(&id, "*", method, path, body.as_bytes(), nonce);
        let mut curl = Command::new("curl");
        curl.current_dir(&beta.dir).args(["--unix-socket", "kithd.sock"]);
        let body = (!body.is_empty()).then_some(body);
        ask(curl, method, &format!("http://kithd{path}"), &[(signed, &header)], body)
    };
    let required = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": "home" },
        "spec": { "adminKey": key, "signing": "required" } }])
    .to_string();
    let (code, said) = at_beta("POST", "/v1/apply", 1, &required);
    assert_eq!(code, "200", "{said}");
    assert!(
        alpha
            .ok(&["get", "cluster/home", "-o", "json"])
            .contains("\"signing\": \"required\"")
    );

    // Two revisions of the Release `r`: the first names package `maps`, the second `other`.
    let release = |package: &str| {
        serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Release", "metadata": { "name": "r" },
            "spec": { "package": { "name": package } } }])
        .to_string()
    };
    let (code, said) = at_beta("POST", "/v1/apply", 2, &release("maps"));
    assert_eq!(code, "200", "{said}");
    let (code, said) = at_beta("POST", "/v1/apply", 3, &release("other"));
    assert_eq!(code, "200", "{said}");
    let before = alpha.ok(&["get", "release/r", "-o", "json"]);
    assert!(before.contains("other") && !before.contains("maps"), "{before}");

    // A rollback signed for `?to=1`, sent to `?to=2` by beta's certificate: refused where the
    // leader is, and the Release is still `other`.
    let betas = beta.dir.join("state/pki");
    let signed_for_one = signed_by_admin(&id, "alpha", "POST", "/v1/rollback/Release/default/r?to=1", b"", 4);
    let (code, said) = ask_as_node_with(
        &alpha.address(),
        &betas,
        "POST",
        "/v1/rollback/Release/default/r?to=2",
        &[(by, "local socket"), (signed, &signed_for_one)],
        None,
    );
    assert!(code == "403" && said.contains("not local socket's"), "{code} {said}");
    assert!(alpha.ok(&["get", "release/r", "-o", "json"]).contains("other"));

    // The admin's rollback to revision 1, made at beta: the leader takes it as the admin's. (A
    // Release is applied as it goes back, so its audit line is an apply's: the lines the rollback
    // adds at the leader are the ones checked.)
    let before = alpha.ok(&["audit", "--tail", "1000"]).lines().count();
    let (code, said) = at_beta("POST", "/v1/rollback/Release/default/r?to=1", 5, "");
    assert_eq!(code, "200", "{said}");
    let back = alpha.ok(&["get", "release/r", "-o", "json"]);
    assert!(back.contains("maps") && !back.contains("other"), "{back}");
    let audit = alpha.ok(&["audit", "--tail", "1000"]);
    assert!(
        audit
            .lines()
            .skip(before)
            .any(|line| line.contains("Release/default/r") && line.contains("local socket via node beta")),
        "the rollback is not in the leader's audit ({before} lines before): {audit}"
    );
}

/// A signed restore asked of a node that does not have the volume is passed on as it came, so the
/// node that has the volume checks the signature the admin made, over the path the admin signed,
/// and takes it as the admin's under `signing: required`. A restore whose path is not the one
/// signed is refused where the volume is, and restores nothing.
#[test]
fn signed_restore_through_another_node_is_taken_under_required_signing() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    use ring::signature::KeyPair;
    let (test, signed, by) = ("signed_restore", "x-kith-signed", "x-kith-for");
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let id = token.trim().split('.').nth(2).unwrap().to_string();
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("two nodes with addresses", || {
        alpha.nodes().iter().filter(|(_, at)| !at.is_empty()).count() == 2
    });
    let key = admin_key()
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let cluster =
        format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {key} }}\n");
    std::fs::write(alpha.dir.join("cluster.yaml"), cluster).unwrap();
    alpha.ok(&["apply", "-f", "cluster.yaml"]);
    wait_for("beta to hold the admin's key", || {
        beta.kith(&["get", "cluster/home", "-o", "json"]).1.contains(&key)
    });

    // The volume and its backup are at alpha; beta does not have the volume.
    let data = alpha.dir.join("state/volumes/default/data/d");
    std::fs::create_dir_all(data.join("deep")).unwrap();
    std::fs::write(data.join("deep/file"), b"what must not be lost").unwrap();
    let yaml = "apiVersion: kith.dev/v1\nkind: Volume\nmetadata: { name: data }\nspec: { node: alpha, path: d }\n---\n\
                apiVersion: kith.dev/v1\nkind: Backup\nmetadata: { name: often }\nspec: { volume: data, every: 1d, keep: 2 }\n";
    std::fs::write(alpha.dir.join("backup.yaml"), yaml).unwrap();
    alpha.ok(&["apply", "-f", "backup.yaml"]);
    let status = |node: &Node, kind: &str, name: &str| {
        let found: serde_json::Value = serde_json::from_str(&node.ok(&["get", kind, name, "-o", "json"])).unwrap();
        found.as_array().map_or(found.clone(), |found| found[0].clone())["status"].clone()
    };
    wait_for("the backup to be made", || {
        status(&alpha, "backup", "often")["backups"][0]["blob"].is_string()
    });
    let made = status(&alpha, "backup", "often")["backups"][0].clone();
    std::fs::remove_dir_all(&data).unwrap();

    // Required from here on: the signed Cluster is made at beta.
    let at_beta = |method: &str, path: &str, nonce: u32, body: &str| {
        let header = signed_by_admin(&id, "*", method, path, body.as_bytes(), nonce);
        let mut curl = Command::new("curl");
        curl.current_dir(&beta.dir).args(["--unix-socket", "kithd.sock"]);
        let body = (!body.is_empty()).then_some(body);
        ask(curl, method, &format!("http://kithd{path}"), &[(signed, &header)], body)
    };
    let required = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": "home" },
        "spec": { "adminKey": key, "signing": "required" } }])
    .to_string();
    let (code, said) = at_beta("POST", "/v1/apply", 1, &required);
    assert_eq!(code, "200", "{said}");
    assert!(
        alpha
            .ok(&["get", "cluster/home", "-o", "json"])
            .contains("\"signing\": \"required\"")
    );

    // A restore signed for another path than the one it is sent on, passed on by beta's certificate:
    // refused where the volume is, and nothing is restored.
    // The admin signs the latest backup's restore (no `?at=`); beta would add `?at=` to it, so the
    // path the admin signed is the one it must pass on.
    let betas = beta.dir.join("state/pki");
    let path = "/v1/backups/default/often/restore";
    let signed_other = signed_by_admin(&id, "*", "POST", path, b"", 2);
    let sent_other = format!("{path}?at={}", made["at"]);
    let (code, said) = ask_as_node_with(
        &alpha.address(),
        &betas,
        "POST",
        &sent_other,
        &[(by, "local socket"), (signed, &signed_other)],
        None,
    );
    assert!(code == "403" && said.contains("not local socket's"), "{code} {said}");
    assert!(!data.exists(), "a refused restore wrote the volume");

    // The restore the admin signed, made at beta: beta passes it on as it came, and the volume is back.
    let before = alpha.ok(&["audit", "--tail", "1000"]).lines().count();
    let (code, said) = at_beta("POST", path, 3, "");
    assert_eq!(code, "200", "{said}");
    assert_eq!(std::fs::read(data.join("deep/file")).unwrap(), b"what must not be lost");
    let audit = alpha.ok(&["audit", "--tail", "1000"]);
    assert!(
        audit
            .lines()
            .skip(before)
            .any(|line| line.contains("restore") && line.contains("local socket via node beta")),
        "the restore is not in the leader's audit ({before} lines before): {audit}"
    );
}

/// A signed change a follower would make on a route the leader does not check the signature of (a
/// drain, which applies a Node) is refused at the follower: it is not sent to the leader as the
/// node's own write, and nothing changes.
#[test]
fn a_signed_change_a_follower_cannot_pass_on_as_it_came_is_refused() {
    use ring::signature::KeyPair;
    let (test, signed) = ("signed_refuse", "x-kith-signed");
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let id = token.trim().split('.').nth(2).unwrap().to_string();
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("beta to have the store", || beta.nodes().len() == 2);
    let key = admin_key()
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let cluster =
        format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {key} }}\n");
    std::fs::write(alpha.dir.join("cluster.yaml"), cluster).unwrap();
    alpha.ok(&["apply", "-f", "cluster.yaml"]);
    wait_for("beta to hold the admin's key", || {
        beta.kith(&["get", "cluster/home", "-o", "json"]).1.contains(&key)
    });
    let at_beta = |method: &str, path: &str, nonce: u32, body: &str| {
        let header = signed_by_admin(&id, "*", method, path, body.as_bytes(), nonce);
        let mut curl = Command::new("curl");
        curl.current_dir(&beta.dir).args(["--unix-socket", "kithd.sock"]);
        let body = (!body.is_empty()).then_some(body);
        ask(curl, method, &format!("http://kithd{path}"), &[(signed, &header)], body)
    };
    let required = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": "home" },
        "spec": { "adminKey": key, "signing": "required" } }])
    .to_string();
    let (code, said) = at_beta("POST", "/v1/apply", 1, &required);
    assert_eq!(code, "200", "{said}");

    // The drain of beta, signed and made at beta: refused there, and beta is not drained.
    let (code, said) = at_beta("POST", "/v1/drain/beta?do=drain", 2, "");
    assert!(
        code != "200" && said.contains("not passed on as it came"),
        "{code} {said}"
    );
    let node = alpha.ok(&["get", "node/beta", "-o", "json"]);
    assert!(!node.contains("kith.dev/drain"), "{node}");
}

/// The status names the cluster (the id a signer salts its key with, the print of the CA the
/// join token carries) and says `open` until the Cluster says `signing: required`.
#[test]
fn the_status_names_the_cluster_and_whether_writes_must_be_signed() {
    use ring::signature::KeyPair;
    let alpha = Node::start("signed_status", "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token"]);
    let id = token.trim().split('.').nth(2).unwrap().to_string();
    let status = || {
        let mut curl = Command::new("curl");
        curl.current_dir(&alpha.dir).args(["--unix-socket", "kithd.sock"]);
        let (code, said) = ask(curl, "GET", "http://kithd/v1/cluster", &[], None);
        assert_eq!(code, "200", "{said}");
        serde_json::from_str::<serde_json::Value>(&said).unwrap()
    };
    let before = status();
    assert_eq!(before["clusterId"], id.as_str(), "{before}");
    assert_eq!(before["signing"], "open", "{before}");

    let key = admin_key()
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let cluster =
        format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {key} }}\n");
    std::fs::write(alpha.dir.join("cluster.yaml"), cluster).unwrap();
    alpha.ok(&["apply", "-f", "cluster.yaml"]);
    assert_eq!(status()["signing"], "open");

    let body = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": "home" },
        "spec": { "adminKey": key, "signing": "required" } }])
    .to_string();
    let header = signed_by_admin(&id, "*", "POST", "/v1/apply", body.as_bytes(), 1);
    let mut curl = Command::new("curl");
    curl.current_dir(&alpha.dir).args(["--unix-socket", "kithd.sock"]);
    let (code, said) = ask(
        curl,
        "POST",
        "http://kithd/v1/apply",
        &[("x-kith-signed", header.as_str())],
        Some(&body),
    );
    assert_eq!(code, "200", "{said}");
    let after = status();
    assert_eq!(after["signing"], "required", "{after}");
    assert_eq!(after["clusterId"], id.as_str(), "{after}");
}

/// A Workload that runs as an Identity: the CA holder signs, for the worker it is placed on
/// alone, a certificate for a key it never saw; the API takes that for what the Identity's
/// Role allows, and refuses it the moment the store says otherwise. The test plays the
/// worker's part with its certificate: the container's image is one nobody serves, so the
/// worker asks for nothing itself (e2e.rs has a container that runs as an Identity).
#[test]
fn a_workload_runs_as_an_identity() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let test = "runsas";
    let alpha = Node::start(test, "alpha", &[]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let token = alpha.ok(&["node", "token", "--worker"]);
    let beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    wait_for("two ready nodes", || {
        alpha.kith(&["get", "node"]).1.matches("ready at").count() == 2
    });
    let apply = |text: &str| {
        std::fs::write(alpha.dir.join("apply.yaml"), text).unwrap();
        alpha.ok(&["apply", "-f", "apply.yaml"]);
    };
    let identity = |namespace: &str| {
        format!(
            "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {{ name: gateway }}\n\
             spec: {{ workloads: [{{ namespace: {namespace}, names: [proxy] }}] }}\n"
        )
    };
    apply(&format!(
        "apiVersion: kith.dev/v1\nkind: Namespace\nmetadata: {{ name: web }}\n---\n{}---\n\
         apiVersion: kith.dev/v1\nkind: Role\nmetadata: {{ name: services }}\n\
         spec: {{ rules: [{{ kinds: [Service], verbs: [get, list] }}] }}\n---\n\
         apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{ name: gateway }}\n\
         spec: {{ role: services, subjects: [gateway] }}\n---\n\
         apiVersion: kith.dev/v1\nkind: Secret\nmetadata: {{ name: token, namespace: web }} # pragma: allowlist secret\n\
         spec: {{ data: {{ a: b }} }}\n---\n\
         apiVersion: kith.dev/v1\nkind: Workload\nmetadata: {{ name: proxy, namespace: web }}\nspec:\n  \
         identity: gateway\n  placement: {{ require: {{ kith.dev/trust: worker }} }}\n  template:\n    \
         containers: [{{ name: run, image: '127.0.0.1:1/none:1' }}]\n",
        identity("web")
    ));
    wait_for("proxy to be placed on the worker", || {
        let proxy = alpha.ok(&["get", "workload/proxy", "-n", "web", "-o", "json"]);
        serde_json::from_str::<serde_json::Value>(&proxy).unwrap()["status"]["nodes"]["0"] == "beta"
    });

    // The worker makes the key; the CA holder is sent its public half.
    let key = rcgen::KeyPair::generate().unwrap();
    let public = alpha.dir.join("public.der");
    std::fs::write(&public, rcgen::PublicKeyData::subject_public_key_info(&key)).unwrap();
    let ask = |node: &Path| {
        let mut curl = Command::new("curl");
        curl.args([
            "-sk",
            "-w",
            "\n%{http_code}",
            "--max-time",
            "15",
            "-X",
            "POST",
            "--data-binary",
        ]);
        curl.arg(format!("@{}", public.display()));
        curl.arg("--cert")
            .arg(node.join("node.crt"))
            .arg("--key")
            .arg(node.join("node.key"));
        let out = curl.arg(format!(
            "https://{}/v1/workload-certificate/web/proxy/0",
            alpha.address()
        ));
        let out = String::from_utf8_lossy(&out.output().unwrap().stdout).into_owned();
        let (said, code) = out.rsplit_once('\n').unwrap();
        (code.to_string(), said.to_string())
    };
    let (alphas, betas) = (alpha.dir.join("state/pki"), beta.dir.join("state/pki"));
    // Not for a node it is not placed on, whatever that node is.
    let (code, said) = ask(&alphas);
    assert!(
        code == "403" && said.contains("not placed on node alpha"),
        "{code} {said}"
    );
    let (code, cert) = ask(&betas);
    assert_eq!(code, "200", "{cert}");
    let (code, said) = ask(&betas);
    assert_eq!(code, "429", "once a minute: {said}");

    // The pod's files: what its Identity's Role allows, and nothing else.
    let pod = alpha.dir.join("pod");
    std::fs::create_dir_all(&pod).unwrap();
    std::fs::write(pod.join("node.crt"), &cert).unwrap();
    std::fs::write(pod.join("node.key"), key.serialize_pem()).unwrap();
    let call = |path: &str| ask_as_node(&alpha.address(), &pod, "GET", path, None);
    let services = "/v1/resources?kind=Service";
    assert_eq!(call(services).0, "200", "{:?}", call(services));
    assert_eq!(call("/v1/resources/Secret/web/token").0, "403");
    // The Identity's word withdrawn (the Identity still there): refused; given back, good.
    apply(&identity("shop"));
    let (code, said) = call(services);
    assert!(
        code == "401" && said.contains("does not name namespace web"),
        "{code} {said}"
    );
    apply(&identity("web"));
    assert_eq!(call(services).0, "200");
    // A copy of the files taken before the Workload is deleted is refused after.
    alpha.ok(&["delete", "workload/proxy", "-n", "web"]);
    let (code, said) = call(services);
    assert!(
        code == "401" && said.contains("there is no Workload/web/proxy"),
        "{code} {said}"
    );
    // Each certificate made is written down.
    let audit = alpha.ok(&["audit"]);
    assert!(
        audit.contains("node beta") && audit.contains("Identity/gateway"),
        "{audit}"
    );
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
    // Whether a worker serves ingress (and is sent the hosts' certificates) is its token's
    // maker's to say, never the node's: one that says so with a plain worker's token is not let in.
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

/// A helper process, killed when the test is over.
struct Stop(Child);

impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A worker that serves ingress runs from a view too: it is sent the certificate (and key) of
/// each host the cluster exposes and the ACME account's thumbprint, and no other Secret it is
/// not placed on; a control node with `--acme` orders for it, and it serves HTTPS with what was
/// ordered. It writes no Secret and orders nothing; a plain worker is sent no host's
/// certificate and may not start serving ingress. (In a network namespace of its own, where
/// it may listen on ports 80 and 443.)
#[test]
fn ingress_worker_is_sent_its_hosts_certificates_and_no_other_secret() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1");
        return;
    }
    let name = "ingress_worker_is_sent_its_hosts_certificates_and_no_other_secret";
    if std::env::var_os("KITH_IN_NAMESPACE").is_none() {
        let unshare = |args: &[&str]| Command::new("unshare").arg("-Urn").args(args).status();
        if !unshare(&["true"]).is_ok_and(|status| status.success()) {
            return eprintln!("skipped: no unprivileged user namespaces here (unshare -Urn)");
        }
        let me = std::env::current_exe().unwrap();
        let again = "ip link set lo up && KITH_IN_NAMESPACE=1 exec \"$0\" --exact \"$1\" --nocapture";
        let status = unshare(&["sh", "-c", again, me.to_str().unwrap(), name]).unwrap();
        assert!(status.success(), "the test failed inside its namespace");
        return;
    }
    use serde_json::json;
    let test = "ingress";
    // A certificate authority of our own (never a real one): every host is 127.0.0.1 to it,
    // where the ingress worker answers its challenges on port 80.
    let authority = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test).join("authority");
    let _ = std::fs::remove_dir_all(&authority);
    std::fs::create_dir_all(&authority).unwrap();
    std::fs::write(authority.join("fake_acme.py"), include_str!("fake_acme.py")).unwrap();
    let port = free_port().to_string();
    let fake = Command::new("python3")
        .args(["fake_acme.py", "127.0.0.1", &port, "."])
        .current_dir(&authority)
        .spawn()
        .unwrap();
    let _fake = Stop(fake);
    wait_for("the authority to listen", || authority.join("ca.pem").exists());
    let directory = format!("http://127.0.0.1:{port}/directory");
    let alpha = Node::start(test, "alpha", &["--acme", &directory]);
    wait_for("alpha to list itself", || {
        alpha.kith(&["get", "node"]).0 == 0 && alpha.nodes().len() == 1
    });
    let apply = |node: &Node, text: &str| {
        std::fs::write(node.dir.join("apply.yaml"), text).unwrap();
        node.ok(&["apply", "-f", "apply.yaml"]);
    };
    // A Secret nothing places, a certificate kept by hand for a host nothing exposes, and a
    // Service exposed at a host, through the nodes that serve ingress.
    let (unplaced, gone) = ("the-word-nothing-places", "the-key-of-a-host-nothing-exposes");
    apply(
        &alpha,
        &format!(
            "apiVersion: kith.dev/v1\nkind: Secret\nmetadata: {{ name: unplaced }}\nspec: {{ data: {{ word: {unplaced} }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Secret\nmetadata: {{ name: tls-gone.example.test }}\n\
             spec: {{ data: {{ tls.crt: none, tls.key: {gone} }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: shop }}\nspec:\n  selector: {{ app: shop }}\n  \
             ports: [{{ port: 80, targetPort: 8080 }}]\n  expose: {{ host: shop.example.test, via: edge }}\n"
        ),
    );
    // A plain worker, and a worker whose token says it serves ingress.
    let token = alpha.ok(&["node", "token", "--worker"]);
    let mut beta = Node::start(test, "beta", &["--join", &alpha.address(), "--token", token.trim()]);
    let token = alpha.ok(&["node", "token", "--worker", "--ingress"]);
    let mesh = free_port().to_string();
    let join = ["--join", &alpha.address(), "--token", token.trim()];
    let serve = ["--ingress", "--mesh", &mesh, "--mesh-interface", "kith-edge"];
    let edge = Node::start(test, "edge", &[&join[..], &serve[..]].concat());
    wait_for("both workers to have their views", || {
        beta.nodes().len() == 3 && edge.nodes().len() == 3
    });
    let node: serde_json::Value = serde_json::from_str(&alpha.ok(&["get", "node/edge", "-o", "json"])).unwrap();
    assert_eq!(
        (&node["spec"]["ingress"], &node["status"]["view"]),
        (&json!(true), &json!(true)),
        "{node}"
    );

    // Alpha (which serves no ingress itself) orders the certificate, and the edge serves it.
    let tls = || {
        let service = alpha.ok(&["get", "service/shop", "-o", "json"]);
        serde_json::from_str::<serde_json::Value>(&service).unwrap()["status"]["tls"].clone()
    };
    wait_for("a certificate for the edge's host", || tls()["state"] == "ready");
    wait_for("the certificate to reach the edge's view", || {
        edge.kith(&["get", "secret/tls-shop.example.test"]).0 == 0
    });
    let ca = authority.join("ca.pem");
    // (No replica behind the Service: the handshake, with the authority's certificate, is enough.)
    let handshake = |host: &str| {
        let said = Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                "127.0.0.1:443",
                "-servername",
                host,
                "-verify_hostname",
                host,
            ])
            .arg("-CAfile")
            .arg(&ca)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        // (Said only where the server showed a certificate that the authority signed for it.)
        let said = String::from_utf8_lossy(&said.stdout).into_owned();
        said.contains(&format!("Verified peername: {host}\n")) && said.contains("Verify return code: 0 (ok)")
    };
    wait_for("the edge to serve HTTPS for the host", || {
        handshake("shop.example.test")
    });
    assert!(!handshake("gone.example.test"), "a host nothing exposes is served");
    let ordered = Command::new("curl")
        .args(["-s", &format!("http://127.0.0.1:{port}/orders")])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(ordered.stdout).unwrap(), "1");

    // What the edge's view holds: the host's certificate, the thumbprint, no other Secret.
    let view: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(edge.dir.join("state/view.json")).unwrap()).unwrap();
    let secrets: Vec<String> = view["resources"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|resource| resource["kind"] == "Secret")
        .map(|secret| {
            let metadata = &secret["metadata"];
            format!(
                "{}/{}",
                metadata["namespace"].as_str().unwrap_or("default"),
                metadata["name"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(secrets, ["default/tls-shop.example.test"]);
    assert_eq!(edge.kith(&["get", "configmap/acme", "-n", "kith-system"]).0, 0);
    let secret = |name: &str, namespace: &str| {
        let got = alpha.ok(&["get", &format!("secret/{name}"), "-n", namespace, "-o", "json"]);
        serde_json::from_str::<serde_json::Value>(&got).unwrap()["spec"]["data"].clone()
    };
    let account = secret("acme-account", "kith-system")["key"]
        .as_str()
        .unwrap()
        .to_string();
    let key = secret("tls-shop.example.test", "default")["tls.key"]
        .as_str()
        .unwrap()
        .to_string();
    let key = key.lines().nth(1).unwrap().to_string();
    for (node, text) in [
        (&edge, &account),
        (&edge, &unplaced.to_string()),
        (&edge, &gone.to_string()),
    ] {
        assert_eq!(files_with(&node.dir, text), Vec::<PathBuf>::new(), "{text}");
    }
    assert!(files_with(&edge.dir, &key).contains(&edge.dir.join("state/view.json")));
    let (code, _, err) = edge.kith(&["get", "secret/acme-account", "-n", "kith-system"]);
    assert!(code != 0 && err.contains("not found"), "{err}");
    // The plain worker has no host's certificate.
    assert_eq!(files_with(&beta.dir, &key), Vec::<PathBuf>::new());
    assert_eq!(files_with(&beta.dir, &account), Vec::<PathBuf>::new());

    // With its own certificate the edge writes no Secret and says no certificate was ordered.
    let edges = edge.dir.join("state/pki");
    let write = |command: serde_json::Value| {
        let (code, said) = ask_as_node(
            &alpha.address(),
            &edges,
            "POST",
            "/v1/raft/write",
            Some(&command.to_string()),
        );
        format!("{code} {said}")
    };
    let forged = json!({ "apiVersion": "kith.dev/v1", "kind": "Secret",
        "metadata": { "name": "tls-shop.example.test" }, "spec": { "data": { "tls.crt": "c", "tls.key": "k" } } });
    for forged in [
        json!({ "Apply": { "resources": [forged], "at": 0 } }),
        json!({ "Patch": { "statuses": [["Service/default/shop", { "tls": { "state": "ready" } }]] } }),
    ] {
        let said = write(forged.clone());
        assert!(
            said.contains("a worker writes only what it says of itself"),
            "{forged}: {said}"
        );
    }

    // The plain worker may not start serving ingress: it would be sent no host's certificate.
    beta.stop();
    let args = ["--name", "beta", "--ingress", "--mesh", &free_port().to_string()];
    let said = kithd_fails(&beta.dir, &args);
    assert!(said.contains("kith node token --worker --ingress"), "{said}");
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
