//! kithd through the `kith` CLI, the way a user drives it.
//!
//! `api_through_the_cli` needs nothing special. `workloads_run` pulls an image
//! and runs containers, so it is opt-in like kith-runtime's e2e:
//!
//! ```sh
//! KITH_E2E=1 cargo test -p kithd --test e2e
//! ```

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
    dir: PathBuf,
    kith: PathBuf,
}

impl Daemon {
    fn start(name: &str) -> Daemon {
        // `kith` is another package's binary: cargo only builds it when asked.
        let built = Command::new(env!("CARGO"))
            .args(["build", "--quiet", "-p", "kith-cli"])
            .status()
            .unwrap();
        assert!(built.success());
        let kithd = Path::new(env!("CARGO_BIN_EXE_kithd"));
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let child = Command::new(kithd)
            .arg("--state")
            .arg(dir.join("state"))
            .arg("--socket")
            .arg(dir.join("kithd.sock"))
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let daemon = Daemon {
            child,
            dir,
            kith: kithd.with_file_name("kith"),
        };
        wait_for("kithd to serve", || daemon.dir.join("kithd.sock").exists());
        daemon
    }

    /// Run `kith` against this daemon; returns (exit code, stdout, stderr).
    fn kith(&self, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(&self.kith)
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

    fn apply(&self, yaml: &str) -> String {
        std::fs::write(self.dir.join("apply.yaml"), yaml).unwrap();
        self.ok(&["apply", "-f", "apply.yaml"])
    }

    fn status(&self, target: &str) -> serde_json::Value {
        let resource: serde_json::Value = serde_json::from_str(&self.ok(&["get", target, "-o", "json"])).unwrap();
        resource["status"].clone()
    }

    /// SIGTERM, as systemd would, and wait for it to finish cleaning up.
    fn stop(&mut self) {
        let _ = Command::new("kill").arg(self.child.id().to_string()).status();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

const CONFIG: &str = "\
apiVersion: kith.dev/v1
kind: ConfigMap
metadata:
  name: settings
spec:
  data: { greeting: hello }
";

#[test]
fn api_through_the_cli() {
    let mut daemon = Daemon::start("api");
    assert_eq!(
        daemon.apply(CONFIG),
        "ConfigMap/default/settings created (revision 1)\n"
    );
    assert_eq!(
        daemon.apply(CONFIG),
        "ConfigMap/default/settings unchanged (revision 1)\n"
    );

    // diff is a dry run on the daemon: it reports and changes nothing.
    let changed = CONFIG.replace("hello", "hi");
    std::fs::write(daemon.dir.join("changed.yaml"), &changed).unwrap();
    let (code, out, _) = daemon.kith(&["diff", "-f", "changed.yaml"]);
    assert_eq!(code, 1);
    assert!(out.contains("-    greeting: hello\n+    greeting: hi\n"), "{out}");
    assert!(
        daemon
            .ok(&["get", "ConfigMap/settings", "-o", "yaml"])
            .contains("greeting: hello")
    );

    assert!(daemon.apply(&changed).contains("updated (revision 2)"));
    assert_eq!(daemon.ok(&["history", "ConfigMap/settings"]).lines().count(), 3);
    assert!(
        daemon
            .ok(&["rollback", "ConfigMap/settings", "--to", "1"])
            .contains("now revision 3")
    );
    assert!(
        daemon
            .ok(&["get", "ConfigMap", "settings", "-o", "yaml"])
            .contains("greeting: hello")
    );
    assert!(daemon.ok(&["get"]).contains("ConfigMap  default    settings  3"));

    // Errors come back as the store's own messages, with exit code 2.
    let stale = CONFIG.replace("name: settings", "name: settings\n  revision: 1");
    std::fs::write(daemon.dir.join("stale.yaml"), stale).unwrap();
    let (code, _, err) = daemon.kith(&["apply", "-f", "stale.yaml"]);
    assert_eq!(code, 2);
    assert!(err.starts_with("error: ") && err.contains("revision"), "{err}");
    let (code, _, err) = daemon.kith(&["get", "ConfigMap/nope"]);
    assert_eq!((code, err.as_str()), (2, "error: ConfigMap/default/nope not found\n"));
    // One bad resource and the whole apply is refused.
    let two = format!(
        "{}---\n{}",
        CONFIG.replace("settings", "other"),
        CONFIG.replace("name: settings", "name: settings\n  revision: 1")
    );
    std::fs::write(daemon.dir.join("two.yaml"), two).unwrap();
    assert_eq!(daemon.kith(&["apply", "-f", "two.yaml"]).0, 2);
    assert_eq!(daemon.kith(&["get", "ConfigMap/other"]).0, 2);

    assert_eq!(
        daemon.ok(&["delete", "ConfigMap/settings"]),
        "ConfigMap/default/settings deleted\n"
    );
    assert_eq!(daemon.ok(&["get"]).lines().count(), 1);

    // A second kithd on the same socket refuses to start; the socket is the owner's alone.
    let second = Command::new(env!("CARGO_BIN_EXE_kithd"))
        .arg("--state")
        .arg(daemon.dir.join("state"))
        .arg("--socket")
        .arg(daemon.dir.join("kithd.sock"))
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already serving"));
    // So does one on another socket but the same state: it says who has it instead of waiting.
    let second = Command::new(env!("CARGO_BIN_EXE_kithd"))
        .arg("--state")
        .arg(daemon.dir.join("state"))
        .arg("--socket")
        .arg(daemon.dir.join("other.sock"))
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("is in use by another kithd"));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(daemon.dir.join("kithd.sock"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    // Without a daemon the CLI says what to do, and the store file can be read directly.
    daemon.apply(CONFIG);
    daemon.stop();
    assert!(!daemon.dir.join("kithd.sock").exists(), "the socket is removed on exit");
    let (code, _, err) = daemon.kith(&["get"]);
    assert_eq!(code, 2);
    assert!(err.contains("cannot reach kithd") && err.contains("--store"), "{err}");
    let store = daemon.dir.join("state/store.json");
    let (code, out, _) = daemon.kith(&["--store", store.to_str().unwrap(), "get"]);
    assert_eq!(code, 0);
    assert!(out.contains("settings"), "{out}");
}

#[test]
fn workloads_run() {
    if std::env::var_os("KITH_E2E").is_none() {
        eprintln!("skipped: set KITH_E2E=1 (needs network and a delegated cgroup)");
        return;
    }
    let image = std::env::var("KITH_E2E_IMAGE").unwrap_or("mirror.gcr.io/library/busybox:1.36".into());
    let mut daemon = Daemon::start("workloads");
    let workload = |name: &str, script: &str, policy: &str| {
        format!(
            "{CONFIG}---
apiVersion: kith.dev/v1
kind: Workload
metadata:
  name: {name}
spec:
  replicas: 2
  template:
    restartPolicy: {policy}
    containers:
      - name: main
        image: {image}
        command: [sh, -c, '{script}']
        env:
          - name: GREETING
            configMap: {{ name: settings, key: greeting }}
        resources: {{ memory: 32Mi, cpu: 250m }}
"
        )
    };

    // Apply: both replicas come up, with the ConfigMap value in their environment.
    daemon.apply(&workload(
        "hello",
        "echo $GREETING from $(hostname); sleep 300",
        "always",
    ));
    wait_for("hello to be ready", || daemon.status("Workload/hello")["ready"] == 2);
    let logs = daemon.dir.join("state/logs");
    let log = |id: &str| std::fs::read_to_string(logs.join(format!("{id}.out"))).unwrap_or_default();
    wait_for("the container's output", || {
        log("default_hello_1_main").contains("hello from default_hello_1_main")
    });
    assert!(daemon.ok(&["get", "Workload"]).contains("2/2 ready"));

    // Scaling up adds a replica and leaves the running ones alone.
    let hello = workload("hello", "echo $GREETING from $(hostname); sleep 300", "always");
    daemon.apply(&hello.replace("replicas: 2", "replicas: 3"));
    wait_for("the third replica", || daemon.status("Workload/hello")["ready"] == 3);
    assert_eq!(
        log("default_hello_0_main").lines().count(),
        1,
        "replica 0 was not restarted"
    );
    daemon.apply(&hello);
    wait_for("the third replica to go", || {
        daemon.status("Workload/hello")["replicas"] == 2
    });
    // Stopped containers are collected, not left as zombies of kithd.
    let ps = Command::new("ps")
        .args(["--ppid", &daemon.child.id().to_string(), "-o", "stat="])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&ps.stdout).contains('Z'),
        "kithd has zombie children"
    );

    // A container that exits is restarted, and the status says so.
    daemon.apply(&workload("flaky", "sleep 1; exit 3", "always"));
    wait_for("flaky to be restarted", || {
        let status = daemon.status("Workload/flaky");
        status["containers"][0]["restarts"].as_u64() >= Some(1) && status["containers"][0]["exitCode"] == 3
    });
    // A changed Workload replaces its containers.
    daemon.apply(&workload("hello", "echo changed; sleep 300", "always"));
    wait_for("the new revision to run", || {
        log("default_hello_0_main").contains("changed")
    });

    // restartPolicy Never: it runs once.
    daemon.apply(&workload("once", "exit 0", "never"));
    wait_for("once to finish", || {
        daemon.status("Workload/once")["containers"][1]["state"] == "exited"
    });
    assert_eq!(daemon.status("Workload/once")["containers"][0]["restarts"], 0);

    // A Workload that cannot start says why.
    daemon.apply(&workload("broken", "true", "always").replace(&image, "mirror.gcr.io/library/busybox:no-such-tag"));
    wait_for("broken to report", || {
        daemon.status("Workload/broken")["containers"][0]["state"] == "failed"
    });
    assert!(daemon.status("Workload/broken")["containers"][0]["message"].is_string());

    // Delete: its containers go away, the others stay.
    let running = daemon.dir.join("state/runtime/state");
    let count = |prefix: &str| {
        let entries = std::fs::read_dir(&running).unwrap().flatten();
        entries
            .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
            .count()
    };
    assert_eq!(count("default_hello_"), 2);
    daemon.ok(&["delete", "Workload/hello"]);
    wait_for("hello's containers to stop", || count("default_hello_") == 0);

    // Stopping kithd stops everything it started.
    daemon.stop();
    assert_eq!(count(""), 0, "no container outlives kithd");
}

/// `GET /v1/watch` over the raw socket: (status line, JSON body).
fn watch_request(daemon: &Daemon, query: &str) -> serde_json::Value {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(daemon.dir.join("kithd.sock")).unwrap();
    write!(
        stream,
        "GET /v1/watch{query} HTTP/1.1\r\nHost: kithd\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    let (head, body) = reply.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    serde_json::from_str(body).unwrap()
}

#[test]
fn watch_reports_changes() {
    let daemon = Daemon::start("watch");
    daemon.apply(CONFIG);
    let now = watch_request(&daemon, "");
    let g = now["generation"].as_u64().unwrap();
    assert_eq!(now["resources"].as_array().unwrap().len(), 1);

    // A generation other than the current one (older, or from before a restart) answers at once.
    let t = Instant::now();
    assert_eq!(
        watch_request(&daemon, &format!("?after={}&wait=20", g - 1))["generation"],
        g
    );
    assert_eq!(
        watch_request(&daemon, &format!("?after={}&wait=20", g + 1))["generation"],
        g
    );
    // Nothing changes: the wait runs out and the same state comes back.
    let quiet = watch_request(&daemon, &format!("?after={g}&wait=1"));
    assert_eq!(quiet["generation"], g);
    assert!(t.elapsed() >= Duration::from_secs(1) && t.elapsed() < Duration::from_secs(10));
    // The kind filter applies.
    let other = watch_request(&daemon, "?kind=Secret");
    assert_eq!(other["resources"].as_array().unwrap().len(), 0);

    // A change wakes a waiting request long before its wait is up.
    let t = Instant::now();
    let waiting = std::thread::scope(|scope| {
        let waiting = scope.spawn(|| watch_request(&daemon, &format!("?after={g}&wait=20")));
        std::thread::sleep(Duration::from_millis(300));
        daemon.apply(&CONFIG.replace("hello", "goodbye"));
        waiting.join().unwrap()
    });
    assert!(t.elapsed() < Duration::from_secs(10));
    assert!(waiting["generation"].as_u64().unwrap() > g);
    assert_eq!(waiting["resources"][0]["metadata"]["revision"], 2);

    // `kith get -w`: the table, then the rows that change.
    let mut watcher = Command::new(&daemon.kith)
        .args(["get", "-w", "configmap"])
        .env("KITH_SOCKET", daemon.dir.join("kithd.sock"))
        .env_remove("KITH_STORE")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, lines) = std::sync::mpsc::channel();
    let stdout = watcher.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(std::io::BufReader::new(stdout)) {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let next = || {
        lines
            .recv_timeout(Duration::from_secs(20))
            .expect("a line from kith get -w")
    };
    assert!(next().starts_with("KIND"));
    assert!(next().contains("settings  2"));
    daemon.apply(&CONFIG.replace("hello", "again"));
    assert!(next().contains("settings  3"));
    daemon.ok(&["delete", "configmap/settings"]);
    assert!(next().ends_with("deleted"));
    // kithd stopping ends the watch without waiting out a long-poll.
    let t = Instant::now();
    let mut daemon = daemon;
    daemon.stop();
    assert!(t.elapsed() < Duration::from_secs(10));
    assert!(!watcher.wait().unwrap().success());

    // -w needs the daemon.
    let (code, _, err) = daemon.kith(&["--store", "x.json", "get", "-w"]);
    assert_eq!((code, err.contains("-w needs kithd")), (2, true), "{err}");
}
