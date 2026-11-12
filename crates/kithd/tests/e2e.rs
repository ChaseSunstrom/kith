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
    args: &'static [&'static str],
    kith: PathBuf,
}

impl Daemon {
    fn start(name: &str) -> Daemon {
        Daemon::start_with(name, &[])
    }

    fn start_with(name: &str, args: &'static [&'static str]) -> Daemon {
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
        let daemon = Daemon {
            child: Daemon::spawn(&dir, args),
            dir,
            args,
            kith: kithd.with_file_name("kith"),
        };
        wait_for("kithd to serve", || daemon.dir.join("kithd.sock").exists());
        daemon
    }

    fn spawn(dir: &Path, args: &[&str]) -> Child {
        Command::new(env!("CARGO_BIN_EXE_kithd"))
            .arg("--state")
            .arg(dir.join("state"))
            .arg("--socket")
            .arg(dir.join("kithd.sock"))
            .args(args)
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    }

    /// Stop it and start it again on the same state.
    fn restart(&mut self) {
        self.stop();
        self.child = Daemon::spawn(&self.dir, self.args);
        wait_for("kithd to serve again", || self.dir.join("kithd.sock").exists());
    }

    /// The output so far of a unit, by its id.
    fn log(&self, id: &str) -> String {
        std::fs::read_to_string(self.dir.join("state/logs").join(format!("{id}.out"))).unwrap_or_default()
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
        log("w_default_hello_1_main").contains("hello from w_default_hello_1_main")
    });
    assert!(daemon.ok(&["get", "Workload"]).contains("2/2 ready"));

    // Scaling up adds a replica and leaves the running ones alone.
    let hello = workload("hello", "echo $GREETING from $(hostname); sleep 300", "always");
    daemon.apply(&hello.replace("replicas: 2", "replicas: 3"));
    wait_for("the third replica", || daemon.status("Workload/hello")["ready"] == 3);
    assert_eq!(
        log("w_default_hello_0_main").lines().count(),
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
        log("w_default_hello_0_main").contains("changed")
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
    assert_eq!(count("w_default_hello_"), 2);
    daemon.ok(&["delete", "Workload/hello"]);
    wait_for("hello's containers to stop", || count("w_default_hello_") == 0);

    // Stopping kithd stops everything it started.
    daemon.stop();
    assert_eq!(count(""), 0, "no container outlives kithd");
}

fn e2e() -> bool {
    let asked = std::env::var_os("KITH_E2E").is_some();
    if !asked {
        eprintln!("skipped: set KITH_E2E=1 to run");
    }
    asked
}

/// A Workload or Job whose one unit is an exec unit running `script` with the host's sh.
fn exec(kind: &str, name: &str, script: &str, rest: &str) -> String {
    format!(
        "apiVersion: kith.dev/v1
kind: {kind}
metadata:
  name: {name}
spec:
{rest}  template:
    restartPolicy: never
    exec:
      - name: main
        command: [sh, -c, '{script}']
"
    )
}

#[test]
fn logs_and_follow() {
    if !e2e() {
        return;
    }
    let daemon = Daemon::start("logs");
    daemon.apply(&exec(
        "Workload",
        "talk",
        "echo one; echo two; echo oops >&2; sleep 2; echo three",
        "",
    ));
    // -f prints what is there, then what arrives, and ends when the unit has.
    assert_eq!(daemon.ok(&["logs", "Workload/talk", "-f"]), "one\ntwo\nthree\n");
    assert_eq!(daemon.ok(&["logs", "Workload", "talk"]), "one\ntwo\nthree\n");
    assert_eq!(daemon.ok(&["logs", "Workload/talk", "--tail", "1"]), "three\n");
    assert_eq!(
        daemon.ok(&["logs", "Workload/talk", "--unit", "main", "--stderr"]),
        "oops\n"
    );
    assert_eq!(daemon.ok(&["logs", "Workload/talk", "--previous"]), "");

    // The file is found from the stored Workload, never from what was asked for.
    let (code, _, err) = daemon.kith(&["logs", "Workload/talk", "--unit", "../../store.json"]);
    assert_eq!(code, 2);
    assert!(err.contains("has no unit `../../store.json`"), "{err}");
    assert!(
        daemon
            .kith(&["logs", "Workload/talk", "--replica", "3"])
            .2
            .contains("no replica 3")
    );
    daemon.apply(CONFIG);
    assert!(
        daemon
            .kith(&["logs", "ConfigMap/settings"])
            .2
            .contains("a ConfigMap runs nothing")
    );
    assert!(daemon.kith(&["logs", "Workload/nope"]).2.contains("not found"));
    let (code, _, err) = daemon.kith(&["--store", "s.json", "logs", "Workload/talk"]);
    assert_eq!(
        (code, err.as_str()),
        (2, "error: logs are kept by kithd: leave out --store\n")
    );
}

#[test]
fn logs_are_capped_and_removed() {
    if !e2e() {
        return;
    }
    const CAP: u64 = 4096;
    let daemon = Daemon::start_with("logcap", &["--log-cap", "4096"]);
    // About 10 kB a second, for as long as it lives.
    let line = "x".repeat(99);
    daemon.apply(&exec(
        "Workload",
        "noisy",
        &format!("while true; do echo {line}; sleep 0.01; done"),
        "",
    ));
    let logs = daemon.dir.join("state/logs");
    let size = |name: &str| std::fs::metadata(logs.join(name)).map_or(0, |meta| meta.len());
    // Nothing pokes the controller here: its own tick (10 s) has to notice.
    wait_for("the log to be moved aside", || {
        size("w_default_noisy_0_main.out.1") > CAP
    });
    // From then on the live file starts over each tick: never more than a tick's output above the cap.
    let tick_of_output = 10 * 10_000 * 2;
    let until = Instant::now() + Duration::from_secs(12);
    while Instant::now() < until {
        let now = size("w_default_noisy_0_main.out");
        assert!(now < CAP + tick_of_output, "the log grew to {now} bytes");
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        daemon
            .ok(&["logs", "Workload/noisy", "--previous", "--tail", "1"])
            .contains(&line)
    );

    // Deleting the Workload removes its logs, old copy included.
    daemon.ok(&["delete", "Workload/noisy"]);
    wait_for("the logs to be removed", || {
        let files = std::fs::read_dir(&logs).unwrap().flatten();
        files.count() == 0
    });
}

#[test]
fn exec_units_run() {
    if !e2e() {
        return;
    }
    let mut daemon = Daemon::start("exec");
    daemon.apply(&format!(
        "{CONFIG}---
apiVersion: kith.dev/v1
kind: Workload
metadata:
  name: tool
spec:
  template:
    exec:
      - name: run
        command: [sh, -c, 'sleep 300 & echo $GREETING $$ $!; cat /proc/self/cgroup; wait']
        env:
          - name: GREETING
            configMap: {{ name: settings, key: greeting }}
        resources: {{ memory: 32Mi, cpu: 250m }}
      - name: missing
        command: [/no/such/tool]
"
    ));
    wait_for("the exec unit's output", || {
        daemon.log("w_default_tool_0_run").lines().count() >= 2
    });
    let out = daemon.log("w_default_tool_0_run");
    let mut lines = out.lines();
    // A process of this host: its pids are real ones here.
    let first: Vec<&str> = lines.next().unwrap().split(' ').collect();
    let (pid, child) = (first[1], first[2]);
    assert_eq!(first[0], "hello");
    let alive = |pid: &str| Path::new("/proc").join(pid).exists();
    assert!(alive(pid) && alive(child));
    // In its own cgroup, with the limits asked for.
    let cgroup = lines.next().unwrap().strip_prefix("0::").unwrap();
    assert!(cgroup.ends_with("/kith-w_default_tool_0_run"), "{cgroup}");
    let cgroup = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
    let read = |file: &str| std::fs::read_to_string(cgroup.join(file)).unwrap();
    assert_eq!(read("memory.max").trim(), (32 << 20).to_string());
    assert_eq!(read("memory.swap.max").trim(), "0");
    assert_eq!(read("cpu.max").trim(), "25000 100000");
    assert_eq!(read("pids.max").trim(), "4096");
    let members = read("cgroup.procs");
    assert!(
        members.lines().any(|p| p == pid) && members.lines().any(|p| p == child),
        "{members}"
    );

    // A command that cannot start is an exit like any other: reported, retried.
    wait_for("the missing tool to be reported", || {
        let status = daemon.status("Workload/tool");
        status["containers"][0]["exitCode"] == 127 && status["containers"][0]["restarts"].as_u64() >= Some(1)
    });
    let err = std::fs::read_to_string(daemon.dir.join("state/logs/w_default_tool_0_missing.err")).unwrap();
    assert!(err.contains("/no/such/tool"), "{err}");

    // It is supervised: killed, it comes back.
    Command::new("kill").args(["-9", pid]).status().unwrap();
    wait_for("the exec unit to be restarted", || {
        daemon.status("Workload/tool")["containers"][1]["restarts"].as_u64() >= Some(1)
            && daemon.status("Workload/tool")["containers"][1]["state"] == "running"
    });
    // ...and what it had forked went with it, not on as an orphan.
    wait_for("the unit's child to be gone", || !alive(child));

    // Stopping kithd stops exec units too, children and cgroup included.
    let out = daemon.log("w_default_tool_0_run");
    let second: Vec<&str> = out.lines().rev().nth(1).unwrap().split(' ').collect();
    assert!(alive(second[1]) && alive(second[2]));
    // Children that end while the unit lives on are collected too, not left as zombies of kithd.
    daemon.apply(&exec(
        "Workload",
        "forker",
        "(sleep 0.2 &) ; echo forked; sleep 300",
        "",
    ));
    wait_for("forker to run", || daemon.log("w_default_forker_0_main") == "forked\n");
    std::thread::sleep(Duration::from_millis(600));
    let ps = Command::new("ps")
        .args(["--ppid", &daemon.child.id().to_string(), "-o", "stat="])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&ps.stdout).contains('Z'),
        "kithd has zombie children"
    );
    daemon.stop();
    // (kithd is gone; what it had not collected yet is init's to collect, any moment now.)
    wait_for("the unit and its child to be gone", || {
        !alive(second[1]) && !alive(second[2])
    });
    assert!(!cgroup.exists(), "the cgroup is removed");
}

#[test]
fn jobs_run_to_completion() {
    if !e2e() {
        return;
    }
    let mut daemon = Daemon::start("jobs");
    fn state(daemon: &Daemon, name: &str) -> serde_json::Value {
        daemon.status(&format!("Job/{name}"))["state"].clone()
    }

    // Three runs, two at a time.
    daemon.apply(&exec("Job", "ok", "echo run", "  completions: 3\n  parallelism: 2\n"));
    wait_for("ok to finish", || state(&daemon, "ok") == "succeeded");
    let status = daemon.status("Job/ok");
    assert_eq!(
        (&status["state"], &status["succeeded"], &status["failed"]),
        (&"succeeded".into(), &3.into(), &0.into())
    );
    for run in 0..3 {
        assert_eq!(daemon.log(&format!("j_default_ok_{run}_main")), "run\n");
    }
    assert_eq!(daemon.ok(&["logs", "Job/ok", "--replica", "2"]), "run\n");
    assert!(daemon.ok(&["get", "Job"]).contains("succeeded"));

    // Failed runs are retried, up to `retries` of them.
    let counter = daemon.dir.join("n");
    let count = counter.display();
    let flaky = format!("n=$(cat {count} 2>/dev/null || echo 0); echo $((n+1)) > {count}; [ $n -ge 2 ]");
    daemon.apply(&exec("Job", "flaky", &flaky, "  retries: 2\n"));
    wait_for("flaky to finish", || state(&daemon, "flaky") == "succeeded");
    let status = daemon.status("Job/flaky");
    assert_eq!(
        (&status["state"], &status["failed"]),
        (&"succeeded".into(), &2.into()),
        "{status}"
    );

    // One failure too many and the Job has failed, saying why.
    daemon.apply(&exec("Job", "bad", "echo try; exit 7", "  retries: 1\n"));
    wait_for("bad to fail", || state(&daemon, "bad") == "failed");
    let status = daemon.status("Job/bad");
    assert_eq!(status["failed"], 2);
    assert_eq!(status["message"], "run 0, main: exited with code 7");
    assert_eq!(daemon.log("j_default_bad_0_main"), "try\ntry\n");
    assert!(
        daemon
            .ok(&["get", "Job/bad", "-o", "table"])
            .contains("failed: run 0, main: exited with code 7")
    );

    // A Job that takes too long is stopped. (The time is checked on the controller's tick; applying wakes it.)
    daemon.apply(&exec("Job", "slow", "sleep 300", "  timeoutSeconds: 1\n"));
    wait_for("slow to time out", || {
        daemon.apply(CONFIG);
        state(&daemon, "slow") == "failed"
    });
    assert_eq!(daemon.status("Job/slow")["message"], "not finished after 1 s");
    assert_eq!(daemon.status("Job/slow")["containers"].as_array().unwrap().len(), 0);

    // A restarted kithd does not run finished Jobs again.
    daemon.restart();
    daemon.apply(CONFIG);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(daemon.log("j_default_ok_0_main"), "run\n");
    assert_eq!(daemon.log("j_default_bad_0_main"), "try\ntry\n");
    assert_eq!(state(&daemon, "ok"), "succeeded");
    assert_eq!(state(&daemon, "bad"), "failed");

    // A changed Job is a new Job: it runs again.
    daemon.apply(&exec("Job", "bad", "echo better", "  retries: 1\n"));
    wait_for("bad to succeed", || state(&daemon, "bad") == "succeeded");
    assert_eq!(daemon.log("j_default_bad_0_main"), "try\ntry\nbetter\n");

    // Jobs run containers as well.
    let image = std::env::var("KITH_E2E_IMAGE").unwrap_or("mirror.gcr.io/library/busybox:1.36".into());
    daemon.apply(&format!(
        "apiVersion: kith.dev/v1
kind: Job
metadata:
  name: boxed
spec:
  template:
    containers:
      - name: main
        image: {image}
        command: [sh, -c, 'echo from $(hostname)']
"
    ));
    wait_for("boxed to finish", || state(&daemon, "boxed") == "succeeded");
    assert_eq!(daemon.log("j_default_boxed_0_main"), "from j_default_boxed_0_main\n");
}
