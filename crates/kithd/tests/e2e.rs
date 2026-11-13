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
            // A relative state directory has to work too.
            .current_dir(dir)
            .args(["--state", "state"])
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

    // Without a daemon the CLI says what to do; the next kithd has what the last one was given.
    daemon.apply(CONFIG);
    daemon.stop();
    assert!(!daemon.dir.join("kithd.sock").exists(), "the socket is removed on exit");
    let (code, _, err) = daemon.kith(&["get"]);
    assert_eq!(code, 2);
    assert!(err.contains("cannot reach kithd") && err.contains("--store"), "{err}");
    daemon.restart();
    assert!(daemon.ok(&["get"]).contains("settings"));

    // The store of a kithd from before replication is brought in, once.
    daemon.stop();
    let state = daemon.dir.join("state");
    std::fs::remove_dir_all(state.join("raft")).unwrap();
    let old = state.join("store.json");
    std::fs::write(daemon.dir.join("old.yaml"), CONFIG.replace("settings", "from-before")).unwrap();
    daemon.ok(&["--store", old.to_str().unwrap(), "apply", "-f", "old.yaml"]);
    daemon.restart();
    assert!(daemon.ok(&["get"]).contains("from-before"));
    assert!(!old.exists() && state.join("store.json.imported").exists());
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
    // From then on the live file starts over every tick: it shrinks again and again, and is
    // never more than a tick's output (10 s at 10 kB/s, with room for a slow machine) above the cap.
    let tick_of_output = 10 * 10_000 * 2;
    let (mut before, mut shrank) = (size("w_default_noisy_0_main.out"), 0);
    wait_for("the log to start over twice more", || {
        let now = size("w_default_noisy_0_main.out");
        assert!(now < CAP + tick_of_output, "the log grew to {now} bytes");
        shrank += u32::from(now < before);
        before = now;
        shrank >= 2
    });
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
fn node_workload_runs_one_copy_alone() {
    if !e2e() {
        return;
    }
    let daemon = Daemon::start("nodewl");
    let agent = |selector: &str| {
        format!(
            "apiVersion: kith.dev/v1\nkind: NodeWorkload\nmetadata: {{ name: agent }}\nspec:\n  {selector}\n  template:\n    \
             exec: [{{ name: run, command: [sh, -c, 'echo up; exec sleep 300'] }}]\n"
        )
    };
    daemon.apply(&agent("selector: {}"));
    wait_for("the copy", || daemon.status("NodeWorkload/agent")["ready"] == 1);
    assert!(daemon.ok(&["get", "nodeworkload"]).contains("1/1 ready"));
    wait_for("the copy's output", || daemon.log("n_default_agent_0_run") == "up\n");
    // `kith logs` finds copy 0 though no scheduler numbered it.
    assert_eq!(daemon.ok(&["logs", "nodeworkload/agent"]), "up\n");
    // Nothing here has the labels a selector asks for.
    daemon.apply(&agent("selector: { role: edge }"));
    wait_for("the copy to stop", || {
        daemon.status("NodeWorkload/agent")["replicas"] == 0
    });
    assert_eq!(daemon.status("NodeWorkload/agent")["ready"], 0);
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

    // A Job with nothing that can run says so instead of running forever.
    let twins = exec("Job", "twins", "true", "").replace("name: main", "name: a_b");
    daemon.apply(&twins);
    wait_for("twins to fail", || state(&daemon, "twins") == "failed");
    assert_eq!(
        daemon.status("Job/twins")["message"],
        "the template has nothing that can run"
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

/// A Workload of busybox containers running `script`, with `extra` lines in the container.
fn boxed(name: &str, replicas: u32, strategy: &str, script: &str, extra: &str) -> String {
    let image = std::env::var("KITH_E2E_IMAGE").unwrap_or("mirror.gcr.io/library/busybox:1.36".into());
    format!(
        "apiVersion: kith.dev/v1
kind: Workload
metadata:
  name: {name}
spec:
  replicas: {replicas}
  strategy: {strategy}
  template:
    containers:
      - name: main
        image: {image}
        command: [sh, -c, '{script}']
{extra}"
    )
}

/// A port nothing listens on right now.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[test]
fn probes_gate_ready_and_restart() {
    if !e2e() {
        return;
    }
    let daemon = Daemon::start("probes");
    let unit = |name: &str| daemon.status(&format!("Workload/{name}"))["containers"][0].clone();

    // Readiness: running is not ready until the probe passes, and not ready again when it stops passing.
    let port = free_port();
    let serve = format!(
        "mkdir /tmp/www; echo ok > /tmp/www/ok; sleep 3; httpd -p {port} -h /tmp/www; sleep 5; rm /tmp/www/ok; sleep 300"
    );
    let probes = format!(
        "        readiness: {{ http: {{ path: /ok, port: {port} }}, intervalSeconds: 1, failureThreshold: 1 }}
        liveness: {{ tcp: {{ port: {port} }}, intervalSeconds: 1, failureThreshold: 3 }}
"
    );
    daemon.apply(&boxed("web", 1, "rolling", &serve, &probes));
    wait_for("web to run, not ready yet", || unit("web")["state"] == "running");
    assert_eq!(
        (
            unit("web")["ready"].clone(),
            daemon.status("Workload/web")["ready"].clone()
        ),
        (false.into(), 0.into())
    );
    wait_for("web to be ready", || daemon.status("Workload/web")["ready"] == 1);
    assert!(daemon.ok(&["get", "Workload/web", "-o", "table"]).contains("1/1 ready"));
    wait_for("web to stop being ready", || {
        daemon.status("Workload/web")["ready"] == 0
    });
    // Its port still answers, so it was never restarted.
    assert_eq!(
        (unit("web")["state"].clone(), unit("web")["restarts"].clone()),
        ("running".into(), 0.into())
    );

    // Liveness: a container that runs on but stopped answering is restarted. The test is
    // what answers here, so it decides when that is.
    let port = free_port();
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let probes = format!("        liveness: {{ tcp: {{ port: {port} }}, intervalSeconds: 1, failureThreshold: 2 }}\n");
    daemon.apply(&boxed("stuck", 1, "rolling", "echo up; sleep 300", &probes));
    wait_for("stuck to run", || unit("stuck")["state"] == "running");
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(unit("stuck")["restarts"], 0, "restarted though its probe passes");
    drop(listener);
    wait_for("stuck to be restarted", || {
        unit("stuck")["restarts"].as_u64() >= Some(1)
    });
    assert_eq!(unit("stuck")["exitCode"], 137);
    wait_for("stuck to be up again", || {
        daemon.log("w_default_stuck_0_main").starts_with("up\nup\n")
    });

    // A probe that cannot run says so and holds nothing back.
    let probes = "        readiness: { exec: [\"true\"] }\n";
    daemon.apply(&boxed("plain", 1, "rolling", "sleep 300", probes));
    wait_for("plain to be ready", || daemon.status("Workload/plain")["ready"] == 1);
    assert_eq!(
        daemon.status("Workload/plain")["notes"][0],
        "main: readiness probe: exec probes are not run yet"
    );
}

#[test]
fn rolling_updates_keep_replicas_ready() {
    if !e2e() {
        return;
    }
    let daemon = Daemon::start("rolling");
    // The test answers the readiness probe itself: while it listens, replicas are ready.
    let port = free_port();
    let listen = || std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    // A replica that was ready stays so through 100 failures; a new one needs one success first.
    let probe =
        format!("        readiness: {{ tcp: {{ port: {port} }}, intervalSeconds: 1, failureThreshold: 100 }}\n");
    let version = |v: &str, strategy: &str| boxed("roll", 3, strategy, &format!("echo {v}; sleep 300"), &probe);
    let ready = || daemon.status("Workload/roll")["ready"].as_u64().unwrap_or(0);
    let on = |v: &str| {
        let has = |replica: u32| daemon.log(&format!("w_default_roll_{replica}_main")).contains(v);
        (0..3).filter(|replica| has(*replica)).count()
    };

    let listener = listen();
    daemon.apply(&version("v1", "rolling"));
    wait_for("v1 to be ready", || ready() == 3);

    // Nothing answers the probe: the first new replica never becomes ready, and the update stops there.
    drop(listener);
    daemon.apply(&version("v2", "rolling"));
    wait_for("the first replica to be replaced", || on("v2") == 1);
    let until = Instant::now() + Duration::from_secs(4);
    while Instant::now() < until {
        assert_eq!(
            (on("v2"), ready()),
            (1, 2),
            "the update went on past a replica that is not ready"
        );
    }
    let notes = daemon.status("Workload/roll")["notes"].to_string();
    assert!(notes.contains("rolling update: replica 1 is next"), "{notes}");

    // Answer again: it goes on, one replica at a time, never more than one down.
    let listener = listen();
    wait_for("the update to finish", || {
        assert!(ready() >= 2, "more than one replica was down");
        on("v2") == 3 && ready() == 3
    });

    // strategy: recreate replaces everything at once, ready or not.
    drop(listener);
    daemon.apply(&version("v3", "recreate"));
    wait_for("all replicas to be replaced", || on("v3") == 3);
    assert_eq!(ready(), 0);
}

#[test]
fn config_changes_restart() {
    if !e2e() {
        return;
    }
    let daemon = Daemon::start("config");
    let env = "        env:
          - name: GREETING
            configMap: { name: settings, key: greeting }
";
    daemon.apply(CONFIG);
    daemon.apply(&boxed("greeter", 2, "rolling", "echo $GREETING; sleep 300", env));
    daemon.apply(&boxed("bystander", 1, "rolling", "echo here; sleep 300", ""));
    let greeted = |with: &str| {
        let has = |replica: u32| daemon.log(&format!("w_default_greeter_{replica}_main")).contains(with);
        (0..2).filter(|replica| has(*replica)).count()
    };
    wait_for("greeter to greet", || greeted("hello") == 2);

    // The value changes: the containers that read it are restarted with the new one.
    daemon.apply(&CONFIG.replace("hello", "goodbye"));
    wait_for("greeter to say goodbye", || greeted("goodbye") == 2);
    wait_for("greeter to be ready again", || {
        daemon.status("Workload/greeter")["ready"] == 2
    });
    // ...and nothing else is.
    assert_eq!(daemon.log("w_default_bystander_0_main"), "here\n");
    assert_eq!(daemon.log("w_default_greeter_0_main"), "hello\ngoodbye\n");

    // A value that is gone stops nothing: what runs keeps the value it was started with.
    daemon.ok(&["delete", "ConfigMap/settings"]);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(daemon.status("Workload/greeter")["ready"], 2);
    assert_eq!(daemon.log("w_default_greeter_1_main"), "hello\ngoodbye\n");
}

/// Ask the DNS server on `port` for the A record of `name`, over UDP or TCP: the address,
/// or the response code.
fn resolve_over(tcp: bool, port: u16, name: &str) -> Result<[u8; 4], u8> {
    use std::io::{Read, Write};
    // Header: id, recursion desired, one question. Then the name, type A, class IN.
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.extend([0, 0, 1, 0, 1]);
    let wait = Some(Duration::from_secs(5));
    let reply = if tcp {
        // Over TCP every message has its length in front.
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(wait).unwrap();
        stream.write_all(&(query.len() as u16).to_be_bytes()).unwrap();
        stream.write_all(&query).unwrap();
        let mut len = [0; 2];
        stream
            .read_exact(&mut len)
            .expect("an answer from kithd's DNS over TCP");
        let mut reply = vec![0; u16::from_be_bytes(len).into()];
        stream.read_exact(&mut reply).unwrap();
        reply
    } else {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(wait).unwrap();
        socket.send_to(&query, ("127.0.0.1", port)).unwrap();
        let mut reply = vec![0; 512];
        let (len, _) = socket.recv_from(&mut reply).expect("an answer from kithd's DNS");
        reply.truncate(len);
        reply
    };
    assert_eq!(reply[..2], query[..2]);
    match (reply[3] & 0x0f, reply[7]) {
        // The address is the last thing in a reply with one A record.
        (0, 1) => Ok(reply[reply.len() - 4..].try_into().unwrap()),
        (0, _) => Err(0),
        (code, _) => Err(code),
    }
}

fn resolve(port: u16, name: &str) -> Result<[u8; 4], u8> {
    resolve_over(false, port, name)
}

/// A resolver that says every name is at 198.51.100.7; returns its port.
fn upstream() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut query = [0; 512];
        while let Ok((len, from)) = socket.recv_from(&mut query) {
            let mut reply = query[..len].to_vec();
            // A response, recursion available, one answer: the question's name, A, IN, 60 s.
            (reply[2], reply[3], reply[7]) = (0x81, 0x80, 1);
            reply.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7]);
            let _ = socket.send_to(&reply, from);
        }
    });
    port
}

#[test]
fn dns_answers_from_the_store() {
    if !e2e() {
        return;
    }
    let port = free_port();
    let listen: &'static str = Box::leak(format!("127.0.0.1:{port}").into_boxed_str());
    let other: &'static str = Box::leak(format!("127.0.0.1:{}", upstream()).into_boxed_str());
    let args: &'static [&'static str] = Box::leak(Box::new(["--dns", listen, "--dns-upstream", other]));
    let daemon = Daemon::start_with("dns", args);
    let home = include_str!("../../../examples/dns.yaml");
    daemon.apply(home);
    wait_for("the name to resolve", || {
        resolve(port, "nas.home.example") == Ok([192, 168, 1, 20])
    });
    assert_eq!(daemon.status("dnsrecord/nas")["state"], "served");
    // No such name in our zone (3); a name that is not ours is what the other resolver says.
    assert_eq!(resolve(port, "printer.home.example"), Err(3));
    assert_eq!(resolve(port, "example.org"), Ok([198, 51, 100, 7]));
    // Our names over TCP too.
    assert_eq!(resolve_over(true, port, "nas.home.example"), Ok([192, 168, 1, 20]));
    assert_eq!(resolve_over(true, port, "printer.home.example"), Err(3));

    // A record that changes is answered anew; one in a zone that is not there says so.
    daemon.apply(
        &home
            .replace("192.168.1.20", "192.168.1.30")
            .replace("zone: home\n  name: \"*.apps\"", "zone: away\n  name: \"*.apps\""),
    );
    wait_for("the new address", || {
        resolve(port, "nas.home.example") == Ok([192, 168, 1, 30])
    });
    wait_for("the report on the lost record", || {
        daemon.status("dnsrecord/apps")["state"] == "error"
    });
    let said = daemon.status("dnsrecord/apps")["message"].to_string();
    assert!(said.contains("no DNSZone named `away`"), "{said}");
    assert_eq!(resolve(port, "x.apps.home.example"), Err(3));
    daemon.ok(&["delete", "dnsrecord/nas"]);
    wait_for("the name to be gone", || resolve(port, "nas.home.example") == Err(3));
}

/// A package pushed to the daemon, and a Release of it: installed, upgraded (what is no
/// longer rendered goes), rolled back, uninstalled. Only ConfigMaps: nothing is pulled.
#[test]
fn release_installs_a_package() {
    let daemon = Daemon::start("release");
    let package = daemon.dir.join("maps");
    std::fs::create_dir_all(package.join("templates")).unwrap();
    std::fs::write(package.join("package.yaml"), "name: maps\nversion: 1.0.0\n").unwrap();
    std::fs::write(package.join("values.yaml"), "colour: red\nextra: true\n").unwrap();
    let map = "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: {{ name }} }\n\
               spec: { data: { colour: {{ values.colour }} } }\n\
               {% if values.extra %}---\napiVersion: kith.dev/v1\nkind: ConfigMap\n\
               metadata: { name: {{ name }}-extra }\nspec: { data: { a: b } }\n{% endif %}";
    std::fs::write(package.join("templates/map.yaml"), map).unwrap();
    assert_eq!(daemon.ok(&["package", "push", "maps"]), "Package/maps-1.0.0 created\n");
    assert_eq!(
        daemon.ok(&["package", "push", "maps"]),
        "Package/maps-1.0.0 unchanged\n"
    );

    let release = |values: &str| {
        format!(
            "apiVersion: kith.dev/v1\nkind: Release\nmetadata: {{ name: mine }}\nspec: {{ package: {{ name: maps }}, values: {values} }}\n"
        )
    };
    let installed = |daemon: &Daemon, revision: u64| {
        wait_for("the release to be installed", || {
            let status = daemon.status("Release/mine");
            status["state"] == "installed" && status["observedRevision"] == revision
        });
    };
    let there = |target: &str| daemon.kith(&["get", target]).0 == 0;
    daemon.apply(&release("{}"));
    installed(&daemon, 1);
    assert!(
        daemon
            .ok(&["get", "ConfigMap/mine-maps", "-o", "yaml"])
            .contains("colour: red")
    );
    assert!(there("ConfigMap/mine-maps-extra"));
    assert_eq!(daemon.status("Release/mine")["version"], "1.0.0");

    // New values: one map changes, the other is no longer rendered and goes.
    daemon.apply(&release("{ colour: blue, extra: false }"));
    installed(&daemon, 2);
    assert!(
        daemon
            .ok(&["get", "ConfigMap/mine-maps", "-o", "yaml"])
            .contains("colour: blue")
    );
    assert!(!there("ConfigMap/mine-maps-extra"));

    // Back to how it was: a rollback of the Release is a rollback of what it installed.
    daemon.ok(&["rollback", "Release/mine", "--to", "1"]);
    installed(&daemon, 3);
    assert!(
        daemon
            .ok(&["get", "ConfigMap/mine-maps", "-o", "yaml"])
            .contains("colour: red")
    );
    assert!(there("ConfigMap/mine-maps-extra"));

    // Values the package's templates cannot take: said in the status, nothing torn down.
    daemon.apply(&release("{ colour: { not: text }, extra: [] }"));
    wait_for("the release to say what is wrong", || {
        daemon.status("Release/mine")["state"] == "error"
    });
    assert!(there("ConfigMap/mine-maps-extra"));

    daemon.ok(&["delete", "Release/mine"]);
    wait_for("what the release installed to go", || {
        !there("ConfigMap/mine-maps") && !there("ConfigMap/mine-maps-extra")
    });
    assert!(there("Package/maps-1.0.0"));
}

/// Stops a helper process when the test is over.
struct Stop(Child);

impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A fake OCI registry on this machine: it, and its port.
fn registry(dir: &Path) -> (Stop, u16) {
    let port = free_port();
    let ready = dir.join("registry.ready");
    let registry = Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fake_registry.py"))
        .arg(port.to_string())
        .arg(&ready)
        .spawn()
        .unwrap();
    let registry = Stop(registry);
    wait_for("the registry to listen", || ready.exists());
    (registry, port)
}

/// Packages in a registry (a fake one, here): signed, pushed, pulled and checked through
/// the CLI; and a Release that names a Repository gets the newest version its range
/// allows, checked against the Repository's key, and follows newer ones.
#[test]
fn repository_supplies_releases() {
    let daemon = Daemon::start_with("repository", &["--repository-poll", "1"]);
    let (_registry, port) = registry(&daemon.dir);
    let url = format!("oci://127.0.0.1:{port}/packages");

    let package = |version: &str, colour: &str| {
        let dir = daemon.dir.join(format!("src-{version}"));
        std::fs::create_dir_all(dir.join("templates")).unwrap();
        std::fs::write(dir.join("package.yaml"), format!("name: maps\nversion: {version}\n")).unwrap();
        let map = format!(
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{ name: {{{{ name }}}} }}\nspec: {{ data: {{ colour: {colour} }} }}\n"
        );
        std::fs::write(dir.join("templates/map.yaml"), map).unwrap();
        format!("src-{version}")
    };
    let public = daemon.ok(&["package", "keygen", "signing.key"]);
    let public = public.trim();
    let other = daemon.ok(&["package", "keygen", "other.key"]);
    let (code, _, err) = daemon.kith(&["package", "keygen", "signing.key"]);
    assert_eq!(code, 2, "a key is not written over: {err}");

    let pushed = daemon.ok(&[
        "package",
        "push",
        &package("1.0.0", "red"),
        "--to",
        &url,
        "--key",
        "signing.key",
    ]);
    assert_eq!(
        pushed,
        format!("127.0.0.1:{port}/packages/maps:1.0.0 pushed (signed)\n")
    );
    daemon.ok(&[
        "package",
        "push",
        &package("1.2.0", "green"),
        "--to",
        &url,
        "--key",
        "signing.key",
    ]);
    // (2.0.0 is outside what the Release will ask for; 1.3.0 is signed by someone else.)
    daemon.ok(&[
        "package",
        "push",
        &package("2.0.0", "black"),
        "--to",
        &url,
        "--key",
        "signing.key",
    ]);

    // Pulled back: the same files, checked against the key; not against another.
    let pulled = daemon.ok(&[
        "package",
        "pull",
        &url,
        "maps",
        "1.2.0",
        "--public-key",
        public,
        "-o",
        "back",
    ]);
    assert_eq!(pulled, "maps 1.2.0 in back (signature checked)\n");
    let same = |file: &str| {
        std::fs::read(daemon.dir.join("back").join(file)).unwrap()
            == std::fs::read(daemon.dir.join("src-1.2.0").join(file)).unwrap()
    };
    assert!(same("package.yaml") && same("templates/map.yaml"));
    let (code, _, err) = daemon.kith(&[
        "package",
        "pull",
        &url,
        "maps",
        "1.2.0",
        "--public-key",
        other.trim(),
        "-o",
        "not",
    ]);
    assert!(code == 2 && err.contains("the signature is not this key's"), "{err}");
    assert!(!daemon.dir.join("not").exists());
    let (code, _, err) = daemon.kith(&["package", "pull", &url, "maps", "1.2.0", "-o", "back"]);
    assert!(
        code == 2 && err.contains("back"),
        "a directory that is there is left alone: {err}"
    );

    // A Release from the Repository, on 1.x: 1.2.0 it is.
    daemon.apply(&format!("apiVersion: kith.dev/v1\nkind: Repository\nmetadata: {{ name: ours }}\nspec: {{ url: '{url}', publicKey: {public} }}\n"));
    let release = |auto: bool| {
        format!(
            "apiVersion: kith.dev/v1\nkind: Release\nmetadata: {{ name: mine }}\nspec: {{ package: {{ repo: ours, name: maps, version: ^1 }}, autoUpgrade: {auto} }}\n"
        )
    };
    daemon.apply(&release(false));
    let on = |version: &str| {
        daemon.status("Release/mine")["version"] == version && daemon.status("Release/mine")["state"] == "installed"
    };
    wait_for("the release to be on 1.2.0", || on("1.2.0"));
    assert!(
        daemon
            .ok(&["get", "ConfigMap/mine-maps", "-o", "yaml"])
            .contains("colour: green")
    );
    assert_eq!(daemon.status("Repository/ours")["state"], "ok");

    // A newer one in its range: left alone until the Release follows (autoUpgrade).
    daemon.ok(&[
        "package",
        "push",
        &package("1.3.0", "blue"),
        "--to",
        &url,
        "--key",
        "signing.key",
    ]);
    std::thread::sleep(Duration::from_secs(3));
    assert!(on("1.2.0"));
    daemon.apply(&release(true));
    wait_for("the release to follow to 1.3.0", || on("1.3.0"));
    assert!(
        daemon
            .ok(&["get", "ConfigMap/mine-maps", "-o", "yaml"])
            .contains("colour: blue")
    );

    // A newer one still, signed with another key: passed over, the Repository says so,
    // and the release stays where it is; a new Release gets the newest that checks out.
    daemon.ok(&[
        "package",
        "push",
        &package("1.4.0", "stolen"),
        "--to",
        &url,
        "--key",
        "other.key",
    ]);
    let said = || daemon.status("Repository/ours")["message"].to_string();
    wait_for("the repository to say what it passed over", || {
        said().contains("passed over: maps 1.4.0: the signature is not this key's")
    });
    assert!(on("1.3.0") && daemon.kith(&["get", "Package/maps-1.4.0"]).0 != 0);
    daemon.apply(&release(false).replace("name: mine", "name: second"));
    wait_for("a second release to be on 1.3.0", || {
        daemon.status("Release/second")["version"] == "1.3.0"
    });

    // What kithd fetched and checked is marked so; nobody marks a Package so by hand.
    let fetched = daemon.ok(&["get", "Package/maps-1.3.0", "-o", "yaml"]);
    assert!(fetched.contains("kith.dev/repository: ours@"), "{fetched}");
    std::fs::write(
        daemon.dir.join("forged.yaml"),
        fetched
            .replace("maps-1.3.0", "maps-1.9.0")
            .replace("version: 1.3.0", "version: 1.9.0"),
    )
    .unwrap();
    let (code, _, err) = daemon.kith(&["apply", "-f", "forged.yaml"]);
    assert!(
        code == 2 && err.contains("which says kithd fetched and checked it"),
        "{err}"
    );

    // The Repository checks with another key from now on: what was fetched under the
    // old one is no longer its, and nothing in the registry is signed with the new one.
    daemon.apply(&format!("apiVersion: kith.dev/v1\nkind: Repository\nmetadata: {{ name: ours }}\nspec: {{ url: '{url}', publicKey: {} }}\n", other.trim()));
    wait_for("the newest signed with the new key to be fetched", || on("1.4.0"));
}

/// A Source: a commit to a git repository changes what is in the store (applied,
/// pruned, put back when someone changes it), a manual one waits to be approved, and
/// an OCI artifact syncs the same way.
#[test]
fn source_syncs_git_and_oci() {
    let daemon = Daemon::start_with("source", &["--local-sources"]);
    let repo = daemon.dir.join("repo");
    std::fs::create_dir_all(repo.join("conf")).unwrap();
    let git = |args: &[&str]| {
        let ran = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.org",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            ran.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&ran.stderr)
        );
    };
    let map = |name: &str, colour: &str| {
        format!(
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{ name: {name} }}\nspec: {{ data: {{ colour: {colour} }} }}\n"
        )
    };
    let commit = |files: &[(&str, Option<String>)]| {
        for (path, text) in files {
            match text {
                Some(text) => std::fs::write(repo.join(path), text).unwrap(),
                None => std::fs::remove_file(repo.join(path)).unwrap(),
            }
        }
        git(&["add", "-A"]);
        git(&["commit", "--quiet", "-m", "change"]);
    };
    git(&["init", "--quiet", "-b", "main"]);
    // (Outside the Source's path, and a link out of the repository: neither is read.)
    std::fs::write(repo.join("elsewhere.yaml"), map("elsewhere", "red")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", repo.join("conf/link.yaml")).unwrap();
    commit(&[("conf/a.yaml", Some(map("a", "red")))]);

    let source = |more: &str| {
        format!(
            "apiVersion: kith.dev/v1\nkind: Source\nmetadata: {{ name: repo }}\nspec:\n  git: {{ url: 'file://{}', rev: main }}\n  path: conf\n  intervalSeconds: 5\n  prune: true\n{more}",
            repo.display()
        )
    };
    let colour = |name: &str| {
        let (code, out, _) = daemon.kith(&["get", &format!("ConfigMap/{name}"), "-o", "json"]);
        (code == 0).then(|| serde_json::from_str::<serde_json::Value>(&out).unwrap()["spec"]["data"]["colour"].clone())
    };
    daemon.apply(&source(""));
    wait_for("the source to be applied", || colour("a") == Some("red".into()));
    let status = daemon.status("Source/repo");
    assert_eq!(status["state"], "synced");
    assert!(
        status["skipped"][0].as_str().unwrap().contains("conf/link.yaml"),
        "{status}"
    );
    assert_eq!(colour("elsewhere"), None);

    // A commit: one map changes, another comes; the next: one goes.
    commit(&[
        ("conf/a.yaml", Some(map("a", "blue"))),
        ("conf/b.yaml", Some(map("b", "red"))),
    ]);
    wait_for("the commit to be applied", || {
        colour("a") == Some("blue".into()) && colour("b").is_some()
    });
    commit(&[("conf/b.yaml", None)]);
    wait_for("what the source dropped to go", || colour("b").is_none());

    // Someone applies over what the source says: put back, and said.
    daemon.apply(&map("a", "pink"));
    wait_for("the map to be put back", || colour("a") == Some("blue".into()));
    wait_for("the drift to be said", || {
        daemon.status("Source/repo")["drift"][0] == "ConfigMap/default/a"
    });

    // Manual approval: a commit waits, and is applied once approved.
    daemon.apply(&source("  approval: manual\n"));
    let (code, _, err) = daemon.kith(&["source", "approve", "repo"]);
    assert!(code == 2 && err.contains("nothing waiting"), "{err}");
    commit(&[("conf/a.yaml", Some(map("a", "green")))]);
    wait_for("the commit to wait", || {
        daemon.status("Source/repo")["state"] == "pending"
    });
    assert_eq!(
        daemon.status("Source/repo")["pending"]["changes"][0],
        "ConfigMap/default/a"
    );
    assert_eq!(colour("a"), Some("blue".into()));
    assert!(daemon.ok(&["source", "approve", "repo"]).contains("approved"));
    wait_for("the approved commit to be applied", || {
        colour("a") == Some("green".into())
    });

    // A git URL that is no repository over the network is refused when not told otherwise
    // (here it is told otherwise: what is refused is a transport that runs a program).
    daemon.apply(
        &source("")
            .replace("name: repo", "name: bad")
            .replace("file://", "ext::sh -c id "),
    );
    wait_for("the bad URL to be refused", || {
        daemon.status("Source/bad")["message"]
            .to_string()
            .contains("a git URL is https:// or ssh://")
    });

    // The same from a registry.
    let (_registry, port) = registry(&daemon.dir);
    let to = format!("oci://127.0.0.1:{port}/sources/conf:v1");
    std::fs::remove_file(repo.join("conf/link.yaml")).unwrap();
    std::fs::write(repo.join("conf/o.yaml"), map("from-oci", "red")).unwrap();
    std::fs::remove_file(repo.join("conf/a.yaml")).unwrap();
    assert!(
        daemon
            .ok(&["source", "push", "repo/conf", "--to", &to])
            .contains("pushed (1 files)")
    );
    daemon.apply(&format!("apiVersion: kith.dev/v1\nkind: Source\nmetadata: {{ name: artifact, namespace: kith-system }}\nspec: {{ oci: '{to}', intervalSeconds: 5 }}\n"));
    let there = || daemon.kith(&["get", "ConfigMap/from-oci", "-n", "kith-system"]).0 == 0;
    wait_for("the artifact to be applied", there);
    // (Only the cluster's own Source is fetched from this very machine.)
    daemon.apply(&format!(
        "apiVersion: kith.dev/v1\nkind: Source\nmetadata: {{ name: inward }}\nspec: {{ oci: '{to}' }}\n"
    ));
    wait_for("a namespace's Source to be refused this machine", || {
        daemon.status("Source/inward")["message"]
            .to_string()
            .contains("only a Source in kith-system")
    });

    // A Source gone takes what it applied with it.
    daemon.ok(&["delete", "Source/repo"]);
    wait_for("what the source applied to go", || colour("a").is_none());
    assert!(there());
}
