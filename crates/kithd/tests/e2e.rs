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
            // (No two of these on one machine serve Images on one port: only who asks does.)
            .args(if args.contains(&"--registry-port") {
                vec![]
            } else {
                vec!["--registry-port", "0"]
            })
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

/// README.md's first run, as it is written: every `kithd` and `kith` line of its steps
/// is run, in a directory with nothing in it and as whoever runs the tests, and what a
/// step says you should see is looked for in what came out (`…` stands for anything).
#[test]
fn readme_first_run_is_what_happens() {
    if !e2e() {
        return;
    }
    let readme = include_str!("../../../README.md");
    let part = readme
        .split("\n## First run\n")
        .nth(1)
        .expect("README.md has a First run");
    let mut pieces = part.split("\n## ").next().unwrap().split("You should see `");
    let (mut before, mut steps) = (pieces.next().unwrap(), Vec::new());
    for piece in pieces {
        let (seen, rest) = piece.split_once('`').expect("what is seen ends");
        let block = before.rsplit("```sh\n").next().unwrap().split("```").next().unwrap();
        steps.push((block.lines().map(str::trim).collect::<Vec<_>>(), seen));
        before = rest;
    }
    assert_eq!(
        steps.len(),
        7,
        "the first run has other steps than this test knows: {steps:?}"
    );
    for (_, seen) in &steps {
        let said = seen.split('…').any(|part| part.len() >= 4);
        assert!(said, "`{seen}` says nothing that can be looked for");
    }
    let built = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "-p", "kith-cli"])
        .status()
        .unwrap();
    assert!(built.success());
    let (kithd, root) = (
        Path::new(env!("CARGO_BIN_EXE_kithd")),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
    );
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("first-run");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let kith = |args: &[&str]| {
        let mut command = Command::new(kithd.with_file_name("kith"));
        command
            .args(args)
            .current_dir(&root)
            .env("KITH_SOCKET", dir.join("kithd.sock"))
            .env_remove("KITH_STORE");
        command
    };
    let is = |said: &str, seen: &str| {
        let mut rest = said;
        seen.split('…')
            .all(|part| rest.find(part).map(|at| rest = &rest[at + part.len()..]).is_some())
    };
    let mut daemon = None;
    for (lines, seen) in steps {
        for line in lines {
            let words: Vec<&str> = line.split('#').next().unwrap().split_whitespace().collect();
            let mut said = String::new();
            match words.as_slice() {
                // (Where the page's kithd keeps its socket and state is this user's own: here, the directory.)
                ["kithd", "&"] => {
                    let log = std::fs::File::create(dir.join("kithd.log")).unwrap();
                    let mut command = Command::new(kithd);
                    command
                        .current_dir(&dir)
                        .args(["--state", "state", "--registry-port", "0", "--socket"]);
                    let child = command
                        .arg(dir.join("kithd.sock"))
                        .stdin(Stdio::null())
                        .stderr(log)
                        .spawn()
                        .unwrap();
                    daemon = Some(Daemon {
                        child,
                        dir: dir.clone(),
                        args: &[],
                        kith: kithd.with_file_name("kith"),
                    });
                    wait_for("kithd to say what the page says", || {
                        said = std::fs::read_to_string(dir.join("kithd.log")).unwrap();
                        is(&said, seen)
                    });
                }
                // (It serves until it is stopped: its address is all that is waited for.)
                ["kith", "ui"] => {
                    use std::io::BufRead;
                    let mut ui = kith(&["ui"]).stdout(Stdio::piped()).spawn().unwrap();
                    let lines = std::io::BufReader::new(ui.stdout.take().unwrap()).lines();
                    // (Read aside, so that a `kith ui` that never says it is given up on and ended.)
                    let (tell, told) = std::sync::mpsc::channel();
                    std::thread::spawn(move || lines.map_while(Result::ok).all(|line| tell.send(line).is_ok()));
                    while !is(&said, seen) {
                        match told.recv_timeout(Duration::from_secs(30)) {
                            Ok(line) => said += &line,
                            Err(_) => break,
                        }
                    }
                    ui.kill().unwrap();
                    let _ = ui.wait();
                }
                ["kith", args @ ..] => wait_for(&format!("`{line}` to say `{seen}`"), || {
                    let out = kith(args).output().unwrap();
                    said = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
                    is(&said, seen)
                }),
                // (Building and the path: what `cargo test` did, and where the two are.)
                ["cargo", "build", "--release"] | ["export", _] | [] => continue,
                _ => panic!("the first run has a line this test does not run: {line}"),
            }
            assert!(is(&said, seen), "`{line}` said:\n{said}\nnot: {seen}");
        }
    }
    assert!(daemon.is_some(), "the first run never started kithd");
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

/// A KindDefinition makes a kind that the store and the CLI take like one of kith's own.
#[test]
fn custom_kind_works_like_a_builtin() {
    let daemon = Daemon::start("custom_kind");
    let definition = "apiVersion: kith.dev/v1\nkind: KindDefinition\nmetadata: { name: gameserver }\nspec:\n  group: games.example.com\n  version: v1\n  kind: GameServer\n  schema:\n    type: object\n    required: [map]\n    additionalProperties: false\n    properties:\n      map: { type: string }\n      players: { type: integer, maximum: 64 }\n  columns:\n    - { name: Map, path: spec.map }\n    - { name: Players, path: spec.players }\n";
    let server = |name: &str, spec: &str| {
        format!("apiVersion: games.example.com/v1\nkind: GameServer\nmetadata: {{ name: {name} }}\nspec: {spec}\n")
    };
    let refused = |yaml: &str| {
        std::fs::write(daemon.dir.join("bad.yaml"), yaml).unwrap();
        let (code, _, err) = daemon.kith(&["apply", "-f", "bad.yaml"]);
        assert_eq!(code, 2, "{err}");
        err
    };

    // Not a kind until it is defined.
    assert!(
        daemon
            .kith(&["get", "gameserver"])
            .2
            .contains("unknown kind `gameserver`")
    );
    assert!(refused(&server("one", "{ map: dust }")).contains("no KindDefinition makes it"));

    // Defined and used in one apply (the definition first); then like any kind.
    let both = format!("{definition}---\n{}", server("one", "{ map: dust, players: 8 }"));
    assert!(daemon.apply(&both).contains("GameServer/default/one created"));
    let wrong = refused(&server("two", "{ players: 99, cheats: true }"));
    for said in [
        "spec.map: is required",
        "spec.players: it must be at most 64",
        "spec.cheats",
    ] {
        assert!(wrong.contains(said), "{wrong}");
    }
    daemon.apply(&server("two", "{ map: nuke }").replace("name: two", "name: two, namespace: shop"));
    let table = daemon.ok(&["get", "gameserver"]);
    let lines: Vec<Vec<&str>> = table.lines().map(|line| line.split_whitespace().collect()).collect();
    assert_eq!(lines[0], ["NAMESPACE", "NAME", "REVISION", "MAP", "PLAYERS"], "{table}");
    assert_eq!(
        (&lines[1], &lines[2]),
        (
            &vec!["default", "one", "1", "dust", "8"],
            &vec!["shop", "two", "1", "nuke"]
        )
    );
    assert!(
        daemon
            .ok(&["get", "GameServer/two", "-n", "shop", "-o", "yaml"])
            .contains("apiVersion: games.example.com/v1")
    );
    assert!(
        daemon
            .ok(&["schema"])
            .contains("games.example.com/v1 (KindDefinition/gameserver)")
    );
    assert!(daemon.ok(&["schema", "gameserver"]).contains("\"maximum\": 64"));
    let watched = watch_request(&daemon, "?kind=GameServer");
    assert_eq!(watched["resources"].as_array().unwrap().len(), 2);
    assert!(daemon.ok(&["history", "gameserver/one"]).contains('1'));

    // The definition stays while its kind is used; then both go.
    let (code, _, err) = daemon.kith(&["delete", "kinddefinition/gameserver"]);
    assert!(code == 2 && err.contains("2 `GameServer` resources exist"), "{err}");
    daemon.ok(&["delete", "gameserver/one"]);
    daemon.ok(&["delete", "gameserver", "two", "-n", "shop"]);
    daemon.ok(&["delete", "kinddefinition/gameserver"]);
    assert!(daemon.kith(&["get", "gameserver"]).2.contains("unknown kind"));
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
        // The address is the last thing in a reply whose last record is an A.
        (0, 1..) => Ok(reply[reply.len() - 4..].try_into().unwrap()),
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

    // A CNAME to a name outside the zone comes with the address the other resolver gives for it.
    daemon.apply(
        "apiVersion: kith.dev/v1\nkind: DNSRecord\nmetadata:\n  name: www\n\
         spec:\n  zone: home\n  name: www\n  type: CNAME\n  values: [example.org]\n",
    );
    wait_for("the CNAME", || daemon.status("dnsrecord/www")["state"] == "served");
    assert_eq!(resolve(port, "www.home.example"), Ok([198, 51, 100, 7]));

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

/// An Identity with a certificate does over TLS what its Roles allow, and the audit
/// log says who did what. (Loopback and curl are all this needs.)
#[test]
fn rbac_is_enforced_and_audited() {
    let port = free_port();
    let listen: &'static str = Box::leak(format!("127.0.0.1:{port}").into_boxed_str());
    let args: &'static [&'static str] = Box::leak(Box::new(["--name", "alpha", "--listen", listen]));
    let daemon = Daemon::start_with("rbac", args);
    // As whoever holds the certificate in `dir`: the status and the reply.
    let call = |dir: &str, method: &str, path: &str, body: &str| {
        let file = |name: &str| daemon.dir.join(dir).join(name);
        let mut curl = Command::new("curl");
        curl.args(["-s", "--max-time", "10", "-w", "\n%{http_code}", "-X", method])
            .arg("--cacert")
            .arg(file("ca.crt"))
            .args(["--resolve", &format!("kith:{port}:127.0.0.1")]);
        if dir != "nobody" {
            curl.arg("--cert").arg(file("alice.crt"));
            curl.arg("--key").arg(file("alice.key"));
        }
        if !body.is_empty() {
            curl.args(["-H", "Content-Type: application/json", "-d", body]);
        }
        let out = curl.arg(format!("https://kith:{port}{path}")).output().unwrap();
        let out = String::from_utf8(out.stdout).unwrap();
        let (reply, status) = out.rsplit_once('\n').unwrap_or_default();
        let reply = serde_json::from_str(reply).unwrap_or(serde_json::Value::Null);
        (status.parse::<u16>().unwrap_or(0), reply)
    };
    for dir in ["first", "second", "nobody"] {
        std::fs::create_dir_all(daemon.dir.join(dir)).unwrap();
    }
    let said = daemon.ok(&["identity", "cert", "alice", "--out", "first"]);
    assert!(said.contains("nothing, until a RoleBinding names it"), "{said}");
    std::fs::copy(daemon.dir.join("first/ca.crt"), daemon.dir.join("nobody/ca.crt")).unwrap();
    wait_for("the TLS port to answer", || {
        call("nobody", "GET", "/v1/ca", "").0 == 200
    });
    use std::os::unix::fs::PermissionsExt;
    let key = std::fs::metadata(daemon.dir.join("first/alice.key")).unwrap();
    assert_eq!(key.permissions().mode() & 0o777, 0o600);

    // No certificate: nobody. A certificate and no Role: known, and allowed nothing.
    assert_eq!(call("nobody", "GET", "/v1/resources", "").0, 401);
    let (status, reply) = call("first", "GET", "/v1/resources", "");
    assert_eq!(status, 403, "{reply}");
    assert_eq!(
        reply["error"],
        "alice may not list anything: no Role bound to it allows that"
    );

    let map = |namespace: &str, name: &str, value: &str| {
        serde_json::json!({
            "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
            "metadata": { "name": name, "namespace": namespace }, "spec": { "data": { "k": value } },
        })
    };
    let admin = serde_json::json!([
        { "apiVersion": "kith.dev/v1", "kind": "Role", "metadata": { "name": "web-editor" }, "spec": { "rules": [
            { "kinds": ["ConfigMap"], "verbs": ["get", "list", "apply"], "namespaces": ["web"] },
        ] } },
        { "apiVersion": "kith.dev/v1", "kind": "RoleBinding", "metadata": { "name": "alice-web" },
          "spec": { "role": "web-editor", "subjects": ["alice"] } },
        map("web", "site", "one"),
        map("default", "other", "one"),
    ]);
    // (A JSON list is YAML too, but `kith apply` takes documents: one each.)
    let documents: Vec<String> = admin.as_array().unwrap().iter().map(|r| r.to_string()).collect();
    daemon.apply(&documents.join("\n---\n"));

    // She lists what she may see, and gets the same; the rest is refused with the reason.
    let (status, reply) = call("first", "GET", "/v1/resources", "");
    let keys = |reply: &serde_json::Value| -> Vec<String> {
        let all = reply.as_array().into_iter().flatten();
        let key = |r: &serde_json::Value| {
            let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
            format!("{}/{}", text(&r["metadata"]["namespace"]), text(&r["metadata"]["name"]))
        };
        all.map(key).collect()
    };
    assert_eq!((status, keys(&reply)), (200, vec!["web/site".to_string()]), "{reply}");
    assert_eq!(call("first", "GET", "/v1/resources/ConfigMap/web/site", "").0, 200);
    let (status, reply) = call("first", "GET", "/v1/resources/ConfigMap/default/other", "");
    assert_eq!(status, 403);
    assert_eq!(
        reply["error"],
        "alice may not get ConfigMap in namespace default: no Role bound to it allows that"
    );
    assert_eq!(call("first", "GET", "/v1/resources?kind=Role", "").0, 403);
    assert_eq!(call("first", "GET", "/v1/watch", "").0, 403);
    assert_eq!(call("first", "GET", "/v1/audit", "").0, 403);
    assert_eq!(call("first", "DELETE", "/v1/resources/ConfigMap/web/site", "").0, 403);
    // What is the nodes' own is not hers, whatever a Role says.
    assert_eq!(call("first", "POST", "/v1/ping", "{}").0, 403);

    // She applies where she may; one resource she may not refuses the whole body.
    let body = serde_json::json!([map("web", "site", "two")]);
    let (status, reply) = call("first", "POST", "/v1/apply", &body.to_string());
    assert_eq!(status, 200, "{reply}");
    let both = serde_json::json!([map("web", "site", "three"), map("default", "other", "three")]);
    assert_eq!(call("first", "POST", "/v1/apply", &both.to_string()).0, 403);
    let grant = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "RoleBinding", "metadata": { "name": "mine" },
        "spec": { "role": "web-editor", "subjects": ["alice"] } }]);
    assert_eq!(call("first", "POST", "/v1/apply", &grant.to_string()).0, 403);
    let site = daemon.ok(&["get", "configmap/site", "-n", "web", "-o", "json"]);
    let site: serde_json::Value = serde_json::from_str(&site).unwrap();
    assert_eq!(site["spec"]["data"]["k"], "two");

    // The audit log: her change, her refusals, and the admin's own.
    let audit = daemon.ok(&["audit"]);
    let line = |who: &str, did: &str, what: &str, outcome: &str| {
        let found = audit.lines().any(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            words.get(1..3) == Some(&[who, did]) && line.contains(what) && line.contains(outcome)
        });
        assert!(found, "no `{who} {did} {what} {outcome}` in:\n{audit}");
    };
    line("alice", "apply", "ConfigMap/web/site", "ok");
    line(
        "alice",
        "apply",
        "ConfigMap in namespace default",
        "alice may not apply ConfigMap",
    );
    line("alice", "delete", "ConfigMap in namespace web", "alice may not delete");
    line("alice", "apply", "RoleBinding", "alice may not apply RoleBinding");
    line("local", "socket", "Identity/alice", "ok");
    assert!(audit.contains("Role/web-editor"), "{audit}");

    // A new certificate ends the old one's access; deleting the Identity ends it all.
    daemon.ok(&["identity", "cert", "alice", "--out", "second"]);
    let (status, reply) = call("first", "GET", "/v1/resources", "");
    assert_eq!(status, 401, "{reply}");
    assert_eq!(call("second", "GET", "/v1/resources/ConfigMap/web/site", "").0, 200);
    daemon.ok(&["delete", "identity/alice"]);
    assert_eq!(call("second", "GET", "/v1/resources/ConfigMap/web/site", "").0, 401);
}

/// The SDK's example, built to WebAssembly as its users would. `None` (and the test
/// skipped) where this Rust cannot build for wasm32: `rustup target add wasm32-unknown-unknown`.
fn wasm_example() -> Option<PathBuf> {
    let sysroot = Command::new("rustc").args(["--print", "sysroot"]).output().unwrap();
    let sysroot = PathBuf::from(String::from_utf8(sysroot.stdout).unwrap().trim());
    if !sysroot.join("lib/rustlib/wasm32-unknown-unknown").exists() {
        eprintln!("skipped: no wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown)");
        return None;
    }
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/kith-controller/examples/gameserver");
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("wasm-example");
    let built = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "--release", "--target", "wasm32-unknown-unknown"])
        .arg("--manifest-path")
        .arg(example.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target)
        // (Not this build's flags: that one is for another machine.)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .unwrap();
    assert!(built.success(), "the SDK example does not build");
    Some(target.join("wasm32-unknown-unknown/release/gameserver_controller.wasm"))
}

/// Two kinds of one's own, with the example module as the controller of both and the
/// admission hook of GameServer.
fn game_definitions() -> String {
    let kind = |kind: &str| {
        let name = kind.to_lowercase();
        format!(
            "apiVersion: kith.dev/v1\nkind: KindDefinition\nmetadata: {{ name: {name} }}\nspec:\n  group: games.example.com\n  \
             version: v1\n  kind: {kind}\n  schema:\n    type: object\n    required: [map]\n    additionalProperties: false\n    \
             properties:\n      map: {{ type: string }}\n      players: {{ type: integer, maximum: 64 }}\n"
        )
    };
    format!("{}---\n{}", kind("GameServer"), kind("Match"))
}

fn game_kinds(daemon: &Daemon, module: &Path) {
    daemon.apply(&game_definitions());
    let module = module.to_str().unwrap();
    let said = daemon.ok(&[
        "controller",
        "set",
        "gameserver",
        "--controller",
        module,
        "--admission",
        module,
    ]);
    assert!(said.contains("KindDefinition/gameserver: admission is"), "{said}");
    daemon.ok(&["controller", "set", "Match", "--controller", module]);
}

fn game(kind: &str, name: &str, spec: &str) -> String {
    format!("apiVersion: games.example.com/v1\nkind: {kind}\nmetadata: {{ name: {name} }}\nspec: {spec}\n")
}

fn json_of(daemon: &Daemon, target: &str) -> Option<serde_json::Value> {
    let (code, out, _) = daemon.kith(&["get", target, "-o", "json"]);
    (code == 0).then(|| serde_json::from_str(&out).unwrap())
}

#[test]
fn wasm_admission_refuses_and_changes_writes() {
    let Some(module) = wasm_example() else { return };
    let daemon = Daemon::start("wasm_admission");
    game_kinds(&daemon, &module);
    let refused = |yaml: &str, dry: bool| {
        std::fs::write(daemon.dir.join("bad.yaml"), yaml).unwrap();
        let mut args = vec!["apply", "-f", "bad.yaml"];
        args.extend(dry.then_some("--dry-run"));
        let (code, _, err) = daemon.kith(&args);
        assert_eq!(code, 2, "{err}");
        err
    };

    // Changed on the way in: the module fills in what was left out, and leaves what was said.
    daemon.apply(&game("GameServer", "one", "{ map: dust }"));
    assert_eq!(json_of(&daemon, "gameserver/one").unwrap()["spec"]["players"], 8);
    daemon.apply(&game("GameServer", "two", "{ map: dust, players: 4 }"));
    assert_eq!(json_of(&daemon, "gameserver/two").unwrap()["spec"]["players"], 4);

    // Refused, with the module's reason; a dry run says the same.
    for dry in [false, true] {
        let said = refused(&game("GameServer", "three", "{ map: lava }"), dry);
        let why = "GameServer/default/three: refused by GameServer's admission: the map lava is closed";
        assert!(said.contains(why), "{said}");
    }
    assert!(json_of(&daemon, "gameserver/three").is_none());
    // What the module makes of it still has to fit the kind's schema.
    assert!(refused(&game("GameServer", "four", "{ map: dust, players: 99 }"), false).contains("at most 64"));

    // A controller's writes are asked about like anyone's: a Match's server gets its players
    // from the admission hook, and one on a closed map is refused, which the Match says.
    daemon.apply(&game("Match", "final", "{ map: dust }"));
    wait_for("the match's server", || {
        json_of(&daemon, "gameserver/final-server").is_some()
    });
    assert_eq!(
        json_of(&daemon, "gameserver/final-server").unwrap()["spec"]["players"],
        8
    );
    daemon.apply(&game("Match", "doomed", "{ map: lava }"));
    wait_for("the match to say why it has no server", || {
        daemon.status("match/doomed")["controller"]["state"] == "error"
    });
    let said = daemon.status("match/doomed")["controller"]["message"].to_string();
    assert!(said.contains("the map lava is closed"), "{said}");
    assert!(json_of(&daemon, "gameserver/doomed-server").is_none());

    // A module that is not one is refused when it is set, and the kind keeps the one it had.
    std::fs::write(daemon.dir.join("not.wasm"), "not a module").unwrap();
    let (code, _, err) = daemon.kith(&["controller", "set", "GameServer", "--admission", "not.wasm"]);
    assert!(
        code == 2 && err.contains("admission.wasm: not a module that can run"),
        "{err}"
    );
    assert!(refused(&game("GameServer", "five", "{ map: lava }"), false).contains("lava is closed"));

    // A rollback is asked about too: what was written before the hook was there does not
    // come back past it. (The definitions applied again, as they were: without the modules.)
    daemon.apply(&game_definitions());
    daemon.apply(&game("GameServer", "six", "{ map: lava, players: 2 }"));
    daemon.apply(&game("GameServer", "six", "{ map: dust, players: 2 }"));
    game_kinds(&daemon, &module);
    let (code, _, err) = daemon.kith(&["rollback", "gameserver/six", "--to", "1"]);
    assert!(code == 2 && err.contains("the map lava is closed"), "{err}");
    assert_eq!(json_of(&daemon, "gameserver/six").unwrap()["spec"]["map"], "dust");
    daemon.apply(&game("GameServer", "six", "{ map: ice, players: 2 }"));
    daemon.ok(&["rollback", "gameserver/six", "--to", "2"]);
    assert_eq!(json_of(&daemon, "gameserver/six").unwrap()["spec"]["map"], "dust");
}

#[test]
fn wasm_controller_makes_what_its_resource_needs() {
    let Some(module) = wasm_example() else { return };
    let daemon = Daemon::start("wasm_controller");
    game_kinds(&daemon, &module);
    let data = |name: &str| json_of(&daemon, &format!("configmap/{name}")).map(|map| map["spec"]["data"].clone());

    // What the controller answers appears, as the resource's own, and the status says so.
    daemon.apply(&game("GameServer", "one", "{ map: dust, players: 4 }"));
    wait_for("the server's settings", || data("one-config").is_some());
    assert_eq!(
        data("one-config").unwrap(),
        serde_json::json!({ "map": "dust", "players": "4" })
    );
    wait_for("the server's status", || {
        daemon.status("gameserver/one")["state"] == "ready"
    });
    let status = daemon.status("gameserver/one");
    assert_eq!(status["resources"], serde_json::json!(["ConfigMap/default/one-config"]));
    assert_eq!(status["controller"]["state"], "ok");
    let config = json_of(&daemon, "configmap/one-config").unwrap();
    assert_eq!(
        config["metadata"]["annotations"]["kith.dev/owned-by"],
        "GameServer/default/one"
    );

    // It follows the resource, and is put back when someone changes or removes it.
    daemon.apply(&game("GameServer", "one", "{ map: ice, players: 4 }"));
    wait_for("the settings to follow", || {
        data("one-config").is_some_and(|data| data["map"] == "ice")
    });
    daemon.ok(&["delete", "configmap/one-config"]);
    wait_for("the settings to come back", || data("one-config").is_some());

    // A chain: a Match's server has settings of its own; all of it goes with the Match.
    daemon.apply(&game("Match", "final", "{ map: dust }"));
    wait_for("the match's server's settings", || {
        data("final-server-config").is_some()
    });
    wait_for("the match's status", || daemon.status("match/final")["servers"] == 1);
    daemon.ok(&["delete", "match/final"]);
    wait_for("what the match made to go", || {
        json_of(&daemon, "gameserver/final-server").is_none() && data("final-server-config").is_none()
    });
    daemon.ok(&["delete", "gameserver/one"]);
    wait_for("the server's settings to go", || data("one-config").is_none());
}

/// curl, for the web UI's tests: (status, headers in lower case, body).
fn fetch(args: &[&str]) -> (u16, String, String) {
    let out = Command::new("curl")
        .args(["-s", "-i", "--max-time", "10"])
        .args(args)
        .output()
        .unwrap();
    let out = String::from_utf8(out.stdout).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or_default();
    let status = head.split(' ').nth(1).and_then(|status| status.parse().ok());
    (status.unwrap_or(0), head.to_lowercase(), body.to_string())
}

#[test]
fn web_ui_is_served_and_asks_as_its_caller() {
    let port = free_port();
    let listen: &'static str = Box::leak(format!("127.0.0.1:{port}").into_boxed_str());
    let args: &'static [&'static str] = Box::leak(Box::new(["--name", "alpha", "--listen", listen]));
    let daemon = Daemon::start_with("web_ui", args);
    daemon.apply(&game_definitions());
    daemon.apply(&game("GameServer", "one", "{ map: dust }"));
    let rules = serde_json::json!([
        { "apiVersion": "kith.dev/v1", "kind": "Role", "metadata": { "name": "games" }, "spec": { "rules": [
            { "kinds": ["GameServer"], "verbs": ["get", "list", "watch", "apply"] },
            { "kinds": ["ConfigMap"], "verbs": ["apply"] },
        ] } },
        { "apiVersion": "kith.dev/v1", "kind": "RoleBinding", "metadata": { "name": "alice-games" },
          "spec": { "role": "games", "subjects": ["alice"] } },
    ]);
    let documents: Vec<String> = rules.as_array().unwrap().iter().map(|r| r.to_string()).collect();
    daemon.apply(&documents.join("\n---\n"));
    daemon.ok(&["identity", "cert", "alice", "--out", "."]);
    let json = |body: &str| serde_json::from_str::<serde_json::Value>(body).unwrap_or_default();

    // On the TLS port: the page for anyone (it is the same for everyone, and locked down),
    // what it asks for only for who the certificate says.
    let resolve = format!("kith:{port}:127.0.0.1");
    let ca = daemon.dir.join("ca.crt");
    let tls = |path: &str, certificate: bool, body: Option<&str>| {
        let url = format!("https://kith:{port}{path}");
        let (cert, key) = (daemon.dir.join("alice.crt"), daemon.dir.join("alice.key"));
        let mut args = vec!["--cacert", ca.to_str().unwrap(), "--resolve", &resolve];
        if certificate {
            args.extend(["--cert", cert.to_str().unwrap(), "--key", key.to_str().unwrap()]);
        }
        if let Some(body) = body {
            // (No "Expect: 100-continue" curl adds to a big body: the status asked for is the last.)
            args.extend(["-H", "Content-Type: application/json", "-H", "Expect:", "-d", body]);
        }
        args.push(&url);
        fetch(&args)
    };
    wait_for("the TLS port to answer", || tls("/v1/ca", false, None).0 == 200);
    for (file, kind) in [
        ("", "text/html"),
        ("app.js", "text/javascript"),
        ("forms.js", "text/javascript"),
        ("app.css", "text/css"),
    ] {
        let (status, head, body) = tls(&format!("/ui/{file}"), false, None);
        assert_eq!(status, 200, "/ui/{file}");
        assert!(head.contains(&format!("content-type: {kind}")), "{head}");
        assert!(
            head.contains("content-security-policy: default-src 'none'; script-src 'self';"),
            "{head}"
        );
        assert!(
            head.contains("x-content-type-options: nosniff") && head.contains("referrer-policy: no-referrer"),
            "{head}"
        );
        assert!(body.len() > 500, "/ui/{file} is {} bytes", body.len());
    }
    let (status, head, _) = tls("/ui", false, None);
    assert!(status == 308 && head.contains("location: ui/"), "{head}");
    assert_eq!(tls("/ui/Cargo.toml", false, None).0, 404);
    for path in ["/v1/schemas", "/v1/watch", "/v1/resources"] {
        assert_eq!(tls(path, false, None).0, 401, "{path} without a certificate");
    }
    assert_eq!(tls("/v1/diff", false, Some("[]")).0, 401);
    assert_eq!(tls("/v1/convert", false, Some("{}")).0, 401);

    // Alice is told who she is and shown the one kind a Role gives her, with its schema.
    let (status, _, body) = tls("/v1/schemas", true, None);
    let said = json(&body);
    assert_eq!(status, 200, "{body}");
    assert_eq!(said["caller"], "alice");
    let kinds = said["kinds"].as_array().unwrap();
    assert_eq!(kinds.len(), 2, "{body}");
    assert_eq!(
        (&kinds[0]["kind"], &kinds[0]["may"]),
        (&"ConfigMap".into(), &serde_json::json!(["apply"]))
    );
    assert_eq!(kinds[1]["kind"], "GameServer");
    assert_eq!(kinds[1]["may"], serde_json::json!(["get", "list", "watch", "apply"]));
    assert_eq!(kinds[1]["schema"]["properties"]["spec"]["required"][0], "map");

    // What the page does before a write: YAML to JSON, then the diff of a dry run, as her.
    let yaml = game("GameServer", "one", "{ map: ice }");
    let (status, _, body) = tls(
        "/v1/convert",
        true,
        Some(&serde_json::json!({ "yaml": yaml }).to_string()),
    );
    assert_eq!(status, 200, "{body}");
    let resources = json(&body)["resources"].clone();
    assert_eq!(resources[0]["spec"]["map"], "ice");
    // It is text a person typed: over 1 MB is refused before it is read (a file: an argument is too short).
    let big = daemon.dir.join("big.json");
    std::fs::write(&big, serde_json::json!({ "yaml": "#".repeat(1 << 20) }).to_string()).unwrap();
    let (status, _, body) = tls("/v1/convert", true, Some(&format!("@{}", big.display())));
    assert_eq!(status, 413, "{body}");
    let (status, _, body) = tls("/v1/diff", true, Some(&resources.to_string()));
    let plan = json(&body);
    assert_eq!(status, 200, "{body}");
    assert_eq!(plan[0]["key"], "GameServer/default/one");
    assert_eq!(plan[0]["action"], "updated");
    let diff = plan[0]["diff"].as_str().unwrap();
    assert!(diff.contains("-  map: dust") && diff.contains("+  map: ice"), "{diff}");
    // (Nothing was written by asking.)
    assert_eq!(json_of(&daemon, "gameserver/one").unwrap()["spec"]["map"], "dust");
    // What is wrong is said as the store says it; what is not hers to change is refused.
    let bad = serde_json::json!([{ "apiVersion": "games.example.com/v1", "kind": "GameServer",
        "metadata": { "name": "one" }, "spec": { "map": "dust", "players": 99 } }]);
    let (status, _, body) = tls("/v1/diff", true, Some(&bad.to_string()));
    assert!(status == 422 && body.contains("at most 64"), "{status} {body}");
    let other = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "Namespace", "metadata": { "name": "x" }, "spec": {} }]);
    let (status, _, body) = tls("/v1/diff", true, Some(&other.to_string()));
    assert!(
        status == 403 && body.contains("alice may not apply Namespace"),
        "{status} {body}"
    );
    // What she may apply but not get, she is not shown as it was: neither asking nor applying.
    daemon.apply(
        "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: kept }\nspec: { data: { word: hush-hush } }\n",
    );
    let over = serde_json::json!([{ "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
        "metadata": { "name": "kept" }, "spec": { "data": { "word": "loud" } } }]);
    for path in ["/v1/diff", "/v1/apply?dryRun=true", "/v1/apply"] {
        let (status, _, body) = tls(path, true, Some(&over.to_string()));
        assert!(
            status == 200 && body.contains("loud") && !body.contains("hush-hush"),
            "{path}: {status} {body}"
        );
    }
    // The write itself is `kith apply`'s call, and is in the audit log as hers.
    let (status, _, body) = tls("/v1/apply", true, Some(&resources.to_string()));
    assert_eq!(status, 200, "{body}");
    assert_eq!(json_of(&daemon, "gameserver/one").unwrap()["spec"]["map"], "ice");
    let audit = daemon.ok(&["audit", "--tail", "5"]);
    assert!(
        audit
            .lines()
            .any(|line| line.contains("alice") && line.contains("GameServer/one") && line.ends_with("ok")),
        "{audit}"
    );

    // `kith ui`: the same page for a browser on this machine, as its administrator, behind
    // the address it prints and nothing else.
    let mut forwarder = Command::new(&daemon.kith)
        .args(["ui"])
        .current_dir(&daemon.dir)
        .env("KITH_SOCKET", daemon.dir.join("kithd.sock"))
        .env_remove("KITH_STORE")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut address = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(forwarder.stdout.take().unwrap()),
        &mut address,
    )
    .unwrap();
    let address = address
        .trim()
        .strip_suffix("/ui/")
        .expect("the address of the page")
        .to_string();
    let (origin, secret) = address.rsplit_once('/').unwrap();
    assert!(
        origin.starts_with("http://127.0.0.1:") && secret.len() == 32,
        "{address}"
    );
    let (status, head, body) = fetch(&[&format!("{address}/ui/")]);
    assert!(status == 200 && body.contains("<title>kith</title>"), "{status} {head}");
    assert!(head.contains("content-security-policy"), "{head}");
    let (status, _, body) = fetch(&[&format!("{address}/v1/schemas")]);
    assert_eq!(status, 200, "{body}");
    assert_eq!(json(&body)["caller"], "local socket");
    assert!(json(&body)["kinds"].as_array().unwrap().len() > 20);
    // A write through it, from the page's own origin.
    let new = serde_json::json!([{ "apiVersion": "games.example.com/v1", "kind": "GameServer",
        "metadata": { "name": "two" }, "spec": { "map": "dust" } }]);
    let post = |url: &str, more: &[&str]| {
        let body = new.to_string();
        let mut args = vec!["-H", "Content-Type: application/json", "-d", &body];
        args.extend(more);
        args.push(url);
        fetch(&args)
    };
    let (status, _, body) = post(&format!("{address}/v1/apply"), &["-H", &format!("Origin: {origin}")]);
    assert_eq!(status, 200, "{body}");
    assert_eq!(json_of(&daemon, "gameserver/two").unwrap()["spec"]["map"], "dust");
    // Refused: no secret, a wrong one, another site's page, a name pointed at this machine.
    let refusals = [
        post(&format!("{origin}/v1/apply"), &[]),
        post(&format!("{origin}/{}/v1/apply", "0".repeat(32)), &[]),
        post(&format!("{address}/v1/apply"), &["-H", "Origin: http://evil.example"]),
        post(&format!("{address}/v1/apply"), &["-H", "Host: evil.example"]),
        fetch(&[&format!("{origin}/ui/")]),
    ];
    for (status, _, body) in refusals {
        assert_eq!(status, 403, "{body}");
    }
    forwarder.kill().unwrap();
    forwarder.wait().unwrap();
}

/// A node with no shell (kith OS): its first admin is made over TLS, by whoever has the
/// token `--claim` prints while the cluster has no Identity.
#[test]
fn claim_makes_the_first_admin_over_tls() {
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("claim");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let kithd = Path::new(env!("CARGO_BIN_EXE_kithd"));
    // (Its own start: what kithd says is what is read here.)
    let spawn = |said: &str| {
        Command::new(kithd)
            .current_dir(&dir)
            .args(["--state", "state", "--name", "alpha", "--listen", &listen, "--claim"])
            .arg("--socket")
            .arg(dir.join("kithd.sock"))
            .stdin(Stdio::null())
            .stderr(std::fs::File::create(dir.join(said)).unwrap())
            .spawn()
            .unwrap()
    };
    let mut daemon = Daemon {
        child: spawn("said"),
        dir: dir.clone(),
        args: &[],
        kith: kithd.with_file_name("kith"),
    };
    let token_in = |said: &str| {
        let said = std::fs::read_to_string(dir.join(said)).unwrap_or_default();
        let token = said.split_whitespace().find(|word| word.starts_with("kith1."));
        token.map(str::to_string)
    };
    wait_for("kithd to print a claim token", || token_in("said").is_some());
    let token = token_in("said").unwrap();

    let post = |path: &str, body: serde_json::Value| {
        let mut curl = Command::new("curl");
        curl.args(["-s", "-k", "--max-time", "10", "-w", "\n%{http_code}"])
            .args(["-H", "Content-Type: application/json", "-d", &body.to_string()])
            .arg(format!("https://127.0.0.1:{port}{path}"));
        let out = String::from_utf8(curl.output().unwrap().stdout).unwrap();
        let (reply, status) = out.rsplit_once('\n').unwrap_or_default();
        let reply = serde_json::from_str(reply).unwrap_or(serde_json::Value::Null);
        (status.parse::<u16>().unwrap_or(0), reply)
    };
    wait_for("the TLS port to answer", || {
        post("/v1/claim", serde_json::json!({ "token": "x", "name": "root" })).0 == 403
    });
    // Only a cluster with no Identity can be claimed: once the socket's admin has made
    // one, the token on the console is worth nothing (and takes nobody's name over).
    daemon.ok(&["identity", "cert", "alice", "--out", "."]);
    for name in ["alice", "root"] {
        let (status, reply) = post("/v1/claim", serde_json::json!({ "token": token, "name": name }));
        assert_eq!(status, 409, "{reply}");
    }
    assert!(!daemon.ok(&["get", "rolebinding"]).contains("cluster-admin"));
    daemon.ok(&["delete", "identity/alice"]);
    // Each token for its own use: one that admits a node makes no admin, and the reverse.
    let join = daemon.ok(&["node", "token"]);
    let join = join.split_whitespace().find(|word| word.starts_with("kith1.")).unwrap();
    let (status, reply) = post("/v1/claim", serde_json::json!({ "token": join, "name": "root" }));
    assert_eq!(status, 403, "{reply}");
    let (status, reply) = post(
        "/v1/join",
        serde_json::json!({ "token": token, "name": "beta", "port": 1 }),
    );
    assert_eq!(status, 403, "{reply}");
    // A name that cannot be an Identity's does not spend the token.
    let (status, reply) = post("/v1/claim", serde_json::json!({ "token": token, "name": "Not A Name" }));
    assert_eq!(status, 422, "{reply}");

    let (status, reply) = post("/v1/claim", serde_json::json!({ "token": token, "name": "root" }));
    assert_eq!(status, 200, "{reply}");
    for (file, field) in [("ca.crt", "ca"), ("root.crt", "cert"), ("root.key", "key")] {
        std::fs::write(dir.join(file), reply[field].as_str().unwrap()).unwrap();
    }
    // The token's last part is the CA's fingerprint, as openssl prints it: who claims
    // can tell the node is the one whose console showed the token.
    let print = Command::new("openssl")
        .args(["x509", "-noout", "-fingerprint", "-sha256", "-in"])
        .arg(dir.join("ca.crt"))
        .output()
        .unwrap();
    let print = String::from_utf8(print.stdout).unwrap().replace(':', "").to_lowercase();
    assert!(print.trim().ends_with(token.rsplit('.').next().unwrap()), "{print}");
    // Good once.
    let (status, reply) = post("/v1/claim", serde_json::json!({ "token": token, "name": "other" }));
    assert_eq!(status, 403, "{reply}");
    assert_eq!(
        reply["error"],
        "the claim token is wrong, already used, or older than an hour"
    );

    // With the certificate, and the node checked against the CA: everything.
    let call = |who: &str, method: &str, path: &str, body: &str| {
        let mut curl = Command::new("curl");
        curl.args([
            "-s",
            "--max-time",
            "10",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-X",
            method,
        ])
        .arg("--cacert")
        .arg(dir.join("ca.crt"))
        .arg("--cert")
        .arg(dir.join(format!("{who}.crt")))
        .arg("--key")
        .arg(dir.join(format!("{who}.key")))
        .args(["--resolve", &format!("kith:{port}:127.0.0.1")]);
        if !body.is_empty() {
            curl.args(["-H", "Content-Type: application/json", "-d", body]);
        }
        let out = curl.arg(format!("https://kith:{port}{path}")).output().unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(call("root", "GET", "/v1/resources", ""), "200");
    let role = serde_json::json!([{
        "apiVersion": "kith.dev/v1", "kind": "Role", "metadata": { "name": "reader" },
        "spec": { "rules": [{ "kinds": ["*"], "verbs": ["get", "list"] }] },
    }]);
    assert_eq!(call("root", "POST", "/v1/apply", &role.to_string()), "200");
    assert!(daemon.ok(&["get", "identity"]).contains("root"));
    assert!(daemon.ok(&["audit"]).contains("claim"), "the claim is in the audit log");
    // A join token, without the node's socket: for who may apply Nodes, and nobody else.
    assert_eq!(call("root", "POST", "/v1/tokens", ""), "200");
    daemon.ok(&["identity", "cert", "alice", "--out", "."]);
    assert_eq!(call("alice", "POST", "/v1/tokens", ""), "403");
    // Nor for one that may apply Nodes and no more: a node may do everything, so a
    // join token is for who could give itself every right anyway.
    let noder = serde_json::json!([
        { "apiVersion": "kith.dev/v1", "kind": "Role", "metadata": { "name": "noder" },
          "spec": { "rules": [{ "kinds": ["Node"], "verbs": ["get", "list", "apply"] }] } },
        { "apiVersion": "kith.dev/v1", "kind": "RoleBinding", "metadata": { "name": "noder-alice" },
          "spec": { "role": "noder", "subjects": ["alice"] } },
    ]);
    assert_eq!(call("root", "POST", "/v1/apply", &noder.to_string()), "200");
    assert_eq!(call("alice", "POST", "/v1/tokens", ""), "403");
    assert_eq!(post("/v1/tokens", serde_json::json!({})).0, 401);
    assert!(daemon.ok(&["node", "token"]).contains("kith1."));

    // There is an Identity now: a restart prints no token.
    daemon.stop();
    std::fs::remove_file(dir.join("kithd.sock")).ok();
    daemon.child = spawn("said-again");
    wait_for("kithd to serve again", || {
        std::fs::read_to_string(dir.join("said-again")).is_ok_and(|said| said.contains("serving other nodes"))
    });
    assert_eq!(token_in("said-again"), None);
}

/// A `vms` unit is a real machine: a Job boots a kernel under KVM, the machine's console is
/// the unit's log, and the Job is done when the machine ends (with no disk the kernel has no
/// root, gives up and restarts, which ends the hypervisor). Skipped where there is no KVM,
/// QEMU or kernel to boot (`KITH_E2E_KERNEL`, else the host's own).
#[test]
fn a_vm_unit_boots_a_kernel_and_its_console_is_the_log() {
    if !e2e() {
        return;
    }
    let kernel = std::env::var("KITH_E2E_KERNEL").ok().or_else(|| {
        let boot = std::fs::read_dir("/boot").ok()?;
        let mut found: Vec<_> = boot.flatten().map(|entry| entry.path()).collect();
        found.sort();
        let kernel = found.into_iter().find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("vmlinuz"))
                && std::fs::File::open(path).is_ok()
        })?;
        Some(kernel.to_string_lossy().into_owned())
    });
    let qemu = Command::new("qemu-system-x86_64").arg("--version").output().is_ok();
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    let (Some(kernel), true, true) = (kernel, qemu, kvm) else {
        eprintln!("skipped: needs /dev/kvm, qemu-system-x86_64 and a kernel (KITH_E2E_KERNEL)");
        return;
    };
    let daemon = Daemon::start("vm");
    daemon.apply(&format!(
        "apiVersion: kith.dev/v1
kind: Job
metadata:
  name: boot
spec:
  timeoutSeconds: 120
  template:
    restartPolicy: never
    vms:
      - name: machine
        kernel: {kernel}
        cmdline: console=ttyS0 loglevel=7 panic=-1
        cpus: 1
        memory: 256Mi
"
    ));
    wait_for("the machine to end", || daemon.status("Job/boot")["succeeded"] == 1);
    let console = daemon.ok(&["logs", "Job/boot", "--unit", "machine"]);
    assert!(console.contains("Linux version"), "{console}");
    assert!(
        console.contains("Kernel panic"),
        "it had no root to go on with: {console}"
    );
}

/// A template that is `confidential` runs nothing on a node whose processor keeps no guest's
/// memory encrypted, and its status says why. Skipped on a machine that would run it.
#[test]
fn a_confidential_template_runs_nothing_on_a_node_that_encrypts_no_guest() {
    if !e2e() {
        return;
    }
    let on = |path: &str| std::fs::read_to_string(path).is_ok_and(|said| said.trim() == "Y");
    if on("/sys/module/kvm_amd/parameters/sev_snp") || on("/sys/module/kvm_intel/parameters/tdx") {
        eprintln!("skipped: this machine has SEV-SNP or TDX, and would start the guest");
        return;
    }
    let daemon = Daemon::start("confidential");
    daemon.apply(
        "apiVersion: kith.dev/v1
kind: Job
metadata:
  name: sealed
spec:
  template:
    confidential: true
    vms:
      - name: machine
        firmware: /nowhere/OVMF.fd
        disks: [{ path: /nowhere/disk.raw }]
        memory: 256Mi
",
    );
    let notes = || daemon.status("Job/sealed")["notes"].to_string();
    wait_for("the node to say why it runs none of it", || {
        notes().contains("no AMD SEV-SNP and no Intel TDX")
    });
    // (Were the machine started, its hypervisor would have failed on the firmware by now.)
    std::thread::sleep(std::time::Duration::from_secs(2));
    let status = daemon.status("Job/sealed");
    assert!(status["succeeded"] != 1 && status["failed"] != 1, "{status}");
    assert!(
        status["containers"].as_array().is_none_or(|units| units.is_empty()),
        "{status}"
    );
}

/// The cluster makes an image of its own and runs it: a Job fills a Volume, an Image packs
/// the volume when the Job has succeeded, the node's registry serves it, and a Job whose
/// container is that image runs what was built. (The container needs a program with no
/// libraries: kith built for musl, `sh ci/musl.sh`, or `KITH_E2E_STATIC`; without one the
/// test ends once the registry has served the image.)
#[test]
fn an_image_built_in_the_cluster_is_pulled_from_its_registry_and_run() {
    use std::io::{Read, Write};
    if !e2e() {
        return;
    }
    let port = free_port();
    let args: &'static [&'static str] = Box::leak(Box::new([
        "--registry-port",
        Box::leak(port.to_string().into_boxed_str()),
    ]));
    let daemon = Daemon::start_with("image", args);
    let musl = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/x86_64-unknown-linux-musl/release/kith");
    let fixed = std::env::var("KITH_E2E_STATIC")
        .ok()
        .map(PathBuf::from)
        .or(musl.exists().then_some(musl));
    let program = fixed.clone().unwrap_or(daemon.kith.clone());
    let root = daemon.dir.join("state/volumes/default/out/root");
    let build = format!(
        "mkdir -p {0}/bin && cp {1} {0}/bin/kith",
        root.display(),
        program.display()
    );
    daemon.apply(&format!(
        "apiVersion: kith.dev/v1
kind: Volume
metadata: {{ name: out }}
spec: {{ node: local, path: root }}
---
{}---
apiVersion: kith.dev/v1
kind: Image
metadata: {{ name: hello }}
spec:
  volume: out
  tag: '1'
  job: build
  entrypoint: [/bin/kith]
  cmd: [schema]
",
        exec("Job", "build", &build, "")
    ));
    wait_for("the image to be made", || {
        daemon.status("Image/hello")["digest"].is_string()
    });
    let status = daemon.status("Image/hello");
    let digest = status["digest"].as_str().unwrap();
    assert_eq!(status["blobs"].as_object().unwrap().len(), 3, "{status}");

    // The registry: the manifest by its tag, under its digest; nothing under another tag.
    let get = |path: &str| {
        let mut registry = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            registry,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut reply = String::new();
        registry.read_to_string(&mut reply).unwrap();
        reply
    };
    assert!(get("/v2/").starts_with("HTTP/1.1 200"));
    let manifest = get("/v2/default/hello/manifests/1");
    assert!(manifest.starts_with("HTTP/1.1 200"), "{manifest}");
    assert!(
        manifest.contains(&format!("docker-content-digest: {digest}")),
        "{manifest}"
    );
    assert!(
        manifest.contains("application/vnd.oci.image.layer.v1.tar"),
        "{manifest}"
    );
    assert!(get("/v2/default/hello/manifests/2").starts_with("HTTP/1.1 404"));
    assert!(get("/v2/other/hello/manifests/1").starts_with("HTTP/1.1 404"));

    if fixed.is_none() {
        return eprintln!("the image was not run: no static program (sh ci/musl.sh, or KITH_E2E_STATIC)");
    }
    daemon.apply(&format!(
        "apiVersion: kith.dev/v1
kind: Job
metadata: {{ name: run }}
spec:
  template:
    containers:
      - name: main
        image: 127.0.0.1:{port}/default/hello:1
"
    ));
    wait_for("what was built to run", || {
        let status = daemon.status("Job/run");
        assert_ne!(
            status["state"],
            "failed",
            "{status} {}",
            daemon.log("j_default_run_0_main")
        );
        status["state"] == "succeeded"
    });
    assert!(
        daemon.log("j_default_run_0_main").contains("Workload"),
        "it ran `kith schema`"
    );
}
