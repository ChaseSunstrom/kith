//! Liveness and readiness probes, `tcp` and `http`, made from this host (units
//! share its network, so a container's port is a port of `localhost`), and `exec`,
//! a command run in the container's namespaces (as `kubectl exec` is) that passes by exiting 0.
//!
//! One task per probed container. It publishes what it sees and pokes the
//! controller when that changes; the controller does the restarting.

use crate::Shared;
use kith_api::kinds::{Container, PortRef, Probe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, watch};

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Health {
    /// False once the liveness probe has failed `failureThreshold` times in a row,
    /// after passing at least once: something still starting is not killed for it.
    pub live: bool,
    /// True while the readiness probe passes (always, without one).
    pub ready: bool,
}

/// The probing of one container. Dropping it stops the probing.
pub struct Probes {
    pub health: watch::Receiver<Health>,
    /// Why an exec probe cannot run (its command could not be started in the container), for the status.
    why: Arc<Mutex<Option<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Probes {
    pub fn why(&self) -> Option<String> {
        self.why.lock().expect("nothing panics holding it").clone()
    }
}

impl Drop for Probes {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Runs a command in the probed unit and blocks: whether it exited 0 within the timeout. What
/// outlasts the timeout is killed. (A stand-in in a test.)
type Exec = Arc<dyn Fn(&[String], Duration) -> bool + Send + Sync>;

/// One probe, resolved: where to connect, what to ask, how often.
#[derive(Debug, PartialEq)]
struct Check {
    port: u16,
    /// `Some` for an http probe.
    path: Option<String>,
    /// `Some` for an exec probe (`port` is then unused): the command.
    exec: Option<Vec<String>>,
    every: Duration,
    timeout: Duration,
    threshold: u32,
    /// How long after the probe began a probe that has never passed counts as failing (`startSeconds`).
    start: Option<Duration>,
}

fn check(container: &Container, probe: &Probe) -> Result<Check, String> {
    let secs = |given: Option<u32>, default: u64| Duration::from_secs(given.map_or(default, |s| s.max(1).into()));
    let make = |port, path, exec| Check {
        port,
        path,
        exec,
        every: secs(probe.interval_seconds, 10),
        timeout: secs(probe.timeout_seconds, 1),
        threshold: probe.failure_threshold.unwrap_or(3).max(1),
        start: probe
            .start_seconds
            .filter(|s| *s > 0)
            .map(|s| Duration::from_secs(s.into())),
    };
    let (port, path) = match (&probe.http, &probe.tcp, &probe.exec) {
        (Some(http), None, None) => (&http.port, Some(http.path.clone())),
        (None, Some(tcp), None) => (&tcp.port, None),
        (None, None, Some(argv)) if argv.is_empty() => return Err("an exec probe needs a command".into()),
        (None, None, Some(argv)) => return Ok(make(0, None, Some(argv.clone()))),
        _ => return Err("a probe is exactly one of http, tcp or exec".into()),
    };
    // The path goes into a request line as it is.
    if path
        .as_ref()
        .is_some_and(|p| !p.starts_with('/') || p.contains(|c: char| c.is_control() || c == ' '))
    {
        return Err("an http probe's path starts with `/` and has no spaces".into());
    }
    let port = match port {
        PortRef::Number(0) => return Err("port 0 cannot be probed".into()),
        PortRef::Number(number) => *number,
        PortRef::Name(name) => {
            let mut ports = container.ports.iter();
            let named = ports.find(|p| p.name.as_ref() == Some(name));
            named.map(|p| p.port).ok_or(format!("no port is named `{name}`"))?
        }
    };
    Ok(make(port, path, None))
}

/// Why a container's probes will not run, for its Workload's status.
pub fn problems(container: &Container) -> Vec<String> {
    let probes = [("liveness", &container.liveness), ("readiness", &container.readiness)];
    let checked = probes.into_iter().filter_map(|(which, probe)| {
        let problem = check(container, probe.as_ref()?).err()?;
        Some(format!("{}: {which} probe: {problem}", container.name))
    });
    checked.collect()
}

/// Start probing a container that was just started. `None` when it has no probe that can run:
/// it then counts as live and ready for as long as it runs.
/// `unit`: its id, where an exec probe's command is run. `pod`: the pod the container is of, if it
/// is of one: its ports are that pod's.
pub fn start(shared: Arc<Shared>, container: &Container, unit: &str, pod: Option<String>) -> Option<Probes> {
    let resolve = |probe: &Option<Probe>| probe.as_ref().and_then(|p| check(container, p).ok());
    let (liveness, readiness) = (resolve(&container.liveness), resolve(&container.readiness));
    if liveness.is_none() && readiness.is_none() {
        return None;
    }
    let (tx, health) = watch::channel(Health {
        live: true,
        ready: readiness.is_none(),
    });
    let why = Arc::new(Mutex::new(None));
    let exec = enter_unit(unit.to_string(), why.clone(), shared.changed.clone());
    let task = tokio::spawn(async move {
        // ponytail: liveness only counts once it has passed, so a container that never
        // listens is never restarted for it (it is never ready either, if it has a readiness
        // probe), unless it has a `startSeconds`: then failing that long after it started counts.
        let at = pod.as_deref().map(|pod| (&*shared, pod));
        let live = watch_one(at, &exec, liveness, &tx, &shared.changed, true, |health, ok| {
            health.live = ok
        });
        let ready = watch_one(at, &exec, readiness, &tx, &shared.changed, false, |health, ok| {
            health.ready = ok
        });
        tokio::join!(live, ready);
    });
    Some(Probes { health, why, task })
}

/// A probe stand-in for a test: no probe runs, `Health` is what it is told.
#[cfg(test)]
pub fn held(health: Health) -> (Probes, watch::Sender<Health>) {
    let (tx, health) = watch::channel(health);
    (
        Probes {
            health,
            why: Arc::default(),
            task: tokio::spawn(async {}),
        },
        tx,
    )
}

/// Runs commands in the container `unit` of this node, as `kubectl exec` does. When it cannot enter
/// it says why, once per change: on stderr, in `why` (the status carries it) and by poking `poke`.
fn enter_unit(unit: String, why: Arc<Mutex<Option<String>>>, poke: Arc<Notify>) -> Exec {
    Arc::new(move |argv, timeout| {
        let begun = std::time::Instant::now();
        let entered = crate::root_part::enter(&unit, argv);
        let said = entered
            .as_ref()
            .err()
            .map(|e| format!("exec probe: cannot run in the container: {e}"));
        if std::mem::replace(&mut *why.lock().expect("nothing panics holding it"), said.clone()) != said {
            if let Some(said) = &said {
                eprintln!("kithd: {unit}: {said}");
            }
            poke.notify_one();
        }
        let Ok(mut entered) = entered else {
            return false;
        };
        // Nothing is read from it, and nothing is typed: it sees the end of its input. (Its output is held
        // unread till it ends, so a probe that writes more than a pipe holds waits and times out.)
        drop(entered.stdin.take());
        let entered = Arc::new(entered);
        let ended = entered.clone();
        // (The time `enter` took is spent.)
        let left = timeout.saturating_sub(begun.elapsed());
        within(left, move || entered.kill(), move || ended.wait().ok())
    })
}

/// Sets the flag again when dropped (a panicking probe too).
struct Idle(Arc<AtomicBool>);

impl Drop for Idle {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Waits for `wait` (a process's exit code) for `timeout`: true if it is 0. Past it `kill` ends the
/// process, `wait` returns, and the probe counts as failed.
fn within(timeout: Duration, kill: impl FnOnce(), wait: impl FnOnce() -> Option<i32> + Send) -> bool {
    std::thread::scope(|scope| {
        let (done, code) = std::sync::mpsc::channel();
        scope.spawn(move || {
            let _ = done.send(wait());
        });
        match code.recv_timeout(timeout) {
            Ok(code) => code == Some(0),
            Err(_) => {
                kill();
                false
            }
        }
    })
}

/// `after_first`: failures count only once the probe has passed.
async fn watch_one(
    at: Option<(&Shared, &str)>,
    exec: &Exec,
    check: Option<Check>,
    tx: &watch::Sender<Health>,
    poke: &Notify,
    after_first: bool,
    set: fn(&mut Health, bool),
) {
    let Some(check) = check else {
        return;
    };
    let (mut failures, mut passed_once, began) = (0, false, tokio::time::Instant::now());
    let idle = Arc::new(AtomicBool::new(true));
    loop {
        let ok = tokio::time::timeout(check.timeout, probe(at, exec, &check, &idle))
            .await
            .unwrap_or(false);
        failures = if ok { 0 } else { failures + 1 };
        passed_once |= ok;
        // Up at the first success; down only after `threshold` failures in a row.
        let late = check.start.is_some_and(|start| began.elapsed() >= start);
        if ok || (failures >= check.threshold && (passed_once || !after_first || late)) {
            let changed = tx.send_if_modified(|health| {
                let before = *health;
                set(health, ok);
                *health != before
            });
            if changed {
                poke.notify_one();
            }
        }
        // Something still starting is asked more often, so it is ready soon after it listens.
        let pause = if passed_once {
            check.every
        } else {
            check.every.min(Duration::from_secs(1))
        };
        tokio::time::sleep(pause).await;
    }
}

/// One attempt: can the port be connected to, and for http, is the answer 2xx or 3xx? For exec, does
/// the command exit 0 in time? `idle`: false while an earlier attempt of this probe still runs on its
/// thread (the caller's timeout drops this future, not the thread): that tick fails without another
/// thread, so a command that cannot be entered or ended does not pile them up.
async fn probe(at: Option<(&Shared, &str)>, exec: &Exec, check: &Check, idle: &Arc<AtomicBool>) -> bool {
    if let Some(argv) = &check.exec {
        if !idle.swap(false, Ordering::SeqCst) {
            return false;
        }
        // (Off the runtime's threads: it forks and waits. The timeout is its own: it kills the process.)
        let (run, argv, timeout, idle) = (exec.clone(), argv.clone(), check.timeout, idle.clone());
        return tokio::task::spawn_blocking(move || {
            let _idle = Idle(idle);
            run(&argv, timeout)
        })
        .await
        .unwrap_or(false);
    }
    // Listeners on either loopback address count: the machine's, or the container's pod's.
    let Ok(mut stream) = crate::pods::connect(at, check.port).await else {
        return false;
    };
    let Some(path) = &check.path else {
        return true;
    };
    let request = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\nUser-Agent: kith-probe\r\n\r\n");
    // "HTTP/1.1 200": the status line is all that is read.
    let mut head = [0u8; 12];
    stream.write_all(request.as_bytes()).await.is_ok()
        && stream.read_exact(&mut head).await.is_ok()
        && head.starts_with(b"HTTP/1.")
        && matches!(head[9], b'2' | b'3')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn container(yaml_json: serde_json::Value) -> Container {
        serde_json::from_value(yaml_json).unwrap()
    }

    /// What enters a unit, with the host in its place: the command runs here, under the same timeout
    /// and kill the unit's runs under.
    fn host() -> &'static Exec {
        static HOST: std::sync::LazyLock<Exec> = std::sync::LazyLock::new(stand_in);
        &HOST
    }

    fn stand_in() -> Exec {
        Arc::new(|argv, timeout| {
            let Ok(mut child) = std::process::Command::new(&argv[0]).args(&argv[1..]).spawn() else {
                return false;
            };
            let pid = nix::unistd::Pid::from_raw(child.id() as i32);
            let kill = move || {
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
            };
            within(timeout, kill, move || child.wait().ok().and_then(|s| s.code()))
        })
    }

    /// A path of this test's own, free.
    fn scratch(name: &str) -> String {
        let path = std::env::temp_dir().join(format!("kith-probe-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path.to_str().unwrap().to_string()
    }

    fn exec_check(argv: &[&str], timeout: u64) -> Check {
        Check {
            port: 0,
            path: None,
            exec: Some(argv.iter().map(|a| a.to_string()).collect()),
            every: Duration::from_secs(1),
            timeout: Duration::from_secs(timeout),
            threshold: 1,
            start: None,
        }
    }

    async fn within_secs<T>(secs: u64, what: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(secs), what)
            .await
            .expect("in time")
    }

    /// A container is not ready until its command exits 0, and a failing one keeps it not ready.
    #[tokio::test]
    async fn exec_readiness_waits_for_the_command_to_pass() {
        let file = scratch("ready");
        let check = exec_check(&["test", "-f", &file], 1);
        let (tx, mut health) = watch::channel(Health {
            live: true,
            ready: false,
        });
        let changed = Notify::new();
        let watching = watch_one(None, host(), Some(check), &tx, &changed, false, |health, ok| {
            health.ready = ok
        });
        let story = async {
            tokio::time::sleep(Duration::from_millis(2500)).await;
            assert!(!health.borrow().ready, "ready before the command passed");
            std::fs::write(&file, "").unwrap();
            within_secs(5, health.wait_for(|h| h.ready)).await.unwrap();
            std::fs::remove_file(&file).unwrap();
            within_secs(5, health.wait_for(|h| !h.ready)).await.unwrap();
        };
        tokio::select! {
            _ = watching => unreachable!(),
            _ = story => {}
        }
    }

    /// A command that fails after a first pass ends the container (`live` false), as a tcp probe does,
    /// and one that fails before it does not.
    #[tokio::test]
    async fn exec_liveness_ends_the_container_after_a_first_pass() {
        let file = scratch("live");
        let check = exec_check(&["test", "-f", &file], 1);
        let (tx, mut health) = watch::channel(Health {
            live: true,
            ready: true,
        });
        let changed = Notify::new();
        let watching = watch_one(None, host(), Some(check), &tx, &changed, true, |health, ok| {
            health.live = ok
        });
        let story = async {
            tokio::time::sleep(Duration::from_millis(2500)).await;
            assert!(health.borrow().live, "ended before it ever passed");
            std::fs::write(&file, "").unwrap();
            tokio::time::sleep(Duration::from_millis(1500)).await;
            std::fs::remove_file(&file).unwrap();
            within_secs(5, health.wait_for(|h| !h.live)).await.unwrap();
        };
        tokio::select! {
            _ = watching => unreachable!(),
            _ = story => {}
        }
    }

    /// A command that outlasts `timeoutSeconds` counts as a failure, and its process is killed, not left.
    #[tokio::test]
    async fn exec_liveness_kills_a_command_that_outlasts_its_timeout() {
        let (pid_file, ok_file) = (scratch("pid"), scratch("ok"));
        std::fs::write(&ok_file, "").unwrap();
        // Passes while `ok_file` is there (the first pass); otherwise writes its pid and sleeps.
        let passed = scratch("passed");
        let script = format!(
            "test -f {ok_file} && {{ : > {passed}; exit 0; }}; test -s {pid_file} || echo $$ > {pid_file}; exec sleep 30"
        );
        let check = exec_check(&["sh", "-c", &script], 1);
        let (tx, mut health) = watch::channel(Health {
            live: true,
            ready: true,
        });
        let changed = Notify::new();
        let watching = watch_one(None, host(), Some(check), &tx, &changed, true, |health, ok| {
            health.live = ok
        });
        let story = async {
            // (Failures count once a probe has passed: wait for that, however slow the machine is.)
            within_secs(20, async {
                while !std::path::Path::new(&passed).exists() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await;
            assert!(health.borrow().live);
            std::fs::remove_file(&ok_file).unwrap();
            within_secs(20, health.wait_for(|h| !h.live)).await.unwrap();
            let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
            // (The probe is called failed when its timeout passes on the runtime's side, a moment before the
            // blocking thread's own deadline kills the process: it is gone within a few seconds, not at once.)
            let gone = within_secs(20, async {
                while nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
            gone.await;
        };
        tokio::select! {
            _ = watching => unreachable!(),
            _ = story => {}
        }
    }

    /// A command that stays past its timeout (here one that is not even ended in time) is not run again
    /// beside itself: the ticks in between fail without taking another thread.
    #[tokio::test]
    async fn exec_probe_is_not_run_again_while_an_attempt_is_still_running() {
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = runs.clone();
        let stuck: Exec = Arc::new(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(3000));
            true
        });
        let (tx, health) = watch::channel(Health {
            live: true,
            ready: false,
        });
        let changed = Notify::new();
        let check = exec_check(&["x"], 1);
        let watching = watch_one(None, &stuck, Some(check), &tx, &changed, false, |health, ok| {
            health.ready = ok
        });
        tokio::select! {
            _ = watching => unreachable!(),
            _ = tokio::time::sleep(Duration::from_millis(2500)) => {}
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "one attempt per stuck probe, not one per tick"
        );
        assert!(!health.borrow().ready);
    }

    /// A unit that cannot be entered fails the probe and says why, for the status.
    #[tokio::test]
    async fn exec_probe_says_why_it_cannot_enter() {
        let (why, poke) = (Arc::new(Mutex::new(None)), Arc::new(Notify::new()));
        let enter = enter_unit("no-such-unit".into(), why.clone(), poke.clone());
        assert!(!enter(&["true".to_string()], Duration::from_secs(1)));
        let said = why.lock().unwrap().clone().expect("it said why");
        assert!(said.contains("no-such-unit"), "{said}");
        within_secs(1, poke.notified()).await;
    }

    #[test]
    fn checks_resolve_ports_and_refuse_what_cannot_run() {
        let c = container(serde_json::json!({
            "name": "web", "image": "x",
            "ports": [{ "name": "http", "port": 8080 }],
            "liveness": { "tcp": { "port": "http" }, "intervalSeconds": 0 },
            "readiness": { "http": { "path": "/ok", "port": 81 }, "failureThreshold": 5 },
        }));
        let live = check(&c, c.liveness.as_ref().unwrap()).unwrap();
        assert_eq!((live.port, live.path, live.every), (8080, None, Duration::from_secs(1)));
        let ready = check(&c, c.readiness.as_ref().unwrap()).unwrap();
        assert_eq!(
            (ready.port, ready.path.as_deref(), ready.threshold),
            (81, Some("/ok"), 5)
        );
        assert!(problems(&c).is_empty());

        let exec = container(serde_json::json!({
            "name": "web", "image": "x",
            "readiness": { "exec": ["test", "-f", "/tmp/ready"], "timeoutSeconds": 3 },
        }));
        let run = check(&exec, exec.readiness.as_ref().unwrap()).unwrap();
        assert_eq!(
            run.exec.as_deref(),
            Some(["test".to_string(), "-f".into(), "/tmp/ready".into()].as_slice())
        );
        assert_eq!(run.timeout, Duration::from_secs(3));
        assert!(problems(&exec).is_empty(), "an exec probe runs");

        let bad = container(serde_json::json!({
            "name": "web", "image": "x",
            "liveness": { "exec": [] },
            "readiness": { "http": { "path": "/ok HTTP/1.0\r\nX: y", "port": "nope" } },
        }));
        assert_eq!(
            problems(&bad),
            [
                "web: liveness probe: an exec probe needs a command",
                "web: readiness probe: an http probe's path starts with `/` and has no spaces"
            ]
        );
    }

    #[tokio::test]
    async fn probes_connect_and_read_the_status() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Answers 200 to /ok and 500 to anything else.
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = [0u8; 64];
                let read = stream.read(&mut request).unwrap_or(0);
                let status = if request[..read].starts_with(b"GET /ok ") {
                    "200 OK"
                } else {
                    "500 No"
                };
                let _ = write!(stream, "HTTP/1.1 {status}\r\n\r\n");
            }
        });
        let check = |port, path: Option<&str>| Check {
            port,
            path: path.map(String::from),
            exec: None,
            every: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            threshold: 1,
            start: None,
        };
        let (exec, idle) = (host(), Arc::new(AtomicBool::new(true)));
        assert!(probe(None, exec, &check(port, None), &idle).await);
        assert!(probe(None, exec, &check(port, Some("/ok")), &idle).await);
        assert!(!probe(None, exec, &check(port, Some("/broken")), &idle).await);
        // Nothing listens on port 1.
        assert!(!probe(None, exec, &check(1, None), &idle).await);
    }

    #[tokio::test]
    async fn liveness_waits_for_a_first_success() {
        // A port nothing listens on yet, then something does, then it is gone. (Held bound
        // but not listening until then: freed, another test could take it, answer once and
        // go, and the probe would see a success and a failure while still starting.)
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = socket.local_addr().unwrap().port();
        let check = Check {
            port,
            path: None,
            exec: None,
            every: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            threshold: 1,
            start: None,
        };
        let (tx, mut health) = watch::channel(Health {
            live: true,
            ready: true,
        });
        let changed = Notify::new();
        let watching = watch_one(None, host(), Some(check), &tx, &changed, true, |health, ok| {
            health.live = ok
        });
        let story = async {
            tokio::time::sleep(Duration::from_millis(2500)).await;
            assert!(health.borrow().live, "killed while still starting");
            let listener = socket.listen(16).unwrap();
            tokio::time::sleep(Duration::from_millis(1500)).await;
            drop(listener);
            let down = health.wait_for(|health| !health.live);
            tokio::time::timeout(Duration::from_secs(5), down)
                .await
                .unwrap()
                .unwrap();
        };
        tokio::select! {
            _ = watching => unreachable!(),
            _ = story => {}
        }
    }

    #[test]
    fn start_seconds_is_the_probes_start_deadline() {
        let c = container(serde_json::json!({
            "name": "web", "image": "x",
            "liveness": { "tcp": { "port": 80 }, "startSeconds": 7 },
            "readiness": { "tcp": { "port": 80 } },
        }));
        assert_eq!(
            check(&c, c.liveness.as_ref().unwrap()).unwrap().start,
            Some(Duration::from_secs(7))
        );
        assert_eq!(check(&c, c.readiness.as_ref().unwrap()).unwrap().start, None);
    }

    /// A container that never passes its liveness probe is restarted once `startSeconds` have
    /// gone by (without it, never: it may still be starting).
    #[tokio::test]
    async fn start_seconds_end_the_wait_for_a_first_success() {
        // Port 1 (tcpmux) is one nothing listens on and no test binds, unlike a freed ephemeral port.
        let check = |start| Check {
            port: 1,
            path: None,
            exec: None,
            every: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            threshold: 1,
            start,
        };
        let down_within = |start: Option<Duration>, within: Duration| async move {
            let (tx, mut health) = watch::channel(Health {
                live: true,
                ready: true,
            });
            let changed = Notify::new();
            let watching = watch_one(None, host(), Some(check(start)), &tx, &changed, true, |health, ok| {
                health.live = ok
            });
            let down = tokio::time::timeout(within, health.wait_for(|health| !health.live));
            tokio::select! {
                _ = watching => unreachable!(),
                down = down => down.is_ok(),
            }
        };
        // Not before the deadline, and then within a probe or two.
        assert!(!down_within(Some(Duration::from_secs(3)), Duration::from_millis(2000)).await);
        assert!(down_within(Some(Duration::from_secs(2)), Duration::from_millis(15000)).await);
        // No deadline: a container that never listens is not killed for it.
        assert!(!down_within(None, Duration::from_millis(3500)).await);
    }
}
