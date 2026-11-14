//! Liveness and readiness probes, `tcp` and `http`, made from this host: units
//! share its network, so a container's port is a port of `localhost`.
//!
//! One task per probed container. It publishes what it sees and pokes the
//! controller when that changes; the controller does the restarting.
//!
// ponytail: `exec` probes are not run. Running a command inside a container needs a
// second process in its namespaces whose exit status the controller's orphan reaper
// would race for; it comes with `kith exec`.

use crate::Shared;
use kith_api::kinds::{Container, PortRef, Probe};
use std::sync::Arc;
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
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Probes {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One probe, resolved: where to connect, what to ask, how often.
#[derive(Debug, PartialEq)]
struct Check {
    port: u16,
    /// `Some` for an http probe.
    path: Option<String>,
    every: Duration,
    timeout: Duration,
    threshold: u32,
}

fn check(container: &Container, probe: &Probe) -> Result<Check, String> {
    let (port, path) = match (&probe.http, &probe.tcp, &probe.exec) {
        (Some(http), None, None) => (&http.port, Some(http.path.clone())),
        (None, Some(tcp), None) => (&tcp.port, None),
        (None, None, Some(_)) => return Err("exec probes are not run yet".into()),
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
    let secs = |given: Option<u32>, default: u64| Duration::from_secs(given.map_or(default, |s| s.max(1).into()));
    Ok(Check {
        port,
        path,
        every: secs(probe.interval_seconds, 10),
        timeout: secs(probe.timeout_seconds, 1),
        threshold: probe.failure_threshold.unwrap_or(3).max(1),
    })
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
/// `pod`: the pod the container is of, if it is of one: its ports are that pod's.
pub fn start(shared: Arc<Shared>, container: &Container, pod: Option<String>) -> Option<Probes> {
    let resolve = |probe: &Option<Probe>| probe.as_ref().and_then(|p| check(container, p).ok());
    let (liveness, readiness) = (resolve(&container.liveness), resolve(&container.readiness));
    if liveness.is_none() && readiness.is_none() {
        return None;
    }
    let (tx, health) = watch::channel(Health {
        live: true,
        ready: readiness.is_none(),
    });
    let task = tokio::spawn(async move {
        // ponytail: liveness only counts once it has passed, so a container that never
        // listens is never restarted for it (it is never ready either, if it has a readiness
        // probe). The API has no initialDelaySeconds; a start deadline comes with it.
        let at = pod.as_deref().map(|pod| (&*shared, pod));
        let live = watch_one(at, liveness, &tx, &shared.changed, true, |health, ok| health.live = ok);
        let ready = watch_one(at, readiness, &tx, &shared.changed, false, |health, ok| {
            health.ready = ok
        });
        tokio::join!(live, ready);
    });
    Some(Probes { health, task })
}

/// `after_first`: failures count only once the probe has passed.
async fn watch_one(
    at: Option<(&Shared, &str)>,
    check: Option<Check>,
    tx: &watch::Sender<Health>,
    poke: &Notify,
    after_first: bool,
    set: fn(&mut Health, bool),
) {
    let Some(check) = check else {
        return;
    };
    let (mut failures, mut passed_once) = (0, false);
    loop {
        let ok = tokio::time::timeout(check.timeout, probe(at, &check))
            .await
            .unwrap_or(false);
        failures = if ok { 0 } else { failures + 1 };
        passed_once |= ok;
        // Up at the first success; down only after `threshold` failures in a row.
        if ok || (failures >= check.threshold && (passed_once || !after_first)) {
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

/// One attempt: can the port be connected to, and for http, is the answer 2xx or 3xx?
async fn probe(at: Option<(&Shared, &str)>, check: &Check) -> bool {
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

        let bad = container(serde_json::json!({
            "name": "web", "image": "x",
            "liveness": { "exec": ["true"] },
            "readiness": { "http": { "path": "/ok HTTP/1.0\r\nX: y", "port": "nope" } },
        }));
        assert_eq!(
            problems(&bad),
            [
                "web: liveness probe: exec probes are not run yet",
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
            every: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            threshold: 1,
        };
        assert!(probe(None, &check(port, None)).await);
        assert!(probe(None, &check(port, Some("/ok"))).await);
        assert!(!probe(None, &check(port, Some("/broken"))).await);
        // Nothing listens on port 1.
        assert!(!probe(None, &check(1, None)).await);
    }

    #[tokio::test]
    async fn liveness_waits_for_a_first_success() {
        // A port nothing listens on yet, then something does, then it is gone.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let check = Check {
            port,
            path: None,
            every: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            threshold: 1,
        };
        let (tx, mut health) = watch::channel(Health {
            live: true,
            ready: true,
        });
        let changed = Notify::new();
        let watching = watch_one(None, Some(check), &tx, &changed, true, |health, ok| health.live = ok);
        let story = async {
            tokio::time::sleep(Duration::from_millis(2500)).await;
            assert!(health.borrow().live, "killed while still starting");
            let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
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
}
