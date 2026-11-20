//! `kith launch` and `kith ps`: a one-off container without a file, and what is running.
//!
//! Both are the resources kith already has, made and read through the usual routes: a launch
//! is an apply of a Job (or, with `-d`, a Workload of one replica), and `ps` reads the
//! `status.containers` that kithd writes for every Workload, NodeWorkload and Job.

use super::{Backend, DEFAULT_NAMESPACE, Resource, escape, fail, print_table, stream_logs};
use clap::Args;
use serde_json::{Value, json};
use std::process::ExitCode;

#[derive(Args)]
pub struct Launch {
    /// The image to run
    image: String,
    #[arg(short, long, default_value = DEFAULT_NAMESPACE)]
    namespace: String,
    /// The resource's name [default: the image's name and the first number free]
    #[arg(long)]
    name: Option<String>,
    /// An environment variable of the container (repeat)
    #[arg(short, long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// A port the container listens on (repeat)
    #[arg(short, long = "port", value_name = "PORT")]
    port: Vec<u16>,
    /// A Workload of one replica, and return (without it: a Job, run in front, whose exit code this is)
    #[arg(short, long)]
    detach: bool,
    /// What to run in place of what the image runs, as written after `--`
    #[arg(last = true, value_name = "CMD")]
    command: Vec<String>,
}

#[derive(Args)]
pub struct Ps {
    /// Only this namespace
    #[arg(short, long, default_value = DEFAULT_NAMESPACE, conflicts_with = "all")]
    namespace: String,
    /// Every namespace
    #[arg(short = 'A', long)]
    all: bool,
}

/// The name an image gives: its last path part without a tag or a digest, as a DNS label.
fn base_name(image: &str) -> String {
    let last = image.rsplit('/').next().unwrap_or(image);
    let last = last.split(['@', ':']).next().unwrap_or(last);
    let mut name = String::new();
    for c in last.chars().flat_map(char::to_lowercase) {
        match c {
            'a'..='z' | '0'..='9' => name.push(c),
            _ if !name.ends_with('-') => name.push('-'),
            _ => {}
        }
    }
    let name: String = name.trim_matches('-').chars().take(50).collect();
    if name.is_empty() { "app".into() } else { name }
}

/// The resource a launch applies. `name` is final; the Job never retries and never restarts.
fn resource(l: &Launch, kind: &str, name: &str) -> Result<Resource, String> {
    let mut env = Vec::new();
    for pair in &l.env {
        match pair.split_once('=') {
            Some((key, value)) if !key.is_empty() => env.push(json!({ "name": key, "value": value })),
            _ => return fail(format!("-e {pair}: say it as KEY=VALUE")),
        }
    }
    let mut container = json!({ "name": "main", "image": l.image });
    if !l.command.is_empty() {
        container["command"] = json!(l.command);
    }
    if !env.is_empty() {
        container["env"] = json!(env);
    }
    if !l.port.is_empty() {
        container["ports"] = l.port.iter().map(|p| json!({ "port": p })).collect();
    }
    let spec = match kind {
        "Job" => json!({ "retries": 0, "template": { "containers": [container], "restartPolicy": "never" } }),
        _ => json!({ "replicas": 1, "template": { "containers": [container] } }),
    };
    let whole = json!({
        "apiVersion": "kith.dev/v1", "kind": kind,
        "metadata": { "name": name, "namespace": l.namespace },
        "spec": spec,
    });
    serde_json::from_value::<Resource>(whole)
        .or_else(fail)?
        .validated()
        .or_else(fail)
}

/// `NAME` if it was given and is free, or the first `BASE-N` that is.
fn free_name(backend: &Backend, kind: &str, l: &Launch) -> Result<String, String> {
    let taken: Vec<String> = backend
        .list(Some(kind))?
        .into_iter()
        .filter(|r| r.metadata.namespace.as_deref() == Some(l.namespace.as_str()))
        .map(|r| r.metadata.name)
        .collect();
    if let Some(name) = &l.name {
        return match taken.contains(name) {
            true => {
                let ns = if l.namespace == DEFAULT_NAMESPACE {
                    String::new()
                } else {
                    format!(" -n {}", l.namespace)
                };
                fail(format!(
                    "{kind}/{}/{name} is already there: pick another --name, or `kith delete {}/{name}{ns}` it",
                    l.namespace,
                    kind.to_lowercase()
                ))
            }
            false => Ok(name.clone()),
        };
    }
    let base = base_name(&l.image);
    // (The first number free: a rerun finds the earlier launch's Job and takes the next.)
    let number = (1..).find(|n| !taken.contains(&format!("{base}-{n}")));
    Ok(format!("{base}-{}", number.expect("an endless range")))
}

pub fn launch(l: Launch, backend: &Backend) -> Result<ExitCode, String> {
    if l.detach {
        let name = free_name(backend, "Workload", &l)?;
        for change in backend.apply(vec![resource(&l, "Workload", &name)?], false)? {
            println!("{} created: `kith ps -n {}` shows it", change.after.key(), l.namespace);
        }
        return Ok(ExitCode::SUCCESS);
    }
    // (Before anything is made: the output of a Job is kithd's to give.)
    let Backend::Daemon(kithd) = backend else {
        return fail("a launch in front follows kithd's logs: use -d, or leave out --store");
    };
    let name = free_name(backend, "Job", &l)?;
    let job = resource(&l, "Job", &name)?;
    let key = job.key();
    backend.apply(vec![job], false)?;
    let path = format!("/v1/logs/{}?replica=0&unit=main", escape(&key));
    if !stream_logs(kithd, &path, None, true, &mut std::io::stdout())? {
        eprintln!("{key} goes on: `kith logs {} -f` follows it", key.replacen('/', " ", 1));
        return Ok(ExitCode::SUCCESS);
    }
    // The logs end when the Job does (kithd says no more may come), so its state is final and
    // its stderr is whole: it is read after the output, not interleaved with it.
    // ponytail: a failed command's error comes after its output; interleave if that ever misleads.
    stream_logs(
        kithd,
        &format!("{path}&stderr=true"),
        None,
        false,
        &mut std::io::stderr(),
    )?;
    let status = backend.get(&key)?.status.unwrap_or_default();
    let code = job_code(&status);
    match (status["state"].as_str(), code) {
        (Some("failed"), code) => {
            if let Some(message) = status["message"].as_str() {
                eprintln!("{key} failed: {}", message.replace(char::is_control, " "));
            }
            // (A Job that failed without running has no code of its own.)
            Ok(ExitCode::from(code.filter(|c| *c != 0).map_or(1, |c| (c & 0xff) as u8)))
        }
        (_, Some(code)) => Ok(ExitCode::from((code & 0xff) as u8)),
        _ => Ok(ExitCode::SUCCESS),
    }
}

/// The exit code of a Job's run: a unit's own `exitCode` when kithd reports units, else the one
/// its message names. kithd clears a finished Job's `containers` and keeps the culprit in
/// `message`, as `run 0, main: exited with code 3` (crates/kithd/src/controller.rs, where
/// `job.message` is made): a change to that text shows here as an exit code of 1.
fn job_code(status: &Value) -> Option<i64> {
    let from_units = status["containers"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|u| u["exitCode"].as_i64());
    from_units.or_else(|| {
        let (_, tail) = status["message"].as_str()?.split_once("exited with code ")?;
        let digits: String = tail
            .chars()
            .enumerate()
            .take_while(|(i, c)| c.is_ascii_digit() || (*i == 0 && *c == '-'))
            .map(|(_, c)| c)
            .collect();
        digits.parse().ok()
    })
}

/// One row per unit of each Workload, NodeWorkload and Job: where it runs, its state, how it
/// ended, what it runs, and how long ago its resource was first applied.
pub fn ps(p: &Ps, backend: &Backend) -> Result<(), String> {
    let mut rows = Vec::new();
    for kind in ["Workload", "NodeWorkload", "Job"] {
        for r in backend.list(Some(kind))? {
            let namespace = r.metadata.namespace.clone().unwrap_or_default();
            if p.all || namespace == p.namespace {
                rows.extend(unit_rows(&r, backend));
            }
        }
    }
    print_table(
        [
            "NAMESPACE",
            "KIND",
            "NAME",
            "UNIT",
            "NODE",
            "STATE",
            "EXIT",
            "IMAGE/COMMAND",
            "AGE",
        ],
        rows,
    );
    Ok(())
}

/// Text from a status or a spec goes to a terminal: no control character gets through.
fn plain(text: &str) -> String {
    text.replace(char::is_control, "")
}

fn unit_rows(r: &Resource, backend: &Backend) -> Vec<[String; 9]> {
    let template = &r.spec["template"];
    // What a unit runs: a container's image, an exec unit's command, a machine's `vm`.
    let what = |name: &str| {
        let named = |list: &str| {
            template[list]
                .as_array()
                .into_iter()
                .flatten()
                .find(|u| u["name"] == name)
        };
        let image = named("containers")
            .or_else(|| named("initContainers"))
            .map(|c| c["image"].as_str());
        match (image, named("exec"), named("vms")) {
            (Some(image), ..) => image.unwrap_or_default().to_string(),
            (_, Some(exec), _) => exec["command"]
                .as_array()
                .map(|words| words.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "))
                .unwrap_or_default(),
            (_, _, Some(_)) => "vm".into(),
            _ => "-".into(),
        }
    };
    let status = r.status.clone().unwrap_or_default();
    let units = status["containers"].as_array().cloned().unwrap_or_default();
    let age = backend
        .history(&r.key())
        .ok()
        .and_then(|h| h.iter().map(|rev| rev.at).min())
        .map_or("-".into(), age);
    let text = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
    let cell = |v: &Value| if v.is_null() { "-".to_string() } else { plain(&text(v)) };
    let row = |name: String, unit: String, node: String, state: String, exit: String| {
        let (namespace, kind) = (r.metadata.namespace.clone().unwrap_or_default(), r.kind.to_lowercase());
        let what = what(&unit);
        [namespace, kind, name, unit, node, state, exit, what, age.clone()].map(|c| plain(&c))
    };
    if units.is_empty() {
        // (Applied and not yet reported: a launch is there to see at once.)
        let first = template["containers"][0]["name"].as_str().unwrap_or("-");
        let state = status["state"].as_str().unwrap_or("pending");
        // (A finished Job has no units: its code is the one in its message, or 0 if it succeeded.)
        let exit = job_code(&status).map(|c| c.to_string());
        let exit = exit.or_else(|| (state == "succeeded").then(|| "0".to_string()));
        return vec![row(
            r.metadata.name.clone(),
            first.into(),
            "-".into(),
            state.into(),
            exit.unwrap_or("-".into()),
        )];
    }
    units
        .iter()
        .map(|u| {
            let name = format!("{}-{}", r.metadata.name, u["replica"].as_u64().unwrap_or(0));
            row(
                name,
                cell(&u["name"]),
                cell(&u["node"]),
                cell(&u["state"]),
                cell(&u["exitCode"]),
            )
        })
        .collect()
}

/// Seconds since `since` as the one largest unit: `45s`, `3m`, `5h`, `2d`.
fn age(since: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let secs = now.saturating_sub(since);
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m", secs / 60),
        3600..86400 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_come_from_images() {
        for (image, name) in [
            ("alpine:3.20", "alpine"),
            ("ghcr.io/Org/My_App@sha256:abc", "my-app"),
            ("localhost:5000/web", "web"),
            (":::", "app"),
        ] {
            assert_eq!(base_name(image), name, "{image}");
        }
    }

    #[test]
    fn a_jobs_code_is_a_units_or_the_messages() {
        let code = |s: Value| job_code(&s);
        let said = json!({ "message": "run 0, main: exited with code 3", "containers": [] });
        assert_eq!(code(said), Some(3));
        let both = json!({ "message": "run 0, main: exited with code 3", "containers": [{ "exitCode": 7 }] });
        assert_eq!(code(both), Some(7));
        assert_eq!(code(json!({ "message": "run 1, main: exited with code -1" })), Some(-1));
        assert_eq!(code(json!({ "message": "not finished after 5 s" })), None);
        assert_eq!(code(json!({})), None);
    }
}
