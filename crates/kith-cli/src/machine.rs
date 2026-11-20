//! `kith machine create|list|run|rm`: a dev machine, made of what kith has already (T-1131's
//! guide recipe): a Workload of one replica that runs as you, and its home on a replicated
//! Volume. Nothing is new on kithd's side: the machine is a Workload `kith get` shows.

use super::{Backend, DEFAULT_NAMESPACE, Resource, fail, print_table, status_summary};
use clap::Subcommand;
use serde_json::{Value, json};
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;

const LABEL: &str = "kith.dev/machine";

#[derive(Subcommand)]
pub enum Machine {
    /// Make a machine that runs as you, with its home on a Volume copied to another node
    Create {
        /// One DNS label, 40 characters at most
        name: String,
        /// debian, alpine, ubuntu or an image reference
        #[arg(long, default_value = "debian")]
        distro: String,
        /// The node that holds its home first [default: the cluster's only node]
        #[arg(long)]
        node: Option<String>,
        /// Copies of its home in all; one takes over when the node is lost
        #[arg(long, default_value_t = 2)]
        replicas: u32,
    },
    /// List the machines
    List,
    /// Run a command in a machine's image and home, as a Job of its own (kith has no way into a running container)
    Run {
        name: String,
        #[arg(last = true, required = true, value_name = "COMMAND")]
        argv: Vec<String>,
    },
    /// Delete a machine and its Jobs; its home stays unless --purge
    Rm {
        name: String,
        /// Delete the home Volume too
        #[arg(long)]
        purge: bool,
    },
}

/// Who the machine runs as: the caller, by number, taken from the process and not from the
/// environment, and only if the home it names is theirs. Root and a stranger's home are refused.
fn caller() -> Result<(String, u32), String> {
    let uid = std::fs::metadata("/proc/self").or_else(fail)?.uid();
    if uid == 0 {
        return fail("a machine is never root: run kith as yourself");
    }
    let home = std::env::var_os("HOME").unwrap_or_default();
    if std::fs::metadata(&home).map(|m| m.uid()).ok() != Some(uid) {
        return fail(format!(
            "$HOME ({}) is not your home: a machine runs as the owner of one",
            home.to_string_lossy()
        ));
    }
    // The name goes into a path and a YAML text: a plain one or `dev`.
    let user = std::env::var("USER").ok().filter(|u| {
        (1..=32).contains(&u.len())
            && u.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
    });
    Ok((user.unwrap_or_else(|| "dev".into()), uid))
}

fn image(distro: &str) -> Result<String, String> {
    let library = |name: &str| format!("docker.io/library/{name}");
    match distro {
        "debian" => Ok(library("debian:stable-slim")),
        "ubuntu" => Ok(library("ubuntu:24.04")),
        "alpine" => Ok(library("alpine:3")),
        d if d.contains('/') => Ok(d.into()),
        d => fail(format!(
            "distro `{d}`: debian, alpine, ubuntu, or an image reference (REGISTRY/NAME:TAG)"
        )),
    }
}

fn make(value: Value) -> Result<Resource, String> {
    let resource: Resource = serde_json::from_value(value).or_else(fail)?;
    resource.submitted()?;
    resource.validated().or_else(fail)
}

/// The Volume and the Workload. Its one container sleeps (the machine is what a session or a
/// Job runs in), as the user and with the Volume as `/home/USER`.
fn resources(
    name: &str,
    image: &str,
    user: &str,
    uid: u32,
    node: &str,
    replicas: u32,
) -> Result<Vec<Resource>, String> {
    if name.len() > 40 {
        return fail("a machine's name is 40 characters at most");
    }
    let home = format!("/home/{user}");
    let volume = format!("{name}-home");
    let labels = json!({ LABEL: name });
    Ok(vec![
        make(json!({
            "apiVersion": "kith.dev/v1", "kind": "Volume",
            "metadata": { "name": volume, "labels": labels },
            "spec": { "node": node, "path": "home", "replicas": replicas, "sync": "10s" },
        }))?,
        make(json!({
            "apiVersion": "kith.dev/v1", "kind": "Workload",
            "metadata": { "name": name, "labels": labels },
            "spec": { "replicas": 1, "template": { "containers": [{
                "name": "machine", "image": image,
                "command": ["sleep", "1000000000"],
                "runAsUser": uid, "workingDir": home,
                "env": [{ "name": "HOME", "value": home }, { "name": "USER", "value": user }],
                "volumeMounts": [{ "volume": volume, "path": home }],
            }] } },
        }))?,
    ])
}

fn key(kind: &str, name: &str) -> String {
    format!("{kind}/{DEFAULT_NAMESPACE}/{name}")
}

/// The machine `name`: a Workload that carries the label.
fn find(backend: &Backend, name: &str) -> Result<Resource, String> {
    match backend.get(&key("Workload", name)) {
        Ok(w) if w.metadata.labels.get(LABEL).map(String::as_str) == Some(name) => Ok(w),
        _ => fail(format!("no machine `{name}` (`kith machine list`)")),
    }
}

pub fn run(command: Machine, backend: &dyn Fn() -> Result<Backend, String>) -> Result<ExitCode, String> {
    let backend = backend()?;
    match command {
        Machine::Create {
            name,
            distro,
            node,
            replicas,
        } => {
            let (user, uid) = caller()?;
            let node = match node {
                Some(node) => node,
                None => match &backend.list(Some("Node"))?[..] {
                    [only] => only.metadata.name.clone(),
                    _ => return fail("--node NODE: the node that holds its home first (`kith get node`)"),
                },
            };
            for change in backend.apply(resources(&name, &image(&distro)?, &user, uid, &node, replicas)?, false)? {
                println!(
                    "{} {}",
                    change.after.key(),
                    format!("{:?}", change.action).to_lowercase()
                );
            }
        }
        Machine::List => {
            let mut rows = vec![];
            for w in backend.list(Some("Workload"))? {
                if w.metadata.labels.contains_key(LABEL) {
                    let image = w.spec["template"]["containers"][0]["image"]
                        .as_str()
                        .unwrap_or_default();
                    rows.push([
                        w.metadata.name.clone(),
                        image.replace(char::is_control, ""),
                        status_summary(&w),
                    ]);
                }
            }
            print_table(["NAME", "IMAGE", "STATUS"], rows);
        }
        Machine::Run { name, argv } => {
            let machine = find(&backend, &name)?;
            let mut container = machine.spec["template"]["containers"][0].clone();
            container["name"] = json!("run");
            container["command"] = json!(argv);
            let job = format!(
                "{name}-run-{}",
                std::time::UNIX_EPOCH.elapsed().map_or(0, |t| t.as_secs())
            );
            let job = make(json!({
                "apiVersion": "kith.dev/v1", "kind": "Job",
                "metadata": { "name": job, "labels": { LABEL: name } },
                "spec": { "template": { "containers": [container] } },
            }))?;
            for change in backend.apply(vec![job], false)? {
                println!(
                    "{} (`kith logs job {} -f`)",
                    change.after.key(),
                    change.after.metadata.name
                );
            }
        }
        Machine::Rm { name, purge } => {
            find(&backend, &name)?;
            // The Workload first, so nothing starts another Job on the Volume; Jobs, then the Volume.
            backend.delete(&key("Workload", &name))?;
            for job in backend.list(Some("Job"))? {
                if job.metadata.labels.get(LABEL).map(String::as_str) == Some(&name) {
                    backend.delete(&job.key())?;
                }
            }
            if purge {
                backend.delete(&key("Volume", &format!("{name}-home")))?;
            }
            println!(
                "machine {name} deleted{}",
                if purge { "" } else { " (its home Volume stays: --purge)" }
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
