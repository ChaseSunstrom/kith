//! `kith machine create|list|run|rm`: a dev machine, made of what kith has already (T-1131's
//! guide recipe): a Workload of one replica that runs as you, and its home on a replicated
//! Volume. Nothing is new on kithd's side: the machine is a Workload `kith get` shows.

use super::{Backend, DEFAULT_NAMESPACE, Resource, fail, print_table, status_summary};
use clap::Subcommand;
use serde_json::{Value, json};
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;

pub(crate) mod shell;

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
    /// A shell in the running machine, on a terminal (or a command with `-- COMMAND`); its exit code is kith's
    Shell {
        name: String,
        /// Root of the machine's own user namespace: root there only, never the node's (refused where it would be)
        #[arg(long)]
        root: bool,
        #[arg(last = true, value_name = "COMMAND")]
        argv: Vec<String>,
    },
    /// Run a command in a fresh Job in a machine's image and home (`shell` goes into the running one)
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

/// Part of machine `name`: in the default namespace and labelled with it.
fn mine(r: &Resource, name: &str) -> bool {
    r.metadata.namespace.as_deref() == Some(DEFAULT_NAMESPACE)
        && r.metadata.labels.get(LABEL).map(String::as_str) == Some(name)
}

/// Does this Workload or Job mount the Volume `volume`?
fn mounts(r: &Resource, volume: &str) -> bool {
    let all = |v: &Value| v.as_array().into_iter().flatten().cloned().collect::<Vec<_>>();
    all(&r.spec["template"]["containers"])
        .iter()
        .any(|c| all(&c["volumeMounts"]).iter().any(|m| m["volume"] == volume))
}

/// The resource `key`, or None when the store or kithd says it is not there. Any other error
/// (a refusal, a timeout) stays one: what could not be read is not known to be absent.
fn lookup(backend: &Backend, key: &str) -> Result<Option<Resource>, String> {
    match backend.get(key) {
        Ok(r) => Ok(Some(r)),
        Err(e) if e.ends_with(" not found") => Ok(None),
        Err(e) => Err(e),
    }
}

/// The machine `name`: a Workload that is part of it.
fn find(backend: &Backend, name: &str) -> Result<Resource, String> {
    match lookup(backend, &key("Workload", name))? {
        Some(w) if mine(&w, name) => Ok(w),
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
            if replicas < 2 {
                return fail("--replicas: 2 or more (a machine's home is copied to another node)");
            }
            let new = resources(&name, &image(&distro)?, &user, uid, &node, replicas)?;
            // Never over another's resource, nor a changed machine: remove it, then create.
            for r in &new {
                if let Some(old) = lookup(&backend, &r.key())? {
                    if !mine(&old, &name) {
                        return fail(format!("{} exists and is not machine `{name}`'s", r.key()));
                    }
                    if old.spec != r.spec && r.kind == "Volume" {
                        return fail(format!(
                            "machine `{name}`'s home Volume {} exists with other settings: changing it needs `kith machine rm {name} --purge`, which deletes its data",
                            r.metadata.name
                        ));
                    }
                    if old.spec != r.spec {
                        return fail(format!(
                            "machine `{name}` exists with other settings (`kith machine rm {name}`, then create)"
                        ));
                    }
                }
            }
            for change in backend.apply(new, false)? {
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
                if mine(&w, &w.metadata.name) {
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
        Machine::Shell { name, root, argv } => return shell::shell(&backend, &name, root, argv),
        Machine::Run { name, argv } => {
            let machine = find(&backend, &name)?;
            let mut container = machine.spec["template"]["containers"][0].clone();
            container["name"] = json!("run");
            container["command"] = json!(argv);
            let job = format!(
                "{name}-run-{}",
                // Microseconds: 16 digits, so a 40-character name still fits a label of 63.
                std::time::UNIX_EPOCH.elapsed().map_or(0, |t| t.as_micros())
            );
            let job = make(json!({
                "apiVersion": "kith.dev/v1", "kind": "Job",
                "metadata": { "name": job, "labels": { LABEL: name } },
                "spec": { "retries": 0, "template": { "containers": [container] } },
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
            // Whatever of it is left (a first `rm` may have stopped midway, or kept the home).
            let volume = format!("{name}-home");
            let home = lookup(&backend, &key("Volume", &volume))?;
            let mut all = backend.list(Some("Workload"))?;
            all.extend(backend.list(Some("Job"))?);
            let ours: Vec<_> = all.iter().filter(|r| mine(r, &name)).collect();
            if purge && home.as_ref().is_some_and(|v| !mine(v, &name)) {
                return fail(format!("Volume {volume} is not machine `{name}`'s: it stays"));
            }
            let home = home.filter(|v| mine(v, &name));
            if ours.is_empty() && home.is_none() {
                return fail(format!("no machine `{name}` (`kith machine list`)"));
            }
            if purge && all.iter().any(|r| !mine(r, &name) && mounts(r, &volume)) {
                return fail(format!("another Workload or Job mounts {volume}: it stays"));
            }
            // The Workload first (they come first), so nothing runs on the Volume as it goes.
            for r in ours {
                backend.delete(&r.key())?;
            }
            if purge && home.is_some() {
                backend.delete(&key("Volume", &volume))?;
            }
            println!(
                "machine {name} deleted{}",
                if purge {
                    String::new()
                } else {
                    format!(
                        " (its home Volume {volume} stays; `kith machine rm {name} --purge` deletes it, data and all)"
                    )
                }
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
