//! `kith import`: Kubernetes manifests (and `helm template` output) as kith resources.
//!
//! Every field is taken out of the input as it is carried over, so what is left
//! at the end is exactly what was not: it goes in the report, by path.

use clap::Subcommand;
use kith_kube::{documents, translate};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

#[derive(Subcommand)]
pub enum Import {
    /// Print the kith resources Kubernetes manifests translate to; what could not be goes on stderr
    /// (exit 0: all of it translated, 1: something was left out, 2: unreadable input)
    K8s {
        /// YAML or JSON file, or `-` for stdin
        #[arg(short, long = "file", value_name = "PATH", required = true)]
        files: Vec<PathBuf>,
    },
    /// The same for a docker-compose file (`docker compose config` prints one with its variables filled in)
    Compose {
        /// A docker-compose.yml, or `-` for stdin
        file: PathBuf,
        #[arg(short, long)]
        namespace: Option<String>,
        /// The node that holds the volumes' directories
        #[arg(long)]
        node: Option<String>,
    },
    /// The same for containers made with `docker run`: what `docker inspect` says of them, run
    /// for the NAMEs, or saved (`docker inspect NAME... > FILE`, or piped to `-f -`). Each named
    /// volume gets a line on stderr that copies its files in once the resources are applied
    Docker {
        /// Containers, by name or id
        containers: Vec<String>,
        /// A saved `docker inspect` (JSON), or `-` for stdin, in place of NAMEs
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: Option<PathBuf>,
        #[arg(short, long)]
        namespace: Option<String>,
        /// The node that holds the volumes' directories
        #[arg(long)]
        node: Option<String>,
    },
    /// The same for a Helm chart, rendered by the installed `helm template`
    Helm {
        /// A chart directory, archive or `repo/chart`
        chart: String,
        /// The release's name [default: the chart's directory or name]
        #[arg(long)]
        name: Option<String>,
        #[arg(short, long)]
        namespace: Option<String>,
        /// A YAML file of values over the chart's defaults; later ones win
        #[arg(short = 'f', long = "values", value_name = "FILE")]
        values: Vec<PathBuf>,
    },
}

/// A file's name and text; `-` is stdin.
/// ponytail: files and stdin only; a directory is an error, not a walk.
fn read(file: &Path) -> Result<(String, String), String> {
    if file.as_os_str() == "-" {
        let mut src = String::new();
        std::io::stdin()
            .read_to_string(&mut src)
            .map_err(|e| format!("error: stdin: {e}"))?;
        return Ok(("<stdin>".to_string(), src));
    }
    let src = std::fs::read_to_string(file).map_err(|e| format!("error: {}: {e}", file.display()))?;
    Ok((file.display().to_string(), src))
}

pub fn run(what: Import) -> Result<ExitCode, String> {
    // The docker volumes a container mounts, and the Volumes kith names them.
    let mut named = Vec::new();
    let mut copy_into = "default".to_string();
    let (resources, report) = match what {
        Import::Docker {
            containers,
            file,
            namespace,
            node,
        } => {
            let (name, src) =
                match (&file, containers.is_empty()) {
                    (Some(file), true) => read(file)?,
                    (None, false) => ("docker inspect".to_string(), docker_inspect(&containers)?),
                    _ => return Err(
                        "error: name the containers to inspect, or give a saved `docker inspect` as -f FILE (not both)"
                            .into(),
                    ),
                };
            let (doc, volumes) =
                kith_kube::compose::from_docker(documents(&name, &src)?).map_err(|e| format!("error: {name}: {e}"))?;
            named = volumes;
            copy_into = namespace.clone().unwrap_or(copy_into);
            kith_kube::compose::translate(doc, namespace.as_deref(), node.as_deref())
        }
        Import::K8s { files } => {
            let mut objects = Vec::new();
            for file in files {
                let (name, src) = read(&file)?;
                objects.extend(documents(&name, &src)?);
            }
            translate(objects)
        }
        Import::Helm {
            chart,
            name,
            namespace,
            values,
        } => translate(documents("helm template", &helm(&chart, name, namespace, &values)?)?),
        Import::Compose { file, namespace, node } => {
            let (name, src) = read(&file)?;
            // kith's YAML has no anchors, aliases or merge keys, which compose files lean on.
            let docs = documents(&name, &src).map_err(|e| {
                if e.contains("not supported in kith YAML") {
                    format!("{e}\nerror: a compose file must be written out: `docker compose config` does")
                } else {
                    e
                }
            })?;
            // (More than one document is not one stack: nothing of it is dropped in silence.)
            let [doc] = <[_; 1]>::try_from(docs)
                .map_err(|docs| format!("error: {name}: {} documents in it: a compose file is one", docs.len()))?;
            kith_kube::compose::translate(doc, namespace.as_deref(), node.as_deref())
        }
    };
    let mut out = std::io::stdout();
    for (i, resource) in resources.iter().enumerate() {
        let separator = if i == 0 { "" } else { "---\n" };
        // A closed stdout (`| head`) ends the resources, not the report.
        if write!(out, "{separator}{}", resource.to_yaml()).is_err() {
            break;
        }
    }
    for line in &report {
        eprintln!("not translated: {line}");
    }
    // A volume that no Workload made here mounts (a refused mount, or a name two things make)
    // is not copied into: it would be a Volume nothing uses.
    let mounted = |kith: &str| {
        resources.iter().filter(|r| r.kind == "Workload").any(|r| {
            let containers = r.spec["template"]["containers"].as_array();
            containers.into_iter().flatten().any(|c| {
                let mounts = c["volumeMounts"].as_array();
                mounts.into_iter().flatten().any(|m| m["volume"] == kith)
            })
        })
    };
    for (docker, kith) in named.iter().filter(|(_, kith)| mounted(kith)) {
        // The line is one to paste into a shell, and a saved inspect is not trusted: docker's
        // own volume names are these characters, and a name of others gets no line.
        let plain = docker.starts_with(|c: char| c.is_ascii_alphanumeric())
            && docker.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
        if !plain {
            eprintln!("volume {kith}: its docker name has characters a docker volume's does not: copy it in by hand");
            continue;
        }
        eprintln!(
            "volume {kith}: once applied, copy the docker volume's files in: \
             docker run --rm -v {docker}:/v:ro busybox tar -C /v -c . | kith volume put {kith} - -n {copy_into}"
        );
    }
    eprintln!("{} resources, {} things not translated", resources.len(), report.len());
    Ok(ExitCode::from(u8::from(!report.is_empty())))
}

/// What `docker inspect` prints of the containers. No shell: the names go to docker as they are.
fn docker_inspect(names: &[String]) -> Result<String, String> {
    // A name that looks like a flag would be read by docker as one.
    if let Some(bad) = names.iter().find(|s| s.starts_with('-')) {
        return Err(format!("error: `{bad}` starts with `-`: it is not a container's name"));
    }
    let out = Command::new("docker")
        .args(["inspect", "--type", "container"])
        .args(names)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "error: docker is not installed: pipe `docker inspect NAME... | kith import docker -f -` from where it is"
                    .to_string()
            } else {
                format!("error: running docker: {e}")
            }
        })?;
    if !out.status.success() {
        return Err(format!("error: docker inspect failed ({})", out.status));
    }
    String::from_utf8(out.stdout).map_err(|_| "error: docker inspect printed text that is not UTF-8".to_string())
}

/// What `helm template` prints. No shell: the arguments go to helm as they are.
fn helm(chart: &str, name: Option<String>, namespace: Option<String>, values: &[PathBuf]) -> Result<String, String> {
    // ponytail: the release is named for the chart's last path component (of where `.`
    // is, too), made a name Helm takes; `--name` overrides.
    let name = name.unwrap_or_else(|| {
        let full = std::fs::canonicalize(chart).ok();
        let full = full.as_deref().and_then(|full| full.to_str()).unwrap_or(chart);
        let last = full.trim_end_matches('/').rsplit('/').next().unwrap_or(full);
        let plain = |c: char| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        };
        let name: String = last.strip_suffix(".tgz").unwrap_or(last).chars().map(plain).collect();
        name.trim_matches('-').to_string()
    });
    // A name or chart that looks like a flag would be read by helm as one.
    if let Some(bad) = [&name, chart].into_iter().find(|s| s.starts_with('-')) {
        return Err(format!("error: `{bad}` starts with `-`: write ./{bad} for a path"));
    }
    let mut cmd = Command::new("helm");
    cmd.args(["template", &name, chart]);
    if let Some(ns) = namespace {
        cmd.args(["--namespace", &ns]);
    }
    for file in values {
        cmd.arg("-f").arg(file);
    }
    let out = cmd
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "error: helm is not installed: install it, or pipe `helm template ... | kith import k8s -f -`"
                    .to_string()
            } else {
                format!("error: running helm: {e}")
            }
        })?;
    if !out.status.success() {
        return Err(format!("error: helm template failed ({})", out.status));
    }
    String::from_utf8(out.stdout).map_err(|_| "error: helm template printed text that is not UTF-8".to_string())
}
