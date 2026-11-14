//! `kith import`: Kubernetes manifests (and `helm template` output) as kith resources.
//!
//! Every field is taken out of the input as it is carried over, so what is left
//! at the end is exactly what was not: it goes in the report, by path.

use clap::Subcommand;
use kith_kube::{documents, translate};
use std::io::{Read, Write};
use std::path::PathBuf;
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

pub fn run(what: Import) -> Result<ExitCode, String> {
    let objects = match what {
        Import::K8s { files } => {
            let mut objects = Vec::new();
            for file in files {
                // ponytail: files and stdin only; a directory is an error, not a walk.
                let (name, src) = if file.as_os_str() == "-" {
                    let mut src = String::new();
                    std::io::stdin()
                        .read_to_string(&mut src)
                        .map_err(|e| format!("error: stdin: {e}"))?;
                    ("<stdin>".to_string(), src)
                } else {
                    let src = std::fs::read_to_string(&file).map_err(|e| format!("error: {}: {e}", file.display()))?;
                    (file.display().to_string(), src)
                };
                objects.extend(documents(&name, &src)?);
            }
            objects
        }
        Import::Helm {
            chart,
            name,
            namespace,
            values,
        } => documents("helm template", &helm(&chart, name, namespace, &values)?)?,
    };
    let (resources, report) = translate(objects);
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
    eprintln!("{} resources, {} things not translated", resources.len(), report.len());
    Ok(ExitCode::from(u8::from(!report.is_empty())))
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
