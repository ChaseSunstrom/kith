//! `kith`: the command line for kith.
//!
//! Phase 0 works on a local store file. Once kithd serves the API (Phase 1),
//! the same commands talk to it instead.

use clap::{Args, Parser, Subcommand, ValueEnum};
use kith_api::store::{Action, FileStore, rfc3339};
use kith_api::{DEFAULT_NAMESPACE, KINDS, Resource};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "kith",
    version,
    about = "Configure a kith cluster through declarative resources"
)]
struct Cli {
    /// Local store file [default: $XDG_DATA_HOME/kith/store.json]
    #[arg(long, env = "KITH_STORE", global = true, value_name = "PATH")]
    store: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create or update resources from files
    Apply {
        #[command(flatten)]
        files: Files,
        /// Show what would happen without changing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Show what `apply` would change; exits 1 if there are changes
    Diff {
        #[command(flatten)]
        files: Files,
    },
    /// Check files without touching the store
    Lint {
        #[command(flatten)]
        files: Files,
    },
    /// List resources, or show one
    Get {
        /// KIND or KIND/NAME; everything when omitted
        target: Option<String>,
        name: Option<String>,
        #[arg(short, long)]
        namespace: Option<String>,
        #[arg(short, long, value_enum, default_value = "table")]
        output: Output,
    },
    /// Delete a resource and its history
    Delete {
        #[command(flatten)]
        target: Target,
    },
    /// List the revisions of a resource
    History {
        #[command(flatten)]
        target: Target,
    },
    /// Re-apply an earlier revision
    Rollback {
        #[command(flatten)]
        target: Target,
        /// Revision to go back to, from `kith history`
        #[arg(long, value_name = "REVISION")]
        to: u64,
    },
    /// Print the JSON Schema of a kind, or list the kinds
    Schema { kind: Option<String> },
}

#[derive(Args)]
struct Files {
    /// YAML or JSON file, a directory of them, or `-` for stdin
    #[arg(short, long = "file", value_name = "PATH", required = true)]
    files: Vec<PathBuf>,
}

#[derive(Args)]
struct Target {
    /// KIND/NAME, or KIND followed by NAME
    target: String,
    name: Option<String>,
    #[arg(short, long)]
    namespace: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Table,
    Yaml,
    Json,
}

/// `println!` panics when stdout is closed (`kith get | head`); stop quietly instead.
macro_rules! println {
    ($($arg:tt)*) => {{
        use std::io::Write;
        if writeln!(std::io::stdout(), $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

fn main() -> ExitCode {
    let code = match run(Cli::parse()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
    };
    // For ci/budgets.py: a parent can't measure this from outside, because the
    // rusage it gets back includes its own pre-exec memory.
    if std::env::var_os("KITH_PRINT_PEAK_RSS").is_some() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        if let Some(line) = status.lines().find(|l| l.starts_with("VmHWM:")) {
            eprintln!("{line}");
        }
    }
    code
}

fn fail<T>(e: impl std::fmt::Display) -> Result<T, String> {
    Err(format!("error: {e}"))
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let path = || {
        cli.store
            .clone()
            .or_else(default_store)
            .ok_or("error: no store path: set --store or $KITH_STORE")
    };
    // Commands that only look never create, lock or wait for the store.
    let read = || FileStore::read(&path()?).or_else(fail);
    let open = || FileStore::open(&path()?).or_else(fail);
    match cli.command {
        Command::Lint { files } => {
            let n = load(&files)?.len();
            println!("{n} resource{} ok", if n == 1 { "" } else { "s" });
        }
        Command::Diff { files } => {
            let resources = load(&files)?;
            let file_store = read()?;
            let mut counts = [0; 3];
            for resource in resources {
                let change = file_store.store.plan(resource).or_else(fail)?;
                counts[change.action as usize] += 1;
                let diff = change.diff();
                if !diff.is_empty() {
                    println!("{}", diff.trim_end_matches('\n'));
                }
            }
            eprintln!(
                "{} to create, {} to update, {} unchanged",
                counts[0], counts[1], counts[2]
            );
            return Ok(ExitCode::from(u8::from(counts[0] + counts[1] > 0)));
        }
        Command::Apply { files, dry_run } => {
            let resources = load(&files)?;
            let mut file_store = if dry_run { read()? } else { open()? };
            // Nothing is saved unless every resource applies.
            for resource in resources {
                let change = file_store.store.apply(resource).or_else(fail)?;
                let what = match change.action {
                    Action::Created => "created",
                    Action::Updated => "updated",
                    Action::Unchanged => "unchanged",
                };
                let revision = change.after.metadata.revision.unwrap_or(0);
                let dry = if dry_run { " (dry run)" } else { "" };
                println!("{} {what} (revision {revision}){dry}", change.after.key());
            }
            if !dry_run {
                file_store.save().or_else(fail)?;
            }
        }
        Command::Get {
            target,
            name,
            namespace,
            output,
        } => {
            let file_store = open()?;
            let store = &file_store.store;
            let (kind_name, name) = match &target {
                Some(t) => match t.split_once('/') {
                    Some((kind, name)) => (Some(kind), Some(name.to_string())),
                    None => (Some(t.as_str()), name),
                },
                None => (None, None),
            };
            let info = kind_name.map(find_kind).transpose()?;
            let single = name.is_some();
            let found: Vec<&Resource> = match (info, name) {
                (Some(info), Some(name)) => {
                    let key = key(info, &name, namespace.as_deref());
                    vec![store.get(&key).ok_or(format!("error: {key} not found"))?]
                }
                (info, _) => store
                    .list(info.map(|i| i.kind))
                    .filter(|r| namespace.is_none() || r.metadata.namespace == namespace)
                    .collect(),
            };
            match output {
                Output::Yaml => {
                    let docs: Vec<String> = found.iter().map(|r| r.to_yaml()).collect();
                    if !docs.is_empty() {
                        println!("{}", docs.join("---\n").trim_end());
                    }
                }
                // One named resource is an object; a listing is an array.
                Output::Json if single => println!("{}", serde_json::to_string_pretty(found[0]).or_else(fail)?),
                Output::Json => println!("{}", serde_json::to_string_pretty(&found).or_else(fail)?),
                Output::Table => {
                    let rows = found.iter().map(|r| {
                        let m = &r.metadata;
                        [
                            r.kind.clone(),
                            m.namespace.clone().unwrap_or_default(),
                            m.name.clone(),
                            m.revision.unwrap_or(0).to_string(),
                        ]
                    });
                    print_table(["KIND", "NAMESPACE", "NAME", "REVISION"], rows.collect());
                }
            }
        }
        Command::Delete { target } => {
            let key = target.key()?;
            let mut file_store = open()?;
            file_store.store.delete(&key).or_else(fail)?;
            file_store.save().or_else(fail)?;
            println!("{key} deleted");
        }
        Command::History { target } => {
            let key = target.key()?;
            let file_store = read()?;
            let rows = file_store.store.history(&key).or_else(fail)?.iter().map(|r| {
                let m = &r.resource.metadata;
                [m.revision.unwrap_or(0).to_string(), rfc3339(r.at)]
            });
            print_table(["REVISION", "APPLIED"], rows.collect());
        }
        Command::Rollback { target, to } => {
            let key = target.key()?;
            let mut file_store = open()?;
            let change = file_store.store.rollback(&key, to).or_else(fail)?;
            file_store.save().or_else(fail)?;
            match change.action {
                Action::Unchanged => println!("{key} already matches revision {to}"),
                _ => println!(
                    "{key} rolled back to revision {to} (now revision {})",
                    change.after.metadata.revision.unwrap_or(0)
                ),
            }
        }
        Command::Schema { kind: None } => {
            let rows = KINDS
                .iter()
                .map(|k| [k.kind, if k.namespaced { "namespaced" } else { "cluster" }, k.about].map(String::from));
            print_table(["KIND", "SCOPE", "ABOUT"], rows.collect());
        }
        Command::Schema { kind: Some(name) } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&find_kind(&name)?.schema()).or_else(fail)?
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn default_store() -> Option<PathBuf> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".local/share")))?;
    Some(data.join("kith/store.json"))
}

fn find_kind(name: &str) -> Result<&'static kith_api::KindInfo, String> {
    kith_api::kind(name).ok_or(format!("error: unknown kind `{name}` (`kith schema` lists the kinds)"))
}

fn key(info: &kith_api::KindInfo, name: &str, namespace: Option<&str>) -> String {
    match info.namespaced {
        true => format!("{}/{}/{name}", info.kind, namespace.unwrap_or(DEFAULT_NAMESPACE)),
        false => format!("{}/{name}", info.kind),
    }
}

impl Target {
    fn key(&self) -> Result<String, String> {
        let (kind, name) = match (self.target.split_once('/'), &self.name) {
            (Some((kind, name)), None) => (kind, name),
            (None, Some(name)) => (self.target.as_str(), name.as_str()),
            _ => return fail("name the resource as KIND/NAME or KIND NAME"),
        };
        Ok(key(find_kind(kind)?, name, self.namespace.as_deref()))
    }
}

/// Read and validate every document in the given files. All problems are
/// reported at once, each as `file:line:column: message`.
fn load(files: &Files) -> Result<Vec<Resource>, String> {
    let mut paths = Vec::new();
    for path in &files.files {
        if path.is_dir() {
            let entries = std::fs::read_dir(path).or_else(|e| fail(format!("{}: {e}", path.display())))?;
            let mut found: Vec<PathBuf> = entries
                .filter_map(|e| Some(e.ok()?.path()))
                .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml" | "json")))
                .collect();
            found.sort();
            paths.extend(found);
        } else {
            paths.push(path.clone());
        }
    }
    let (mut resources, mut errors) = (Vec::new(), Vec::new());
    for path in paths {
        let (name, src) = if path.as_os_str() == "-" {
            let mut src = String::new();
            std::io::stdin()
                .read_to_string(&mut src)
                .or_else(|e| fail(format!("stdin: {e}")))?;
            ("<stdin>".to_string(), src)
        } else {
            let src = std::fs::read_to_string(&path).or_else(|e| fail(format!("{}: {e}", path.display())))?;
            (path.display().to_string(), src)
        };
        match Resource::from_source(&src) {
            Err(e) => errors.push(e.render(&name, &src)),
            Ok(docs) => {
                for doc in docs {
                    match doc {
                        Ok(resource) => resources.push(resource),
                        Err(e) => errors.push(e.render(&name, &src)),
                    }
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(resources)
    } else {
        Err(errors.join("\n"))
    }
}

fn print_table<const N: usize>(header: [&str; N], rows: Vec<[String; N]>) {
    let mut widths = header.map(str::len);
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |cells: [&str; N]| {
        let cols: Vec<String> = cells.iter().zip(widths).map(|(c, w)| format!("{c:<w$}")).collect();
        println!("{}", cols.join("  ").trim_end());
    };
    line(header);
    for row in &rows {
        line(std::array::from_fn(|i| row[i].as_str()));
    }
}
