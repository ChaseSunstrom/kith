//! `kith`: the command line for kith.
//!
//! Commands talk to kithd over its unix socket, or with `--store` work on a
//! store file directly (no daemon, nothing runs).

use clap::{Args, Parser, Subcommand, ValueEnum};
use kith_api::store::{self, Action, Change, FileStore, Revision, Store, rfc3339};
use kith_api::{DEFAULT_NAMESPACE, KINDS, Resource};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod import;
mod ui;

#[derive(Parser)]
#[command(
    name = "kith",
    version,
    about = "Configure a kith cluster through declarative resources"
)]
struct Cli {
    /// kithd's socket [default: $XDG_RUNTIME_DIR/kith/kithd.sock, or /run/kith/kithd.sock]
    #[arg(long, env = "KITH_SOCKET", global = true, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// Give up when kithd has not answered for this many seconds
    #[arg(
        long,
        env = "KITH_TIMEOUT",
        global = true,
        value_name = "SECONDS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    timeout: u64,
    /// Work on a store file directly instead of talking to kithd (wins over --socket)
    #[arg(long, env = "KITH_STORE", global = true, value_name = "FILE")]
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
        /// After the table, print each row that changes, until interrupted (needs kithd)
        #[arg(short, long)]
        watch: bool,
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
    /// Print the output of a Workload's, NodeWorkload's or Job's container or exec unit
    Logs {
        #[command(flatten)]
        target: Target,
        /// Which container or exec unit [default: the first]
        #[arg(short, long, value_name = "NAME")]
        unit: Option<String>,
        /// Which replica, or which run of a Job
        #[arg(long, default_value_t = 0)]
        replica: u32,
        /// Its error output instead
        #[arg(long)]
        stderr: bool,
        /// The output moved aside when the log reached its size cap
        #[arg(long)]
        previous: bool,
        /// Only the last LINES lines
        #[arg(long, value_name = "LINES")]
        tail: Option<u64>,
        /// Keep printing as output arrives, until the unit is done
        #[arg(short, long)]
        follow: bool,
    },
    /// Print the JSON Schema of a kind, or list the kinds
    Schema { kind: Option<String> },
    /// Manage the nodes of the cluster
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Identities: who may call the API over the network, as their Roles allow
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Show who changed what through this node, and who was refused
    Audit {
        /// How many of the last entries to show (1000 at most)
        #[arg(long, default_value_t = 100)]
        tail: u64,
    },
    /// Open kithd's web UI to a browser on this machine (prints the address)
    Ui {
        /// The loopback port to listen on; any free one when left out
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Controllers: WebAssembly modules kithd runs for a kind of your own
    Controller {
        #[command(subcommand)]
        command: ControllerCommand,
    },
    /// Work on a package: a directory of resource templates and default values
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
    /// Sources: what a cluster keeps synced from git or a registry
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    /// Translate Kubernetes manifests or a Helm chart into kith resources
    Import {
        #[command(subcommand)]
        command: import::Import,
    },
}

#[derive(Subcommand)]
enum ControllerCommand {
    /// Put WebAssembly modules in a kind's KindDefinition: its controller, its admission hook
    Set {
        /// The kind, as its KindDefinition names it
        kind: String,
        /// The module kithd runs for each resource of the kind (`kith_reconcile`)
        #[arg(long, value_name = "FILE")]
        controller: Option<PathBuf>,
        /// The module kithd asks before a resource of the kind is written (`kith_admit`)
        #[arg(long, value_name = "FILE")]
        admission: Option<PathBuf>,
    },
}

/// Bytes as base64, the way a KindDefinition carries a module.
fn base64(bytes: &[u8]) -> String {
    const LETTERS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for three in bytes.chunks(3) {
        let bits = three.iter().fold(0u32, |bits, byte| bits << 8 | u32::from(*byte)) << (8 * (3 - three.len()));
        for place in 0..4 {
            let letter = LETTERS[(bits >> (18 - 6 * place) & 63) as usize] as char;
            text.push(if place <= three.len() { letter } else { '=' });
        }
    }
    text
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Write a certificate and key for an Identity (made if it is not there) as NAME.crt,
    /// NAME.key and ca.crt; a certificate it had before stops working
    Cert {
        name: String,
        /// The directory to write them in
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum SourceCommand {
    /// Let a Source with `approval: manual` apply the revision that waits in its status
    Approve {
        name: String,
        #[arg(short, long)]
        namespace: Option<String>,
    },
    /// Put a directory's YAML and JSON files in a registry, for a Source to sync (`oci:`)
    Push {
        dir: PathBuf,
        /// Where: `oci://HOST/PATH/NAME[:TAG]`
        #[arg(long, value_name = "URL")]
        to: String,
    },
}

#[derive(Subcommand)]
enum PackageCommand {
    /// Print the resources a package renders to (and its notes, on stderr); nothing is applied
    Render {
        /// The package's directory
        dir: PathBuf,
        /// The release's name: what the resources are named for [default: the package's name]
        #[arg(long)]
        name: Option<String>,
        /// The namespace of resources that name none
        #[arg(short, long, default_value = "default")]
        namespace: String,
        /// A YAML file of values over the package's defaults; later ones win
        #[arg(short = 'f', long = "values", value_name = "FILE")]
        values: Vec<PathBuf>,
        /// One value over those: `replicas=3`, `expose.host=example.org`. Read as YAML,
        /// so quote text that looks like a number: `'tag="1.10"'`
        #[arg(long = "set", value_name = "KEY=VALUE")]
        set: Vec<String>,
    },
    /// Check a package: its files, its schema, and what it renders to with its default values
    Lint {
        /// The package's directory
        dir: PathBuf,
    },
    /// Put a package in the cluster, as the Package `NAME-VERSION`, for Releases to
    /// install; or, with --to, in a registry
    Push {
        /// The package's directory
        dir: PathBuf,
        /// The repository to put it in instead: `oci://HOST/PATH`
        #[arg(long, value_name = "URL")]
        to: Option<String>,
        /// Sign it with this key (from `kith package keygen`)
        #[arg(long, value_name = "FILE", requires = "to")]
        key: Option<PathBuf>,
    },
    /// Fetch a package from a registry into a directory
    Pull {
        /// The repository: `oci://HOST/PATH`
        from: String,
        name: String,
        version: String,
        /// The public key it must be signed with [default: taken unsigned or signed by anyone]
        #[arg(long, value_name = "HEX")]
        public_key: Option<String>,
        /// Where to put it [default: NAME-VERSION]
        #[arg(short, long, value_name = "DIR")]
        output: Option<PathBuf>,
    },
    /// Make a key to sign packages with: the secret into FILE, the public key printed
    Keygen { file: PathBuf },
}

/// `a.b=1` as values: `{a: {b: 1}}`. The value is read as YAML, and is text if it is none.
fn set_value(assignment: &str) -> Result<serde_json::Value, String> {
    let Some((path, value)) = assignment.split_once('=') else {
        return fail(format!("--set {assignment}: write KEY=VALUE"));
    };
    let value = kith_yaml::from_str(value).unwrap_or_else(|_| serde_json::Value::String(value.into()));
    let nest = |inside, key: &str| serde_json::json!({ key: inside });
    Ok(path.rsplit('.').fold(value, nest))
}

#[derive(Subcommand)]
enum NodeCommand {
    /// Print a token that lets one more node join, within the hour: `kithd --join ADDR:PORT --token TOKEN`
    Token,
    /// Say which node leads the store, which nodes vote, and how far this one has got
    Status,
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

/// Where the resources live: kithd behind its socket, or a store file used directly.
enum Backend {
    Daemon(Kithd),
    Local(PathBuf),
}

impl Backend {
    /// Local changes go through here: nothing is saved unless `change` succeeds.
    fn local<T>(
        path: &Path,
        write: bool,
        change: impl FnOnce(&mut Store) -> Result<T, store::Error>,
    ) -> Result<T, String> {
        // Commands that only look never create, lock or wait for the store.
        let mut file_store = if write {
            FileStore::open(path)
        } else {
            FileStore::read(path)
        }
        .or_else(fail)?;
        let value = change(&mut file_store.store).or_else(fail)?;
        if write {
            file_store.save().or_else(fail)?;
        }
        Ok(value)
    }

    /// All or nothing. A dry run reports the same changes and keeps none of them.
    fn apply(&self, resources: Vec<Resource>, dry_run: bool) -> Result<Vec<Change>, String> {
        match self {
            Backend::Local(path) => Self::local(path, !dry_run, |store| store.apply_all(resources)),
            Backend::Daemon(socket) => {
                let body = serde_json::to_vec(&resources).or_else(fail)?;
                let query = if dry_run { "?dryRun=true" } else { "" };
                request(socket, "POST", &format!("/v1/apply{query}"), &body)
            }
        }
    }

    /// Have kithd do something with a registry: `kith` itself speaks to none.
    fn registry<T: serde::de::DeserializeOwned>(&self, verb: &str, asked: &serde_json::Value) -> Result<T, String> {
        match self {
            Backend::Local(_) => fail("a registry is reached through kithd: not with --store"),
            Backend::Daemon(socket) => request(
                socket,
                "POST",
                &format!("/v1/packages/{verb}"),
                asked.to_string().as_bytes(),
            ),
        }
    }

    fn list(&self, kind: Option<&str>) -> Result<Vec<Resource>, String> {
        match self {
            Backend::Local(path) => Self::local(path, false, |store| Ok(store.list(kind).cloned().collect())),
            Backend::Daemon(socket) => {
                let query = kind.map(|k| format!("?kind={k}")).unwrap_or_default();
                request(socket, "GET", &format!("/v1/resources{query}"), b"")
            }
        }
    }

    fn get(&self, key: &str) -> Result<Resource, String> {
        match self {
            Backend::Local(path) => {
                let found = |store: &mut Store| store.get(key).cloned().ok_or(store::Error::NotFound(key.into()));
                Self::local(path, false, found)
            }
            Backend::Daemon(socket) => request(socket, "GET", &format!("/v1/resources/{}", escape(key)), b""),
        }
    }

    fn delete(&self, key: &str) -> Result<Resource, String> {
        match self {
            Backend::Local(path) => Self::local(path, true, |store| store.delete(key)),
            Backend::Daemon(socket) => request(socket, "DELETE", &format!("/v1/resources/{}", escape(key)), b""),
        }
    }

    fn history(&self, key: &str) -> Result<Vec<Revision>, String> {
        match self {
            Backend::Local(path) => Self::local(path, false, |store| store.history(key).map(<[Revision]>::to_vec)),
            Backend::Daemon(socket) => request(socket, "GET", &format!("/v1/history/{}", escape(key)), b""),
        }
    }

    fn rollback(&self, key: &str, to: u64) -> Result<Change, String> {
        match self {
            Backend::Local(path) => Self::local(path, true, |store| store.rollback(key, to)),
            Backend::Daemon(socket) => request(socket, "POST", &format!("/v1/rollback/{}?to={to}", escape(key)), b""),
        }
    }
}

struct Kithd {
    socket: PathBuf,
    /// How long it may stay silent.
    timeout: std::time::Duration,
}

/// Percent-encode a resource key for a URL path. Valid keys pass through unchanged.
fn escape(key: &str) -> String {
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"-._/".contains(&b);
    key.bytes()
        .map(|b| {
            if plain(b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// One HTTP request to kithd over its unix socket.
// ponytail: HTTP/1.1 by hand keeps an HTTP client and an async runtime out of the CLI
// (the size and RSS budgets). It relies on `Connection: close` and kithd never
// chunking these replies; swap in a client library when the API goes over the network.
fn request<T: serde::de::DeserializeOwned>(kithd: &Kithd, method: &str, path: &str, body: &[u8]) -> Result<T, String> {
    let socket = &kithd.socket;
    use std::io::Write;
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(|e| {
        let socket = socket.display();
        format!("error: cannot reach kithd at {socket}: {e}\nStart kithd, or work on a store file with --store FILE.")
    })?;
    // A kithd that accepts and then says nothing must not hang a script forever.
    let timeout = Some(kithd.timeout);
    let _ = stream.set_read_timeout(timeout).and(stream.set_write_timeout(timeout));
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: kithd\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut reply = Vec::new();
    let sent = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(body));
    // kithd may refuse a request before reading all of it (too large): its reply still explains why.
    let read = stream.read_to_end(&mut reply);
    let sent = if reply.is_empty() { sent } else { Ok(()) };
    sent.and(read).or_else(|e| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            let secs = kithd.timeout.as_secs();
            // A change that timed out may still have landed: say so rather than imply it did not.
            let maybe = if method == "GET" {
                ""
            } else {
                "; the change may still have been applied"
            };
            fail(format!(
                "kithd has not answered for {secs} s (--timeout sets how long to wait){maybe}"
            ))
        }
        _ => fail(format!("talking to kithd: {e}")),
    })?;

    let split = reply
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("error: kithd sent no reply")?;
    let head = String::from_utf8_lossy(&reply[..split]).to_ascii_lowercase();
    let body = &reply[split + 4..];
    if head.contains("transfer-encoding") {
        return fail("kithd sent a chunked reply, which this kith cannot read");
    }
    let ok = head.split(' ').nth(1).is_some_and(|status| status.starts_with('2'));
    if !ok {
        // API errors are `{"error": "..."}`; anything else (a malformed request) is plain text.
        let message = serde_json::from_slice::<serde_json::Value>(body).ok();
        let message = message.as_ref().and_then(|m| m["error"].as_str()).map(String::from);
        return fail(message.unwrap_or_else(|| String::from_utf8_lossy(body).into_owned()));
    }
    serde_json::from_slice(body).or_else(|e| fail(format!("reading kithd's reply: {e}")))
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let backend = || match (&cli.store, cli.socket.clone().or_else(kith_api::default_socket)) {
        (Some(path), _) => Ok(Backend::Local(path.clone())),
        (None, Some(socket)) => Ok(Backend::Daemon(Kithd {
            socket,
            timeout: std::time::Duration::from_secs(cli.timeout),
        })),
        (None, None) => fail("no kithd socket: set --socket, or --store for a store file"),
    };
    match cli.command {
        Command::Import { command } => return import::run(command),
        Command::Lint { files } => {
            let n = load(&files)?.len();
            println!("{n} resource{} ok", if n == 1 { "" } else { "s" });
        }
        Command::Diff { files } => {
            let mut counts = [0; 3];
            for change in backend()?.apply(load(&files)?, true)? {
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
            for change in backend()?.apply(load(&files)?, dry_run)? {
                let what = match change.action {
                    Action::Created => "created",
                    Action::Updated => "updated",
                    Action::Unchanged => "unchanged",
                };
                let revision = change.after.metadata.revision.unwrap_or(0);
                let dry = if dry_run { " (dry run)" } else { "" };
                println!("{} {what} (revision {revision}){dry}", change.after.key());
            }
        }
        Command::Get {
            target,
            name,
            namespace,
            output,
            watch,
        } => {
            let (kind_name, name) = match &target {
                Some(t) => match t.split_once('/') {
                    Some((kind, name)) => (Some(kind), Some(name.to_string())),
                    None => (Some(t.as_str()), name),
                },
                None => (None, None),
            };
            let info = kind_name.map(|name| Kind::find(name, &backend)).transpose()?;
            let single = name.is_some();
            if watch {
                let Backend::Daemon(kithd) = backend()? else {
                    return fail("-w needs kithd: it cannot watch a --store file");
                };
                if !matches!(output, Output::Table) {
                    return fail("-w prints a table: leave out -o");
                }
                let one = info
                    .as_ref()
                    .zip(name.as_deref())
                    .map(|(info, n)| info.key(n, namespace.as_deref()));
                let keep = |r: &Resource| match &one {
                    Some(one) => r.key() == *one,
                    None => namespace.is_none() || r.metadata.namespace == namespace,
                };
                return watch_get(&kithd, info.as_ref().map(|i| i.kind.as_str()), keep);
            }
            let found: Vec<Resource> = match (&info, name) {
                (Some(info), Some(name)) => vec![backend()?.get(&info.key(&name, namespace.as_deref()))?],
                (info, _) => {
                    let mut all = backend()?.list(info.as_ref().map(|i| i.kind.as_str()))?;
                    all.retain(|r| namespace.is_none() || r.metadata.namespace == namespace);
                    all
                }
            };
            match output {
                Output::Yaml => {
                    let docs: Vec<String> = found.iter().map(|r| r.to_yaml()).collect();
                    if !docs.is_empty() {
                        println!("{}", docs.join("---\n").trim_end());
                    }
                }
                // One named resource is an object; a listing is an array.
                Output::Json if single => println!("{}", serde_json::to_string_pretty(&found[0]).or_else(fail)?),
                Output::Json => println!("{}", serde_json::to_string_pretty(&found).or_else(fail)?),
                // A kind with columns of its own (a KindDefinition's) shows those.
                Output::Table if info.as_ref().is_some_and(|info| !info.columns.is_empty()) => {
                    let columns = &info.as_ref().expect("checked").columns;
                    let titles: Vec<String> = columns.iter().map(|(name, _)| name.to_uppercase()).collect();
                    let header = ["NAMESPACE", "NAME", "REVISION"]
                        .into_iter()
                        .chain(titles.iter().map(String::as_str));
                    let row = |r: &Resource| {
                        let whole = serde_json::to_value(r).unwrap_or_default();
                        let cell =
                            |(_, path): &(String, String)| match path.split('.').fold(&whole, |at, part| &at[part]) {
                                serde_json::Value::Null => String::new(),
                                serde_json::Value::String(text) => text.replace(char::is_control, ""),
                                other => other.to_string(),
                            };
                        let m = &r.metadata;
                        let own = [
                            m.namespace.clone().unwrap_or_default(),
                            m.name.clone(),
                            m.revision.unwrap_or(0).to_string(),
                        ];
                        own.into_iter().chain(columns.iter().map(cell)).collect()
                    };
                    print_rows(
                        &header.collect::<Vec<_>>(),
                        &found.iter().map(row).collect::<Vec<Vec<String>>>(),
                    );
                }
                Output::Table => {
                    let rows = found.iter().map(table_row);
                    print_table(["KIND", "NAMESPACE", "NAME", "REVISION", "STATUS"], rows.collect());
                }
            }
        }
        Command::Delete { target } => {
            let key = target.key(&backend)?;
            backend()?.delete(&key)?;
            println!("{key} deleted");
        }
        Command::Logs {
            target,
            unit,
            replica,
            stderr,
            previous,
            tail,
            follow,
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("logs are kept by kithd: leave out --store");
            };
            let mut path = format!("/v1/logs/{}?replica={replica}", escape(&target.key(&backend)?));
            for (flag, option) in [(stderr, "&stderr=true"), (previous, "&previous=true")] {
                path += if flag { option } else { "" };
            }
            if let Some(unit) = unit {
                path += &format!("&unit={}", escape(&unit));
            }
            let mut from = tail.map_or("&offset=0".into(), |lines| format!("&tail={lines}"));
            loop {
                let reply: serde_json::Value = request(&kithd, "GET", &format!("{path}{from}"), b"")?;
                let data = reply["data"].as_str().unwrap_or_default();
                {
                    use std::io::Write;
                    let mut out = std::io::stdout();
                    if out.write_all(data.as_bytes()).and_then(|()| out.flush()).is_err() {
                        break; // `kith logs | head`
                    }
                }
                from = format!("&offset={}", reply["next"].as_u64().unwrap_or(0));
                if data.is_empty() {
                    // Drained. Without -f that is all; with it, wait for more while more may come.
                    if !follow || reply["more"] != true {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
        Command::History { target } => {
            let history = backend()?.history(&target.key(&backend)?)?;
            let rows = history.iter().map(|r| {
                let m = &r.resource.metadata;
                [m.revision.unwrap_or(0).to_string(), rfc3339(r.at)]
            });
            print_table(["REVISION", "APPLIED"], rows.collect());
        }
        Command::Rollback { target, to } => {
            let key = target.key(&backend)?;
            let change = backend()?.rollback(&key, to)?;
            match change.action {
                Action::Unchanged => println!("{key} already matches revision {to}"),
                _ => println!(
                    "{key} rolled back to revision {to} (now revision {})",
                    change.after.metadata.revision.unwrap_or(0)
                ),
            }
        }
        Command::Node {
            command: NodeCommand::Token,
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("tokens are made by kithd: leave out --store");
            };
            let reply: serde_json::Value = request(&kithd, "POST", "/v1/tokens", b"")?;
            println!("{}", reply["token"].as_str().unwrap_or_default());
        }
        Command::Identity {
            command: IdentityCommand::Cert { name, out },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("certificates are made by kithd: leave out --store");
            };
            let made: serde_json::Value = request(&kithd, "POST", &format!("/v1/identities/{name}/certificate"), b"")?;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            for (file, part) in [
                (format!("{name}.key"), "key"),
                (format!("{name}.crt"), "cert"),
                ("ca.crt".into(), "ca"),
            ] {
                let path = out.join(file);
                // (The mode is for the key; it does the others no harm.)
                let mut options = std::fs::OpenOptions::new();
                let opened = options.write(true).create(true).truncate(true).mode(0o600).open(&path);
                let text = made[part].as_str().unwrap_or_default();
                let written = opened.and_then(|mut file| file.write_all(text.as_bytes()));
                written.map_err(|e| format!("error: writing {}: {e}", path.display()))?;
            }
            let out = out.display();
            println!(
                "Identity/{name} can call the API with {out}/{name}.crt and {out}/{name}.key (nodes show {out}/ca.crt, as `kith`)"
            );
            println!("It may do what Roles bound to it allow: nothing, until a RoleBinding names it.");
        }
        Command::Controller {
            command:
                ControllerCommand::Set {
                    kind,
                    controller,
                    admission,
                },
        } => {
            if controller.is_none() && admission.is_none() {
                return fail("give --controller FILE, --admission FILE or both");
            }
            let backend = backend()?;
            let definitions = backend.list(Some("KindDefinition"))?;
            let named = |definition: &Resource| {
                definition.spec["kind"]
                    .as_str()
                    .is_some_and(|k| k.eq_ignore_ascii_case(&kind))
            };
            let Some(mut definition) = definitions.into_iter().find(named) else {
                return fail(format!("no KindDefinition makes a kind `{kind}`"));
            };
            let mut said = Vec::new();
            for (role, file) in [("controller", controller), ("admission", admission)] {
                let Some(file) = file else { continue };
                let module = std::fs::read(&file).map_err(|e| format!("error: reading {}: {e}", file.display()))?;
                definition.spec[role] = serde_json::json!({ "wasm": base64(&module) });
                said.push(format!(
                    "{}: {role} is {} ({} bytes)",
                    definition.key(),
                    file.display(),
                    module.len()
                ));
            }
            definition.status = None;
            backend.apply(vec![definition], false)?;
            println!("{}", said.join("\n"));
        }
        Command::Ui { port } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("the web UI is kithd's: leave out --store");
            };
            ui::serve(&kithd.socket, port)?;
        }
        Command::Audit { tail } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("the audit log is kithd's: leave out --store");
            };
            let entries: Vec<serde_json::Value> = request(&kithd, "GET", &format!("/v1/audit?tail={tail}"), b"")?;
            let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_string();
            let rows = entries.iter().map(|entry| {
                let what = entry["what"].as_array().into_iter().flatten().map(text);
                let outcome = if entry["ok"] == true {
                    "ok".into()
                } else {
                    text(&entry["error"])
                };
                let at = rfc3339(entry["at"].as_u64().unwrap_or(0));
                [
                    at,
                    text(&entry["who"]),
                    text(&entry["verb"]),
                    what.collect::<Vec<_>>().join(" "),
                    outcome,
                ]
            });
            print_table(["WHEN", "WHO", "DID", "WHAT", "OUTCOME"], rows.collect());
        }
        Command::Node {
            command: NodeCommand::Status,
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("only kithd knows: leave out --store");
            };
            let reply: serde_json::Value = request(&kithd, "GET", "/v1/cluster", b"")?;
            let names = |value: &serde_json::Value| {
                let names = value.as_array().into_iter().flatten().filter_map(|name| name.as_str());
                names.collect::<Vec<_>>().join(", ")
            };
            println!("leader:    {}", reply["leader"].as_str().unwrap_or("none"));
            println!("voters:    {}", names(&reply["voters"]));
            println!("receiving: {}", names(&reply["learners"]));
            println!(
                "this node: {}, change {}",
                reply["node"].as_str().unwrap_or_default(),
                reply["applied"]
            );
            for peer in reply["mesh"].as_array().into_iter().flatten() {
                let shook = match peer["handshake"].as_u64() {
                    Some(ago) => format!("handshake {ago} s ago"),
                    None => "no handshake yet".into(),
                };
                let how = if peer["relayed"] == true {
                    ", through an edge node"
                } else {
                    ""
                };
                let (node, address) = (peer["node"].as_str(), peer["address"].as_str());
                println!(
                    "mesh:      {} at {}, {shook}{how}",
                    node.unwrap_or_default(),
                    address.unwrap_or_default()
                );
            }
        }
        Command::Package {
            command:
                PackageCommand::Render {
                    dir,
                    name,
                    namespace,
                    values,
                    set,
                },
        } => {
            let package = kith_packages::Package::load(&dir).or_else(fail)?;
            let mut layers = Vec::new();
            for path in &values {
                let source = std::fs::read_to_string(path).or_else(|e| fail(format!("{}: {e}", path.display())))?;
                let layer = kith_yaml::from_str(&source).map_err(|e| e.render(&path.display().to_string(), &source))?;
                layers.push(layer);
            }
            for assignment in &set {
                layers.push(set_value(assignment)?);
            }
            let release = kith_packages::Release {
                name: name.as_deref().unwrap_or(&package.meta.name),
                namespace: &namespace,
            };
            let rendered = package.render(release, &layers).or_else(fail)?;
            let documents: Vec<String> = rendered.resources.iter().map(kith_api::Resource::to_yaml).collect();
            print!("{}", documents.join("---\n"));
            if let Some(notes) = rendered.notes {
                eprintln!("{}", notes.trim_end());
            }
        }
        Command::Package {
            command: PackageCommand::Lint { dir },
        } => {
            let package = kith_packages::Package::load(&dir).or_else(fail)?;
            let wrong = package.lint();
            if !wrong.is_empty() {
                return fail(wrong.join("\n"));
            }
            println!("{} {} ok", package.meta.name, package.meta.version);
        }
        Command::Package {
            command: PackageCommand::Push { dir, to, key },
        } => {
            let package = kith_packages::Package::load(&dir).or_else(fail)?;
            let wrong = package.lint();
            if !wrong.is_empty() {
                return fail(wrong.join("\n"));
            }
            if let Some(to) = to {
                let signature = match key {
                    None => None,
                    Some(key) => {
                        let secret =
                            std::fs::read_to_string(&key).or_else(|e| fail(format!("{}: {e}", key.display())))?;
                        Some(package.sign(&secret).or_else(fail)?)
                    }
                };
                let asked = serde_json::json!({ "to": to, "files": package.files, "signature": signature });
                let pushed: String = backend()?.registry("push", &asked)?;
                let signed = if signature.is_some() { "signed" } else { "not signed" };
                println!("{pushed} pushed ({signed})");
                return Ok(ExitCode::SUCCESS);
            }
            for change in backend()?.apply(vec![package.resource().or_else(fail)?], false)? {
                let what = match change.action {
                    Action::Created => "created",
                    Action::Updated => "updated",
                    Action::Unchanged => "unchanged",
                };
                println!("{} {what}", change.after.key());
            }
        }
        Command::Package {
            command:
                PackageCommand::Pull {
                    from,
                    name,
                    version,
                    public_key,
                    output,
                },
        } => {
            let asked = serde_json::json!({ "from": from, "name": name, "version": version, "publicKey": public_key });
            let files: std::collections::BTreeMap<String, String> = backend()?.registry("pull", &asked)?;
            // (Checked here too: what is written is what this kith takes for a package.)
            let package = kith_packages::Package::from_files(files).or_else(fail)?;
            let dir = output.unwrap_or_else(|| PathBuf::from(format!("{name}-{version}")));
            let wrote = |path: &std::path::Path, done: std::io::Result<()>| {
                done.or_else(|e| fail(format!("{}: {e}", path.display())))
            };
            // (Never into a directory that is there: nothing of anyone's is written over.)
            wrote(&dir, std::fs::create_dir(&dir))?;
            for (path, text) in &package.files {
                let path = dir.join(path);
                let parent = path.parent().unwrap_or(&dir);
                wrote(parent, std::fs::create_dir_all(parent))?;
                wrote(&path, std::fs::write(&path, text))?;
            }
            let checked = if public_key.is_some() {
                "signature checked"
            } else {
                "signature not checked"
            };
            println!(
                "{} {} in {} ({checked})",
                package.meta.name,
                package.meta.version,
                dir.display()
            );
        }
        Command::Package {
            command: PackageCommand::Keygen { file },
        } => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let (secret, public) = kith_packages::artifact::keygen().or_else(fail)?;
            // (A new file only its owner reads: a key is not written over, nor left open.)
            let made = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&file);
            let written = made.and_then(|mut made| writeln!(made, "{secret}"));
            written.or_else(|e| fail(format!("{}: {e}", file.display())))?;
            println!("{public}");
        }
        Command::Source {
            command: SourceCommand::Approve { name, namespace },
        } => {
            let backend = backend()?;
            let mut source = backend.get(&format!(
                "Source/{}/{name}",
                namespace.as_deref().unwrap_or(DEFAULT_NAMESPACE)
            ))?;
            let pending = source
                .status
                .as_ref()
                .and_then(|status| status["pending"]["revision"].as_str());
            let Some(revision) = pending.map(str::to_string) else {
                return fail(format!("{} has nothing waiting to be approved", source.key()));
            };
            source.spec["approve"] = serde_json::json!(revision);
            (source.metadata.revision, source.status) = (None, None);
            backend.apply(vec![source.validated().or_else(fail)?], false)?;
            println!("{name}: revision {revision} approved");
        }
        Command::Source {
            command: SourceCommand::Push { dir, to },
        } => {
            // (Files themselves, not links: nothing from elsewhere on this machine goes out.)
            fn read(
                dir: &std::path::Path,
                under: &str,
                files: &mut std::collections::BTreeMap<String, String>,
            ) -> std::io::Result<()> {
                for entry in std::fs::read_dir(dir)? {
                    let entry = entry?;
                    let name = format!("{under}{}", entry.file_name().to_string_lossy());
                    let kind = entry.file_type()?;
                    if kind.is_dir() {
                        read(&entry.path(), &format!("{name}/"), files)?;
                    } else if kind.is_file() && [".yaml", ".yml", ".json"].iter().any(|suffix| name.ends_with(suffix)) {
                        files.insert(name, std::fs::read_to_string(entry.path())?);
                    }
                }
                Ok(())
            }
            let mut files = std::collections::BTreeMap::new();
            read(&dir, "", &mut files).or_else(|e| fail(format!("{}: {e}", dir.display())))?;
            let Some((url, name)) = to.rsplit_once('/') else {
                return fail("--to is oci://HOST/PATH/NAME[:TAG]");
            };
            let (name, tag) = name.split_once(':').unwrap_or((name, "latest"));
            let count = files.len();
            let asked = serde_json::json!({ "to": url, "files": files, "source": [name, tag] });
            let pushed: String = backend()?.registry("push", &asked)?;
            println!("{pushed} pushed ({count} files)");
        }
        Command::Schema { kind: None } => {
            let rows = KINDS
                .iter()
                .map(|k| [k.kind, if k.namespaced { "namespaced" } else { "cluster" }, k.about].map(String::from));
            // (And the kinds the cluster's KindDefinitions make, when there is a cluster to ask.)
            let defined = backend()
                .and_then(|backend| backend.list(Some("KindDefinition")))
                .unwrap_or_default();
            let made = defined.iter().map(|d| {
                let text = |field: &str| d.spec[field].as_str().unwrap_or_default().replace(char::is_control, "");
                let scope = if d.spec["namespaced"] == false {
                    "cluster"
                } else {
                    "namespaced"
                };
                [
                    text("kind"),
                    scope.into(),
                    format!("{}/{} ({})", text("group"), text("version"), d.key()),
                ]
            });
            print_table(["KIND", "SCOPE", "ABOUT"], rows.chain(made).collect());
        }
        Command::Schema { kind: Some(name) } => {
            let schema = match kith_api::kind(&name) {
                Some(own) => own.schema(),
                None => Kind::find(&name, &backend)?.schema,
            };
            println!("{}", serde_json::to_string_pretty(&schema).or_else(fail)?);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn table_row(r: &Resource) -> [String; 5] {
    let m = &r.metadata;
    [
        r.kind.clone(),
        m.namespace.clone().unwrap_or_default(),
        m.name.clone(),
        m.revision.unwrap_or(0).to_string(),
        status_summary(r),
    ]
}

/// `kith get -w`: the table, then each row that changes (a deleted one says so),
/// by long-polling `GET /v1/watch` until interrupted or kithd goes away.
fn watch_get(kithd: &Kithd, kind: Option<&str>, keep: impl Fn(&Resource) -> bool) -> Result<ExitCode, String> {
    #[derive(serde::Deserialize)]
    struct Watched {
        generation: u64,
        resources: Vec<Resource>,
    }
    // The reply must come back before --timeout, or every quiet minute would be an error.
    let wait = kithd.timeout.as_secs().saturating_sub(1).min(25);
    let kind = kind.map(|k| format!("&kind={k}")).unwrap_or_default();
    let mut shown = std::collections::BTreeMap::new();
    let mut after = None;
    loop {
        let path = match after {
            None => format!("/v1/watch?wait=0{kind}"),
            Some(g) => format!("/v1/watch?after={g}&wait={wait}{kind}"),
        };
        let now: Watched = match request(kithd, "GET", &path, b"") {
            Ok(now) => now,
            // A kithd too busy to answer in time has not changed anything we would miss: ask again.
            Err(e) if after.is_some() && e.contains("has not answered") => continue,
            Err(e) if after.is_some() && (e.contains("cannot reach kithd") || e.contains("sent no reply")) => {
                return fail("kithd stopped");
            }
            Err(e) => return Err(e),
        };
        let rows: std::collections::BTreeMap<String, [String; 5]> = now
            .resources
            .iter()
            .filter(|r| keep(r))
            .map(|r| (r.key(), table_row(r)))
            .collect();
        if after.is_none() {
            print_table(
                ["KIND", "NAMESPACE", "NAME", "REVISION", "STATUS"],
                rows.values().cloned().collect(),
            );
        } else {
            // ponytail: changed rows are not aligned with the first table's columns
            for (key, row) in &rows {
                if shown.get(key) != Some(row) {
                    println!("{}", row.join("  ").trim_end());
                }
            }
            for (key, row) in &shown {
                if !rows.contains_key(key) {
                    println!("{}", [&row[0], &row[1], &row[2], "", "deleted"].join("  "));
                }
            }
        }
        shown = rows;
        if after == Some(now.generation) && wait == 0 {
            // --timeout 1: kithd answers at once, so do not spin.
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        after = Some(now.generation);
    }
}

/// The STATUS column: what a controller reported, in a few words.
fn status_summary(resource: &Resource) -> String {
    let Some(status) = &resource.status else {
        return String::new();
    };
    // First line only, and nothing that could drive the terminal: messages quote image names and output.
    let clean = |m: &str| m.lines().next().unwrap_or_default().replace(char::is_control, "");
    match (status["ready"].as_u64(), status["replicas"].as_u64()) {
        (Some(ready), Some(replicas)) => {
            // Why it is not ready, if a container said so.
            let containers = status["containers"].as_array().into_iter().flatten();
            let why = containers.filter_map(|c| c["message"].as_str()).next();
            let why = why.map(|m| format!(": {}", clean(m))).unwrap_or_default();
            format!("{ready}/{replicas} ready{why}")
        }
        // A Job or a DNS record; a Node: its state and where it is.
        _ => match (
            status["state"].as_str(),
            status["message"].as_str(),
            status["address"].as_str(),
        ) {
            (Some(state), Some(why), _) if state != "succeeded" => format!("{state}: {}", clean(why)),
            (Some(state), _, Some(address)) => format!("{state} at {}", clean(address)),
            (Some(state), ..) | (None, _, Some(state)) => clean(state),
            _ => String::new(),
        },
    }
}

/// A kind as a command needs it: one of kith's own, or one a KindDefinition in the
/// cluster makes.
struct Kind {
    kind: String,
    namespaced: bool,
    /// The columns `kith get` shows for it (name, dotted path), when it says.
    columns: Vec<(String, String)>,
    /// The schema of its spec (a made kind's only: kith's own have a whole one).
    schema: serde_json::Value,
}

impl Kind {
    /// The kind called `name`, in any case; the cluster is asked only when it is not kith's own.
    fn find(name: &str, backend: &dyn Fn() -> Result<Backend, String>) -> Result<Kind, String> {
        if let Some(own) = kith_api::kind(name) {
            return Ok(Kind {
                kind: own.kind.into(),
                namespaced: own.namespaced,
                columns: Vec::new(),
                schema: serde_json::Value::Null,
            });
        }
        let unknown = |why: &str| {
            fail(format!(
                "error: unknown kind `{name}` (`kith schema` lists the kinds{why})"
            ))
        };
        let defined = match backend().and_then(|backend| backend.list(Some("KindDefinition"))) {
            Ok(defined) => defined,
            Err(e) => return unknown(&format!("; the cluster's own could not be asked for: {e}")),
        };
        let made = |d: &&Resource| {
            d.spec["kind"]
                .as_str()
                .is_some_and(|kind| kind.eq_ignore_ascii_case(name))
        };
        let Some(definition) = defined.iter().find(made) else {
            return unknown("");
        };
        let columns = definition.spec["columns"].as_array().into_iter().flatten();
        let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().replace(char::is_control, "");
        Ok(Kind {
            kind: text(&definition.spec["kind"]),
            namespaced: definition.spec["namespaced"] != false,
            columns: columns
                .map(|column| (text(&column["name"]), text(&column["path"])))
                .collect(),
            schema: definition.spec["schema"].clone(),
        })
    }

    fn key(&self, name: &str, namespace: Option<&str>) -> String {
        match self.namespaced {
            true => format!("{}/{}/{name}", self.kind, namespace.unwrap_or(DEFAULT_NAMESPACE)),
            false => format!("{}/{name}", self.kind),
        }
    }
}

impl Target {
    fn key(&self, backend: &dyn Fn() -> Result<Backend, String>) -> Result<String, String> {
        let (kind, name) = match (self.target.split_once('/'), &self.name) {
            (Some((kind, name)), None) => (kind, name),
            (None, Some(name)) => (self.target.as_str(), name.as_str()),
            _ => return fail("name the resource as KIND/NAME or KIND NAME"),
        };
        Ok(Kind::find(kind, backend)?.key(name, self.namespace.as_deref()))
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
    print_rows(&header, &rows.into_iter().map(Vec::from).collect::<Vec<_>>());
}

fn print_rows(header: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = header.iter().map(|title| title.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let cols: Vec<String> = cells.iter().zip(&widths).map(|(c, w)| format!("{c:<w$}")).collect();
        println!("{}", cols.join("  ").trim_end());
    };
    line(header.to_vec());
    for row in rows {
        line(row.iter().map(String::as_str).collect());
    }
}
