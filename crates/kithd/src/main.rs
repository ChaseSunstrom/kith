//! `kithd`, in agent mode (PLAN.md §4.1): a service on an existing distro that
//! owns the store, serves the API and runs workloads on this one node.
//!
//! The API is HTTP/JSON on a unix socket only its owner can open. With
//! `--listen` it is also served to other nodes over TLS, and `--join` makes
//! this node a member of another node's cluster (see `cluster.rs`). The store is
//! a Raft replica either way (`raft.rs`): alone, this node is all of its voters.

mod access;
mod access_sign;
mod acme;
mod api;
mod audit;
mod backups;
mod blobs;
mod blocklist;
mod claims;
mod cluster;
mod controller;
mod controllers;
mod cron;
mod crypt;
mod devices;
mod dhcp;
mod dns;
mod encrypted;
mod exits;
mod files;
#[cfg(feature = "forge")]
mod forge;
mod gpt;
mod home;
mod images;
mod ingress;
mod init;
mod install;
mod keeper;
mod kube;
mod kubeproto;
mod levels;
mod members;
mod mesh;
mod modules;
mod netboot;
mod os;
mod own_writes;
mod people;
mod pki;
mod pods;
mod policy;
mod predict;
mod probe;
mod raft;
mod registry;
mod releases;
mod replicas;
mod root_part;
mod sched;
mod seats;
mod services;
mod share;
mod sources;
mod tpm;
mod ui;
mod update;
mod view;
mod vm;
mod volume_files;
mod volumes;
mod wasm;
mod websocket;
mod worker;
mod workload_identity;

use clap::Parser;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, watch};

/// A release key as an argument: an Ed25519 public key, 64 hex digits.
fn release_key(key: &str) -> Result<String, String> {
    let hex = key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit());
    hex.then(|| key.to_string())
        .ok_or("not a key: 64 hex digits, as `kith package keygen` prints".into())
}

#[derive(Parser)]
#[command(name = "kithd", version, about = "The kith node daemon")]
struct Args {
    /// Where the store, images and logs live [default: $XDG_STATE_HOME/kith, or /var/lib/kith as root]
    #[arg(long, env = "KITH_STATE", value_name = "DIR")]
    state: Option<PathBuf>,
    /// Socket to serve the API on [default: $XDG_RUNTIME_DIR/kith/kithd.sock]
    #[arg(long, env = "KITH_SOCKET", value_name = "PATH")]
    socket: Option<PathBuf>,
    /// Bytes of output kept per unit and stream before the file is moved aside (one old copy is kept)
    #[arg(long, env = "KITH_LOG_CAP", value_name = "BYTES", default_value_t = 10 << 20)]
    log_cap: u64,
    /// Bytes the state disk keeps free: under them the pod that wrote the most outside its volumes
    /// is replaced, one each count. 0 for none [default: 5% of the disk, at most 1 GiB, as root; 0 otherwise]
    #[arg(long, env = "KITH_STORAGE_RESERVE", value_name = "BYTES")]
    storage_reserve: Option<u64>,
    /// Seconds an image no unit on this node uses is kept before it is removed (sooner, oldest
    /// first, while the state disk is under its reserve); pulled again when a unit needs it. 0 keeps every image
    #[arg(long, env = "KITH_IMAGE_GRACE", value_name = "SECONDS", default_value_t = 86400)]
    image_grace: u64,
    /// The IPv4 network this node's pods get their addresses from (/8 to /24; refused if an address of this node, a LAN or a tailnet, is in it)
    #[arg(long, env = "KITH_POD_RANGE", value_name = "ADDR/BITS", default_value_t = kith_mesh::pod::Range::default())]
    pod_range: kith_mesh::pod::Range,
    /// Serve the API to other nodes on this address (TLS); the first start makes this node a cluster of one
    #[arg(long, env = "KITH_LISTEN", value_name = "ADDR:PORT")]
    listen: Option<std::net::SocketAddr>,
    /// Join the cluster of the node at this address (needs --token; listens on 0.0.0.0:7443, or [::]:7443 for a roaming or mesh-joined node, unless --listen says otherwise)
    #[arg(long, env = "KITH_JOIN", value_name = "ADDR:PORT", requires = "token")]
    join: Option<String>,
    /// A join token, from `kith node token` on a node of that cluster
    #[arg(long, env = "KITH_TOKEN", value_name = "TOKEN")]
    token: Option<String>,
    /// This node's name in the cluster [default: the hostname]
    #[arg(long, env = "KITH_NAME", value_name = "NAME")]
    name: Option<String>,
    /// The address other nodes reach this one at, when it is not the one it listens on (an IP address: a name is not looked up)
    #[arg(long, env = "KITH_ADVERTISE", value_name = "ADDR:PORT")]
    advertise: Option<std::net::SocketAddr>,
    /// While the cluster has no Identity, print a one-time token at start: whoever sends it to /v1/claim on --listen becomes its admin (for a node nobody can log in to)
    #[arg(long, env = "KITH_CLAIM")]
    claim: bool,
    /// Serve DNS here, on UDP and TCP: node names, DNSZone and DNSRecord resources, and the rest from upstream
    #[arg(long, env = "KITH_DNS", value_name = "ADDR:PORT")]
    dns: Option<std::net::SocketAddr>,
    /// Resolvers for names that are not ours, in the order tried [default: those in /etc/resolv.conf]
    #[arg(long, env = "KITH_DNS_UPSTREAM", value_name = "ADDR[:PORT]", value_delimiter = ',')]
    dns_upstream: Vec<String>,
    /// Take any node certificate of this cluster's CA, even one whose Node was deleted (for a cluster locked out of itself)
    #[arg(long, env = "KITH_ADMIT_DELETED_NODES")]
    admit_deleted_nodes: bool,
    /// Seconds a node may be out of contact before what it runs is started on other nodes
    #[arg(long, env = "KITH_LOST_AFTER", value_name = "SECONDS", default_value_t = 300)]
    lost_after: u64,
    /// Seconds between asking registries for newer packages (for Releases that name a Repository)
    #[arg(long, env = "KITH_REPOSITORY_POLL", value_name = "SECONDS", default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    repository_poll: u64,
    /// The port on 127.0.0.1 where this node serves the cluster's Images to itself, as a
    /// registry to pull from (0: not served)
    #[arg(long, env = "KITH_REGISTRY_PORT", value_name = "PORT", default_value_t = 5000)]
    registry_port: u16,
    /// A key (hex) this node takes kith OS releases from; repeat for more. Without one, those
    /// it keeps, or else those its system was built with (/etc/kith/release-keys); with none
    /// of those, the key of the first release it updates to is kept (said at every start)
    #[arg(long, env = "KITH_RELEASE_KEY", value_name = "KEY", value_delimiter = ',', value_parser = release_key)]
    release_key: Vec<String>,
    /// Fetch kith OS updates from the private ranges of this node's networks too (a release
    /// server on the LAN); never from this node, its loopback or link-local addresses
    #[arg(long, env = "KITH_LAN_RELEASES")]
    lan_releases: bool,
    /// Let a Source name a git repository on this machine (`file://`): for tests
    #[arg(long, hide = true)]
    local_sources: bool,
    /// Join the cluster's WireGuard mesh, on this UDP port (needs CAP_NET_ADMIN)
    #[arg(long, env = "KITH_MESH", value_name = "PORT", num_args = 0..=1, default_missing_value = "51820")]
    mesh: Option<u16>,
    /// The name of the mesh's network interface
    #[arg(long, env = "KITH_MESH_INTERFACE", value_name = "NAME", default_value = "kith0")]
    mesh_interface: String,
    /// Run the people's WireGuard device on this UDP port (docs/adr-people.md): kwg0, beside the
    /// mesh's interface. Needs --mesh, and root
    #[arg(long, env = "KITH_PEOPLE", value_name = "PORT", num_args = 0..=1, default_missing_value = "51821", requires = "mesh", value_parser = clap::value_parser!(u16).range(1..))]
    people: Option<u16>,
    /// Where other nodes reach this node's people's device, as NAME:PORT or ADDRESS:PORT (with --people)
    #[arg(long, env = "KITH_PEOPLE_ENDPOINT", value_name = "NAME:PORT", requires = "people", value_parser = people_endpoint)]
    people_endpoint: Option<String>,
    /// The networks a level of the people may reach (with --people): each AccessLevel's `networks`
    /// are held only where they lie in one of these, so the cluster cannot widen what this node's
    /// links are open to. None: Services only
    #[arg(long, env = "KITH_PEOPLE_NETWORKS", value_name = "CIDR,...", requires = "people", value_delimiter = ',', value_parser = levels::network)]
    people_networks: Vec<(std::net::IpAddr, u8)>,
    /// With --join: this node comes and goes (a laptop). It is reached on the mesh wherever it is,
    /// never votes, and what it runs is not started elsewhere while it is away
    #[arg(long, env = "KITH_ROAMING", requires_all = ["join", "mesh"])]
    roaming: bool,
    /// What the cluster may not have this node do as its root, whoever asks: `hardened`
    /// (none of it, and no NodeWorkloads: add host-users to run them), or words with commas between, `no-` before one to turn it off:
    /// exec-units, root-containers, unconfined, host-users, node-network, vms, vm-paths,
    /// passthrough, host-paths, run, wipe; and devices=gpu+input for the classes of Device handed out
    #[arg(long, env = "KITH_NODE_POLICY", value_name = "WORDS")]
    node_policy: Option<String>,
    /// Serve HTTPS (port 443, and 80) for Services with `expose`; for edge nodes
    #[arg(long, env = "KITH_INGRESS", requires = "mesh")]
    ingress: bool,
    /// Get the certificates for exposed hosts from this ACME directory (Let's Encrypt
    /// if none is named); giving this agrees to that authority's terms. On control nodes:
    /// one that serves ingress orders for itself, and the leader for the workers that do
    #[arg(
        long,
        env = "KITH_ACME",
        value_name = "URL",
        num_args = 0..=1,
        default_missing_value = "https://acme-v02.api.letsencrypt.org/directory"
    )]
    acme: Option<String>,
}

/// The ports kithd serves on at this node, and what for: none of them is published for a pod.
fn own_ports(args: &Args) -> Vec<(u16, &'static str)> {
    let mut own = vec![(args.listen.map_or(7443, |at| at.port()), "API")];
    own.extend(args.dns.map(|at| (at.port(), "DNS")));
    own.extend((args.registry_port != 0).then_some((args.registry_port, "registry")));
    own.extend(args.mesh.map(|port| (port, "mesh")));
    own.extend(args.people.map(|port| (port, "people")));
    if args.ingress {
        own.extend([(80, "ingress"), (443, "ingress")]);
    }
    own
}

/// A `--people-endpoint`: a name or an address, then `:PORT` (the port not 0). An IPv6 address is
/// in brackets. A name is labels of letters, digits and '-' (not at either end of a label); the
/// unspecified address (0.0.0.0, ::) is not one a peer can reach.
fn people_endpoint(at: &str) -> Result<String, String> {
    let bad = || format!("{at}: wants NAME:PORT or ADDRESS:PORT, the port from 1 to 65535, a real address");
    let (host, port) = at.rsplit_once(':').ok_or_else(bad)?;
    if !matches!(port.parse::<u16>(), Ok(port) if port != 0) {
        return Err(bad());
    }
    let fine = match host.strip_prefix('[').and_then(|host| host.strip_suffix(']')) {
        Some(six) => six.parse::<std::net::Ipv6Addr>().is_ok_and(|six| !six.is_unspecified()),
        None => match host.parse::<std::net::Ipv4Addr>() {
            Ok(four) => !four.is_unspecified(),
            Err(_) => host.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            }),
        },
    };
    if fine { Ok(at.to_string()) } else { Err(bad()) }
}

/// Why this start is refused, if it is: `--people` sets the people's device and table up as root.
fn people_refusal(args: &Args, root: bool) -> Option<String> {
    (args.people.is_some() && !root).then(|| {
        "--people sets up the people's WireGuard device and table: run kithd as root (or drop --people)".to_string()
    })
}

fn mesh_options(args: &Args, state: &std::path::Path, port: u16) -> mesh::Options {
    mesh::Options {
        interface: args.mesh_interface.clone(),
        port,
        key: state.join("pki").join("mesh.key"),
    }
}

/// What the API handlers and the controller share.
pub struct Shared {
    /// This node's copy of the store, to read. Changes go through [`Shared::submit`].
    pub store: Arc<Mutex<kith_store::State>>,
    pub raft: kith_store::Raft,
    /// Poked after every change to the store, so the controller reconciles at once.
    pub changed: Arc<Notify>,
    /// Where the output of every unit goes: `<unit id>.out` and `.err`.
    pub logs: PathBuf,
    /// Who changed what, and who was refused.
    pub audit: Arc<audit::Audit>,
    /// The WASM modules of `KindDefinition`s, compiled.
    pub wasm: Arc<wasm::Modules>,
    /// Counts changes to the store, for `GET /v1/watch`. Bumped while the store is
    /// locked, so a reader under the lock sees the generation that matches what it reads.
    /// Starts at the clock (ms) so a restarted kithd never repeats a number a client holds.
    pub generation: watch::Sender<u64>,
    /// `None` in agent mode: one node, nothing on the network.
    pub cluster: Option<cluster::Cluster>,
    /// Which nodes were heard from, and when.
    pub members: members::Members,
    /// The mesh's peers as last looked at, for `kith node status`; null without a mesh.
    pub mesh: Mutex<serde_json::Value>,
    /// Set once kithd is told to stop: long-polls answer at once instead of holding it up.
    pub stop: watch::Sender<bool>,
    /// The pods of this node, and their networks.
    pub pods: Mutex<pods::Pods>,
    /// The replicas a `kubectl delete pod` asked to restart here: (owner key, replica). The
    /// controller takes them at its next pass; a restart is not kept over a restart of kithd.
    pub restarts: Mutex<std::collections::BTreeSet<(String, u32)>>,
    /// The tunnels of the Exits this node holds.
    pub exits: Mutex<exits::Exits>,
    /// Dry runs (`/v1/diff`, `apply?dryRun`) at once, from asking admission to the answer:
    /// the page asks on every edit, and each asks the kinds' WASM. The rest wait their turn.
    pub dry_runs: tokio::sync::Semaphore,
    /// The order access is decided in, where a change is put in the log: a change to access
    /// holds it alone until applied, an Identity's write shared once decided again (`raft.rs`).
    pub order: tokio::sync::RwLock<()>,
    /// The nonces of the signed requests this node has taken (`access_sign.rs`).
    pub nonces: access_sign::Nonces,
    /// On a worker that runs from a view (`view`): the index of the store its view is at.
    /// `None` on every other node, which keeps the store.
    pub view: watch::Sender<Option<u64>>,
    /// On such a worker: where the control node it follows is, and the client that calls it
    /// and no other.
    pub upstream: Mutex<Option<(String, reqwest::Client)>>,
    /// How long a node may be out of contact before its replicas move (`--lost-after`).
    pub lost_after: std::time::Duration,
}

/// How many dry runs at once.
const DRY_RUNS: usize = 4;

/// The most open files kithd asks for: ingress's 1024 connections hold two each, and the
/// relays, the API and the listeners come on top (SECURITY.md).
const NOFILE_WANTED: u64 = 65536;

/// The soft limit of open files to set: the hard limit, but no more than [`NOFILE_WANTED`],
/// and never below what it has now (a limit kithd lowered would be worse than none).
fn nofile_soft(soft: u64, hard: u64) -> u64 {
    hard.min(NOFILE_WANTED).max(soft).min(hard)
}

/// Raise the soft limit of open files ([`nofile_soft`]); the hard one is not touched. A
/// failure leaves the limit as it was and is only said.
fn raise_nofile() {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let said = |e: &dyn std::fmt::Display| {
        // (Not `eprintln!`: it panics when stderr cannot be written, and PID 1 may not.)
        let _ = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!("kithd: could not raise its limit of open files: {e}\n"),
        );
    };
    match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok((soft, hard)) => {
            let want = nofile_soft(soft, hard);
            if want != soft
                && let Err(e) = setrlimit(Resource::RLIMIT_NOFILE, want, hard)
            {
                said(&e);
            }
        }
        Err(e) => said(&e),
    }
}

fn main() -> ExitCode {
    // First of all, before a thread or an argument (and before the shim below, which is
    // this same program started again): what musl's start code left writable is shut. A node
    // that cannot shut it still has to boot, so a failure is only said.
    if let Err(e) = kith_dm_sys::seal_relro() {
        // (Not `eprintln!`: it panics when stderr cannot be written, and PID 1 may not.)
        let _ = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!("kithd: could not make its tables of functions read-only: {e}\n"),
        );
    }
    // Started again by the runtime as an exec unit's helper? Then this never returns.
    kith_runtime::exec_shim();
    // Started again to render a package's templates? Then this never returns either.
    releases::render_shim();
    // Then, before the runtime and its listeners, the limit of open files they share.
    raise_nofile();
    // A test build says so, loudly, each time it starts (ci/vm/access.sh looks for the line).
    #[cfg(feature = "forge")]
    let _ = std::io::Write::write_all(
        &mut std::io::stderr(),
        b"kithd: built with forge: POST /v1/forge appends unchecked entries; never ship this\n",
    );
    // Process 1 keeps kithd (keeper.rs) and is nothing else; kithd it keeps is the node's first.
    if std::process::id() == 1 {
        keeper::keep();
    }
    let kept = keeper::kept();
    let first = kept.is_some();
    if let Some((start, end)) = kept {
        init::FIRST.store(true, std::sync::atomic::Ordering::Relaxed);
        // (What `pod kill` and a reader of ps find it by: it was started as /proc/self/exe.)
        let _ = nix::sys::prctl::set_name(c"kithd");
        if end {
            eprintln!("kithd: init: kithd failed 10 times in a minute");
            init::end(true);
        }
        if start > 1 {
            eprintln!("kithd: init: started again ({start}): what runs is taken back");
        }
    }
    let mut boot = kept.map(|(start, _)| init::early(start > 1));
    if let Some(source) = boot.as_mut().and_then(|boot| boot.install.take()) {
        installer(boot.expect("there is one"), source);
    }
    let config = boot.as_mut().map(|boot| std::mem::take(&mut boot.args));
    // (As the first process, a mistake in its arguments is clap's to say, and then a restart.)
    let read = move || {
        if first {
            use clap::{CommandFactory, FromArgMatches};
            // What the node's config says, then the command line's own, which is the last word.
            let mut given = init::arguments(std::env::args());
            given.splice(1..1, config.unwrap_or_default());
            let matched = Args::command().args_override_self(true).try_get_matches_from(given);
            matched
                .and_then(|matched| Args::from_arg_matches(&matched))
                .map_err(|e| e.to_string())
        } else {
            Ok(Args::parse())
        }
    };
    // On a thread of their own: clap builds its command on the stack (70 kB of it), and that
    // thread's stack goes back when it ends; this one's stays for as long as the daemon runs.
    // (A thread that cannot be made is a start that failed, like a mistake in the arguments.)
    let args = std::thread::Builder::new()
        .spawn(read)
        .map_err(|e| format!("reading the arguments: {e}"))
        .and_then(|read| {
            read.join()
                .map_err(|_| "reading the arguments: it panicked".to_string())
        })
        .and_then(|args| args);
    let done = args.and_then(|args| run(args, boot));
    if let Err(msg) = &done {
        eprintln!("kithd: {msg}");
    }
    if first {
        init::end(done.is_err());
    }
    if done.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Whether a range that clashes with an address of this node ends the start: one an operator
/// named (not the default), when kithd is not the first process. There a refusal restarts the
/// machine, and a lease that lands in the range one day would make a reboot loop nobody
/// can reach: it is said and the start goes on.
fn clash_refuses(range: kith_mesh::pod::Range, first_process: bool) -> bool {
    range != kith_mesh::pod::Range::default() && !first_process
}

/// The installer (kith OS started with `kith.install`): nothing is served, a disk is
/// written, and the machine is powered off.
fn installer(boot: init::Boot, source: String) -> ! {
    let made = tokio::runtime::Builder::new_current_thread().enable_all().build();
    match made {
        Ok(runtime) => runtime.block_on(async {
            // As a node does: Ctrl-Alt-Del starts the machine again, SIGTERM and the power button power it off.
            // (Registered here, not in the task: heard from now on, whenever the task runs.)
            if let Ok((mut off, mut again)) = stops() {
                tokio::spawn(async move {
                    tokio::select! {
                        _ = off.recv() => init::POWER_OFF.store(true, std::sync::atomic::Ordering::Relaxed),
                        _ = again.recv() => {}
                        () = init::BUTTON.notified() => {}
                    }
                    init::end(false)
                });
            }
            boot.network();
            install::run(source).await
        }),
        Err(e) => {
            eprintln!("kithd: install: {e}");
            init::end(true)
        }
    }
}

/// How long a server goes on with what it is answering, once kithd is stopping.
const LAST_ANSWERS: std::time::Duration = std::time::Duration::from_secs(3);

/// `served` until it ends, or [`LAST_ANSWERS`] after the stop. It ends by itself once every
/// connection has, and a request left half sent, or an answer nobody reads, would hold it
/// (and the stop, and a node's power-off) for as long as its client stays.
async fn within(
    served: impl IntoFuture<Output = std::io::Result<()>>,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let late = async {
        let _ = stop.wait_for(|stopping| *stopping).await;
        tokio::time::sleep(LAST_ANSWERS).await;
    };
    tokio::select! {
        ended = served.into_future() => ended,
        () = late => Ok(()),
    }
}

/// SIGTERM and SIGINT, heard from here on (one that comes before it is read is kept).
/// Call inside the runtime.
fn stops() -> std::io::Result<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)> {
    use tokio::signal::unix::{SignalKind, signal};
    let heard = (signal(SignalKind::terminate())?, signal(SignalKind::interrupt())?);
    // (A kept kithd inherits the keeper's blocked mask: unblocked once these handlers are set.)
    keeper::unblock_heard();
    Ok(heard)
}

fn default_state() -> Option<PathBuf> {
    let env = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    match (env("XDG_STATE_HOME"), env("HOME")) {
        (Some(dir), _) => Some(dir.join("kith")),
        // No per-user state directory: a system service.
        (None, Some(home)) if home != std::path::Path::new("/root") => Some(home.join(".local/state/kith")),
        _ => Some("/var/lib/kith".into()),
    }
}

/// Why a node that makes or holds a cluster's CA cannot be reached, when it listens on every
/// address and was not told where it is.
fn unreachable_listen(listen: std::net::SocketAddr, advertised: bool, holds_ca: bool) -> Option<String> {
    (listen.ip().is_unspecified() && !advertised && holds_ca)
        .then(|| format!("other nodes cannot reach {listen}: say where this node is with --advertise ADDR:PORT"))
}

/// This node's place in a cluster, and the port it serves other nodes on: made on the
/// first start with `--listen` or `--join`, read back from the state directory after that.
async fn membership(
    args: &Args,
    state: &std::path::Path,
) -> Result<(Option<cluster::Cluster>, Option<tokio::net::TcpListener>), String> {
    let dir = state.join("pki");
    let known = pki::load(&dir)?;
    if known.is_none() && args.listen.is_none() && args.join.is_none() {
        return Ok((None, None));
    }
    // (A node that roams is called at its mesh address, which is an IPv6 one.)
    // It joined as one if it was told whom to call first; that file stays.
    let roams = args.roaming || mesh::first_peers(&dir.join("mesh.key")).exists();
    let anywhere: std::net::IpAddr = if roams {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    };
    let listen = args.listen.unwrap_or((anywhere, 7443).into());
    // As the first process the address is waited for from the network, and said below.
    let holds_ca = known.as_ref().map_or(args.join.is_none(), |(_, ca)| ca.is_some());
    if !init::is_init()
        && let Some(why) = unreachable_listen(listen, args.advertise.is_some(), holds_ca)
    {
        return Err(why);
    }
    let tcp = tokio::net::TcpListener::bind(listen).await;
    let tcp = tcp.map_err(|e| format!("listening on {listen}: {e}"))?;
    if let Some((me, ca)) = known {
        if args.join.is_some() {
            eprintln!(
                "kithd: already a member as node {}: --join is not needed again",
                me.name
            );
        }
        if args.name.as_ref().is_some_and(|name| *name != me.name) {
            return Err(format!(
                "this node joined as `{}`: it cannot be renamed with --name",
                me.name
            ));
        }
        return Ok((Some(cluster::Cluster::new(me, ca)?), Some(tcp)));
    }
    let name = match &args.name {
        Some(name) => name.clone(),
        None => {
            let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
            hostname.trim().to_ascii_lowercase()
        }
    };
    pki::valid_name(&name).map_err(|e| format!("{e} (set --name)"))?;
    let (me, ca) = match &args.join {
        Some(address) => {
            // Its store would be another cluster's: nothing of it could be kept.
            let held = [state.join("raft"), state.join("store.json"), view::path(state)];
            if held.iter().any(|held| held.exists()) {
                return Err(format!(
                    "{} already holds a store or a view of one, which joining would discard: join with an empty --state",
                    state.display()
                ));
            }
            let port = tcp.local_addr().map_err(|e| e.to_string())?.port();
            let token = args.token.as_deref().expect("clap requires --token with --join");
            let options = args
                .mesh
                .filter(|_| args.roaming)
                .map(|port| mesh_options(args, state, port));
            let mesh = match &options {
                Some(options) => {
                    let made = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir);
                    made.map_err(|e| format!("creating {}: {e}", dir.display()))?;
                    let key = mesh::key_before_joining(options, token, &name)?;
                    Some(cluster::OnMesh {
                        key,
                        port: options.port,
                    })
                }
                None => None,
            };
            // (A worker runs from a view; one that serves ingress says so, as its token must.)
            let joined = cluster::request_join(address, token, &name, port, mesh, args.ingress).await?;
            if let Some((through, certificate)) = joined.view.clone() {
                let first = view::Upstream {
                    name: through,
                    address: address.clone(),
                    certificate,
                };
                view::begin(state, &first)?;
            }
            if let Some(options) = &options {
                let peers = serde_json::to_vec(&joined.peers).expect("JSON values");
                let path = mesh::first_peers(&options.key);
                pki::write_whole(&path, &peers).map_err(|e| format!("writing {}: {e}", path.display()))?;
            }
            eprintln!("kithd: joined the cluster of {address} as node {name}");
            let me = pki::Identity {
                name,
                ca: joined.ca,
                cert: joined.cert,
                key: joined.key,
            };
            (me, None)
        }
        None => {
            let ca = pki::Ca::create()?;
            let (cert, key) = ca.issue(&name)?;
            eprintln!("kithd: new cluster; `kith node token` lets another node join");
            let me = pki::Identity {
                name,
                ca: ca.cert.clone(),
                cert,
                key,
            };
            (me, Some(ca))
        }
    };
    pki::save(&dir, &me, ca.as_ref())?;
    Ok((Some(cluster::Cluster::new(me, ca)?), Some(tcp)))
}

/// Open this node's replica of the store and start Raft on it.
async fn replica(
    cluster: Option<cluster::Cluster>,
    state: &std::path::Path,
    lost_after: std::time::Duration,
) -> Result<Arc<Shared>, String> {
    // One kept by an earlier version holds the NodeKeys of its day, and so does one a crash left
    // between the rename and the cut: every start cuts, on any node.
    cut_or_say(&state.join("store.json.imported"));
    let changed = Arc::new(Notify::new());
    let clock = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    let generation = watch::channel(clock.map_or(0, |d| d.as_millis() as u64)).0;
    let poke = {
        let (changed, generation) = (changed.clone(), generation.clone());
        Arc::new(move || {
            generation.send_modify(|g| *g += 1);
            changed.notify_one();
        })
    };
    let name = cluster.as_ref().map_or("local", |cluster| &cluster.me.name);
    let network = raft::Network::default();
    let reach = network.0.clone();
    // A worker that runs from a view keeps no store: what Raft kept here before is erased
    // (a kithd that stopped between its first view and the erasing left it).
    let view = view::load(state)?;
    if view.is_some() {
        let raft = state.join("raft");
        match std::fs::remove_dir_all(&raft) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("erasing {}: {e}", raft.display()));
            }
            _ => {}
        }
    }
    // What each entry is asked once the store is in format 3: a signed one is applied only
    // where its signature, command, signer's rights and nonce hold by the store
    // (`access_sign::admit`; under the store's lock, and deterministic). A CA whose fingerprint
    // cannot be read stops the start: without it every signed entry would be refused here
    // alone, and this store would part from the others'.
    let audit = Arc::new(audit::Audit::new(state.join("audit.log")));
    let id = cluster
        .as_ref()
        .map(|cluster| pki::fingerprint(&cluster.me.ca))
        .transpose()
        .map_err(|e| format!("the cluster CA's fingerprint: {e}"))?;
    let check = access_sign::hook(id, audit.clone());
    let replica = kith_store::open(&state.join("raft"), kith_store::node_id(name), network, poke, check).await?;
    let shared = Arc::new(Shared {
        store: replica.state,
        raft: replica.raft,
        changed,
        logs: state.join("logs"),
        audit,
        wasm: Arc::default(),
        generation,
        members: members::Members::new(name),
        mesh: Mutex::default(),
        cluster,
        stop: watch::channel(false).0,
        pods: Mutex::default(),
        restarts: Mutex::default(),
        exits: Mutex::default(),
        dry_runs: tokio::sync::Semaphore::new(DRY_RUNS),
        order: tokio::sync::RwLock::default(),
        nonces: access_sign::Nonces::default(),
        view: watch::channel(None).0,
        upstream: Mutex::default(),
        lost_after,
    });
    // (Raft's links look a voter's Node up in the store; the state holds Raft, so by a weak hold.)
    let _ = reach.set(Arc::downgrade(&shared));
    // ponytail: an empty Raft is opened and ended again, so that what reads `shared.raft`
    // (who leads, who votes) needs no second path on a worker: it leads nothing and has no members.
    if let Some((mut store, at, _)) = view {
        let _ = shared.raft.shutdown().await;
        let mut state = shared.store.lock().expect("nothing panics holding the store");
        store.continue_changes(&state.store);
        state.store = store;
        drop(state);
        shared.view.send_replace(Some(at));
        return Ok(shared);
    }
    // A node that joined waits to be sent the store; any other is where a cluster starts.
    if shared.cluster.as_ref().is_some_and(|cluster| cluster.ca.is_none()) {
        return Ok(shared);
    }
    let failed = |e: &dyn std::fmt::Display| format!("starting the store: {e}");
    if !shared.raft.is_initialized().await.map_err(|e| failed(&e))? {
        // Its address is filled in from its Node, once it has one.
        let alone = std::collections::BTreeMap::from([(replica.id, kith_store::openraft::BasicNode::new(""))]);
        shared.raft.initialize(alone).await.map_err(|e| failed(&e))?;
    }
    // The store of a kithd from before replication comes in once, into an empty store.
    let (old, kept) = (state.join("store.json"), state.join("store.json.imported"));
    if old.exists() {
        let empty = shared.store.lock().expect("nothing panics holding the store").store == Default::default();
        if empty {
            let store = kith_api::store::FileStore::read(&old).map_err(|e| e.to_string())?.store;
            let imported = shared.submit(kith_store::Command::Import { store }).await;
            imported.map_err(|e| format!("bringing in {}: {e}", old.display()))?;
            // Left in place it would come in again, should the store ever be empty.
            keep_imported(&old, &kept).map_err(|e| {
                format!(
                    "{} was brought in but cannot be moved aside ({e}): remove it",
                    old.display()
                )
            })?;
            eprintln!("kithd: brought in {} (kept as store.json.imported)", old.display());
        } else {
            eprintln!(
                "kithd: {} is not used: the store is in {}",
                old.display(),
                state.join("raft").display()
            );
        }
    }
    Ok(shared)
}

/// Keep the store from before replication aside, as `kept`, with no NodeKey in it: the
/// replicated store holds them, and forgets or wipes them, which a copy here would outlive.
fn keep_imported(old: &std::path::Path, kept: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(old, kept)?;
    // (A cut that fails is said, not an error: it is tried again at each start.)
    cut_or_say(kept);
    Ok(())
}

fn cut_or_say(kept: &std::path::Path) {
    if let Err(e) = strip_node_keys(kept) {
        eprintln!(
            "kithd: {} may hold NodeKeys and could not be cut ({e}); it is left as it is",
            kept.display()
        );
    }
}

/// Rewrite the kept file without its NodeKeys (and their history), if it has any: a temporary
/// file beside it, synced, renamed over it. A file that is not a store is left as it is.
fn strip_node_keys(kept: &std::path::Path) -> Result<(), String> {
    if !kept.exists() {
        return Ok(());
    }
    let mut file = kith_api::store::FileStore::read(kept).map_err(|e| e.to_string())?;
    if file.store.drop_node_keys() {
        file.save().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn run(args: Args, mut boot: Option<init::Boot>) -> Result<(), String> {
    let first_process = boot.is_some();
    if let Some(why) = people_refusal(&args, nix::unistd::getuid().is_root()) {
        return Err(why);
    }
    // Before anything is run or served: what this node's owner has it refuse.
    let node_policy = policy::read(args.node_policy.as_deref(), first_process)?;
    // And, where it refuses every way to be root with all the kernel's capabilities, before
    // the runtime or any other thread: a thread keeps the bounding set it was made with.
    // (Only the threads of `init::early`, which read and write and start nothing, are older.)
    policy::cut(&node_policy)?;
    policy::set(node_policy);
    // One thread for everything that is awaited: kithd forks containers, and a small idle
    // footprint is the point (§3.2). (What blocks goes to a thread of its own for as long as it does.)
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("starting: {e}"))?;
    let sealed = boot.as_mut().and_then(|boot| boot.sealed.take());
    // As the first process, SIGTERM and Ctrl-Alt-Del are heard from the start: the kernel
    // drops what process 1 does not handle. (Anywhere else the default, which ends kithd, stays until serving.)
    let mut early = None;
    if let Some(boot) = boot {
        let _in = rt.enter();
        early = stops().ok();
        boot.network();
    }
    // Pods are made as root only; elsewhere the range is never used, so a clash is no matter.
    pods::set_range(args.pod_range);
    if nix::unistd::getuid().is_root()
        && let Err(clash) = args.pod_range.refuse_if_in_use()
    {
        if clash_refuses(args.pod_range, first_process) {
            return Err(clash);
        }
        // (Not `eprintln!`: PID 1 must not panic on a stderr it cannot write.)
        let _ = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!("kithd: WARNING: {clash} (going on: pods may not reach, or be reached from, that network)\n"),
        );
    }
    // --people: neither the pods' range nor a network of this node may overlap 100.89.0.0/16
    // (docs/adr-people.md, Review 4). The range is a flag, so it refuses; a lease that lands in
    // the people's range is only said where a refusal would restart the machine (as above).
    if args.people.is_some() {
        args.pod_range.refuse_people()?;
        if let Err(clash) = kith_mesh::pod::Range::refuse_people_in_use() {
            if !first_process {
                return Err(clash);
            }
            let _ = std::io::Write::write_fmt(
                &mut std::io::stderr(),
                format_args!(
                    "kithd: WARNING: {clash} (going on: people may not reach, or be reached from, that network)\n"
                ),
            );
        }
    }
    // An encrypted state is opened with a key the cluster holds: nothing below can be
    // done before that, and it takes as long as it takes. A stop that comes meanwhile ends it.
    //
    // ponytail: past this, a stop waits for the serving below (the membership and the replica
    // open in moments, not as long as a key); it is kept until then.
    let mut opened = None;
    if let Some((record, config)) = &sealed {
        let key = crypt::open(record, config, args.join.as_ref());
        opened = Some(match &mut early {
            Some((term, int)) => rt.block_on(async {
                tokio::select! {
                    key = key => key,
                    _ = term.recv() => {
                        init::POWER_OFF.store(true, std::sync::atomic::Ordering::Relaxed);
                        init::end(false)
                    }
                    _ = int.recv() => init::end(false),
                    () = init::BUTTON.notified() => init::end(false),
                }
            })?,
            None => rt.block_on(key)?,
        });
    }
    // (From here the node has its state: a slot on trial may be marked good.)
    init::STATE_OPEN.notify_one();
    let state = args
        .state
        .clone()
        .or_else(|| init::is_init().then(|| init::STATE.into()))
        .or_else(default_state)
        .ok_or("no state directory: set --state")?;
    let socket = args
        .socket
        .clone()
        .or_else(kith_api::default_socket)
        .ok_or("no socket path: set --socket")?;
    let fail = |what: &str, e: &dyn std::fmt::Display| format!("{what}: {e}");

    if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
        return Err(format!("another kithd is already serving {}", socket.display()));
    }
    if let Some(dir) = socket.parent() {
        // Owner-only: until RBAC exists, reaching the socket is the permission check.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| fail("creating the socket directory", &e))?;
    }
    // Owner-only: container logs and bundles under it carry Secret values.
    std::fs::create_dir_all(&state)
        .and_then(|()| std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)))
        .map_err(|e| fail("creating the state directory", &e))?;
    // The runtime hands this path to containers, whose working directory is not ours.
    let state = state
        .canonicalize()
        .map_err(|e| fail("resolving the state directory", &e))?;
    // The root part's own word for where a mount may be (`root_part::check_create`).
    root_part::set_state(state.clone());
    // Nobody answered and the state is ours: a socket here is a dead kithd's. Anything else is not ours to remove.
    use std::os::unix::fs::FileTypeExt;
    if std::fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket()) {
        let _ = std::fs::remove_file(&socket);
    }
    let mut runtime = kith_runtime::Runtime::new(state.join("runtime"));
    let dmem = runtime.as_ref().is_ok_and(|runtime| runtime.gives_dmem());
    if let Some(said) = runtime.as_ref().ok().and_then(|runtime| runtime.cgroup_problem()) {
        eprintln!("kithd: {said}");
    }
    // Started again by process 1: a container the kithd before made and did not start holds
    // its sockets (this one's address among them) until it is gone.
    if let (Ok(runtime), Some((2.., _))) = (&runtime, keeper::kept()) {
        let stopped = runtime.stop_unstarted(std::path::Path::new(controller::UNITS));
        if stopped > 0 {
            eprintln!(
                "kithd: {stopped} container(s) an earlier kithd made and never started: stopped, to be started again"
            );
        }
    }
    // The registry's door, and the one copy of what opens it: the runtime's, for its pulls.
    // (No door is no kithd: without one a pull of `localhost:PORT/…` would ask whatever
    // else took the port, in the clear.)
    let door = match args.registry_port {
        0 => None,
        port => Some(Arc::new(
            images::Door::new(port).map_err(|e| fail("making the registry's door", &e))?,
        )),
    };
    if let (Ok(runtime), Some(door)) = (&mut runtime, &door) {
        runtime.images.local = Some(door.local.clone());
    }
    // Its port is taken now: the controller's first pass may ask it before it is served.
    let door = door.map(|door| {
        let tcp = door.bind();
        (door, tcp)
    });

    let upstream = |address: &String| {
        let with_port = address.parse().ok();
        let bare = || address.parse().ok().map(|ip| std::net::SocketAddr::new(ip, 53));
        with_port
            .or_else(bare)
            .ok_or(format!("--dns-upstream: `{address}` is not an address"))
    };
    let upstreams = args.dns_upstream.iter().map(upstream).collect::<Result<Vec<_>, _>>()?;
    let (membership, tcp) = rt.block_on(membership(&args, &state))?;
    let names = rt.block_on(async {
        match args.dns {
            Some(listen) => dns::bind(listen).await.map(Some),
            None => Ok(None),
        }
    })?;
    let shared = rt.block_on(replica(
        membership,
        &state,
        std::time::Duration::from_secs(args.lost_after),
    ))?;
    // (An exit's pods pass on to the mesh by its link alone.)
    shared.pods.lock().expect("nothing panics holding the pods").mesh = args.mesh_interface.clone();
    // A viewed worker serves ingress only where its Node says so (as the join of a token for
    // an ingress worker wrote it): only then is its view sent the hosts' certificates. (Its
    // Node not in the view yet: its first view is still to come, and says.)
    let unsaid = args.ingress && shared.view.borrow().is_some() && {
        let me = shared.members.me();
        let state = shared.store.lock().expect("nothing panics holding the store");
        let node = state.store.get(&format!("Node/{me}"));
        node.is_some_and(|node| node.spec["ingress"] != true)
    };
    if unsaid {
        return Err(
            "--ingress: this node is a worker that joined without a token for an ingress worker, so it is sent no \
             host's certificate: delete this node and join it again with a token from \
             `kith node token --worker --ingress`, or serve ingress on a control node"
                .into(),
        );
    }

    let served = rt.block_on(async {
        // ponytail: bound, then made owner-only. The directory kithd creates for it is
        // already 0700; in a shared directory there is a moment in between (umask needs libc).
        let listener = tokio::net::UnixListener::bind(&socket).map_err(|e| fail("binding the socket", &e))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| fail("securing the socket", &e))?;
        // (Heard before it says it serves: a first process is not sent what it does not handle.)
        let (mut term, mut int) = early.take().map_or_else(stops, Ok).unwrap();
        eprintln!("kithd: serving {} (state in {})", socket.display(), state.display());

        let stopping = shared.stop.subscribe();
        let watched = shared.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = term.recv() => init::POWER_OFF.store(true, std::sync::atomic::Ordering::Relaxed),
                _ = int.recv() => {}
                () = init::BUTTON.notified() => {}
            }
            if first_process && let Some((all, files)) = init::resident() {
                eprintln!("kithd: init: told to stop: {all} kB resident, {files} kB of it files");
            }
            watched.stop.send_replace(true);
            // Told again while it stops: it ends now, as a kill would end it, and what still
            // runs is found by the next start. (Not the first process: its end unmounts the disks.)
            if !first_process {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = int.recv() => {}
                }
                eprintln!("kithd: told to stop twice: ending now, with what it had not stopped left to the next start");
                std::process::exit(1);
            }
        });
        let mut server_stop = stopping.clone();
        // Whoever can open the socket is the machine's admin: under `spec.signing: required`,
        // with the admin's signature (`access_sign::local`).
        let local = api::router(shared.clone())
            .merge(cluster::admin_router(shared.clone()))
            .merge(ui::pages())
            .layer(axum::middleware::from_fn_with_state(shared.clone(), access_sign::local));
        let server =
            axum::serve(listener, local).with_graceful_shutdown(async move { drop(server_stop.changed().await) });
        let server = within(server, stopping.clone());
        // The same API for other nodes, over TLS.
        let nodes = async {
            let (Some(cluster), Some(tcp)) = (&shared.cluster, tcp) else {
                return Ok(());
            };
            let address = tcp.local_addr().map_err(|e| fail("listening", &e))?;
            // A machine that asked its network for an address says the one it was given.
            let mut advertise = args.advertise.map(|at| at.to_string());
            if first_process && advertise.is_none() && address.ip().is_unspecified() && cluster.ca.is_some() {
                for _ in 0..600 {
                    if init::ADDRESS.get().is_some() || *stopping.borrow() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                advertise = init::ADDRESS.get().map(|ip| format!("{ip}:{}", address.port()));
            }
            if let Some(why) = unreachable_listen(address, advertise.is_some(), cluster.ca.is_some()) {
                // (As the first process it stops now: the rest would run for a node nobody can reach.)
                shared.stop.send_replace(true);
                return Err(why);
            }
            if args.claim {
                cluster::offer_claim(&shared);
            }
            eprintln!("kithd: node {} serving other nodes on {address}", cluster.me.name);
            let _ = netboot::PORT.set(address.port());
            if args.admit_deleted_nodes {
                eprintln!("kithd: --admit-deleted-nodes: a deleted node's certificate is still taken here");
                cluster::ADMIT_DELETED.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            let listener = cluster::listen(tcp, pki::server_config(&cluster.me)?).map_err(|e| fail("listening", &e))?;
            let app = cluster::node_router(shared.clone()).into_make_service_with_connect_info::<cluster::Peer>();
            let mut stop = stopping.clone();
            let served = axum::serve(listener, app).with_graceful_shutdown(async move { drop(stop.changed().await) });
            let served = within(served, stopping.clone());
            let members = raft::tend_members(shared.clone(), stopping.clone());
            // The node the cluster started on says where it is; one that joined was written down as it did.
            // ponytail: so a joined node that moves has to be deleted and joined again.
            let registered = async {
                if cluster.ca.is_some() {
                    let reachable = advertise.clone().unwrap_or(address.to_string());
                    let id = shared.raft.metrics().borrow().id;
                    // Not fatal: the address the cluster has for this node is the one from last time.
                    let registered = match pki::print_of(&cluster.me.cert) {
                        Ok(print) => {
                            let more = serde_json::json!({ "ca": true });
                            let registered =
                                cluster::register_first(&shared, &cluster.me.name, &reachable, id, &print, more);
                            registered.await.map(drop).map_err(|e| e.to_string())
                        }
                        Err(e) => Err(e),
                    };
                    if let Err(e) = registered {
                        eprintln!("kithd: telling the cluster this node is at {reachable}: {e}");
                    }
                }
            };
            let pings = members::run(shared.clone(), stopping.clone());
            let lost_after = std::time::Duration::from_secs(args.lost_after);
            let scheduler = sched::run(shared.clone(), lost_after, stopping.clone());
            let view = view::follow(shared.clone(), state.clone(), args.ingress, stopping.clone());
            let (served, (), (), (), (), ()) = tokio::join!(
                served,
                apart(members),
                apart(registered),
                apart(pings),
                apart(scheduler),
                apart(view)
            );
            served.map_err(|e| fail("serving other nodes", &e))
        };
        let work = async {
            let releases = releases::run(shared.clone(), stopping.clone());
            let poll = std::time::Duration::from_secs(args.repository_poll);
            let repositories = registry::run(shared.clone(), poll, stopping.clone());
            let units = controller::run(
                shared.clone(),
                runtime,
                args.log_cap,
                args.storage_reserve,
                std::time::Duration::from_secs(args.image_grace),
                stopping.clone(),
            );
            let sources = sources::run(shared.clone(), state.clone(), args.local_sources, stopping.clone());
            let controllers = controllers::run(shared.clone(), stopping.clone());
            let plans = update::run(shared.clone(), stopping.clone());
            let system = update::node(
                shared.clone(),
                state.clone(),
                args.release_key.clone(),
                args.lan_releases,
                stopping.clone(),
            );
            let key = async {
                if let Some(((record, config), opened)) = sealed.zip(opened) {
                    let keys = update::keys(args.release_key.clone(), &state);
                    crypt::keep(shared.clone(), config, record, opened, keys, stopping.clone()).await;
                }
            };
            let hardware = devices::run(shared.clone(), stopping.clone(), dmem);
            let crons = cron::run(shared.clone(), stopping.clone());
            let exits = exits::run(shared.clone(), stopping.clone());
            let people = people::run(shared.clone(), stopping.clone());
            let published = pods::publish(shared.clone(), own_ports(&args), stopping.clone());
            tokio::join!(
                apart(exits),
                apart(people),
                apart(published),
                apart(units),
                apart(releases),
                apart(repositories),
                apart(sources),
                apart(controllers),
                apart(plans),
                apart(system),
                apart(key),
                apart(hardware),
                apart(crons)
            );
        };
        let names = async {
            let upstreams = dns::upstreams(upstreams);
            let pods = pods::names(shared.clone(), upstreams.clone(), stopping.clone());
            let asked = async {
                if let Some(sockets) = names {
                    dns::run(shared.clone(), sockets, upstreams, stopping.clone()).await;
                }
            };
            tokio::join!(pods, asked);
        };
        let mesh = async {
            if let Some(port) = args.mesh {
                mesh::run(shared.clone(), mesh_options(&args, &state, port), stopping.clone()).await;
            } else {
                mesh::left(shared.clone(), "mesh", stopping.clone()).await;
            }
        };
        // (Its own leftovers too, with no --people: see `people::device`.)
        let device = async {
            let held = args.people.map(|_| levels::Config {
                interface: args.mesh_interface.clone(),
                networks: args.people_networks.clone(),
                api: args.listen.map_or(7443, |at| at.port()),
                pods: args.pod_range.network(),
            });
            let device = people::device(
                shared.clone(),
                state.clone(),
                args.people,
                args.people_endpoint.clone(),
                args.mesh_interface.clone(),
                stopping.clone(),
            );
            tokio::join!(device, levels::run(shared.clone(), held, stopping.clone()));
        };
        let (strays, taken) = tokio::sync::mpsc::unbounded_channel();
        let taken = args.ingress.then_some(taken);
        // (Without a mesh too: a node's Services answer its pods there as well, T-0723.)
        let services = services::run(shared.clone(), args.mesh, taken, stopping.clone());
        // (What each pod may reach, kept in step with its policies: on a node alone too.)
        let held = pods::keep_held(shared.clone(), stopping.clone());
        let proxy = async {
            tokio::join!(services, held);
        };
        let ingress = async {
            // (A control node with --acme alone orders for the workers that serve ingress.)
            if args.ingress || args.acme.is_some() {
                let strays = args.ingress.then_some(strays);
                ingress::run(shared.clone(), args.acme.clone(), strays, stopping.clone()).await;
            }
        };
        let shares = share::run(shared.clone(), state.clone(), stopping.clone());
        let blobs = blobs::run(shared.clone(), stopping.clone());
        let backups = backups::run(shared.clone(), state.clone(), stopping.clone());
        let replicas = replicas::run(shared.clone(), state.clone(), stopping.clone());
        let images = images::run(shared.clone(), state.clone(), stopping.clone());
        let encrypted = encrypted::run(shared.clone(), state.clone(), stopping.clone());
        let identities = workload_identity::run(shared.clone(), stopping.clone());
        let registry = images::serve(shared.clone(), door, stopping.clone());
        let storage = async {
            tokio::join!(
                apart(shares),
                apart(blobs),
                apart(backups),
                apart(replicas),
                apart(images),
                apart(registry),
                apart(encrypted),
                apart(identities)
            )
        };
        let says = vec![
            ("serves", serves(args.dns, args.ingress)),
            ("policy", policy::get().status()),
        ];
        let saying = async {
            let format = raft::tend_format(shared.clone(), stopping.clone());
            tokio::join!(say_serves(shared.clone(), says, stopping.clone()), format);
        };
        let house = home::run(shared.clone(), stopping.clone());
        let (served, nodes, (), (), (), (), (), (), (), (), _) = tokio::join!(
            server,
            apart(nodes),
            apart(work),
            apart(names),
            apart(mesh),
            apart(device),
            apart(proxy),
            apart(ingress),
            apart(saying),
            apart(house),
            apart(storage)
        );
        let _ = shared.raft.shutdown().await;
        served.map_err(|e| fail("serving", &e)).and(nodes)
    });
    let _ = std::fs::remove_file(&socket);
    served
}

/// `loops`, kept by itself and polled through a pointer. Every loop of the daemon is joined
/// into one future; polled in line, each loop's working room was a part of that one future's
/// stack frame (87 kB of it, touched at every poll, so held for as long as the daemon runs).
/// Apart, a loop's frame is there while it is polled and the next one's takes its place.
fn apart<'a, T>(loops: impl Future<Output = T> + 'a) -> std::pin::Pin<Box<dyn Future<Output = T> + 'a>> {
    Box::pin(loops)
}

/// What this node serves, as its own Node says it (`status.serves`): the DNS port and ingress, or
/// null when it serves neither, so a start without the flags takes off what the last start said.
fn serves(dns: Option<std::net::SocketAddr>, ingress: bool) -> serde_json::Value {
    let mut said = serde_json::Map::new();
    // (Port 0 is "any port": not one to tell anyone.)
    if let Some(dns) = dns.filter(|dns| dns.port() != 0) {
        said.insert("dns".into(), dns.port().into());
    }
    if ingress {
        said.insert("ingress".into(), true.into());
    }
    if said.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(said)
    }
}

/// Keep what this node says of itself in its own Node's status as its flags say (what it
/// `serves`, and its own `policy` where it has one), for as long as the node runs.
async fn say_serves(shared: Arc<Shared>, mine: Vec<(&str, serde_json::Value)>, mut stopping: watch::Receiver<bool>) {
    let Some(cluster) = &shared.cluster else { return };
    let node = format!("Node/{}", cluster.me.name);
    let mut generation = shared.generation.subscribe();
    loop {
        // (Not known until the store has this node: asked again when the store changes.)
        let says = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let said = |own: &kith_api::Resource, field: &str| {
                own.status
                    .as_ref()
                    .map_or(serde_json::Value::Null, |s| s[field].clone())
            };
            let same = |own: &kith_api::Resource| mine.iter().all(|(field, value)| said(own, field) == *value);
            state.store.get(&node).map(same)
        };
        // Looked at whenever the store changes, not once: a whole-status write to this Node
        // would take it off.
        let wrote = says == Some(false);
        if wrote {
            let fields = mine
                .iter()
                .map(|(field, value)| (field.to_string(), value.clone()))
                .collect();
            let statuses = vec![(node.clone(), fields)];
            if let Err(e) = shared.submit(kith_store::Command::Patch { statuses }).await {
                eprintln!("kithd: serves: saying what this node serves: {e}");
            }
        }
        // No tick: the store's change wakes this. After a write, a rest first, so one that was
        // refused (or a view that has not caught up) is not sent again at every change.
        let rest = async {
            if wrote {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            } else {
                let _ = generation.changed().await;
            }
        };
        tokio::select! {
            () = rest => {}
            _ = stopping.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn nofile_soft_is_the_hard_limit_up_to_65536_and_never_less_than_now() {
        use super::nofile_soft;
        assert_eq!(nofile_soft(1024, 4096), 4096);
        assert_eq!(nofile_soft(1024, 524288), 65536);
        assert_eq!(nofile_soft(1024, 1024), 1024);
        assert_eq!(nofile_soft(100_000, 524288), 100_000);
        assert_eq!(nofile_soft(1024, u64::MAX), 65536);
        assert_eq!(nofile_soft(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn advertise_is_an_address_not_a_name() {
        use clap::Parser;
        let parse = |at: &str| super::Args::try_parse_from(["kithd", "--advertise", at]);
        assert_eq!(parse("[fd00::1]:7443").unwrap().advertise.unwrap().port(), 7443);
        assert!(parse("10.0.0.5:7443").is_ok());
        assert!(parse("node-b.example.org:7443").is_err() && parse("10.0.0.5").is_err());
    }

    /// The ports this node serves on are the ones a pod may not publish here.
    #[test]
    fn the_ports_kithd_serves_on_are_its_own() {
        use clap::Parser;
        let own = |extra: &[&str]| {
            let args = ["kithd"].iter().chain(extra).copied();
            super::own_ports(&super::Args::try_parse_from(args).unwrap())
        };
        assert_eq!(own(&[]), [(7443, "API"), (5000, "registry")]);
        let said = own(&[
            "--listen=0.0.0.0:8443",
            "--dns=0.0.0.0:5353",
            "--registry-port=0",
            "--mesh=51999",
            "--people=51998",
            "--ingress",
        ]);
        let ports: Vec<u16> = said.iter().map(|(port, _)| *port).collect();
        assert_eq!(ports, [8443, 5353, 51999, 51998, 80, 443]);
    }

    /// `--people` needs `--mesh`; its endpoint is a name or an address, with a port; and a kithd
    /// not run as root refuses it by name.
    #[test]
    fn people_flag() {
        use clap::Parser;
        let parse = |args: &[&str]| super::Args::try_parse_from(["kithd"].into_iter().chain(args.iter().copied()));
        let without_mesh = parse(&["--people"]).err().expect("--people needs --mesh").to_string();
        assert!(without_mesh.contains("--mesh"), "{without_mesh}");
        assert_eq!(parse(&["--mesh", "--people"]).unwrap().people, Some(51821));
        assert_eq!(parse(&["--mesh", "--people=40000"]).unwrap().people, Some(40000));
        assert_eq!(parse(&["--mesh"]).unwrap().people, None);
        assert!(parse(&["--mesh", "--people=0"]).is_err(), "the port is from 1 to 65535");
        assert!(parse(&["--mesh", "--people=65535"]).is_ok());
        for bad in [
            "node-a.:51821",
            ".node-a:51821",
            "node..a:51821",
            "-node-a:51821",
            "node-a-:51821",
            "0.0.0.0:51821",
            "[::]:51821",
        ] {
            let endpoint = format!("--people-endpoint={bad}");
            assert!(parse(&["--mesh", "--people", endpoint.as_str()]).is_err(), "{bad}");
        }
        for ok in [
            "node-a.example.org:51821",
            "10.0.0.5:51821",
            "[fd00::1]:51821",
            "a-b.c1:51821",
        ] {
            let endpoint = format!("--people-endpoint={ok}");
            assert!(parse(&["--mesh", "--people", endpoint.as_str()]).is_ok(), "{ok}");
        }
        for bad in ["node-a", ":51821", "node-a:0", "node-a:http"] {
            let endpoint = format!("--people-endpoint={bad}");
            assert!(parse(&["--mesh", "--people", endpoint.as_str()]).is_err(), "{bad}");
        }
        assert!(
            parse(&["--mesh", "--people-endpoint=node-a:51821"]).is_err(),
            "needs --people"
        );
        let refused = super::people_refusal(&parse(&["--mesh", "--people"]).unwrap(), false);
        assert!(refused.is_some_and(|why| why.contains("--people")));
        assert!(super::people_refusal(&parse(&["--mesh", "--people"]).unwrap(), true).is_none());
        assert!(super::people_refusal(&parse(&["--mesh"]).unwrap(), false).is_none());
        // The networks a level may name: CIDRs, comma between, with --people only.
        let nets = parse(&["--mesh", "--people", "--people-networks=192.168.0.0/16,fd00::/8"]).unwrap();
        assert_eq!(nets.people_networks.len(), 2);
        assert!(parse(&["--mesh", "--people"]).unwrap().people_networks.is_empty());
        for bad in [
            "--people-networks=0.0.0.0/0",
            "--people-networks=10.0.0.0",
            "--people-networks=10.0.0.0/33",
        ] {
            assert!(parse(&["--mesh", "--people", bad]).is_err(), "{bad}");
        }
        assert!(
            parse(&["--mesh", "--people-networks=10.0.0.0/8"]).is_err(),
            "needs --people"
        );
    }

    #[test]
    fn a_clash_of_the_pods_range_ends_the_start_only_for_one_named_outside_init() {
        let (default, named) = (kith_mesh::pod::Range::default(), "10.77.0.0/20".parse().unwrap());
        assert!(super::clash_refuses(named, false));
        assert!(!super::clash_refuses(named, true), "as init it would loop the reboot");
        assert!(!super::clash_refuses(default, false) && !super::clash_refuses(default, true));
    }

    #[test]
    fn the_pods_range_is_the_default_or_a_network_the_node_names() {
        use clap::Parser;
        let parse = |args: &[&str]| super::Args::try_parse_from(["kithd"].into_iter().chain(args.iter().copied()));
        assert_eq!(parse(&[]).unwrap().pod_range.to_string(), "100.88.0.0/16");
        assert_eq!(
            parse(&["--pod-range", "10.77.0.0/20"])
                .unwrap()
                .pod_range
                .gateway()
                .to_string(),
            "10.77.0.1"
        );
        let refused = parse(&["--pod-range", "127.0.0.0/16"])
            .err()
            .expect("loopback")
            .to_string();
        assert!(
            refused.contains("--pod-range") && refused.contains("loopback"),
            "{refused}"
        );
        assert!(parse(&["--pod-range", "10.77.0.0/25"]).is_err() && parse(&["--pod-range", "10.77.0.0"]).is_err());
    }

    use super::*;
    use clap::{CommandFactory, FromArgMatches};

    #[test]
    fn unreachable_listen_is_refused_for_a_cluster_maker_on_an_unspecified_address_without_advertise() {
        let any: std::net::SocketAddr = "0.0.0.0:7443".parse().unwrap();
        let some: std::net::SocketAddr = "10.0.0.5:7443".parse().unwrap();
        let why = unreachable_listen(any, false, true).expect("refused");
        assert!(
            why.contains("cannot reach 0.0.0.0:7443") && why.contains("--advertise"),
            "{why}"
        );
        assert!(unreachable_listen("[::]:7443".parse().unwrap(), false, true).is_some());
        // Said where it is, a specific address, or a node that joined (it said where it is by joining).
        assert!(unreachable_listen(any, true, true).is_none());
        assert!(unreachable_listen(some, false, true).is_none());
        assert!(unreachable_listen(any, false, false).is_none());
    }

    /// The `--join` help names both addresses the node may listen on: 0.0.0.0 for a LAN node, and
    /// [::] for a roaming or mesh-joined one (see `listen` in `membership`).
    #[test]
    fn join_help_names_both_binds() {
        let cmd = Args::command();
        let join = cmd.get_arguments().find(|arg| arg.get_id() == "join").expect("--join");
        let help = join.get_help().expect("--join has help").to_string();
        assert!(help.contains("0.0.0.0:7443") && help.contains("[::]:7443"), "{help}");
    }

    #[test]
    fn unreachable_listen_ends_the_start_before_a_cluster_is_made_or_a_port_is_bound() {
        let dir = std::env::temp_dir().join(format!("kith-unreachable-listen-{}", std::process::id()));
        let state = dir.join("state");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let args = |more: &[&str]| {
            let mut all = vec!["kithd", "--state", state.to_str().unwrap(), "--listen"];
            all.extend(more);
            Args::try_parse_from(all)
        };
        let refused = rt.block_on(membership(&args(&["0.0.0.0:0"]).unwrap(), &state)).err();
        assert!(refused.is_some_and(|e| e.contains("--advertise")));
        assert!(!state.join("pki").exists(), "no cluster was made");
        let said = args(&["0.0.0.0:0", "--advertise", "10.0.0.5:7443"]).unwrap();
        assert!(rt.block_on(membership(&said, &state)).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn serves_says_the_dns_port_and_ingress_and_is_null_when_neither_flag_is_given() {
        let dns: std::net::SocketAddr = "192.0.2.1:5353".parse().unwrap();
        assert_eq!(
            serves(Some(dns), true),
            serde_json::json!({ "dns": 5353, "ingress": true })
        );
        assert_eq!(serves(None, true), serde_json::json!({ "ingress": true }));
        assert_eq!(serves(Some(dns), false), serde_json::json!({ "dns": 5353 }));
        // A restart without the flags takes what the last start said off.
        assert_eq!(serves(None, false), serde_json::Value::Null);
    }

    #[test]
    fn serving_lists_the_nodes_that_answer_dns_or_ingress_and_leaves_out_the_unreachable_and_the_unaddressed() {
        use kith_api::{Resource, store::Store};
        let nodes = "\
apiVersion: kith.dev/v1
kind: Node
metadata: { name: a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: c }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: d }
spec: { roaming: true }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: e }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: f }
spec: {}
";
        let mut store = Store::default();
        for resource in Resource::from_source(nodes).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let mut set = |key: &str, status: serde_json::Value| store.set_status(key, Some(status)).unwrap();
        set(
            "Node/a",
            serde_json::json!({ "address": "192.0.2.1:7443", "serves": { "dns": 53, "ingress": true } }),
        );
        set(
            "Node/b",
            serde_json::json!({ "address": "192.0.2.2:7443", "serves": { "ingress": true }, "state": "unreachable" }),
        );
        set(
            "Node/c",
            serde_json::json!({ "address": "[::ffff:198.51.100.3]:7443", "serves": { "dns": 5353 } }),
        );
        set(
            "Node/d",
            serde_json::json!({ "address": "10.8.0.4:7443", "serves": { "dns": 53 } }),
        );
        // An empty `serves` is nothing served; this machine's own address is no place on a LAN.
        set(
            "Node/e",
            serde_json::json!({ "address": "198.51.100.5:7443", "serves": {} }),
        );
        set(
            "Node/f",
            serde_json::json!({ "address": "127.0.0.1:7443", "serves": { "ingress": true } }),
        );
        let serving = store.serving();
        let names: Vec<&str> = serving.iter().map(|node| node.metadata.name.as_str()).collect();
        assert_eq!(names, ["a", "c"]);
        // An IPv4 address seen in IPv6's clothes is the IPv4 one.
        assert_eq!(
            serving[1].lan_address().map(|at| at.to_string()).as_deref(),
            Some("198.51.100.3")
        );
        // A port of 0 is any port: not said.
        let any: std::net::SocketAddr = "192.0.2.1:0".parse().unwrap();
        assert_eq!(serves(Some(any), false), serde_json::Value::Null);
    }

    /// A store with a NodeKey that has an earlier revision (as one written before the limit of one
    /// holds), and a Workload beside it, as text.
    fn old_store_text(wrapped: &str) -> String {
        let key = |wrapped: &str| {
            let id = "ab".repeat(32);
            let text = format!(
                "apiVersion: kith.dev/v1\nkind: NodeKey\nmetadata:\n  name: n1\nspec:\n  id: \"{id}\"\n  wrapped: \"{wrapped}\"\n"
            );
            kith_api::Resource::from_source(&text).unwrap().pop().unwrap().unwrap()
        };
        let mut store = kith_api::store::Store::default();
        store.apply(key(wrapped)).unwrap();
        let web = "apiVersion: kith.dev/v1\nkind: Workload\nmetadata:\n  name: web\nspec:\n  template:\n    containers:\n      - name: web\n        image: nginx:1.27\n";
        store
            .apply(kith_api::Resource::from_source(web).unwrap().pop().unwrap().unwrap())
            .unwrap();
        let mut old = serde_json::to_value(&store).unwrap();
        let first = old["resources"]["NodeKey/n1"][0].clone();
        old["resources"]["NodeKey/n1"].as_array_mut().unwrap().insert(0, first);
        old["resources"]["NodeKey/n1"][0]["resource"]["spec"]["wrapped"] = "deadbeef".repeat(8).into();
        old.to_string()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kithd-imported-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// What the kept file holds is the store as it was, less every NodeKey and its history.
    fn assert_kept_without_node_keys(kept: &std::path::Path, wrapped: &str) {
        let text = std::fs::read_to_string(kept).unwrap();
        for leaked in ["NodeKey", wrapped, "deadbeef"] {
            assert!(!text.contains(leaked), "{leaked} is still in the kept file");
        }
        let store = kith_api::store::FileStore::read(kept).unwrap().store;
        assert_eq!(
            store.history("Workload/default/web").unwrap().len(),
            1,
            "the rest is as it was"
        );
    }

    #[test]
    fn imported_store_holds_no_node_key() {
        let dir = scratch("import");
        let (old, kept) = (dir.join("store.json"), dir.join("store.json.imported"));
        let wrapped = "c0ffee".repeat(10); // pragma: allowlist secret
        std::fs::write(&old, old_store_text(&wrapped)).unwrap();
        keep_imported(&old, &kept).unwrap();
        assert!(!old.exists());
        assert_kept_without_node_keys(&kept, &wrapped);
    }

    #[test]
    fn imported_store_from_an_earlier_version_is_rewritten_at_start_and_a_bad_one_left_alone() {
        let dir = scratch("start");
        let kept = dir.join("store.json.imported");
        let wrapped = "c0ffee".repeat(10); // pragma: allowlist secret
        std::fs::write(&kept, old_store_text(&wrapped)).unwrap();
        strip_node_keys(&kept).unwrap();
        assert_kept_without_node_keys(&kept, &wrapped);
        assert!(!dir.join("store.json.imported.tmp").exists());
        // A second start finds nothing to cut, and does not write.
        let before = std::fs::metadata(&kept).unwrap().modified().unwrap();
        strip_node_keys(&kept).unwrap();
        assert_eq!(std::fs::metadata(&kept).unwrap().modified().unwrap(), before);
        // A file that is not a store stays as it is; a missing one is nothing.
        std::fs::write(&kept, "not json, a NodeKey wrapped").unwrap();
        assert!(strip_node_keys(&kept).is_err());
        assert_eq!(std::fs::read_to_string(&kept).unwrap(), "not json, a NodeKey wrapped");
        assert!(strip_node_keys(&dir.join("absent")).is_ok());
    }

    #[test]
    fn args_from_the_config_give_way_to_the_command_lines_and_lists_stay_lists() {
        let given = "kithd --listen 0.0.0.0:7443 --dns-upstream 9.9.9.9 --listen 127.0.0.1:1 --dns-upstream 1.1.1.1";
        let matched = Args::command()
            .args_override_self(true)
            .try_get_matches_from(given.split(' '))
            .unwrap();
        let args = Args::from_arg_matches(&matched).unwrap();
        assert_eq!(args.dns_upstream, ["9.9.9.9", "1.1.1.1"]);
        assert_eq!(args.listen.map(|at| at.to_string()).as_deref(), Some("127.0.0.1:1"));
    }
}
