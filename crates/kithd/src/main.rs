//! `kithd`, in agent mode (PLAN.md §4.1): a service on an existing distro that
//! owns the store, serves the API and runs workloads on this one node.
//!
//! The API is HTTP/JSON on a unix socket only its owner can open. With
//! `--listen` it is also served to other nodes over TLS, and `--join` makes
//! this node a member of another node's cluster (see `cluster.rs`). The store is
//! a Raft replica either way (`raft.rs`): alone, this node is all of its voters.

mod access;
mod acme;
mod api;
mod audit;
mod cluster;
mod controller;
mod controllers;
mod crypt;
mod dhcp;
mod dns;
mod ingress;
mod init;
mod install;
mod members;
mod mesh;
mod netboot;
mod os;
mod pki;
mod probe;
mod raft;
mod registry;
mod releases;
mod sched;
mod services;
mod sources;
mod ui;
mod update;
mod wasm;

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
    /// Serve the API to other nodes on this address (TLS); the first start makes this node a cluster of one
    #[arg(long, env = "KITH_LISTEN", value_name = "ADDR:PORT")]
    listen: Option<std::net::SocketAddr>,
    /// Join the cluster of the node at this address (needs --token; listens on 0.0.0.0:7443 unless --listen says otherwise)
    #[arg(long, env = "KITH_JOIN", value_name = "ADDR:PORT", requires = "token")]
    join: Option<String>,
    /// A join token, from `kith node token` on a node of that cluster
    #[arg(long, env = "KITH_TOKEN", value_name = "TOKEN")]
    token: Option<String>,
    /// This node's name in the cluster [default: the hostname]
    #[arg(long, env = "KITH_NAME", value_name = "NAME")]
    name: Option<String>,
    /// The address other nodes reach this one at, when it is not the one it listens on
    #[arg(long, env = "KITH_ADVERTISE", value_name = "ADDR:PORT")]
    advertise: Option<String>,
    /// While the cluster has no Identity, print a one-time token at start: whoever sends it to /v1/claim on --listen becomes its admin (for a node nobody can log in to)
    #[arg(long, env = "KITH_CLAIM")]
    claim: bool,
    /// Serve DNS here, on UDP and TCP: node names, DNSZone and DNSRecord resources, and the rest from upstream
    #[arg(long, env = "KITH_DNS", value_name = "ADDR:PORT")]
    dns: Option<std::net::SocketAddr>,
    /// Resolvers for names that are not ours, in the order tried [default: those in /etc/resolv.conf]
    #[arg(long, env = "KITH_DNS_UPSTREAM", value_name = "ADDR[:PORT]", value_delimiter = ',')]
    dns_upstream: Vec<String>,
    /// Seconds a node may be out of contact before what it runs is started on other nodes
    #[arg(long, env = "KITH_LOST_AFTER", value_name = "SECONDS", default_value_t = 300)]
    lost_after: u64,
    /// Seconds between asking registries for newer packages (for Releases that name a Repository)
    #[arg(long, env = "KITH_REPOSITORY_POLL", value_name = "SECONDS", default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    repository_poll: u64,
    /// A key (hex) this node takes kith OS releases from; repeat for more. Without one,
    /// the key of the first release it updates to is kept, and only that one is taken after
    #[arg(long, env = "KITH_RELEASE_KEY", value_name = "KEY", value_delimiter = ',', value_parser = release_key)]
    release_key: Vec<String>,
    /// Let a Source name a git repository on this machine (`file://`): for tests
    #[arg(long, hide = true)]
    local_sources: bool,
    /// Join the cluster's WireGuard mesh, on this UDP port (needs CAP_NET_ADMIN)
    #[arg(long, env = "KITH_MESH", value_name = "PORT", num_args = 0..=1, default_missing_value = "51820")]
    mesh: Option<u16>,
    /// The name of the mesh's network interface
    #[arg(long, env = "KITH_MESH_INTERFACE", value_name = "NAME", default_value = "kith0")]
    mesh_interface: String,
    /// With --join: this node comes and goes (a laptop). It is reached on the mesh wherever it is,
    /// never votes, and what it runs is not started elsewhere while it is away
    #[arg(long, env = "KITH_ROAMING", requires_all = ["join", "mesh"])]
    roaming: bool,
    /// Serve HTTPS (port 443, and 80) for Services with `expose`; for edge nodes
    #[arg(long, env = "KITH_INGRESS", requires = "mesh")]
    ingress: bool,
    /// Get the certificates for exposed hosts from this ACME directory (Let's Encrypt
    /// if none is named); giving this agrees to that authority's terms
    #[arg(
        long,
        env = "KITH_ACME",
        value_name = "URL",
        requires = "ingress",
        num_args = 0..=1,
        default_missing_value = "https://acme-v02.api.letsencrypt.org/directory"
    )]
    acme: Option<String>,
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
    pub audit: audit::Audit,
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
    /// Dry runs (`/v1/diff`, `apply?dryRun`) at once, from asking admission to the answer:
    /// the page asks on every edit, and each asks the kinds' WASM. The rest wait their turn.
    pub dry_runs: tokio::sync::Semaphore,
}

/// How many dry runs at once.
const DRY_RUNS: usize = 4;

fn main() -> ExitCode {
    // Started again by the runtime as an exec unit's helper? Then this never returns.
    kith_runtime::exec_shim();
    let first = init::is_init();
    let mut boot = first.then(init::early);
    if let Some(source) = boot.as_mut().and_then(|boot| boot.install.take()) {
        installer(boot.expect("there is one"), source);
    }
    // (As the first process, a mistake in its arguments is clap's to say, and then a restart.)
    let args = if first {
        use clap::{CommandFactory, FromArgMatches};
        // What the node's config says, then the command line's own, which is the last word.
        let mut given = init::arguments(std::env::args());
        let config = boot
            .as_mut()
            .map(|boot| std::mem::take(&mut boot.args))
            .unwrap_or_default();
        given.splice(1..1, config);
        let matched = Args::command().args_override_self(true).try_get_matches_from(given);
        matched
            .and_then(|matched| Args::from_arg_matches(&matched))
            .map_err(|e| e.to_string())
    } else {
        Ok(Args::parse())
    };
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

/// SIGTERM and SIGINT, heard from here on (one that comes before it is read is kept).
/// Call inside the runtime.
fn stops() -> std::io::Result<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)> {
    use tokio::signal::unix::{SignalKind, signal};
    Ok((signal(SignalKind::terminate())?, signal(SignalKind::interrupt())?))
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
            if state.join("raft").exists() || state.join("store.json").exists() {
                return Err(format!(
                    "{} already holds a store, which joining would discard: join with an empty --state",
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
            let joined = cluster::request_join(address, token, &name, port, mesh).await?;
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
async fn replica(cluster: Option<cluster::Cluster>, state: &std::path::Path) -> Result<Arc<Shared>, String> {
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
    let network = raft::Network(cluster.as_ref().map(|cluster| cluster.client.clone()));
    let replica = kith_store::open(&state.join("raft"), kith_store::node_id(name), network, poke).await?;
    let shared = Arc::new(Shared {
        store: replica.state,
        raft: replica.raft,
        changed,
        logs: state.join("logs"),
        audit: audit::Audit::new(state.join("audit.log")),
        wasm: Arc::default(),
        generation,
        members: members::Members::new(name),
        mesh: Mutex::default(),
        cluster,
        stop: watch::channel(false).0,
        dry_runs: tokio::sync::Semaphore::new(DRY_RUNS),
    });
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
    let old = state.join("store.json");
    if old.exists() {
        let empty = shared.store.lock().expect("nothing panics holding the store").store == Default::default();
        if empty {
            let store = kith_api::store::FileStore::read(&old).map_err(|e| e.to_string())?.store;
            let imported = shared.submit(kith_store::Command::Import { store }).await;
            imported.map_err(|e| format!("bringing in {}: {e}", old.display()))?;
            // Left in place it would come in again, should the store ever be empty.
            std::fs::rename(&old, state.join("store.json.imported")).map_err(|e| {
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

fn run(args: Args, mut boot: Option<init::Boot>) -> Result<(), String> {
    // One thread: kithd forks containers, and a small idle footprint is the point (§3.2).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("starting: {e}"))?;
    let first_process = boot.is_some();
    let sealed = boot.as_mut().and_then(|boot| boot.sealed.take());
    // As the first process, SIGTERM and Ctrl-Alt-Del are heard from the start: the kernel
    // drops what process 1 does not handle. (Anywhere else the default, which ends kithd, stays until serving.)
    let mut early = None;
    if let Some(boot) = boot {
        let _in = rt.enter();
        early = stops().ok();
        boot.network();
    }
    // An encrypted state is opened with a key the cluster holds: nothing below can be
    // done before that, and it takes as long as it takes. A stop that comes meanwhile ends it.
    //
    // ponytail: past this, a stop waits for the serving below (the membership and the replica
    // open in moments, not as long as a key); it is kept until then.
    let mut opened = None;
    if let Some((record, _)) = &sealed {
        let key = crypt::open(record, args.join.as_ref());
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
    // Nobody answered and the state is ours: a socket here is a dead kithd's. Anything else is not ours to remove.
    use std::os::unix::fs::FileTypeExt;
    if std::fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket()) {
        let _ = std::fs::remove_file(&socket);
    }
    let runtime = kith_runtime::Runtime::new(state.join("runtime"));

    let upstream = |address: &String| {
        let with_port = address.parse().ok();
        let bare = || address.parse().ok().map(|ip| std::net::SocketAddr::new(ip, 53));
        with_port
            .or_else(bare)
            .ok_or(format!("--dns-upstream: `{address}` is not an address"))
    };
    let mut upstreams = args.dns_upstream.iter().map(upstream).collect::<Result<Vec<_>, _>>()?;
    if upstreams.is_empty() {
        upstreams = dns::system_upstreams();
    }
    let (membership, tcp) = rt.block_on(membership(&args, &state))?;
    let names = rt.block_on(async {
        match args.dns {
            Some(listen) => dns::bind(listen).await.map(Some),
            None => Ok(None),
        }
    })?;
    let shared = rt.block_on(replica(membership, &state))?;

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
            watched.stop.send_replace(true);
        });
        let mut server_stop = stopping.clone();
        // Whoever can open the socket is the machine's admin.
        let local = api::router(shared.clone())
            .layer(axum::Extension(access::Caller::Admin))
            .merge(cluster::admin_router(shared.clone()))
            .merge(ui::pages());
        let server =
            axum::serve(listener, local).with_graceful_shutdown(async move { drop(server_stop.changed().await) });
        // The same API for other nodes, over TLS.
        let nodes = async {
            let (Some(cluster), Some(tcp)) = (&shared.cluster, tcp) else {
                return Ok(());
            };
            let address = tcp.local_addr().map_err(|e| fail("listening", &e))?;
            // A machine that asked its network for an address says the one it was given.
            let mut advertise = args.advertise.clone();
            if first_process && advertise.is_none() && address.ip().is_unspecified() && cluster.ca.is_some() {
                for _ in 0..600 {
                    if init::ADDRESS.get().is_some() || *stopping.borrow() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                advertise = init::ADDRESS.get().map(|ip| format!("{ip}:{}", address.port()));
            }
            if address.ip().is_unspecified() && advertise.is_none() && cluster.ca.is_some() {
                return Err(format!(
                    "other nodes cannot reach {address}: say where this node is with --advertise ADDR:PORT"
                ));
            }
            if args.claim {
                cluster::offer_claim(&shared);
            }
            eprintln!("kithd: node {} serving other nodes on {address}", cluster.me.name);
            let _ = netboot::PORT.set(address.port());
            let listener = cluster::listen(tcp, pki::server_config(&cluster.me)?).map_err(|e| fail("listening", &e))?;
            let app = cluster::node_router(shared.clone()).into_make_service_with_connect_info::<cluster::Peer>();
            let mut stop = stopping.clone();
            let served = axum::serve(listener, app).with_graceful_shutdown(async move { drop(stop.changed().await) });
            let members = raft::tend_members(shared.clone(), stopping.clone());
            // The node the cluster started on says where it is; one that joined was written down as it did.
            // ponytail: so a joined node that moves has to be deleted and joined again.
            let registered = async {
                if cluster.ca.is_some() {
                    let reachable = advertise.clone().unwrap_or(address.to_string());
                    let id = shared.raft.metrics().borrow().id;
                    // Not fatal: the address the cluster has for this node is the one from last time.
                    if let Err(e) = cluster::register(&shared, &cluster.me.name, &reachable, id).await {
                        eprintln!("kithd: telling the cluster this node is at {reachable}: {e}");
                    }
                }
            };
            let pings = members::run(shared.clone(), stopping.clone());
            let lost_after = std::time::Duration::from_secs(args.lost_after);
            let scheduler = sched::run(shared.clone(), lost_after, stopping.clone());
            let (served, (), (), (), ()) = tokio::join!(served, members, registered, pings, scheduler);
            served.map_err(|e| fail("serving other nodes", &e))
        };
        let work = async {
            let releases = releases::run(shared.clone(), stopping.clone());
            let poll = std::time::Duration::from_secs(args.repository_poll);
            let repositories = registry::run(shared.clone(), poll, stopping.clone());
            let units = controller::run(shared.clone(), runtime, args.log_cap, stopping.clone());
            let sources = sources::run(shared.clone(), state.clone(), args.local_sources, stopping.clone());
            let controllers = controllers::run(shared.clone(), stopping.clone());
            let plans = update::run(shared.clone(), stopping.clone());
            let system = update::node(
                shared.clone(),
                state.clone(),
                args.release_key.clone(),
                stopping.clone(),
            );
            let key = async {
                if let Some(((record, config), opened)) = sealed.zip(opened) {
                    crypt::keep(shared.clone(), config, record, opened, stopping.clone()).await;
                }
            };
            tokio::join!(units, releases, repositories, sources, controllers, plans, system, key);
        };
        let names = async {
            if let Some(sockets) = names {
                dns::run(shared.clone(), sockets, upstreams, stopping.clone()).await;
            }
        };
        let mesh = async {
            if let Some(port) = args.mesh {
                mesh::run(shared.clone(), mesh_options(&args, &state, port), stopping.clone()).await;
            } else {
                mesh::left(shared.clone(), stopping.clone()).await;
            }
        };
        let (strays, taken) = tokio::sync::mpsc::unbounded_channel();
        let taken = args.ingress.then_some(taken);
        let proxy = async {
            if let Some(port) = args.mesh {
                services::run(shared.clone(), port, taken, stopping.clone()).await;
            }
        };
        let ingress = async {
            if args.ingress {
                ingress::run(shared.clone(), args.acme.clone(), strays, stopping.clone()).await;
            }
        };
        let (served, nodes, (), (), (), (), ()) = tokio::join!(server, nodes, work, names, mesh, proxy, ingress);
        let _ = shared.raft.shutdown().await;
        served.map_err(|e| fail("serving", &e)).and(nodes)
    });
    let _ = std::fs::remove_file(&socket);
    served
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};

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
