//! `kithd`, in agent mode (PLAN.md §4.1): a service on an existing distro that
//! owns the store, serves the API and runs workloads on this one node.
//!
//! The API is HTTP/JSON on a unix socket only its owner can open. With
//! `--listen` it is also served to other nodes over TLS, and `--join` makes
//! this node a member of another node's cluster (see `cluster.rs`).

mod api;
mod cluster;
mod controller;
mod pki;
mod probe;

use clap::Parser;
use kith_api::store::FileStore;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, watch};

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
}

/// What the API handlers and the controller share.
pub struct Shared {
    pub store: Mutex<FileStore>,
    /// Poked after every change to the store, so the controller reconciles at once.
    pub changed: Notify,
    /// Where the output of every unit goes: `<unit id>.out` and `.err`.
    pub logs: PathBuf,
    /// Counts changes to the store, for `GET /v1/watch`. Bumped while holding the store
    /// lock, so a reader under the lock sees the generation that matches what it reads.
    /// Starts at the clock (ms) so a restarted kithd never repeats a number a client holds.
    pub generation: watch::Sender<u64>,
    /// `None` in agent mode: one node, nothing on the network.
    pub cluster: Option<cluster::Cluster>,
}

impl Shared {
    pub fn bump(&self) {
        self.generation.send_modify(|g| *g += 1);
    }
}

fn main() -> ExitCode {
    // Started again by the runtime as an exec unit's helper? Then this never returns.
    kith_runtime::exec_shim();
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("kithd: {msg}");
            ExitCode::FAILURE
        }
    }
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
    let listen = args.listen.unwrap_or(([0, 0, 0, 0], 7443).into());
    let tcp = tokio::net::TcpListener::bind(listen).await;
    let tcp = tcp.map_err(|e| format!("listening on {listen}: {e}"))?;
    let leader_file = dir.join("leader");
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
        let leader = std::fs::read_to_string(&leader_file).ok();
        if ca.is_none() && leader.is_none() {
            let dir = dir.display();
            return Err(format!(
                "{dir} is incomplete (a join was interrupted): remove it and join again"
            ));
        }
        return Ok((Some(cluster::Cluster::new(me, ca, leader)?), Some(tcp)));
    }
    let name = match &args.name {
        Some(name) => name.clone(),
        None => {
            let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
            hostname.trim().to_ascii_lowercase()
        }
    };
    pki::valid_name(&name).map_err(|e| format!("{e} (set --name)"))?;
    let (me, ca, leader) = match &args.join {
        Some(address) => {
            let port = tcp.local_addr().map_err(|e| e.to_string())?.port();
            let token = args.token.as_deref().expect("clap requires --token with --join");
            let joined = cluster::request_join(address, token, &name, port).await?;
            eprintln!("kithd: joined the cluster of {address} as node {name}");
            let me = pki::Identity {
                name,
                ca: joined.ca,
                cert: joined.cert,
                key: joined.key,
            };
            (me, None, Some(address.clone()))
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
            (me, Some(ca), None)
        }
    };
    // The identity last: its presence is what a restart takes for a finished join.
    if let Some(leader) = &leader {
        let made = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&leader_file, leader));
        made.map_err(|e| format!("writing {}: {e}", leader_file.display()))?;
    }
    pki::save(&dir, &me, ca.as_ref())?;
    Ok((Some(cluster::Cluster::new(me, ca, leader)?), Some(tcp)))
}

fn run(args: Args) -> Result<(), String> {
    let state = args
        .state
        .clone()
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
    let store = FileStore::open_owned(&state.join("store.json")).map_err(|e| e.to_string())?;
    // Nobody answered and the state is ours: a socket here is a dead kithd's. Anything else is not ours to remove.
    use std::os::unix::fs::FileTypeExt;
    if std::fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket()) {
        let _ = std::fs::remove_file(&socket);
    }
    let runtime = kith_runtime::Runtime::new(state.join("runtime"));

    // One thread: kithd forks containers, and a small idle footprint is the point (§3.2).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| fail("starting", &e))?;
    let (membership, tcp) = rt.block_on(membership(&args, &state))?;
    let shared = Arc::new(Shared {
        cluster: membership,
        store: Mutex::new(store),
        changed: Notify::new(),
        logs: state.join("logs"),
        generation: watch::channel(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
        )
        .0,
    });

    let served = rt.block_on(async {
        // ponytail: bound, then made owner-only. The directory kithd creates for it is
        // already 0700; in a shared directory there is a moment in between (umask needs libc).
        let listener = tokio::net::UnixListener::bind(&socket).map_err(|e| fail("binding the socket", &e))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| fail("securing the socket", &e))?;
        eprintln!("kithd: serving {} (state in {})", socket.display(), state.display());

        let (stop, stopping) = watch::channel(false);
        let watched = shared.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let (mut term, mut int) = (
                signal(SignalKind::terminate()).unwrap(),
                signal(SignalKind::interrupt()).unwrap(),
            );
            tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            let _ = stop.send(true);
            // Shutdown waits for open requests: wake the long-polls so it does not wait out their timeout.
            watched.bump();
        });
        let mut server_stop = stopping.clone();
        let local = cluster::local_router(shared.clone()).merge(cluster::admin_router(shared.clone()));
        let server =
            axum::serve(listener, local).with_graceful_shutdown(async move { drop(server_stop.changed().await) });
        // The same API for other nodes, over TLS.
        let nodes = async {
            let (Some(cluster), Some(tcp)) = (&shared.cluster, tcp) else {
                return Ok(());
            };
            let address = tcp.local_addr().map_err(|e| fail("listening", &e))?;
            if cluster.leader.is_none() {
                if address.ip().is_unspecified() && args.advertise.is_none() {
                    return Err(format!(
                        "other nodes cannot reach {address}: say where this node is with --advertise ADDR:PORT"
                    ));
                }
                let reachable = args.advertise.clone().unwrap_or(address.to_string());
                cluster::register(&shared, &cluster.me.name, &reachable).map_err(|e| e.to_string())?;
            }
            eprintln!("kithd: node {} serving other nodes on {address}", cluster.me.name);
            let listener = cluster::listen(tcp, pki::server_config(&cluster.me)?).map_err(|e| fail("listening", &e))?;
            let app = cluster::node_router(shared.clone()).into_make_service_with_connect_info::<cluster::Peer>();
            let mut stop = stopping.clone();
            let served = axum::serve(listener, app).with_graceful_shutdown(async move { drop(stop.changed().await) });
            served.await.map_err(|e| fail("serving other nodes", &e))
        };
        let work = async {
            // A node that joined forwards its API and is not given workloads yet (see cluster.rs).
            if !shared.cluster.as_ref().is_some_and(|cluster| cluster.leader.is_some()) {
                controller::run(shared.clone(), runtime, args.log_cap, stopping.clone()).await;
            }
        };
        let (served, nodes, ()) = tokio::join!(server, nodes, work);
        served.map_err(|e| fail("serving", &e)).and(nodes)
    });
    let _ = std::fs::remove_file(&socket);
    served
}
