//! `kithd`, in agent mode (PLAN.md §4.1): a service on an existing distro that
//! owns the store, serves the API and runs workloads on this one node.
//!
//! The API is HTTP/JSON on a unix socket only its owner can open. With
//! `--listen` it is also served to other nodes over TLS, and `--join` makes
//! this node a member of another node's cluster (see `cluster.rs`). The store is
//! a Raft replica either way (`raft.rs`): alone, this node is all of its voters.

mod acme;
mod api;
mod cluster;
mod controller;
mod dns;
mod ingress;
mod members;
mod mesh;
mod pki;
mod probe;
mod raft;
mod registry;
mod releases;
mod sched;
mod services;

use clap::Parser;
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
    /// Join the cluster's WireGuard mesh, on this UDP port (needs CAP_NET_ADMIN)
    #[arg(long, env = "KITH_MESH", value_name = "PORT", num_args = 0..=1, default_missing_value = "51820")]
    mesh: Option<u16>,
    /// The name of the mesh's network interface
    #[arg(long, env = "KITH_MESH_INTERFACE", value_name = "NAME", default_value = "kith0")]
    mesh_interface: String,
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

/// What the API handlers and the controller share.
pub struct Shared {
    /// This node's copy of the store, to read. Changes go through [`Shared::submit`].
    pub store: Arc<Mutex<kith_store::State>>,
    pub raft: kith_store::Raft,
    /// Poked after every change to the store, so the controller reconciles at once.
    pub changed: Arc<Notify>,
    /// Where the output of every unit goes: `<unit id>.out` and `.err`.
    pub logs: PathBuf,
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
            let joined = cluster::request_join(address, token, &name, port).await?;
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
        generation,
        members: members::Members::new(name),
        mesh: Mutex::default(),
        cluster,
        stop: watch::channel(false).0,
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
        eprintln!("kithd: serving {} (state in {})", socket.display(), state.display());

        let stopping = shared.stop.subscribe();
        let watched = shared.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let (mut term, mut int) = (
                signal(SignalKind::terminate()).unwrap(),
                signal(SignalKind::interrupt()).unwrap(),
            );
            tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            watched.stop.send_replace(true);
        });
        let mut server_stop = stopping.clone();
        let local = api::router(shared.clone()).merge(cluster::admin_router(shared.clone()));
        let server =
            axum::serve(listener, local).with_graceful_shutdown(async move { drop(server_stop.changed().await) });
        // The same API for other nodes, over TLS.
        let nodes = async {
            let (Some(cluster), Some(tcp)) = (&shared.cluster, tcp) else {
                return Ok(());
            };
            let address = tcp.local_addr().map_err(|e| fail("listening", &e))?;
            if address.ip().is_unspecified() && args.advertise.is_none() && cluster.ca.is_some() {
                return Err(format!(
                    "other nodes cannot reach {address}: say where this node is with --advertise ADDR:PORT"
                ));
            }
            eprintln!("kithd: node {} serving other nodes on {address}", cluster.me.name);
            let listener = cluster::listen(tcp, pki::server_config(&cluster.me)?).map_err(|e| fail("listening", &e))?;
            let app = cluster::node_router(shared.clone()).into_make_service_with_connect_info::<cluster::Peer>();
            let mut stop = stopping.clone();
            let served = axum::serve(listener, app).with_graceful_shutdown(async move { drop(stop.changed().await) });
            let members = raft::tend_members(shared.clone(), stopping.clone());
            // The node the cluster started on says where it is; one that joined was written down as it did.
            // ponytail: so a joined node that moves has to be deleted and joined again.
            let registered = async {
                if cluster.ca.is_some() {
                    let reachable = args.advertise.clone().unwrap_or(address.to_string());
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
            tokio::join!(units, releases, repositories);
        };
        let names = async {
            if let Some(sockets) = names {
                dns::run(shared.clone(), sockets, upstreams, stopping.clone()).await;
            }
        };
        let mesh = async {
            if let Some(port) = args.mesh {
                let options = mesh::Options {
                    interface: args.mesh_interface.clone(),
                    port,
                    key: state.join("pki").join("mesh.key"),
                };
                mesh::run(shared.clone(), options, stopping.clone()).await;
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
