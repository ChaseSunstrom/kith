//! `kithd`, in agent mode (PLAN.md §4.1): a service on an existing distro that
//! owns the store, serves the API and runs workloads on this one node.
//!
//! The API is HTTP/JSON on a unix socket only its owner can open. gRPC and
//! mTLS over the mesh arrive with the second node (Phase 2).

mod api;
mod controller;

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
}

/// What the API handlers and the controller share.
pub struct Shared {
    pub store: Mutex<FileStore>,
    /// Poked after every change to the store, so the controller reconciles at once.
    pub changed: Notify,
}

fn main() -> ExitCode {
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

fn run(args: Args) -> Result<(), String> {
    let state = args
        .state
        .or_else(default_state)
        .ok_or("no state directory: set --state")?;
    let socket = args
        .socket
        .or_else(kith_api::default_socket)
        .ok_or("no socket path: set --socket")?;
    let fail = |what: &str, e: &dyn std::fmt::Display| format!("{what}: {e}");

    if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
        return Err(format!("another kithd is already serving {}", socket.display()));
    }
    // Nobody answered: a socket here is a dead kithd's. Anything else is not ours to remove.
    use std::os::unix::fs::FileTypeExt;
    if std::fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket()) {
        let _ = std::fs::remove_file(&socket);
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
    let store = FileStore::open(&state.join("store.json")).map_err(|e| e.to_string())?;
    let runtime = kith_runtime::Runtime::new(state.join("runtime"));
    let shared = Arc::new(Shared {
        store: Mutex::new(store),
        changed: Notify::new(),
    });

    // One thread: kithd forks containers, and a small idle footprint is the point (§3.2).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| fail("starting", &e))?;
    let served = rt.block_on(async {
        // ponytail: bound, then made owner-only. The directory kithd creates for it is
        // already 0700; in a shared directory there is a moment in between (umask needs libc).
        let listener = tokio::net::UnixListener::bind(&socket).map_err(|e| fail("binding the socket", &e))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| fail("securing the socket", &e))?;
        eprintln!("kithd: serving {} (state in {})", socket.display(), state.display());

        let (stop, stopping) = watch::channel(false);
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let (mut term, mut int) = (
                signal(SignalKind::terminate()).unwrap(),
                signal(SignalKind::interrupt()).unwrap(),
            );
            tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            let _ = stop.send(true);
        });
        let mut server_stop = stopping.clone();
        let server = axum::serve(listener, api::router(shared.clone()))
            .with_graceful_shutdown(async move { drop(server_stop.changed().await) });
        let (served, ()) = tokio::join!(
            server,
            controller::run(shared.clone(), runtime, state.join("logs"), stopping)
        );
        served.map_err(|e| fail("serving", &e))
    });
    let _ = std::fs::remove_file(&socket);
    served
}
