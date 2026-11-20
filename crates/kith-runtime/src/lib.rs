//! kith's workload runtime (PLAN.md §4.5): containers and exec units. (Virtual
//! machines are kithd's own: `crates/kithd/src/vm.rs`.)
//!
//! - [`ImageStore`] pulls OCI images into a content-addressed blob store and
//!   unpacks each image once.
//! - [`Runtime`] runs a container from an image in its own cgroup, through
//!   youki's `libcontainer` used as a library: no containerd, no shim process.
//!   It also runs exec units: plain host processes in a cgroup, for host-level tools.
//!
//! It works unprivileged (user namespace, delegated cgroup), which is how the
//! tests run it, and is meant to work as root; the root path is not tested yet.

mod container;
mod devfilter;
mod image;
mod keyless;
mod outside;
mod seccomp;
pub mod signed;

pub use container::{
    Awaited, Handle, Left, Mount, NODE_ROOT, ROOTS, Runtime, Undeleted, Unit, container_nofile, exec_shim,
    has_delegated_cgroup, plugged, reap_orphans, spawn_awaited, started, tune,
};
pub use image::{Image, ImageStore, Local, PullPolicy, Unpacking, registry, repository, sha256_hex};
pub use outside::{Patience, read_capped};
pub use seccomp::REFUSED;

/// Where a node's first process (kithd's keeper) writes how each process it reaped ended, one
/// file per pid holding the code (128 + the signal for one killed) and the process's start
/// time ([`started`]): a unit kithd took back after a restart is no child of the kithd that
/// waits for it, and one may end while no kithd runs.
pub const EXITS: &str = "/run/kith/exits";

#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// `.ctx("unpacking layer")?` turns any error into `unpacking layer: <cause>`.
pub(crate) trait Context<T> {
    fn ctx(self, what: impl std::fmt::Display) -> Result<T>;
}

impl<T, E: std::fmt::Display> Context<T> for std::result::Result<T, E> {
    fn ctx(self, what: impl std::fmt::Display) -> Result<T> {
        self.map_err(|e| Error(format!("{what}: {e}")))
    }
}

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error(msg.into()))
}
