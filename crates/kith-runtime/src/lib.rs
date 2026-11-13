//! kith's workload runtime (PLAN.md §4.5), containers only for now.
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
mod image;

pub use container::{Awaited, Handle, Runtime, Unit, exec_shim, reap_orphans, spawn_awaited};
pub use image::{Image, ImageStore, PullPolicy};

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
