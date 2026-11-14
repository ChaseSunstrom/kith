//! Pods: a replica whose template says `pod: true` runs as Kubernetes runs one. Its
//! containers share a network namespace of their own (kith-mesh's `pod`: an address on
//! the mesh, in its node's /80, and one only the node knows for what goes elsewhere), are
//! told where to ask for names (this node's DNS, with the search list Kubernetes gives),
//! and a connection of a Service or a probe is made inside the namespace, to the pod's
//! own loopback.
//!
//! Only where kithd is root. Elsewhere a pod shares the node's network like any replica.
//
// ponytail: a pod's numbers are kept in memory: kithd starts with no containers (it
// removes what an earlier one left), so with no pods. Names of the pods themselves (a
// StatefulSet's `web-0.web`) are not served yet.

use crate::Shared;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{Notify, watch};

struct Pod {
    number: u16,
    namespace: OwnedFd,
    address: IpAddr,
    dir: PathBuf,
}

/// What a container of a pod is given.
pub struct Given {
    /// The pod's network namespace, by a path any process of this machine can open.
    pub netns: PathBuf,
    pub hostname: String,
    /// The pod's `resolv.conf` and `hosts`, for the container's `/etc`.
    pub files: [PathBuf; 2],
}

#[derive(Default)]
pub struct Pods {
    made: BTreeMap<String, Pod>,
    /// Told once the node is ready for pods: its DNS for them starts then.
    up: Arc<Notify>,
}

/// Where the node keeps that it guards what it passes on, until it restarts.
const GUARDED: &str = "/run/kith-pods";

impl Pods {
    /// The pod `id` (of `namespace`, called `hostname`), made if it is not there yet.
    /// `net`: this node's /80 of the mesh, where there is a cluster.
    pub fn given(
        &mut self,
        state: &Path,
        id: &str,
        namespace: &str,
        hostname: &str,
        net: Option<Ipv6Addr>,
    ) -> Result<Given, String> {
        let failed = |e: std::io::Error| format!("the pod's network: {e}");
        if self.made.is_empty() {
            let guarded = kith_mesh::pod::node(Path::new(GUARDED).exists()).map_err(failed)?;
            if guarded {
                let _ = std::fs::write(GUARDED, "");
            }
            self.up.notify_one();
        }
        if !self.made.contains_key(id) {
            let taken: Vec<u16> = self.made.values().map(|pod| pod.number).collect();
            let number = kith_mesh::pod::NUMBERS
                .into_iter()
                .find(|number| !taken.contains(number));
            let number = number.ok_or("this node has no number left for another pod")?;
            let (v4, v6) = kith_mesh::pod::addresses(net, number);
            let address = v6.map_or(IpAddr::V4(v4), IpAddr::V6);
            let dir = state.join("pods").join(id);
            let gateway = kith_mesh::pod::GATEWAY;
            let resolv = format!(
                "nameserver {gateway}\nsearch {namespace}.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n"
            );
            let hosts = format!("127.0.0.1 localhost\n::1 localhost\n{address} {hostname}\n");
            let written = std::fs::create_dir_all(&dir)
                .and_then(|()| std::fs::write(dir.join("resolv.conf"), resolv))
                .and_then(|()| std::fs::write(dir.join("hosts"), hosts));
            written.map_err(|e| format!("{}: {e}", dir.display()))?;
            let namespace = kith_mesh::pod::make(number, v6).map_err(failed)?;
            let pod = Pod {
                number,
                namespace,
                address,
                dir,
            };
            self.made.insert(id.into(), pod);
        }
        let pod = &self.made[id];
        let netns = format!("/proc/{}/fd/{}", std::process::id(), pod.namespace.as_raw_fd());
        Ok(Given {
            netns: netns.into(),
            hostname: hostname.into(),
            files: [pod.dir.join("resolv.conf"), pod.dir.join("hosts")],
        })
    }

    /// Let go of every pod `wanted` does not name: its namespace goes with its last process.
    pub fn keep(&mut self, wanted: impl Fn(&str) -> bool) {
        self.made.retain(|id, pod| {
            let kept = wanted(id);
            if !kept {
                let _ = std::fs::remove_dir_all(&pod.dir);
            }
            kept
        });
    }

    pub fn address(&self, id: &str) -> Option<IpAddr> {
        self.made.get(id).map(|pod| pod.address)
    }
}

/// A connection to `port` of a pod, or (`None`, or a pod with no network of its own) of
/// this machine: on the loopback either way, so what listens only there is reached.
//
// ponytail: a thread is started and ended for every connection into a pod (the socket has
// to be made inside its namespace). Sockets made ahead, or the kernel passing the
// connection on (services.rs's own note), when a node's Services are that busy.
pub async fn connect(pod: Option<(&Shared, &str)>, port: u16) -> std::io::Result<TcpStream> {
    let socket = |v4: bool| -> std::io::Result<TcpSocket> {
        let make = || if v4 { TcpSocket::new_v4() } else { TcpSocket::new_v6() };
        let Some((shared, id)) = pod else { return make() };
        let pods = shared.pods.lock().expect("nothing panics holding the pods");
        match pods.made.get(id) {
            Some(pod) => kith_mesh::pod::within(&pod.namespace, make)?,
            None => make(),
        }
    };
    match socket(true)?.connect((Ipv4Addr::LOCALHOST, port).into()).await {
        Ok(stream) => Ok(stream),
        Err(_) => socket(false)?.connect((Ipv6Addr::LOCALHOST, port).into()).await,
    }
}

/// This node's DNS for its pods, from the first pod on: at the address every pod is told.
pub async fn names(shared: Arc<Shared>, upstreams: Vec<std::net::SocketAddr>, mut stopping: watch::Receiver<bool>) {
    let up = shared.pods.lock().expect("nothing panics holding the pods").up.clone();
    tokio::select! {
        () = up.notified() => {}
        _ = stopping.changed() => return,
    }
    match crate::dns::bind((kith_mesh::pod::GATEWAY, 53).into()).await {
        Ok(sockets) => crate::dns::run(shared, sockets, upstreams, stopping).await,
        // (A `--dns` on every address has this one too.)
        Err(e) => eprintln!("kithd: no DNS of the pods' own: {e}"),
    }
}
