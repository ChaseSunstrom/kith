//! kithd's DNS server (`--dns ADDR:PORT`): what it answers comes from the store.
//!
//! - `<node>.node.kith`: the address each Node is reached at; `<node>.mesh.kith`: its
//!   address on the mesh, if it is on it; `<service>.<namespace>.kith`: a Service's
//!   address on the mesh.
//! - `DNSZone` and `DNSRecord`: names of your own. A zone with `clients` is split
//!   horizon: clients in those networks get it, and not a zone for everyone with the
//!   same domain.
//! - Every other name goes to the upstream resolvers, for clients on private networks.
//!
//! The server itself is the `kith-dns` crate; this builds its zones again whenever a
//! resource they are made from changes, and reports on each DNSZone and DNSRecord.
//
// ponytail: a client inside two zones' different `clients` lists gets only the first
// of them by name; give zones that belong together the same list.

use crate::{Shared, ingress};
use kith_api::Resource;
use kith_api::kinds::{DnsRecordSpec, DnsRecordType, DnsZoneSpec, ServiceSpec};
use kith_api::store::Store;
use kith_dns::{Cidr, Rdata, Record, Records, View, Zones};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

/// Seconds an answer may be kept when neither the record nor its zone says.
const TTL: u32 = 300;
/// Node addresses change when a node moves: resolvers ask again soon.
const NODE_TTL: u32 = 30;

fn soa(domain: &str) -> Record {
    let data = Rdata::Soa {
        mname: format!("ns.{domain}"),
        rname: format!("hostmaster.{domain}"),
        serial: 1,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        // How long "no such name" may be kept.
        minimum: 60,
    };
    let (name, ttl) = (domain.to_string(), TTL);
    Record { name, ttl, data }
}

/// One DNSZone and the records in it that could be read.
struct Zone {
    domain: String,
    clients: Vec<String>,
    ttl: u32,
    records: Vec<Record>,
}

fn spec<S: serde::de::DeserializeOwned>(resource: &Resource) -> Result<S, String> {
    serde_json::from_value(resource.spec.clone()).map_err(|e| format!("cannot read this {}: {e}", resource.kind))
}

/// The records one DNSRecord stands for, in the zone with this `domain` and default `ttl`.
fn records_of(record: &DnsRecordSpec, domain: &str, ttl: u32) -> Result<Vec<Record>, String> {
    let name = match record.name.as_str() {
        "@" => domain.to_string(),
        name => format!("{name}.{domain}"),
    };
    let full = |value: &str| value.trim_end_matches('.').to_string();
    let one = |value: &String| {
        let bad = || format!("`{value}` is not a value for this type");
        let data = match record.record_type {
            DnsRecordType::A => Rdata::A(value.parse().map_err(|_| bad())?),
            DnsRecordType::Aaaa => Rdata::Aaaa(value.parse().map_err(|_| bad())?),
            DnsRecordType::Cname => Rdata::Cname(full(value)),
            DnsRecordType::Ns => Rdata::Ns(full(value)),
            DnsRecordType::Ptr => Rdata::Ptr(full(value)),
            DnsRecordType::Txt => Rdata::Txt(value.clone()),
            DnsRecordType::Srv => {
                let (priority, weight, port, target) = DnsRecordSpec::srv(value).ok_or_else(bad)?;
                let target = full(target);
                Rdata::Srv {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
        };
        let (name, ttl) = (name.clone(), record.ttl.unwrap_or(ttl));
        Ok(Record { name, ttl, data })
    };
    record.values.iter().map(one).collect()
}

/// The kinds the zones are made of (see [`zones_made_of`]).
const ZONE_KINDS: [&str; 6] = ["Node", "Service", "Workload", "DNSZone", "DNSRecord", "Namespace"];

#[cfg(test)]
thread_local! {
    /// How many times [`zones_made_of`] has read a store on this thread: a test counts them.
    static ZONE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// What the zones were last built from, and the store's change counts of [`ZONE_KINDS`] when
/// that was last looked at: a store whose counts have not moved is not read at all.
#[derive(Default)]
pub(crate) struct Built {
    counts: Option<[u64; 6]>,
    from: Option<Vec<(String, Value, Option<Value>)>>,
}

impl Built {
    /// Whether the zones now differ from the ones last built. The zone kinds are read only when
    /// one of their counts moved, so a write to any other kind costs six counter reads.
    pub(crate) fn changed(&mut self, store: &Store) -> bool {
        let counts = ZONE_KINDS.map(|kind| store.changes(kind));
        if self.counts == Some(counts) {
            return false;
        }
        self.counts = Some(counts);
        let from = zones_made_of(store);
        let changed = self.from.as_ref() != Some(&from);
        self.from = Some(from);
        changed
    }
}

/// What the zones are made of, as `run` compares it with the last build: each resource's key and
/// spec, and a Node's address, what it serves and its state (the ingress addresses come from
/// those); a Workload's labels (which Services pick it) and each replica's node, readiness and
/// address (the names come from those). Not the revision: deleted and made again, it starts over.
fn zones_made_of(store: &Store) -> Vec<(String, Value, Option<Value>)> {
    #[cfg(test)]
    ZONE_READS.with(|reads| reads.set(reads.get() + 1));
    ZONE_KINDS
        .into_iter()
        .flat_map(|kind| store.list(Some(kind)))
        .map(|r| {
            let status = r.status.as_ref().map(|s| {
                if r.kind == "Node" {
                    json!([s["address"], s["lan"], s["serves"], s["state"]])
                } else if r.kind == "Workload" {
                    let units = s["containers"].as_array().into_iter().flatten();
                    let units: Vec<Value> = units
                        .map(|unit| json!([unit["replica"], unit["node"], unit["ready"], unit["address"]]))
                        .collect();
                    json!([r.metadata.labels, units])
                } else {
                    s["address"].clone()
                }
            });
            (r.key(), r.spec.clone(), status)
        })
        .collect()
}

/// What the server answers from, and what to report on each DNSZone and DNSRecord.
/// Whether a Service's or Workload's name and namespace are each one DNS label. A dotted one (a
/// store written before the rule at submission holds one) would name another's: not served.
fn one_label(resource: &Resource) -> bool {
    !resource.metadata.name.contains('.') && !crate::services::namespace(resource).contains('.')
}

pub fn zones_of(store: &Store, mesh: Option<std::net::Ipv6Addr>) -> (Zones, BTreeMap<String, Value>) {
    let mut status = BTreeMap::new();
    let served = || json!({ "state": "served" });
    let failed = |why: String| json!({ "state": "error", "message": why });

    // Our own names. Having the zone means a name that is not in it is answered "no
    // such name" here, and never sent to the internet to ask.
    let mut own = vec![soa("kith"), soa("cluster.local")];
    let mut empty: Vec<String> = Vec::new();
    for node in store.list(Some("Node")) {
        // (`<node>.node.kith` stays its LAN address, not the mesh one the leader may have moved it to.)
        let address = node.node_addresses().next();
        if let Some(address) = address.and_then(|address| address.parse::<SocketAddr>().ok()) {
            let data = match address.ip() {
                IpAddr::V4(ip) => Rdata::A(ip),
                IpAddr::V6(ip) => Rdata::Aaaa(ip),
            };
            let (name, ttl) = (format!("{}.node.kith", node.metadata.name), NODE_TTL);
            own.push(Record { name, ttl, data });
        }
        // A node's mesh name is its own mesh address, the one the cluster gives it (its peers reach
        // it there, mesh.rs): a status that names another address publishes nothing. (With no
        // prefix to derive it from, what the status says.)
        let said = node
            .status
            .as_ref()
            .and_then(|status| status["mesh"]["address"].as_str())
            .and_then(|address| address.parse::<std::net::Ipv6Addr>().ok());
        let published = match mesh {
            Some(prefix) => said.filter(|said| *said == kith_mesh::node_address(prefix, &node.metadata.name)),
            None => said,
        };
        if let Some(address) = published {
            let (name, ttl) = (format!("{}.mesh.kith", node.metadata.name), NODE_TTL);
            let data = Rdata::Aaaa(address);
            own.push(Record { name, ttl, data });
        }
    }
    // Each Service, by its name (`<service>.<namespace>.kith`, and as Kubernetes writes it,
    // under `svc.cluster.local`, where a pod is told to look): the Service's address on the
    // mesh, or for a headless one, the addresses of its ready replicas. Each ready replica is
    // also named under every Service that selects its Workload: `<workload>-<replica>.<service>.
    // <namespace>.svc.cluster.local` (a StatefulSet's pod names).
    for service in store.list(Some("Service")) {
        let Ok(spec) = serde_json::from_value::<ServiceSpec>(service.spec.clone()) else {
            continue;
        };
        if !one_label(service) {
            continue;
        }
        let namespace = crate::services::namespace(service);
        let name = &service.metadata.name;
        let mut replicas = Vec::new();
        for workload in crate::services::behind(store, service, &spec) {
            if !one_label(workload) {
                continue;
            }
            for (replica, address) in crate::services::ready_addresses(workload) {
                let named = format!(
                    "{}-{replica}.{name}.{namespace}.svc.cluster.local",
                    workload.metadata.name
                );
                own.push(Record {
                    name: named,
                    ttl: NODE_TTL,
                    data: Rdata::Aaaa(address),
                });
                replicas.push(address);
            }
        }
        let addresses = if spec.headless == Some(true) {
            replicas
        } else {
            mesh.map(|mesh| kith_mesh::service_address(mesh, &namespace, name))
                .into_iter()
                .collect()
        };
        for named in [
            format!("{name}.{namespace}.kith"),
            format!("{name}.{namespace}.svc.cluster.local"),
        ] {
            // The Service's name is there with no address: NODATA, as Kubernetes answers an empty headless one.
            empty.push(named.clone());
            for address in &addresses {
                own.push(Record {
                    name: named.clone(),
                    ttl: NODE_TTL,
                    data: Rdata::Aaaa(*address),
                });
            }
        }
    }

    let mut zones: BTreeMap<String, Zone> = BTreeMap::new();
    for resource in store.list(Some("DNSZone")) {
        let report = match spec::<DnsZoneSpec>(resource) {
            Ok(zone) => {
                let made = Zone {
                    domain: zone.domain.to_ascii_lowercase(),
                    clients: zone.clients,
                    ttl: zone.ttl.unwrap_or(TTL),
                    records: Vec::new(),
                };
                zones.insert(resource.metadata.name.clone(), made);
                served()
            }
            Err(e) => failed(e),
        };
        status.insert(resource.key(), report);
    }
    // Checks every record against the rest of its domain's (for the same clients), as the
    // server will hold them. Per name: is what is there a CNAME? One has its name to itself.
    type Trial = (Records, BTreeMap<String, bool>);
    let mut trial: BTreeMap<(String, Vec<String>), Trial> = BTreeMap::new();
    for resource in store.list(Some("DNSRecord")) {
        let added = spec::<DnsRecordSpec>(resource).and_then(|record| {
            let no_zone = || format!("there is no DNSZone named `{}`", record.zone);
            let zone = zones.get_mut(&record.zone).ok_or_else(no_zone)?;
            let records = records_of(&record, &zone.domain, zone.ttl)?;
            let (trial, aliases) = trial.entry((zone.domain.clone(), zone.clients.clone())).or_default();
            for record in &records {
                let alias = matches!(record.data, Rdata::Cname(_));
                if aliases.get(&record.name).is_some_and(|other| alias || *other) {
                    return Err(format!("`{}` is a CNAME and has other records too", record.name));
                }
                trial.add(record.clone())?;
                aliases.insert(record.name.clone(), alias);
            }
            zone.records.extend(records);
            Ok(())
        });
        status.insert(resource.key(), added.map_or_else(failed, |()| served()));
    }

    // Everyone's zones, then one view for each list of clients.
    let zones: Vec<Zone> = zones.into_values().collect();
    // The hosts Services expose, each under the longest zone that covers it (a host under two
    // zones is the longer one's). `exposed` reads the Services' hosts only: the mesh prefix it
    // is given shapes the addresses of Services, which are not read here.
    let hosts = ingress::exposed(store, std::net::Ipv6Addr::UNSPECIFIED).0;
    let exposed: Vec<(String, String)> = hosts
        .into_keys()
        .filter_map(|host| {
            let covers = |domain: &&str| host == *domain || host.ends_with(&format!(".{domain}"));
            let domain = zones
                .iter()
                .map(|zone| zone.domain.as_str())
                .filter(covers)
                .max_by_key(|domain| domain.len())?;
            Some((host.clone(), domain.to_string()))
        })
        .collect();
    // The LAN addresses of the nodes that serve ingress: the IPv4 ones (AAAA is not answered), and
    // not link-local, multicast or broadcast ones, which no client can reach a host at.
    let ingress_ips: BTreeSet<Ipv4Addr> = store
        .serving()
        .into_iter()
        .filter(|node| {
            node.status
                .as_ref()
                .is_some_and(|status| status["serves"]["ingress"] == true)
        })
        .filter_map(|node| match node.lan_address() {
            Some(IpAddr::V4(ip)) if !(ip.is_link_local() || ip.is_multicast() || ip.is_broadcast()) => Some(ip),
            _ => None,
        })
        .collect();
    let assemble = |clients: &[String]| {
        let mine: Vec<&Zone> = zones.iter().filter(|zone| zone.clients == clients).collect();
        let hidden: BTreeSet<&str> = mine.iter().map(|zone| zone.domain.as_str()).collect();
        let everyone = zones.iter().filter(|zone| zone.clients.is_empty());
        let shown = everyone.filter(|zone| clients.is_empty() || !hidden.contains(zone.domain.as_str()));
        let shown: Vec<&Zone> = if clients.is_empty() {
            shown.collect()
        } else {
            shown.chain(mine).collect()
        };
        let mut records = Records::default();
        let domains: BTreeSet<&str> = shown.iter().map(|zone| zone.domain.as_str()).collect();
        let apexes = domains.into_iter().map(soa);
        let mut refused = None;
        for record in own
            .iter()
            .cloned()
            .chain(apexes)
            .chain(shown.iter().flat_map(|zone| zone.records.clone()))
        {
            // Each record was added once already, beside the rest of its domain's, so this
            // only fails where one zone's domain lies inside another's and they collide, or
            // past the RRset limit. Said once: the first, with a line on stderr.
            if let Err(error) = records.add(record) {
                refused.get_or_insert(error);
            }
        }
        for name in &empty {
            if let Err(error) = records.add_name(name) {
                refused.get_or_insert(error);
            }
        }
        if let Some(error) = refused {
            eprintln!("kithd: dns: records refused, not answered: {error}");
        }
        // An exposed host is answered where its zone is shown, at each ingress address, for the
        // zone's TTL. A DNSRecord of that name answers instead when it is an A or a CNAME; a TXT
        // or other type beside it does not stop the addresses.
        let names: BTreeSet<String> = shown
            .iter()
            .flat_map(|zone| zone.records.iter())
            .filter(|record| matches!(record.data, Rdata::A(_) | Rdata::Cname(_)))
            .map(|record| record.name.to_ascii_lowercase())
            .collect();
        for (host, domain) in &exposed {
            let Some(zone) = shown.iter().find(|zone| zone.domain == *domain) else {
                continue;
            };
            if names.contains(host) {
                continue;
            }
            for ip in &ingress_ips {
                let (name, ttl, data) = (host.clone(), zone.ttl, Rdata::A(*ip));
                // Refused past the RRset limit (100 addresses for one name): logged, not silent.
                if let Err(error) = records.add(Record { name, ttl, data }) {
                    eprintln!("kithd: dns: exposed host {host} is not answered at every ingress address: {error}");
                    break;
                }
            }
        }
        records
    };
    let lists: BTreeSet<&[String]> = zones.iter().map(|zone| zone.clients.as_slice()).collect();
    let view = |clients: &&[String]| View {
        nets: clients.iter().filter_map(|net| net.parse::<Cidr>().ok()).collect(),
        records: assemble(clients),
    };
    let views = lists.iter().filter(|clients| !clients.is_empty()).map(view).collect();
    let records = assemble(&[]);
    // (The block lists come from `blocklist`, put in by `run`.)
    (
        Zones {
            records,
            views,
            blocks: Vec::new(),
        },
        status,
    )
}

/// The resolvers a resolv.conf names (`conf`, its text).
fn resolvers_in(conf: &str) -> Vec<SocketAddr> {
    let server = |line: &str| {
        let mut words = line.split_ascii_whitespace();
        (words.next() == Some("nameserver")).then(|| words.next()?.parse::<IpAddr>().ok())?
    };
    conf.lines()
        .filter_map(server)
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// The resolvers for names that are not ours: those `told` (`--dns-upstream`), or else the
/// system's, in `/etc/resolv.conf`. Call inside the runtime.
pub fn upstreams(told: Vec<SocketAddr>) -> watch::Receiver<Vec<SocketAddr>> {
    follow(told, "/etc/resolv.conf".into(), std::time::Duration::from_secs(5))
}

/// `told`, or else what the file `conf` names, read again `every` so often for as long as
/// someone listens: a node's lease, and with it its resolvers, can come after kithd started
/// (kith OS asks for one while kithd serves) and change with the network.
fn follow(
    told: Vec<SocketAddr>,
    conf: std::path::PathBuf,
    every: std::time::Duration,
) -> watch::Receiver<Vec<SocketAddr>> {
    let read = move || resolvers_in(&std::fs::read_to_string(&conf).unwrap_or_default());
    let (say, said) = watch::channel(if told.is_empty() { read() } else { told.clone() });
    if told.is_empty() {
        // ponytail: a few bytes read every few seconds; a watch on the file if that ever shows.
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = say.closed() => return,
                    () = tokio::time::sleep(every) => {}
                }
                // (None named any more is none to ask: a network left is not asked from the
                // next one. kith OS writes the file whole, so it is never read half made.)
                let now = read();
                say.send_if_modified(|was| {
                    let changed = *was != now;
                    *was = now;
                    changed
                });
            }
        });
    }
    said
}

/// Would asking `upstream` be asking ourselves, listening on `listen`?
fn is_self(upstream: SocketAddr, listen: SocketAddr) -> bool {
    // Listening on every address: any address of this machine (one a socket can be bound to) is us.
    let ours = || std::net::UdpSocket::bind((upstream.ip(), 0)).is_ok();
    let same_host = upstream.ip() == listen.ip() || (listen.ip().is_unspecified() && ours());
    upstream.port() == listen.port() && same_host
}

/// The resolvers of `all` that are not this server, listening on `listen`, nor the house address
/// `house` (whichever node holds it, it is asked of this one: a resolver named so loops).
fn others(all: &[SocketAddr], listen: SocketAddr, house: Option<Ipv4Addr>) -> Arc<[SocketAddr]> {
    let at_house = house.map(|address| SocketAddr::new(address.into(), listen.port()));
    all.iter()
        .copied()
        .filter(|upstream| !is_self(*upstream, listen) && !at_house.is_some_and(|house| is_self(*upstream, house)))
        .collect()
}

/// A UDP socket on `address`, non-blocking. It may share its port with another of ours bound to
/// a different address (the one on every address and the one on the house address), and an
/// address not yet on any card can be bound: the house address comes and goes with the leader.
/// SO_REUSEPORT, not SO_REUSEADDR: the kernel lets only a socket of the same user share the port,
/// so another program on the node cannot bind beside ours and take its queries.
fn udp_socket(address: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, SockaddrStorage, bind, setsockopt, socket, sockopt};
    let family = if address.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    let flags = SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC;
    let fd = socket(family, SockType::Datagram, flags, None)?;
    setsockopt(&fd, sockopt::ReusePort, &true)?;
    if address.is_ipv4() {
        setsockopt(&fd, sockopt::IpFreebind, &true)?;
    }
    bind(std::os::fd::AsRawFd::as_raw_fd(&fd), &SockaddrStorage::from(address))?;
    Ok(fd.into())
}

/// How long the house address's socket waits to be bound again after it could not be.
const HOUSE_RETRY: std::time::Duration = std::time::Duration::from_secs(10);

/// Answers on the house address, on `port`, while the store names one (`serve_udp_on`).
async fn house(
    port: u16,
    mut wanted: watch::Receiver<Option<Ipv4Addr>>,
    zones: watch::Receiver<Arc<Zones>>,
    upstreams: watch::Receiver<Arc<[SocketAddr]>>,
    forwarders: Vec<Cidr>,
    cache: Arc<kith_dns::Cache>,
) {
    // The last error said, so that one that stays is said once.
    let mut said = String::new();
    loop {
        let now = *wanted.borrow_and_update();
        let serving = async {
            let Some(address) = now else {
                return std::future::pending::<()>().await;
            };
            let at = SocketAddr::from((address, port));
            match udp_socket(at).and_then(UdpSocket::from_std) {
                Ok(udp) => {
                    eprintln!("kithd: serving DNS on the house address {at}");
                    said.clear();
                    kith_dns::serve_udp_on(udp, zones.clone(), upstreams.clone(), forwarders.clone(), cache.clone())
                        .await;
                }
                Err(e) => {
                    if said != e.to_string() {
                        eprintln!(
                            "kithd: serving DNS on the house address {at}: {e} (tried again every {} s)",
                            HOUSE_RETRY.as_secs()
                        );
                        said = e.to_string();
                    }
                }
            }
            // (Not bound, or no longer served: the next try is after this, or when the store changes.)
            tokio::time::sleep(HOUSE_RETRY).await;
        };
        tokio::select! {
            () = serving => {}
            changed = wanted.changed() => {
                if changed.is_err() {
                    return std::future::pending::<()>().await;
                }
            }
        }
    }
}

/// UDP and TCP on the same address; with port 0, on the same free port.
pub async fn bind(listen: SocketAddr) -> Result<(UdpSocket, TcpListener), String> {
    let failed = |e: std::io::Error| format!("serving DNS on {listen}: {e}");
    for _ in 0..20 {
        let tcp = TcpListener::bind(listen).await.map_err(failed)?;
        let address = tcp.local_addr().map_err(failed)?;
        match udp_socket(address).and_then(UdpSocket::from_std) {
            Ok(udp) => return Ok((udp, tcp)),
            // Someone else has that port on UDP: with port 0, take another.
            Err(_) if listen.port() == 0 => {}
            Err(e) => return Err(failed(e)),
        }
    }
    Err(format!("serving DNS on {listen}: no port is free on both UDP and TCP"))
}

/// Whether this node leads the log: the one control node that says the DNS statuses (and the
/// block lists') for all of them.
pub fn leads(shared: &Shared) -> bool {
    let metrics = shared.raft.metrics();
    let metrics = metrics.borrow();
    metrics.current_leader == Some(metrics.id)
}

/// Serve DNS until kithd stops.
pub async fn run(
    shared: Arc<Shared>,
    (udp, tcp): (UdpSocket, TcpListener),
    mut upstreams: watch::Receiver<Vec<SocketAddr>>,
    mut stopping: watch::Receiver<bool>,
) {
    // This node's pods are its own to ask for any name, whatever their addresses are. (A list
    // takes the place of the local networks, so they are named with it: a list of the pods'
    // network alone had every other client refused.)
    let pods = crate::pods::range().to_string();
    let forwarders = kith_dns::LOCAL_NETWORKS.into_iter().chain([pods.as_str()]);
    let forwarders: Vec<Cidr> = forwarders.filter_map(|net| net.parse().ok()).collect();
    let listen = tcp.local_addr().expect("a bound socket has an address");
    // The house address the Clusters name (held by this node or not): a resolver list that names
    // it (a router's DHCP) must not be asked by the node that holds it, nor dropped for good by
    // the one that held it when the list was read.
    let (house_wants, house_wanted) = watch::channel(None::<Ipv4Addr>);
    let configured = || {
        let state = shared.store.lock().expect("nothing panics holding the store");
        crate::home::configured(&state.store).map(|home| home.address)
    };
    house_wants.send_replace(configured());
    let ours = move |all: &[SocketAddr], house: Option<Ipv4Addr>| others(all, listen, house);
    let said = move |now: &[SocketAddr]| {
        eprintln!("kithd: serving DNS on {listen}; other names go to {now:?}");
        if now.is_empty() {
            eprintln!("kithd: no other resolver to ask (--dns-upstream): only names in the store resolve");
        }
    };
    let (ask, asked) = watch::channel(ours(&upstreams.borrow_and_update(), *house_wanted.borrow()));
    said(&asked.borrow());
    let mut house_seen = house_wanted.clone();
    house_seen.mark_unchanged();
    let told = async {
        // (Resolvers named on the command line: the list never changes, the house address may.)
        let mut listed = true;
        loop {
            tokio::select! {
                got = upstreams.changed(), if listed => listed = got.is_ok(),
                got = house_seen.changed() => {
                    if got.is_err() {
                        return std::future::pending::<()>().await;
                    }
                }
            }
            let now = ours(&upstreams.borrow_and_update(), *house_seen.borrow_and_update());
            said(&now);
            ask.send_replace(now);
        }
    };
    let (zones, served) = watch::channel(Arc::new(Zones::default()));
    // The lists of names to answer as not there, and the answers kept from the upstreams.
    let cache = Arc::new(kith_dns::Cache::default());
    let (listed, mut lists) = watch::channel(Arc::new(Vec::<kith_dns::Block>::new()));
    let lists_now = lists.clone();
    let blocks = crate::blocklist::run(shared.clone(), cache.clone(), listed);
    let relist = async {
        // A change to the lists goes into the zones being served; the cache needs no flush, for
        // it sits behind them.
        while lists.changed().await.is_ok() {
            let blocks = lists.borrow_and_update().to_vec();
            zones.send_modify(|zones| Arc::make_mut(zones).blocks = blocks);
        }
    };
    let feed = async {
        let mut generation = shared.generation.subscribe();
        // What the zones were last built from: most changes to the store are not about DNS.
        let mut built = Built::default();
        loop {
            let reports = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                let home = crate::home::configured(&state.store).map(|home| home.address);
                house_wants.send_if_modified(|was| std::mem::replace(was, home) != home);
                built.changed(&state.store).then(|| {
                    let mesh = shared
                        .cluster
                        .as_ref()
                        .map(|cluster| crate::mesh::prefix(&cluster.me.ca));
                    let (mut built, reports) = zones_of(&state.store, mesh);
                    built.blocks = lists_now.borrow().to_vec();
                    zones.send_replace(Arc::new(built));
                    let stale = |(key, report): &(String, Value)| {
                        let live = state.store.get(key).and_then(|resource| resource.status.as_ref());
                        live != Some(report)
                    };
                    reports
                        .into_iter()
                        .filter(stale)
                        .map(|(key, report)| (key, Some(report)))
                        .collect::<Vec<_>>()
                })
            };
            // (Every node that answers says the same of the records: a worker leaves the
            // saying to the control nodes, whose it is to write.)
            let worker = crate::access::worker(&shared, shared.members.me());
            if let Some(statuses) = reports.filter(|statuses| !statuses.is_empty() && !worker) {
                // (Every control node builds the same statuses: the leader alone says them. A
                // follower's would be passed on as its own write, and refused.)
                if !leads(&shared) {
                    // Said again at the next change to the store, which may find this node leading.
                    built = Built::default();
                } else if let Err(e) = shared.submit(kith_store::Command::Status { statuses }).await {
                    eprintln!("kithd: reporting on DNS records: {e}");
                    // Tried again at the next change to the store.
                    built = Built::default();
                }
            }
            if generation.changed().await.is_err() {
                return;
            }
        }
    };
    // Answered on a thread of its own: a busy API, controller or Service does not hold a
    // lookup up. (Where none can be started, on kithd's own, as before.)
    let thread = crate::services::thread("kith-dns".into()).unwrap_or_else(|e| {
        eprintln!("kithd: DNS: starting a thread: {e}");
        tokio::runtime::Handle::current()
    });
    let sockets = udp.into_std().and_then(|udp| Ok((udp, tcp.into_std()?)));
    let at_home = thread.spawn(house(
        listen.port(),
        house_wanted,
        served.clone(),
        asked.clone(),
        forwarders.clone(),
        cache.clone(),
    ));
    let answering = thread.spawn(async move {
        let (udp, tcp) = sockets?;
        let (udp, tcp) = (UdpSocket::from_std(udp)?, TcpListener::from_std(tcp)?);
        kith_dns::serve(udp, tcp, served, asked, forwarders, cache).await;
        Ok::<_, std::io::Error>(())
    });
    let stop = answering.abort_handle();
    tokio::select! {
        done = answering => {
            if let Ok(Err(e)) = done {
                eprintln!("kithd: serving DNS on {listen}: {e}");
            }
        }
        () = feed => {}
        () = relist => {}
        () = blocks => {}
        () = told => {}
        _ = stopping.changed() => {}
    }
    stop.abort();
    at_home.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The socket on every address and the one on the house address share a port, and the
    /// second binds an address no card has yet.
    #[test]
    fn house_socket_shares_the_port() {
        let all = udp_socket("0.0.0.0:0".parse().unwrap()).unwrap();
        let port = all.local_addr().unwrap().port();
        let house = udp_socket(SocketAddr::from(([10, 9, 0, 100], port))).unwrap();
        assert_eq!(house.local_addr().unwrap().port(), port);
    }

    /// A node's resolvers can be written after kithd started (its lease comes while it serves).
    #[tokio::test]
    async fn resolvers_written_later_are_followed() {
        let conf = std::env::temp_dir().join(format!("kith-resolvers-{}", std::process::id()));
        let _ = std::fs::remove_file(&conf);
        let every = std::time::Duration::from_millis(10);
        let mut said = follow(vec![], conf.clone(), every);
        assert!(said.borrow_and_update().is_empty());
        std::fs::write(&conf, "# from a lease\nnameserver 10.0.2.3\n").unwrap();
        said.changed().await.unwrap();
        assert_eq!(*said.borrow_and_update(), ["10.0.2.3:53".parse().unwrap()]);
        // A lease that names none (another network): the old ones are not asked from there.
        std::fs::write(&conf, "").unwrap();
        said.changed().await.unwrap();
        assert!(said.borrow_and_update().is_empty());
        // Told on the command line: the file is not read.
        let told: Vec<SocketAddr> = vec!["9.9.9.9:53".parse().unwrap()];
        let mut fixed = follow(told.clone(), conf.clone(), every);
        std::fs::write(&conf, "nameserver 10.0.2.4\n").unwrap();
        said.changed().await.unwrap();
        assert_eq!(*fixed.borrow_and_update(), told);
        assert!(fixed.has_changed().is_err(), "nothing follows the file for it");
        let _ = std::fs::remove_file(&conf);
    }

    /// A name no node knows, asked by a client the forwarders let through (run gives a node its
    /// local networks and its pods'), is passed to the upstream and its answer comes back. (The
    /// client here is on loopback: a test cannot send from a pod's own address.)
    #[tokio::test]
    async fn pod_outside_name() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let told = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = upstream.recv_from(&mut buf).await.unwrap();
            // The query again, answered with one A record of 198.51.100.7 for its name.
            let mut reply = buf[..n].to_vec();
            reply[2..4].copy_from_slice(&[0x81, 0x80]);
            reply[6..8].copy_from_slice(&[0, 1]);
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7]);
            upstream.send_to(&reply, from).await.unwrap();
        });
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = udp.local_addr().unwrap();
        let pods = crate::pods::range().to_string();
        let forwarders: Vec<Cidr> = kith_dns::LOCAL_NETWORKS
            .into_iter()
            .chain([pods.as_str()])
            .filter_map(|net| net.parse().ok())
            .collect();
        let (_zones, served) = watch::channel(Arc::new(Zones::default()));
        let (_, asked) = watch::channel(Arc::from(vec![told]));
        let cache = Arc::new(kith_dns::Cache::default());
        tokio::spawn(kith_dns::serve(udp, tcp, served, asked, forwarders, cache));
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["outside", "example", "test"] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query, listen).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let reply = &buf[..n];
        assert_eq!(reply[3] & 0x0f, 0, "answered, not refused or failed");
        assert_eq!(reply[6..8], [0, 1], "one answer");
        assert!(reply.ends_with(&[198, 51, 100, 7]), "the upstream's address: {reply:?}");
    }

    fn store(yaml: &str) -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(yaml).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        store
    }

    /// What `client` is told `name` is (type A): the addresses, or the response code.
    fn ask(zones: &Zones, client: &str, name: &str) -> Result<Vec<String>, Option<u16>> {
        let found = zones.lookup(client.parse().unwrap(), name, 1).ok_or(None)?;
        let address = |record: &Record| match &record.data {
            Rdata::A(ip) => Some(ip.to_string()),
            _ => None,
        };
        match found.rcode {
            0 => Ok(found.answers.iter().filter_map(address).collect()),
            rcode => Err(Some(rcode)),
        }
    }

    const HOME: &str = "
apiVersion: kith.dev/v1
kind: DNSZone
metadata: { name: home }
spec: { domain: home.example }
---
apiVersion: kith.dev/v1
kind: DNSZone
metadata: { name: home-inside }
spec: { domain: home.example, clients: [192.168.0.0/16] }
---
apiVersion: kith.dev/v1
kind: DNSRecord
metadata: { name: nas-outside }
spec: { zone: home, name: nas, type: A, values: [203.0.113.7] }
---
apiVersion: kith.dev/v1
kind: DNSRecord
metadata: { name: nas-inside }
spec: { zone: home-inside, name: nas, type: A, values: [192.168.1.20] }
---
apiVersion: kith.dev/v1
kind: DNSRecord
metadata: { name: apps }
spec: { zone: home, name: '*.apps', type: A, values: [203.0.113.8, 203.0.113.9] }
---
apiVersion: kith.dev/v1
kind: DNSRecord
metadata: { name: lost }
spec: { zone: nowhere, name: x, type: A, values: [10.0.0.1] }
---
apiVersion: kith.dev/v1
kind: DNSZone
metadata: { name: home-too }
spec: { domain: home.example }
---
apiVersion: kith.dev/v1
kind: DNSRecord
metadata: { name: other-alias }
spec: { zone: home-too, name: nas, type: CNAME, values: [elsewhere.example] }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: alpha }
spec: {}
";

    #[test]
    fn zones_come_from_the_store() {
        let mut store = store(HOME);
        let mesh = kith_mesh::prefix(b"test");
        let own = kith_mesh::node_address(mesh, "alpha");
        store
            .set_status(
                "Node/alpha",
                Some(json!({ "address": "10.1.2.3:7443", "mesh": { "address": own.to_string() } })),
            )
            .unwrap();
        let (zones, status) = zones_of(&store, Some(mesh));
        let outside = "198.51.100.1";
        let on_mesh = zones.lookup(outside.parse().unwrap(), "alpha.mesh.kith", 28).unwrap();
        assert_eq!(on_mesh.answers[0].data, Rdata::Aaaa(own));

        assert_eq!(ask(&zones, outside, "alpha.node.kith"), Ok(vec!["10.1.2.3".into()]));
        // Ours to answer, so "no such name" (3), and never forwarded.
        assert_eq!(ask(&zones, outside, "beta.node.kith"), Err(Some(3)));
        assert_eq!(ask(&zones, outside, "web.default.kith"), Err(Some(3)));
        // Not ours: upstream.
        assert_eq!(ask(&zones, outside, "example.org"), Err(None));

        // Split horizon: the same name, by who asks; names only the outside zone has are not inside.
        assert_eq!(ask(&zones, outside, "nas.home.example"), Ok(vec!["203.0.113.7".into()]));
        assert_eq!(
            ask(&zones, "192.168.1.50", "NAS.home.example"),
            Ok(vec!["192.168.1.20".into()])
        );
        assert_eq!(ask(&zones, "192.168.1.50", "x.apps.home.example"), Err(Some(3)));
        assert_eq!(
            ask(&zones, "192.168.1.50", "alpha.node.kith"),
            Ok(vec!["10.1.2.3".into()])
        );
        let both = vec!["203.0.113.8".to_string(), "203.0.113.9".to_string()];
        assert_eq!(ask(&zones, outside, "x.apps.home.example"), Ok(both));

        assert_eq!(status["DNSZone/home"], json!({ "state": "served" }));
        assert_eq!(status["DNSRecord/nas-inside"], json!({ "state": "served" }));
        // A CNAME where another zone of the same domain has an address is refused, not half served.
        let alias = status["DNSRecord/other-alias"]["message"].as_str().unwrap();
        assert!(alias.contains("is a CNAME and has other records too"), "{alias}");
        let lost = status["DNSRecord/lost"]["message"].as_str().unwrap();
        assert!(lost.contains("no DNSZone named `nowhere`"), "{lost}");
    }

    /// A node's mesh name is published at the address the cluster gives it (its node_address) and at
    /// no other: what its status says of its mesh address counts only when it is that one.
    #[test]
    fn a_node_publishes_its_mesh_name_only_at_its_own_address() {
        let mesh = kith_mesh::prefix(b"test");
        let own = kith_mesh::node_address(mesh, "alpha");
        let published = |said: Option<&str>| -> Vec<Rdata> {
            let mut store = store(HOME);
            if let Some(said) = said {
                let status = json!({ "address": "10.1.2.3:7443", "mesh": { "address": said } });
                store.set_status("Node/alpha", Some(status)).unwrap();
            }
            let (zones, _) = zones_of(&store, Some(mesh));
            let found = zones.lookup(OUTSIDE.parse().unwrap(), "alpha.mesh.kith", 28);
            found
                .map(|found| found.answers.into_iter().map(|record| record.data).collect())
                .unwrap_or_default()
        };
        assert_eq!(published(Some(own.to_string().as_str())), vec![Rdata::Aaaa(own)]);
        assert_eq!(published(Some("fd00:1::1")), Vec::<Rdata>::new());
        assert_eq!(published(None), Vec::<Rdata>::new());
    }

    const OUTSIDE: &str = "198.51.100.1";
    const INSIDE: &str = "192.168.1.50";

    /// The zones of `example.test` (for everyone, TTL 60) and `apps.example.test` under it (TTL 120),
    /// and Services in `shop` that expose hosts under them, one that is refused, one that a DNSRecord
    /// of the same name answers, and one under no zone. Its nodes are in `expose_nodes`.
    const EXPOSED: &str = "
apiVersion: kith.dev/v1
kind: DNSZone
metadata: { name: example }
spec: { domain: example.test, ttl: 60 }
---
apiVersion: kith.dev/v1
kind: DNSZone
metadata: { name: apps }
spec: { domain: apps.example.test, ttl: 120 }
---
apiVersion: kith.dev/v1
kind: Namespace
metadata: { name: shop }
spec: { hosts: ['*.apps.example.test', 'www.example.test'] }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: web, namespace: shop }
spec:
  selector: { app: web }
  ports: [{ port: 8080 }]
  expose: { host: web.apps.example.test, via: edge }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: www, namespace: shop }
spec:
  selector: { app: www }
  ports: [{ port: 8080 }]
  expose: { host: www.example.test, via: edge }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: api, namespace: shop }
spec:
  selector: { app: api }
  ports: [{ port: 8080 }]
  expose: { host: api.apps.example.test, via: edge }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: dev, namespace: shop }
spec:
  selector: { app: dev }
  ports: [{ port: 8080 }]
  expose: { host: stray.example.test, via: edge }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: other, namespace: shop }
spec:
  selector: { app: other }
  ports: [{ port: 8080 }]
  expose: { host: other.example.org, via: edge }
---
apiVersion: kith.dev/v1
kind: DNSRecord
metadata: { name: api-record }
spec: { zone: apps, name: api, type: A, values: [198.51.100.9] }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: edge-a }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: edge-b }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: lan-dns }
spec: {}
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: roamer }
spec: { roaming: true }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: down }
spec: {}
";

    /// Each node of `EXPOSED` as it says itself: its address, what it serves, and its state.
    fn expose_nodes(store: &mut Store) {
        let nodes = [
            (
                "edge-a",
                json!({ "address": "192.0.2.10:7443", "serves": { "dns": 53, "ingress": true } }),
            ),
            (
                "edge-b",
                json!({ "address": "192.0.2.11:7443", "serves": { "ingress": true } }),
            ),
            (
                "lan-dns",
                json!({ "address": "192.0.2.12:7443", "serves": { "dns": 53 } }),
            ),
            (
                "roamer",
                json!({ "address": "192.0.2.13:7443", "serves": { "ingress": true } }),
            ),
            (
                "down",
                json!({ "address": "192.0.2.14:7443", "serves": { "ingress": true }, "state": "unreachable" }),
            ),
        ];
        for (name, status) in nodes {
            store.set_status(&format!("Node/{name}"), Some(status)).unwrap();
        }
    }

    /// The addresses `name` is answered with (type A) for `client`, sorted.
    fn answers_of(zones: &Zones, client: &str, name: &str) -> Vec<String> {
        let mut answers = ask(zones, client, name).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        answers.sort();
        answers
    }

    /// The seconds an answer (type A) for `name` may be kept, for `client`.
    fn ttl_of(zones: &Zones, client: &str, name: &str) -> u32 {
        zones.lookup(client.parse().unwrap(), name, 1).unwrap().answers[0].ttl
    }

    #[test]
    fn exposed_hosts_are_answered_at_the_lan_address_of_each_ingress_node() {
        let mut store = store(EXPOSED);
        expose_nodes(&mut store);
        let (zones, _) = zones_of(&store, None);
        // Both nodes that serve ingress; not the one that answers DNS only, the roaming one, or the unreachable one.
        assert_eq!(
            answers_of(&zones, OUTSIDE, "web.apps.example.test"),
            ["192.0.2.10", "192.0.2.11"]
        );
        assert_eq!(
            answers_of(&zones, OUTSIDE, "www.example.test"),
            ["192.0.2.10", "192.0.2.11"]
        );
        // A host under no zone is not ours: forwarded, as before.
        assert_eq!(ask(&zones, OUTSIDE, "other.example.org"), Err(None));
    }

    #[test]
    fn exposed_hosts_go_to_the_longest_zone_they_are_under() {
        let mut store = store(EXPOSED);
        expose_nodes(&mut store);
        let (zones, _) = zones_of(&store, None);
        // web is under example.test (TTL 60) and apps.example.test (TTL 120): the longer one answers.
        assert_eq!(ttl_of(&zones, OUTSIDE, "web.apps.example.test"), 120);
        assert_eq!(ttl_of(&zones, OUTSIDE, "www.example.test"), 60);
    }

    #[test]
    fn exposed_hosts_are_answered_to_their_zones_clients_only() {
        let mut store = store(
            "
apiVersion: kith.dev/v1
kind: DNSZone
metadata: { name: inside }
spec: { domain: apps.example.test, ttl: 30, clients: [192.168.0.0/16] }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: web, namespace: shop }
spec:
  selector: { app: web }
  ports: [{ port: 8080 }]
  expose: { host: web.apps.example.test, via: edge }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: edge-a }
spec: {}
",
        );
        store
            .set_status(
                "Node/edge-a",
                Some(json!({ "address": "192.0.2.10:7443", "serves": { "ingress": true } })),
            )
            .unwrap();
        let (zones, _) = zones_of(&store, None);
        assert_eq!(answers_of(&zones, INSIDE, "web.apps.example.test"), ["192.0.2.10"]);
        assert_eq!(ttl_of(&zones, INSIDE, "web.apps.example.test"), 30);
        // Not the zone's clients: the name is not in any zone of theirs, so it is forwarded, as before.
        assert_eq!(ask(&zones, OUTSIDE, "web.apps.example.test"), Err(None));
    }

    #[test]
    fn exposed_hosts_lose_to_a_dnsrecord_of_the_same_name_and_to_a_refused_host() {
        let mut store = store(EXPOSED);
        expose_nodes(&mut store);
        let (zones, _) = zones_of(&store, None);
        // The DNSRecord of the same name is the answer, with no LAN address beside it.
        assert_eq!(answers_of(&zones, OUTSIDE, "api.apps.example.test"), ["198.51.100.9"]);
        // A host its Namespace does not keep for it is refused, so not answered; nor is a name nothing exposes.
        assert_eq!(ask(&zones, OUTSIDE, "stray.example.test"), Err(Some(3)));
        assert_eq!(ask(&zones, OUTSIDE, "nothing.apps.example.test"), Err(Some(3)));
    }

    #[test]
    fn exposed_hosts_are_rebuilt_when_a_nodes_serves_or_a_namespaces_hosts_change() {
        let mut store = store(EXPOSED);
        expose_nodes(&mut store);
        let built = zones_made_of(&store);
        // A node that stops serving ingress is left out.
        store
            .set_status(
                "Node/edge-b",
                Some(json!({ "address": "192.0.2.11:7443", "serves": { "dns": 53 } })),
            )
            .unwrap();
        assert_ne!(zones_made_of(&store), built);
        let (zones, _) = zones_of(&store, None);
        assert_eq!(answers_of(&zones, OUTSIDE, "www.example.test"), ["192.0.2.10"]);
        // A Namespace whose hosts do not include a Service's refuses that Service's host.
        let built = zones_made_of(&store);
        let namespace = "apiVersion: kith.dev/v1\nkind: Namespace\nmetadata: { name: shop }\nspec: { hosts: [elsewhere.example.test] }\n";
        store
            .apply(Resource::from_source(namespace).unwrap().remove(0).unwrap())
            .unwrap();
        assert_ne!(zones_made_of(&store), built);
        let (zones, _) = zones_of(&store, None);
        assert_eq!(ask(&zones, OUTSIDE, "www.example.test"), Err(Some(3)));
    }

    /// A write to a kind the zones are not made of: the counts of the zone kinds do not move, so
    /// nothing is read, and nothing is built.
    #[test]
    fn dns_a_write_to_a_kind_the_zones_are_not_made_of_builds_nothing() {
        let mut store = store(EXPOSED);
        expose_nodes(&mut store);
        let mut built = Built::default();
        assert!(built.changed(&store), "the first look builds");
        let reads = zone_reads();
        let config =
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: motd }\nspec: { data: { text: hi } }\n";
        store
            .apply(Resource::from_source(config).unwrap().remove(0).unwrap())
            .unwrap();
        assert!(!built.changed(&store), "nothing to build");
        assert_eq!(zone_reads(), reads, "zones_made_of was not called");
    }

    /// A Service is one of the kinds the zones are made of: its addition builds again.
    #[test]
    fn dns_a_service_change_still_rebuilds() {
        let mut store = store(EXPOSED);
        expose_nodes(&mut store);
        let mut built = Built::default();
        built.changed(&store);
        let reads = zone_reads();
        let service = "apiVersion: kith.dev/v1\nkind: Service\nmetadata: { name: cache, namespace: shop }\nspec:\n  selector: { app: cache }\n  ports: [{ port: 8080 }]\n";
        store
            .apply(Resource::from_source(service).unwrap().remove(0).unwrap())
            .unwrap();
        assert!(built.changed(&store), "a Service's addition builds");
        assert_eq!(zone_reads(), reads + 1, "read once");
    }

    fn zone_reads() -> usize {
        ZONE_READS.with(std::cell::Cell::get)
    }

    /// `EXPOSED` with more documents after it.
    fn exposed_plus(docs: &str) -> String {
        format!("{EXPOSED}{docs}")
    }

    /// One DNSRecord (named `extra`) whose spec is `spec`, as a document for `exposed_plus`.
    fn record_doc(spec: &str) -> String {
        format!("---\napiVersion: kith.dev/v1\nkind: DNSRecord\nmetadata: {{ name: extra }}\nspec: {{ {spec} }}\n")
    }

    #[test]
    fn an_exposed_host_keeps_its_lan_addresses_beside_a_txt_at_its_name() {
        let mut store = store(&exposed_plus(&record_doc(
            "zone: apps, name: web, type: TXT, values: ['hello']",
        )));
        expose_nodes(&mut store);
        let (zones, _) = zones_of(&store, None);
        assert_eq!(
            answers_of(&zones, OUTSIDE, "web.apps.example.test"),
            ["192.0.2.10", "192.0.2.11"]
        );
        // The TXT is still answered beside them.
        assert!(
            zones
                .lookup(OUTSIDE.parse().unwrap(), "web.apps.example.test", 16)
                .is_some()
        );
    }

    #[test]
    fn a_dnsrecord_a_or_cname_at_an_exposed_host_wins_over_it() {
        let mut store = store(&exposed_plus(&record_doc(
            "zone: apps, name: web, type: A, values: [198.51.100.9]",
        )));
        expose_nodes(&mut store);
        let (zones, _) = zones_of(&store, None);
        assert_eq!(answers_of(&zones, OUTSIDE, "web.apps.example.test"), ["198.51.100.9"]);
    }

    #[test]
    fn a_cname_at_an_exposed_host_wins_over_it() {
        let mut store = store(&exposed_plus(&record_doc(
            "zone: apps, name: web, type: CNAME, values: [elsewhere.example.test]",
        )));
        expose_nodes(&mut store);
        let (zones, _) = zones_of(&store, None);
        // The CNAME is the answer: no LAN address beside it.
        assert!(
            ask(&zones, OUTSIDE, "web.apps.example.test")
                .unwrap_or_default()
                .is_empty()
        );
        assert!(
            zones
                .lookup(OUTSIDE.parse().unwrap(), "web.apps.example.test", 5)
                .is_some()
        );
    }

    #[test]
    fn an_exposed_host_is_answered_before_a_wildcard_dnsrecord() {
        let mut store = store(&exposed_plus(&record_doc(
            "zone: apps, name: '*', type: A, values: [198.51.100.7]",
        )));
        expose_nodes(&mut store);
        let (zones, _) = zones_of(&store, None);
        // The wildcard answers the other names under the zone; the exposed host has its own answer.
        assert_eq!(
            answers_of(&zones, OUTSIDE, "web.apps.example.test"),
            ["192.0.2.10", "192.0.2.11"]
        );
        assert_eq!(
            answers_of(&zones, OUTSIDE, "nothing.apps.example.test"),
            ["198.51.100.7"]
        );
    }

    #[test]
    fn a_host_equal_to_a_zones_apex_is_answered_beside_its_soa() {
        let mut store = store(
            "
apiVersion: kith.dev/v1
kind: DNSZone
metadata: { name: home }
spec: { domain: home.example.test, ttl: 45 }
---
apiVersion: kith.dev/v1
kind: Namespace
metadata: { name: shop }
spec: { hosts: [home.example.test] }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: web, namespace: shop }
spec:
  selector: { app: web }
  ports: [{ port: 8080 }]
  expose: { host: home.example.test, via: edge }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: edge-a }
spec: {}
",
        );
        store
            .set_status(
                "Node/edge-a",
                Some(json!({ "address": "192.0.2.10:7443", "serves": { "ingress": true } })),
            )
            .unwrap();
        let (zones, _) = zones_of(&store, None);
        assert_eq!(answers_of(&zones, OUTSIDE, "home.example.test"), ["192.0.2.10"]);
        assert_eq!(ttl_of(&zones, OUTSIDE, "home.example.test"), 45);
        // The zone's SOA is still answered at its apex.
        assert!(zones.lookup(OUTSIDE.parse().unwrap(), "home.example.test", 6).is_some());
    }

    #[test]
    fn a_host_under_two_zones_is_the_longer_zones_and_not_answered_to_the_shorter_zones_clients() {
        let mut store = store(
            "
apiVersion: kith.dev/v1
kind: DNSZone
metadata: { name: example }
spec: { domain: example.test, ttl: 60 }
---
apiVersion: kith.dev/v1
kind: DNSZone
metadata: { name: inside }
spec: { domain: apps.example.test, ttl: 120, clients: [192.168.0.0/16] }
---
apiVersion: kith.dev/v1
kind: Namespace
metadata: { name: shop }
spec: { hosts: [web.apps.example.test] }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: web, namespace: shop }
spec:
  selector: { app: web }
  ports: [{ port: 8080 }]
  expose: { host: web.apps.example.test, via: edge }
---
apiVersion: kith.dev/v1
kind: Node
metadata: { name: edge-a }
spec: {}
",
        );
        store
            .set_status(
                "Node/edge-a",
                Some(json!({ "address": "192.0.2.10:7443", "serves": { "ingress": true } })),
            )
            .unwrap();
        let (zones, _) = zones_of(&store, None);
        // The longer zone's clients get the host, at its TTL.
        assert_eq!(answers_of(&zones, INSIDE, "web.apps.example.test"), ["192.0.2.10"]);
        assert_eq!(ttl_of(&zones, INSIDE, "web.apps.example.test"), 120);
        // Outside the longer zone's clients, the shorter zone is shown but the host is not answered.
        assert!(
            ask(&zones, OUTSIDE, "web.apps.example.test")
                .unwrap_or_default()
                .is_empty()
        );
    }

    #[test]
    fn ingress_addresses_leave_out_link_local_multicast_and_broadcast() {
        let extra: String = ["linked", "group", "all"]
            .iter()
            .map(|name| format!("---\napiVersion: kith.dev/v1\nkind: Node\nmetadata: {{ name: {name} }}\nspec: {{}}\n"))
            .collect();
        let mut store = store(&exposed_plus(&extra));
        expose_nodes(&mut store);
        for (name, ip) in [
            ("linked", "169.254.1.5"),
            ("group", "224.0.0.251"),
            ("all", "255.255.255.255"),
        ] {
            store
                .set_status(
                    &format!("Node/{name}"),
                    Some(json!({ "address": format!("{ip}:7443"), "serves": { "ingress": true } })),
                )
                .unwrap();
        }
        let (zones, _) = zones_of(&store, None);
        // Only the two ordinary ingress addresses of EXPOSED are answered.
        assert_eq!(
            answers_of(&zones, OUTSIDE, "web.apps.example.test"),
            ["192.0.2.10", "192.0.2.11"]
        );
    }

    #[test]
    fn asking_ourselves_is_noticed() {
        let at = |address: &str| address.parse::<SocketAddr>().unwrap();
        assert!(is_self(at("127.0.0.1:53"), at("0.0.0.0:53")));
        assert!(is_self(at("192.168.1.1:53"), at("192.168.1.1:53")));
        assert!(!is_self(at("127.0.0.1:53"), at("0.0.0.0:5353")));
        assert!(!is_self(at("1.1.1.1:53"), at("0.0.0.0:53")));
        // Any address of this machine, when listening on all of them.
        assert!(is_self(at("127.0.0.2:53"), at("0.0.0.0:53")));
    }

    /// Every control node builds the same DNS statuses, and only the leader says them: a
    /// follower's would be passed on as its own write, and refused for the kinds it does not hold.
    #[tokio::test]
    async fn dns_statuses_are_said_by_the_leader_alone() {
        let ca = crate::pki::Ca::create().unwrap();
        let me = crate::cluster::pinned_peer::node(&ca, "dns-c");
        let shared = crate::cluster::pinned_peer::shared_with("dns-leader", me, &[]).await;
        assert!(!leads(&shared));
        let id = shared.raft.metrics().borrow().id;
        let one = std::collections::BTreeMap::from([(id, kith_store::openraft::BasicNode::new(""))]);
        shared.raft.initialize(one).await.unwrap();
        let leads_now = shared.raft.wait(Some(std::time::Duration::from_secs(30)));
        leads_now.current_leader(id, "leads").await.unwrap();
        assert!(leads(&shared));
    }

    /// A router that names the house address as a resolver: it is dropped from the upstreams
    /// when a Cluster names it, held by this node or not (and kept when none does).
    #[test]
    fn the_house_address_named_as_an_upstream_is_not_asked() {
        let at = |address: &str| address.parse::<SocketAddr>().unwrap();
        let (listen, house) = (at("0.0.0.0:5353"), Some(Ipv4Addr::new(10, 9, 0, 100)));
        let all = [at("10.9.0.100:5353"), at("1.1.1.1:5353"), at("10.9.0.100:53")];
        assert_eq!(*others(&all, listen, house), [at("1.1.1.1:5353"), at("10.9.0.100:53")]);
        assert_eq!(*others(&all, listen, None), all);
    }

    /// The addresses `client` is told `name` is (type AAAA), sorted.
    fn answers6(zones: &Zones, client: &str, name: &str) -> Vec<std::net::Ipv6Addr> {
        let found = zones.lookup(client.parse().unwrap(), name, 28).unwrap();
        let mut ips: Vec<std::net::Ipv6Addr> = found
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                Rdata::Aaaa(ip) => Some(*ip),
                _ => None,
            })
            .collect();
        ips.sort();
        ips
    }

    #[test]
    fn a_statefulsets_replicas_are_named_under_each_service_and_a_headless_service_answers_them() {
        let mut store = store(
            "
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web, labels: { app: web } }
spec:
  replicas: 3
  template:
    containers: [{ name: main, image: example.org/web }]
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: web }
spec: { headless: true, selector: { app: web }, ports: [{ port: 80 }] }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: api }
spec: { selector: { app: web }, ports: [{ port: 80 }] }
",
        );
        let unit = |replica: u32, ready: bool, address: &str| json!({ "name": "main", "replica": replica, "node": "a", "ready": ready, "address": address });
        let status = |second: &str| json!({ "containers": [unit(0, true, "fd00:1::10"), unit(1, true, second), unit(2, false, "fd00:1::12")] });
        store
            .set_status("Workload/default/web", Some(status("fd00:1::11")))
            .unwrap();
        let before = zones_made_of(&store);

        let ip = |text: &str| text.parse::<std::net::Ipv6Addr>().unwrap();
        let prefix = kith_mesh::prefix(b"test");
        let (zones, _) = zones_of(&store, Some(prefix));
        let client = "10.0.0.1";
        // Each ready replica is named under each Service that selects its Workload, and it
        // answers its own address; one not ready answers nothing.
        assert_eq!(
            answers6(&zones, client, "web-0.web.default.svc.cluster.local"),
            [ip("fd00:1::10")]
        );
        assert_eq!(
            answers6(&zones, client, "web-1.api.default.svc.cluster.local"),
            [ip("fd00:1::11")]
        );
        assert!(answers6(&zones, client, "web-2.api.default.svc.cluster.local").is_empty());
        // A headless Service answers its ready replicas, and not an address of its own.
        assert_eq!(
            answers6(&zones, client, "web.default.svc.cluster.local"),
            [ip("fd00:1::10"), ip("fd00:1::11")]
        );
        assert_eq!(
            answers6(&zones, client, "web.default.kith"),
            [ip("fd00:1::10"), ip("fd00:1::11")]
        );
        // The other Service answers its own address, as it did.
        let api = kith_mesh::service_address(prefix, "default", "api");
        assert_eq!(answers6(&zones, client, "api.default.svc.cluster.local"), [api]);

        // A replica that moves to another address is told apart, so the zones are built again.
        store
            .set_status("Workload/default/web", Some(status("fd00:1::99")))
            .unwrap();
        assert_ne!(zones_made_of(&store), before);
        let (zones, _) = zones_of(&store, Some(prefix));
        assert_eq!(
            answers6(&zones, client, "web-1.api.default.svc.cluster.local"),
            [ip("fd00:1::99")]
        );
    }

    /// A headless Service with no ready replica is a name that exists with no records (NODATA, as
    /// Kubernetes answers), not one that is missing (NXDOMAIN, which a client holds for the SOA's
    /// minimum); a Service that is not there is still NXDOMAIN.
    #[test]
    fn a_headless_service_with_no_replica_answers_nodata() {
        let mut store = store(
            "
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: db, namespace: prod, labels: { app: db } }
spec:
  replicas: 1
  template:
    containers: [{ name: main, image: example.org/db }]
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: db, namespace: prod }
spec: { headless: true, selector: { app: db }, ports: [{ port: 80 }] }
",
        );
        let (zones, _) = zones_of(&store, Some(kith_mesh::prefix(b"test")));
        let client = "10.0.0.1".parse().unwrap();
        for name in ["db.prod.kith", "db.prod.svc.cluster.local"] {
            let found = zones.lookup(client, name, 28).unwrap();
            assert_eq!(
                (found.rcode, found.answers.len(), found.authority.len()),
                (0, 0, 1),
                "{name}"
            );
        }
        let missing = zones.lookup(client, "nope.prod.svc.cluster.local", 28).unwrap();
        assert_eq!(missing.rcode, 3);
        // With no mesh prefix a Service has no address of its own either, and still exists.
        let (bare, _) = zones_of(&store, None);
        let found = bare.lookup(client, "db.prod.kith", 28).unwrap();
        assert_eq!((found.rcode, found.answers.len(), found.authority.len()), (0, 0, 1));
        // Deleted, the name is missing again.
        store.delete("Service/prod/db").unwrap();
        let (gone, _) = zones_of(&store, Some(kith_mesh::prefix(b"test")));
        assert_eq!(gone.lookup(client, "db.prod.kith", 28).unwrap().rcode, 3);
    }

    #[test]
    fn a_service_or_namespace_with_a_dot_in_its_name_is_not_served() {
        // A Service `db-0` in namespace `db.prod` would name `db-0.db.prod.svc.cluster.local`, which
        // is replica 0 of Workload `db` under Service `db` in `prod`: a dotted one is not served.
        let mut store = store(
            "
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: db, namespace: prod, labels: { app: db } }
spec:
  replicas: 1
  template:
    containers: [{ name: main, image: example.org/db }]
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: db, namespace: prod }
spec: { headless: true, selector: { app: db }, ports: [{ port: 80 }] }
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: db-0, namespace: 'db.prod' }
spec: { selector: { app: other }, ports: [{ port: 80 }] }
",
        );
        let status = json!({ "containers": [{ "name": "main", "replica": 0, "node": "a", "ready": true, "address": "fd00:1::10" }] });
        store.set_status("Workload/prod/db", Some(status)).unwrap();
        let prefix = kith_mesh::prefix(b"test");
        let (zones, _) = zones_of(&store, Some(prefix));
        let client = "10.0.0.1";
        let ip = |text: &str| text.parse::<std::net::Ipv6Addr>().unwrap();
        assert_eq!(
            answers6(&zones, client, "db-0.db.prod.svc.cluster.local"),
            [ip("fd00:1::10")]
        );
        assert!(answers6(&zones, client, "db-0.db.prod.kith").is_empty());
    }
}
