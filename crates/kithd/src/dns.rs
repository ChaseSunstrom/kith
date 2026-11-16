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
use kith_api::kinds::{DnsRecordSpec, DnsRecordType, DnsZoneSpec};
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

/// What the zones are made of, as `run` compares it with the last build: each resource's key and
/// spec, and a Node's address, what it serves and its state (the ingress addresses come from
/// those). Not the revision: deleted and made again, it starts over.
fn zones_made_of(store: &Store) -> Vec<(String, Value, Option<Value>)> {
    let kinds = ["Node", "Service", "DNSZone", "DNSRecord", "Namespace"].into_iter();
    kinds
        .flat_map(|kind| store.list(Some(kind)))
        .map(|r| {
            let status = r.status.as_ref().map(|s| {
                if r.kind == "Node" {
                    json!([s["address"], s["serves"], s["state"]])
                } else {
                    s["address"].clone()
                }
            });
            (r.key(), r.spec.clone(), status)
        })
        .collect()
}

/// What the server answers from, and what to report on each DNSZone and DNSRecord.
pub fn zones_of(store: &Store, mesh: Option<std::net::Ipv6Addr>) -> (Zones, BTreeMap<String, Value>) {
    let mut status = BTreeMap::new();
    let served = || json!({ "state": "served" });
    let failed = |why: String| json!({ "state": "error", "message": why });

    // Our own names. Having the zone means a name that is not in it is answered "no
    // such name" here, and never sent to the internet to ask.
    let mut own = vec![soa("kith"), soa("cluster.local")];
    for node in store.list(Some("Node")) {
        let address = node.status.as_ref().and_then(|status| status["address"].as_str());
        if let Some(address) = address.and_then(|address| address.parse::<SocketAddr>().ok()) {
            let data = match address.ip() {
                IpAddr::V4(ip) => Rdata::A(ip),
                IpAddr::V6(ip) => Rdata::Aaaa(ip),
            };
            let (name, ttl) = (format!("{}.node.kith", node.metadata.name), NODE_TTL);
            own.push(Record { name, ttl, data });
        }
        let mesh = node
            .status
            .as_ref()
            .and_then(|status| status["mesh"]["address"].as_str());
        if let Some(address) = mesh.and_then(|address| address.parse().ok()) {
            let (name, ttl) = (format!("{}.mesh.kith", node.metadata.name), NODE_TTL);
            let data = Rdata::Aaaa(address);
            own.push(Record { name, ttl, data });
        }
    }
    // `<service>.<namespace>.kith`: the Service's address on the mesh.
    for (key, address) in mesh
        .into_iter()
        .flat_map(|mesh| crate::services::addresses(store, mesh))
    {
        let mut parts = key.split('/').skip(1);
        if let (Some(namespace), Some(service)) = (parts.next(), parts.next()) {
            let (name, ttl) = (format!("{service}.{namespace}.kith"), NODE_TTL);
            let data = Rdata::Aaaa(address);
            own.push(Record {
                name,
                ttl,
                data: data.clone(),
            });
            // (As what is written for Kubernetes names it: a pod is told to look there.)
            let name = format!("{service}.{namespace}.svc.cluster.local");
            own.push(Record { name, ttl, data });
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
        for record in own
            .iter()
            .cloned()
            .chain(apexes)
            .chain(shown.iter().flat_map(|zone| zone.records.clone()))
        {
            // Each record was added once already, beside the rest of its domain's, so this
            // only fails where one zone's domain lies inside another's and they collide.
            let _ = records.add(record);
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

/// UDP and TCP on the same address; with port 0, on the same free port.
pub async fn bind(listen: SocketAddr) -> Result<(UdpSocket, TcpListener), String> {
    let failed = |e: std::io::Error| format!("serving DNS on {listen}: {e}");
    for _ in 0..20 {
        let tcp = TcpListener::bind(listen).await.map_err(failed)?;
        let address = tcp.local_addr().map_err(failed)?;
        match UdpSocket::bind(address).await {
            Ok(udp) => return Ok((udp, tcp)),
            // Someone else has that port on UDP: with port 0, take another.
            Err(_) if listen.port() == 0 => {}
            Err(e) => return Err(failed(e)),
        }
    }
    Err(format!("serving DNS on {listen}: no port is free on both UDP and TCP"))
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
    let ours = move |all: &[SocketAddr]| -> Arc<[SocketAddr]> {
        all.iter()
            .copied()
            .filter(|upstream| !is_self(*upstream, listen))
            .collect()
    };
    let said = move |now: &[SocketAddr]| {
        eprintln!("kithd: serving DNS on {listen}; other names go to {now:?}");
        if now.is_empty() {
            eprintln!("kithd: no other resolver to ask (--dns-upstream): only names in the store resolve");
        }
    };
    let (ask, asked) = watch::channel(ours(&upstreams.borrow_and_update()));
    said(&asked.borrow());
    let told = async {
        while upstreams.changed().await.is_ok() {
            let now = ours(&upstreams.borrow_and_update());
            said(&now);
            ask.send_replace(now);
        }
        // (Resolvers named on the command line: nothing more is told.)
        std::future::pending::<()>().await;
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
        // ponytail: finding that out reads five kinds on every change; index them if stores get large.
        let mut built_from = None;
        loop {
            let reports = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                let from = zones_made_of(&state.store);
                (built_from.as_ref() != Some(&from)).then(|| {
                    built_from = Some(from);
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
            if let Some(statuses) = reports.filter(|statuses| !statuses.is_empty() && !worker)
                && let Err(e) = shared.submit(kith_store::Command::Status { statuses }).await
            {
                eprintln!("kithd: reporting on DNS records: {e}");
                // Tried again at the next change to the store.
                built_from = None;
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let pods = format!("{}/16", kith_mesh::pod::GATEWAY);
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
        store
            .set_status(
                "Node/alpha",
                Some(json!({ "address": "10.1.2.3:7443", "mesh": { "address": "fd00:1::1" } })),
            )
            .unwrap();
        let mesh = kith_mesh::prefix(b"test");
        let (zones, status) = zones_of(&store, Some(mesh));
        let outside = "198.51.100.1";
        let on_mesh = zones.lookup(outside.parse().unwrap(), "alpha.mesh.kith", 28).unwrap();
        assert_eq!(on_mesh.answers[0].data, Rdata::Aaaa("fd00:1::1".parse().unwrap()));

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
}
