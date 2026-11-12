//! kithd's DNS server (`--dns ADDR:PORT`): what it answers comes from the store.
//!
//! - `<node>.node.kith`: the address each Node is reached at; `<node>.mesh.kith`: its
//!   address on the mesh, if it is on it.
//! - `DNSZone` and `DNSRecord`: names of your own. A zone with `clients` is split
//!   horizon: clients in those networks get it, and not a zone for everyone with the
//!   same domain.
//! - Every other name goes to the upstream resolvers, for clients on private networks.
//!
//! The server itself is the `kith-dns` crate; this builds its zones again whenever a
//! resource they are made from changes, and reports on each DNSZone and DNSRecord.
//
// ponytail: `<service>.<namespace>.kith` waits for Services to have addresses (the
// load balancer). A client inside two zones' different `clients` lists gets only the
// first of them by name; give zones that belong together the same list.

use crate::Shared;
use kith_api::Resource;
use kith_api::kinds::{DnsRecordSpec, DnsRecordType, DnsZoneSpec};
use kith_api::store::Store;
use kith_dns::{Cidr, Rdata, Record, Records, View, Zones};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
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

/// What the server answers from, and what to report on each DNSZone and DNSRecord.
pub fn zones_of(store: &Store, mesh: Option<std::net::Ipv6Addr>) -> (Zones, BTreeMap<String, Value>) {
    let mut status = BTreeMap::new();
    let served = || json!({ "state": "served" });
    let failed = |why: String| json!({ "state": "error", "message": why });

    // Our own names. Having the zone means a name that is not in it is answered "no
    // such name" here, and never sent to the internet to ask.
    let mut own = vec![soa("kith")];
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
            own.push(Record { name, ttl, data });
        }
    }

    let mut zones: BTreeMap<String, (Zone, u32)> = BTreeMap::new();
    for resource in store.list(Some("DNSZone")) {
        let report = match spec::<DnsZoneSpec>(resource) {
            Ok(zone) => {
                let made = Zone {
                    domain: zone.domain.to_ascii_lowercase(),
                    clients: zone.clients,
                    records: Vec::new(),
                };
                zones.insert(resource.metadata.name.clone(), (made, zone.ttl.unwrap_or(TTL)));
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
            let (zone, ttl) = zones.get_mut(&record.zone).ok_or_else(no_zone)?;
            let records = records_of(&record, &zone.domain, *ttl)?;
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
    let zones: Vec<Zone> = zones.into_values().map(|(zone, _)| zone).collect();
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
        records
    };
    let lists: BTreeSet<&[String]> = zones.iter().map(|zone| zone.clients.as_slice()).collect();
    let view = |clients: &&[String]| View {
        nets: clients.iter().filter_map(|net| net.parse::<Cidr>().ok()).collect(),
        records: assemble(clients),
    };
    let views = lists.iter().filter(|clients| !clients.is_empty()).map(view).collect();
    let records = assemble(&[]);
    (Zones { records, views }, status)
}

/// The resolvers in `/etc/resolv.conf`, for names that are not ours.
pub fn system_upstreams() -> Vec<SocketAddr> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let server = |line: &str| {
        let mut words = line.split_ascii_whitespace();
        (words.next() == Some("nameserver")).then(|| words.next()?.parse::<IpAddr>().ok())?
    };
    conf.lines()
        .filter_map(server)
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
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
    mut upstreams: Vec<SocketAddr>,
    mut stopping: watch::Receiver<bool>,
) {
    let listen = tcp.local_addr().expect("a bound socket has an address");
    upstreams.retain(|upstream| !is_self(*upstream, listen));
    eprintln!("kithd: serving DNS on {listen}; other names go to {upstreams:?}");
    if upstreams.is_empty() {
        eprintln!("kithd: no other resolver to ask (--dns-upstream): only names in the store resolve");
    }
    let (zones, served) = watch::channel(Arc::new(Zones::default()));
    let feed = async {
        let mut generation = shared.generation.subscribe();
        // What the zones were last built from: most changes to the store are not about DNS.
        // ponytail: finding that out reads three kinds on every change; index them if stores get large.
        let mut built_from = None;
        loop {
            let reports = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                let kinds = ["Node", "Service", "DNSZone", "DNSRecord"].into_iter();
                let made_of = |r: &Resource| {
                    (
                        r.key(),
                        // Not the revision: deleted and made again, it starts over.
                        r.spec.clone(),
                        r.status.as_ref().map(|s| s["address"].clone()),
                    )
                };
                let from: Vec<_> = kinds
                    .flat_map(|kind| state.store.list(Some(kind)))
                    .map(made_of)
                    .collect();
                (built_from.as_ref() != Some(&from)).then(|| {
                    built_from = Some(from);
                    let mesh = shared
                        .cluster
                        .as_ref()
                        .map(|cluster| crate::mesh::prefix(&cluster.me.ca));
                    let (built, reports) = zones_of(&state.store, mesh);
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
            if let Some(statuses) = reports.filter(|statuses| !statuses.is_empty())
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
    tokio::select! {
        () = kith_dns::serve(udp, tcp, served, upstreams, Vec::new()) => {}
        () = feed => {}
        _ = stopping.changed() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
