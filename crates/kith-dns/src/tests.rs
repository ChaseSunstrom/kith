use crate::wire::read_name;
use crate::*;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::time::timeout;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const A: u16 = 1;
const CNAME: u16 = 5;
const TXT: u16 = 16;
const SRV: u16 = 33;
const ANY: u16 = 255;

use std::net::IpAddr;

/// A query packet built by hand.
fn query(id: u16, name: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
    let mut q = [id, 0x0100, 1, 0, 0, u16::from(edns.is_some())]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect::<Vec<_>>();
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.push(0);
    q.extend([qtype.to_be_bytes(), 1u16.to_be_bytes()].concat());
    if let Some(size) = edns {
        q.push(0);
        q.extend([41u16, size, 0, 0, 0].iter().flat_map(|v| v.to_be_bytes()));
    }
    q
}

struct Rr {
    name: String,
    ty: u16,
    at: usize,
    len: usize,
}

struct Reply {
    raw: Vec<u8>,
    flags: u16,
    an: Vec<Rr>,
    ns: Vec<Rr>,
}

impl Reply {
    fn rcode(&self) -> u16 {
        self.flags & 0xF
    }
    fn data(&self, r: &Rr) -> &[u8] {
        &self.raw[r.at..r.at + r.len]
    }
    fn name_at(&self, r: &Rr) -> String {
        read_name(&self.raw, r.at).unwrap().0
    }
}

fn u16_at(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([b[p], b[p + 1]])
}

fn decode(raw: Vec<u8>) -> Reply {
    let (qd, an, ns) = (
        u16_at(&raw, 4),
        usize::from(u16_at(&raw, 6)),
        usize::from(u16_at(&raw, 8)),
    );
    let mut p = 12;
    for _ in 0..qd {
        p = read_name(&raw, p).unwrap().1 + 4;
    }
    let mut rrs = vec![];
    for _ in 0..an + ns {
        let (name, next) = read_name(&raw, p).unwrap();
        let len = usize::from(u16_at(&raw, next + 8));
        rrs.push(Rr {
            name,
            ty: u16_at(&raw, next),
            at: next + 10,
            len,
        });
        p = next + 10 + len;
    }
    // What is left is the OPT record, if the reply has one.
    assert_eq!(raw.len() - p, 11 * usize::from(u16_at(&raw, 10)), "trailing bytes");
    let ns = rrs.split_off(an);
    Reply {
        flags: u16_at(&raw, 2),
        an: rrs,
        ns,
        raw,
    }
}

fn rec(name: &str, data: Rdata) -> Record {
    Record {
        name: name.into(),
        ttl: 60,
        data,
    }
}

fn soa() -> Record {
    rec(
        "kith",
        Rdata::Soa {
            mname: "ns.kith".into(),
            rname: "root.kith".into(),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 30,
        },
    )
}

fn zones() -> Zones {
    let mut r = Records::default();
    let ip = |a, b, c, d| Rdata::A(Ipv4Addr::new(a, b, c, d));
    for x in [
        soa(),
        rec("web.default.kith", ip(10, 0, 0, 1)),
        rec("web.default.kith", Rdata::Aaaa("fd00::1".parse().unwrap())),
        rec("web.default.kith", Rdata::Txt("v=1".into())),
        rec(
            "web.default.kith",
            Rdata::Srv {
                priority: 1,
                weight: 2,
                port: 80,
                target: "web.default.kith".into(),
            },
        ),
        rec("alias.kith", Rdata::Cname("web.default.kith".into())),
        rec("out.kith", Rdata::Cname("example.com".into())),
        rec("loop1.kith", Rdata::Cname("loop2.kith".into())),
        rec("loop2.kith", Rdata::Cname("loop1.kith".into())),
        rec("*.wild.kith", ip(10, 9, 9, 9)),
        rec("4.3.2.1.rev.kith", Rdata::Ptr("web.default.kith".into())),
        rec("kith", Rdata::Ns("ns.kith".into())),
    ] {
        r.add(x).unwrap();
    }
    Zones {
        records: r,
        views: vec![],
    }
}

fn ask(z: &Zones, name: &str, qtype: u16) -> Reply {
    match answer(&query(7, name, qtype, None), LOCAL, z, true) {
        Answer::Reply(r) => decode(r),
        other => panic!("{other:?}"),
    }
}

#[test]
fn answers_records_of_every_type() {
    let z = zones();
    let r = ask(&z, "web.default.kith", A);
    assert_eq!((r.rcode(), r.flags & 0x0400 != 0, r.an.len()), (0, true, 1));
    assert_eq!(r.data(&r.an[0]), [10, 0, 0, 1]);
    assert_eq!(
        ask(&z, "web.default.kith", 28)
            .data(&ask(&z, "web.default.kith", 28).an[0])
            .len(),
        16
    );
    assert_eq!(ask(&z, "web.default.kith", TXT).an[0].ty, TXT);
    let srv = ask(&z, "web.default.kith", SRV);
    assert_eq!(&srv.data(&srv.an[0])[..6], [0, 1, 0, 2, 0, 80]);
    let ptr = ask(&z, "4.3.2.1.rev.kith", 12);
    assert_eq!(ptr.name_at(&ptr.an[0]), "web.default.kith");
    assert_eq!(ask(&z, "kith", 2).an[0].ty, 2);
    assert_eq!(ask(&z, "kith", 6).an[0].ty, 6);
}

#[test]
fn names_compare_case_insensitively_and_the_reply_echoes_the_case() {
    let r = ask(&zones(), "WeB.Default.KITH", A);
    assert_eq!(r.an.len(), 1);
    assert_eq!(r.an[0].name, "WeB.Default.KITH");
    assert_eq!(read_name(&r.raw, 12).unwrap().0, "WeB.Default.KITH");
}

#[test]
fn replies_compress_names() {
    let r = ask(&zones(), "web.default.kith", A);
    // The answer's owner is a 2-byte pointer to the question.
    assert_eq!(r.raw[r.raw.len() - 4 - 10 - 2..][..2], [0xC0, 12]);
}

#[test]
fn missing_names_get_nxdomain_or_nodata_with_the_soa() {
    let z = zones();
    let r = ask(&z, "nope.kith", A);
    assert_eq!((r.rcode(), r.an.len(), r.ns.len()), (3, 0, 1));
    assert_eq!((r.ns[0].ty, r.ns[0].name.as_str()), (6, "kith"));
    // The SOA's TTL is capped by its minimum (30).
    assert_eq!(
        u32::from_be_bytes(r.raw[r.ns[0].at - 6..r.ns[0].at - 2].try_into().unwrap()),
        30
    );
    let r = ask(&z, "web.default.kith", 15);
    assert_eq!((r.rcode(), r.an.len(), r.ns.len()), (0, 0, 1));
}

#[test]
fn cnames_are_chased_inside_zones_and_left_alone_outside() {
    let z = zones();
    let r = ask(&z, "alias.kith", A);
    assert_eq!(r.an.iter().map(|x| x.ty).collect::<Vec<_>>(), [CNAME, A]);
    assert_eq!(r.an[1].name, "web.default.kith");
    let r = ask(&z, "out.kith", A);
    assert_eq!((r.rcode(), r.an.len()), (0, 1));
    assert_eq!(ask(&z, "alias.kith", CNAME).an.len(), 1);
    assert_eq!(ask(&z, "loop1.kith", A).rcode(), 2);
}

#[test]
fn wildcards_match_below_but_not_at_the_name() {
    let z = zones();
    let r = ask(&z, "a.b.wild.kith", A);
    assert_eq!((r.rcode(), r.an[0].name.as_str()), (0, "a.b.wild.kith"));
    assert_eq!(ask(&z, "wild.kith", A).rcode(), 3);
    // A name that exists with no wildcard of its own is not covered by one further up.
    let mut z = zones();
    z.records.add(rec("*.kith", Rdata::A(Ipv4Addr::LOCALHOST))).unwrap();
    assert_eq!(ask(&z, "x.kith", A).rcode(), 0);
    z.records.add(rec("default.kith", Rdata::Txt("d".into()))).unwrap();
    assert_eq!(ask(&z, "x.default.kith", A).rcode(), 3);
}

#[test]
fn any_gets_an_empty_noerror_and_responses_are_never_answered() {
    let z = zones();
    let r = ask(&z, "web.default.kith", ANY);
    assert_eq!((r.rcode(), r.an.len()), (0, 0));
    let mut q = query(1, "web.default.kith", A, None);
    q[2] |= 0x80;
    assert_eq!(answer(&q, LOCAL, &z, true), Answer::Drop);
    assert_eq!(answer(&q[..5], LOCAL, &z, true), Answer::Drop);
    q[2] = 0x28; // opcode 5, UPDATE
    let Answer::Reply(r) = answer(&q, LOCAL, &z, true) else {
        panic!()
    };
    assert_eq!(decode(r).rcode(), 4);
}

#[test]
fn outside_names_are_forwarded() {
    assert_eq!(
        answer(&query(1, "example.com", A, None), LOCAL, &zones(), true),
        Answer::Forward
    );
}

#[test]
fn views_replace_the_default_records_for_their_clients() {
    let mut z = zones();
    let mut lan = Records::default();
    lan.add(soa()).unwrap();
    lan.add(rec("web.default.kith", Rdata::A(Ipv4Addr::new(192, 168, 1, 5))))
        .unwrap();
    z.views.push(View {
        nets: vec!["192.168.0.0/16".parse().unwrap(), "fd12::/16".parse().unwrap()],
        records: lan,
    });
    let ip = |s: &str| -> Vec<u8> {
        let Answer::Reply(r) = answer(&query(1, "web.default.kith", A, None), s.parse().unwrap(), &z, true) else {
            panic!()
        };
        let r = decode(r);
        r.data(&r.an[0]).to_vec()
    };
    assert_eq!(ip("192.168.7.7"), [192, 168, 1, 5]);
    assert_eq!(ip("fd12::9"), [192, 168, 1, 5]);
    assert_eq!(ip("::ffff:192.168.7.7"), [192, 168, 1, 5]);
    assert_eq!(ip("10.1.1.1"), [10, 0, 0, 1]);
    assert_eq!(ip("fd13::9"), [10, 0, 0, 1]);
}

#[test]
fn cidr_parses_and_matches() {
    let c: Cidr = "10.1.0.0/16".parse().unwrap();
    assert!(c.contains("10.1.255.255".parse().unwrap()) && !c.contains("10.2.0.0".parse().unwrap()));
    assert!(!c.contains("fd00::1".parse().unwrap()));
    assert!("0.0.0.0/0".parse::<Cidr>().unwrap().contains(LOCAL));
    assert!("::/0".parse::<Cidr>().unwrap().contains("fd00::1".parse().unwrap()));
    assert!("1.2.3.4".parse::<Cidr>().unwrap().contains("1.2.3.4".parse().unwrap()));
    for bad in ["1.2.3.4/33", "::/129", "x/8", "1.2.3.4/", "1.2.3.4/-1", ""] {
        assert!(bad.parse::<Cidr>().is_err(), "{bad}");
    }
}

#[test]
fn records_with_bad_names_are_refused() {
    let mut r = Records::default();
    for name in [
        "",
        "a..b",
        &"a".repeat(64),
        &format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        ),
        "é.kith",
    ] {
        assert!(r.add(rec(name, Rdata::A(Ipv4Addr::LOCALHOST))).is_err(), "{name}");
    }
    assert!(r.add(rec("a.kith", Rdata::Cname("b..kith".into()))).is_err());
    assert!(r.add(rec("a.kith", Rdata::Txt("x".repeat(4001)))).is_err());
    assert!(r.add(rec("a.kith.", Rdata::A(Ipv4Addr::LOCALHOST))).is_ok());
}

#[test]
fn long_udp_replies_are_truncated_and_tcp_ones_are_not() {
    let mut z = zones();
    for i in 0..60u8 {
        z.records
            .add(rec("big.kith", Rdata::A(Ipv4Addr::new(10, 1, 1, i))))
            .unwrap();
    }
    let q = query(1, "big.kith", A, None);
    let Answer::Reply(r) = answer(&q, LOCAL, &z, true) else {
        panic!()
    };
    let r = decode(r);
    assert!(r.raw.len() <= 512 && r.flags & 0x0200 != 0 && r.an.is_empty());
    // With EDNS 1232 all 60 (16 bytes each) fit; a client size over 1232 is capped.
    let Answer::Reply(r) = answer(&query(1, "big.kith", A, Some(4096)), LOCAL, &z, true) else {
        panic!()
    };
    let r = decode(r);
    assert!(r.raw.len() <= 1232 && r.flags & 0x0200 == 0 && r.an.len() == 60);
    for i in 60..120u8 {
        z.records
            .add(rec("big.kith", Rdata::A(Ipv4Addr::new(10, 1, 2, i))))
            .unwrap();
    }
    let Answer::Reply(r) = answer(&query(1, "big.kith", A, Some(4096)), LOCAL, &z, true) else {
        panic!()
    };
    assert!(decode(r).flags & 0x0200 != 0);
    let Answer::Reply(r) = answer(&q, LOCAL, &z, false) else {
        panic!()
    };
    let r = decode(r);
    assert!(r.flags & 0x0200 == 0 && r.an.len() == 120);
}

#[test]
fn edns_queries_get_an_opt_back() {
    let Answer::Reply(r) = answer(&query(1, "web.default.kith", A, Some(1400)), LOCAL, &zones(), true) else {
        panic!()
    };
    assert_eq!(u16_at(&r, 10), 1);
    assert_eq!(r[r.len() - 11..][..3], [0, 0, 41]);
}

#[test]
fn hostile_packets_are_rejected_without_panicking() {
    let z = zones();
    let head = |qd: u16| [0u8, 1, 1, 0, (qd >> 8) as u8, qd as u8, 0, 0, 0, 0, 0, 0];
    let formerr = |p: Vec<u8>| {
        let Answer::Reply(r) = answer(&p, LOCAL, &z, true) else {
            panic!("{p:?}")
        };
        assert_eq!(r[3] & 0xF, 1);
    };
    // A pointer to itself, to a later byte, and two pointers in a loop.
    formerr([&head(1)[..], &[0xC0, 12, 0, 1, 0, 1]].concat());
    formerr([&head(1)[..], &[0xC0, 40, 0, 1, 0, 1]].concat());
    formerr([&head(1)[..], &[1, b'a', 0xC0, 12, 0, 1, 0, 1]].concat());
    // A reserved label type, a label running past the end, a missing type and class.
    formerr([&head(1)[..], &[0x80, 0, 0, 1, 0, 1]].concat());
    formerr([&head(1)[..], &[9, b'a', b'b']].concat());
    formerr([&head(1)[..], &[1, b'a', 0]].concat());
    // No question, two questions, a record count with no records, an rdlength past the end.
    formerr(head(0).to_vec());
    formerr(head(2).to_vec());
    let mut p = query(1, "a.kith", A, None);
    p[11] = 1;
    formerr(p);
    let mut p = query(1, "a.kith", A, Some(512));
    let n = p.len();
    p[n - 1] = 9;
    formerr(p);
    // A name over 255 bytes, a label with a dot or a high byte.
    formerr([&head(1)[..], &[1, b'a'].repeat(130), &[0, 0, 1, 0, 1]].concat());
    formerr([&head(1)[..], &[3, b'a', b'.', b'b', 0, 0, 1, 0, 1]].concat());
    formerr([&head(1)[..], &[1, 0xE9, 0, 0, 1, 0, 1]].concat());
}

#[test]
fn random_bytes_never_panic() {
    let z = zones();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let valid = query(5, "web.default.kith", A, Some(1232));
    for i in 0..30_000 {
        let mut p: Vec<u8> = if i % 2 == 0 {
            (0..next() % 80).map(|_| next() as u8).collect()
        } else {
            // A valid query with a few bytes flipped, then maybe cut short.
            let mut p = valid.clone();
            for _ in 0..1 + next() % 4 {
                let at = next() as usize % p.len();
                p[at] = next() as u8;
            }
            p
        };
        if next() % 4 == 0 {
            p.truncate(next() as usize % (p.len() + 1));
        }
        match answer(&p, LOCAL, &z, i % 3 == 0) {
            Answer::Reply(r) => assert!(r.len() >= 12 && r[2] & 0x80 != 0),
            Answer::Forward | Answer::Drop => {}
        }
        let _ = servfail(&p);
    }
}

// --- servers ---

async fn frame(s: &mut TcpStream, msg: &[u8]) -> Vec<u8> {
    s.write_all(&[&(msg.len() as u16).to_be_bytes()[..], msg].concat())
        .await
        .unwrap();
    let mut len = [0; 2];
    s.read_exact(&mut len).await.unwrap();
    let mut r = vec![0; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut r).await.unwrap();
    r
}

/// The upstream's reply to `q`: the question and one A record, 1.2.3.4.
fn upstream_reply(q: &[u8], id: u16) -> Vec<u8> {
    let mut r = [id, 0x8180, 1, 1, 0, 0]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect::<Vec<_>>();
    r.extend(&q[12..]);
    r.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
    r
}

/// A fake upstream on one port for UDP and TCP. Over UDP it first sends a reply with the wrong id.
async fn fake_upstream() -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let mut buf = [0; 512];
        loop {
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            let id = u16_at(&buf, 0);
            udp.send_to(&upstream_reply(&buf[..n], id ^ 1), from).await.unwrap();
            udp.send_to(&upstream_reply(&buf[..n], id), from).await.unwrap();
        }
    });
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tcp.accept().await.unwrap();
            let mut len = [0; 2];
            s.read_exact(&mut len).await.unwrap();
            let mut q = vec![0; usize::from(u16::from_be_bytes(len))];
            s.read_exact(&mut q).await.unwrap();
            let r = upstream_reply(&q, u16_at(&q, 0));
            s.write_all(&[&(r.len() as u16).to_be_bytes()[..], &r].concat())
                .await
                .unwrap();
        }
    });
    addr
}

/// An address nothing listens on (UDP and TCP both refuse at once).
async fn dead_upstream() -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.local_addr().unwrap()
}

async fn start(z: Zones, upstreams: Vec<SocketAddr>) -> (SocketAddr, SocketAddr, watch::Sender<Arc<Zones>>) {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (u, t) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
    let (tx, rx) = watch::channel(Arc::new(z));
    tokio::spawn(serve(udp, tcp, rx, upstreams));
    (u, t, tx)
}

async fn udp_ask(to: SocketAddr, q: &[u8]) -> Reply {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(q, to).await.unwrap();
    let mut buf = vec![0; 4096];
    let (n, _) = timeout(Duration::from_secs(5), s.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    decode(buf[..n].to_vec())
}

async fn tcp_ask(to: SocketAddr, q: &[u8]) -> Reply {
    let mut s = TcpStream::connect(to).await.unwrap();
    decode(timeout(Duration::from_secs(5), frame(&mut s, q)).await.unwrap())
}

#[tokio::test]
async fn names_resolve_over_udp_and_tcp_and_unknown_names_go_upstream() {
    let up = fake_upstream().await;
    // The first upstream is dead: the second is tried.
    let (u, t, _tx) = start(zones(), vec![dead_upstream().await, up]).await;
    let q = query(0x1234, "web.default.kith", A, None);
    for r in [udp_ask(u, &q).await, tcp_ask(t, &q).await] {
        assert_eq!((u16_at(&r.raw, 0), r.rcode(), r.flags & 0x0400 != 0), (0x1234, 0, true));
        assert_eq!(r.data(&r.an[0]), [10, 0, 0, 1]);
    }
    let q = query(0x4321, "example.com", A, None);
    for r in [udp_ask(u, &q).await, tcp_ask(t, &q).await] {
        assert_eq!(
            (u16_at(&r.raw, 0), r.rcode(), r.flags & 0x0400 != 0),
            (0x4321, 0, false)
        );
        assert_eq!(r.data(&r.an[0]), [1, 2, 3, 4]);
    }
}

#[tokio::test]
async fn servfail_when_no_upstream_answers() {
    let (u, t, _tx) = start(zones(), vec![dead_upstream().await]).await;
    let q = query(9, "example.com", A, None);
    for r in [udp_ask(u, &q).await, tcp_ask(t, &q).await] {
        assert_eq!((u16_at(&r.raw, 0), r.rcode(), r.an.len()), (9, 2, 0));
        assert_eq!(read_name(&r.raw, 12).unwrap().0, "example.com");
    }
    let (u, _, _tx) = start(zones(), vec![]).await;
    assert_eq!(udp_ask(u, &q).await.rcode(), 2);
}

#[tokio::test]
async fn a_new_zones_value_is_served_at_once() {
    let (u, _, tx) = start(Zones::default(), vec![dead_upstream().await]).await;
    let q = query(1, "web.default.kith", A, None);
    assert_eq!(udp_ask(u, &q).await.rcode(), 2);
    tx.send(Arc::new(zones())).unwrap();
    assert_eq!(udp_ask(u, &q).await.an.len(), 1);
}

#[tokio::test]
async fn a_tcp_connection_serves_many_queries_and_junk_ends_it() {
    let (_, t, _tx) = start(zones(), vec![]).await;
    let mut s = TcpStream::connect(t).await.unwrap();
    for id in 1..4 {
        let r = decode(frame(&mut s, &query(id, "web.default.kith", A, None)).await);
        assert_eq!(u16_at(&r.raw, 0), id);
    }
    // A frame shorter than a header closes the connection.
    s.write_all(&[0, 3, 1, 2, 3]).await.unwrap();
    let mut buf = [0; 1];
    // Closed with bytes unread, the server's socket may reset instead of ending cleanly.
    assert!(matches!(
        timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap(),
        Ok(0) | Err(_)
    ));
}
