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
fn cnames_are_chased_inside_zones_and_handed_on_for_the_upstream_outside() {
    let z = zones();
    let r = ask(&z, "alias.kith", A);
    assert_eq!(r.an.iter().map(|x| x.ty).collect::<Vec<_>>(), [CNAME, A]);
    assert_eq!(r.an[1].name, "web.default.kith");
    // Outside, the server has to ask: the zone's own answer is the CNAME alone.
    let Answer::Chase(c) = answer(&query(7, "out.kith", A, None), LOCAL, &z, true) else {
        panic!("not a chase")
    };
    let r = decode(c.plain());
    assert_eq!((r.rcode(), r.an.len()), (0, 1));
    assert_eq!(ask(&z, "alias.kith", CNAME).an.len(), 1);
    assert_eq!(ask(&z, "out.kith", CNAME).an.len(), 1);
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
    for i in 60..100u8 {
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
    assert!(r.flags & 0x0200 == 0 && r.an.len() == 100);
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

/// Valid queries that reach the record loop: an OPT record, an answer record, and both with
/// names that end in a compression pointer.
fn seed_packets() -> Vec<Vec<u8>> {
    let rr = [1, b'z', 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4];
    let opt = [0, 0, 41, 4, 0xD0, 0, 0, 0, 0, 0, 0];
    let mut with_an = query(5, "web.default.kith", A, None);
    with_an[7] = 1;
    with_an.extend(rr);
    let mut with_ar = query(5, "web.default.kith", A, None);
    with_ar[11] = 2;
    with_ar.extend(rr);
    with_ar.extend(opt);
    vec![query(5, "web.default.kith", A, Some(1232)), with_an, with_ar]
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
    let seeds = seed_packets();
    assert!(seeds.iter().all(|s| wire::Query::parse(s).is_some()));
    let mut parsed = 0;
    for i in 0..40_000 {
        let mut p: Vec<u8> = if i % 2 == 0 {
            (0..next() % 80).map(|_| next() as u8).collect()
        } else {
            // A valid query with a few bytes flipped anywhere; half the time it keeps one question.
            let mut p = seeds[next() as usize % seeds.len()].clone();
            for _ in 0..1 + next() % 4 {
                let at = next() as usize % p.len();
                p[at] = next() as u8;
            }
            if next() % 2 == 0 {
                p[4..6].copy_from_slice(&[0, 1]);
            }
            p
        };
        if next() % 4 == 0 {
            p.truncate(next() as usize % (p.len() + 1));
        }
        parsed += usize::from(wire::Query::parse(&p).is_some());
        match answer(&p, LOCAL, &z, i % 3 == 0) {
            Answer::Reply(r) => assert!(r.len() >= 12 && r[2] & 0x80 != 0),
            Answer::Forward | Answer::Drop | Answer::Chase(_) => {}
        }
        let _ = servfail(&p);
        // Upstream replies are hostile too.
        let _ = wire::question(&p);
        let _ = wire::for_upstream(&p, 1);
        let _ = wire::truncate(p.clone(), 12 + next() as usize % 100);
    }
    assert!(parsed > 2_000, "only {parsed} mutated packets got past the parser");
}

#[test]
fn pointers_into_the_header_are_refused() {
    let head = [0u8, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for target in [0u8, 4, 11] {
        let p = [&head[..], &[1, b'a', 0xC0, target, 0, 1, 0, 1]].concat();
        assert!(read_name(&p, 12).is_none(), "{target}");
    }
    let p = [&head[..], &[1, b'a', 0, 1, b'b', 0xC0, 12, 0, 1, 0, 1]].concat();
    assert_eq!(read_name(&p, 15).unwrap().0, "b.a");
}

#[test]
fn any_for_a_missing_name_is_nxdomain_and_other_classes_are_refused() {
    let z = zones();
    assert_eq!(ask(&z, "nope.kith", ANY).rcode(), 3);
    assert_eq!(ask(&z, "wild.kith", ANY).rcode(), 3);
    assert_eq!(ask(&z, "a.wild.kith", ANY).rcode(), 0);
    for name in ["web.default.kith", "example.com"] {
        let mut q = query(1, name, A, None);
        let n = q.len();
        q[n - 1] = 3; // class CH
        let Answer::Reply(r) = answer(&q, LOCAL, &z, true) else {
            panic!("{name} was not refused")
        };
        assert_eq!(decode(r).rcode(), 5);
    }
}

#[test]
fn a_name_and_type_hold_100_records_and_a_huge_reply_over_tcp_is_servfail() {
    let mut z = zones();
    let a = |i: u8| rec("many.kith", Rdata::A(Ipv4Addr::new(10, 2, 0, i)));
    for i in 0..100 {
        z.records.add(a(i)).unwrap();
    }
    assert!(z.records.add(a(100)).is_err());
    z.records.add(rec("many.kith", Rdata::Txt("x".into()))).unwrap();
    for _ in 0..100 {
        z.records.add(rec("fat.kith", Rdata::Txt("x".repeat(4000)))).unwrap();
    }
    let Answer::Reply(r) = answer(&query(1, "fat.kith", TXT, None), LOCAL, &z, false) else {
        panic!()
    };
    let r = decode(r);
    assert_eq!((r.rcode(), r.an.len()), (2, 0));
    // Over UDP it is only truncated.
    let Answer::Reply(r) = answer(&query(1, "fat.kith", TXT, None), LOCAL, &z, true) else {
        panic!()
    };
    assert!(decode(r).flags & 0x0200 != 0);
}

#[test]
fn only_private_clients_may_forward_unless_a_list_says_otherwise() {
    use crate::server::may_forward;
    let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
    for yes in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.1.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "fd12::9",
        "::ffff:192.168.1.1",
    ] {
        assert!(may_forward(ip(yes), &[]), "{yes}");
    }
    for no in [
        "8.8.8.8",
        "172.32.0.1",
        "100.64.0.1",
        "192.169.0.1",
        "2001:db8::1",
        "fec0::1",
        "::ffff:8.8.8.8",
    ] {
        assert!(!may_forward(ip(no), &[]), "{no}");
    }
    let nets = ["8.8.8.0/24".parse().unwrap()];
    assert!(may_forward(ip("8.8.8.8"), &nets) && !may_forward(ip("10.0.0.1"), &nets));
}

#[test]
fn the_per_client_counter_refuses_past_its_limit_and_frees_on_drop() {
    let p = server::PerIp::default();
    let other: IpAddr = "10.0.0.9".parse().unwrap();
    let held: Vec<_> = (0..3).map(|_| p.take(LOCAL, 3).unwrap()).collect();
    assert!(p.take(LOCAL, 3).is_none());
    assert!(p.take(other, 3).is_some());
    drop(held);
    assert!(p.take(LOCAL, 3).is_some());
}

#[test]
fn forwarded_queries_get_a_new_id_and_a_capped_edns_size() {
    let q = query(0x1234, "example.com", A, Some(4096));
    let out = wire::for_upstream(&q, 0xBEEF).unwrap();
    assert_eq!(u16_at(&out, 0), 0xBEEF);
    assert_eq!(u16_at(&out, out.len() - 8), 1232);
    assert_eq!(out[2..out.len() - 8], q[2..q.len() - 8]);
    // A smaller size, and no OPT at all, are left as they are.
    let q = query(0x1234, "example.com", A, Some(600));
    assert_eq!(wire::for_upstream(&q, 1).unwrap()[2..], q[2..]);
    let q = query(0x1234, "example.com", A, None);
    assert_eq!(wire::for_upstream(&q, 1).unwrap()[2..], q[2..]);
}

#[test]
fn relayed_udp_replies_are_cut_to_the_client_limit_with_tc() {
    let mut z = zones();
    for i in 0..60u8 {
        z.records
            .add(rec("big.kith", Rdata::A(Ipv4Addr::new(10, 1, 1, i))))
            .unwrap();
    }
    let Answer::Reply(big) = answer(&query(1, "big.kith", A, None), LOCAL, &z, false) else {
        panic!()
    };
    assert!(big.len() > 512);
    let cut = decode(wire::truncate(big.clone(), 512));
    assert!(cut.raw.len() <= 512 && cut.flags & 0x0200 != 0 && cut.an.is_empty());
    assert_eq!(read_name(&cut.raw, 12).unwrap().0, "big.kith");
    // A reply that fits is untouched.
    assert_eq!(wire::truncate(big.clone(), big.len()), big);
    assert_eq!(
        wire::Query::parse(&query(1, "a.kith", A, None)).unwrap().udp_limit(),
        512
    );
    assert_eq!(
        wire::Query::parse(&query(1, "a.kith", A, Some(100)))
            .unwrap()
            .udp_limit(),
        512
    );
    assert_eq!(
        wire::Query::parse(&query(1, "a.kith", A, Some(9000)))
            .unwrap()
            .udp_limit(),
        1232
    );
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
    // TCP first on a free port, then UDP on the same number; try again if another test took it.
    let (tcp, udp) = loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()).await {
            break (tcp, udp);
        }
    };
    let addr = udp.local_addr().unwrap();
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

/// An address nothing listens on: port 1 refuses UDP and TCP at once, and no test binds it.
fn dead_upstream() -> SocketAddr {
    "127.0.0.1:1".parse().unwrap()
}

async fn start(z: Zones, upstreams: Vec<SocketAddr>) -> (SocketAddr, SocketAddr, watch::Sender<Arc<Zones>>) {
    start_for(z, upstreams, vec![]).await
}

async fn start_for(
    z: Zones,
    upstreams: Vec<SocketAddr>,
    forwarders: Vec<Cidr>,
) -> (SocketAddr, SocketAddr, watch::Sender<Arc<Zones>>) {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (u, t) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
    let (tx, rx) = watch::channel(Arc::new(z));
    tokio::spawn(serve(udp, tcp, rx, upstreams, forwarders));
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
    let (u, t, _tx) = start(zones(), vec![dead_upstream(), up]).await;
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

/// One resource record, written out: a plain name, the type, IN, `ttl` and the data.
fn rr(name: &str, ty: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
    let mut r = vec![];
    for label in name.split('.') {
        r.push(label.len() as u8);
        r.extend(label.as_bytes());
    }
    r.push(0);
    r.extend(ty.to_be_bytes());
    r.extend(1u16.to_be_bytes());
    r.extend(ttl.to_be_bytes());
    r.extend((data.len() as u16).to_be_bytes());
    r.extend(data);
    r
}

/// An upstream on one port for UDP and TCP that answers every question with `rcode` and the
/// `an` records in `records`, after the question.
async fn canned_upstream(rcode: u16, an: u16, records: Vec<u8>) -> SocketAddr {
    let (tcp, udp) = loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()).await {
            break (tcp, udp);
        }
    };
    let addr = udp.local_addr().unwrap();
    let reply = move |q: &[u8]| {
        let mut r = [u16_at(q, 0), 0x8180 | rcode, 1, an, 0, 0]
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect::<Vec<_>>();
        r.extend(&q[12..]);
        r.extend(&records);
        r
    };
    let again = reply.clone();
    tokio::spawn(async move {
        let mut buf = [0; 512];
        loop {
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            udp.send_to(&reply(&buf[..n]), from).await.unwrap();
        }
    });
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tcp.accept().await.unwrap();
            let mut len = [0; 2];
            s.read_exact(&mut len).await.unwrap();
            let mut q = vec![0; usize::from(u16::from_be_bytes(len))];
            s.read_exact(&mut q).await.unwrap();
            let r = again(&q);
            s.write_all(&[&(r.len() as u16).to_be_bytes()[..], &r].concat())
                .await
                .unwrap();
        }
    });
    addr
}

/// The TTL of a record of a decoded reply.
fn ttl(r: &Reply, rr: &Rr) -> u32 {
    u32::from_be_bytes(r.raw[rr.at - 6..rr.at - 2].try_into().unwrap())
}

#[tokio::test]
async fn a_cname_that_leaves_the_zones_gets_its_targets_records_from_the_upstream() {
    // What a recursive resolver says for example.com: a CNAME on, then two addresses for the end
    // of it. An address for another name and a TXT for the right one do not belong.
    let mut records = rr("example.com", CNAME, 120, b"\x04edge\x07example\x03net\x00");
    records.extend(rr("edge.example.net", A, 300, &[9, 9, 9, 9]));
    records.extend(rr("other.example.net", A, 300, &[6, 6, 6, 6]));
    records.extend(rr("edge.example.net", TXT, 300, b"\x01x"));
    records.extend(rr("EDGE.example.net", A, 300, &[9, 9, 9, 8]));
    let up = canned_upstream(0, 5, records).await;
    let (u, t, _tx) = start(zones(), vec![dead_upstream(), up]).await;
    let q = query(0x55, "out.kith", A, None);
    for r in [udp_ask(u, &q).await, tcp_ask(t, &q).await] {
        assert_eq!((u16_at(&r.raw, 0), r.rcode()), (0x55, 0));
        assert_eq!(r.an.iter().map(|x| x.ty).collect::<Vec<_>>(), [CNAME, CNAME, A, A]);
        assert_eq!(r.an[0].name, "out.kith");
        assert_eq!(r.name_at(&r.an[1]), "edge.example.net");
        assert_eq!(r.data(&r.an[2]), [9, 9, 9, 9]);
        assert_eq!(r.data(&r.an[3]), [9, 9, 9, 8]);
        assert_eq!((ttl(&r, &r.an[0]), ttl(&r, &r.an[2])), (60, 300));
    }
    // A question for the CNAME itself, or for a name inside the zones, is not sent upstream.
    assert_eq!(udp_ask(u, &query(1, "out.kith", CNAME, None)).await.an.len(), 1);
    assert_eq!(udp_ask(u, &query(1, "alias.kith", A, None)).await.an.len(), 2);
}

#[test]
fn upstream_replies_cut_or_corrupted_anywhere_never_panic() {
    let mut records = rr("example.com", CNAME, 120, b"\x04edge\x07example\x03net\x00");
    records.extend(rr("edge.example.net", A, 300, &[9, 9, 9, 9]));
    records.extend(rr("edge.example.net", TXT, 300, b"\x01x"));
    let mut reply = [1u16, 0x8180, 1, 3, 0, 0]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect::<Vec<_>>();
    reply.extend(&wire::ask("example.com", A)[12..]);
    reply.extend(&records);
    assert_eq!(wire::answers(&reply).len(), 3);
    for cut in 0..reply.len() {
        wire::answers(&reply[..cut]);
        for bad in [0, 0x7F, 0xC0, 0xFF] {
            let mut r = reply.clone();
            r[cut] = bad;
            wire::answers(&r);
        }
    }
}

#[tokio::test]
async fn a_cname_that_leaves_the_zones_stays_alone_when_the_upstream_cannot_help() {
    let one = |r: &Reply| (r.rcode(), r.an.len(), r.an[0].ty);
    let q = query(3, "out.kith", A, None);
    let (u, t, _tx) = start(zones(), vec![dead_upstream()]).await;
    for r in [udp_ask(u, &q).await, tcp_ask(t, &q).await] {
        assert_eq!(one(&r), (0, 1, CNAME));
    }
    // No such name upstream, or an address for something else, or a client that may not forward.
    let nx = canned_upstream(3, 0, vec![]).await;
    let (u, t, _tx) = start(zones(), vec![nx]).await;
    for r in [udp_ask(u, &q).await, tcp_ask(t, &q).await] {
        assert_eq!(one(&r), (0, 1, CNAME));
    }
    let other = canned_upstream(0, 1, rr("other.example.net", A, 300, &[6, 6, 6, 6])).await;
    let (u, _, _tx) = start(zones(), vec![other]).await;
    assert_eq!(one(&udp_ask(u, &q).await), (0, 1, CNAME));
    let up = canned_upstream(0, 1, rr("example.com", A, 300, &[9, 9, 9, 9])).await;
    let (u, t, _tx) = start_for(zones(), vec![up], vec!["10.0.0.0/8".parse().unwrap()]).await;
    for r in [udp_ask(u, &q).await, tcp_ask(t, &q).await] {
        assert_eq!(one(&r), (0, 1, CNAME));
    }
}

#[tokio::test]
async fn servfail_when_no_upstream_answers() {
    let (u, t, _tx) = start(zones(), vec![dead_upstream()]).await;
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
    let (u, _, tx) = start(Zones::default(), vec![dead_upstream()]).await;
    let q = query(1, "web.default.kith", A, None);
    assert_eq!(udp_ask(u, &q).await.rcode(), 2);
    tx.send(Arc::new(zones())).unwrap();
    assert_eq!(udp_ask(u, &q).await.an.len(), 1);
}

#[tokio::test]
async fn the_forwarder_uses_its_own_ids_and_ignores_replies_to_other_questions() {
    let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = up.local_addr().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(vec![]));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0; 512];
        loop {
            let (n, from) = up.recv_from(&mut buf).await.unwrap();
            let id = u16_at(&buf, 0);
            log.lock().unwrap().push(id);
            // The right id with another question first, then the real reply.
            let other = query(id, "evil.example", A, None);
            up.send_to(&upstream_reply(&other, id), from).await.unwrap();
            up.send_to(&upstream_reply(&buf[..n], id), from).await.unwrap();
        }
    });
    let (u, _, _tx) = start(zones(), vec![addr]).await;
    for _ in 0..4 {
        let r = udp_ask(u, &query(0x1234, "ExAmple.com", A, None)).await;
        assert_eq!((u16_at(&r.raw, 0), r.rcode(), r.an.len()), (0x1234, 0, 1));
        assert_eq!(read_name(&r.raw, 12).unwrap().0, "ExAmple.com");
    }
    // Four random ids are not all the client's.
    assert!(seen.lock().unwrap().iter().any(|&id| id != 0x1234));
}

#[tokio::test]
async fn clients_outside_the_allowed_networks_are_refused_for_outside_names_only() {
    let up = fake_upstream().await;
    let nets = vec!["203.0.113.0/24".parse().unwrap()];
    let (u, t, _tx) = start_for(zones(), vec![up], nets).await;
    let q = query(5, "example.com", A, None);
    for r in [udp_ask(u, &q).await, tcp_ask(t, &q).await] {
        assert_eq!((u16_at(&r.raw, 0), r.rcode(), r.an.len()), (5, 5, 0));
    }
    let q = query(6, "web.default.kith", A, None);
    for r in [udp_ask(u, &q).await, tcp_ask(t, &q).await] {
        assert_eq!((r.rcode(), r.an.len()), (0, 1));
    }
}

/// Whether the server closes `s` instead of answering.
async fn closed(s: &mut TcpStream) -> bool {
    let q = query(1, "web.default.kith", A, None);
    let _ = s.write_all(&[&(q.len() as u16).to_be_bytes()[..], &q].concat()).await;
    let mut buf = [0; 1];
    matches!(
        timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap(),
        Ok(0) | Err(_)
    )
}

#[tokio::test]
async fn one_client_ip_gets_a_few_tcp_connections() {
    let (_, t, _tx) = start(zones(), vec![]).await;
    let mut held = vec![];
    for _ in 0..server::TCP_PER_IP {
        let mut s = TcpStream::connect(t).await.unwrap();
        // Answered, so the server has counted it.
        frame(&mut s, &query(1, "web.default.kith", A, None)).await;
        held.push(s);
    }
    assert!(closed(&mut TcpStream::connect(t).await.unwrap()).await);
    // Closing one makes room.
    drop(held.pop());
    let mut room = false;
    for _ in 0..100 {
        let mut s = TcpStream::connect(t).await.unwrap();
        if !closed(&mut s).await {
            room = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(room);
}

#[tokio::test]
async fn a_tcp_connection_ends_after_its_query_limit() {
    let (_, t, _tx) = start(zones(), vec![]).await;
    let mut s = TcpStream::connect(t).await.unwrap();
    for id in 0..server::TCP_QUERIES {
        let r = decode(frame(&mut s, &query(id as u16, "web.default.kith", A, None)).await);
        assert_eq!(usize::from(u16_at(&r.raw, 0)), id);
    }
    assert!(closed(&mut s).await);
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
