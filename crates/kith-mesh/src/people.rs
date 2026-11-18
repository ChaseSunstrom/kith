//! The people table: `inet kith-people`, where a level is enforced on the node that ends the
//! people's tunnels (`docs/adr-people.md`, "Where a level is enforced"). Not wired into
//! kithd yet; this module only builds the table and its chains, and reads them back.

use crate::pod::{
    Batch, INET, NESTED, answering, at, attribute, expression, is, l4proto, link_name, nfproto, number, text, verdict,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A level's reach: the networks it may reach, its Services' addresses and ports, its API's
/// port, its resolver, and its internet (see `docs/adr-people.md`).
#[derive(Clone)]
pub struct Level {
    pub networks: Vec<(IpAddr, u8)>,
    /// (address, TCP ports; none is all of them).
    pub services: Vec<(Ipv6Addr, Vec<u16>)>,
    pub api: Option<u16>,
    pub resolver: Option<IpAddr>,
    pub internet: Internet,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Internet {
    None,
    Home,
    Exit(u16),
}

/// A peer of the people's device: its level, its 16 bits in `100.89.0.0/16`, its addresses.
#[derive(Clone)]
pub struct Person {
    pub level: String,
    pub offset: u16,
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

/// A chain of the table, and its rules (each one's expressions, as bytes, in order). A base
/// chain has its hook, priority and kind (`filter`, `nat`); a level's chain has none, and a
/// rule jumps to it.
#[derive(Debug)]
pub struct Chain {
    pub name: String,
    pub hook: Option<(u32, u32, &'static str)>,
    pub rules: Vec<Vec<u8>>,
}

/// The people's device's own range (`100.89.0.0/16`): a peer's offset is in it.
const PEOPLE4: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 89, 0, 0), 16);

/// The DNS ports a resolver answers on: UDP (17) and TCP (6), 53 and 853.
const DNS: [(u8, u16); 4] = [(17, 53), (17, 853), (6, 53), (6, 853)];

/// The table's name in nftables.
const TABLE: &str = "kith-people";

/// The table's chains, base ones first (pre, in, fwd, out, post), then each level's four
/// (`-in`, `-out`, `-back`, `-replies`). `people64` is the people's /64, `mesh` the mesh's link
/// (kithd's `--mesh-interface`), `links` the node's own links' networks (what `-out` never
/// reaches). A peer whose level is not in `levels` refuses the table: its jump would go nowhere.
pub fn table(
    people64: Ipv6Addr,
    people: &[Person],
    levels: &[(String, Level)],
    mesh: &str,
    links: &[(IpAddr, u8)],
) -> Result<Vec<Chain>, String> {
    let drop_on = |which: u32, name: &str| [named(which, name), verdict(0)].concat();
    let (mut input, mut inward, mut outward, mut out) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for person in people {
        let mark = 0x6b79_0000 | u32::from(person.offset);
        let level = &person.level;
        if !levels.iter().any(|(name, _)| name == level) {
            return Err(format!(
                "{} is in level {level}, which the levels given do not have",
                describe(person)
            ));
        }
        for address in [person.v4.map(IpAddr::V4), person.v6.map(IpAddr::V6)]
            .into_iter()
            .flatten()
        {
            input.push(
                [
                    named(6, "kwg0"),
                    host(address, false),
                    set_mark(mark),
                    jump(&format!("{level}-in")),
                ]
                .concat(),
            );
            inward.push(
                [
                    named(6, "kwg0"),
                    host(address, false),
                    set_mark(mark),
                    jump(&format!("{level}-out")),
                ]
                .concat(),
            );
            outward.push([named(7, "kwg0"), host(address, true), jump(&format!("{level}-back"))].concat());
            out.push([named(7, "kwg0"), host(address, true), jump(&format!("{level}-replies"))].concat());
        }
    }
    input.push(drop_on(6, "kwg0"));
    let mut forward = inward;
    forward.extend(outward);
    forward.push(drop_on(6, "kwg0"));
    forward.push(drop_on(7, "kwg0"));
    out.push(drop_on(7, "kwg0"));
    let base = |name: &str, hook: u32, priority: u32, kind: &'static str, rules: Vec<Vec<u8>>| Chain {
        name: name.into(),
        hook: Some((hook, priority, kind)),
        rules,
    };
    let mut chains = vec![
        base(
            "pre",
            0,
            0,
            "filter",
            vec![
                [
                    not_named(6, "kwg0"),
                    reach(IpAddr::V4(PEOPLE4.0), PEOPLE4.1, false),
                    verdict(0),
                ]
                .concat(),
                [not_named(6, "kwg0"), reach(IpAddr::V6(people64), 64, false), verdict(0)].concat(),
            ],
        ),
        base("in", 1, 0, "filter", input),
        base("fwd", 2, 0, "filter", forward),
        base("out", 3, 0, "filter", out),
        base(
            "post",
            4,
            100,
            "nat",
            vec![
                [
                    not_named(7, "kwg0"),
                    reach(IpAddr::V4(PEOPLE4.0), PEOPLE4.1, false),
                    expression("masq", &[]),
                ]
                .concat(),
                [
                    not_named(7, "kwg0"),
                    reach(IpAddr::V6(people64), 64, false),
                    expression("masq", &[]),
                ]
                .concat(),
            ],
        ),
    ];
    for (name, level) in levels {
        let plain = |suffix: &str, rules: Vec<Vec<u8>>| Chain {
            name: format!("{name}-{suffix}"),
            hook: None,
            rules,
        };
        chains.push(plain("in", level_in(level)));
        chains.push(plain("out", level_out(level, mesh, links)));
        chains.push(plain("back", level_back(level, mesh)));
        chains.push(plain("replies", level_replies(level)));
    }
    Ok(chains)
}

/// A peer as an error names it: its offset and its addresses.
fn describe(person: &Person) -> String {
    let addresses: Vec<String> = [person.v4.map(|a| a.to_string()), person.v6.map(|a| a.to_string())]
        .into_iter()
        .flatten()
        .collect();
    format!("peer {:#06x} ({})", person.offset, addresses.join(", "))
}

/// Makes the table whole, in one batch: the kernel takes all of it or none, and a table made
/// anew has no moment without its rules (as `pod.rs`'s `nat` does).
pub fn send(
    people64: Ipv6Addr,
    people: &[Person],
    levels: &[(String, Level)],
    mesh: &str,
    links: &[(IpAddr, u8)],
) -> std::io::Result<()> {
    build(&table(people64, people, levels, mesh, links).map_err(std::io::Error::other)?)
}

/// Makes `chains` the table, in one batch (see `send`).
fn build(chains: &[Chain]) -> std::io::Result<()> {
    let mut batch = Batch::new(TABLE);
    batch.table(INET);
    for chain in chains {
        match chain.hook {
            Some((hook, priority, kind)) => batch.chain(INET, &chain.name, kind, hook, priority, Some(1)),
            None => batch.plain(INET, &chain.name),
        }
    }
    for chain in chains {
        for rule in &chain.rules {
            batch.rule(INET, &chain.name, std::slice::from_ref(rule));
        }
    }
    batch.send()
}

/// The level's `-in`: a Service's address and port (each port, or any with none listed), the
/// API's port, the resolver's DNS ports, as the node's own. Ends in drop.
fn level_in(level: &Level) -> Vec<Vec<u8>> {
    let mut rules = Vec::new();
    for (address, ports) in &level.services {
        let head = [host(IpAddr::V6(*address), true), l4proto(6)].concat();
        for matched in port_matches(ports, 2) {
            rules.push([head.clone(), matched, verdict(1)].concat());
        }
    }
    if let Some(port) = level.api {
        rules.push([l4proto(6), at(2, 2, &port.to_be_bytes()), verdict(1)].concat());
    }
    if let Some(resolver) = level.resolver {
        rules.extend(resolver_to(resolver));
    }
    rules.push(verdict(0));
    rules
}

/// The level's `-out`, in the ADR's order: the resolver's DNS, the other DNS dropped, the named
/// networks, private addresses and the node's own networks dropped, then the internet (none,
/// the home's, or an exit's own link). Ends in drop.
fn level_out(level: &Level, mesh: &str, own: &[(IpAddr, u8)]) -> Vec<Vec<u8>> {
    let mut rules = Vec::new();
    if let Some(resolver) = level.resolver {
        rules.extend(resolver_to(resolver));
    }
    for port in [53u16, 853] {
        for protocol in [17u8, 6] {
            rules.push([l4proto(protocol), at(2, 2, &port.to_be_bytes()), verdict(0)].concat());
        }
    }
    for &(network, bits) in &level.networks {
        // Out by no Exit's link, no pod link and no people link, nor the mesh's: a named range is
        // accepted only where it may go (the ADR's review, condition 3).
        rules.push(
            [
                reach(network, bits, true),
                not_begins(7, "kx"),
                not_begins(7, "kp"),
                not_named(7, mesh),
                not_named(7, "kwg0"),
                verdict(1),
            ]
            .concat(),
        );
    }
    rules.extend(private(true));
    for &(network, bits) in own {
        rules.push([reach(network, bits, true), verdict(0)].concat());
    }
    match level.internet {
        Internet::Home => {
            // Out by any link but the mesh's, kp* and kx*: those are dropped, the rest passed.
            rules.push(drop_on_link(7, mesh));
            for prefix in ["kp", "kx"] {
                rules.push([begins(7, prefix), verdict(0)].concat());
            }
            rules.push([nfproto(2), verdict(1)].concat());
        }
        Internet::Exit(n) => rules.push([nfproto(2), named(7, &crate::exit::device(n)), verdict(1)].concat()),
        Internet::None => {}
    }
    rules.push(verdict(0));
    rules
}

/// The level's `-back`: an answer (the connection seen both ways) from a named network, the
/// resolver's DNS, or the internet (an exit's link, or home's public sources by no mesh, pod
/// or exit link). Ends in drop.
fn level_back(level: &Level, mesh: &str) -> Vec<Vec<u8>> {
    let mut rules = Vec::new();
    for &(network, bits) in &level.networks {
        rules.push([answering(), reach(network, bits, false), verdict(1)].concat());
    }
    if let Some(resolver) = level.resolver {
        rules.extend(resolver_from(resolver));
    }
    match level.internet {
        Internet::Home => {
            rules.extend(private(false));
            rules.push(drop_on_link(6, mesh));
            for prefix in ["kp", "kx"] {
                rules.push([begins(6, prefix), verdict(0)].concat());
            }
            rules.push([answering(), nfproto(2), verdict(1)].concat());
        }
        Internet::Exit(n) => {
            rules.push([answering(), nfproto(2), named(6, &crate::exit::device(n)), verdict(1)].concat())
        }
        Internet::None => {}
    }
    rules.push(verdict(0));
    rules
}

/// The level's `-replies`: an answer from a named Service's address and port, the API's port,
/// or the resolver; and ICMP errors of those, when there is any such. Ends in drop.
fn level_replies(level: &Level) -> Vec<Vec<u8>> {
    let mut rules = Vec::new();
    for (address, ports) in &level.services {
        let head = [answering(), host(IpAddr::V6(*address), false), l4proto(6)].concat();
        for matched in port_matches(ports, 0) {
            rules.push([head.clone(), matched, verdict(1)].concat());
        }
    }
    if let Some(port) = level.api {
        rules.push([answering(), l4proto(6), at(2, 0, &port.to_be_bytes()), verdict(1)].concat());
    }
    if let Some(resolver) = level.resolver {
        rules.extend(resolver_from(resolver));
    }
    if !rules.is_empty() {
        rules.push([answering(), nfproto(2), l4proto(1), verdict(1)].concat());
        rules.push([answering(), nfproto(10), l4proto(58), verdict(1)].concat());
    }
    rules.push(verdict(0));
    rules
}

/// The resolver's DNS as the node's own, from anywhere: the packet is to it (`-in`, `-out`).
fn resolver_to(resolver: IpAddr) -> Vec<Vec<u8>> {
    DNS.iter()
        .map(|&(protocol, port)| {
            [
                host(resolver, true),
                l4proto(protocol),
                at(2, 2, &port.to_be_bytes()),
                verdict(1),
            ]
            .concat()
        })
        .collect()
}

/// The resolver's answers, from its DNS port: the packet is from it, and answers (`-back`,
/// `-replies`).
fn resolver_from(resolver: IpAddr) -> Vec<Vec<u8>> {
    DNS.iter()
        .map(|&(protocol, port)| {
            [
                answering(),
                host(resolver, false),
                l4proto(protocol),
                at(2, 0, &port.to_be_bytes()),
                verdict(1),
            ]
            .concat()
        })
        .collect()
}

/// Each port of `ports` as a match on the transport header's `offset` (2: destination, 0:
/// source); none listed is one match with no port test (all of them).
fn port_matches(ports: &[u16], offset: u32) -> Vec<Vec<u8>> {
    if ports.is_empty() {
        return vec![Vec::new()];
    }
    ports.iter().map(|port| at(2, offset, &port.to_be_bytes())).collect()
}

/// Private and reserved addresses, dropped: from them (`outward` false) or to them (true). IPv4's
/// private ones and its reserved ones (`0/8`, multicast `224/4`, `240/4`, the benchmark `198.18/15`,
/// `192.0.0/24`); IPv6's unique local, link-local and multicast ones.
fn private(outward: bool) -> Vec<Vec<u8>> {
    let networks: [(IpAddr, u8); 13] = [
        (Ipv4Addr::new(10, 0, 0, 0).into(), 8),
        (Ipv4Addr::new(172, 16, 0, 0).into(), 12),
        (Ipv4Addr::new(192, 168, 0, 0).into(), 16),
        (Ipv4Addr::new(100, 64, 0, 0).into(), 10),
        (Ipv4Addr::new(169, 254, 0, 0).into(), 16),
        (Ipv4Addr::new(0, 0, 0, 0).into(), 8),
        (Ipv4Addr::new(224, 0, 0, 0).into(), 4),
        (Ipv4Addr::new(240, 0, 0, 0).into(), 4),
        (Ipv4Addr::new(198, 18, 0, 0).into(), 15),
        (Ipv4Addr::new(192, 0, 0, 0).into(), 24),
        ("fc00::".parse().unwrap(), 7),
        ("fe80::".parse().unwrap(), 10),
        ("ff00::".parse().unwrap(), 8),
    ];
    networks
        .iter()
        .map(|&(network, bits)| [reach(network, bits, outward), verdict(0)].concat())
        .collect()
}

/// A rule dropping what came by (6) or goes out by (7) the link `name` whole.
fn drop_on_link(which: u32, name: &str) -> Vec<u8> {
    [named(which, name), verdict(0)].concat()
}

/// The packet is from (`outward` false) or to (true) the address `address` exactly, in its
/// family.
fn host(address: IpAddr, outward: bool) -> Vec<u8> {
    let (family, source, destination, bytes) = match address {
        IpAddr::V4(address) => (2, 12, 16, address.octets().to_vec()),
        IpAddr::V6(address) => (10, 8, 24, address.octets().to_vec()),
    };
    let offset = if outward { destination } else { source };
    [nfproto(family), at(1, offset, &bytes)].concat()
}

/// The packet is from (`outward` false) or to (true) a network of `bits`, in its family.
fn reach(network: IpAddr, bits: u8, outward: bool) -> Vec<u8> {
    let (family, source, destination) = match network {
        IpAddr::V4(_) => (2, 12, 16),
        IpAddr::V6(_) => (10, 8, 24),
    };
    let offset = if outward { destination } else { source };
    [nfproto(family), within(1, offset, network, bits)].concat()
}

/// The packet's bytes at `offset` into its header `base` (1: network, 2: transport) are in
/// `network`'s first `bits`: masked, then compared, as `pod.rs`'s `nat` does.
fn within(base: u32, offset: u32, network: IpAddr, bits: u8) -> Vec<u8> {
    let bytes = match network {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    let len = bytes.len();
    let mask: Vec<u8> = (0..len)
        .map(|i| {
            let ones = (bits as usize).saturating_sub(8 * i).min(8);
            (0xffu16 << (8 - ones)) as u8
        })
        .collect();
    let masked: Vec<u8> = bytes.iter().zip(&mask).map(|(byte, bits)| byte & bits).collect();
    let load = expression(
        "payload",
        &[number(1, 1), number(2, base), number(3, offset), number(4, len as u32)],
    );
    let and = expression(
        "bitwise",
        &[
            number(1, 1),
            number(2, 1),
            number(3, len as u32),
            attribute(4 | NESTED, &attribute(1, &mask)),
            attribute(5 | NESTED, &attribute(1, &vec![0; len])),
        ],
    );
    [load, and, is(&masked)].concat()
}

/// The link it came by (6) or goes out by (7) is `name` whole.
fn named(which: u32, name: &str) -> Vec<u8> {
    [link_name(which), is(&[name.as_bytes(), &[0]].concat())].concat()
}

/// The link it came by (6) or goes out by (7) begins with `name` (`kp` is `kp1` and `kpx2`).
fn begins(which: u32, name: &str) -> Vec<u8> {
    [link_name(which), is(name.as_bytes())].concat()
}

/// The link it came by (6) or goes out by (7) is not `name` whole.
fn not_named(which: u32, name: &str) -> Vec<u8> {
    let value = attribute(3 | NESTED, &attribute(1, &[name.as_bytes(), &[0]].concat()));
    [
        link_name(which),
        expression("cmp", &[number(1, 1), number(2, 1), value]),
    ]
    .concat()
}

/// The link it goes out by (7) does not begin with `name` (`kp` is not `kp1` nor `kpx2`): the
/// first bytes of its name, not the whole of it.
fn not_begins(which: u32, name: &str) -> Vec<u8> {
    let value = attribute(3 | NESTED, &attribute(1, name.as_bytes()));
    [
        link_name(which),
        expression("cmp", &[number(1, 1), number(2, 1), value]),
    ]
    .concat()
}

/// A rule that jumps to the chain `name` (the verdict -3, with the chain's name).
fn jump(name: &str) -> Vec<u8> {
    let verdict = attribute(
        2 | NESTED,
        &attribute(2 | NESTED, &[number(1, (-3i32) as u32), text(2, name)].concat()),
    );
    expression("immediate", &[number(1, 0), verdict])
}

/// Marks the connection with `mark` (the ct mark, as `pod.rs`'s `marked` does).
fn set_mark(mark: u32) -> Vec<u8> {
    let value = attribute(2 | NESTED, &attribute(1, &mark.to_ne_bytes()));
    [
        expression("immediate", &[number(1, 1), value]),
        expression("ct", &[number(2, 3), number(4, 1)]),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pod::has_table;

    trait ContainsBytes {
        fn contains_slice(&self, part: &[u8]) -> bool;
    }

    impl ContainsBytes for [u8] {
        fn contains_slice(&self, part: &[u8]) -> bool {
            self.windows(part.len()).any(|window| window == part)
        }
    }

    const PEOPLE64: &str = "fd8a:2b3c:4d5e:5::";

    fn peer() -> Person {
        Person {
            level: "work".into(),
            offset: 0x0102,
            v4: Some(Ipv4Addr::new(100, 89, 1, 2)),
            v6: Some("fd8a:2b3c:4d5e:5::1".parse().unwrap()),
        }
    }

    fn work() -> Level {
        Level {
            networks: vec![("192.0.2.0".parse().unwrap(), 24)],
            services: vec![("fd8a:2b3c:4d5e::1".parse().unwrap(), vec![443])],
            api: Some(8443),
            resolver: Some("100.64.0.53".parse().unwrap()),
            internet: Internet::Home,
        }
    }

    /// The mesh's link in these tests.
    const MESH: &str = "kith0";

    fn built(people: &[Person], levels: &[(&str, Level)]) -> Vec<Chain> {
        let levels: Vec<(String, Level)> = levels.iter().map(|(n, l)| (n.to_string(), l.clone())).collect();
        table(
            PEOPLE64.parse().unwrap(),
            people,
            &levels,
            MESH,
            &[("10.0.0.0".parse().unwrap(), 24)],
        )
        .unwrap()
    }

    fn chain<'a>(chains: &'a [Chain], name: &str) -> &'a Chain {
        chains
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no chain {name}"))
    }

    /// A rule is a drop (0) at its end.
    fn drops(rule: &[u8]) -> bool {
        rule.ends_with(&verdict(0))
    }

    #[test]
    fn the_table_is_the_adr_table_with_its_chains_in_order() {
        let chains = built(&[peer()], &[("work", work())]);
        let names: Vec<&str> = chains.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "pre",
                "in",
                "fwd",
                "out",
                "post",
                "work-in",
                "work-out",
                "work-back",
                "work-replies"
            ]
        );
        // (One rule per peer per hook and family: a peer with both addresses has two of each.)
        let counts: Vec<usize> = chains.iter().take(5).map(|c| c.rules.len()).collect();
        assert_eq!(counts, [2, 3, 6, 3, 2]);
    }

    #[test]
    fn pre_drops_a_people_source_by_any_link_but_kwg0() {
        let chains = built(&[peer()], &[("work", work())]);
        let pre = &chain(&chains, "pre").rules;
        assert!(pre.iter().all(|r| drops(r)));
        assert!(pre[0].contains_slice(&is(&[100, 89, 0, 0])));
        assert!(pre[0].contains_slice(&not_named(6, "kwg0")));
    }

    #[test]
    fn in_and_fwd_match_a_peer_by_source_and_jump_to_its_level() {
        let chains = built(&[peer()], &[("work", work())]);
        let input = &chain(&chains, "in").rules;
        assert!(input[0].ends_with(&jump("work-in")));
        assert!(input[0].contains_slice(&at(1, 12, &[100, 89, 1, 2])));
        // The mark is set on delivery to the node as well, just before the jump: revocation
        // flushes the connections to the node itself (the ADR's review, condition 6).
        let before_jump = &input[0][..input[0].len() - jump("work-in").len()];
        assert!(before_jump.ends_with(&set_mark(0x6b79_0102)));
        let forward = &chain(&chains, "fwd").rules;
        // The mark (0x6b79 in the high 16 bits, the peer's offset below), then out.
        assert!(forward[0].contains_slice(&set_mark(0x6b79_0102)));
        assert!(forward[0].ends_with(&jump("work-out")));
        assert!(forward[2].ends_with(&jump("work-back")));
        // The two drops for kwg0 come last: in by it, then out by it.
        assert_eq!(forward.len(), 6);
        assert!(forward[4].ends_with(&verdict(0)) && forward[5].ends_with(&verdict(0)));
    }

    #[test]
    fn out_matches_a_peer_by_destination_and_jumps_to_its_replies() {
        let chains = built(&[peer()], &[("work", work())]);
        let out = &chain(&chains, "out").rules;
        assert!(out[0].ends_with(&jump("work-replies")));
        assert!(out[0].contains_slice(&at(1, 16, &[100, 89, 1, 2])));
        assert!(out[2].ends_with(&verdict(0)));
    }

    #[test]
    fn post_masquerades_people_sources_out_by_any_link_but_kwg0() {
        let chains = built(&[peer()], &[("work", work())]);
        let post = &chain(&chains, "post").rules;
        assert!(post.iter().all(|r| r.ends_with(&expression("masq", &[]))));
    }

    #[test]
    fn a_levels_out_chain_is_in_the_adr_order_and_ends_in_drop() {
        let chains = built(&[peer()], &[("work", work())]);
        let out = &chain(&chains, "work-out").rules;
        assert!(out.last().unwrap().ends_with(&verdict(0)));
        // The resolver on 53 and 853 first, then the other 53 and 853 dropped.
        assert!(out[0].contains_slice(&at(2, 2, &53u16.to_be_bytes())));
        let other_dns = [l4proto(17), at(2, 2, &853u16.to_be_bytes()), verdict(0)].concat();
        let first_pass = out.iter().position(|r| r.ends_with(&verdict(1))).unwrap();
        assert!(out.iter().position(|r| *r == other_dns).unwrap() > first_pass);
        // The named range is passed, then private space and the node's own link network
        // dropped, then the internet passed (Home's: out by any link but kith0, kp*, kx*).
        let named_range = out
            .iter()
            .position(|r| {
                r.contains_slice(&reach(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, true)) && r.ends_with(&verdict(1))
            })
            .unwrap();
        let private = out
            .iter()
            .position(|r| {
                r.contains_slice(&reach(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8, true)) && r.ends_with(&verdict(0))
            })
            .unwrap();
        let own = out
            .iter()
            .position(|r| {
                r.contains_slice(&reach(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24, true)) && r.ends_with(&verdict(0))
            })
            .unwrap();
        let home = out
            .iter()
            .position(|r| *r == [nfproto(2), verdict(1)].concat())
            .unwrap();
        assert!(named_range < private && private < home && own < home);
        assert!(out.iter().any(|r| *r == drop_on_link(7, "kith0")));
    }

    #[test]
    fn an_exit_goes_out_by_its_own_link_only() {
        let mut level = work();
        level.internet = Internet::Exit(3);
        let chains = built(&[peer()], &[("work", level)]);
        let out = &chain(&chains, "work-out").rules;
        let to = [link_name(7), is(b"kx3\0")].concat();
        assert!(out.iter().any(|r| r.contains_slice(&to)));
        assert!(
            !out.iter()
                .any(|r| r.contains_slice(&[link_name(7), is(b"kith0\0")].concat()))
        );
    }

    #[test]
    fn the_back_and_replies_chains_answer_what_out_passed() {
        let chains = built(&[peer()], &[("work", work())]);
        let back = &chain(&chains, "work-back").rules;
        assert!(back[0].contains_slice(&answering()));
        assert!(back.last().unwrap().ends_with(&verdict(0)));
        let replies = &chain(&chains, "work-replies").rules;
        assert!(replies[0].contains_slice(&answering()));
        assert!(replies.last().unwrap().ends_with(&verdict(0)));
    }

    #[test]
    fn a_service_is_reached_by_its_address_and_port_only() {
        let chains = built(&[peer()], &[("work", work())]);
        let input = &chain(&chains, "work-in").rules;
        assert!(input.iter().any(|r| r.contains_slice(&at(
            1,
            24,
            &"fd8a:2b3c:4d5e::1".parse::<Ipv6Addr>().unwrap().octets()
        ))));
        assert!(input.iter().any(|r| r.contains_slice(&at(2, 2, &443u16.to_be_bytes()))));
        assert!(input.last().unwrap().ends_with(&verdict(0)));
        assert!(input.iter().all(|r| drops(r) || r.ends_with(&verdict(1))));
    }

    #[test]
    fn an_empty_level_reaches_nothing() {
        let empty = Level {
            networks: Vec::new(),
            services: Vec::new(),
            api: None,
            resolver: None,
            internet: Internet::None,
        };
        let in_nothing = Person {
            level: "nothing".into(),
            ..peer()
        };
        let chains = built(&[in_nothing], &[("nothing", empty)]);
        for name in ["nothing-in", "nothing-out", "nothing-back", "nothing-replies"] {
            let rules = &chain(&chains, name).rules;
            assert!(rules.iter().all(|r| drops(r)), "{name} passes something");
        }
    }

    #[test]
    fn internet_over_ipv6_is_never_passed() {
        let chains = built(&[peer()], &[("work", work())]);
        let out = &chain(&chains, "work-out").rules;
        assert!(
            out.iter()
                .filter(|r| r.ends_with(&verdict(1)))
                .all(|r| r.contains_slice(&nfproto(2)))
        );
    }

    #[test]
    fn a_named_range_is_accepted_only_out_by_no_exit_pod_mesh_or_people_link() {
        let chains = built(&[peer()], &[("work", work())]);
        let out = &chain(&chains, "work-out").rules;
        let named_range = out
            .iter()
            .find(|r| {
                r.contains_slice(&reach(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, true)) && r.ends_with(&verdict(1))
            })
            .expect("the named range is accepted");
        for guard in [
            not_begins(7, "kx"),
            not_begins(7, "kp"),
            not_named(7, MESH),
            not_named(7, "kwg0"),
        ] {
            assert!(
                named_range.contains_slice(&guard),
                "the named range is accepted out by a link it must not"
            );
        }
    }

    #[test]
    fn private_drops_each_range_the_adr_names_in_both_directions() {
        let ranges: [(IpAddr, u8); 6] = [
            (Ipv4Addr::new(0, 0, 0, 0).into(), 8),
            (Ipv4Addr::new(224, 0, 0, 0).into(), 4),
            (Ipv4Addr::new(240, 0, 0, 0).into(), 4),
            (Ipv4Addr::new(198, 18, 0, 0).into(), 15),
            (Ipv4Addr::new(192, 0, 0, 0).into(), 24),
            ("ff00::".parse().unwrap(), 8),
        ];
        for (network, bits) in ranges {
            for outward in [false, true] {
                let rule = [reach(network, bits, outward), verdict(0)].concat();
                assert!(
                    private(outward).contains(&rule),
                    "{network}/{bits} is not dropped (outward {outward})"
                );
            }
        }
    }

    #[test]
    fn the_mesh_link_is_the_name_given_not_kith0() {
        let links = [("10.0.0.0".parse().unwrap(), 24)];
        let levels = [("work".to_string(), work())];
        let chains = table(PEOPLE64.parse().unwrap(), &[peer()], &levels, "wg7", &links).unwrap();
        assert!(chain(&chains, "work-out").rules.contains(&drop_on_link(7, "wg7")));
        assert!(chain(&chains, "work-back").rules.contains(&drop_on_link(6, "wg7")));
        assert!(
            chains
                .iter()
                .flat_map(|c| &c.rules)
                .all(|r| !r.contains_slice(&named(7, "kith0")) && !r.contains_slice(&named(6, "kith0")))
        );
    }

    #[test]
    fn a_peer_in_a_level_not_given_is_refused_by_name() {
        let mut stray = peer();
        stray.level = "gone".into();
        let levels = [("work".to_string(), work())];
        let err = table(PEOPLE64.parse().unwrap(), &[stray], &levels, MESH, &[]).unwrap_err();
        assert!(
            err.contains("gone") && err.contains("100.89.1.2") && err.contains("0x0102"),
            "{err}"
        );
    }

    /// A netfilter message's attributes, as (kind, payload), in order.
    type Attributes = Vec<(u16, Vec<u8>)>;

    /// The attributes of one netfilter message.
    fn attributes(mut rest: &[u8]) -> Attributes {
        let mut found = Vec::new();
        while let Some(head) = rest.get(..4) {
            let length = u16::from_ne_bytes([head[0], head[1]]) as usize;
            let kind = u16::from_ne_bytes([head[2], head[3]]) & 0x3fff;
            if length < 4 || length > rest.len() {
                break;
            }
            found.push((kind, rest[4..length].to_vec()));
            rest = &rest[length.next_multiple_of(4).min(rest.len())..];
        }
        found
    }

    /// Every message of a netfilter dump of `kind` (a GET), each one's attributes, in the
    /// kernel's order: the table's chains are listed in the order they were made.
    fn dump(kind: u16) -> std::io::Result<Vec<Attributes>> {
        // (A dump request: the nfgenmsg's family, INET; the flags, a request that dumps.)
        let mut request = Vec::new();
        request.extend(20u32.to_ne_bytes());
        request.extend(kind.to_ne_bytes());
        request.extend((0x300u16 | 1).to_ne_bytes());
        request.extend(1u32.to_ne_bytes());
        request.extend(0u32.to_ne_bytes());
        request.extend([INET, 0, 0, 0]);
        let socket = crate::netlink::socket(12)?;
        socket.send(&request, 0)?;
        let mut messages = Vec::new();
        loop {
            let (bytes, _) = socket.recv_from_full().map_err(crate::netlink::silent)?;
            if bytes.is_empty() {
                return Err(std::io::Error::other(
                    "the kernel ended the dump before its last message",
                ));
            }
            let mut rest = &bytes[..];
            while let Some(head) = rest.get(..16) {
                let length = u32::from_ne_bytes([head[0], head[1], head[2], head[3]]) as usize;
                let message = u16::from_ne_bytes([head[4], head[5]]);
                if length < 16 || length > rest.len() {
                    return Err(std::io::Error::other("a short netlink message"));
                }
                let body = &rest[16..length];
                match message {
                    // (3: done, the dump's last message.)
                    3 => return Ok(messages),
                    // (2: an acknowledgement, or with a code, an error.)
                    2 => {
                        let code = i32::from_ne_bytes(body.get(..4).unwrap_or(&[0; 4]).try_into().unwrap());
                        if code != 0 {
                            return Err(std::io::Error::from_raw_os_error(-code));
                        }
                    }
                    _ => messages.push(attributes(body.get(4..).unwrap_or_default())),
                }
                rest = &rest[length.next_multiple_of(4).min(rest.len())..];
            }
        }
    }

    /// The name in `message`'s attribute `kind`, NUL-terminated as nftables has it.
    fn name_of(message: &[(u16, Vec<u8>)], kind: u16) -> Option<String> {
        let (_, name) = message.iter().find(|(k, _)| *k == kind)?;
        Some(String::from_utf8_lossy(name).trim_end_matches('\0').to_string())
    }

    /// Whether `message` is of the table `TABLE`.
    fn of_table(message: &[(u16, Vec<u8>)]) -> bool {
        name_of(message, 1).as_deref() == Some(TABLE)
    }

    /// The table as the kernel lists it: each chain in its order, with its rule count.
    fn listed() -> std::io::Result<Vec<(String, usize)>> {
        // (1 is the table's name, 3 a chain's; a rule has its chain at 2.)
        let chains: Vec<String> = dump(0xa04)?
            .iter()
            .filter(|m| of_table(m))
            .filter_map(|m| name_of(m, 3))
            .collect();
        let rules: Vec<String> = dump(0xa07)?
            .iter()
            .filter(|m| of_table(m))
            .filter_map(|m| name_of(m, 2))
            .collect();
        Ok(chains
            .into_iter()
            .map(|chain| {
                let count = rules.iter().filter(|rule| **rule == chain).count();
                (chain, count)
            })
            .collect())
    }

    /// The table `chains` make, as `listed` should give it back.
    fn expected(chains: &[Chain]) -> Vec<(String, usize)> {
        chains.iter().map(|c| (c.name.clone(), c.rules.len())).collect()
    }

    /// `chains` with no masquerade rule (the kernel has none in a namespace).
    fn without_masquerade(chains: &mut [Chain]) {
        let masq = expression("masq", &[]);
        for chain in chains {
            chain.rules.retain(|rule| !rule.contains_slice(&masq));
        }
    }

    /// Fails unless this is root in a network namespace of its own (`unshare -Urn`): the E2E
    /// tests never touch the host's nftables. They all share one table name in that namespace,
    /// so the guard returned is held for the whole test: one at a time, or a test's listing
    /// reads another's table mid-replace.
    fn own_namespace() -> std::sync::MutexGuard<'static, ()> {
        static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            nix::unistd::getuid().is_root(),
            "KITH_E2E=1 needs `unshare -Urn`: not root"
        );
        // (A fresh network namespace has only its loopback; the host's has more.)
        let devices = std::fs::read_to_string("/proc/net/dev").unwrap();
        let names: Vec<&str> = devices
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next())
            .map(str::trim)
            .collect();
        assert_eq!(
            names,
            ["lo"],
            "KITH_E2E=1 needs `unshare -Urn`: this is not a namespace of its own"
        );
        guard
    }

    /// Makes `chains` the table here. A kernel with no masquerade in a namespace refuses the post
    /// chain's masq: then the table is made without those rules, and says so.
    fn build_here(chains: &mut [Chain]) -> std::io::Result<()> {
        match build(chains) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("this kernel has no masquerade here: without");
                without_masquerade(chains);
                build(chains)
            }
            done => done,
        }
    }

    /// Under `unshare -Urn` (KITH_E2E=1), the kernel takes the table whole or not at all, and a
    /// second build replaces the first in one batch: the dump lists the built chains in order,
    /// with their rules. Under KITH_E2E=1 but outside its own network namespace it fails, never
    /// skips: it must not touch the host's nftables.
    #[test]
    fn the_kernel_takes_the_table_whole_and_a_second_build_replaces_it() {
        if std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: KITH_E2E=1 unshare -Urn cargo test -p kith-mesh people");
        }
        let _one_at_a_time = own_namespace();

        let people64: Ipv6Addr = PEOPLE64.parse().unwrap();
        let people = [peer()];
        let links = [("10.0.0.0".parse::<IpAddr>().unwrap(), 24u8)];
        let first = [
            ("work".to_string(), work()),
            (
                "home".to_string(),
                Level {
                    internet: Internet::None,
                    ..work()
                },
            ),
        ];
        let mut first_chains = table(people64, &people, &first, MESH, &links).unwrap();
        build_here(&mut first_chains).unwrap();
        assert!(has_table(INET, TABLE).unwrap());
        let built = expected(&first_chains);
        for (name, rules) in &built {
            eprintln!("{TABLE} {name}: {rules} rules");
        }
        assert_eq!(listed().unwrap(), built);

        // A batch the kernel refuses (a rule into a chain it does not have) takes nothing: the
        // table is as the first build left it.
        let mut refused = Batch::new(TABLE);
        refused.table(INET);
        refused.plain(INET, "pre");
        refused.rule(INET, "nowhere", &[verdict(0)]);
        assert!(refused.send().is_err());
        assert_eq!(listed().unwrap(), built);

        // A second build, with `work` changed and `home` gone, replaces the first in one batch.
        let second = [("work".to_string(), Level { api: None, ..work() })];
        let mut second_chains = table(people64, &people, &second, MESH, &links).unwrap();
        build_here(&mut second_chains).unwrap();
        let built = expected(&second_chains);
        for (name, rules) in &built {
            eprintln!("{TABLE} {name}: {rules} rules");
        }
        assert_eq!(listed().unwrap(), built);
    }

    /// Under KITH_E2E=1, 200 peers (each with both addresses) go in one batch and the kernel takes
    /// it whole: a batch that size is too big for the socket's default send buffer, so the buffer
    /// is raised first (`pod.rs`'s `netfilter`).
    #[test]
    fn a_table_of_200_peers_goes_in_one_batch() {
        if std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: KITH_E2E=1 unshare -Urn cargo test -p kith-mesh people");
        }
        let _one_at_a_time = own_namespace();
        let people: Vec<Person> = (1..=200u16)
            .map(|offset| Person {
                level: "work".into(),
                offset,
                v4: Some(Ipv4Addr::new(100, 89, (offset >> 8) as u8, offset as u8)),
                v6: Some(Ipv6Addr::new(0xfd8a, 0x2b3c, 0x4d5e, 5, 0, 0, 0, offset)),
            })
            .collect();
        let levels = [("work".to_string(), work())];
        let links = [("10.0.0.0".parse::<IpAddr>().unwrap(), 24u8)];
        let mut chains = table(PEOPLE64.parse().unwrap(), &people, &levels, MESH, &links).unwrap();
        build_here(&mut chains).unwrap();
        assert_eq!(listed().unwrap(), expected(&chains));
    }
}
