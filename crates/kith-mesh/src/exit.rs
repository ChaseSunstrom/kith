//! An exit: a WireGuard tunnel of the node's to a server of someone else's (a VPN), and the
//! only way out for the pods that leave by it. Each such pod's link on the node is
//! `kpx<number>`; the kernel sends what comes in by it to the exit's own routing table
//! (where the one route is the tunnel), or to the mesh, or nowhere: never by the node's
//! own routes. The rules are made by the link's name, before the link is there.
//
// ponytail: IPv4 through the tunnel only (a provider's IPv6 address is not used: a pod's
// IPv6 reaches the mesh and nothing else), and one peer a tunnel.

use crate::Key;
use crate::netlink::{Device, ask_route, up};
use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE};
use netlink_packet_route::route::{RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType};
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute, WireguardDeviceFlags,
    WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// What a provider's `wg0.conf` says: this end's key and address, and the server.
#[derive(Clone, Debug, PartialEq)]
pub struct Tunnel {
    pub key: Key,
    pub address: Ipv4Addr,
    pub peer: Key,
    pub shared: Option<Key>,
    pub endpoint: SocketAddr,
    pub keepalive: u16,
}

/// The connection-tracking mark of whatever a pod of an exit started.
pub const MARK: u32 = 0x6b78;

/// The tunnel `number`'s link.
pub fn device(number: u16) -> String {
    format!("kx{number}")
}

/// The link on the node of pod `number`, one that leaves by an exit: a name of its own
/// (another pod's is [`crate::pod::link_of`]'s), which its rules and the node's are made by.
pub fn link(number: u16) -> String {
    format!("kpx{number}")
}

pub fn table(number: u16) -> u32 {
    0x6b78_0000 | u32::from(number)
}

// The rules' places: ahead of the main table's (32766), after the local one's (0).
const TO_PODS: u32 = 9000;
const NOT_A_POD: u32 = 9001;
const OUT: u32 = 9002;
const NOWHERE: u32 = 9003;
const FROM_TUNNEL: u32 = 9004;
const FROM_TUNNEL_NOWHERE: u32 = 9005;

/// One routing rule: where it is looked at (`priority`), what it takes, where that goes
/// (a table, or `None`: unreachable).
struct Rule<'a> {
    v6: bool,
    priority: u32,
    iif: Option<&'a str>,
    to: Option<(IpAddr, u8)>,
    from: Option<Ipv4Addr>,
    table: Option<u32>,
    /// Of a rule with no table (unreachable), a table all the same: the kernel tells two
    /// rules apart by it, so each exit has its own (two may have one address).
    owner: Option<u32>,
    /// Of the main table, the routes of this prefix length or shorter are left out: 31 for a
    /// pod (only its /32 routes and the mesh's), 0 for a person (no default route).
    suppress: Option<u32>,
}

impl Rule<'_> {
    fn message(&self) -> RuleMessage {
        let mut rule = RuleMessage::default();
        rule.header.family = if self.v6 {
            AddressFamily::Inet6
        } else {
            AddressFamily::Inet
        };
        rule.header.action = match self.table {
            Some(_) => RuleAction::ToTable,
            None => RuleAction::Unreachable,
        };
        rule.attributes.push(RuleAttribute::Priority(self.priority));
        rule.attributes
            .extend(self.iif.map(|iif| RuleAttribute::Iifname(iif.into())));
        if let Some((to, bits)) = self.to {
            rule.header.dst_len = bits;
            rule.attributes.push(RuleAttribute::Destination(to));
        }
        if let Some(from) = self.from {
            rule.header.src_len = 32;
            rule.attributes.push(RuleAttribute::Source(from.into()));
        }
        if let Some(table) = self.table {
            rule.attributes.push(RuleAttribute::Table(table));
            // (Of the main table, a pod's rule leaves out all but the routes to one pod (a /32) or
            // to the mesh: not its way to everywhere, nor a wider network's that holds the pods' range.)
            rule.attributes
                .extend(self.suppress.map(RuleAttribute::SuppressPrefixLen));
        }
        rule.attributes.extend(self.owner.map(RuleAttribute::Table));
        rule
    }

    /// Made (one that is there already is as good), or with `!there` taken away.
    fn set(&self, there: bool) -> Result<()> {
        let message = self.message();
        let asked = match there {
            true => ask_route(
                RouteNetlinkMessage::NewRule(message),
                NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            ),
            false => ask_route(RouteNetlinkMessage::DelRule(message), NLM_F_ACK),
        };
        match asked {
            Err(e) if there && e.kind() == ErrorKind::AlreadyExists => Ok(()),
            Err(e) if !there && e.kind() == ErrorKind::NotFound => Ok(()),
            asked => asked.map(drop),
        }
    }
}

/// The rules of the pod whose node-side link is `link`, leaving by the tunnel `number`:
/// to another pod (of the node's `range`) by the main table, to the mesh (`mesh`, its
/// /48) the same way, and the rest of IPv4 to the tunnel's table, IPv6 nowhere. Whatever
/// finds no route there finds the last rule, which has nowhere to send it: with the
/// tunnel gone, nothing leaves.
fn rules(link: &str, number: u16, range: crate::pod::Range, mesh: Option<(Ipv6Addr, u8)>) -> Vec<Rule<'_>> {
    let (network, bits) = range.network();
    let pods = Some((IpAddr::V4(network), bits));
    let rule = |v6, priority, to, table| Rule {
        v6,
        priority,
        iif: Some(link),
        to,
        from: None,
        table,
        owner: None,
        suppress: (table == Some(254)).then_some(if v6 { 0 } else { 31 }),
    };
    let mut rules = vec![
        rule(false, NOWHERE, None, None),
        rule(true, NOWHERE, None, None),
        rule(false, NOT_A_POD, pods, None),
        rule(false, TO_PODS, pods, Some(254)),
        rule(false, OUT, None, Some(table(number))),
    ];
    if let Some((mesh, bits)) = mesh {
        rules.push(rule(true, TO_PODS, Some((mesh.into(), bits)), Some(254)));
    }
    rules
}

/// Hold the pod `link` to the tunnel `number` (before its link is made: the last rules,
/// which let nothing out, are made first), and read the rules back from the kernel.
pub fn hold(link: &str, number: u16, range: crate::pod::Range, mesh: Option<(Ipv6Addr, u8)>) -> Result<()> {
    let mut last = rules(link, number, range, mesh);
    let rest = last.split_off(2);
    for rule in last {
        rule.set(true)?;
    }
    // (What an earlier pod of this number had, by another tunnel, goes first.)
    release(link)?;
    for rule in rest {
        rule.set(true)?;
    }
    match held(link)? {
        true => Ok(()),
        false => Err(Error::other(format!("the kernel has no rule holding {link} back"))),
    }
}

/// Take away the rules of a pod gone, but those that send nowhere what its link sends:
/// whatever of it lingers (a process its namespace kept) still goes nowhere. They are
/// two a number, and a number's next pod has them first anyway.
pub fn release(link: &str) -> Result<()> {
    let dump = ask_route(RouteNetlinkMessage::GetRule(RuleMessage::default()), NLM_F_DUMP)?;
    for rule in dump {
        let RouteNetlinkMessage::NewRule(rule) = rule else {
            continue;
        };
        let has = |wanted: &RuleAttribute| rule.attributes.contains(wanted);
        if !has(&RuleAttribute::Iifname(link.into())) || has(&RuleAttribute::Priority(NOWHERE)) {
            continue;
        }
        match ask_route(RouteNetlinkMessage::DelRule(rule), NLM_F_ACK) {
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            gone => drop(gone?),
        }
    }
    Ok(())
}

// The people's rules (docs/adr-people.md, "Where a level is enforced"), by what comes in on kwg0:
// the main table with no default route, a person's IPv4 by the whole of it, and nowhere.
const PEOPLE_MAIN: u32 = 9010;
const PEOPLE_INTERNET: u32 = 9011;
const PEOPLE_NOWHERE: u32 = 9012;

fn people_rule(v6: bool, priority: u32, from: Option<Ipv4Addr>, table: Option<u32>) -> Rule<'static> {
    Rule {
        v6,
        priority,
        iif: Some(crate::people::DEVICE),
        to: None,
        from,
        table,
        owner: None,
        suppress: (priority == PEOPLE_MAIN).then_some(0),
    }
}

/// The rules of the people's device are all of those by `kwg0` at 9010 to 9012, of both families.
fn people_dump() -> Result<Vec<RuleMessage>> {
    let dump = ask_route(RouteNetlinkMessage::GetRule(RuleMessage::default()), NLM_F_DUMP)?;
    let ours = |rule: &RuleMessage| {
        rule.attributes
            .contains(&RuleAttribute::Iifname(crate::people::DEVICE.into()))
            && (PEOPLE_MAIN..=PEOPLE_NOWHERE)
                .any(|priority| rule.attributes.contains(&RuleAttribute::Priority(priority)))
    };
    Ok(dump
        .into_iter()
        .filter_map(|rule| match rule {
            RouteNetlinkMessage::NewRule(rule) if ours(&rule) => Some(rule),
            _ => None,
        })
        .collect())
}

/// One of the people's rules as the kernel has it: (priority, IPv6, source, table), the table being
/// none for the rule that sends nowhere.
pub type PeopleRule = (u32, bool, Option<Ipv4Addr>, Option<u32>);

/// What kwg0 has of the people's rules: for the tests and the check.
pub fn people_rules() -> Result<Vec<PeopleRule>> {
    let mut seen = Vec::new();
    for rule in people_dump()? {
        let priority = rule.attributes.iter().find_map(|a| match a {
            RuleAttribute::Priority(priority) => Some(*priority),
            _ => None,
        });
        let source = rule.attributes.iter().find_map(|a| match a {
            RuleAttribute::Source(IpAddr::V4(from)) => Some(*from),
            _ => None,
        });
        let table = rule.attributes.iter().find_map(|a| match a {
            RuleAttribute::Table(table) => Some(*table),
            _ => None,
        });
        // (The kernel says table 0 of the rule that sends nowhere: it has none.)
        let table = table.filter(|_| priority != Some(PEOPLE_NOWHERE));
        let v6 = rule.header.family == AddressFamily::Inet6;
        // (Only a rule that is the whole rule counts: one by kwg0 at 9010 with another table, or
        // without the suppress, is not the people's.)
        seen.extend(
            priority
                .filter(|&priority| is_whole(&rule, v6, priority, source, table))
                .map(|priority| (priority, v6, source, table)),
        );
    }
    seen.sort();
    Ok(seen)
}

/// Is `rule` the people's rule at `priority` (of `v6`, from `source`, to `table`: none for the last
/// rule) with all of what it is made of: its action, its lengths, its table and its suppress? (The
/// kernel adds attributes of its own.) At 9010 the table is the main one, whatever `table` says.
fn is_whole(rule: &RuleMessage, v6: bool, priority: u32, source: Option<Ipv4Addr>, table: Option<u32>) -> bool {
    let table = match priority {
        PEOPLE_MAIN => Some(254),
        PEOPLE_NOWHERE => None,
        _ if table.is_some() => table,
        _ => return false,
    };
    let want = people_rule(v6, priority, source, table).message();
    rule.header.action == want.header.action
        && rule.header.src_len == want.header.src_len
        && rule.header.dst_len == want.header.dst_len
        && want.attributes.iter().all(|a| rule.attributes.contains(a))
}

/// Hold the people's device (before it is made: the last rule, which lets nothing out, goes first):
/// what an earlier start had of the others is taken away, then both families' main table with no
/// default route. A person's whole internet is [`people_internet`]'s, after.
pub fn people_hold() -> Result<()> {
    for v6 in [false, true] {
        people_rule(v6, PEOPLE_NOWHERE, None, None).set(true)?;
    }
    for rule in people_dump()? {
        let v6 = rule.header.family == AddressFamily::Inet6;
        if !is_whole(&rule, v6, PEOPLE_NOWHERE, None, None) {
            delete(rule)?;
        }
    }
    for v6 in [false, true] {
        people_rule(v6, PEOPLE_MAIN, None, Some(254)).set(true)?;
    }
    Ok(())
}

/// A person's IPv4 `from` by the whole of `table` (254, the main one with its default route, or an
/// Exit's [`table`]): made, or with `!there` taken away (by the table it was made with).
pub fn people_internet(from: Ipv4Addr, table: u32, there: bool) -> Result<()> {
    people_rule(false, PEOPLE_INTERNET, Some(from), Some(table)).set(there)
}

/// Take all of the people's rules away.
pub fn people_release() -> Result<()> {
    people_dump()?.into_iter().try_for_each(delete)
}

fn delete(rule: RuleMessage) -> Result<()> {
    match ask_route(RouteNetlinkMessage::DelRule(rule), NLM_F_ACK) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        gone => gone.map(drop),
    }
}

/// Whether the kernel has the rules that send nowhere what `link` sends, for both families.
pub fn held(link: &str) -> Result<bool> {
    let dump = ask_route(RouteNetlinkMessage::GetRule(RuleMessage::default()), NLM_F_DUMP)?;
    let mut families = [false; 2];
    for rule in dump {
        let RouteNetlinkMessage::NewRule(rule) = rule else {
            continue;
        };
        let has = |wanted: &RuleAttribute| rule.attributes.contains(wanted);
        let last = rule.header.action == RuleAction::Unreachable
            && rule.header.dst_len == 0
            && rule.header.src_len == 0
            && has(&RuleAttribute::Priority(NOWHERE))
            && has(&RuleAttribute::Iifname(link.into()));
        match rule.header.family {
            AddressFamily::Inet if last => families[0] = true,
            AddressFamily::Inet6 if last => families[1] = true,
            _ => {}
        }
    }
    Ok(families == [true, true])
}

/// The node's guard against every tunnel (`inet kith-exits`): what comes in by one (a
/// link `kx`), to the node itself or to be passed on, is an answer to what was sent out
/// by it, or is dropped. A tunnel's other end is someone else's machine, and nothing of
/// the node's is for it, kithd's API least of all. Made anew, whole, before each tunnel.
pub fn guard() -> Result<()> {
    use crate::pod::{INET, answering, came_by, verdict};
    let mut batch = crate::pod::Batch::new(GUARD);
    batch.table(INET);
    for (chain, hook) in [("in", 1), ("passed", 2)] {
        batch.chain(INET, chain, "filter", hook, 0, Some(1));
        batch.rule(INET, chain, &[came_by(b"kx"), answering(), verdict(1)]);
        batch.rule(INET, chain, &[came_by(b"kx"), verdict(0)]);
    }
    batch.send()
}

const GUARD: &str = "kith-exits";

/// The tunnel `number` as `tunnel` says, made or changed: its link, its key and its one
/// peer, its address, a table whose one route is the tunnel, and what the node itself
/// sends from the tunnel's address (a DNS question for a pod) sent by that table only.
pub fn ensure(number: u16, tunnel: &Tunnel) -> Result<()> {
    guard()?;
    let name = device(number);
    // (Made anew: nothing of what it was stays, an address or a peer. Meanwhile its pods'
    // rules find no route in its table, and send nothing.)
    remove(number, None)?;
    let mut device = Device::make(&name)?;
    let mut peer = vec![
        WireguardPeerAttribute::PublicKey(tunnel.peer),
        WireguardPeerAttribute::Flags(WireguardPeerFlags::ReplaceAllowedIps),
        WireguardPeerAttribute::Endpoint(tunnel.endpoint),
        WireguardPeerAttribute::PersistentKeepalive(tunnel.keepalive),
        WireguardPeerAttribute::AllowedIps(vec![WireguardAllowedIp(vec![
            WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv4),
            WireguardAllowedIpAttr::IpAddr(Ipv4Addr::UNSPECIFIED.into()),
            WireguardAllowedIpAttr::Cidr(0),
        ])]),
    ];
    peer.push(WireguardPeerAttribute::PresharedKey(tunnel.shared.unwrap_or([0; 32])));
    device.set(vec![
        WireguardAttribute::PrivateKey(tunnel.key),
        WireguardAttribute::Flags(WireguardDeviceFlags::ReplacePeers),
        WireguardAttribute::Peers(vec![WireguardPeer(peer)]),
    ])?;
    // (What comes back by the tunnel is from anywhere: the node's own routes for it are
    // not the tunnel's, which a strict reverse-path check would hold against it.)
    let checked = format!("/proc/sys/net/ipv4/conf/{name}/rp_filter");
    std::fs::write(checked, "0")?;
    let index = device.index();
    crate::address4(index, tunnel.address, 32, None)?;
    up(index)?;

    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    route.header.table = 252; // (the table is in the attribute: it is past 255)
    route.header.protocol = RouteProtocol::Boot;
    route.header.scope = RouteScope::Link;
    route.header.kind = RouteType::Unicast;
    route
        .attributes
        .extend([RouteAttribute::Table(table(number)), RouteAttribute::Oif(index)]);
    ask_route(
        RouteNetlinkMessage::NewRoute(route),
        NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
    )?;
    for rule in from_tunnel(number, tunnel.address) {
        rule.set(true)?;
    }
    Ok(())
}

/// What the node sends from the tunnel `number`'s `address`: by its table, else nowhere.
/// (Two exits of one address: what either sends goes by the first one's tunnel that is
/// up, and nowhere when neither is.)
fn from_tunnel(number: u16, address: Ipv4Addr) -> [Rule<'static>; 2] {
    let rule = |priority, table, owner| Rule {
        v6: false,
        priority,
        iif: None,
        to: None,
        from: Some(address),
        table,
        owner,
        suppress: None,
    };
    [
        rule(FROM_TUNNEL, Some(table(number)), None),
        rule(FROM_TUNNEL_NOWHERE, None, Some(table(number))),
    ]
}

/// Whether the kernel has all of the tunnel `number` that [`ensure`] made of `address`'s
/// tunnel but the link: its table's route (gone with the link, too), its rules, and the
/// [`guard`]'s table.
pub fn whole(number: u16, address: Ipv4Addr) -> Result<bool> {
    if !crate::pod::has_table(crate::pod::INET, GUARD)? {
        return Ok(false);
    }
    let mut asked = RouteMessage::default();
    asked.header.address_family = AddressFamily::Inet;
    let routes = ask_route(RouteNetlinkMessage::GetRoute(asked), NLM_F_DUMP)?;
    let routed = routes.iter().any(|route| {
        matches!(route, RouteNetlinkMessage::NewRoute(route)
            if route.attributes.contains(&RouteAttribute::Table(table(number))))
    });
    let dump = ask_route(RouteNetlinkMessage::GetRule(RuleMessage::default()), NLM_F_DUMP)?;
    let ruled = from_tunnel(number, address).iter().all(|wanted| {
        let wanted = wanted.message();
        dump.iter().any(|rule| {
            matches!(rule, RouteNetlinkMessage::NewRule(rule)
                if rule.header.family == wanted.header.family
                    && rule.header.action == wanted.header.action
                    && rule.header.src_len == wanted.header.src_len
                    && wanted.attributes.iter().all(|one| rule.attributes.contains(one)))
        })
    });
    Ok(routed && ruled)
}

/// Take the tunnel `number` away, and the rules of its address (`address`, if known).
pub fn remove(number: u16, address: Option<Ipv4Addr>) -> Result<()> {
    for rule in address
        .map(|address| from_tunnel(number, address))
        .into_iter()
        .flatten()
    {
        rule.set(false)?;
    }
    let gone = ask_route(
        RouteNetlinkMessage::DelLink(crate::netlink::link(0, Some(&device(number)))),
        NLM_F_ACK,
    );
    match gone {
        // (A link not there by its name: ENODEV, not ENOENT.)
        Err(e) if e.kind() == ErrorKind::NotFound || e.raw_os_error() == Some(nix::libc::ENODEV) => Ok(()),
        gone => gone.map(drop),
    }
}

/// Forget every connection a pod of an exit started (they are tracked with [`MARK`]): one
/// that went by a tunnel since changed or gone does not go on by what is there now.
pub fn forget() -> Result<()> {
    forget_marked(MARK)
}

/// Forget every connection tracked with exactly this `mark` (a person's: `0x6b79_0000` and its offset).
pub fn forget_marked(mark: u32) -> Result<()> {
    // (Of nfnetlink's conntrack (1), delete (2), with no tuple: all of those whose mark is it.)
    let mut message = Vec::new();
    let attributes = [crate::pod::number(8, mark), crate::pod::number(21, u32::MAX)].concat();
    message.extend((attributes.len() as u32 + 20).to_ne_bytes());
    message.extend(0x102u16.to_ne_bytes());
    message.extend(5u16.to_ne_bytes()); // a request, acknowledged
    message.extend(1u32.to_ne_bytes());
    message.extend(0u32.to_ne_bytes());
    message.extend([0, 0, 0, 0]); // either family
    message.extend(attributes);
    match crate::pod::netfilter(&message, 1) {
        // (Nothing tracked at all: nothing to forget.)
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        done => done,
    }
}

/// A tunnel's number on its node, from its name (two of one node with one number: the
/// second is refused, and named again).
pub fn number(name: &str) -> u16 {
    // FNV-1a, folded.
    let hash = name.bytes().fold(0x811c_9dc5u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    });
    (hash >> 16) as u16 ^ hash as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exits_pods_and_tunnels_have_names_of_their_own() {
        assert_eq!(link(2), "kpx2");
        assert_eq!(crate::pod::link_of(2), "kp2");
        assert_ne!(number("vpn"), number("vpn2"));
    }

    /// The rules of a pod are made before its link, read back, and taken away, as root of
    /// a network namespace (`KITH_E2E=1 unshare -Urn cargo test -p kith-mesh rules`).
    #[test]
    fn a_pods_rules_are_held_and_released() {
        if !nix::unistd::getuid().is_root() || std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: KITH_E2E=1 unshare -Urn cargo test -p kith-mesh rules");
        }
        let mesh = Some(("fd00:1:2::".parse().unwrap(), 48));
        let range = crate::pod::Range::default();
        assert!(!held("kpx65280").unwrap());
        hold("kpx65280", 7, range, mesh).unwrap();
        // (Again changes nothing: one that is there is as good.)
        hold("kpx65280", 7, range, mesh).unwrap();
        assert!(held("kpx65280").unwrap());
        // (Released, it still goes nowhere; held by another tunnel, it has that one's alone.)
        release("kpx65280").unwrap();
        assert!(held("kpx65280").unwrap());
        hold("kpx65280", 8, range, mesh).unwrap();
        let dump = ask_route(RouteNetlinkMessage::GetRule(RuleMessage::default()), NLM_F_DUMP).unwrap();
        let tables: Vec<_> = dump
            .into_iter()
            .filter_map(|rule| match rule {
                RouteNetlinkMessage::NewRule(rule) => Some(rule.attributes),
                _ => None,
            })
            .filter(|said| said.contains(&RuleAttribute::Priority(OUT)))
            .collect();
        assert_eq!(tables.len(), 1);
        assert!(tables[0].contains(&RuleAttribute::Table(table(8))));
        // A tunnel that is not there is taken away all the same (the kernel says ENODEV of a
        // link it does not know by name: the first `ensure` of each tunnel removes one).
        remove(8, Some("10.2.0.2".parse().unwrap())).unwrap();
    }

    /// A rule by kwg0 at the people's priority with another table, or no suppress, is not the people's
    /// rule: not counted, and `people_hold` puts the right one in its place (`KITH_E2E=1 unshare -Urn
    /// cargo test -p kith-mesh people_rules`).
    #[test]
    fn people_rules_are_the_whole_rule() {
        if !nix::unistd::getuid().is_root() || std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: KITH_E2E=1 unshare -Urn cargo test -p kith-mesh people_rules");
        }
        let right = vec![
            (PEOPLE_MAIN, false, None, Some(254)),
            (PEOPLE_MAIN, true, None, Some(254)),
            (PEOPLE_NOWHERE, false, None, None),
            (PEOPLE_NOWHERE, true, None, None),
        ];
        people_release().unwrap();
        people_hold().unwrap();
        assert_eq!(people_rules().unwrap(), right);

        // 9010 with another table; 9010 with no suppress; 9012 that sends to a table.
        people_release().unwrap();
        let by_hand = |priority, table, suppress| Rule {
            suppress,
            ..people_rule(false, priority, None, table)
        };
        by_hand(PEOPLE_MAIN, Some(100), Some(0)).set(true).unwrap();
        by_hand(PEOPLE_MAIN, Some(254), None).set(true).unwrap();
        by_hand(PEOPLE_NOWHERE, Some(100), None).set(true).unwrap();
        assert_eq!(people_rules().unwrap(), [], "none of the three is the people's");

        people_hold().unwrap();
        assert_eq!(people_rules().unwrap(), right);
        assert_eq!(people_dump().unwrap().len(), 4, "the others are gone");

        // A person's rule 9011 is to the table it was made with: the main one or an Exit's.
        let phone: Ipv4Addr = "100.89.0.2".parse().unwrap();
        people_internet(phone, 254, true).unwrap();
        people_internet(phone, table(7), true).unwrap();
        let mut both = right.clone();
        both.push((PEOPLE_INTERNET, false, Some(phone), Some(254)));
        both.push((PEOPLE_INTERNET, false, Some(phone), Some(table(7))));
        both.sort();
        assert_eq!(people_rules().unwrap(), both);
        people_internet(phone, 254, false).unwrap();
        people_internet(phone, table(7), false).unwrap();
        assert_eq!(people_rules().unwrap(), right);
        people_release().unwrap();
    }

    /// A tunnel is made, made again, and taken away (`KITH_E2E=1 unshare -Urn cargo test
    /// -p kith-mesh tunnel`; skipped where the kernel has no WireGuard).
    #[test]
    fn a_tunnel_is_made_again_and_taken_away() {
        if !nix::unistd::getuid().is_root() || std::env::var_os("KITH_E2E").is_none() {
            return eprintln!("skipped: KITH_E2E=1 unshare -Urn cargo test -p kith-mesh tunnel");
        }
        let tunnel = Tunnel {
            key: [1; 32],
            address: "10.2.0.2".parse().unwrap(),
            peer: [2; 32],
            shared: None,
            endpoint: "192.0.2.7:51820".parse().unwrap(),
            keepalive: 25,
        };
        assert!(!crate::pod::has_table(crate::pod::INET, GUARD).unwrap());
        match ensure(7, &tunnel) {
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return eprintln!("skipped: {e} (this namespace may not write its sysctls)");
            }
            made => made.unwrap(),
        }
        // The guard is there with the tunnel, and no pod (whose table is another).
        assert!(crate::pod::has_table(crate::pod::INET, GUARD).unwrap());
        assert!(!crate::pod::tables().unwrap());
        ensure(7, &tunnel).unwrap();
        forget().unwrap();
        // Two exits of one address (a provider gives each the same): taking one away
        // leaves the other's rule that lets nothing of that address out by another way.
        ensure(8, &tunnel).unwrap();
        let nowhere = || {
            let dump = ask_route(RouteNetlinkMessage::GetRule(RuleMessage::default()), NLM_F_DUMP).unwrap();
            dump.into_iter()
                .filter(|rule| {
                    matches!(rule, RouteNetlinkMessage::NewRule(rule)
                    if rule.header.action == RuleAction::Unreachable
                        && rule.attributes.contains(&RuleAttribute::Priority(FROM_TUNNEL_NOWHERE)))
                })
                .count()
        };
        assert_eq!(nowhere(), 2);
        // Whole, until a rule of it or its table's route is taken away by hand.
        assert!(whole(8, tunnel.address).unwrap());
        from_tunnel(8, tunnel.address)[1].set(false).unwrap();
        assert!(!whole(8, tunnel.address).unwrap());
        ensure(8, &tunnel).unwrap();
        let route = ask_route(RouteNetlinkMessage::GetRoute(RouteMessage::default()), NLM_F_DUMP).unwrap();
        let route = route.into_iter().find_map(|route| match route {
            RouteNetlinkMessage::NewRoute(route) if route.attributes.contains(&RouteAttribute::Table(table(8))) => {
                Some(route)
            }
            _ => None,
        });
        ask_route(RouteNetlinkMessage::DelRoute(route.unwrap()), NLM_F_ACK).unwrap();
        assert!(!whole(8, tunnel.address).unwrap());
        remove(7, Some(tunnel.address)).unwrap();
        remove(7, Some(tunnel.address)).unwrap();
        assert_eq!(nowhere(), 1);
        remove(8, Some(tunnel.address)).unwrap();
        assert_eq!(nowhere(), 0);
    }
}
