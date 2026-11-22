//! Records, zones and split-horizon views, and the lookup that turns a question into an answer.

use crate::blocklist::Block;
use crate::wire::{NXDOMAIN, SERVFAIL, valid_name};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const TYPE_ANY: u16 = 255;
const TYPE_CNAME: u16 = 5;
/// CNAMEs followed inside our zones before we give up with SERVFAIL.
const MAX_CHAIN: usize = 8;
/// The longest TXT we take; one record has to fit a 64 KiB message.
const MAX_TXT: usize = 4000;
/// The most records one name holds of one type.
const MAX_RRSET: usize = 100;

#[derive(Debug, Clone, PartialEq)]
pub enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Txt(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Ns(String),
    Ptr(String),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
}

impl Rdata {
    /// The RFC 1035 type number.
    pub fn rtype(&self) -> u16 {
        match self {
            Rdata::A(_) => 1,
            Rdata::Ns(_) => 2,
            Rdata::Cname(_) => TYPE_CNAME,
            Rdata::Soa { .. } => 6,
            Rdata::Ptr(_) => 12,
            Rdata::Txt(_) => 16,
            Rdata::Aaaa(_) => 28,
            Rdata::Srv { .. } => 33,
        }
    }

    fn names(&self) -> Vec<&str> {
        match self {
            Rdata::Cname(n) | Rdata::Ns(n) | Rdata::Ptr(n) => vec![n],
            Rdata::Srv { target, .. } => vec![target],
            Rdata::Soa { mname, rname, .. } => vec![mname, rname],
            _ => vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// Dotted, without a trailing dot; `*.zone.kith` is a wildcard.
    pub name: String,
    pub ttl: u32,
    pub data: Rdata,
}

/// A name as we compare it: lowercase, no trailing dot.
pub(crate) fn key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// `name` and then each parent of it, longest first.
pub(crate) fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |n| n.split_once('.').map(|(_, rest)| rest))
}

/// What a lookup found inside our zones.
#[derive(Debug, PartialEq)]
pub struct Found {
    pub rcode: u16,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
}

/// All the records of one view, by name. A zone is every name that has an SOA record.
#[derive(Debug, Clone, Default)]
pub struct Records {
    by_name: HashMap<String, Vec<Record>>,
}

impl Records {
    /// Adds a record, refusing names the wire format cannot carry.
    pub fn add(&mut self, mut r: Record) -> Result<(), String> {
        for n in std::iter::once(r.name.as_str()).chain(r.data.names()) {
            if !valid_name(n) {
                return Err(format!("invalid DNS name {n:?}"));
            }
        }
        if matches!(&r.data, Rdata::Txt(t) if t.len() > MAX_TXT) {
            return Err(format!("TXT record over {MAX_TXT} bytes"));
        }
        r.name = key(&r.name);
        let set = self.by_name.entry(r.name.clone()).or_default();
        if set.iter().filter(|x| x.data.rtype() == r.data.rtype()).count() >= MAX_RRSET {
            return Err(format!(
                "more than {MAX_RRSET} records for {} of type {}",
                r.name,
                r.data.rtype()
            ));
        }
        set.push(r);
        Ok(())
    }

    /// Makes `name` exist with no records of its own yet: asked for a type, it answers NODATA
    /// (NOERROR, the SOA), not NXDOMAIN. Records added to it later join it.
    pub fn add_name(&mut self, name: &str) -> Result<(), String> {
        if !valid_name(name) {
            return Err(format!("invalid DNS name {name:?}"));
        }
        self.by_name.entry(key(name)).or_default();
        Ok(())
    }

    /// The closest zone apex at or above `name`.
    fn apex(&self, name: &str) -> Option<&Record> {
        suffixes(name).find_map(|s| {
            self.by_name
                .get(s)?
                .iter()
                .find(|r| matches!(r.data, Rdata::Soa { .. }))
        })
    }

    /// The records at `name`, or at the wildcard that covers it (renamed to `name`).
    // ponytail: no empty non-terminals, so `a.b.zone` existing does not make `b.zone` exist.
    fn node(&self, name: &str) -> Option<Vec<Record>> {
        if let Some(rs) = self.by_name.get(name) {
            return Some(rs.clone());
        }
        for parent in suffixes(name).skip(1) {
            if let Some(rs) = self.by_name.get(&format!("*.{parent}")) {
                return Some(
                    rs.iter()
                        .map(|r| Record {
                            name: name.to_string(),
                            ..r.clone()
                        })
                        .collect(),
                );
            }
            if self.by_name.contains_key(parent) {
                break;
            }
        }
        None
    }

    /// Answers a question, or `None` when no zone here holds the name (ask upstream).
    pub fn lookup(&self, qname: &str, qtype: u16) -> Option<Found> {
        let mut name = key(qname);
        let mut answers = Vec::new();
        for _ in 0..MAX_CHAIN {
            let Some(soa) = self.apex(&name) else {
                // A CNAME that left our zones: `answer` has the upstreams follow it (a `Chase`).
                return if answers.is_empty() {
                    None
                } else {
                    Some(Found {
                        rcode: 0,
                        answers,
                        authority: vec![],
                    })
                };
            };
            let negative = |rcode: u16, answers: Vec<Record>| {
                let mut soa = soa.clone();
                if let Rdata::Soa { minimum, .. } = soa.data {
                    soa.ttl = soa.ttl.min(minimum);
                }
                Found {
                    rcode,
                    answers,
                    authority: vec![soa],
                }
            };
            let Some(rs) = self.node(&name) else {
                return Some(negative(NXDOMAIN, answers));
            };
            if qtype == TYPE_ANY {
                return Some(negative(0, answers));
            }
            let hits: Vec<_> = rs.iter().filter(|r| r.data.rtype() == qtype).cloned().collect();
            if !hits.is_empty() {
                answers.extend(hits);
                return Some(Found {
                    rcode: 0,
                    answers,
                    authority: vec![],
                });
            }
            let Some(cname) = rs.iter().find(|r| r.data.rtype() == TYPE_CNAME) else {
                return Some(negative(0, answers));
            };
            let Rdata::Cname(target) = &cname.data else { return None };
            name = key(target);
            answers.push(cname.clone());
        }
        Some(Found {
            rcode: SERVFAIL,
            answers: vec![],
            authority: vec![],
        })
    }
}

/// A client network, v4 or v6.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cidr {
    addr: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        fn num(ip: IpAddr) -> (u128, u8) {
            match ip {
                IpAddr::V4(a) => (u32::from(a).into(), 32),
                IpAddr::V6(a) => (a.into(), 128),
            }
        }
        let ((net, width), (ip, w2)) = (num(self.addr), num(ip.to_canonical()));
        let shift = u32::from(width - self.bits);
        width == w2 && net.checked_shr(shift).unwrap_or(0) == ip.checked_shr(shift).unwrap_or(0)
    }

    /// `allowed` with every address of `denied` taken out: each allowed network that holds a
    /// denied one becomes the sibling halves around it (a /7 less a /64 is 57 networks), so a
    /// list of networks can say "all but these" and the deny wins.
    pub fn without(allowed: &[Cidr], denied: &[Cidr]) -> Vec<Cidr> {
        let mut rest = allowed.to_vec();
        for deny in denied {
            rest = rest.into_iter().flat_map(|net| net.minus(deny)).collect();
        }
        rest
    }

    fn minus(self, deny: &Cidr) -> Vec<Cidr> {
        let width = if self.addr.is_ipv4() { 32 } else { 128 };
        if deny.addr.is_ipv4() != self.addr.is_ipv4() || deny.bits > width {
            return vec![self];
        }
        if deny.bits <= self.bits {
            // Inside the denied network whole, or apart from it.
            return if deny.contains(self.addr) { vec![] } else { vec![self] };
        }
        if !self.contains(deny.addr) {
            return vec![self];
        }
        // The denied network is inside this one: keep the other half at each bit between them.
        let num = match deny.addr {
            IpAddr::V4(a) => u128::from(u32::from(a)),
            IpAddr::V6(a) => u128::from(a),
        };
        (self.bits + 1..=deny.bits)
            .map(|len| {
                let shift = u32::from(width - len);
                let sibling = ((num >> shift) ^ 1) << shift;
                let addr = match self.addr {
                    IpAddr::V4(_) => Ipv4Addr::from(sibling as u32).into(),
                    IpAddr::V6(_) => Ipv6Addr::from(sibling).into(),
                };
                Cidr { addr, bits: len }
            })
            .collect()
    }
}

impl FromStr for Cidr {
    type Err = String;

    /// `10.0.0.0/8`, `fd00::/8`, or a bare address for one host. An IPv4 network written as
    /// IPv6 (`::ffff:10.0.0.0/104`) is that IPv4 network, as a client's address is taken
    /// ([`Cidr::contains`]); one wider than all of IPv4 (under /96) is refused.
    fn from_str(s: &str) -> Result<Cidr, String> {
        let (addr, bits) = s.split_once('/').map_or((s, None), |(a, b)| (a, Some(b)));
        let addr: IpAddr = addr.parse().map_err(|_| format!("invalid network {s:?}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits: u8 = bits
            .map_or(Some(max), |b| b.parse().ok().filter(|b| *b <= max))
            .ok_or_else(|| format!("invalid prefix length in {s:?}"))?;
        match addr.to_canonical() {
            IpAddr::V4(v4) if addr.is_ipv6() => match bits.checked_sub(96) {
                Some(bits) => Ok(Cidr { addr: v4.into(), bits }),
                None => Err(format!("{s:?} is wider than IPv4 written as IPv6 (::ffff:0.0.0.0/96)")),
            },
            _ => Ok(Cidr { addr, bits }),
        }
    }
}

/// Records for the clients inside `nets`.
#[derive(Debug, Clone, Default)]
pub struct View {
    pub nets: Vec<Cidr>,
    pub records: Records,
}

/// Everything the server answers from. Cheap to rebuild: swap a new one in through the watch channel.
#[derive(Debug, Clone, Default)]
pub struct Zones {
    /// For clients no view claims.
    pub records: Records,
    /// The view with the longest prefix holding the client replaces `records` for it; of equal
    /// prefixes, the first listed.
    pub views: Vec<View>,
    /// Lists of names answered as not there, for names no zone holds. The first of them that
    /// names the client and the name decides.
    pub blocks: Vec<Block>,
}

impl Zones {
    /// Whether a list blocks `name` for `client`: `Some(true)` to answer 0.0.0.0 and ::,
    /// `Some(false)` to answer NXDOMAIN, `None` for a name that is not blocked.
    pub fn blocked(&self, client: IpAddr, name: &str) -> Option<bool> {
        self.blocks
            .iter()
            .find(|b| (b.nets.is_empty() || b.nets.iter().any(|n| n.contains(client))) && b.names.blocks(name))
            .map(|b| b.null)
    }

    pub fn lookup(&self, client: IpAddr, qname: &str, qtype: u16) -> Option<Found> {
        let prefix = |v: &View| v.nets.iter().filter(|n| n.contains(client)).map(|n| n.bits).max();
        // min_by_key keeps the first of equals; Reverse makes the longest prefix the smallest.
        let view = self
            .views
            .iter()
            .filter_map(|v| Some((v, prefix(v)?)))
            .min_by_key(|&(_, bits)| std::cmp::Reverse(bits))
            .map(|(v, _)| v);
        view.map_or(&self.records, |v| &v.records).lookup(qname, qtype)
    }
}
