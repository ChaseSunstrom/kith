//! RFC 1035 wire format: a strict reader for queries and a compressing writer for replies.

use crate::zones::{Rdata, Record};
use std::collections::HashMap;

pub const FORMERR: u16 = 1;
pub const SERVFAIL: u16 = 2;
pub const NXDOMAIN: u16 = 3;
pub const NOTIMP: u16 = 4;
pub const REFUSED: u16 = 5;

/// The biggest UDP reply we send to a client that speaks EDNS.
const EDNS_MAX: u16 = 1232;
/// Pointers followed in one name before we call it a loop.
const MAX_JUMPS: u32 = 16;

fn u16_at(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(p..p + 2)?.try_into().ok()?))
}

/// Reads the name at `pos`. Returns it (dotted, case kept) and where the bytes after it start.
/// Rejects forward and looping pointers, pointers into the header, reserved label types, oversize
/// names and truncation.
/// Labels with a dot or a non-ASCII byte are refused too, so a name always splits back the same way.
pub fn read_name(b: &[u8], pos: usize) -> Option<(String, usize)> {
    let (mut p, mut end, mut jumps, mut total) = (pos, None, 0, 1);
    let mut name = String::new();
    loop {
        let len = usize::from(*b.get(p)?);
        if len == 0 {
            return Some((name, end.unwrap_or(p + 1)));
        }
        if len & 0xC0 == 0xC0 {
            let target = usize::from(u16_at(b, p)? & 0x3FFF);
            jumps += 1;
            if !(12..p).contains(&target) || jumps > MAX_JUMPS {
                return None;
            }
            end.get_or_insert(p + 2);
            p = target;
        } else if len & 0xC0 != 0 {
            return None;
        } else {
            total += len + 1;
            let label = b.get(p + 1..p + 1 + len)?;
            if total > 255 || !label.is_ascii() || label.contains(&b'.') {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(std::str::from_utf8(label).ok()?);
            p += 1 + len;
        }
    }
}

/// Whether `name` can be written: 1 to 63 ASCII bytes per label, 255 bytes on the wire at most.
pub fn valid_name(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    name.len() + 2 <= 255 && name.split('.').all(|l| (1..=63).contains(&l.len()) && l.is_ascii())
}

/// The first question of a query and what the reply must copy from it.
#[derive(Debug, PartialEq)]
pub struct Query {
    pub id: u16,
    pub flags: u16,
    /// As the client wrote it: the reply echoes the case.
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    /// The UDP size from the query's OPT record, when it has one.
    pub edns: Option<u16>,
    /// Where that size sits in the packet.
    edns_at: usize,
}

impl Query {
    /// One question and well-formed record sections, or `None`.
    pub fn parse(b: &[u8]) -> Option<Query> {
        if b.len() < 12 || u16_at(b, 4)? != 1 {
            return None;
        }
        let (qname, p) = read_name(b, 12)?;
        let (qtype, qclass) = (u16_at(b, p)?, u16_at(b, p + 2)?);
        let (an, ns, ar) = (u16_at(b, 6)?, u16_at(b, 8)?, u16_at(b, 10)?);
        let (mut p, mut edns, mut edns_at) = (p + 4, None, 0);
        for i in 0..u32::from(an) + u32::from(ns) + u32::from(ar) {
            p = read_name(b, p)?.1;
            let rdlen = usize::from(u16_at(b, p + 8)?);
            if i >= u32::from(an) + u32::from(ns) && u16_at(b, p)? == 41 && edns.is_none() {
                (edns, edns_at) = (Some(u16_at(b, p + 2)?), p + 2);
            }
            p += 10 + rdlen;
            if p > b.len() {
                return None;
            }
        }
        Some(Query {
            id: u16::from_be_bytes([b[0], b[1]]),
            flags: u16_at(b, 2)?,
            qname,
            qtype,
            qclass,
            edns,
            edns_at,
        })
    }

    /// The most bytes a UDP reply to this query may have.
    pub fn udp_limit(&self) -> usize {
        usize::from(self.edns.map_or(512, |s| s.clamp(512, EDNS_MAX)))
    }
}

struct Writer {
    buf: Vec<u8>,
    /// Where each name suffix (lowercase) was first written, for compression pointers.
    seen: HashMap<String, u16>,
}

impl Writer {
    fn u16(&mut self, v: u16) {
        self.buf.extend(v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend(v.to_be_bytes());
    }

    fn name(&mut self, name: &str) {
        let mut rest = name.trim_end_matches('.');
        while !rest.is_empty() {
            let key = rest.to_ascii_lowercase();
            if let Some(&at) = self.seen.get(&key) {
                return self.u16(0xC000 | at);
            }
            if let Ok(at @ 0..0x3FFF) = u16::try_from(self.buf.len()) {
                self.seen.insert(key, at);
            }
            let (label, tail) = rest.split_once('.').unwrap_or((rest, ""));
            self.buf.push(label.len() as u8);
            self.buf.extend(label.as_bytes());
            rest = tail;
        }
        self.buf.push(0);
    }

    /// An SRV target is the one name here that RFC 2782 says must not be compressed.
    fn plain_name(&mut self, name: &str) {
        for label in name.trim_end_matches('.').split('.') {
            self.buf.push(label.len() as u8);
            self.buf.extend(label.as_bytes());
        }
        self.buf.push(0);
    }

    fn record(&mut self, r: &Record) {
        self.name(&r.name);
        self.u16(r.data.rtype());
        self.u16(1);
        self.u32(r.ttl);
        let len_at = self.buf.len();
        self.u16(0);
        match &r.data {
            Rdata::A(a) => self.buf.extend(a.octets()),
            Rdata::Aaaa(a) => self.buf.extend(a.octets()),
            Rdata::Cname(n) | Rdata::Ns(n) | Rdata::Ptr(n) => self.name(n),
            Rdata::Txt(t) => {
                for chunk in t.as_bytes().chunks(255) {
                    self.buf.push(chunk.len() as u8);
                    self.buf.extend(chunk);
                }
                if t.is_empty() {
                    self.buf.push(0);
                }
            }
            Rdata::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                for v in [priority, weight, port] {
                    self.u16(*v);
                }
                self.plain_name(target);
            }
            Rdata::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                self.name(mname);
                self.name(rname);
                for v in [serial, refresh, retry, expire, minimum] {
                    self.u32(*v);
                }
            }
        }
        let len = (self.buf.len() - len_at - 2) as u16;
        self.buf[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
    }
}

fn encode(q: &Query, rcode: u16, aa: bool, answers: &[Record], authority: &[Record], tc: bool) -> Vec<u8> {
    let mut w = Writer {
        buf: Vec::new(),
        seen: HashMap::new(),
    };
    // QR, the query's opcode and RD, AA, TC, RA (we forward), the rcode.
    let flags = 0x8000 | (q.flags & 0x7900) | u16::from(aa) << 10 | u16::from(tc) << 9 | 0x80 | rcode;
    for v in [
        q.id,
        flags,
        1,
        answers.len() as u16,
        authority.len() as u16,
        u16::from(q.edns.is_some()),
    ] {
        w.u16(v);
    }
    w.name(&q.qname);
    w.u16(q.qtype);
    w.u16(q.qclass);
    for r in answers.iter().chain(authority) {
        w.record(r);
    }
    if q.edns.is_some() {
        w.buf.push(0);
        for v in [41, EDNS_MAX, 0, 0, 0] {
            w.u16(v);
        }
    }
    w.buf
}

/// A reply to `q`; one over `limit` bytes becomes a header and question with TC set, or SERVFAIL
/// when `limit` is the most a TCP message can hold.
pub fn build(q: &Query, rcode: u16, answers: &[Record], authority: &[Record], limit: usize) -> Vec<u8> {
    let full = encode(q, rcode, true, answers, authority, false);
    if full.len() <= limit {
        full
    } else if limit >= usize::from(u16::MAX) {
        encode(q, SERVFAIL, false, &[], &[], false)
    } else {
        encode(q, rcode, true, &[], &[], true)
    }
}

/// The only question of a message: its name (lowercase), type, class, and where it ends.
pub fn question(b: &[u8]) -> Option<(String, u16, u16, usize)> {
    if b.len() < 12 || u16_at(b, 4)? != 1 {
        return None;
    }
    let (name, p) = read_name(b, 12)?;
    Some((name.to_ascii_lowercase(), u16_at(b, p)?, u16_at(b, p + 2)?, p + 4))
}

/// `query` with the id `id` and any EDNS size over `EDNS_MAX` brought down to it.
pub fn for_upstream(query: &[u8], id: u16) -> Option<Vec<u8>> {
    let q = Query::parse(query)?;
    let mut out = query.to_vec();
    out[..2].copy_from_slice(&id.to_be_bytes());
    if let Some(size) = q.edns {
        out[q.edns_at..q.edns_at + 2].copy_from_slice(&size.min(EDNS_MAX).to_be_bytes());
    }
    Some(out)
}

/// A recursive query for `name` and `qtype` (class IN), with id 0: the forwarder gives it its own.
// ponytail: no EDNS, so a UDP upstream answers in 512 bytes at most; a longer one comes back
// truncated and the CNAME goes out alone (clients that use TCP are asked over TCP).
pub fn ask(name: &str, qtype: u16) -> Vec<u8> {
    let mut w = Writer {
        buf: Vec::new(),
        seen: HashMap::new(),
    };
    for v in [0, 0x0100, 1, 0, 0, 0] {
        w.u16(v);
    }
    w.name(name);
    w.u16(qtype);
    w.u16(1);
    w.buf
}

/// The record at `p` of an answer section and where the next one starts. The record is `None`
/// for a type we cannot hold (or data that is not well formed); `None` overall ends the section.
fn record_at(b: &[u8], p: usize) -> Option<(Option<Record>, usize)> {
    let (name, p) = read_name(b, p)?;
    let (ty, class, len) = (u16_at(b, p)?, u16_at(b, p + 2)?, usize::from(u16_at(b, p + 8)?));
    let ttl = u32::from(u16_at(b, p + 4)?) << 16 | u32::from(u16_at(b, p + 6)?);
    let rd = b.get(p + 10..p + 10 + len)?;
    let data = match (ty, class) {
        (1, 1) => <[u8; 4]>::try_from(rd).ok().map(|a| Rdata::A(a.into())),
        (28, 1) => <[u8; 16]>::try_from(rd).ok().map(|a| Rdata::Aaaa(a.into())),
        (5, 1) => read_name(b, p + 10).map(|n| Rdata::Cname(n.0)),
        (16, 1) => txt(rd),
        _ => None,
    };
    Some((data.map(|data| Record { name, ttl, data }), p + 10 + len))
}

/// The strings of a TXT record joined, if they are UTF-8.
fn txt(mut rd: &[u8]) -> Option<Rdata> {
    let mut text = Vec::new();
    while let [n, rest @ ..] = rd {
        text.extend(rest.get(..usize::from(*n))?);
        rd = &rest[usize::from(*n)..];
    }
    Some(Rdata::Txt(String::from_utf8(text).ok()?))
}

/// The A, AAAA, CNAME and TXT records in the answer section of a NOERROR response, in order. Other
/// types are skipped; so is everything after the first record that cannot be read.
pub fn answers(b: &[u8]) -> Vec<Record> {
    let mut out = vec![];
    let Some((.., mut p)) = question(b) else { return out };
    if b[2] & 0x80 == 0 || b[3] & 0xF != 0 {
        return out;
    }
    for _ in 0..u16_at(b, 6).unwrap_or(0) {
        let Some((r, next)) = record_at(b, p) else { break };
        out.extend(r);
        p = next;
    }
    out
}

/// An upstream `reply` for a UDP client with room for `limit` bytes: a longer one is cut to its
/// header and question with TC set, never in the middle of a record. `reply` has been checked.
pub fn truncate(mut reply: Vec<u8>, limit: usize) -> Vec<u8> {
    if reply.len() <= limit || reply.len() < 12 {
        return reply;
    }
    reply.truncate(question(&reply).map_or(12, |q| q.3));
    reply[2] |= 2;
    reply[6..12].fill(0);
    reply
}

/// An empty reply with `rcode`, echoing the question when the query has a readable one.
pub fn failure(query: &[u8], rcode: u16) -> Vec<u8> {
    if let Some(q) = Query::parse(query) {
        return encode(&q, rcode, false, &[], &[], false);
    }
    let flags = 0x8000 | (u16_at(query, 2).unwrap_or(0) & 0x7900) | 0x80 | rcode;
    let mut r = vec![query.first().copied().unwrap_or(0), query.get(1).copied().unwrap_or(0)];
    r.extend(flags.to_be_bytes());
    r.extend([0; 8]);
    r
}
