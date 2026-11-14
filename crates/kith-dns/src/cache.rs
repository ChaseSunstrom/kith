//! A cache of what the upstreams say, so a name asked again is not asked of them again.
//!
//! It holds whole replies, by question, for as long as their records say (never more than an
//! hour) and in no more than `max_entries` entries and `max_bytes` bytes, the oldest going first.
//! It sits behind the zones and the block lists: those answer first, so changing either never
//! leaves a stale answer in here. Memory only; nothing of it is written anywhere.

use crate::wire::{self, Query};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The longest an answer is kept, whatever its TTL says.
const MAX_LIFETIME: u32 = 3600;
/// What an entry costs besides its reply and name, counted so the byte bound holds.
const ENTRY_OVERHEAD: usize = 96;

/// What two questions must share for one reply to serve both: name, type, and the header and
/// EDNS bits that change what an upstream says (recursion, DNSSEC checking, DNSSEC records).
// A client's UDP size is left out on purpose: replies are cut to it after they are read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    name: Box<str>,
    qtype: u16,
    flags: u16,
    edns: Option<u32>,
}

impl Key {
    pub fn new(q: &Query) -> Key {
        Key {
            name: q.qname.to_ascii_lowercase().into(),
            qtype: q.qtype,
            // RD, AD and CD.
            flags: q.flags & 0x0130,
            edns: q.edns_ttl,
        }
    }
}

struct Entry {
    reply: Box<[u8]>,
    stored: Instant,
    expires: Instant,
    /// Counts up as entries go in: the least is the oldest.
    seq: u64,
}

#[derive(Default)]
struct Inner {
    map: HashMap<Key, Entry>,
    bytes: usize,
    seq: u64,
    hits: u64,
    misses: u64,
}

fn cost(key: &Key, e: &Entry) -> usize {
    e.reply.len() + key.name.len() + ENTRY_OVERHEAD
}

impl Inner {
    fn remove(&mut self, key: &Key) {
        if let Some(e) = self.map.remove(key) {
            self.bytes -= cost(key, &e);
        }
    }
}

pub struct Cache {
    inner: Mutex<Inner>,
    max_entries: usize,
    max_bytes: usize,
}

/// What a cache holds and has done, for a status to show.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CacheStats {
    pub entries: usize,
    pub bytes: usize,
    pub max_entries: usize,
    pub max_bytes: usize,
    pub hits: u64,
    pub misses: u64,
}

impl Default for Cache {
    /// 4096 answers in 1 MiB: enough for a node's own pods and their usual names.
    fn default() -> Cache {
        Cache::new(4096, 1 << 20)
    }
}

impl Cache {
    /// An empty cache; it allocates nothing until an answer comes in.
    pub fn new(max_entries: usize, max_bytes: usize) -> Cache {
        Cache {
            inner: Mutex::default(),
            max_entries,
            max_bytes,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The reply kept for `key`, made for `query` (its id and its question as it wrote it) with
    /// the time since it was kept taken off every TTL; `None` when there is none or it has run out.
    pub fn get(&self, key: &Key, query: &[u8], now: Instant) -> Option<Vec<u8>> {
        let mut g = self.lock();
        let reply = match g.map.get(key) {
            Some(e) if now < e.expires => {
                let secs = now.saturating_duration_since(e.stored).as_secs();
                Some(wire::aged(&e.reply, u32::try_from(secs).unwrap_or(u32::MAX)))
            }
            Some(_) => {
                g.remove(key);
                None
            }
            None => None,
        };
        // The question is copied over from the client's, so its case is echoed.
        let reply = reply.and_then(|mut r| {
            let (ours, theirs) = (wire::question(&r)?.3, wire::question(query)?.3);
            (ours == theirs).then(|| {
                r[..2].copy_from_slice(&query[..2]);
                r[12..ours].copy_from_slice(&query[12..theirs]);
                r
            })
        });
        match reply {
            Some(_) => g.hits += 1,
            None => g.misses += 1,
        }
        reply
    }

    /// Keeps `reply` for `key`, if it is one worth keeping: a whole answer or a "no such name",
    /// with a record to say how long. An answer too big for the byte bound is not kept.
    pub fn put(&self, key: Key, reply: &[u8], now: Instant) {
        let ok = reply.len() >= 12
            // A response, not truncated, of opcode 0, NOERROR or NXDOMAIN.
            && reply[2] & 0xFA == 0x80
            && matches!(reply[3] & 0xF, 0 | 3);
        let Some(life) = ok.then(|| wire::lifetime(reply)).flatten() else {
            return;
        };
        let life = life.min(MAX_LIFETIME);
        if life == 0 {
            return;
        }
        let entry = Entry {
            reply: reply.into(),
            stored: now,
            expires: now + Duration::from_secs(life.into()),
            seq: 0,
        };
        let size = cost(&key, &entry);
        if size > self.max_bytes || self.max_entries == 0 {
            return;
        }
        let mut g = self.lock();
        g.remove(&key);
        // ponytail: finding the oldest scans every entry; fine at the default bounds, a queue
        // of keys if they are ever raised a lot.
        while g.map.len() >= self.max_entries || g.bytes + size > self.max_bytes {
            let Some(oldest) = g.map.iter().min_by_key(|(_, e)| e.seq).map(|(k, _)| k.clone()) else {
                break;
            };
            g.remove(&oldest);
        }
        g.seq += 1;
        g.bytes += size;
        let seq = g.seq;
        g.map.insert(key, Entry { seq, ..entry });
    }

    pub fn stats(&self) -> CacheStats {
        let g = self.lock();
        CacheStats {
            entries: g.map.len(),
            bytes: g.bytes,
            max_entries: self.max_entries,
            max_bytes: self.max_bytes,
            hits: g.hits,
            misses: g.misses,
        }
    }
}
