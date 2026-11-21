//! A node's state partition under dm-crypt, its key held by the cluster.
//!
//! Chosen when the machine is installed (`encrypt: true`). The installer makes a key
//! (512 bits, aes-xts), writes the state's file system through it, and leaves a *lock
//! record* in the config partition:
//!
//! ```text
//! kith-lock v1
//! secret: …      32 bytes only this disk has: what the key is wrapped with for the cluster
//! recovery: …    the key wrapped with the recovery key the installer showed, once
//! key: …         the key itself, only until another node holds it
//! tpm: …         the key as this machine's TPM sealed it, if the cluster lets it
//! tpm-next: …    the same, sealed ahead for the system an update will start (tried after
//!                `tpm:`; tpm-pin: has tpm-pin-next:, its k1 so sealed)
//! passphrase: …  the key wrapped under its owner's passphrase, if one was given
//! seen: yes      somebody was shown the recovery key, or typed it
//! duress: …      the public key of this node's duress code, if the cluster made one
//! duress-all: …  and of the cluster's, which forgets every node
//! peers: …       where to ask
//! ```
//!
//! Once the node is in a cluster it writes a `NodeKey` (the key wrapped with the secret,
//! under an id made from the secret); when a node other than itself answers
//! `POST /v1/unlock` with it, the key is taken off the disk. From then on the node, at
//! each start, brings its network up and asks the nodes it knows for its key before it
//! mounts anything. A disk away from its cluster opens for nobody; `kith node lock` has
//! the cluster refuse, `kith node wipe` has it forget. The recovery key, typed at the
//! machine's console, opens it where no cluster answers.
//!
//! A node the cluster lets (`kith node seal`) also has its own TPM keep the key, sealed to
//! the system it runs (tpm.rs): a `tpm:` line of the record. It then opens its state with
//! no node asked (a laptop away from home), for as long as it starts that very system: a
//! start the TPM refuses (an update, other firmware, another command line) asks the
//! cluster as before and, once open, seals again. The cost is said plainly: such a
//! machine, taken whole, opens its state by itself; locked or wiped, it drops the seal
//! when it hears of it, not before.
//!
//! And a passphrase its owner gives it (`kith node passphrase`), for the machine without a
//! TPM, or whose owner will not have the machine alone be enough: a `passphrase:` line,
//! the key wrapped under what Argon2id draws from the passphrase. Typed at the console
//! where the recovery key is typed, it opens the state with no node in reach. The cost:
//! the key is on the disk again, behind a secret a person chose, which whoever has the
//! disk can guess at for as long as they like; a locked node drops the line when it
//! hears of it.
//!
//! A recovery key nobody saw opens nothing: an install nobody watched printed it to a log.
//! `kith node recovery` has a running node make a new one (the old one stops opening) and
//! shows it, once; the record says `seen` from then on, as it does once a recovery key
//! typed at the console opened the state, and the NodeKey's status says so
//! (`recoverySeen`), for the cluster to warn while no node has one.
//!
//! A duress code (`kith node duress`) is for whoever is made to open a node: it has the
//! recovery key's shape, and typed at the waiting console it erases the lock record (the
//! disk's secret and every wrapped key with it), has the cluster forget the node's key
//! when a node answers, and is answered as a wrong key is, at the same time after it was
//! entered. Only the public key of a signing key drawn from the code is kept (in the
//! NodeKey and in the record), so neither says what the code is; the cluster forgets
//! (`POST /v1/forget`) only for a signature of that key over a number it just gave.
//! The store keeps no earlier version of a NodeKey, and every control node snapshots and
//! drops its log up to the write that forgot a key (kith-store's `scrub`), so no control
//! node's store keeps the key after it. What it does not do: a disk copied beforehand, with its recovery key, still opens;
//! flash may keep the record's old blocks; and the record shows that a code exists.
//!
//! The cluster's code (`kith node duress --all`) is one code on every NodeKey there is
//! when it is made. Typed at one node's console it does to that node what its own code
//! does, and has the cluster forget the key of every other node under it (`forgotten`):
//! those run on, with their records, drop what opens them with no node asked (the TPM's
//! seal, a passphrase), and from then on open with their own recovery keys alone, until
//! `kith node unlock` has the cluster hold a key again. So no such code is made while one
//! of them has a recovery key nobody was shown.
//!
//! Neither the store alone (the key is wrapped with what only the disk has) nor the disk
//! alone opens the state. Who answers `/v1/unlock` is not checked by certificate (the
//! node's own are in the state it cannot read yet): what comes back is sealed with the
//! disk's secret, so nobody else could have made it, and TLS keeps it from a listener.

use crate::cluster::refuse;
use crate::init;
use crate::pki::hex;
use crate::{Shared, access::Caller};
use axum::extract::{Path as Named, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use kith_store::Command;
use ring::rand::SecureRandom;
use ring::{aead, digest, hkdf};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Where in the config partition the record is (the node's config is its first 64 kB),
/// and how long it may be. A copy of it follows, written first: a write cut by a power
/// cut leaves one of the two whole (T-0596).
pub const AT: u64 = 512 << 10;
const ROOM: usize = 4096;
const FIRST: &str = "kith-lock v1";
/// What an erased lock record's room begins with (see `erase`).
const TOMBSTONE: &[u8] = b"kith-lock erased\n";
/// What [`Record::read`] says of an erased record: init powers off on it, as a restart would
/// find the same.
pub const ERASED: &str = "this node's lock record was erased (a duress code or a wipe): its state cannot be opened";
/// `sum: ` and the SHA-256 of the lines after it, in hex: a record cut part way is not taken.
const SUM_LINE: usize = "sum: \n".len() + 64;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
    secret: Vec<u8>,
    recovery: Vec<u8>,
    key: Option<Vec<u8>>,
    /// The key as this machine's TPM sealed it (tpm.rs).
    tpm: Option<Vec<u8>>,
    /// The name of the TPM's storage key it was sealed under (34 bytes); empty when the
    /// line cannot be read, which still counts as one: the seal is then not opened.
    parent: Option<Vec<u8>>,
    pass: Option<Pass>,
    /// The key under this machine's TPM and a PIN; empty when the line cannot be read,
    /// which opens nothing.
    pin: Option<PinSeal>,
    /// The key sealed ahead for the next system (`tpm-next:`), and k1 for it
    /// (`tpm-pin-next:`): tried after the seals they stand for, which stay until the next
    /// system opened the state. Empty when the line cannot be read, which opens nothing.
    next: Option<Vec<u8>>,
    pin_next: Option<Vec<u8>>,
    /// Whether somebody was shown this disk's recovery key, or typed it.
    seen: bool,
    /// The public keys of the duress codes the cluster made for this node, and for all.
    duress: Option<Vec<u8>>,
    duress_all: Option<Vec<u8>>,
    /// The state's key wrapped under what each FIDO2 key gives (`fido2:` lines, at most
    /// [`FIDO2_KEYS`]; docs/adr-fido2.md section 4).
    fido2: Vec<Fido2>,
    peers: Vec<String>,
}

/// How many `fido2:` lines a record holds: two keys, so a lost one does not lock the node
/// out; four would not fit [`ROOM`] beside the other ways.
const FIDO2_KEYS: usize = 2;
/// What a wrapped key is made of (a nonce, the key, a tag), and what CTAP2 gives a
/// `fido2:` line: a credential id of 128 bytes at most, a salt and a secret of 32.
const NONCE: usize = aead::NONCE_LEN;
const TAG: usize = aead::MAX_TAG_LEN;
const CRED_ID_MAX: usize = 128;
const SALT: usize = 32;
/// A wrapped state key at most (a 64-byte key is 92; this leaves room for a longer one).
const WRAPPED_MAX: usize = 128;

/// A FIDO2 key's line: its credential id (not secret), the salt asked of its `hmac-secret`,
/// and the state's key wrapped under what it gave.
#[derive(Clone, Debug, PartialEq)]
struct Fido2 {
    id: Vec<u8>,
    salt: Vec<u8>,
    wrapped: Vec<u8>,
}

impl Fido2 {
    /// A line of the sizes CTAP2 gives (an id of 128 bytes at most, a salt of 32) and a
    /// wrapped key of a nonce, a key and a tag: one that is none is not written, as it
    /// would be dropped when read.
    fn shaped(self) -> Option<Fido2> {
        let fits = (1..=CRED_ID_MAX).contains(&self.id.len())
            && self.salt.len() == SALT
            && (NONCE + 1 + TAG..=WRAPPED_MAX).contains(&self.wrapped.len());
        fits.then_some(self)
    }

    /// A line for a key that gave `secret` (the 32 bytes `hmac-secret` gives: a shorter one
    /// is not wrapped under).
    fn new(id: &[u8], salt: &[u8], secret: &[u8], key: &[u8]) -> Option<Fido2> {
        (secret.len() == SALT).then_some(())?;
        let (id, salt, wrapped) = (id.to_vec(), salt.to_vec(), wrap(secret, key));
        Fido2 { id, salt, wrapped }.shaped()
    }

    /// The state's key, if `secret` is what this key gave for the line's salt.
    fn open(&self, secret: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        unwrap_kept(secret, &self.wrapped)
    }

    fn parse(line: &str) -> Option<Fido2> {
        let mut words = line.split_whitespace().map(unhex);
        let (id, salt, wrapped) = (words.next()??, words.next()??, words.next()??);
        // (A fourth word is a line of another shape: dropped, not read as its first three.)
        words.next().is_none().then_some(())?;
        Fido2 { id, salt, wrapped }.shaped()
    }

    fn text(&self) -> String {
        format!("{} {} {}", hex(&self.id), hex(&self.salt), hex(&self.wrapped))
    }
}

/// The key wrapped under a passphrase: what drawing the wrapping key from it costs
/// (Argon2id's memory in KiB, and its passes), the salt, and the wrapped key.
#[derive(Clone, Debug, PartialEq)]
struct Pass {
    cost: (u32, u32),
    salt: Vec<u8>,
    wrapped: Vec<u8>,
}

/// The key under the TPM and a PIN (docs/adr-unlock.md, "TPM plus PIN"): `k1` sealed to the
/// system this machine runs (drawn from the key, so made again with no PIN), `k2` sealed
/// under the PIN (each wrong one counted by the TPM), and the key wrapped under both.
#[derive(Clone, Debug, Default, PartialEq)]
struct PinSeal {
    k1: Vec<u8>,
    k2: Vec<u8>,
    wrapped: Vec<u8>,
}

impl PinSeal {
    fn parse(line: &str) -> Option<PinSeal> {
        let mut words = line.split_whitespace().map(unhex);
        let (k1, k2, wrapped) = (words.next()??, words.next()??, words.next()??);
        Some(PinSeal { k1, k2, wrapped })
    }

    fn text(&self) -> String {
        format!("{} {} {}", hex(&self.k1), hex(&self.k2), hex(&self.wrapped))
    }
}

/// k1 of the state whose key is `key`: what the TPM seals to the system (never kept).
fn k1_of(key: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    let drawn = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(key);
    let mut k1 = zeroize::Zeroizing::new([0; 32]);
    let filled = drawn
        .expand(&[b"kith-lock tpm-pin pcr"], hkdf::HKDF_SHA256)
        .and_then(|k1_of| k1_of.fill(&mut k1[..]));
    filled.expect("32 bytes are within what HKDF gives");
    k1
}

/// What can be a PIN: 6 to 32 digits.
fn pin_shaped(line: &str) -> bool {
    (6..=32).contains(&line.len()) && line.bytes().all(|byte| byte.is_ascii_digit())
}

/// What a passphrase given now costs to try: 19 MiB and 2 passes, in one lane (OWASP's
/// floor for Argon2id; a record says its own, so this can rise).
const COST: (u32, u32) = (19 << 10, 2);
/// What can be a passphrase: 8 characters or more, of those every keyboard has (a console
/// at start has the kernel's layout and no way to compose others), and no more than a line.
fn chosen(passphrase: &str) -> bool {
    let typed = |byte: u8| byte == b' ' || byte.is_ascii_graphic();
    (8..=256).contains(&passphrase.len()) && passphrase.bytes().all(typed)
}

/// How a state was opened at a start: by its owner (the key was still on the disk, or its
/// passphrase was typed), by the recovery key typed (so somebody has it), by the cluster's
/// answer, by the machine's own TPM, by its TPM and the PIN typed, or by a security key touched.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum By {
    Owner,
    Recovery,
    Cluster,
    Tpm,
    Pin,
    /// A security key touched at the console (docs/adr-fido2.md), as a passphrase typed is.
    Key,
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |byte: &u8| (*byte as char).to_digit(16).map(|digit| digit as u8);
    let (pairs, rest) = text.trim().as_bytes().as_chunks::<2>();
    let bytes = pairs.iter().map(|[high, low]| Some(digit(high)? << 4 | digit(low)?));
    rest.is_empty().then(|| bytes.collect())?
}

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    let filled = ring::rand::SystemRandom::new().fill(&mut bytes);
    filled.expect("the kernel gives random bytes");
    bytes
}

fn sealing(secret: &[u8]) -> aead::LessSafeKey {
    let drawn = hkdf::Salt::new(hkdf::HKDF_SHA256, b"kith-lock").extract(secret);
    let key = drawn.expand(&[b"wrap"], &aead::CHACHA20_POLY1305);
    aead::LessSafeKey::new(aead::UnboundKey::from(key.expect("a key's length")))
}

/// `key` sealed under `secret` (ChaCha20-Poly1305, its key drawn from the secret): a
/// nonce, then what only the secret opens.
fn wrap(secret: &[u8], key: &[u8]) -> Vec<u8> {
    let nonce: [u8; NONCE] = random();
    let mut sealed = zeroize::Zeroizing::new(key.to_vec());
    let nonced = aead::Nonce::assume_unique_for_key(nonce);
    let done = sealing(secret).seal_in_place_append_tag(nonced, aead::Aad::empty(), &mut *sealed);
    done.expect("a key is short enough to seal");
    [&nonce[..], &sealed].concat()
}

fn unwrap(secret: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
    unwrap_kept(secret, wrapped).map(|key| key.to_vec())
}

/// The key `wrapped` holds, if `secret` opens it: kept in what wipes itself, as is the copy
/// it was opened in.
fn unwrap_kept(secret: &[u8], wrapped: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let (nonce, sealed) = wrapped.split_at_checked(NONCE)?;
    let mut sealed = zeroize::Zeroizing::new(sealed.to_vec());
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
    let key = sealing(secret).open_in_place(nonce, aead::Aad::empty(), &mut sealed);
    key.ok().map(|key| zeroize::Zeroizing::new(key.to_vec()))
}

fn drawn(passphrase: &str, salt: &[u8], (memory, passes): (u32, u32)) -> Option<[u8; 32]> {
    let cost = argon2::Params::new(memory, passes, 1, Some(32)).ok()?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, cost);
    let mut key = [0; 32];
    let filled = argon.hash_password_into(passphrase.as_bytes(), salt, &mut key);
    filled.ok().map(|()| key)
}

impl Pass {
    fn new(passphrase: &str, key: &[u8], cost: (u32, u32)) -> Option<Pass> {
        let salt: [u8; 16] = random();
        let wrapped = wrap(&drawn(passphrase, &salt, cost)?, key);
        Some(Pass {
            cost,
            salt: salt.to_vec(),
            wrapped,
        })
    }

    /// The key, if `passphrase` is the one it was wrapped under.
    fn open(&self, passphrase: &str) -> Option<Vec<u8>> {
        unwrap(&drawn(passphrase, &self.salt, self.cost)?, &self.wrapped)
    }

    fn parse(line: &str) -> Option<Pass> {
        let mut words = line.split_whitespace();
        let cost: (u32, u32) = (words.next()?.parse().ok()?, words.next()?.parse().ok()?);
        let (salt, wrapped) = (unhex(words.next()?)?, unhex(words.next()?)?);
        // (Whoever wrote the record does not have a start take a quarter of a GiB or more.)
        (cost.0 <= 1 << 18 && cost.1 <= 16).then_some(Pass { cost, salt, wrapped })
    }

    fn text(&self) -> String {
        let (memory, passes) = self.cost;
        format!("{memory} {passes} {} {}", hex(&self.salt), hex(&self.wrapped))
    }
}

/// The signing key drawn from a duress code (16 bytes, shown and typed as a recovery key
/// is): what is kept of a code is this key's public half, which says nothing of the code.
fn duress_key(code: &[u8]) -> ring::signature::Ed25519KeyPair {
    let drawn = hkdf::Salt::new(hkdf::HKDF_SHA256, b"kith-lock duress").extract(code);
    let mut seed = [0; 32];
    let filled = drawn
        .expand(&[b"sign"], hkdf::HKDF_SHA256)
        .and_then(|seed_of| seed_of.fill(&mut seed));
    filled.expect("32 bytes are within what HKDF gives");
    ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).expect("32 bytes are a seed")
}

/// What a forget is signed over: the disk's id and the number the cluster just gave.
fn forget_text(id: &str, nonce: &[u8]) -> Vec<u8> {
    [b"kith-forget ", id.as_bytes(), b" ", nonce].concat()
}

/// The recovery key as shown and typed: 32 hex digits in fours.
fn shown(recovery: &[u8]) -> String {
    let digits = hex(recovery);
    let fours: Vec<&str> = (0..digits.len()).step_by(4).map(|at| &digits[at..at + 4]).collect();
    fours.join("-")
}

/// What was typed, if it can be a recovery key: dashes, spaces and capitals are forgiven.
fn typed(line: &str) -> Option<Vec<u8>> {
    let digits: String = line.chars().filter(|c| !"- ".contains(*c)).collect();
    unhex(&digits.to_ascii_lowercase()).filter(|bytes| bytes.len() == 16)
}

/// What a line the record keeps, that cannot be read, is said to be.
fn unread(read: bool, name: &str, said: &mut dyn FnMut(&str)) {
    if !read {
        said(&format!(
            "kithd: init: the lock record's {name}: line cannot be read: it opens nothing, and the rest of the record stands"
        ));
    }
}

impl Record {
    /// The record in `bytes`, and each line of a known kind that was left out (or counts as
    /// there and opens nothing) said to `said`: a flipped byte in one seal does not cost the
    /// seals that still hold.
    fn parse_said(bytes: &[u8], said: &mut dyn FnMut(&str)) -> Option<Record> {
        let text = std::str::from_utf8(bytes.split(|byte| *byte == 0).next()?).ok()?;
        // (One an older kithd wrote has no sum, and is taken as it is.)
        if let Some(summed) = text.strip_prefix(FIRST).and_then(|text| text.strip_prefix("\nsum: ")) {
            let (sum, rest) = summed.split_once('\n')?;
            (unhex(sum)?[..] == *digest::digest(&digest::SHA256, rest.as_bytes()).as_ref()).then_some(())?;
        }
        let mut lines = text.lines();
        (lines.next()? == FIRST).then_some(())?;
        let mut record = Record::default();
        for line in lines {
            // (A seal line cut to its bare name is an unreadable one, not a damaged record.)
            let bare = |name: &'static str| line.strip_suffix(':').filter(|n| *n == name).map(|n| (n, ""));
            let (name, value) = line.split_once(": ").or_else(|| {
                [
                    "tpm-parent",
                    "tpm-pin",
                    "tpm-next",
                    "tpm-pin-next",
                    "passphrase",
                    "fido2",
                ]
                .into_iter()
                .find_map(bare)
            })?;
            match name {
                "secret" => record.secret = unhex(value)?,
                "recovery" => record.recovery = unhex(value)?,
                "key" => record.key = Some(unhex(value)?),
                "tpm" => record.tpm = Some(unhex(value)?),
                "tpm-parent" => {
                    let name = unhex(value).filter(|name| name.len() == 34);
                    unread(name.is_some(), "tpm-parent", said);
                    record.parent = Some(name.unwrap_or_default());
                }
                // (One that cannot be read opens nothing: the node asks as if it had none.)
                "passphrase" => {
                    record.pass = Pass::parse(value);
                    unread(record.pass.is_some(), "passphrase", said);
                }
                // (One that cannot be read is dropped, and said; so is a third, which no
                // kithd writes: a record's room holds two. Neither is a damaged record.)
                "fido2" => match Fido2::parse(value) {
                    // (A second line of one credential is no spare key: with_fido2 refuses it too.)
                    Some(line)
                        if record.fido2.len() < FIDO2_KEYS && record.fido2.iter().any(|have| have.id == line.id) =>
                    {
                        said(
                            "kithd: init: the lock record has two fido2: lines of one key: the second is dropped (kith node key remove NAME takes the keys off, and kith node key add NAME enrols two again)",
                        )
                    }
                    Some(line) if record.fido2.len() < FIDO2_KEYS => record.fido2.push(line),
                    Some(_) => said(&format!(
                        "kithd: init: the lock record has more than {FIDO2_KEYS} fido2: lines: the others are dropped (kith node key remove NAME takes both off, and kith node key add NAME enrols two again)"
                    )),
                    None => said(
                        "kithd: init: the lock record's fido2: line cannot be read: it is dropped, and the rest of the record stands (kith node key remove NAME takes the keys off, and kith node key add NAME enrols two again)",
                    ),
                },
                "tpm-pin" => {
                    let pin = PinSeal::parse(value);
                    unread(pin.is_some(), "tpm-pin", said);
                    record.pin = Some(pin.unwrap_or_default());
                }
                // (These count as there if they cannot be read: a next seal beside no storage
                // key's name is not opened.)
                "tpm-next" | "tpm-pin-next" => {
                    let seal = unhex(value).filter(|seal| !seal.is_empty());
                    unread(seal.is_some(), name, said);
                    let seal = Some(seal.unwrap_or_default());
                    match name {
                        "tpm-next" => record.next = seal,
                        _ => record.pin_next = seal,
                    }
                }
                "seen" => record.seen = true,
                // (One that cannot be a key is none: nothing typed is then a duress code.)
                "duress" => record.duress = unhex(value).filter(|key| key.len() == 32),
                "duress-all" => record.duress_all = unhex(value).filter(|key| key.len() == 32),
                "peers" => record.peers = value.split_whitespace().map(str::to_string).collect(),
                // (A line of a later kithd's.)
                _ => {}
            }
        }
        (record.secret.len() == 32).then_some(record)
    }

    fn text(&self) -> String {
        let mut text = format!(
            "{FIRST}\nsecret: {}\nrecovery: {}\n",
            hex(&self.secret),
            hex(&self.recovery)
        );
        if let Some(key) = &self.key {
            text += &format!("key: {}\n", hex(key));
        }
        if let Some(sealed) = &self.tpm {
            text += &format!("tpm: {}\n", hex(sealed));
        }
        if let Some(name) = &self.parent {
            text += &format!("tpm-parent: {}\n", hex(name));
        }
        if let Some(pass) = &self.pass {
            text += &format!("passphrase: {}\n", pass.text());
        }
        for line in &self.fido2 {
            text += &format!("fido2: {}\n", line.text());
        }
        if let Some(pin) = &self.pin {
            text += &format!("tpm-pin: {}\n", pin.text());
        }
        for (name, seal) in [("tpm-next", &self.next), ("tpm-pin-next", &self.pin_next)] {
            if let Some(seal) = seal {
                text += &format!("{name}: {}\n", hex(seal));
            }
        }
        if self.seen {
            text += "seen: yes\n";
        }
        for (name, key) in [("duress", &self.duress), ("duress-all", &self.duress_all)] {
            if let Some(key) = key {
                text += &format!("{name}: {}\n", hex(key));
            }
        }
        // (Last, with as many whole peers as fit the room and its ending zero: the rest are
        // left out, as a node finds its peers again.)
        let mut line = "peers:".to_string();
        for peer in &self.peers {
            if SUM_LINE + text.len() + line.len() + peer.len() + 2 >= ROOM {
                break;
            }
            line += &format!(" {peer}");
        }
        if line.len() > "peers:".len() {
            text += &line;
            text += "\n";
        }
        let rest = &text[FIRST.len() + 1..];
        let sum = digest::digest(&digest::SHA256, rest.as_bytes());
        format!("{FIRST}\nsum: {}\n{rest}", hex(sum.as_ref()))
    }

    /// The state's key as the record holds it plain (the `key:` line, until another node holds
    /// it): what an encryption in place is done under (in_place.rs).
    pub fn plain_key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    /// The record of the node whose config partition is `config`, if its state is encrypted.
    /// A record that begins as one and cannot be read is an error: the state under it is
    /// not a file system to mount as it lies.
    pub fn read(config: &Path) -> Result<Option<Record>, String> {
        let mut bytes = vec![0; 2 * ROOM];
        let read = File::open(config).and_then(|config| config.read_exact_at(&mut bytes, AT));
        let (record, copy) = bytes.split_at(ROOM);
        // (The copy, where a write was cut in the record: it was written first.)
        let said = &mut |line: &str| eprintln!("{line}");
        let parsed = Record::parse_said(record, said).or_else(|| Record::parse_said(copy, said));
        Ok(match (read, parsed) {
            (Ok(()), None) if record.starts_with(FIRST.as_bytes()) || copy.starts_with(FIRST.as_bytes()) => {
                return Err("this node's state is encrypted, and its lock record is damaged".into());
            }
            (Ok(()), None) if record.starts_with(TOMBSTONE) || copy.starts_with(TOMBSTONE) => {
                return Err(ERASED.into());
            }
            (Ok(()), record) => record,
            (Err(_), _) => None,
        })
    }

    /// Write it `at` this place of `disk` (a config partition's start and [`AT`]), over
    /// all of what was there, and read it back. One that would not fit its room but by
    /// peers left out is not written: the line it would cut is named.
    fn write(&self, disk: &File, at: u64) -> Result<(), String> {
        let order = self.order()?;
        let bytes = &order[1].1;
        let mut back = vec![0; ROOM];
        let wrote = order.iter().try_for_each(|(to, bytes)| {
            let written = disk.write_all_at(bytes, at + *to as u64);
            written.and_then(|()| disk.sync_all())
        });
        let read = wrote.and_then(|()| from_disk(disk, at).read_exact_at(&mut back, at));
        read.map_err(|e| format!("writing the lock record: {e}"))?;
        (back == *bytes)
            .then_some(())
            .ok_or("the lock record did not stay on the disk as written".into())
    }

    /// The writes that put this record on a disk, in their order: where each goes (from the
    /// record's place) and its ROOM bytes. The copy is first, so the record stays the old one,
    /// whole, until the copy holds the new; a cut after that is read as the new one (from the
    /// copy, where the record was cut).
    fn order(&self) -> Result<[(usize, Vec<u8>); 2], String> {
        let mut bytes = self.text().into_bytes();
        // (A zero ends it, so one byte less than the room.)
        if bytes.len() >= ROOM {
            let mut end = 0;
            let cut = bytes.split(|b| *b == b'\n').find(|line| {
                end += line.len() + 1;
                end >= ROOM
            });
            let cut = cut
                .and_then(|line| line.split(|b| *b == b':').next())
                .unwrap_or_default();
            return Err(format!(
                "the lock record would not fit its {ROOM} bytes: its {}: line would be cut, so it is not written",
                String::from_utf8_lossy(cut)
            ));
        }
        bytes.resize(ROOM, 0);
        Ok([(ROOM, bytes.clone()), (0, bytes)])
    }
}

#[allow(
    dead_code,
    reason = "the record's half of fido2 (T-0971): the verbs call it next (docs/adr-fido2.md section 6)"
)]
impl Record {
    /// This record with `new` (a credential id, its salt and the secret the key gave for it)
    /// as its two fido2 keys, the state's `key` wrapped under each secret. Two keys or none;
    /// none held yet (a third line is refused); and it must fit its room, which is said here
    /// and not when the write is begun. Every other line stays as it is.
    fn with_fido2(&self, key: &[u8], new: &[(&[u8], &[u8], &[u8])]) -> Result<Record, String> {
        if new.len() != FIDO2_KEYS {
            return Err(format!(
                "{FIDO2_KEYS} fido2 keys are enrolled together: not {}",
                new.len()
            ));
        }
        if !self.fido2.is_empty() {
            return Err("this node already holds fido2 keys: they are removed before others are enrolled".into());
        }
        // (Two keys that gave one secret are one way in: the second would be no spare.)
        if new[0].0 == new[1].0 || new[0].2 == new[1].2 {
            return Err("that is the same key".into());
        }
        let made = new.iter().map(|(id, salt, secret)| Fido2::new(id, salt, secret, key));
        let fido2 = made.collect::<Option<Vec<_>>>();
        let fido2 = fido2.ok_or("a credential id, a salt or a secret is not of a size a fido2 key gives")?;
        let mut with = Record { fido2, ..self.clone() };
        // (The clone holds the plaintext `key:` if the record has one: wiped when it is refused.
        // The other clones of a Record, as `ways_left` makes, are not: a Drop on Record would
        // end the `..record.clone()` updates the module is built on. ponytail: wipe all clones, if Record is split from its key.)
        if let Err(why) = with.order() {
            zeroize::Zeroize::zeroize(&mut with.key);
            return Err(why);
        }
        let kept = |record: &Record| {
            let text = record.text();
            let peers = text.lines().find_map(|line| line.strip_prefix("peers:"));
            peers.map_or(0, |peers| peers.split_whitespace().count())
        };
        if kept(&with) < self.peers.len() {
            eprintln!(
                "kithd: the lock record has room for {} of this node's {} peers once its fido2 keys are in: the rest are found again, as they are when the record is full",
                kept(&with),
                self.peers.len()
            );
        }
        Ok(with)
    }

    /// This record without its fido2 keys, both: one alone is not removed. Refused until the
    /// recovery key was shown, so the record is never left with only a lost key's way in.
    fn without_fido2(&self) -> Result<Record, String> {
        if self.fido2.is_empty() {
            return Err("this node holds no fido2 keys".into());
        }
        if !self.seen {
            return Err(
                "the recovery key was not shown yet: it is, before the keys that open the state are removed".into(),
            );
        }
        Ok(Record {
            fido2: Vec::new(),
            ..self.clone()
        })
    }

    /// Whether each of `secrets` opens one of the fido2 lines to `key`: what a record read
    /// back must do, with the secrets still in memory, before a key is said to be enrolled.
    fn fido2_proves(&self, key: &[u8], secrets: &[&[u8]]) -> bool {
        secrets.len() == FIDO2_KEYS
            && self.fido2.len() == FIDO2_KEYS
            && self
                .fido2
                .iter()
                .zip(secrets)
                .all(|(line, secret)| line.open(secret).is_some_and(|opened| opened[..] == *key))
    }

    /// What the cluster knows this disk by: says nothing of the secret it is made from.
    fn id(&self) -> String {
        hex(digest::digest(&digest::SHA256, &[b"kith-lock id", &self.secret[..]].concat()).as_ref())
    }
}

/// A device that the kernel has just made, opened: its name takes a moment to be there.
pub(crate) fn opened(device: &Path) -> std::io::Result<File> {
    for _ in 0..100 {
        match File::options().read(true).write(true).open(device) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::thread::sleep(Duration::from_millis(20)),
            opened => return opened,
        }
    }
    File::options().read(true).write(true).open(device)
}

/// Close the mapping `name` once what had it open is done: the kernel holds it for a moment
/// after, at times.
pub(crate) fn unmap(name: &str) -> std::io::Result<()> {
    let mut removed = kith_dm_sys::remove(name);
    for _ in 0..50 {
        if removed.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
        removed = kith_dm_sys::remove(name);
    }
    removed
}

/// The installer's part, once the image is on `disk`: write the state partition again,
/// through a key made here, and leave the lock record. Says the recovery key.
pub fn seal(image: &File, disk: &Path) -> Result<String, String> {
    let (at, length) = crate::install::named(image, "state")?;
    let (config, _) = crate::install::named(image, "config")?;
    let (key, secret, recovery) = draw();
    let io = |what: &'static str| move |e: std::io::Error| format!("{what}: {e}");
    let mapped = kith_dm_sys::crypt("kith-install", disk, at / 512, length / 512, &key);
    let mapped = mapped.map_err(io("opening the state partition under its key"))?;
    let copied = opened(&mapped).and_then(|through| {
        let (mut block, mut done) = (vec![0; 1 << 20], 0);
        while done < length {
            let some = block.len().min((length - done) as usize);
            image.read_exact_at(&mut block[..some], at + done)?;
            through.write_all_at(&block[..some], done)?;
            done += some as u64;
        }
        through.sync_all()
    });
    let removed = unmap("kith-install");
    copied.map_err(io("writing the state under its key"))?;
    removed.map_err(io("closing the state partition"))?;
    let disk = File::options().read(true).write(true).open(disk);
    let disk = disk.map_err(io("opening the disk again"))?;
    // The image's file system must not be readable where the image had it.
    let (mut plain, mut there) = ([0; 4096], [0; 4096]);
    let read = image.read_exact_at(&mut plain, at + 1024);
    let read = read.and_then(|()| disk.read_exact_at(&mut there, at + 1024));
    read.map_err(io("reading the state partition back"))?;
    if plain == there {
        return Err("the state partition is still readable without its key".into());
    }
    let record = sealed_record(&key, &secret, &recovery);
    record.write(&disk, config + AT)?;
    Ok(shown(&recovery))
}

/// One `kith node encrypt` (or its cancel) at a time: a second ask must see the first's record,
/// not draw a key over it, or the recovery key the first one showed opens nothing.
static ENCRYPTING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The state's key, the lock record's secret and the recovery key, drawn as the installer draws
/// them (and as `kith node encrypt` does for a node that is already installed).
fn draw() -> ([u8; 64], [u8; 32], [u8; 16]) {
    (random(), random(), random())
}

/// The lock record of a state under `key`, with its `secret` and the `recovery` key that wraps the
/// key.
fn sealed_record(key: &[u8; 64], secret: &[u8; 32], recovery: &[u8; 16]) -> Record {
    Record {
        secret: secret.to_vec(),
        recovery: wrap(recovery, key),
        key: Some(key.to_vec()),
        tpm: None,
        parent: None,
        pass: None,
        pin: None,
        next: None,
        pin_next: None,
        peers: Vec::new(),
        seen: false,
        duress: None,
        duress_all: None,
        fido2: Vec::new(),
    }
}

/// Whether a plain node's state may be encrypted in place now: not in the installer, drained,
/// with no lock record yet and no marker (or pass) already put.
fn may_encrypt(config: &Path, drained: bool, installing: bool, name: &str) -> Result<(), String> {
    if installing {
        return Err(format!(
            "{name} is in its installer: its state is encrypted by the install"
        ));
    }
    if !drained {
        return Err(format!(
            "drain {name} first: its state is encrypted with nothing running on it"
        ));
    }
    if Record::read(config)?.is_some() {
        return Err(format!("{name} is already encrypted"));
    }
    let disk = File::open(config).map_err(|e| format!("opening the config partition: {e}"))?;
    let reading = |e: std::io::Error| format!("reading the config partition: {e}");
    if crate::in_place::marked(&disk).map_err(reading)? || crate::in_place::begun(&disk).map_err(reading)? {
        return Err(format!("{name} is already marked for an encryption"));
    }
    Ok(())
}

/// Write a lock record under a new key on the config partition `config`, then put the marker that
/// the next start encrypts the state under it. A marker that cannot be put takes the record back:
/// a record over a state that is not marked would have the next start open it under a key the
/// state is not under. Says the recovery key, once.
fn begin_encrypt(config: &Path) -> Result<String, String> {
    let (key, secret, recovery) = draw();
    let disk = File::options().read(true).write(true).open(config);
    let disk = disk.map_err(|e| format!("opening the config partition: {e}"))?;
    let record = sealed_record(&key, &secret, &recovery);
    let put = record
        .write(&disk, AT)
        .and_then(|()| crate::in_place::mark(&disk).map_err(|e| format!("putting the marker down: {e}")));
    if let Err(why) = put {
        let zero = [0; 2 * ROOM];
        let taken = disk.write_all_at(&zero, AT).and_then(|()| disk.sync_all());
        taken.map_err(|e| format!("{why}, and the lock record could not be taken back: {e}"))?;
        return Err(why);
    }
    Ok(shown(&recovery))
}

/// Take an unstarted marker away, and the lock record written with it: the record first, so a
/// cut leaves a marker with no record, which the next start takes for nothing.
fn cancel_encrypt(config: &Path) -> Result<(), String> {
    let disk = File::options().read(true).write(true).open(config);
    let disk = disk.map_err(|e| format!("opening the config partition: {e}"))?;
    let io = |e: std::io::Error| format!("reading the config partition: {e}");
    if crate::in_place::begun(&disk).map_err(io)? {
        return Err("the encryption has begun: it is not cancelled".into());
    }
    if !crate::in_place::marked(&disk).map_err(io)? {
        return Err("no encryption is marked here".into());
    }
    let zero = [0; 2 * ROOM];
    let taken = disk.write_all_at(&zero, AT).and_then(|()| disk.sync_all());
    taken.map_err(|e| format!("taking the lock record back: {e}"))?;
    crate::in_place::unmark(&disk).map_err(|e| format!("taking the marker away: {e}"))
}

/// The body of `POST /v1/lock/NAME/encrypt`: `cancel` takes an unstarted marker away instead.
#[derive(serde::Deserialize)]
pub struct Encrypt {
    #[serde(default)]
    cancel: bool,
}

/// `POST /v1/lock/NAME/encrypt` (`kith node encrypt NAME`): NAME, a drained node that is not
/// installing, makes its state's key as the installer does, writes its lock record, marks its
/// state for an encryption in place and says its recovery key once. The next start encrypts the
/// state (in_place.rs), so NAME restarts after this answer is sent. Another node asks NAME, as
/// itself, having checked the caller.
pub async fn encrypt(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Named(name): Named<String>,
    Json(asked): Json<Encrypt>,
) -> Response {
    let kind = |_: &_| vec![("NodeKey".to_string(), None)];
    if let Err(refused) = crate::api::permit(&shared, &caller, kith_api::kinds::Verb::Apply, kind) {
        return crate::cluster::no_store(refused.into_response());
    }
    let done: Result<Value, String> = async {
        let cluster = shared.cluster.as_ref();
        let cluster = cluster.ok_or("this node is in no cluster: its state is its own to encrypt")?;
        if name != cluster.me.name {
            return at_node(&shared, &caller, &name, "encrypt", json!({ "cancel": asked.cancel })).await;
        }
        let config = crate::init::labelled("config").ok_or("no partition is labelled config")?;
        let _one = ENCRYPTING.lock().unwrap_or_else(|e| e.into_inner());
        if asked.cancel {
            cancel_encrypt(&config)?;
            return Ok(json!({ "node": name, "cancelled": true }));
        }
        let drained = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            let node = state.store.get(&format!("Node/{name}"));
            node.is_some_and(|node| crate::sched::has_record(&node.spec, kith_sched::DRAIN))
        };
        let line = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let installing = crate::init::options(&line).0.install.is_some();
        may_encrypt(&config, drained, installing, &name)?;
        let recovery = begin_encrypt(&config)?;
        // (The restart comes after this answer: the next start is what encrypts the state.)
        let stop = shared.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            stop.stop.send_replace(true);
        });
        Ok(json!({ "node": name, "recovery": recovery }))
    }
    .await;
    let said = done.as_ref().map(drop).map_err(String::clone);
    shared
        .audit
        .record(&caller, "encrypt", vec![format!("NodeKey/{name}")], said);
    // (The key is this answer's alone: no cache keeps it, and the web UI shows it once.)
    crate::cluster::no_store(match done {
        Ok(answer) => Json(answer).into_response(),
        Err(why) => refuse(StatusCode::CONFLICT, why).into_response(),
    })
}

fn client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // (Whoever answers: see the module's last paragraph.)
    let client = reqwest::Client::builder()
        .tls_danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .no_proxy();
    client.build().expect("a client without settings of the machine's")
}

/// Ask the node at `peer` for the key of `record`.
async fn asked(client: &reqwest::Client, peer: &str, record: &Record) -> Result<Vec<u8>, String> {
    let ask = client.post(format!("https://{peer}/v1/unlock"));
    let reply = ask.json(&json!({ "id": record.id() })).send().await;
    let reply = reply.map_err(|e| format!("{peer} cannot be reached ({e})"))?;
    if !reply.status().is_success() {
        return Err(refusing(peer));
    }
    let said = reply.json::<Value>().await.ok();
    let wrapped = said.and_then(|said| unhex(said["wrapped"].as_str()?));
    let key = wrapped.and_then(|wrapped| unwrap(&record.secret, &wrapped));
    key.ok_or(format!("what {peer} answered is not this node's key"))
}

fn refusing(peer: &str) -> String {
    format!("{peer} does not hand this node's key out: it is locked (`kith node unlock`), wiped, or not known there")
}

/// Have the node at `peer` forget the key of the disk `id`, by a duress code's key: it
/// gives a number, and takes the number signed. Whether it did.
async fn forgotten(client: &reqwest::Client, peer: &str, id: &str, pair: &ring::signature::Ed25519KeyPair) -> bool {
    let ask = |body: Value| client.post(format!("https://{peer}/v1/forget")).json(&body).send();
    let taken = async {
        let given: Value = ask(json!({ "id": id })).await.ok()?.json().await.ok()?;
        let nonce = unhex(given["nonce"].as_str()?)?;
        let signature = hex(pair.sign(&forget_text(id, &nonce)).as_ref());
        let answer = ask(json!({ "id": id, "nonce": hex(&nonce), "signature": signature })).await;
        answer.ok().filter(|answer| answer.status().is_success())
    };
    taken.await.is_some()
}

/// `disk`, with what the kernel holds in memory of the record `at` this place let go:
/// what is read next is what the disk gives back, not what was just written to it.
/// (After a sync: only then is nothing of it waiting to be written, and so nothing
/// kept. The kernel lets whole pages go: the pages the record lies in, to their ends.)
fn from_disk(disk: &File, at: u64) -> &File {
    let gone = nix::fcntl::PosixFadviseAdvice::POSIX_FADV_DONTNEED;
    let (first, end) = (at & !4095, (at + 2 * ROOM as u64 + 4095) & !4095);
    let fd = std::os::fd::AsRawFd::as_raw_fd(disk);
    let _ = nix::fcntl::posix_fadvise(fd, first as i64, (end - first) as i64, gone);
    disk
}

/// The lock record of the config partition `config`, erased, and its copy: the disk's
/// secret and every wrapped key with it. Read back from the disk: one that took the write
/// and kept the record is not erased.
fn erase(config: &Path) -> std::io::Result<()> {
    let disk = File::options().read(true).write(true).open(config)?;
    let mut back = [1; 2 * ROOM];
    // (A tombstone in both places, no secret in it: `Record::read` says it was erased.)
    let mut tomb = [0; 2 * ROOM];
    tomb[..TOMBSTONE.len()].copy_from_slice(TOMBSTONE);
    tomb[ROOM..ROOM + TOMBSTONE.len()].copy_from_slice(TOMBSTONE);
    disk.write_all_at(&tomb, AT)?;
    disk.sync_all()?;
    from_disk(&disk, AT).read_exact_at(&mut back, AT)?;
    match back == tomb {
        true => Ok(()),
        false => Err(std::io::Error::other("the lock record is still on the disk")),
    }
}

/// How long after a line is read from the console it is answered, whatever it was: a
/// wrong key and a duress code are answered with the same words at the same time.
const ANSWER: Duration = Duration::from_secs(2);
/// What is said of every line that opens nothing.
const WRONG: &str = "kithd: init: that does not open this node's state";

/// What a line typed at the waiting console is.
enum Typed {
    /// (The key is wiped when this is dropped, as it is when the line did not stand.)
    Opens(zeroize::Zeroizing<Vec<u8>>, By),
    Duress(ring::signature::Ed25519KeyPair),
    Wrong,
    /// Not tried: what is said instead of [`WRONG`] (the TPM refuses every PIN for now).
    Refused(String),
}

/// What opens the key by a PIN typed (its digits): [`by_pin`].
type Pin = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

/// The PIN's way in, once this system's k1 opened: k2 from `tpm` under the PIN typed, then
/// the key unwrapped from W under both. While the TPM refuses every PIN, the refusal says
/// within how long the next is taken.
fn by_pin<T: std::io::Read + std::io::Write + Send + 'static>(
    tpm: crate::tpm::Tpm<T>,
    seal: &PinSeal,
    k1: zeroize::Zeroizing<[u8; 32]>,
    parent: Option<Vec<u8>>,
) -> Pin {
    let (tpm, k2, wrapped) = (std::sync::Mutex::new(tpm), seal.k2.clone(), seal.wrapped.clone());
    Arc::new(move |pin| {
        let mut tpm = tpm
            .lock()
            .map_err(|_| "the TPM was left by a thread that failed".to_string())?;
        match tpm.unseal_pin(&k2, pin, parent.as_deref()) {
            Ok(k2) => {
                let k2 = zeroize::Zeroizing::new(k2);
                let both = zeroize::Zeroizing::new([&k1[..], &k2[..]].concat());
                unwrap(&both, &wrapped).ok_or("the TPM gave the PIN's half, and the key is not under it".into())
            }
            Err(why) if why == crate::tpm::LOCKED_OUT => Err(match tpm.lockout() {
                Ok(lockout) => format!("{why}: the next is taken within {} seconds", lockout.interval),
                Err(_) => why,
            }),
            Err(why) => Err(why),
        }
    })
}

/// Whether a PIN is asked at all, by `seal`: only once the TPM gave k1, so the system that
/// runs is the one it was sealed to (no PIN typed into another is counted, or heard). Else
/// why not, as said at the console. k1 is the same for every system: `seal`'s opens it for
/// the system the PIN was set on, `next` (`tpm-pin-next:`, if there is one) for the next.
fn pin_way<T: std::io::Read + std::io::Write + Send + 'static>(
    seal: &PinSeal,
    next: Option<&[u8]>,
    parent: Option<&[u8]>,
    tpm: impl FnOnce() -> Result<crate::tpm::Tpm<T>, String>,
) -> Result<Pin, String> {
    if *seal == PinSeal::default() {
        return Err("the lock record's tpm-pin: line cannot be read: no PIN is asked".into());
    }
    if parent.is_none_or(|name| name.len() != 34) {
        return Err(
            "the lock record's tpm-pin: line has no tpm-parent: line it can be checked by: no PIN is asked".into(),
        );
    }
    let mut tpm = tpm().map_err(|why| format!("no PIN is asked: {why}"))?;
    // (An unreadable `tpm-pin-next:` is empty: not tried. The refusal said is the first's.)
    let k1 = tpm.unseal(&seal.k1, parent).or_else(|why| {
        let next = next.filter(|next| !next.is_empty());
        next.map_or(Err(why.clone()), |next| tpm.unseal(next, parent).map_err(|_| why))
    });
    let k1 = k1.map_err(|why| format!("this system is not the one the PIN's seal names, so no PIN is asked: {why}"))?;
    let (k1, mut held) = (zeroize::Zeroizing::new(k1), zeroize::Zeroizing::new([0; 32]));
    if k1.len() != held.len() {
        return Err("the PIN's seal gave a key of another length: no PIN is asked".into());
    }
    held.copy_from_slice(&k1);
    Ok(by_pin(tpm, seal, held, parent.map(<[u8]>::to_vec)))
}

/// (Off the thread that asks the cluster: a passphrase costs its tries, a PIN the TPM's.)
fn judged(record: &Record, line: &str, pin: Option<&Pin>) -> Typed {
    let code = typed(line);
    if let Some(key) = code.as_ref().and_then(|recovery| unwrap(recovery, &record.recovery)) {
        return Typed::Opens(zeroize::Zeroizing::new(key), By::Recovery);
    }
    if let Some(pair) = code.map(|code| duress_key(&code)) {
        use ring::signature::KeyPair;
        let public = pair.public_key().as_ref();
        let made = [&record.duress, &record.duress_all].into_iter().flatten();
        if made.into_iter().any(|key| key == public) {
            return Typed::Duress(pair);
        }
    }
    // (Only what can be a passphrase is tried.)
    let pass = record.pass.as_ref().filter(|_| chosen(line));
    if let Some(key) = pass.and_then(|pass| pass.open(line)) {
        return Typed::Opens(zeroize::Zeroizing::new(key), By::Owner);
    }
    // (And a PIN last: a wrong one is counted. One the TPM refuses is said so, as the
    // right one is refused then too.)
    match pin.filter(|_| pin_shaped(line)).map(|pin| pin(line.as_bytes())) {
        Some(Ok(key)) => Typed::Opens(zeroize::Zeroizing::new(key), By::Pin),
        Some(Err(why)) if why.starts_with(crate::tpm::LOCKED_OUT) => Typed::Refused(why),
        Some(Err(why)) if why != crate::tpm::NOT_THE_PIN => {
            // (Not the PIN's fault: the TPM failed. Said where the machine logs, not as
            // an answer: the console answers it as every line that opens nothing.)
            eprintln!("kithd: init: a PIN could not be tried: {why}");
            Typed::Wrong
        }
        _ => Typed::Wrong,
    }
}

/// The security keys at the waiting console (docs/adr-fido2.md section 6): the `fido2:`
/// lines of the record, and `plugged`, which hands out each key plugged in once.
struct Touch {
    lines: Vec<Fido2>,
    /// The keys plugged in that were not tried yet, by name; asked with the names of those to
    /// be tried again.
    plugged: Finder,
    /// Called each time keys are found: somebody is there (see [`touched`]).
    present: Box<dyn Fn() + Send>,
    /// The keys that timed out, by name, and when: tried again after [`RETRY_GAP`].
    retry: Vec<(String, std::time::Instant)>,
}

/// A security key plugged in.
type SecurityKey = Box<dyn crate::fido2::frame::Device + Send>;
/// A security key with the name it was found under.
type FoundKey = (String, SecurityKey);
type Finder = Box<dyn FnMut(&[String]) -> Vec<FoundKey> + Send>;

/// How long after a key timed out (or did not answer) it is tried again: no sooner, so a key
/// that is stuck is not asked, and said of, every second.
const RETRY_GAP: Duration = Duration::from_secs(5);

/// A [`Touch`] for the node's record: none without `fido2:` lines, so a node that has no
/// key never looks for one; the keys are those on this machine's hidraw devices.
fn touch_of(record: &Record) -> Option<Arc<std::sync::Mutex<Touch>>> {
    let mut tried = std::collections::HashSet::new();
    let plugged = Box::new(move |again: &[String]| {
        // (A key to be tried again is one that is not tried: it is handed out again.)
        tried.retain(|name| !again.contains(name));
        let keys = crate::fido2::hidraw::plugged_in(Path::new("/sys/class/hidraw"), Path::new("/dev"), &mut tried);
        keys.into_iter()
            .map(|(name, key)| (name, Box::new(key) as SecurityKey))
            .collect()
    });
    let present = Box::new(|| TYPED.notify_one());
    let lines = record.fido2.clone();
    (!lines.is_empty()).then(|| {
        Arc::new(std::sync::Mutex::new(Touch {
            lines,
            plugged,
            present,
            retry: Vec::new(),
        }))
    })
}

/// A security key that reads and writes until `stop` is set (the console is done with it).
struct Stopping<'a>(
    &'a mut (dyn crate::fido2::frame::Device + Send),
    &'a std::sync::atomic::AtomicBool,
);

impl crate::fido2::frame::Device for Stopping<'_> {
    fn write(&mut self, report: &[u8; crate::fido2::frame::REPORT]) -> std::io::Result<()> {
        if self.1.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(std::io::Error::other("the console is done with the key"));
        }
        self.0.write(report)
    }

    fn read(&mut self) -> std::io::Result<Vec<u8>> {
        if self.1.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(std::io::Error::other("the console is done with the key"));
        }
        self.0.read()
    }
}

/// Said of a key that could not be used (where the machine logs, not as an answer: no secret
/// is in `why`), and whether it is worth trying again: a touch not given in time or a key
/// that said nothing is, a key that wants its PIN is not (and nothing but the PIN helps).
fn unusable(name: &str, why: &str, stop: &std::sync::atomic::AtomicBool) -> bool {
    use crate::fido2::frame;
    if stop.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    if why.contains(frame::PIN_REQUIRED) {
        eprintln!(
            "kithd: init: the security key {name} needs its PIN: kith asks for none at the console; use another way in"
        );
        return false;
    }
    let again = why.contains(frame::USER_ACTION_TIMEOUT) || why.contains("timed out");
    let then = if again {
        "it is tried again"
    } else {
        "unplug it and plug it in to try again"
    };
    eprintln!("kithd: init: the security key {name} could not be used: {why}: {then}");
    again
}

/// Each key plugged in that was not tried yet, asked for its secret under each line (a
/// touch, if the key holds the line's credential: one that does not says so at once), and
/// the state's key from the first line it opens. None where no key is there (or `stop`);
/// a key that opens nothing is [`Typed::Wrong`], as is a line that opens nothing. A key
/// that timed out is asked again after [`RETRY_GAP`], and each time keys are found the
/// wait of a system on trial starts over (a key plugged in and never touched, for good,
/// holds that off: somebody is there, or something is stuck).
/// (Off the thread that asks the cluster: a key waits for a touch.)
fn touched(touch: &mut Touch, stop: &std::sync::atomic::AtomicBool) -> Option<Typed> {
    use crate::fido2::{flow, frame};
    let (due, waiting) = std::mem::take(&mut touch.retry)
        .into_iter()
        .partition::<Vec<_>, _>(|(_, at)| at.elapsed() >= RETRY_GAP);
    touch.retry = waiting;
    let again: Vec<String> = due.into_iter().map(|(name, _)| name).collect();
    let keys = (touch.plugged)(&again);
    if keys.is_empty() {
        return None;
    }
    (touch.present)();
    eprintln!("kithd: init: a security key is plugged in: touch it, if it is this node's");
    for (name, mut key) in keys {
        let mut key = Stopping(&mut *key, stop);
        let channel = match frame::init(&mut key, random()) {
            Ok(channel) => channel,
            Err(why) => {
                if unusable(&name, &why, stop) {
                    touch.retry.push((name, std::time::Instant::now()));
                }
                continue;
            }
        };
        for line in &touch.lines {
            let Ok(salt) = <[u8; crate::fido2::hmac::SALT]>::try_from(&line.salt[..]) else {
                continue;
            };
            match flow::get_assertion(&mut key, channel.cid, flow::RP_ID, &line.id, &salt) {
                Ok(secret) => {
                    if let Some(opened) = line.open(&secret[..]) {
                        return Some(Typed::Opens(opened, By::Key));
                    }
                }
                Err(why) if why.contains(frame::NO_CREDENTIALS) => {}
                Err(why) => {
                    if unusable(&name, &why, stop) {
                        touch.retry.push((name, std::time::Instant::now()));
                    }
                    break;
                }
            }
        }
    }
    // (A key let go of, mid-attempt, is no wrong answer: nobody is left to hear it.)
    (!stop.load(std::sync::atomic::Ordering::Relaxed)).then_some(Typed::Wrong)
}

/// Sets the flag it holds when dropped: [`touched`] stops at its key's next report.
struct StopKeys(Arc<std::sync::atomic::AtomicBool>);

impl Drop for StopKeys {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A duress code that was typed: its key, for the cluster to be told with.
type Duressed = tokio::sync::watch::Sender<Option<Arc<ring::signature::Ed25519KeyPair>>>;

/// The waiting console: each of `lines` judged as it is read, until one opens the state.
/// A line that opens nothing is answered ([`ANSWER`] after it was read, by `say`) in the
/// same words whatever it was, and the next is judged meanwhile: a duress code does not
/// wait behind the answer to a wrong key. For a duress code the record is `erase`d
/// first (whether it is: tried again for as long as it is not) and `forget` is given its
/// key; nothing typed opens from then on. A PIN is tried by `pin`, if this node has one;
/// what was typed is zeroed once judged. A security key plugged in is tried by `touch`
/// (beside the lines, after what was typed in the same pass: a key that waits for its
/// touch holds no line), and one that opens nothing is answered as a wrong line is,
/// [`ANSWER`] after it was found. After a duress code no key is looked for.
async fn console(
    mut record: Record,
    lines: std::sync::mpsc::Receiver<String>,
    say: impl Fn(&str),
    erase: impl Fn() -> bool,
    forget: &Duressed,
    mut pin: Option<Pin>,
    mut touch: Option<Arc<std::sync::Mutex<Touch>>>,
) -> (Vec<u8>, By) {
    let (mut answers, mut erased) = (std::collections::VecDeque::new(), true);
    // The key being tried (off this thread), when it began, and when the keys are looked for next.
    let mut trying: Option<(tokio::time::Instant, tokio::task::JoinHandle<Option<Typed>>)> = None;
    let mut looked = tokio::time::Instant::now();
    // (Set when this returns, or is dropped because the cluster gave the key first: a key
    // being tried is let go of at its next report, not at its touch timeout.)
    let stop = StopKeys(Arc::new(std::sync::atomic::AtomicBool::new(false)));
    loop {
        while let Ok(line) = lines.try_recv() {
            let line = zeroize::Zeroizing::new(line);
            if line.is_empty() {
                continue;
            }
            // (Somebody is there: the wait of a system on trial starts over.)
            TYPED.notify_one();
            let due = tokio::time::Instant::now() + ANSWER;
            let (judge, by) = (record.clone(), pin.clone());
            let judged = tokio::task::spawn_blocking(move || judged(&judge, &line, by.as_ref())).await;
            let gone = forget.borrow().is_some();
            let answer = match judged.unwrap_or(Typed::Wrong) {
                Typed::Opens(mut key, by) if !gone => return (std::mem::take(&mut *key), by),
                Typed::Duress(pair) if !gone => {
                    erased = erase();
                    // (And from memory: what was typed before no longer opens either.)
                    (record.recovery, record.pass, pin) = (Vec::new(), None, None);
                    // (And no security key opens it either: its lines go, and none is looked for.)
                    (record.fido2, touch) = (Vec::new(), None);
                    forget.send_replace(Some(Arc::new(pair)));
                    WRONG.to_string()
                }
                Typed::Refused(why) if !gone => format!("kithd: init: {why}"),
                _ => WRONG.to_string(),
            };
            answers.push_back((due, answer));
        }
        // A key, after the lines: tried off this thread (it waits for a touch, and a line typed
        // meanwhile is judged all the same), looked at when it is done, looked for each second.
        if let Some((started, handle)) = trying.take_if(|(_, handle)| handle.is_finished()) {
            let gone = forget.borrow().is_some();
            let found = handle.await.unwrap_or_else(|why| {
                // (A thread that failed: said, and the keys are looked for again.)
                eprintln!("kithd: init: a security key could not be tried: {why}");
                None
            });
            match found {
                Some(Typed::Opens(mut key, by)) if !gone => return (std::mem::take(&mut *key), by),
                Some(_) => answers.push_back((started + ANSWER, WRONG.to_string())),
                None => {}
            }
        }
        let now = tokio::time::Instant::now();
        match &touch {
            Some(shared) if trying.is_none() && now >= looked => {
                let (shared, stop) = (Arc::clone(shared), Arc::clone(&stop.0));
                let attempt = tokio::task::spawn_blocking(move || {
                    // (A thread that failed while it held this left nothing half-done in it.)
                    let mut touch = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    touched(&mut touch, &stop)
                });
                (trying, looked) = (Some((now, attempt)), now + Duration::from_secs(1));
            }
            _ => {}
        }
        erased = erased || erase();
        let next = tokio::time::Instant::now() + Duration::from_millis(100);
        match answers.front() {
            Some(&(due, _)) if due <= next => {
                tokio::time::sleep_until(due).await;
                if let Some((_, answer)) = answers.pop_front() {
                    say(&answer);
                }
            }
            _ => tokio::time::sleep_until(next).await,
        }
    }
}

/// Whether the machine's consoles show what is typed at them.
fn echo(shown: bool) {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
    let active = std::fs::read_to_string("/sys/class/tty/console/active").unwrap_or_default();
    for name in active.split_whitespace() {
        let Ok(console) = File::open(format!("/dev/{name}")) else {
            continue;
        };
        if let Ok(mut how) = tcgetattr(&console) {
            how.local_flags.set(LocalFlags::ECHO, shown);
            let _ = tcsetattr(&console, SetArg::TCSANOW, &how);
        }
    }
}

/// The key, from the cluster or from whoever types the recovery key or the node's
/// passphrase, or its PIN (where `pin` tries one): asked until one gives it. And which did.
async fn fetched(record: &Record, config: &Path, join: Option<&String>, pin: Option<Pin>) -> (Vec<u8>, By) {
    let (client, lines, id) = (client(), crate::install::keyboard(), record.id());
    let (pass, hidden) = (record.pass.as_ref(), record.pass.is_some() || pin.is_some());
    let asks = match (pass.is_some(), pin.is_some()) {
        (true, true) => "its PIN, its passphrase, or the recovery key, here: none is shown",
        (false, true) => "its PIN, or the recovery key, here: neither is shown",
        (true, false) => "its passphrase, or the recovery key, here: neither is shown",
        (false, false) => "the recovery key here",
    };
    let (forget, mut forgetting) = tokio::sync::watch::channel(None);
    // (Said nowhere: a duress code looks like a wrong key, whatever became of it. A disk
    // that did not take it is written again, ten times a second, while this node waits.)
    let erased = || erase(config).is_ok();
    // (Read all the while: a peer that does not answer takes its time to say so.)
    let console = console(
        record.clone(),
        lines,
        |said| eprintln!("{said}"),
        erased,
        &forget,
        pin,
        touch_of(record),
    );
    let cluster = async {
        let (mut said, mut told) = (String::new(), false);
        loop {
            let mut why = "it knows of no node to ask".to_string();
            for peer in record.peers.iter().chain(join) {
                // (After a duress code the cluster forgets before it is asked again: then
                // it hands nothing out, and this node looks like one that is locked.)
                let duress = forgetting.borrow_and_update().clone();
                if let Some(pair) = duress.as_ref().filter(|_| !told) {
                    told = forgotten(&client, peer, &id, pair).await;
                }
                match asked(&client, peer, record).await {
                    // (Looked at only now: a code typed while the key was on its way.)
                    Ok(key) if forgetting.borrow().is_none() => return key,
                    // (Not taken: the record is erased, and this state opens no more. And
                    // the cluster has the key still, or again: it is told again.)
                    Ok(_) => (why, told) = (refusing(peer), false),
                    Err(e) => why = e,
                }
            }
            if why != said {
                eprintln!("kithd: init: still locked: {why}");
                said = why;
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(5)) => {}
                _ = forgetting.changed() => {}
            }
        }
    };
    eprintln!("kithd: init: this node's state is encrypted: asking the cluster for its key. (Or type {asks}.)");
    if !record.fido2.is_empty() {
        eprintln!("kithd: init: (Or plug in a security key of this node's, and touch it when it blinks.)");
    }
    // (A passphrase or a PIN is not for whoever looks at the screen.)
    if hidden {
        echo(false);
    }
    let fetched = tokio::select! {
        key = cluster => (key, By::Cluster),
        (key, by) = console => {
            let with = match by {
                By::Recovery => "the recovery key",
                By::Pin => "its PIN",
                By::Key => "its security key",
                _ => "its passphrase",
            };
            eprintln!("kithd: init: opened with {with}");
            (key, by)
        }
    };
    if hidden {
        echo(true);
    }
    fetched
}

/// The seals the TPM tries to open `record`'s state by alone, in order: `tpm:`, then
/// `tpm-next:` (one that cannot be read is none). None where its key is still on the disk,
/// nor where a PIN guards it (a record with both lines, as the first PIN-setting kithd
/// could leave, never opens without the PIN).
fn seals(record: &Record) -> Vec<&Vec<u8>> {
    let next = record.next.as_ref().filter(|seal| !seal.is_empty());
    let alone = record.key.is_none() && record.pin.is_none();
    [record.tpm.as_ref(), next]
        .into_iter()
        .flatten()
        .filter(|_| alone)
        .collect()
}

/// What a `tpm-next:` seal beside no `tpm-parent:` line is: not opened, as no storage key's
/// name says which key answered.
const NAMELESS: &str = "the lock record has a tpm-next: seal and no tpm-parent: line to check the TPM's storage key by, so its TPM seals are not opened (kith node seal NAME --off, then kith node seal NAME, makes a new one)";

/// The key the TPM gives from `seals(record)`, and whether it was `tpm-next:` that opened.
/// The refusal said is `tpm:`'s, the seal of the system that runs now.
fn unsealed<T: std::io::Read + std::io::Write>(
    tpm: &mut crate::tpm::Tpm<T>,
    record: &Record,
) -> Result<(Vec<u8>, bool), String> {
    match &record.parent {
        Some(name) if name.len() != 34 => return Err(UNREAD.to_string()),
        None if record.next.is_some() || record.pin_next.is_some() => return Err(NAMELESS.to_string()),
        None => eprintln!(
            "kithd: init: this machine's TPM seal is of the old form (no tpm-parent: line): which storage key answers is not checked; once open, it is sealed again with its name"
        ),
        Some(_) => {}
    }
    let mut refused = None;
    for (at, sealed) in seals(record).into_iter().enumerate() {
        match tpm.unseal(sealed, record.parent.as_deref()) {
            Ok(key) => return Ok((key, at > 0 || record.tpm.is_none())),
            Err(why) => refused = refused.or(Some(why)),
        }
    }
    Err(refused.unwrap_or_default())
}

/// Whether this kernel's slot is one still counting its tries on the ESP: an update that
/// has not come up yet (os.rs). No slot, or an ESP that cannot be read: not.
async fn on_trial() -> bool {
    let Some(slot) = running_slot() else {
        return false;
    };
    let said = tokio::task::spawn_blocking(move || crate::os::esp(|esp| crate::os::trial(slot, esp)));
    said.await.is_ok_and(|said| said.unwrap_or(false))
}

/// The slot this kernel booted from, from the kernel command line.
fn running_slot() -> Option<char> {
    let line = std::fs::read_to_string("/proc/cmdline").ok()?;
    init::options(&line).0.slot
}

/// Check 3 of docs/adr-unlock.md: the running system is release-signed by a key this node
/// takes, and the TPM's PCR 4 and 9 are the ones its boot predicts (the log replayed with
/// the running files as they are).
fn system_vouched(keys: &crate::update::Keys) -> Result<(), String> {
    let slot = running_slot().ok_or("the kernel command line names no slot")?;
    let running = crate::os::esp(|esp| crate::os::running_image(esp, slot))??;
    let log = measurements()?;
    let mut tpm = crate::tpm::open()?;
    let (read4, read9) = (tpm.read(4)?, tpm.read(9)?);
    // (predict_pcrs refuses unless the running image is in the log once in PCR 4 and once in PCR 9.)
    crate::predict::predict_pcrs(&log, &read4, &read9, &running, &running)?;
    let events = crate::predict::parse_log(&log)?;
    vouched(&events, &[(4, read4), (9, read9)], || {
        keys.signed_system(slot, &running)
    })
}

/// [`system_vouched`]'s decision on values: the log explains PCRs 4 and 9 as read, and `signed`
/// (the release header, and the piece of it that runs) vouches for the system.
fn vouched(
    events: &[crate::predict::Event],
    read: &[(u32, [u8; 32])],
    signed: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    crate::predict::explains(events, read)?;
    signed()
}

/// Open and mount the state of a node that has `record`. Returns once it is mounted,
/// however long the key takes to come: the key, and who gave it.
pub async fn open(record: &Record, config: &Path, join: Option<&String>) -> Result<(Vec<u8>, By), String> {
    let device = init::labelled("state").ok_or("this node's state is encrypted, and no partition is labelled state")?;
    let name = device.file_name().unwrap_or_default().to_string_lossy();
    let sectors = std::fs::read_to_string(format!("/sys/class/block/{name}/size"));
    let sectors = sectors.ok().and_then(|size| size.trim().parse::<u64>().ok());
    let sectors = sectors.ok_or(format!("{}: how long is it?", device.display()))?;
    // (The TPM is asked first: it answers at once, and where no node is in reach.)
    let own = || crate::tpm::open().and_then(|mut tpm| unsealed(&mut tpm, record));
    let (key, by) = match (&record.key, (!seals(record).is_empty()).then(own)) {
        (Some(key), _) => {
            eprintln!(
                "kithd: init: the key of this node's encrypted state is still on its disk: no other node holds it yet"
            );
            (key.clone(), By::Owner)
        }
        (None, Some(Ok((key, next)))) => {
            let ahead = if next {
                " (the seal made ahead for this system, tpm-next:)"
            } else {
                ""
            };
            eprintln!("kithd: init: this machine's TPM gave the key of its state{ahead}: no node was asked");
            (key, By::Tpm)
        }
        (None, refused) => {
            if let Some(Err(why)) = refused {
                eprintln!("kithd: init: {why}");
            }
            let pin = record.pin.as_ref().and_then(|seal| {
                let next = record.pin_next.as_deref();
                match pin_way(seal, next, record.parent.as_deref(), crate::tpm::open) {
                    Ok(pin) => Some(pin),
                    Err(why) => {
                        eprintln!("kithd: init: {why}");
                        None
                    }
                }
            });
            // (A system on trial that holds a TPM seal and could not open by it: its measured
            // start is not the one that seal was made for. It does not wait for a key for
            // good: five minutes with nobody typing, and it restarts, the boot loader counting
            // the try, until it goes back to the system that was sealed for.)
            let holds = record.tpm.is_some() || record.next.is_some() || record.pin.is_some();
            let trial = holds && on_trial().await;
            let waiting = fetched(record, config, join, pin);
            if trial {
                match given_up(waiting, TRIAL_WAIT, &TYPED).await {
                    Some(fetched) => fetched,
                    None => {
                        eprintln!(
                            "kithd: init: this system is on trial, its TPM seal did not open, and no key came in {} minutes: restarting",
                            TRIAL_WAIT.as_secs() / 60
                        );
                        init::end(true)
                    }
                }
            } else {
                waiting.await
            }
        }
    };
    let mapped = kith_dm_sys::crypt("kith-state", &device, 0, sectors, &key);
    let mapped = mapped.map_err(|e| format!("opening {} under its key: {e}", device.display()))?;
    drop(opened(&mapped));
    init::mount_state(&mapped);
    Ok((key, by))
}

/// `record` with a new recovery key for the state `opened` is the key of, and the key as
/// it is shown. The old one stops opening: one line of the record holds one. Whoever
/// asked is shown it: seen.
fn renewed(record: &Record, opened: &[u8]) -> (Record, String) {
    let recovery: [u8; 16] = random();
    let with = Record {
        recovery: wrap(&recovery, opened),
        seen: true,
        ..record.clone()
    };
    (with, shown(&recovery))
}

/// The ways in `record` the cluster's word leaves: the TPM's seal while it says `seal`; a
/// passphrase, a PIN and the fido2 keys until the node is locked or forgotten (`shut`). The storage key's
/// name stays while either seal it checks may: a PIN's seal is checked by it as well. The
/// seals made ahead for the next system go as the ones they stand for do.
fn ways_left(record: &Record, seal: bool, shut: bool) -> Record {
    let pin = record.pin.clone().filter(|_| !shut);
    Record {
        // (Beside a PIN, a plain seal would open the state with no PIN typed.)
        tpm: record.tpm.clone().filter(|_| seal && pin.is_none()),
        next: record.next.clone().filter(|_| seal && pin.is_none()),
        pin_next: record.pin_next.clone().filter(|_| pin.is_some()),
        parent: record.parent.clone().filter(|_| seal || pin.is_some()),
        pass: record.pass.clone().filter(|_| !shut),
        // (A key touched is a way in with no node asked, as a passphrase is.)
        fido2: if shut { Vec::new() } else { record.fido2.clone() },
        pin,
        ..record.clone()
    }
}

/// Whether none of `record`'s ways in is left that opens the state with no node asked: a
/// node locked while one is, restarted, would open by it.
fn opens_nothing_asked(record: &Record) -> bool {
    record.tpm.is_none()
        && record.next.is_none()
        && record.pass.is_none()
        && record.pin.is_none()
        && record.fido2.is_empty()
}

/// `left` (written) is now the record in memory, its peers (which are kept apart) aside: a
/// field not copied would stay, and a later write would put it back on the disk.
fn adopt(record: &mut Record, left: Record) {
    *record = Record {
        peers: std::mem::take(&mut record.peers),
        ..left
    };
}

/// What a `tpm-parent:` line that cannot be read is: present, so the seal beside it is not
/// opened without the check it stands for.
const UNREAD: &str = "the lock record's tpm-parent: line cannot be read, so its TPM seal is not opened (kith node seal NAME --off, then kith node seal NAME, makes a new one)";

/// NodeKey's status of a node's key: sealed when the seal fits this system (`fits`: it opened
/// this start, or was made again), else why the last try refused, when a seal is wanted; and
/// the secrets the node holds.
fn sealed_status(record: &Record, fits: bool, unsealed: Option<&(Instant, String)>, seal: bool) -> Value {
    let sealed = fits && (record.tpm.is_some() || record.pin.is_some());
    let mut status = match unsealed.filter(|_| seal && !sealed) {
        Some((_, why)) => json!({ "sealed": false, "message": why }),
        None => json!({ "sealed": sealed }),
    };
    for (name, set) in [
        ("passphrase", record.pass.is_some()),
        // (Not while a plain seal is beside it: that opens with no PIN.)
        ("pin", record.pin.is_some() && record.tpm.is_none()),
        ("recoverySeen", record.seen),
        ("duress", record.duress.is_some()),
        ("duressAll", record.duress_all.is_some()),
    ] {
        if set {
            status[name] = true.into();
        }
    }
    status
}

/// Whether a seal may be made again now (docs/adr-unlock.md): the NodeKey says `seal`, a
/// cluster handed this node's key out this start, and `system` vouches for the running
/// system. Else the check that failed, as the NodeKey's status says it.
fn again(seal: bool, handed: bool, system: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    if !seal {
        return Err("the NodeKey does not say seal (the node is locked, forgotten, or seal is off)".into());
    }
    if !handed {
        return Err(
            "no cluster handed this node's key out this start: it opened by its recovery key, passphrase or PIN".into(),
        );
    }
    system()
}

/// `opened` sealed by this machine's TPM again (under the storage key whose name `record`
/// keeps, if it keeps one), written in place of `record`'s seal in one write, read back,
/// and unsealed from what was read: the record as it now is. When that does not open,
/// `record` is written back as it was. A PIN node's seal is of k1 alone (k2 and the wrapped
/// key stay as they are: the state key is the same).
fn sealed_anew<T: std::io::Read + std::io::Write>(
    tpm: &mut crate::tpm::Tpm<T>,
    record: &Record,
    opened: &[u8],
    config: &Path,
) -> Result<Record, String> {
    if record.parent.as_ref().is_some_and(|name| name.len() != 34) {
        return Err(UNREAD.into());
    }
    let k1 = k1_of(opened);
    let data: &[u8] = if record.pin.is_some() { &k1[..] } else { opened };
    let (sealed, parent) = tpm.seal(data, record.parent.as_deref())?;
    let with = match &record.pin {
        Some(pin) => Record {
            pin: Some(PinSeal {
                k1: sealed,
                ..pin.clone()
            }),
            parent: Some(parent),
            ..record.clone()
        },
        None => Record {
            tpm: Some(sealed),
            parent: Some(parent),
            ..record.clone()
        },
    };
    tried(record, &with, config, |back| {
        let (sealed, expect): (&[u8], &[u8]) = match &back.pin {
            Some(pin) => (&pin.k1, &k1[..]),
            None => (back.tpm.as_deref().unwrap_or_default(), opened),
        };
        let key = tpm.unseal(sealed, back.parent.as_deref())?;
        (key == expect)
            .then_some(())
            .ok_or("the TPM gave another key back".into())
    })
}

/// `with` written in place of `record` in one write, read back, and `opens` asked of what
/// was read: the record as it now is. When it does not read back or open, `record` is
/// written back as it was.
fn tried(
    record: &Record,
    with: &Record,
    config: &Path,
    opens: impl FnOnce(&Record) -> Result<(), String>,
) -> Result<Record, String> {
    let disk = File::options().read(true).write(true).open(config);
    let disk = disk.map_err(|e| format!("writing the lock record: {e}"))?;
    let back = with.write(&disk, AT).and_then(|()| Record::read(config));
    // (As written but for peers that did not fit, which are left out.)
    let back = back.and_then(|back| {
        back.filter(|back| {
            *back
                == Record {
                    peers: back.peers.clone(),
                    ..with.clone()
                }
        })
        .ok_or("the lock record did not read back as written".into())
    });
    let why = match back.and_then(|back| opens(&back).map(|()| back)) {
        Ok(back) => return Ok(back),
        Err(why) => why,
    };
    match record.write(&disk, AT) {
        Ok(()) => Err(format!(
            "the new seal did not open as written ({why}): the old one stays"
        )),
        Err(e) => Err(format!(
            "the new seal did not open as written ({why}), and the old record could not be put back ({e})"
        )),
    }
}

/// Where kithd keeps the TPM's lockout authorization, once it set it: in the state, which
/// only an opened node reads.
fn lockout_kept() -> PathBuf {
    Path::new(init::STATE).join("tpm-lockout")
}

/// The state's key under this machine's TPM and `pin` (docs/adr-unlock.md, "TPM plus PIN"):
/// the TPM's lockout bounds checked and its authorization taken where it is empty (kept at
/// `kept` first); `tpm-pin:` written in place of `tpm:` (whose seal would open the state with
/// no PIN), read back and opened by the PIN. The record as it now is, and the TPM's lockout
/// settings. Where a step fails, the record is put back as it was.
fn pin_sealed<T: std::io::Read + std::io::Write>(
    tpm: &mut crate::tpm::Tpm<T>,
    record: &Record,
    opened: &[u8],
    pin: &[u8],
    config: &Path,
    kept: &Path,
) -> Result<(Record, crate::tpm::Lockout), String> {
    if record.parent.as_ref().is_some_and(|name| name.len() != 34) {
        return Err(UNREAD.into());
    }
    let keep = |auth: &[u8]| {
        use std::os::unix::fs::OpenOptionsExt;
        let file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(kept);
        let kept = file.and_then(|mut file| std::io::Write::write_all(&mut file, auth).and_then(|()| file.sync_all()));
        kept.map_err(|e| format!("keeping the TPM's lockout authorization in the state: {e}"))
    };
    let held = std::fs::read(kept).ok().map(zeroize::Zeroizing::new);
    let lockout = tpm.guard(
        pin.len(),
        held.as_deref().map(|h| &h[..]),
        record.parent.as_deref(),
        keep,
    )?;
    let k1 = k1_of(opened);
    let (k1_sealed, parent) = tpm.seal(&k1[..], record.parent.as_deref())?;
    let k2 = zeroize::Zeroizing::new(random::<32>());
    let (k2_sealed, _) = tpm.seal_pin(&k2[..], pin, Some(&parent))?;
    let both = zeroize::Zeroizing::new([&k1[..], &k2[..]].concat());
    let seal = PinSeal {
        k1: k1_sealed,
        k2: k2_sealed,
        wrapped: wrap(&both, opened),
    };
    // (One write, `tpm:` gone with it: written beside it first, a power cut between would
    // leave a node that opens by its TPM alone while it says a PIN guards it.)
    let alone = Record {
        tpm: None,
        // (Nor its next seal: it would open the state with no PIN typed as well.)
        next: None,
        pin: Some(seal),
        parent: Some(parent),
        ..record.clone()
    };
    let alone = tried(record, &alone, config, |back| {
        let seal = back.pin.clone().unwrap_or_default();
        let k1 = zeroize::Zeroizing::new(tpm.unseal(&seal.k1, back.parent.as_deref())?);
        let k2 = zeroize::Zeroizing::new(tpm.unseal_pin(&seal.k2, pin, back.parent.as_deref())?);
        let both = zeroize::Zeroizing::new([&k1[..], &k2[..]].concat());
        let key = unwrap(&both, &seal.wrapped).map(zeroize::Zeroizing::new);
        key.filter(|key| key[..] == *opened)
            .map(drop)
            .ok_or("the PIN's seal gave another key back".into())
    })?;
    Ok((alone, lockout))
}

/// What its owner asks of this node's record: a passphrase to give its state (none: to take
/// away), a PIN (the same), or a new recovery key. And what an update asks: the TPM's seal
/// made ahead for the system it has put in the other slot.
enum Change {
    Passphrase(Option<String>),
    Pin(Option<zeroize::Zeroizing<String>>),
    Recovery,
    Ahead(crate::os::Boots),
}

/// The PCR 4 and PCR 9 values the system `boots.new` will start with, as an override for
/// sealing: the log of the firmware's measurements, replayed with the two files that
/// change, once it is shown to explain the values the TPM holds now (predict.rs).
fn ahead_over<T: std::io::Read + std::io::Write>(
    tpm: &mut crate::tpm::Tpm<T>,
    log: &[u8],
    boots: &crate::os::Boots,
) -> Result<[(u8, [u8; 32]); 2], String> {
    let (read4, read9) = (tpm.read(4)?, tpm.read(9)?);
    let (four, nine) = crate::predict::predict_pcrs(log, &read4, &read9, &boots.running, &boots.new)?;
    Ok([(4, four), (9, nine)])
}

/// The firmware's event log, as the kernel gives it.
const MEASUREMENTS: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";

/// [`MEASUREMENTS`] read (securityfs mounted first, where nothing mounted it yet).
fn measurements() -> Result<Vec<u8>, String> {
    if !Path::new(MEASUREMENTS).exists() {
        use nix::mount::{MsFlags, mount};
        let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
        // (Already mounted, or no TPM: the read says.)
        let _ = mount(
            Some("securityfs"),
            "/sys/kernel/security",
            Some("securityfs"),
            flags,
            None::<&str>,
        );
    }
    std::fs::read(MEASUREMENTS).map_err(|e| format!("reading {MEASUREMENTS}: {e}"))
}

/// What `record` can have no seal made ahead beside: one that is not promoted yet, and a
/// storage key's name that is not there to check the TPM by.
const AHEAD_NOT_NOW: &str =
    "the seal made ahead for the system that runs is not promoted yet, so none is made for the next";
const AHEAD_NAMELESS: &str = "the TPM seal has no tpm-parent: line (it is of the old form), so none is made ahead";

/// `opened` sealed by this machine's TPM for the PCRs `over` gives (the system an update
/// put in the other slot will start with them), written beside the seal that stays
/// (`tpm-next:`, or `tpm-pin-next:` for the PIN's k1) in one write, read back. The seal
/// that opens this system is opened again from what was read: where it does not, or the
/// write does not read back, the record is put back as it was. The record as it now is.
fn ahead_sealed<T: std::io::Read + std::io::Write>(
    tpm: &mut crate::tpm::Tpm<T>,
    record: &Record,
    opened: &[u8],
    config: &Path,
    over: &[(u8, [u8; 32])],
) -> Result<Record, String> {
    let parent = match &record.parent {
        Some(name) if name.len() == 34 => name,
        Some(_) => return Err(UNREAD.into()),
        None => return Err(AHEAD_NAMELESS.into()),
    };
    // (The key that the PCR-bound seal holds: k1 in PIN mode.)
    let now = zeroize::Zeroizing::new(if record.pin.is_some() {
        k1_of(opened).to_vec()
    } else {
        opened.to_vec()
    });
    // A seal ahead that opens here is this system's, not promoted yet: it stays. One that does
    // not, because the TPM's PCR policy refuses it, is for a system that did not come up (the
    // node fell back to this one): the new signed update's takes its place. Any other failure
    // (a device error, a busy TPM, a seal that is not TPM-shaped) cannot tell whether the seal
    // still opens: it stays, and the seal ahead waits for the next update or wake. (`tpm:` is
    // untouched either way.)
    let waiting = if record.pin.is_some() {
        &record.pin_next
    } else {
        &record.next
    };
    if let Some(seal) = waiting.as_ref().filter(|seal| !seal.is_empty()) {
        match tpm.unseal(seal, Some(parent)).map(zeroize::Zeroizing::new) {
            Ok(key) if key[..] == now[..] => return Err(AHEAD_NOT_NOW.into()),
            Ok(_) => {}
            Err(why) if why == crate::tpm::NOT_THIS_SYSTEM => {}
            Err(why) => return Err(format!("{AHEAD_NOT_NOW} (the seal that waits was not tried: {why})")),
        }
    }
    let with = match (&record.pin, &record.tpm) {
        (Some(_), _) => {
            let (sealed, _) = tpm.seal_over(&now[..], Some(parent), over)?;
            Record {
                pin_next: Some(sealed),
                ..record.clone()
            }
        }
        (None, Some(_)) => {
            let (sealed, _) = tpm.seal_over(&now[..], Some(parent), over)?;
            Record {
                next: Some(sealed),
                ..record.clone()
            }
        }
        (None, None) => return Err("the record holds no TPM seal".into()),
    };
    tried(record, &with, config, |back| {
        let kept = match &back.pin {
            Some(pin) => &pin.k1,
            None => back.tpm.as_ref().ok_or("the lock record lost its TPM seal")?,
        };
        let gives = zeroize::Zeroizing::new(tpm.unseal(kept, Some(parent))?);
        let ahead = back.next.as_ref().or(back.pin_next.as_ref());
        (gives[..] == now[..] && ahead.is_some_and(|ahead| !ahead.is_empty()))
            .then_some(())
            .ok_or("the record did not keep the seal for this system and the one ahead".into())
    })
}

/// The seal made ahead, promoted: it opens what this system runs on now, so it takes the
/// place of the seal of the system before (one write, read back, and opened from what was
/// read). `None` where there is nothing to promote, or the seal ahead does not open here
/// (the old seal stays). A write that fails is put back as it was.
fn promoted<T: std::io::Read + std::io::Write>(
    tpm: &mut crate::tpm::Tpm<T>,
    record: &Record,
    opened: &[u8],
    config: &Path,
) -> Result<Option<Record>, String> {
    let parent = record.parent.as_deref().filter(|name| name.len() == 34);
    let Some(parent) = parent else { return Ok(None) };
    let ahead = |seal: &Option<Vec<u8>>| seal.clone().filter(|seal| !seal.is_empty());
    let (with, wanted) = match (&record.pin, ahead(&record.next), ahead(&record.pin_next)) {
        (Some(pin), _, Some(next)) => {
            let with = Record {
                pin: Some(PinSeal {
                    k1: next.clone(),
                    ..pin.clone()
                }),
                pin_next: None,
                ..record.clone()
            };
            (with, k1_of(opened).to_vec())
        }
        (None, Some(next), _) => {
            let with = Record {
                tpm: Some(next),
                next: None,
                ..record.clone()
            };
            (with, opened.to_vec())
        }
        _ => return Ok(None),
    };
    let now = with.pin.as_ref().map(|pin| &pin.k1).or(with.tpm.as_ref());
    let opens = |tpm: &mut crate::tpm::Tpm<T>, seal: Option<&Vec<u8>>| {
        let given = seal
            .ok_or("no seal".to_string())
            .and_then(|seal| tpm.unseal(seal, Some(parent)));
        given.map(zeroize::Zeroizing::new)
    };
    // (Not this system's seal: the old one stays. Asked before anything is written.)
    if opens(tpm, now).is_ok_and(|key| key[..] == wanted[..]) {
        let kept = tried(record, &with, config, |back| {
            let seal = back.pin.as_ref().map(|pin| &pin.k1).or(back.tpm.as_ref());
            let key = opens(tpm, seal)?;
            (key[..] == wanted[..] && back.next.is_none() && back.pin_next.is_none())
                .then_some(())
                .ok_or("the promoted seal did not open the state's key".into())
        });
        return kept.map(Some);
    }
    Ok(None)
}

/// How many times promoting one seal made ahead is tried, a failure (the TPM would not
/// open, the write did not read back) being tried again at a later wake of [`keep`].
const PROMOTE_TRIES: u8 = 3;

/// How many of those tries `seal` has used up, given what [`promotion_tried`] last said.
fn promotions_used(tried: &Option<(Vec<u8>, u8)>, seal: &[u8]) -> u8 {
    tried
        .as_ref()
        .filter(|(was, _)| was == seal)
        .map_or(0, |(_, used)| *used)
}

/// What is known of the tries after one more at `seal`: all used up when it ended (done or
/// refused, `ended`), one more when it failed.
fn promotion_tried(tried: &Option<(Vec<u8>, u8)>, seal: &[u8], ended: bool) -> (Vec<u8>, u8) {
    let used = if ended {
        PROMOTE_TRIES
    } else {
        promotions_used(tried, seal) + 1
    };
    (seal.to_vec(), used)
}

/// How long a system on trial waits for the key of its state (see `open`) with nobody typing:
/// its seal was made ahead and did not open, so what it would run and measure is not what was
/// predicted, and the boot loader is better off counting the try and going back.
const TRIAL_WAIT: Duration = Duration::from_secs(300);

/// Told when a line is typed at the console (the wait for the key starts over).
static TYPED: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// What `waiting` gives, or `None` once `limit` has passed since the start, or since a line
/// was last typed (`typed`).
async fn given_up<F: std::future::Future>(
    waiting: F,
    limit: Duration,
    typed: &tokio::sync::Notify,
) -> Option<F::Output> {
    tokio::pin!(waiting);
    loop {
        tokio::select! {
            out = &mut waiting => return Some(out),
            () = typed.notified() => {}
            () = tokio::time::sleep(limit) => return None,
        }
    }
}

/// Have [`keep`] seal this node's key ahead for the system an update put in the other slot
/// (docs/adr-unlock.md). `Ok(None)` where the node holds no TPM seal: nothing to make ahead.
pub async fn ahead(boots: crate::os::Boots) -> Result<Option<String>, String> {
    changed("this node", Change::Ahead(boots)).await
}

/// A change, and where to say how it went (a new recovery key: the key, as shown): from
/// [`pass`] and [`recovery`] to [`keep`], which alone writes the record.
type Chosen = (Change, tokio::sync::oneshot::Sender<Result<Option<String>, String>>);
static CHOSEN: std::sync::OnceLock<tokio::sync::mpsc::Sender<Chosen>> = std::sync::OnceLock::new();

/// How long a seal that [`again`] refused waits before it is tried again.
const UNSEALED_RETRY: Duration = Duration::from_secs(300);

/// For as long as the node runs: have the cluster hold the key and take it off the disk
/// once another node does; restart when the cluster locks this node, and end when it
/// wipes it. `opened`: the key the state was opened with, and who gave it at this start
/// (the cluster: so it was not locked). A NodeKey that is gone, or was written over with
/// what is not this key, is given again: without it the next start has no key.
///
/// And the TPM's seal: made while the cluster's NodeKey says `seal` and the node is not
/// locked, and only when a cluster handed the key out this start and the running system is
/// signed and predicted ([`again`]); a refused one is tried again every [`UNSEALED_RETRY`].
/// Dropped as soon as the NodeKey says otherwise; the NodeKey's status says which, and why not.
///
/// And the passphrase: its line is written when one is given ([`pass`]), and dropped when
/// one is taken away or the cluster locks this node.
pub async fn keep(
    shared: Arc<Shared>,
    config: PathBuf,
    mut record: Record,
    (opened, by): (Vec<u8>, By),
    keys: crate::update::Keys,
    mut stopping: tokio::sync::watch::Receiver<bool>,
) {
    let Some(cluster) = &shared.cluster else {
        return;
    };
    let (me, id, client) = (format!("NodeKey/{}", cluster.me.name), record.id(), client());
    let mut generation = shared.generation.subscribe();
    let write = |record: &Record| {
        let disk = File::options().read(true).write(true).open(&config);
        let wrote = disk.map_err(|e| e.to_string()).and_then(|disk| record.write(&disk, AT));
        wrote.inspect_err(|e| eprintln!("kithd: {e}")).is_ok()
    };
    // (Locked before this start: then it was opened with the recovery key, by its owner,
    // and stays open.)
    let mut was_locked = (!matches!(by, By::Owner | By::Recovery | By::Key)).then_some(false);
    // Whether the record's seal is one this system opens, and why none could be made.
    let (mut fits, mut unsealed) = (matches!(by, By::Tpm | By::Pin), None::<(Instant, String)>);
    let (chosen, mut chosen_here) = tokio::sync::mpsc::channel::<Chosen>(1);
    let _ = CHOSEN.set(chosen);
    let mut shut = false;
    // The seal made ahead that was tried to be promoted last (once each: one that does not
    // open here is not asked of the TPM again every half minute).
    let mut promote_tried = None::<(Vec<u8>, u8)>;
    // (Typed at the console: somebody has this disk's recovery key.)
    if by == By::Recovery && !record.seen {
        let with = Record {
            seen: true,
            ..record.clone()
        };
        if write(&with) {
            record = with;
        }
    }
    loop {
        let (mine, peers) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let this = |key: &&kith_api::Resource| {
                let wrapped = key.spec["wrapped"].as_str().and_then(unhex);
                let key_held = wrapped.and_then(|wrapped| unwrap(&record.secret, &wrapped));
                key.spec["id"] == id.as_str() && (gone(key) || key_held.as_ref() == Some(&opened))
            };
            let mine = state.store.get(&me).filter(this);
            let address = |node: &kith_api::Resource| {
                let there = node.status.as_ref()?["address"].as_str()?;
                (node.metadata.name != cluster.me.name).then(|| there.to_string())
            };
            let peers: Vec<String> = state.store.list(Some("Node")).filter_map(address).collect();
            (mine.map(|key| (key.spec.clone(), key.status.clone())), peers)
        };
        let (mine, said) = mine.unzip();
        // (A node whose own policy takes no wipe from the cluster: its record is kept, and
        // the cluster's duress codes are not made its own. A wipe is then as the cluster
        // forgetting its key: it runs on, and opens next with its recovery key alone.)
        let wipes = crate::policy::get().allows("wipe");
        match (&mine, record.key.clone()) {
            (Some(spec), _) if spec["wiped"] == true && wipes => {
                eprintln!(
                    "kithd: the cluster has wiped this node: its lock record is erased and its state can no longer be opened"
                );
                if let Err(e) = erase(&config) {
                    eprintln!("kithd: erasing the lock record: {e}");
                }
                init::POWER_OFF.store(true, std::sync::atomic::Ordering::Relaxed);
                shared.stop.send_replace(true);
                return;
            }
            (Some(spec), key) => {
                let locked = spec["locked"] == true;
                // (Forgotten, by the cluster's duress code: this node runs on, and what
                // opens it with no node asked goes as it does when it is locked. Its
                // recovery key is then what opens it, until `kith node unlock`.)
                let forgotten = spec["forgotten"] == true || spec["wiped"] == true;
                if spec["wiped"] == true && !shut {
                    eprintln!(
                        "kithd: the cluster has wiped this node, and this node's policy takes no wipe from the cluster (wipe is off): its lock record is kept, it runs on, and opens next with its recovery key alone"
                    );
                } else if forgotten && !shut {
                    eprintln!(
                        "kithd: the cluster has forgotten the key of this node's state (its duress code was typed): this node runs on, and opens next with its recovery key alone"
                    );
                }
                let seal = spec["seal"] == true && !locked && !forgotten;
                shut = locked || forgotten;
                // (What opens the state with no node asked goes when the cluster says so.)
                // (And the duress codes the cluster made: known here with no node in reach.)
                let public = |field: &str| spec[field].as_str().and_then(unhex).filter(|key| key.len() == 32);
                let left = Record {
                    duress: if wipes { public("duress") } else { record.duress.clone() },
                    duress_all: if wipes {
                        public("duressAll")
                    } else {
                        record.duress_all.clone()
                    },
                    ..ways_left(&record, seal, shut)
                };
                if left != record && write(&left) {
                    if left.tpm != record.tpm {
                        eprintln!("kithd: this machine's TPM no longer holds the key of its state");
                    }
                    if left.pass != record.pass {
                        eprintln!(
                            "kithd: the cluster no longer hands this node's key out: its passphrase no longer opens its state"
                        );
                    }
                    if left.pin != record.pin {
                        eprintln!(
                            "kithd: the cluster no longer hands this node's key out: its PIN no longer opens its state"
                        );
                    }
                    if left.fido2 != record.fido2 {
                        eprintln!(
                            "kithd: the cluster no longer hands this node's key out: its fido2 keys no longer open its state"
                        );
                    }
                    adopt(&mut record, left);
                }
                // (A seal that could not be dropped is tried again: restarted beside it,
                // the node would open by its TPM, locked or not. And so a passphrase.)
                if locked && was_locked == Some(false) && opens_nothing_asked(&record) {
                    // (This node's store may be behind, just after an unlock: a peer that
                    // still hands the key out says it is not locked, or not yet.)
                    let mut stale = false;
                    for peer in &peers {
                        stale = stale || asked(&client, peer, &record).await.is_ok();
                    }
                    if !stale {
                        eprintln!("kithd: the cluster has locked this node: restarting, to wait until it is unlocked");
                        shared.stop.send_replace(true);
                        return;
                    }
                } else {
                    was_locked = Some(locked);
                }
                if let Some(key) = key {
                    for peer in &peers {
                        if asked(&client, peer, &record).await.as_ref() == Ok(&key) {
                            let held = Record {
                                key: None,
                                peers: peers.clone(),
                                ..record.clone()
                            };
                            if write(&held) {
                                eprintln!(
                                    "kithd: {peer} holds the key of this node's state: it is no longer on this node's disk"
                                );
                                record = held;
                            }
                            break;
                        }
                    }
                } else if record.peers != peers && !peers.is_empty() {
                    record.peers = peers.clone();
                    write(&record);
                }
                // (The system runs and is good: the seal made ahead for it, if it opens here,
                // takes the old seal's place. Tried once for each seal ahead.)
                let ahead = record
                    .next
                    .clone()
                    .or(record.pin_next.clone())
                    .filter(|seal| !seal.is_empty());
                if let Some(seal) = ahead.filter(|seal| {
                    crate::os::GOOD.load(std::sync::atomic::Ordering::Relaxed)
                        && promotions_used(&promote_tried, seal) < PROMOTE_TRIES
                }) {
                    let (now, key, at) = (record.clone(), opened.clone(), config.clone());
                    let made = tokio::task::spawn_blocking(move || {
                        let mut tpm = crate::tpm::open()?;
                        promoted(&mut tpm, &now, &key, &at)
                    });
                    let made = made.await.unwrap_or_else(|_| Err("promoting failed".into()));
                    // (A failure is tried again at a later wake; done, or refused, is not.)
                    promote_tried = Some(promotion_tried(&promote_tried, &seal, made.is_ok()));
                    match made {
                        Ok(Some(with)) => {
                            eprintln!(
                                "kithd: this machine's TPM seal for this system is the one made ahead: the old seal is dropped"
                            );
                            (record, fits) = (with, true);
                        }
                        Ok(None) => {}
                        Err(why) => eprintln!("kithd: the seal made ahead is not promoted: {why}"),
                    }
                }
                // (Once the key is off the disk: beside it, a seal keeps nothing. A seal that
                // does not fit this system, or has no storage key's name, is made again: a
                // plain seal, or a PIN node's k1 alone. Refused ones wait [`UNSEALED_RETRY`].)
                let due = seal
                    && record.key.is_none()
                    && !(fits && record.parent.is_some() && (record.tpm.is_some() || record.pin.is_some()));
                let retry = unsealed.as_ref().is_none_or(|(at, _)| at.elapsed() >= UNSEALED_RETRY);
                if due && retry {
                    // (A cluster handed the key out this start: it opened by one, or a peer
                    // answers with it. Only then is the system checked, off the runtime.)
                    let mut handed = by == By::Cluster;
                    for peer in &peers {
                        if handed {
                            break;
                        }
                        handed = asked(&client, peer, &record).await.as_ref() == Ok(&opened);
                    }
                    let system = if handed {
                        let keys = keys.clone();
                        let checked = tokio::task::spawn_blocking(move || system_vouched(&keys));
                        checked
                            .await
                            .unwrap_or_else(|_| Err("checking the running system failed".into()))
                    } else {
                        Ok(())
                    };
                    let kept = again(seal, handed, || system).and_then(|()| {
                        let mut tpm = crate::tpm::open()?;
                        sealed_anew(&mut tpm, &record, &opened, &config)
                    });
                    match kept {
                        Ok(with) => {
                            eprintln!("kithd: this machine's TPM holds the key of its state, for this system");
                            (record, fits) = (with, true);
                            unsealed = None;
                        }
                        Err(why) => {
                            eprintln!("kithd: the key of this node's state is not sealed: {why}");
                            unsealed = Some((Instant::now(), why));
                        }
                    }
                }
                let status = sealed_status(&record, fits, unsealed.as_ref(), seal);
                if said.flatten() != Some(status.clone()) {
                    let statuses = vec![(me.clone(), Some(status))];
                    if let Err(e) = shared.submit(Command::Status { statuses }).await {
                        eprintln!("kithd: saying whether this node's key is sealed: {e}");
                    }
                }
            }
            (None, _) => {
                let resources = vec![to_hold(&cluster.me.name, &id, &record.secret, &opened)];
                let at = kith_api::store::now();
                if let Err(e) = shared.submit(Command::Apply { resources, at }).await {
                    eprintln!("kithd: giving the cluster this node's key to hold: {e}");
                }
            }
        }
        tokio::select! {
            _ = generation.changed() => {}
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = stopping.changed() => return,
            Some((change, done)) = chosen_here.recv() => match change {
                // (Whoever asked has gone already: no key is made for nobody to see.)
                Change::Recovery if done.is_closed() => {}
                Change::Recovery => {
                    let (with, recovery) = renewed(&record, &opened);
                    let wrote = write(&with);
                    let said = wrote.then_some(Some(recovery));
                    let shown = done.send(said.ok_or("the lock record could not be written".to_string())).is_ok();
                    // (Whoever asked is gone, and nobody was shown the new key: the one
                    // somebody has is put back. Where that fails, the new one stays.)
                    if wrote && (shown || !write(&record)) {
                        record = with;
                    }
                }
                Change::Passphrase(passphrase) => {
                    let pass = match passphrase {
                        None => Ok(None),
                        _ if shut => Err("the cluster does not hand this node's key out (locked, or forgotten): unlock it first".to_string()),
                        Some(passphrase) => {
                            // (Off the threads that serve: it takes its memory and its time.)
                            let key = opened.clone();
                            let made = tokio::task::spawn_blocking(move || Pass::new(&passphrase, &key, COST)).await;
                            let made = made.ok().flatten().map(Some);
                            made.ok_or("no key could be drawn from the passphrase (19 MiB of memory are needed)".to_string())
                        }
                    };
                    let with = pass.and_then(|pass| {
                        let with = Record { pass, ..record.clone() };
                        let wrote = write(&with).then_some(with);
                        wrote.ok_or("the lock record could not be written".to_string())
                    });
                    let _ = done.send(with.map(|with| {
                        record = with;
                        None
                    }));
                }
                Change::Pin(None) => {
                    // (The record's `tpm:` comes back by itself where the NodeKey says seal.)
                    let with = Record {
                        pin: None,
                        pin_next: None,
                        ..record.clone()
                    };
                    let wrote = write(&with);
                    if wrote {
                        record = with;
                    }
                    let _ = done.send(wrote.then_some(None).ok_or("the lock record could not be written".into()));
                }
                Change::Pin(Some(_)) if shut => {
                    let _ = done.send(Err("the cluster does not hand this node's key out (locked, or forgotten): unlock it first".into()));
                }
                Change::Ahead(_) if record.tpm.is_none() && record.pin.is_none() => {
                    let _ = done.send(Ok(None));
                }
                Change::Ahead(boots) => {
                    // (Off the threads that serve: the TPM takes its time.)
                    let (now, key, at) = (record.clone(), opened.clone(), config.clone());
                    let made = tokio::task::spawn_blocking(move || {
                        let log = measurements()?;
                        let mut tpm = crate::tpm::open()?;
                        let over = ahead_over(&mut tpm, &log, &boots)?;
                        ahead_sealed(&mut tpm, &now, &key, &at, &over)
                    });
                    let made = made.await.unwrap_or_else(|_| Err("sealing ahead failed".into()));
                    let _ = done.send(made.map(|with| {
                        record = with;
                        eprintln!("kithd: this machine's TPM holds the key of its state for the next system too (tpm-next:)");
                        Some("sealed ahead".to_string())
                    }));
                }
                Change::Pin(Some(pin)) => {
                    // (Off the threads that serve: the TPM takes its time.)
                    let (now, key, at) = (record.clone(), opened.clone(), config.clone());
                    let made = tokio::task::spawn_blocking(move || {
                        let mut tpm = crate::tpm::open()?;
                        pin_sealed(&mut tpm, &now, &key, pin.as_bytes(), &at, &lockout_kept())
                    });
                    let made = made.await.unwrap_or_else(|_| Err("sealing under the PIN failed".into()));
                    let _ = done.send(made.map(|(with, lockout)| {
                        record = with;
                        eprintln!("kithd: this machine's TPM and its PIN open its state; its TPM alone no longer does");
                        Some(format!(
                            "this TPM refuses every PIN after {} wrong ones, and allows one more every {} seconds",
                            lockout.max, lockout.interval
                        ))
                    }));
                }
            },
        }
    }
}

/// The node and wrapped key the store hands out for the disk of this `id`. Every NodeKey
/// of that id is asked: a second one, written beside a locked one, opens nothing.
fn handed_out<'a>(store: &'a kith_api::store::Store, id: &str) -> Option<(&'a str, &'a str)> {
    let held = || store.list(Some("NodeKey")).filter(|key| key.spec["id"] == id);
    let shut = held().any(|key| key.spec["locked"] == true || gone(key));
    let wrapped = |key: &'a kith_api::Resource| {
        let wrapped = key.spec["wrapped"].as_str().filter(|wrapped| !wrapped.is_empty())?;
        Some((key.metadata.name.as_str(), wrapped))
    };
    held().filter(|_| !shut).find_map(wrapped)
}

#[derive(serde::Deserialize)]
pub struct Asked {
    id: String,
}

/// `POST /v1/unlock {id}` → `{wrapped}`: open to whoever reaches the port, as a node that
/// asks cannot yet read its certificate. One refusal for every reason.
pub async fn unlock(State(shared): State<Arc<Shared>>, Json(asked): Json<Asked>) -> Response {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    match handed_out(&state.store, &asked.id) {
        Some((node, wrapped)) => {
            eprintln!("kithd: handed out the key of {node}'s state");
            Json(json!({ "wrapped": wrapped })).into_response()
        }
        None => refuse(StatusCode::NOT_FOUND, "no key is handed out for that").into_response(),
    }
}

/// `POST /v1/lock/NAME?do=lock|unlock|wipe|seal|unseal|duress|no-duress` (`kith node lock`,
/// `unlock`, `wipe`, `seal`, `duress`): for who may apply NodeKeys. A duress code is made
/// here and answered this once (`code`); the NodeKey keeps its public key alone.
pub async fn set(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Named(name): Named<String>,
    Query(asked): Query<BTreeMap<String, String>>,
) -> Response {
    let kind = |_: &_| vec![("NodeKey".to_string(), None)];
    if let Err(refused) = crate::api::permit(&shared, &caller, kith_api::kinds::Verb::Apply, kind) {
        return refused.into_response();
    }
    let what = asked.get("do").map(String::as_str).unwrap_or_default();
    let held = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        state.store.get(&format!("NodeKey/{name}")).cloned()
    };
    let done = async {
        let mut held = held.ok_or(format!(
            "the cluster holds no key for {name}: its state is not encrypted, or its key is still on its own disk"
        ))?;
        let wiped = held.spec["wiped"] == true;
        let mut code = None;
        match what {
            // (Forgotten: the NodeKey goes, and the node, running or opened next with its
            // recovery key, gives the cluster its key to hold as a new node does.)
            "unlock" if held.spec["forgotten"] == true => {
                let key = held.key();
                let deleted = shared.submit_as(Command::Delete { key }, Some(&caller)).await;
                let said = json!({ "node": name, "locked": false, "wiped": false, "seal": false });
                return deleted.map(|_| said).map_err(|e| e.to_string());
            }
            "wipe" => {}
            // (Taking a code away gives nobody power: a leaked one is revoked before the unlock.
            // The write below is held to `stays_forgotten` as any is.)
            "no-duress" if held.spec["forgotten"] == true && !wiped => {}
            _ if held.spec["forgotten"] == true => {
                return Err(format!(
                    "the cluster has forgotten {name}'s key (a duress code was typed): `kith node unlock {name}` has it held again"
                ));
            }
            _ if wiped => return Err(format!("{name} was wiped: its key is gone")),
            _ => {}
        }
        match what {
            "lock" => held.spec["locked"] = true.into(),
            "unlock" => drop(held.spec.as_object_mut().and_then(|spec| spec.remove("locked"))),
            "wipe" => held.spec = json!({ "id": held.spec["id"], "wiped": true }),
            "seal" => held.spec["seal"] = true.into(),
            "unseal" => drop(held.spec.as_object_mut().and_then(|spec| spec.remove("seal"))),
            "duress" => {
                let (made, public) = duress_made();
                (code, held.spec["duress"]) = (Some(made), public.into());
            }
            "no-duress" => drop(held.spec.as_object_mut().and_then(|spec| spec.remove("duress"))),
            _ => return Err("do=lock, unlock, wipe, seal, unseal, duress or no-duress".to_string()),
        }
        let mut said = json!({
            "node": name, "locked": held.spec["locked"] == true, "wiped": held.spec["wiped"] == true,
            "seal": held.spec["seal"] == true,
        });
        if let Some(code) = code {
            said["code"] = code.into();
        }
        let (resources, at) = (vec![held], kith_api::store::now());
        let applied = shared.submit_as(Command::Apply { resources, at }, Some(&caller)).await;
        stays_forgotten(&shared, &caller, &applied.map_err(|e| e.to_string())?).await?;
        Ok(said)
    }
    .await;
    let said = done.as_ref().map(drop).map_err(String::clone);
    shared
        .audit
        .record(&caller, what, vec![format!("NodeKey/{name}")], said);
    match done {
        Ok(said) => Json(said).into_response(),
        Err(why) => refuse(StatusCode::CONFLICT, why).into_response(),
    }
}

/// The NodeKeys a write put back that the cluster had forgotten, as they were before it:
/// the write was made from what the store held a moment earlier, and a duress code was
/// taken in between.
fn put_back(done: &kith_store::Done) -> Vec<kith_api::Resource> {
    let kith_store::Done::Changes(changes) = done else {
        return Vec::new();
    };
    let was = |change: &kith_api::store::Change| {
        let before = change.before.clone()?;
        (gone(&before) && !gone(&change.after)).then_some(before)
    };
    changes.iter().filter_map(was).collect()
}

/// Forgotten stays forgotten: what [`put_back`] names of a write that was `done` is
/// written as it was, and the write is said to have failed.
async fn stays_forgotten(shared: &Shared, caller: &Caller, done: &kith_store::Done) -> Result<(), String> {
    let back = put_back(done);
    if back.is_empty() {
        return Ok(());
    }
    let names: Vec<String> = back.iter().map(|key| key.metadata.name.clone()).collect();
    let (resources, at) = (back, kith_api::store::now());
    let again = shared.submit_as(Command::Apply { resources, at }, Some(caller)).await;
    let names = names.join(", ");
    Err(match again {
        Ok(_) => format!("a duress code was typed meanwhile: the cluster has forgotten the key of {names}"),
        Err(e) => format!(
            "a duress code was typed meanwhile, and the key of {names} could not be forgotten again ({e}): `kith node wipe` it"
        ),
    })
}

#[derive(serde::Deserialize)]
pub struct Given {
    passphrase: Option<String>,
}

/// Have NAME, another node, change its own lock record (`what`: its passphrase, its
/// recovery key) for whoever asked this node, and what it answered.
async fn at_node(shared: &Shared, caller: &Caller, name: &str, what: &str, body: Value) -> Result<Value, String> {
    let cluster = shared.cluster.as_ref().ok_or("this node is in no cluster")?;
    // (Asked by a node, this is the node it meant, or nobody is.)
    let there = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let there = state
            .store
            .get(&format!("Node/{name}"))
            .filter(|_| caller.node().is_none());
        there.and_then(crate::view::Upstream::of)
    };
    let there = there.ok_or(format!("{name} is not a node known here with an address"))?;
    // (Only the node named is sent it: not another of the cluster at its address.)
    let ask = cluster.to(&there)?;
    let ask = ask.post(format!("https://{}/v1/lock/{name}/{what}", there.address));
    let ask = ask.timeout(Duration::from_secs(60)).json(&body);
    // (For whoever asked this node: the node the record is of asks what they may.)
    let ask = crate::access_sign::pass_on(ask.header(crate::access::FOR, caller.to_string()));
    let unreached = |e: reqwest::Error| {
        let e = crate::cluster::why(&e);
        format!("{name} cannot be reached, and its lock record is its own to write ({e})")
    };
    let answer = ask.send().await.map_err(unreached)?;
    let fine = answer.status().is_success();
    let said: Value = answer.json().await.map_err(unreached)?;
    match said["error"].as_str() {
        _ if fine => Ok(said),
        why => Err(why.map_or(format!("{name} refused"), String::from)),
    }
}

/// Have [`keep`] make a change to this node's (`name`'s) record, and what came of it.
async fn changed(name: &str, change: Change) -> Result<Option<String>, String> {
    let here = CHOSEN.get().ok_or(format!("{name}'s state is not encrypted"))?;
    let (done, said) = tokio::sync::oneshot::channel();
    let gone = format!("{name} is stopping");
    here.send((change, done)).await.map_err(|_| gone.clone())?;
    said.await.map_err(|_| gone)?
}

/// A duress code, as shown, and the public key (hex) that is kept of it.
fn duress_made() -> (String, String) {
    use ring::signature::KeyPair;
    let code: [u8; 16] = random();
    (shown(&code), hex(duress_key(&code).public_key().as_ref()))
}

/// `POST /v1/lock/NAME/recovery` (`kith node recovery`): NAME makes itself a new recovery
/// key, which is answered this once and kept nowhere (not in the store, nor in the audit
/// log); the one it had opens its state no more. For who may apply NodeKeys. Another node
/// asks NAME, as itself, having checked the caller.
pub async fn recovery(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Named(name): Named<String>,
) -> Response {
    let kind = |_: &_| vec![("NodeKey".to_string(), None)];
    if let Err(refused) = crate::api::permit(&shared, &caller, kith_api::kinds::Verb::Apply, kind) {
        return crate::cluster::no_store(refused.into_response());
    }
    let done = async {
        let cluster = shared.cluster.as_ref();
        let cluster = cluster.ok_or("this node is in no cluster: the key of its state is its own to keep")?;
        let made = match name != cluster.me.name {
            true => at_node(&shared, &caller, &name, "recovery", json!({})).await?["recovery"]
                .as_str()
                .map(String::from),
            false => changed(&name, Change::Recovery).await?,
        };
        made.ok_or(format!("{name} answered no recovery key"))
    }
    .await;
    let said = done.as_ref().map(drop).map_err(String::clone);
    shared
        .audit
        .record(&caller, "recovery", vec![format!("NodeKey/{name}")], said);
    // (The key is this answer's alone: no cache keeps it, and the web UI shows it once.)
    crate::cluster::no_store(match done {
        Ok(recovery) => Json(json!({ "node": name, "recovery": recovery })).into_response(),
        Err(why) => refuse(StatusCode::CONFLICT, why).into_response(),
    })
}

/// The nodes of these NodeKeys whose recovery key nobody was shown. Forgotten, a node
/// opens with its recovery key alone: so each has one somebody was shown before there is
/// a code that forgets them all.
fn never_shown(keys: &[kith_api::Resource]) -> Vec<&str> {
    let unseen = |key: &&kith_api::Resource| key.status.as_ref().is_none_or(|status| status["recoverySeen"] != true);
    keys.iter()
        .filter(unseen)
        .map(|key| key.metadata.name.as_str())
        .collect()
}

/// The NodeKeys the cluster's code is written to or taken from: every one not wiped. A
/// forgotten one too, for it keeps the code (its node's record is still there to erase).
fn under_all(store: &kith_api::store::Store) -> Vec<kith_api::Resource> {
    let kept = store.list(Some("NodeKey")).filter(|key| key.spec["wiped"] != true);
    kept.cloned().collect()
}

/// Set the cluster's code `public` on these keys, or (`None`) take it from them; a
/// forgotten key stays forgotten.
fn code_all(keys: &mut [kith_api::Resource], public: Option<&String>) {
    for key in keys {
        match (public, key.spec.as_object_mut()) {
            (None, Some(spec)) => drop(spec.remove("duressAll")),
            (Some(public), _) => key.spec["duressAll"] = public.clone().into(),
            (None, None) => {}
        }
    }
}

/// `POST /v1/duress[?off]` (`kith node duress --all`): one duress code for the cluster,
/// its public key written to every NodeKey there is (`off`: taken from each). Typed at
/// any of those nodes' waiting consoles, it has the cluster forget all of their keys. For
/// who may apply NodeKeys; a node whose key the cluster comes to hold later is not under it.
pub async fn duress_all(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Query(asked): Query<BTreeMap<String, String>>,
) -> Response {
    let kind = |_: &_| vec![("NodeKey".to_string(), None)];
    if let Err(refused) = crate::api::permit(&shared, &caller, kith_api::kinds::Verb::Apply, kind) {
        return refused.into_response();
    }
    let (code, public) = duress_made();
    let off = asked.contains_key("off");
    let mut keys = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        under_all(&state.store)
    };
    let held: Vec<kith_api::Resource> = keys.iter().filter(|key| !gone(key)).cloned().collect();
    let unseen = never_shown(&held);
    if !off && !unseen.is_empty() {
        let why = format!(
            "nobody was shown the recovery key of {}: `kith node recovery NAME` shows a new one, and with the cluster's key forgotten it alone opens a node",
            unseen.join(", ")
        );
        return refuse(StatusCode::CONFLICT, why).into_response();
    }
    code_all(&mut keys, (!off).then_some(&public));
    let names: Vec<String> = keys.iter().map(|key| key.metadata.name.clone()).collect();
    let what = if off {
        "no duress code for all"
    } else {
        "duress code for all"
    };
    let done = async {
        if held.is_empty() {
            return Err("the cluster holds no node's key: no node's state is encrypted".to_string());
        }
        let applied = shared
            .submit_as(
                Command::Apply {
                    resources: keys,
                    at: kith_api::store::now(),
                },
                Some(&caller),
            )
            .await;
        stays_forgotten(&shared, &caller, &applied.map_err(|e| e.to_string())?).await
    }
    .await;
    let about = names.iter().map(|name| format!("NodeKey/{name}")).collect();
    shared.audit.record(&caller, what, about, done.clone());
    match done {
        Ok(()) if off => Json(json!({ "nodes": names })).into_response(),
        Ok(()) => Json(json!({ "nodes": names, "code": code })).into_response(),
        Err(why) => refuse(StatusCode::CONFLICT, why).into_response(),
    }
}

/// What is to be said while the cluster holds nodes' keys and nobody was shown the
/// recovery key of any of them: with every node off, nothing then opens one.
fn unseen(store: &kith_api::store::Store) -> Option<String> {
    let mut held = store.list(Some("NodeKey")).filter(|key| key.spec["wiped"] != true);
    let seen = |key: &kith_api::Resource| key.status.as_ref().is_some_and(|status| status["recoverySeen"] == true);
    let first = held.next().filter(|first| !seen(first))?;
    (!held.any(seen)).then(|| {
        format!(
            "nobody was shown the recovery key of any node whose state is encrypted: once all of them are off, nothing opens one. `kith node recovery {}` shows a new one",
            first.metadata.name
        )
    })
}

/// `GET /v1/lock` → `{warning}`: what [`unseen`] says, for who may read NodeKeys
/// (`kith get node` and the web UI show it).
pub async fn warned(State(shared): State<Arc<Shared>>, Extension(caller): Extension<Caller>) -> Response {
    let kind = |_: &_| vec![("NodeKey".to_string(), None)];
    if let Err(refused) = crate::api::permit(&shared, &caller, kith_api::kinds::Verb::List, kind) {
        return refused.into_response();
    }
    let state = shared.store.lock().expect("a handler panicked holding the store");
    Json(json!({ "warning": unseen(&state.store) })).into_response()
}

#[derive(serde::Deserialize)]
pub struct Forget {
    id: String,
    nonce: Option<String>,
    signature: Option<String>,
}

/// The numbers given to whoever asked to forget and not yet answered: when, for which
/// disk, and the number. A minute each, and [`OUTSTANDING`] at most (the oldest goes):
/// whoever reaches the port can ask.
static GIVEN: std::sync::Mutex<std::collections::VecDeque<(std::time::Instant, String, [u8; 32])>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());
const OUTSTANDING: usize = 64;
const FRESH: Duration = Duration::from_secs(60);

/// A number for a forget of the disk `id`, to be signed.
fn given(id: String) -> [u8; 32] {
    let nonce = random();
    let mut given = GIVEN.lock().expect("nothing panics holding the numbers");
    if given.len() >= OUTSTANDING {
        given.pop_front();
    }
    given.push_back((std::time::Instant::now(), id, nonce));
    nonce
}

/// Whether `nonce` was given for `id` within the last minute; it answers this once.
fn taken(id: &str, nonce: &[u8]) -> bool {
    let mut given = GIVEN.lock().expect("nothing panics holding the numbers");
    let at = given
        .iter()
        .position(|(_, of, number)| of == id && number[..] == *nonce);
    let was = at.and_then(|at| given.remove(at));
    was.is_some_and(|(when, ..)| when.elapsed() < FRESH)
}

/// The NodeKey node `name` gives the cluster to hold: the key of its disk `id`, wrapped
/// with the `secret` only that disk has.
fn to_hold(name: &str, id: &str, secret: &[u8], key: &[u8]) -> kith_api::Resource {
    let held = json!({
        "apiVersion": "kith.dev/v1", "kind": "NodeKey",
        "metadata": { "name": name }, "spec": { "id": id, "wrapped": hex(&wrap(secret, key)) },
    });
    serde_json::from_value(held).expect("a NodeKey")
}

/// The NodeKeys a forget of the disk `id` wipes, as they are to be written: the one of
/// that id whose duress key signed `nonce`, or, signed by the cluster's code, every one
/// under that code. None unless a key the cluster made signed it.
fn forgetting(store: &kith_api::store::Store, id: &str, nonce: &[u8], signature: &[u8]) -> Vec<kith_api::Resource> {
    let text = forget_text(id, nonce);
    let signed = |key: &Value| {
        let public = key.as_str().and_then(unhex);
        let public = public.map(|public| ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public));
        public.is_some_and(|public| public.verify(&text, signature).is_ok())
    };
    // (The disk the code was typed at erased its record: wiped. Another node under the
    // cluster's code has its record still, and its recovery key: forgotten. Both codes
    // stay with it: typed at it later, either still erases its record.)
    let without = |key: &kith_api::Resource| {
        let mut spec = json!({ "id": key.spec["id"] });
        match key.spec["id"] == id {
            true => spec["wiped"] = true.into(),
            false => {
                spec["forgotten"] = true.into();
                // (Both codes stay: a node that was off when the cluster's was used has
                // its record still, and typed at it later, either one erases it.)
                for code in ["duress", "duressAll"] {
                    if let Some(kept) = key.spec.get(code) {
                        spec[code] = kept.clone();
                    }
                }
            }
        }
        kith_api::Resource { spec, ..key.clone() }
    };
    // (The disk asked for is in it though forgotten: its record is what the code erases.)
    let live = || {
        let live = store.list(Some("NodeKey"));
        live.filter(|key| !gone(key) || (key.spec["id"] == id && key.spec["wiped"] != true))
    };
    // (Every NodeKey of that id is asked: one written beside it hides no code. A
    // forgotten one too, for its node's own code.)
    let kept = store.list(Some("NodeKey")).filter(|key| key.spec["wiped"] != true);
    let asking: Vec<&kith_api::Resource> = kept.filter(|key| key.spec["id"] == id).collect();
    let all = asking.iter().find(|key| signed(&key.spec["duressAll"]));
    match (all, asking.iter().find(|key| signed(&key.spec["duress"]))) {
        (Some(under), _) => live()
            .filter(|key| key.spec["duressAll"] == under.spec["duressAll"])
            .map(without)
            .collect(),
        (None, Some(one)) => vec![without(one)],
        (None, None) => Vec::new(),
    }
}

/// Whether the cluster no longer has the key this NodeKey was made for: wiped (its node's
/// record is erased with it), or forgotten (the cluster's duress code: the node has its
/// record, and its recovery key opens it).
fn gone(key: &kith_api::Resource) -> bool {
    key.spec["wiped"] == true || key.spec["forgotten"] == true
}

/// `POST /v1/forget {id}` → `{nonce}`, then `POST /v1/forget {id, nonce, signature}`: a
/// node at whose waiting console a duress code was typed has the cluster forget its key
/// (the cluster's code: every node's under it). Open to whoever reaches the port, as
/// `/v1/unlock` is; taken only for the number just given, once, signed by the key of a
/// duress code the cluster made. One refusal for every reason.
pub async fn forget(State(shared): State<Arc<Shared>>, Json(asked): Json<Forget>) -> Response {
    let refused = || refuse(StatusCode::NOT_FOUND, "no key is handed out for that").into_response();
    let hexed = |text: &Option<String>| text.as_deref().and_then(unhex);
    // (An id is a SHA-256 in hex: what is kept for whoever asks is no longer than one.)
    if asked.id.len() != 64 {
        return refused();
    }
    let (Some(nonce), Some(signature)) = (hexed(&asked.nonce), hexed(&asked.signature)) else {
        return Json(json!({ "nonce": hex(&given(asked.id)) })).into_response();
    };
    if !taken(&asked.id, &nonce) {
        return refused();
    }
    let wiped = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        forgetting(&state.store, &asked.id, &nonce, &signature)
    };
    if wiped.is_empty() {
        return refused();
    }
    let about: Vec<String> = wiped.iter().map(kith_api::Resource::key).collect();
    let (resources, at) = (wiped, kith_api::store::now());
    // (The duress code typed at this node's console is the authority here, as the console token is
    // for `claim`: the admin's. A node that is not the leader passes it on as the admin's write.)
    let admin = crate::access::Caller::Admin;
    let applied = shared.submit_as(Command::Apply { resources, at }, Some(&admin)).await;
    let applied = applied.map(drop).map_err(|e| e.to_string());
    eprintln!("kithd: a duress code was typed: forgetting {}", about.join(", "));
    shared.audit.record(&"a duress code", "forget", about, applied.clone());
    match applied {
        Ok(()) => Json(json!({})).into_response(),
        Err(_) => refused(),
    }
}

/// `POST /v1/lock/NAME/passphrase {passphrase}` (`kith node passphrase`): NAME's state
/// opens with it from then on, typed at its console, with no node in reach; with none in
/// the body, no longer. For who may apply NodeKeys. The passphrase goes to NAME alone
/// (another node asks it, as itself, having checked the caller) and is kept nowhere: not
/// in the store, nor in the audit log.
pub async fn pass(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Named(name): Named<String>,
    Json(given): Json<Given>,
) -> Response {
    let kind = |_: &_| vec![("NodeKey".to_string(), None)];
    if let Err(refused) = crate::api::permit(&shared, &caller, kith_api::kinds::Verb::Apply, kind) {
        return refused.into_response();
    }
    let passphrase = given.passphrase.map(|passphrase| passphrase.trim().to_string());
    let what = if passphrase.is_some() {
        "passphrase"
    } else {
        "no passphrase"
    };
    let done = async {
        if passphrase.as_ref().is_some_and(|passphrase| !chosen(passphrase)) {
            let why = "a passphrase has 8 characters or more (256 at most): letters, digits, spaces and signs of ASCII, which the console of a starting machine can type";
            return Err(why.to_string());
        }
        let cluster = shared.cluster.as_ref();
        let cluster = cluster.ok_or("this node is in no cluster: the key of its state is its own to keep")?;
        if name != cluster.me.name {
            let body = json!({ "passphrase": passphrase });
            return at_node(&shared, &caller, &name, "passphrase", body).await.map(drop);
        }
        changed(&name, Change::Passphrase(passphrase.clone())).await.map(drop)
    }
    .await;
    shared
        .audit
        .record(&caller, what, vec![format!("NodeKey/{name}")], done.clone());
    match done {
        Ok(()) => Json(json!({ "node": name, "passphrase": passphrase.is_some() })).into_response(),
        Err(why) => refuse(StatusCode::CONFLICT, why).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct PinGiven {
    pin: Option<String>,
    /// The owner's word that this machine's TPM is not yet known to hold to its lockout:
    /// a PIN is set nowhere without it.
    #[serde(default)]
    untried: bool,
}

/// What a PIN asked for without the owner's word is refused with.
const UNTRIED: &str = "a PIN has run against a software TPM only, never yet against this machine's: run \"On hardware: the owner's checklist\" in docs/adr-unlock.md on it, then give the PIN with --untried-tpm. Know first: where the TPM's lockout authorization is empty, kithd takes the TPM's lockout authorization and keeps it only in this node's encrypted state; if that state is lost, only clearing the TPM gives it back. And each setting of a PIN tries one wrong PIN, which the TPM counts. Make the PIN random digits: a date or 123456 is among the first guesses";

/// `POST /v1/lock/NAME/pin {pin, untried}` (`kith node pin`): NAME's state opens with its
/// TPM and the PIN from then on, typed at its console, and with its TPM alone no more; with
/// no PIN in the body, no longer. For who may apply NodeKeys, and only with `untried`: no
/// TPM of a machine has yet been shown to hold to its lockout (docs/adr-unlock.md). Asked of
/// NAME alone, over TLS: no node passes it on. The PIN is kept nowhere: not in the store,
/// nor in the audit log. The answer says the TPM's lockout.
pub async fn pin(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Named(name): Named<String>,
    Json(given): Json<PinGiven>,
) -> Response {
    let kind = |_: &_| vec![("NodeKey".to_string(), None)];
    if let Err(refused) = crate::api::permit(&shared, &caller, kith_api::kinds::Verb::Apply, kind) {
        return refused.into_response();
    }
    let pin = given.pin.map(zeroize::Zeroizing::new);
    let what = if pin.is_some() { "pin" } else { "no pin" };
    let done = async {
        if pin.is_some() && !given.untried {
            return Err(UNTRIED.to_string());
        }
        if pin.as_ref().is_some_and(|pin| !pin_shaped(pin)) {
            let why = "a PIN is 6 to 32 digits and nothing else (the row above the letters, which a starting machine's console reads as digits whatever its layout)";
            return Err(why.to_string());
        }
        let cluster = shared.cluster.as_ref();
        let cluster = cluster.ok_or("this node is in no cluster: the key of its state is its own to keep")?;
        // ponytail: never passed on, as the PIN would cross the node passing it in plain;
        // whether one may be is the owner's call (docs/adr-unlock.md "Open").
        if name != cluster.me.name {
            return Err(format!(
                "a PIN is passed on by no node: ask node {name} itself, at its own API address"
            ));
        }
        changed(&name, Change::Pin(pin.clone())).await
    }
    .await;
    shared
        .audit
        .record(&caller, what, vec![format!("NodeKey/{name}")], done.clone().map(drop));
    match done {
        Ok(lockout) => Json(json!({ "node": name, "pin": pin.is_some(), "lockout": lockout })).into_response(),
        Err(why) => refuse(StatusCode::CONFLICT, why).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::pinned_peer::{answering_as, at, node, shared_with};
    use std::sync::atomic::Ordering;

    // (Here, not above `mod tests`: what a file does is read up to its first test attribute.)
    impl Record {
        pub fn parse(bytes: &[u8]) -> Option<Record> {
            Record::parse_said(bytes, &mut |_| {})
        }
    }

    /// What the web UI shows once, a new recovery key, is kept by no cache: the answer, and a
    /// refusal of it, say `no-store`; an Identity with no right to apply NodeKeys gets a 403.
    #[tokio::test]
    async fn no_store_on_the_recovery_key_and_403_for_who_may_not() {
        let ca = crate::pki::Ca::create().unwrap();
        let (a, b, x) = (node(&ca, "a"), node(&ca, "b"), node(&ca, "x"));
        let (taken, _) = answering_as(&x).await;
        let there = at("b", &taken, Some(crate::pki::print_of(&b.cert).unwrap()));
        let shared = shared_with("recovery-no-store", a, &[there]).await;
        let ask = |caller: Caller| recovery(State(shared.clone()), Extension(caller), Named("b".into()));
        let kept = |answer: &Response| {
            answer.headers()[axum::http::header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .to_string()
        };
        let refused = ask(Caller::Identity("carol".into())).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(kept(&refused), "no-store");
        // (A node that cannot be asked: an answer of the same kind, with the same header.)
        let failed = ask(Caller::Admin).await;
        assert_eq!(failed.status(), StatusCode::CONFLICT);
        assert_eq!(kept(&failed), "no-store");
    }

    #[tokio::test]
    async fn pinned_peer_is_sent_no_passphrase() {
        let ca = crate::pki::Ca::create().unwrap();
        let (a, b, x) = (node(&ca, "a"), node(&ca, "b"), node(&ca, "x"));
        // Node/b is where another node of the cluster answers now: its address was b's.
        let (taken, to_x) = answering_as(&x).await;
        let there = at("b", &taken, Some(crate::pki::print_of(&b.cert).unwrap()));
        let shared = shared_with("passphrase", a, &[there]).await;
        let given = Json(Given {
            passphrase: Some("correct horse".into()),
        });
        let answer = pass(State(shared), Extension(Caller::Admin), Named("b".into()), given).await;
        assert_eq!(answer.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(answer.into_body(), 1 << 16).await.unwrap();
        let said = String::from_utf8_lossy(&body);
        assert!(said.contains("node b was called, and node x answered"), "{said}");
        assert_eq!(to_x.load(Ordering::SeqCst), 0, "x was sent the passphrase");
    }

    #[test]
    fn crypt_keys_open_only_under_their_secret() {
        let (key, secret): ([u8; 64], [u8; 32]) = (random(), random());
        let wrapped = wrap(&secret, &key);
        assert_eq!(unwrap(&secret, &wrapped).as_deref(), Some(&key[..]));
        // Sealed anew each time; another secret, or a changed byte, opens nothing.
        assert_ne!(wrap(&secret, &key), wrapped);
        assert_eq!(unwrap(&random::<32>(), &wrapped), None);
        let mut changed = wrapped.clone();
        changed[20] ^= 1;
        assert_eq!(unwrap(&secret, &changed), None);
        assert_eq!(unwrap(&secret, &wrapped[..11]), None);

        // The recovery key as someone types it back.
        let recovery: [u8; 16] = random();
        let said = shown(&recovery);
        assert_eq!((said.len(), said.matches('-').count()), (39, 7));
        assert_eq!(typed(&said).as_deref(), Some(&recovery[..]));
        assert_eq!(
            typed(&said.to_uppercase().replace('-', " ")).as_deref(),
            Some(&recovery[..])
        );
        assert_eq!(typed("not one"), None);
        assert_eq!(typed(&said[..34]), None);
    }

    #[test]
    fn crypt_passphrases_open_what_they_wrapped() {
        let key: [u8; 64] = random();
        // (A small cost: the test is of the wrapping, and is run unoptimised.)
        let pass = Pass::new("correct horse battery", &key, (64, 1)).unwrap();
        assert_eq!(pass.open("correct horse battery").as_deref(), Some(&key[..]));
        assert_eq!(pass.open("correct horse batterz"), None);
        assert_eq!(pass.open(""), None);
        // The line of a record says its own cost, and is read back as written.
        let read = Pass::parse(&pass.text()).unwrap();
        assert_eq!(read, pass);
        assert_eq!(read.open("correct horse battery").as_deref(), Some(&key[..]));
        // The same passphrase wraps to another line each time, and the key is not in it.
        let again = Pass::new("correct horse battery", &key, (64, 1)).unwrap();
        assert!(again.salt != pass.salt && again.wrapped != pass.wrapped);
        assert!(!pass.wrapped.windows(16).any(|window| window == &key[..16]));
        // Argon2id, version 19, one lane: what the reference implementation's own tests
        // have for "password", "somesalt", 2 passes (64 MiB, and 256 KiB).
        let reference = |memory| drawn("password", b"somesalt", (memory, 2)).map(|key| hex(&key));
        let known = "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"; // pragma: allowlist secret
        assert_eq!(reference(1 << 16).as_deref(), Some(known));
        let known = "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"; // pragma: allowlist secret
        assert_eq!(reference(256).as_deref(), Some(known));
        // A cost no machine should pay at its start, and a line that is not one: no passphrase.
        assert_eq!(Pass::parse("4294967295 2 00 00"), None);
        assert_eq!(Pass::parse("262145 2 00 00"), None);
        // What a console at start can type, and no less than eight of it.
        assert!(chosen("correct horse battery") && chosen("a1!~ {}z"));
        assert!(!chosen("short") && !chosen("") && !chosen("pässwörter") && !chosen("tab\tin the middle"));
        assert!(!chosen(&"a".repeat(257)));
        assert_eq!(Pass::parse("19456 2 zz 00"), None);
        assert_eq!(Pass::parse("19456"), None);
        let record = b"kith-lock v1\nsecret: 0707070707070707070707070707070707070707070707070707070707070707\npassphrase: later\n"; // pragma: allowlist secret
        assert_eq!(Record::parse(record).map(|record| record.pass), Some(None));
    }

    /// Against a software TPM: a seal of the old form (no tpm-parent:) is sealed again with
    /// the storage key's name, written, read back and opened; a name kept is sealed to
    /// again, another one is not, and a line that cannot be read is not.
    #[test]
    fn tpm_parent_is_kept_when_an_old_seal_is_sealed_again() {
        use crate::tpm::{ANOTHER, Tpm, tests};
        let Some((_software, wire)) = tests::software() else {
            return;
        };
        let mut tpm = Tpm(wire);
        tests::measured(&mut tpm);
        let key = vec![3; 64]; // pragma: allowlist secret
        let (old, name) = tpm.seal(&key, None).unwrap();
        let path = std::env::temp_dir().join(format!("kith-crypt-tpm-{}", std::process::id()));
        std::fs::write(&path, vec![0; AT as usize + ROOM]).unwrap();
        let record = Record {
            secret: vec![7; 32],
            tpm: Some(old),
            ..Record::default()
        };
        record
            .write(&File::options().read(true).write(true).open(&path).unwrap(), AT)
            .unwrap();
        let with = sealed_anew(&mut tpm, &record, &key, &path).unwrap();
        assert_eq!(with.parent.as_ref(), Some(&name));
        assert_ne!(with.tpm, record.tpm);
        assert_eq!(Record::read(&path), Ok(Some(with.clone())));
        let again = sealed_anew(&mut tpm, &with, &key, &path).unwrap();
        assert_eq!(again.parent, with.parent);
        let other = Record {
            parent: Some(vec![0; 34]),
            ..again.clone()
        };
        assert_eq!(sealed_anew(&mut tpm, &other, &key, &path), Err(ANOTHER.to_string()));
        let unread = Record {
            parent: Some(vec![]),
            ..again.clone()
        };
        assert_eq!(sealed_anew(&mut tpm, &unread, &key, &path), Err(UNREAD.to_string()));
        assert_eq!(Record::read(&path), Ok(Some(again.clone())));
        // A new seal that does not open as written (its answer changed on the bus): the old
        // record is put back, and the error says why.
        tpm.0.flip = Some((crate::tpm::UNSEAL, 16, 1));
        let refused = sealed_anew(&mut tpm, &again, &key, &path).unwrap_err();
        assert!(
            refused.contains(crate::tpm::FORGED) && refused.contains("the old one stays"),
            "{refused}"
        );
        assert_eq!(Record::read(&path), Ok(Some(again.clone())));
        // More peers than the room holds: sealed anew all the same, with those that fit.
        let crowded = Record {
            peers: (0..400).map(|n| format!("10.0.{n}.1:7443")).collect(),
            ..again
        };
        let kept = sealed_anew(&mut tpm, &crowded, &key, &path).unwrap();
        assert!(kept.peers.len() > 100 && kept.peers.len() < 400);
        assert_eq!(Record::read(&path), Ok(Some(kept)));
        std::fs::remove_file(&path).unwrap();
    }

    /// The checks of docs/adr-unlock.md before the TPM's: a node seals its key again only when
    /// it is asked to, a cluster handed the key out this start, and the system is signed. The
    /// reason of the first that fails is what NodeKey's status says.
    #[test]
    fn seals_again_only_when_every_check_holds() {
        assert_eq!(again(true, true, || Ok(())), Ok(()));
        assert!(again(false, true, || Ok(())).unwrap_err().contains("seal"));
        assert!(again(true, false, || Ok(())).unwrap_err().contains("cluster"));
        assert_eq!(
            again(true, true, || Err("the system is not signed".to_string())),
            Err("the system is not signed".to_string())
        );
        // (The system is not looked at when an earlier check does not hold.)
        assert!(again(false, true, || panic!("the system was looked at")).is_err());
    }

    /// A PIN node seals again only k1 (`tpm-pin:`): k2 and the wrapped key stay as they are, and
    /// the k1 read back opens under the storage key's name.
    #[test]
    fn seals_again_a_pin_node_reseals_k1_only() {
        use crate::tpm::{Tpm, tests};
        let Some((_software, wire)) = tests::software() else {
            return;
        };
        let mut tpm = Tpm(wire);
        tests::measured(&mut tpm);
        let key = vec![5; 64]; // pragma: allowlist secret
        let k1 = k1_of(&key);
        let (old_k1, _) = tpm.seal(&k1[..], None).unwrap();
        let pin = PinSeal {
            k1: old_k1.clone(),
            k2: vec![6; 32],
            wrapped: vec![8; 60],
        };
        let record = Record {
            secret: vec![7; 32],
            pin: Some(pin.clone()),
            ..Record::default()
        };
        let path = std::env::temp_dir().join(format!("kith-crypt-seals-again-pin-{}", std::process::id()));
        std::fs::write(&path, vec![0; AT as usize + ROOM]).unwrap();
        record
            .write(&File::options().read(true).write(true).open(&path).unwrap(), AT)
            .unwrap();
        let with = sealed_anew(&mut tpm, &record, &key, &path).unwrap();
        let now = with.pin.clone().unwrap();
        assert_ne!(now.k1, old_k1);
        assert_eq!((&now.k2, &now.wrapped), (&pin.k2, &pin.wrapped));
        assert!(with.parent.is_some());
        assert_eq!(&tpm.unseal(&now.k1, with.parent.as_deref()).unwrap()[..], &k1[..]);
        assert_eq!(Record::read(&path), Ok(Some(with.clone())));
        std::fs::remove_file(&path).unwrap();
    }

    /// A storage key whose name is not the one kept is ANOTHER: nothing is sealed under it, and
    /// the record stays as it was.
    #[test]
    fn seals_again_refuses_another_storage_key_name() {
        use crate::tpm::{ANOTHER, Tpm, tests};
        let Some((_software, wire)) = tests::software() else {
            return;
        };
        let mut tpm = Tpm(wire);
        tests::measured(&mut tpm);
        let key = vec![4; 64]; // pragma: allowlist secret
        let (sealed, _) = tpm.seal(&key, None).unwrap();
        let path = std::env::temp_dir().join(format!("kith-crypt-seals-again-name-{}", std::process::id()));
        std::fs::write(&path, vec![0; AT as usize + ROOM]).unwrap();
        let record = Record {
            secret: vec![7; 32],
            tpm: Some(sealed),
            parent: Some(vec![0; 34]),
            ..Record::default()
        };
        record
            .write(&File::options().read(true).write(true).open(&path).unwrap(), AT)
            .unwrap();
        assert_eq!(sealed_anew(&mut tpm, &record, &key, &path), Err(ANOTHER.to_string()));
        assert_eq!(Record::read(&path), Ok(Some(record.clone())));
        std::fs::remove_file(&path).unwrap();
    }

    /// Check 3 on values: the log must explain PCRs 4 and 9 as read (`explains`), and only then
    /// does the signed check (the header and its piece) decide. A log that does not explain them
    /// refuses before the signed check is asked; a refusal by the check is the refusal.
    #[test]
    fn seals_again_vouched_refuses_a_log_that_does_not_explain_the_pcrs() {
        use crate::predict::{Event, UNEXPLAINED, replay};
        let events = vec![Event {
            pcr: 4,
            kind: 0,
            digest: [1; 32],
        }];
        let replayed = replay(&events).unwrap();
        let read = [(4, replayed[4]), (9, replayed[9])];
        assert_eq!(vouched(&events, &read, || Ok(())), Ok(()));
        let other = [(4, [2; 32]), (9, replayed[9])];
        assert_eq!(
            vouched(&events, &other, || panic!("asked")),
            Err(UNEXPLAINED.to_string())
        );
        let refused = || Err("the image that runs is not the piece the release names for slot b".to_string());
        assert_eq!(vouched(&events, &read, refused), refused());
    }

    /// The status shows why a seal is refused, when one is wanted and does not fit (even with
    /// an old TPM record beside the key); a PIN seal that fits says sealed, and no message.
    #[test]
    fn seals_again_status_shows_the_refusal_and_is_quiet_for_a_fitting_pin_seal() {
        let refused = (Instant::now(), "the system is not signed".to_string());
        let plain = Record {
            tpm: Some(vec![1]),
            parent: Some(vec![2; 34]),
            ..Record::default()
        };
        let shown = sealed_status(&plain, false, Some(&refused), true);
        assert_eq!(shown["sealed"], false);
        assert_eq!(shown["message"], "the system is not signed");
        let pin = Record {
            pin: Some(PinSeal {
                k1: vec![1],
                k2: vec![2],
                wrapped: vec![3],
            }),
            parent: Some(vec![2; 34]),
            ..Record::default()
        };
        let quiet = sealed_status(&pin, true, None, true);
        assert_eq!(quiet["sealed"], true);
        assert!(quiet.get("message").is_none());
    }

    fn holds(bytes: &[u8], secret: &[u8]) -> bool {
        bytes.windows(secret.len()).any(|window| window == secret)
    }

    /// A lock record file with `record` in it, and the PCRs 4 and 9 a TPM that was `measured`
    /// holds after one more event each: what a sealing ahead is given for the next system.
    #[allow(clippy::type_complexity)]
    fn ahead_disk(what: &str, record: &Record) -> (PathBuf, [(u8, [u8; 32]); 2], [[u8; 32]; 2]) {
        use sha2::{Digest, Sha256};
        let path = std::env::temp_dir().join(format!("kith-crypt-next-{what}-{}", std::process::id()));
        std::fs::write(&path, vec![0; AT as usize + ROOM]).unwrap();
        record
            .write(&File::options().read(true).write(true).open(&path).unwrap(), AT)
            .unwrap();
        let (event4, event9) = ([0x44u8; 32], [0x99u8; 32]);
        let after = |pcr: u8, event: [u8; 32]| -> (u8, [u8; 32]) {
            // (`measured` extends each PCR once, with its own number repeated.)
            let was: [u8; 32] = Sha256::digest([&[0u8; 32][..], &[pcr; 32]].concat()).into();
            (pcr, Sha256::digest([&was[..], &event[..]].concat()).into())
        };
        (path, [after(4, event4), after(9, event9)], [event4, event9])
    }

    /// Against a software TPM: a key sealed ahead for the PCRs of the next system is written
    /// as `tpm-next:` beside the seal of this one, which is kept and still opens; none is
    /// made while one waits, nor where no seal, or no storage key's name, is held. Before the
    /// next system runs, promoting does nothing; once it does, `tpm:` is the seal that was
    /// made ahead and `tpm-next:` is gone, read back from the disk.
    #[test]
    fn tpm_next_seal_ahead_keeps_the_old_seal_until_promotion() {
        use crate::tpm::{Tpm, tests};
        let Some((_software, wire)) = tests::software() else {
            return;
        };
        let mut tpm = Tpm(wire);
        tests::measured(&mut tpm);
        let key = vec![5; 64]; // pragma: allowlist secret
        let (old, name) = tpm.seal(&key, None).unwrap();
        let record = Record {
            secret: vec![7; 32],
            tpm: Some(old.clone()),
            parent: Some(name),
            ..Record::default()
        };
        let (path, over, events) = ahead_disk("plain", &record);

        // No seal held, or no name to check the TPM by: none is made, and nothing is written.
        let bare = Record {
            tpm: None,
            ..record.clone()
        };
        assert!(
            ahead_sealed(&mut tpm, &bare, &key, &path, &over)
                .unwrap_err()
                .contains("no TPM seal")
        );
        let nameless = Record {
            parent: None,
            ..record.clone()
        };
        assert_eq!(
            ahead_sealed(&mut tpm, &nameless, &key, &path, &over),
            Err(AHEAD_NAMELESS.to_string())
        );
        assert_eq!(Record::read(&path), Ok(Some(record.clone())));

        let with = ahead_sealed(&mut tpm, &record, &key, &path, &over).unwrap();
        assert_eq!(with.tpm.as_ref(), Some(&old), "the old seal stays until promotion");
        assert!(with.next.as_ref().is_some_and(|next| !next.is_empty() && *next != old));
        assert_eq!(Record::read(&path), Ok(Some(with.clone())));
        // This system still opens by the seal it had, not by the one ahead.
        assert_eq!(unsealed(&mut tpm, &with), Ok((key.clone(), false)));
        // Not the next system yet: nothing is promoted, nothing is written.
        assert_eq!(promoted(&mut tpm, &with, &key, &path), Ok(None));
        assert_eq!(Record::read(&path), Ok(Some(with.clone())));
        // A fallback: this system runs again and the seal ahead (for the system that did not
        // come up) opens nothing here. The next signed update replaces it, and `tpm:` stays.
        let other = [(4, [0x11; 32]), over[1]];
        let again = ahead_sealed(&mut tpm, &with, &key, &path, &other).unwrap();
        assert_eq!(again.tpm.as_ref(), Some(&old), "the old seal stays until promotion");
        assert!(
            again
                .next
                .as_ref()
                .is_some_and(|next| !next.is_empty() && Some(next) != with.next.as_ref())
        );
        assert_eq!(Record::read(&path), Ok(Some(again.clone())));
        assert_eq!(unsealed(&mut tpm, &again), Ok((key.clone(), false)));

        // A seal waiting that the TPM could not be asked about (here one that is cut, so no
        // refusal of the PCRs' but another failure) may be this system's: it stays, none is
        // made now, and nothing is written.
        let unknown = Record {
            next: with.next.as_ref().map(|next| next[..next.len() / 2].to_vec()),
            ..again.clone()
        };
        let refused = ahead_sealed(&mut tpm, &unknown, &key, &path, &other).unwrap_err();
        assert!(
            refused.starts_with(AHEAD_NOT_NOW) && refused.contains("not tried"),
            "{refused}"
        );
        assert_eq!(Record::read(&path), Ok(Some(again.clone())));

        // The next system starts (the PCRs move to what was predicted): the seal ahead opens
        // and the old one no longer does.
        tpm.extend(4, &events[0]).unwrap();
        tpm.extend(9, &events[1]).unwrap();
        assert_eq!(unsealed(&mut tpm, &with), Ok((key.clone(), true)));
        // That seal is this system's and not promoted yet: it is not replaced.
        assert_eq!(
            ahead_sealed(&mut tpm, &with, &key, &path, &over),
            Err(AHEAD_NOT_NOW.to_string())
        );
        assert_eq!(Record::read(&path), Ok(Some(again)), "a refusal writes nothing");
        let now = promoted(&mut tpm, &with, &key, &path).unwrap().unwrap();
        assert_eq!((now.tpm.as_ref(), now.next.as_ref()), (with.next.as_ref(), None));
        assert_eq!(Record::read(&path), Ok(Some(now.clone())));
        assert_eq!(unsealed(&mut tpm, &now), Ok((key.clone(), false)));
        assert_eq!(promoted(&mut tpm, &now, &key, &path), Ok(None));
        std::fs::remove_file(&path).unwrap();
    }

    /// With a PIN the seal that is made ahead is k1's (`tpm-pin-next:`): `tpm-pin:` is kept,
    /// and the next system's k1 takes its place once that system runs. No plain `tpm-next:`
    /// is made, which would open the state with no PIN.
    #[test]
    fn tpm_next_seal_ahead_of_the_pin_seals_k1() {
        use crate::tpm::{Tpm, tests};
        let Some((_software, wire)) = tests::software() else {
            return;
        };
        let mut tpm = Tpm(wire);
        tests::measured(&mut tpm);
        tests::lockout_set(&mut tpm, 3, 40);
        let key: [u8; 64] = random();
        let (sealed, parent) = tpm.seal(&key, None).unwrap();
        let record = Record {
            secret: vec![7; 32],
            tpm: Some(sealed),
            parent: Some(parent.clone()),
            ..Record::default()
        };
        let (path, over, events) = ahead_disk("pin", &record);
        let kept = std::env::temp_dir().join(format!("kith-crypt-next-lockout-{}", std::process::id()));
        let _ = std::fs::remove_file(&kept);
        let (with, _) = pin_sealed(&mut tpm, &record, &key, b"40917253", &path, &kept).unwrap();
        let seal = with.pin.clone().unwrap();

        let ahead = ahead_sealed(&mut tpm, &with, &key, &path, &over).unwrap();
        assert_eq!(
            (ahead.pin.as_ref(), ahead.next.as_ref(), ahead.tpm.as_ref()),
            (Some(&seal), None, None)
        );
        assert!(
            ahead
                .pin_next
                .as_ref()
                .is_some_and(|next| !next.is_empty() && *next != seal.k1)
        );
        assert_eq!(Record::read(&path), Ok(Some(ahead.clone())));
        // (Not yet: nothing is promoted.)
        assert_eq!(promoted(&mut tpm, &ahead, &key, &path), Ok(None));
        tpm.extend(4, &events[0]).unwrap();
        tpm.extend(9, &events[1]).unwrap();
        // The seal of k1 for the system before opens no more, the one ahead does, and with
        // it (and the PIN) the state's key.
        assert!(tpm.unseal(&seal.k1, Some(&parent)).is_err());
        let now = promoted(&mut tpm, &ahead, &key, &path).unwrap().unwrap();
        assert_eq!(now.pin.as_ref().map(|pin| &pin.k1), ahead.pin_next.as_ref());
        assert_eq!((now.pin_next.as_ref(), now.tpm.as_ref()), (None, None));
        assert_eq!(
            now.pin.as_ref().map(|pin| (&pin.k2, &pin.wrapped)),
            Some((&seal.k2, &seal.wrapped))
        );
        assert_eq!(Record::read(&path), Ok(Some(now.clone())));
        let (k1, k2) = (
            tpm.unseal(&now.pin.as_ref().unwrap().k1, Some(&parent)).unwrap(),
            tpm.unseal_pin(&seal.k2, b"40917253", Some(&parent)).unwrap(),
        );
        let both = zeroize::Zeroizing::new([&k1[..], &k2[..]].concat());
        assert_eq!(unwrap(&both, &seal.wrapped).as_deref(), Some(&key[..]));
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_file(&kept);
    }

    /// No event log that explains the PCRs the TPM holds (here none at all): nothing is
    /// predicted, so nothing is sealed ahead.
    #[test]
    fn tpm_next_no_log_no_prediction() {
        use crate::tpm::{Tpm, tests};
        let Some((_software, wire)) = tests::software() else {
            return;
        };
        let mut tpm = Tpm(wire);
        tests::measured(&mut tpm);
        let boots = crate::os::Boots {
            running: vec![1; 64],
            new: vec![2; 64],
        };
        assert!(ahead_over(&mut tpm, &[], &boots).is_err());
    }

    /// A promotion that failed (the TPM could not be opened, a write did not read back) is
    /// tried again, a few times; one that was done, or refused, is not tried again.
    #[test]
    fn tpm_next_promotion_is_retried_after_a_failure() {
        let seal = vec![1u8, 2, 3];
        let mut tried = None;
        assert_eq!(promotions_used(&tried, &seal), 0);
        tried = Some(promotion_tried(&tried, &seal, false));
        assert_eq!(promotions_used(&tried, &seal), 1);
        assert!(
            promotions_used(&tried, &seal) < PROMOTE_TRIES,
            "one failure is not the end"
        );
        // (A seal made ahead later is a new one.)
        assert_eq!(promotions_used(&tried, &[9u8]), 0);
        tried = Some(promotion_tried(&tried, &seal, false));
        tried = Some(promotion_tried(&tried, &seal, false));
        assert!(
            promotions_used(&tried, &seal) >= PROMOTE_TRIES,
            "a fault that stays is not tried for ever"
        );
        let done = promotion_tried(&None, &seal, true);
        assert!(promotions_used(&Some(done), &seal) >= PROMOTE_TRIES);
    }

    /// A wait for the key ends after the limit, starts over with each line typed, and gives
    /// the key when it comes first.
    #[tokio::test(start_paused = true)]
    async fn tpm_next_trial_wait_is_five_minutes_and_a_typed_line_restarts_it() {
        let typed = tokio::sync::Notify::new();
        let five = Duration::from_secs(300);
        let never = || std::future::pending::<u8>();
        let start = tokio::time::Instant::now();
        assert_eq!(given_up(never(), five, &typed).await, None);
        assert_eq!(start.elapsed(), five);
        // A line at four minutes: five more from then.
        let start = tokio::time::Instant::now();
        let line = async {
            tokio::time::sleep(Duration::from_secs(240)).await;
            typed.notify_one();
        };
        let (gave, ()) = tokio::join!(given_up(never(), five, &typed), line);
        assert_eq!(gave, None);
        assert_eq!(start.elapsed(), Duration::from_secs(540));
        // The key before the limit.
        let key = async {
            tokio::time::sleep(Duration::from_secs(299)).await;
            7u8
        };
        assert_eq!(given_up(key, five, &typed).await, Some(7));
        assert_eq!(TRIAL_WAIT, five);
    }

    /// Against a software TPM (docs/adr-unlock.md, "TPM plus PIN"): a PIN too short for the
    /// TPM's lockout is refused and nothing is changed; one it bounds is sealed, `tpm-pin:`
    /// written and `tpm:` dropped, the lockout's authorization kept for kithd alone. At the
    /// console the PIN opens, a wrong one is counted by the TPM, and once it counted M the
    /// right one is refused too, saying when the next is taken; the recovery key still opens.
    /// A system other than the one sealed to is asked no PIN.
    #[test]
    fn tpm_pin_opens_the_state_and_the_tpm_counts_each_wrong_one() {
        use crate::tpm::{CLEAR_FIRST, LOCKED_OUT, Tpm, tests};
        use std::os::unix::fs::PermissionsExt;
        let Some((software, wire)) = tests::software() else {
            return;
        };
        let mut tpm = Tpm(wire);
        tests::measured(&mut tpm);
        tests::lockout_set(&mut tpm, 3, 40);
        let (key, recovery): ([u8; 64], [u8; 16]) = (random(), random());
        let (sealed, parent) = tpm.seal(&key, None).unwrap();
        let at = |what: &str| std::env::temp_dir().join(format!("kith-crypt-pin-{what}-{}", std::process::id()));
        let (path, kept, elsewhere) = (at("disk"), at("lockout"), at("elsewhere"));
        let _ = std::fs::remove_file(&kept);
        std::fs::write(&path, vec![0; AT as usize + ROOM]).unwrap();
        let record = Record {
            secret: vec![7; 32],
            recovery: wrap(&recovery, &key),
            tpm: Some(sealed),
            parent: Some(parent),
            ..Record::default()
        };
        record
            .write(&File::options().read(true).write(true).open(&path).unwrap(), AT)
            .unwrap();

        // 3 wrong ones, one forgotten every 40 seconds: 6 digits are too few.
        let refused = pin_sealed(&mut tpm, &record, &key, b"409172", &path, &kept).unwrap_err();
        assert!(
            refused.contains("the shortest PIN these settings take is 8 digits"),
            "{refused}"
        );
        assert!(!kept.exists() && !tpm.lockout().unwrap().set);
        assert_eq!(Record::read(&path), Ok(Some(record.clone())));

        let pin = "40917253";
        let (with, lockout) = pin_sealed(&mut tpm, &record, &key, pin.as_bytes(), &path, &kept).unwrap();
        assert_eq!((lockout.max, lockout.interval, lockout.set), (3, 40, true));
        assert!(with.tpm.is_none() && with.pin.is_some() && with.parent == record.parent);
        assert_eq!(Record::read(&path), Ok(Some(with.clone())));
        let file = std::fs::metadata(&kept).unwrap();
        assert_eq!((file.len(), file.permissions().mode() & 0o777), (32, 0o600));
        let disk = std::fs::read(&path).unwrap();
        assert!(!holds(&disk, pin.as_bytes()) && !holds(&disk, hex(pin.as_bytes()).as_bytes()));
        // Its lockout authorization held, and not by this node (it keeps none): refused.
        let other = pin_sealed(&mut tpm, &with, &key, pin.as_bytes(), &path, &elsewhere);
        assert_eq!(other.map(drop), Err(CLEAR_FIRST.to_string()));
        assert!(!elsewhere.exists());
        assert_eq!(Record::read(&path), Ok(Some(with.clone())));

        // At the console. (Setting it tried one wrong PIN, to see the TPM count it: 1.)
        let seal = with.pin.clone().unwrap();
        let Tpm(wire) = tpm;
        let way = pin_way(&seal, None, with.parent.as_deref(), || Ok(Tpm(wire))).unwrap();
        let opens = |line: &str| judged(&with, line, Some(&way));
        assert!(matches!(opens(pin), Typed::Opens(opened, By::Pin) if *opened == key));
        assert!(matches!(opens("40917254"), Typed::Wrong));
        // (Not a PIN's shape: not tried, not counted.)
        assert!(matches!(opens("40917"), Typed::Wrong) && matches!(opens("4091725x"), Typed::Wrong));
        assert!(matches!(opens("00000000"), Typed::Wrong));
        match opens(pin) {
            Typed::Refused(why) => assert_eq!(why, format!("{LOCKED_OUT}: the next is taken within 40 seconds")),
            _ => panic!("the right PIN opened while the TPM refused every PIN"),
        }
        assert!(matches!(opens(&shown(&recovery)), Typed::Opens(opened, By::Recovery) if *opened == key));
        drop(way);

        // Another system (a PCR moved): no PIN is asked, so none is counted.
        let mut tpm = Tpm(software.wire());
        tests::measured(&mut tpm);
        let counted = tpm.lockout().unwrap().counter;
        let Tpm(wire) = tpm;
        let refused = pin_way(&seal, None, with.parent.as_deref(), || Ok(Tpm(wire)))
            .err()
            .unwrap();
        assert!(
            refused.contains("this system is not the one the PIN's seal names"),
            "{refused}"
        );
        assert_eq!(Tpm(software.wire()).lockout().unwrap().counter, counted);
        for file in [&path, &kept] {
            std::fs::remove_file(file).unwrap();
        }
    }

    /// The PIN is answered at the console as anything else that opens nothing, never
    /// repeated; one the TPM refuses (every one is, for now) is said so, with when the next
    /// is taken; what is not a PIN's shape is not tried at all.
    #[tokio::test(start_paused = true)]
    async fn pin_kept_nowhere_at_the_console() {
        let (key, recovery): ([u8; 64], [u8; 16]) = (random(), random());
        let record = Record {
            secret: vec![7; 32],
            recovery: wrap(&recovery, &key),
            ..Record::default()
        };
        let tried = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (seen, opened) = (tried.clone(), key.to_vec());
        let pin: Pin = Arc::new(move |typed: &[u8]| {
            seen.lock().unwrap().push(String::from_utf8_lossy(typed).to_string());
            match typed {
                b"40917253" => Err(format!(
                    "{}: the next is taken within 40 seconds",
                    crate::tpm::LOCKED_OUT
                )),
                b"11111111" => Ok(opened.clone()),
                _ => Err(crate::tpm::NOT_THE_PIN.into()),
            }
        });
        let said = std::cell::RefCell::new(Vec::new());
        let say = |line: &str| said.borrow_mut().push(line.to_string());
        let (told, _) = tokio::sync::watch::channel(None);
        let (type_it, lines) = std::sync::mpsc::channel();
        for line in ["40917254", "40917253", "12345", "4091725x"] {
            type_it.send(line.to_string()).unwrap();
        }
        let waiting = console(record.clone(), lines, &say, &|| true, &told, Some(pin.clone()), None);
        assert!(tokio::time::timeout(Duration::from_secs(60), waiting).await.is_err());
        let refused = format!(
            "kithd: init: {}: the next is taken within 40 seconds",
            crate::tpm::LOCKED_OUT
        );
        assert_eq!(*said.borrow(), [WRONG, refused.as_str(), WRONG, WRONG]);
        assert_eq!(*tried.lock().unwrap(), ["40917254", "40917253"]);
        let (type_it, lines) = std::sync::mpsc::channel();
        type_it.send("11111111".to_string()).unwrap();
        let opened = console(record, lines, &say, &|| true, &told, Some(pin), None).await;
        assert_eq!(opened, (key.to_vec(), By::Pin));
        for typed in ["40917254", "40917253", "11111111"] {
            assert!(
                !said.borrow().iter().any(|line| line.contains(typed)),
                "{typed} was said"
            );
        }
    }

    /// `kith node pin`: refused unless the owner says this machine's TPM is untried, naming
    /// the checklist; refused for what is no PIN, without saying it back; for another node,
    /// refused, and passed on to no node (whether a node may pass a PIN on is the owner's
    /// call, docs/adr-unlock.md "Open"). The audit log says a PIN was asked for, never which.
    #[tokio::test]
    async fn pin_kept_nowhere_by_the_api() {
        let ca = crate::pki::Ca::create().unwrap();
        let (a, b, x) = (node(&ca, "a"), node(&ca, "b"), node(&ca, "x"));
        let (taken, to_x) = answering_as(&x).await;
        let there = at("b", &taken, Some(crate::pki::print_of(&b.cert).unwrap()));
        let shared = shared_with("pin", a, &[there]).await;
        let ask = |name: &str, pin: &str, untried: bool| {
            let given = Json(PinGiven {
                pin: Some(pin.into()),
                untried,
            });
            pin_route(shared.clone(), name.to_string(), given)
        };
        for (name, typed, untried, named) in [
            ("a", "40917253", false, "On hardware: the owner's checklist"),
            // (What the owner's word lets kithd do to the TPM, said where it is asked for.)
            ("a", "40917253", false, "kithd takes the TPM's lockout authorization"),
            ("a", "40917253", false, "only clearing the TPM gives it back"),
            ("a", "40917253", false, "each setting of a PIN tries one wrong PIN"),
            ("a", "4091725x", true, "a PIN is 6 to 32 digits"),
            ("a", "40917", true, "a PIN is 6 to 32 digits"),
            ("b", "40917262", true, "ask node b itself"),
        ] {
            let (status, said) = ask(name, typed, untried).await;
            assert_eq!(status, StatusCode::CONFLICT, "{said}");
            assert!(said.contains(named) && !said.contains(typed), "{said}");
        }
        // Taking a PIN away is asked of the node itself as well.
        let off = Json(PinGiven {
            pin: None,
            untried: false,
        });
        let (status, said) = pin_route(shared.clone(), "b".into(), off).await;
        assert!(
            status == StatusCode::CONFLICT && said.contains("ask node b itself"),
            "{said}"
        );
        assert_eq!(to_x.load(Ordering::SeqCst), 0, "x was sent the PIN");
        let audit = serde_json::to_string(&shared.audit.tail(100).unwrap()).unwrap();
        assert!(audit.contains("\"pin\"") && audit.contains("NodeKey/b"), "{audit}");
        for typed in ["40917253", "4091725x", "40917262"] {
            assert!(!audit.contains(typed), "{typed} is in the audit log");
        }
    }

    /// The cluster's word takes the TPM's seal away (not `seal`): a PIN's seal stays, and
    /// with it the storage key's name it is checked by (a VM lost it so, and was asked no
    /// PIN). Locked: the PIN goes, and the name with it.
    #[test]
    fn tpm_pin_keeps_its_storage_key_name_when_the_seal_goes() {
        let record = Record {
            tpm: Some(vec![5; 40]),
            parent: Some(vec![6; 34]),
            pin: Some(PinSeal::default()),
            ..Record::default()
        };
        let left = ways_left(&record, false, false);
        assert_eq!(
            (left.tpm, left.parent, left.pin),
            (None, record.parent.clone(), record.pin.clone())
        );
        let left = ways_left(&record, false, true);
        assert_eq!((left.tpm, left.parent, left.pin), (None, None, None));
        let left = ways_left(&record, true, true);
        assert_eq!((left.tpm, left.parent), (record.tpm.clone(), record.parent.clone()));
        // Both lines (a power cut while an earlier kithd set the PIN): `tpm:` would open the
        // state with no PIN typed, so it goes, sealed or not.
        let left = ways_left(&record, true, false);
        assert_eq!(
            (left.tpm, left.parent, left.pin),
            (None, record.parent.clone(), record.pin.clone())
        );
        // Nor does such a record open by the TPM alone at the start that finds it.
        assert!(seals(&record).is_empty());
        let alone = Record {
            pin: None,
            ..record.clone()
        };
        assert_eq!(seals(&alone), alone.tpm.iter().collect::<Vec<_>>());
    }

    async fn pin_route(shared: Arc<Shared>, name: String, given: Json<PinGiven>) -> (StatusCode, String) {
        let answer = pin(State(shared), Extension(Caller::Admin), Named(name), given).await;
        let status = answer.status();
        let body = axum::body::to_bytes(answer.into_body(), 1 << 16).await.unwrap();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// A record that would not fit its room is refused, naming the line that would be cut;
    /// only whole `peers:` entries are left out to make it fit.
    #[test]
    fn crypt_record_too_long_is_refused_not_cut() {
        let path = std::env::temp_dir().join(format!("kith-crypt-long-{}", std::process::id()));
        std::fs::write(&path, vec![0; AT as usize + ROOM]).unwrap();
        let disk = File::options().read(true).write(true).open(&path).unwrap();
        let record = Record {
            secret: vec![7; 32],
            ..Record::default()
        };
        record.write(&disk, AT).unwrap();
        let long = Record {
            tpm: Some(vec![5; 2100]),
            ..record.clone()
        };
        let refused = long.write(&disk, AT).unwrap_err();
        assert!(refused.contains("tpm:"), "{refused}");
        assert_eq!(Record::read(&path), Ok(Some(record.clone())));
        let many = Record {
            peers: (0..400).map(|n| format!("10.0.{n}.1:7443")).collect(),
            ..record
        };
        many.write(&disk, AT).unwrap();
        let read = Record::read(&path).unwrap().unwrap();
        assert!(read.peers.len() > 100 && read.peers.len() < 400);
        assert_eq!(read.peers[..], many.peers[..read.peers.len()]);
        std::fs::remove_file(&path).unwrap();
    }

    /// A power cut in the record's write leaves the old record or the new one, whichever
    /// 512-byte sectors of either copy it cut after; a record an older kithd wrote (one copy,
    /// no sum) is read as before (T-0596).
    #[test]
    fn lock_record_cut_at_any_sector_reads_as_old_or_new() {
        let path = std::env::temp_dir().join(format!("kith-crypt-torn-{}", std::process::id()));
        let old = Record {
            secret: vec![7; 32],
            recovery: vec![1; 16],
            peers: (0..150).map(|n| format!("10.0.{n}.1:7443")).collect(),
            ..Record::default()
        };
        let new = Record {
            secret: vec![8; 32],
            key: Some(vec![9; 64]),
            ..old.clone()
        };
        let fresh = |with: &Record| {
            std::fs::write(&path, vec![0; AT as usize + 3 * ROOM]).unwrap();
            let disk = File::options().read(true).write(true).open(&path).unwrap();
            with.write(&disk, AT).unwrap();
            disk
        };
        let wrote = {
            let disk = fresh(&new);
            let mut whole = vec![0; 2 * ROOM];
            disk.read_exact_at(&mut whole, AT).unwrap();
            whole
        };
        // The new record goes over the old, cut after each sector of the copy and then of
        // the record (the copy is written first): only the sectors before the cut are new,
        // in any order the disk took them.
        for copy_first in [true, false] {
            for sectors in 0..ROOM / 512 {
                for from_end in [false, true] {
                    let disk = fresh(&old);
                    let (whole, part) = if copy_first { (None, ROOM) } else { (Some(ROOM), 0) };
                    if let Some(copy) = whole {
                        disk.write_all_at(&wrote[copy..copy + ROOM], AT + copy as u64).unwrap();
                    }
                    let range = if from_end {
                        ROOM - 512 * sectors..ROOM
                    } else {
                        0..512 * sectors
                    };
                    let at = part + range.start;
                    disk.write_all_at(&wrote[at..part + range.end], AT + at as u64).unwrap();
                    let read = Record::read(&path).unwrap().unwrap();
                    assert!(read == old || read == new, "cut at {copy_first} {sectors} {from_end}");
                }
            }
        }
        // As an older kithd wrote it: the text alone, in one copy.
        let disk = fresh(&old);
        disk.write_all_at(&vec![0; 2 * ROOM], AT).unwrap();
        let text = old.text();
        let unsummed: String = text
            .lines()
            .filter(|line| !line.starts_with("sum: "))
            .map(|line| format!("{line}\n"))
            .collect();
        disk.write_all_at(unsummed.as_bytes(), AT).unwrap();
        assert_eq!(Record::read(&path), Ok(Some(old.clone())));
        // Both copies damaged: said, not taken as no record.
        disk.write_all_at(b"kith-lock v1\nsum: 00\nsecret: 07", AT).unwrap();
        disk.write_all_at(b"kith-lock v1\nsum: 00\nsecret: 07", AT + ROOM as u64)
            .unwrap();
        assert!(Record::read(&path).unwrap_err().contains("damaged"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn crypt_records_are_read_as_written() {
        let record = Record {
            secret: vec![7; 32],
            recovery: vec![1, 2, 3],
            key: Some(vec![9; 64]),
            tpm: Some(vec![5; 300]),
            parent: Some(vec![6; 34]),
            pass: Some(Pass {
                cost: COST,
                salt: vec![3; 16],
                wrapped: vec![4; 92],
            }),
            seen: true,
            duress: Some(vec![6; 32]),
            duress_all: Some(vec![8; 32]),
            fido2: Vec::new(),
            pin: Some(PinSeal {
                k1: vec![1; 200],
                k2: vec![2; 200],
                wrapped: vec![3; 104],
            }),
            next: Some(vec![4; 20]),
            pin_next: Some(vec![5; 20]),
            peers: vec!["10.0.0.1:7443".into(), "[fd00::2]:7443".into()],
        };
        // A tpm-pin: that cannot be read counts as there, and asks no PIN; the rest is read.
        let unread = b"kith-lock v1\nsecret: 0707070707070707070707070707070707070707070707070707070707070707\ntpm-pin: 00 zz\nduress: 0606\n"; // pragma: allowlist secret
        let unread = Record::parse(unread).unwrap();
        assert_eq!(unread.pin, Some(PinSeal::default()));
        assert!(pin_way::<File>(&PinSeal::default(), None, Some(&[0; 34]), || unreachable!()).is_err());
        // A record from before these lines has none of them; a duress line that cannot be
        // a key is none.
        let old =
            b"kith-lock v1\nsecret: 0707070707070707070707070707070707070707070707070707070707070707\nduress: 0606\n"; // pragma: allowlist secret
        let old = Record::parse(old).unwrap();
        assert_eq!(
            (old.seen, old.duress, old.duress_all, old.parent),
            (false, None, None, None)
        );
        // A tpm-parent: that cannot be read is left out, but counts as there.
        let unread = b"kith-lock v1\nsecret: 0707070707070707070707070707070707070707070707070707070707070707\ntpm: 00\ntpm-parent: 000b06\n"; // pragma: allowlist secret
        assert_eq!(Record::parse(unread).map(|record| record.parent), Some(Some(vec![])));
        let path = std::env::temp_dir().join(format!("kith-crypt-record-{}", std::process::id()));
        let disk = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path);
        let disk = disk.unwrap();
        std::fs::remove_file(&path).unwrap();
        record.write(&disk, AT).unwrap();
        let mut bytes = vec![0; ROOM];
        disk.read_exact_at(&mut bytes, AT).unwrap();
        assert_eq!(Record::parse(&bytes), Some(record.clone()));
        // Without its key and peers; what stood there before does not show through.
        let held = Record {
            key: None,
            peers: vec![],
            ..record.clone()
        };
        held.write(&disk, AT).unwrap();
        disk.read_exact_at(&mut bytes, AT).unwrap();
        assert_eq!(Record::parse(&bytes), Some(held.clone()));
        assert!(!bytes.windows(4).any(|window| window == b"key:"));
        assert_eq!(held.id().len(), 64);
        // More peers than there is room for: the last are left out, the TPM's seal is not.
        let many = Record {
            peers: (0..400).map(|n| format!("10.0.{n}.1:7443")).collect(),
            ..held.clone()
        };
        many.write(&disk, AT).unwrap();
        disk.read_exact_at(&mut bytes, AT).unwrap();
        let read = Record::parse(&bytes).unwrap();
        assert!(read.tpm == held.tpm && read.pass == held.pass && read.peers.len() > 100 && read.peers.len() < 400);
        assert_ne!(held.id(), hex(&held.secret));

        // Nothing there, another format, a secret that is not one: no record.
        assert_eq!(Record::parse(&[0; ROOM]), None);
        assert_eq!(Record::parse(b"kith-lock v2\nsecret: 00\n"), None);
        assert_eq!(Record::parse(b"kith-lock v1\nsecret: 0707\n"), None);
        assert_eq!(Record::parse(b"kith-lock v1\nsecret: zz\n"), None);
        // On a disk, a record that begins as one and is not one, nor is its copy, is an error,
        // not a plain state; one whose copy is whole is the copy.
        disk.write_all_at(b"kith-lock v1\nsecret: zz\n\0", AT).unwrap();
        let path = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&disk));
        assert_eq!(Record::read(Path::new(&path)).unwrap().unwrap().tpm, held.tpm);
        disk.write_all_at(b"kith-lock v1\nsecret: zz\n\0", AT + ROOM as u64)
            .unwrap();
        assert!(Record::read(Path::new(&path)).is_err());
        disk.write_all_at(&[0; 2 * ROOM], AT).unwrap();
        assert_eq!(Record::read(Path::new(&path)), Ok(None));
        // Erased: a record that was there is zeros, as read back.
        many.write(&disk, AT).unwrap();
        assert!(Record::read(Path::new(&path)).unwrap().is_some());
        erase(Path::new(&path)).unwrap();
        assert_eq!(Record::read(Path::new(&path)), Err(ERASED.to_string()));
    }

    /// A seal line of the record that cannot be read is left out (or counts as there and
    /// opens nothing) and said, by name; the rest of the record stands.
    #[test]
    fn crypt_records_say_the_seal_lines_they_could_not_read() {
        let head = "kith-lock v1\nsecret: 0707070707070707070707070707070707070707070707070707070707070707\n"; // pragma: allowlist secret
        let parsed = |lines: &str| {
            let mut said = Vec::new();
            let read = Record::parse_said(format!("{head}{lines}").as_bytes(), &mut |line| {
                said.push(line.to_string())
            });
            (read.unwrap(), said)
        };
        let (read, said) = parsed(
            "tpm-next: zz\ntpm-pin-next: 0\ntpm-pin: 00 zz\ntpm-parent: 000b06\npassphrase: later\nduress: 0606\n",
        );
        assert_eq!(
            (&read.next, &read.pin_next, &read.pin, &read.parent, &read.pass),
            (
                &Some(vec![]),
                &Some(vec![]),
                &Some(PinSeal::default()),
                &Some(vec![]),
                &None
            )
        );
        assert_eq!(read.duress, None);
        for name in ["tpm-next:", "tpm-pin-next:", "tpm-pin:", "tpm-parent:", "passphrase:"] {
            assert_eq!(
                said.iter().filter(|line| line.contains(name)).count(),
                1,
                "{name}: {said:?}"
            );
        }
        assert_eq!(said.len(), 5, "{said:?}");
        // An empty one is as unread as a bad one; a good one says nothing.
        assert_eq!(parsed("tpm-next: \n").0.next, Some(vec![]));
        assert_eq!(parsed("tpm-next: \n").1.len(), 1);
        let (read, said) = parsed(
            "tpm: 0102\ntpm-next: 0304\ntpm-pin-next: 0506\ntpm-parent: 000b0000000000000000000000000000000000000000000000000000000000000000\n",
        );
        assert_eq!((read.next, read.pin_next), (Some(vec![3, 4]), Some(vec![5, 6])));
        assert_eq!(said, Vec::<String>::new());
        // A bare name (its space cut off) is as unread as a bad value, not a damaged record.
        let (read, said) = parsed("tpm-next:\ntpm-pin-next:\ntpm-pin:\ntpm-parent:\npassphrase:\nseen: yes\n");
        assert_eq!(
            (read.next, read.pin_next, read.parent),
            (Some(vec![]), Some(vec![]), Some(vec![]))
        );
        assert!(read.seen && read.pin.is_some() && read.pass.is_none());
        assert_eq!(said.len(), 5, "{said:?}");
    }

    /// The cluster's word, once written, is the record in memory too: a seal dropped from the
    /// disk is not written back by a later write of what is in memory.
    #[test]
    fn crypt_records_in_memory_are_what_the_cluster_left() {
        let record = Record {
            secret: vec![7; 32],
            tpm: Some(vec![1; 20]),
            next: Some(vec![2; 20]),
            parent: Some(vec![0; 34]),
            peers: vec!["10.0.0.2".into()],
            ..Record::default()
        };
        let left = ways_left(&record, false, false);
        assert!(left.next.is_none() && left.tpm.is_none());
        let mut held = record.clone();
        adopt(&mut held, left.clone());
        assert_eq!(held, left);
        assert!(held.next.is_none());
    }

    /// Against a software TPM: `open` tries `tpm:` and then `tpm-next:`, so a system the
    /// seal was made ahead for opens its state with no node asked; one neither names does not.
    /// A record with a next seal and no storage key's name is not opened.
    #[test]
    fn crypt_records_open_by_tpm_next_after_tpm() {
        use crate::tpm::{Tpm, tests};
        let Some((_software, wire)) = tests::software() else {
            return;
        };
        let mut tpm = Tpm(wire);
        tests::measured(&mut tpm);
        let key = vec![3; 64]; // pragma: allowlist secret
        let (now, parent) = tpm.seal(&key, None).unwrap();
        // (The next system: a PCR moves, and the seal is made for it.)
        tpm.extend(0, &[9; 32]).unwrap();
        let (next, _) = tpm.seal(&key, Some(&parent)).unwrap();
        let record = Record {
            secret: vec![7; 32],
            tpm: Some(now.clone()),
            parent: Some(parent.clone()),
            next: Some(next.clone()),
            ..Record::default()
        };
        assert_eq!(unsealed(&mut tpm, &record), Ok((key.clone(), true)));
        // Where `tpm:` opens, it is the one that did.
        tpm.extend(0, &[8; 32]).unwrap();
        let (third, _) = tpm.seal(&key, Some(&parent)).unwrap();
        let then = Record {
            tpm: Some(third),
            ..record.clone()
        };
        assert_eq!(unsealed(&mut tpm, &then), Ok((key.clone(), false)));
        // Neither names this system: the refusal is `tpm:`'s, and said.
        let lost = Record {
            next: Some(next.clone()),
            tpm: Some(now.clone()),
            ..record.clone()
        };
        assert!(
            unsealed(&mut tpm, &lost)
                .unwrap_err()
                .contains("not the system it was sealed for")
        );
        // A next seal that cannot be read opens nothing; the line does not stop `tpm:`.
        let unread = Record {
            next: Some(vec![]),
            tpm: then.tpm.clone(),
            ..record.clone()
        };
        assert_eq!(unsealed(&mut tpm, &unread), Ok((key.clone(), false)));
        // No storage key's name beside a next seal: it is not opened as the old form is.
        let nameless = Record {
            parent: None,
            tpm: then.tpm.clone(),
            ..record.clone()
        };
        assert_eq!(unsealed(&mut tpm, &nameless), Err(NAMELESS.to_string()));
        // And no seal at all is no way in (a key on the disk, or a PIN, is not this one).
        assert_eq!(seals(&record).len(), 2);
        for beside in [
            Record {
                key: Some(key.clone()),
                ..record.clone()
            },
            Record {
                pin: Some(PinSeal::default()),
                ..record.clone()
            },
        ] {
            assert!(seals(&beside).is_empty());
        }
    }

    /// Against a software TPM: a PIN is asked when `tpm-pin:`'s k1 opens or `tpm-pin-next:`'s
    /// does (the same k1, sealed for the next system); when neither does, none is.
    #[test]
    fn crypt_records_ask_a_pin_by_k1_of_the_next_system() {
        use crate::tpm::{Tpm, tests};
        let Some((software, wire)) = tests::software() else {
            return;
        };
        let mut tpm = Tpm(wire);
        tests::measured(&mut tpm);
        let k1 = k1_of(&[3; 64]);
        let (now, parent) = tpm.seal(&k1[..], None).unwrap();
        tpm.extend(0, &[9; 32]).unwrap();
        let (next, _) = tpm.seal(&k1[..], Some(&parent)).unwrap();
        let seal = PinSeal {
            k1: now,
            k2: vec![1; 10],
            wrapped: vec![2; 10],
        };
        let Tpm(wire) = tpm;
        let asked = pin_way(&seal, Some(&next), Some(&parent), || Ok(Tpm(wire)));
        assert!(asked.is_ok(), "{:?}", asked.err());
        drop(asked);
        // Not named by the next one either (nor by an unreadable one): no PIN is asked.
        let mut tpm = Tpm(software.wire());
        tpm.extend(4, &[9; 32]).unwrap();
        let Tpm(wire) = tpm;
        let refused = pin_way(&seal, Some(&next), Some(&parent), || Ok(Tpm(wire)))
            .err()
            .unwrap();
        assert!(refused.contains("not the one the PIN's seal names"), "{refused}");
        let Tpm(wire) = Tpm(software.wire());
        let refused = pin_way(&seal, Some(&[]), Some(&parent), || Ok(Tpm(wire)))
            .err()
            .unwrap();
        assert!(refused.contains("not the one the PIN's seal names"), "{refused}");
    }

    /// The cluster's word leaves the next seals as it leaves the ones they stand for: a plain
    /// one with the TPM's seal (and never beside a PIN), a PIN's with the PIN.
    #[test]
    fn crypt_records_keep_their_next_seals_as_the_seals_they_stand_for() {
        let record = Record {
            tpm: Some(vec![5; 40]),
            parent: Some(vec![6; 34]),
            next: Some(vec![7; 40]),
            pin: Some(PinSeal::default()),
            pin_next: Some(vec![8; 40]),
            ..Record::default()
        };
        let left = ways_left(&record, true, false);
        assert_eq!((left.next, left.pin_next), (None, record.pin_next.clone()));
        let left = ways_left(&record, true, true);
        assert_eq!(
            (left.tpm, left.next, left.pin_next),
            (record.tpm.clone(), record.next.clone(), None)
        );
        let left = ways_left(&record, false, true);
        assert_eq!((left.next, left.pin_next, left.parent), (None, None, None));
        let plain = Record {
            pin: None,
            pin_next: None,
            ..record.clone()
        };
        let left = ways_left(&plain, true, false);
        assert_eq!((left.tpm, left.next), (plain.tpm.clone(), plain.next.clone()));
        let left = ways_left(&plain, false, false);
        assert_eq!((left.tpm, left.next, left.parent), (None, None, None));
    }

    #[test]
    fn an_erased_record_says_so() {
        let path = std::env::temp_dir().join(format!("kith-crypt-erased-{}", std::process::id()));
        let disk = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path);
        let disk = disk.unwrap();
        std::fs::remove_file(&path).unwrap();
        disk.set_len(AT + 2 * ROOM as u64).unwrap();
        let path = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&disk));
        // Never written: no record. Erased: the record is gone, and says so, in either place.
        assert_eq!(Record::read(Path::new(&path)), Ok(None));
        erase(Path::new(&path)).unwrap();
        assert_eq!(Record::read(Path::new(&path)), Err(ERASED.to_string()));
        let mut bytes = vec![0; 2 * ROOM];
        disk.read_exact_at(&mut bytes, AT).unwrap();
        assert!(bytes.starts_with(TOMBSTONE) && bytes[ROOM..].starts_with(TOMBSTONE));
        disk.write_all_at(&[0; ROOM], AT).unwrap();
        assert_eq!(Record::read(Path::new(&path)), Err(ERASED.to_string()));
    }

    #[test]
    fn crypt_keys_are_not_handed_out_beside_a_locked_one() {
        let mut store = kith_api::store::Store::default();
        let mut key = |name: &str, spec: Value| {
            let key =
                json!({ "apiVersion": "kith.dev/v1", "kind": "NodeKey", "metadata": { "name": name }, "spec": spec });
            store.apply(serde_json::from_value(key).unwrap()).unwrap();
        };
        key("beta", json!({ "id": "aa", "wrapped": "0102" }));
        key("gamma", json!({ "id": "bb", "wrapped": "0304", "locked": true }));
        key("other", json!({ "id": "bb", "wrapped": "0304" }));
        key("delta", json!({ "id": "cc", "wiped": true }));
        assert_eq!(handed_out(&store, "aa"), Some(("beta", "0102")));
        assert_eq!(handed_out(&store, "bb"), None);
        assert_eq!(handed_out(&store, "cc"), None);
        assert_eq!(handed_out(&store, "dd"), None);
    }

    /// A NodeKey as a node gives it, with what the cluster wrote on it since.
    fn node_key(name: &str, spec: Value, status: Value) -> kith_api::Resource {
        let key = json!({
            "apiVersion": "kith.dev/v1", "kind": "NodeKey", "metadata": { "name": name },
            "spec": spec, "status": status,
        });
        serde_json::from_value(key).unwrap()
    }

    fn stored(keys: &[kith_api::Resource]) -> kith_api::store::Store {
        let mut store = kith_api::store::Store::default();
        for key in keys {
            store.apply(key.clone()).unwrap();
            store.set_status(&key.key(), key.status.clone()).unwrap();
        }
        store
    }

    /// A duress code as `kith node duress` shows it, its key, and the public key kept.
    fn code() -> (String, ring::signature::Ed25519KeyPair, String) {
        use ring::signature::KeyPair;
        let code: [u8; 16] = random();
        let pair = duress_key(&code);
        let public = hex(pair.public_key().as_ref());
        (shown(&code), pair, public)
    }

    #[tokio::test(start_paused = true)]
    async fn duress_looks_wrong() {
        let (key, recovery): ([u8; 64], [u8; 16]) = (random(), random());
        let (duress, _, public) = code();
        let record = Record {
            secret: vec![7; 32],
            recovery: wrap(&recovery, &key),
            pass: Pass::new("correct horse battery", &key, (64, 1)),
            duress: unhex(&public),
            ..Record::default()
        };
        let wrong = shown(&random::<16>());
        // What is typed, what the console says of it, when (by this test's clock: it is
        // paused, and moves only when the console waits), and what was erased.
        let keyboard = |lines: &[&str]| {
            let (type_it, typed) = std::sync::mpsc::channel();
            for line in lines {
                type_it.send(line.to_string()).unwrap();
            }
            (type_it, typed)
        };
        let began = tokio::time::Instant::now();
        let said = std::cell::RefCell::new(Vec::new());
        let say = |line: &str| said.borrow_mut().push((began.elapsed(), line.to_string()));
        // (The disk refuses the first two writes.)
        let erased = std::cell::Cell::new(0);
        let erase = || {
            erased.set(erased.get() + 1);
            erased.get() >= 3
        };
        let (told, _) = tokio::sync::watch::channel(None);

        // A wrong key, the duress code, the recovery key itself, a wrong passphrase: all
        // typed before the first is answered.
        let (_open, lines) = keyboard(&[&wrong, &duress, &shown(&recovery), "correct horse batterz"]);
        let waiting = console(record.clone(), lines, &say, &erase, &told, None, None);
        let opened = tokio::time::timeout(Duration::from_secs(60), waiting).await;
        assert!(opened.is_err(), "after a duress code nothing typed opens the state");
        // Each is answered with the same words, ANSWER after it was read, the duress code
        // as the wrong key before it; none waited behind another's answer.
        let answers: Vec<(Duration, String)> = (1..=4).map(|_| (ANSWER, WRONG.to_string())).collect();
        assert_eq!(*said.borrow(), answers);
        assert_eq!(
            erased.get(),
            3,
            "the record is erased by the duress code alone: again until the disk took it"
        );
        assert!(told.borrow().is_some(), "and its key is there to tell the cluster with");

        // With no duress code typed, the same wrong key is answered so, and the recovery
        // key opens: typed after it, a moment later.
        said.borrow_mut().clear();
        let (began, (told, _)) = (began.elapsed(), tokio::sync::watch::channel(None));
        let (type_it, lines) = keyboard(&[&wrong]);
        let later = async {
            tokio::time::sleep(ANSWER + Duration::from_secs(1)).await;
            type_it.send(shown(&recovery)).unwrap();
            std::future::pending::<()>().await
        };
        let opened = tokio::select! {
            opened = console(record.clone(), lines, &say, &erase, &told, None, None) => opened,
            () = later => unreachable!(),
        };
        assert_eq!(opened, (key.to_vec(), By::Recovery));
        assert_eq!(*said.borrow(), [(began + ANSWER, WRONG.to_string())]);
        assert_eq!(erased.get(), 3);
        // A record that names no duress code takes that code for a wrong key.
        let none = Record { duress: None, ..record };
        assert!(matches!(judged(&none, &duress, None), Typed::Wrong));
    }

    /// `do=ACTION` on `NodeKey/n` as an admin: the status and what it said.
    async fn locked(shared: &Arc<Shared>, action: &str) -> (StatusCode, String) {
        let asked = Query(BTreeMap::from([("do".to_string(), action.to_string())]));
        let answer = set(
            State(shared.clone()),
            Extension(Caller::Admin),
            Named("n".into()),
            asked,
        )
        .await;
        let status = answer.status();
        let body = axum::body::to_bytes(answer.into_body(), 1 << 16).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// A cluster holding `NodeKey/n` with this spec, as a node's key is kept.
    async fn holding(tag: &str, spec: Value) -> Arc<Shared> {
        let dir = std::env::temp_dir().join(format!("kithd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let shared = crate::replica(None, &dir, Duration::from_secs(300)).await.unwrap();
        shared
            .store
            .lock()
            .unwrap()
            .store
            .apply(node_key("n", spec, json!({})))
            .unwrap();
        shared
    }

    fn spec_of(shared: &Arc<Shared>) -> Value {
        shared
            .store
            .lock()
            .unwrap()
            .store
            .get("NodeKey/n")
            .unwrap()
            .spec
            .clone()
    }

    /// A leaked per-node duress code is revoked while the key is forgotten (T-0879): that
    /// takes the node's own code and nothing else, and the key stays forgotten; the other
    /// actions on a forgotten key are refused as before, and a wiped key has no code to take.
    #[tokio::test]
    async fn no_duress_on_a_forgotten_key() {
        let forgotten = json!({ "id": "aa", "forgotten": true, "duress": "d1", "duressAll": "d2" });
        let shared = holding("no-duress-forgotten", forgotten.clone()).await;
        let (status, said) = locked(&shared, "no-duress").await;
        assert_eq!(status, StatusCode::OK, "{said}");
        assert_eq!(
            spec_of(&shared),
            json!({ "id": "aa", "forgotten": true, "duressAll": "d2" })
        );
        // Every other action but unlock and wipe is refused, and changes nothing.
        let after = spec_of(&shared);
        for action in ["lock", "seal", "unseal", "duress", "bogus"] {
            let (status, said) = locked(&shared, action).await;
            assert_eq!(status, StatusCode::CONFLICT, "{action}: {said}");
            assert!(
                said.contains("`kith node unlock n` has it held again"),
                "{action}: {said}"
            );
        }
        assert_eq!(spec_of(&shared), after);
        // Wiped: no code is there to take, and it is refused as a wiped key is.
        let wiped = holding("no-duress-wiped", json!({ "id": "aa", "wiped": true, "duress": "d1" })).await;
        let (status, said) = locked(&wiped, "no-duress").await;
        assert_eq!(status, StatusCode::CONFLICT, "{said}");
        assert!(said.contains("was wiped"), "{said}");
        assert_eq!(spec_of(&wiped)["duress"], "d1");
        // A key not forgotten takes it as it did.
        let held = holding("no-duress-held", json!({ "id": "aa", "wrapped": "00", "duress": "d1" })).await;
        assert_eq!(locked(&held, "no-duress").await.0, StatusCode::OK);
        assert!(spec_of(&held).get("duress").is_none());
    }

    /// After that, the code once typed at the node (`/v1/forget`) forgets nothing more, and
    /// the cluster's code still does.
    #[tokio::test]
    async fn a_revoked_duress_code_forgets_nothing() {
        let (_, own, own_public) = code();
        let (_, all, all_public) = code();
        let spec = json!({ "id": "aa", "forgotten": true, "duress": own_public, "duressAll": all_public });
        let shared = holding("revoked-duress", spec).await;
        let nonce = [5; 32];
        let typed = |pair: &ring::signature::Ed25519KeyPair| {
            let signature = pair.sign(&forget_text("aa", &nonce));
            let state = shared.store.lock().unwrap();
            forgetting(&state.store, "aa", &nonce, signature.as_ref())
        };
        assert_eq!(typed(&own).len(), 1);
        assert_eq!(locked(&shared, "no-duress").await.0, StatusCode::OK);
        assert!(typed(&own).is_empty());
        assert_eq!(typed(&all).len(), 1);
    }

    #[test]
    fn forgotten_keys_written_over_are_put_back() {
        let wrapped = json!({ "id": "a", "wrapped": "00" });
        let change = |before: Value, after: Value| kith_api::store::Change {
            action: kith_api::store::Action::Updated,
            before: Some(node_key("n", before, json!({}))),
            after: node_key("n", after, json!({})),
        };
        let done = kith_store::Done::Changes(vec![
            // A lock made from what the store held before the duress code was taken.
            change(json!({ "id": "a", "forgotten": true }), wrapped.clone()),
            change(json!({ "id": "a", "wiped": true }), wrapped.clone()),
            // A wipe of a forgotten key, and a write to a key that was never forgotten.
            change(
                json!({ "id": "a", "forgotten": true }),
                json!({ "id": "a", "wiped": true }),
            ),
            change(wrapped.clone(), json!({ "id": "a", "wrapped": "00", "locked": true })),
        ]);
        let back: Vec<Value> = put_back(&done).into_iter().map(|key| key.spec).collect();
        assert_eq!(
            back,
            [
                json!({ "id": "a", "forgotten": true }),
                json!({ "id": "a", "wiped": true })
            ]
        );
        assert!(put_back(&kith_store::Done::Nothing).is_empty());
    }

    /// The store drops its log after a write that takes a wrapped key out (kith-store's
    /// `wrapped`): it has to read a NodeKey as this writes it as holding one, and one a
    /// forget writes as holding none.
    #[test]
    fn forgotten_key_as_kithd_writes_it_is_seen_by_the_store() {
        let id = "aa";
        let mut written = to_hold("a", id, &[7; 32], &[9; 32]);
        assert!(kith_store::wrapped(&written).is_some_and(|wrapped| unhex(wrapped).is_some()));
        let (_, own, own_public) = code();
        written.spec["duress"] = own_public.into();
        let nonce = [5; 32];
        let wiped = forgetting(
            &stored(&[written]),
            id,
            &nonce,
            own.sign(&forget_text(id, &nonce)).as_ref(),
        );
        assert_eq!(wiped.len(), 1);
        assert_eq!(kith_store::wrapped(&wiped[0]), None);
    }

    #[test]
    fn duress_all_forgets_every_key_and_exists_only_once_made() {
        let (_, pair, public) = code();
        let (_, own, own_public) = code();
        let seen = json!({ "recoverySeen": true });
        let held = |name: &str, id: &str| node_key(name, json!({ "id": id, "wrapped": "0102" }), seen.clone());
        let nonce = [5; 32];
        let signed = |pair: &ring::signature::Ed25519KeyPair, id: &str| pair.sign(&forget_text(id, &nonce));
        let keys = |store: &kith_api::store::Store, id: &str, pair: &ring::signature::Ed25519KeyPair| {
            let wiped = forgetting(store, id, &nonce, signed(pair, id).as_ref());
            let said = |key: &kith_api::Resource| (key.metadata.name.clone(), key.spec.clone());
            wiped.iter().map(said).collect::<Vec<(String, Value)>>()
        };
        // No admin made a code: whatever signs, nothing is forgotten.
        let mut plain = vec![held("a", "aa"), held("b", "bb"), held("c", "cc")];
        assert!(keys(&stored(&plain), "aa", &pair).is_empty());
        // The cluster's code, on every NodeKey there was when it was made (c came later),
        // and a's own beside it.
        for key in &mut plain[..2] {
            key.spec["duressAll"] = public.clone().into();
        }
        plain[0].spec["duress"] = own_public.into();
        let (_, bs, bs_public) = code();
        plain[1].spec["duress"] = bs_public.clone().into();
        let store = stored(&plain);
        // a's own code forgets a's key alone; the cluster's, typed at a, every key under it:
        // a's record is erased (wiped), b has its record and its recovery key (forgotten).
        let wiped = ("a".to_string(), json!({ "id": "aa", "wiped": true }));
        assert_eq!(keys(&store, "aa", &own), std::slice::from_ref(&wiped));
        let forgotten = json!({ "id": "bb", "forgotten": true, "duress": bs_public, "duressAll": public });
        assert_eq!(keys(&store, "aa", &pair), [wiped, ("b".to_string(), forgotten)]);
        // (Signed for another disk than the one asked for, or by a's code for b: nothing.)
        let other = forgetting(&store, "bb", &nonce, signed(&pair, "aa").as_ref());
        assert!(other.is_empty() && keys(&store, "bb", &own).is_empty());
        // Forgotten, neither is handed out, and c is as it was.
        let mut store = store;
        for key in forgetting(&store, "aa", &nonce, signed(&pair, "aa").as_ref()) {
            store.apply(key).unwrap();
        }
        assert_eq!((handed_out(&store, "aa"), handed_out(&store, "bb")), (None, None));
        assert_eq!(handed_out(&store, "cc"), Some(("c", "0102")));
        // And a code that was used forgets nothing more at a (wiped, it asks nothing).
        assert!(keys(&store, "aa", &pair).is_empty());
        // b, forgotten, was off when the cluster's code was used: typed at b later, that
        // code (and b's own) erases its record too (wiped), and no other key with it.
        let gone = ("b".to_string(), json!({ "id": "bb", "wiped": true }));
        assert_eq!(keys(&store, "bb", &pair), std::slice::from_ref(&gone));
        assert_eq!(keys(&store, "bb", &bs), [gone]);
        assert!(keys(&store, "aa", &own).is_empty());

        // No code for all while a node under it has a recovery key nobody was shown.
        let unseen = node_key(
            "d",
            json!({ "id": "dd", "wrapped": "0102" }),
            json!({ "sealed": false }),
        );
        let never = node_key("e", json!({ "id": "ee", "wrapped": "0102" }), Value::Null);
        assert_eq!(never_shown(&[held("a", "aa"), unseen, never]), ["d", "e"]);
        assert!(never_shown(&[held("a", "aa")]).is_empty());
    }

    #[test]
    fn duress_all_off_and_anew_reach_a_forgotten_key() {
        let (_, old, old_public) = code();
        let (_, new, new_public) = code();
        let seen = json!({ "recoverySeen": true });
        let nonce = [5; 32];
        let held = |name: &str, id: &str| {
            let spec = json!({ "id": id, "wrapped": "0102", "duressAll": old_public });
            node_key(name, spec, seen.clone())
        };
        let erases = |store: &kith_api::store::Store, pair: &ring::signature::Ed25519KeyPair| {
            let signature = pair.sign(&forget_text("bb", &nonce));
            let wiped = forgetting(store, "bb", &nonce, signature.as_ref());
            wiped.iter().any(|key| key.spec["wiped"] == true)
        };
        // The code used at a: a is wiped, b forgotten (it keeps the code).
        let mut store = stored(&[held("a", "aa"), held("b", "bb")]);
        let signature = old.sign(&forget_text("aa", &nonce));
        for key in forgetting(&store, "aa", &nonce, signature.as_ref()) {
            store.apply(key).unwrap();
        }
        assert!(erases(&store, &old));
        // Revoked (`--off`): it reaches the forgotten key, which stays forgotten and is not
        // erased by the revoked code.
        let (mut revoked, mut anew) = (under_all(&store), under_all(&store));
        assert_eq!(revoked.len(), 1);
        code_all(&mut revoked, None);
        assert!(gone(&revoked[0]) && revoked[0].spec.get("duressAll").is_none());
        let mut off = store.clone();
        off.apply(revoked.remove(0)).unwrap();
        assert!(!erases(&off, &old));
        // A new code for all replaces the old one there: it erases the node, the old one no more.
        code_all(&mut anew, Some(&new_public));
        store.apply(anew.remove(0)).unwrap();
        assert!(erases(&store, &new) && !erases(&store, &old));
    }

    #[test]
    fn forget_unproven_is_refused() {
        let (_, pair, public) = code();
        let key = node_key(
            "a",
            json!({ "id": "aa", "wrapped": "0102", "duress": public }),
            Value::Null,
        );
        let store = stored(&[key]);
        let forgot = |nonce: &[u8], signature: &[u8]| !forgetting(&store, "aa", nonce, signature).is_empty();
        // A copy of the disk has its id, its secret and the code's public key, not the code:
        // signed with another key, with the public key itself, or not at all.
        let nonce = given("aa".into());
        let (_, copy, _) = code();
        assert!(!forgot(&nonce, copy.sign(&forget_text("aa", &nonce)).as_ref()));
        assert!(!forgot(&nonce, &unhex(&public).unwrap()) && !forgot(&nonce, &[]));
        // The code's key over the number just given is taken: once.
        let signature = pair.sign(&forget_text("aa", &nonce));
        assert!(taken("aa", &nonce) && forgot(&nonce, signature.as_ref()));
        assert!(!taken("aa", &nonce), "an answer sent a second time");
        // A number that was given for another disk, one never given, and one given more
        // than a minute ago: none is taken.
        let other = given("bb".into());
        assert!(!taken("aa", &other) && !taken("aa", &[9; 32]));
        let old = std::time::Instant::now().checked_sub(FRESH + Duration::from_secs(1));
        GIVEN.lock().unwrap().push_back((old.unwrap(), "aa".into(), [3; 32]));
        assert!(!taken("aa", &[3; 32]), "an answer to an old number");
        // And a signature over another number than the one sent with it opens nothing.
        let next = given("aa".into());
        assert!(taken("aa", &next) && !forgot(&next, signature.as_ref()));
        // Whoever keeps asking has the oldest numbers forgotten, not the room grow.
        let first = given("aa".into());
        for _ in 0..OUTSTANDING {
            given("zz".into());
        }
        assert!(!taken("aa", &first) && GIVEN.lock().unwrap().len() == OUTSTANDING);
    }

    #[test]
    fn new_recovery_key_opens_and_the_old_one_does_not() {
        let (key, old): ([u8; 64], [u8; 16]) = (random(), random());
        let record = Record {
            secret: vec![7; 32],
            recovery: wrap(&old, &key),
            ..Record::default()
        };
        assert!(matches!(judged(&record, &shown(&old), None), Typed::Opens(opened, By::Recovery) if *opened == key));
        let (with, new) = renewed(&record, &key);
        assert!(matches!(judged(&with, &new, None), Typed::Opens(opened, By::Recovery) if *opened == key));
        assert!(matches!(judged(&with, &shown(&old), None), Typed::Wrong));
        // Whoever asked was shown it; nothing else of the record changed, and the key
        // shown is not in it.
        assert!(with.seen && !record.seen && new != shown(&old));
        let same = Record {
            recovery: record.recovery.clone(),
            seen: false,
            ..with.clone()
        };
        assert_eq!(same, record);
        assert!(!with.text().contains(&new.replace('-', "")));
    }

    #[test]
    fn unseen_recovery_keys_are_warned_of_until_one_was_shown() {
        let held = |name: &str, status: Value| node_key(name, json!({ "id": name, "wrapped": "0102" }), status);
        // No node's state is encrypted: nothing to say.
        assert_eq!(unseen(&stored(&[])), None);
        // Installed with nobody watching, and sealed or not: said, with a node to ask.
        let nobody = [held("a", Value::Null), held("b", json!({ "sealed": true }))];
        let warning = unseen(&stored(&nobody)).unwrap();
        assert!(warning.contains("nobody was shown") && warning.contains("`kith node recovery a`"));
        // One of them was shown its key (`kith node recovery`, or typed at its console): no more.
        let one = [held("a", Value::Null), held("b", json!({ "recoverySeen": true }))];
        assert_eq!(unseen(&stored(&one)), None);
        // A wiped node's key opens nothing, shown or not.
        let mut wiped = held("c", json!({ "recoverySeen": true }));
        wiped.spec = json!({ "id": "c", "wiped": true });
        assert!(unseen(&stored(&[held("a", Value::Null), wiped.clone()])).is_some());
        assert_eq!(unseen(&stored(&[wiped])), None);
    }
}

/// What the fido2 tests share: a record that has every other line, each as long as it
/// is likely to be, and two keys of the largest sizes a `fido2:` line has.
#[cfg(test)]
mod fido2_fixture {
    use super::*;

    pub const KEY: [u8; 64] = [9; 64];

    pub fn every_other_way() -> Record {
        Record {
            secret: vec![7; 32],
            recovery: wrap(&[1; 16], &KEY),
            key: Some(KEY.to_vec()),
            // (The PIN's way and its next seal are the longest; a plain seal is beside no PIN.)
            tpm: None,
            parent: Some(vec![6; 34]),
            pass: Some(Pass {
                cost: COST,
                salt: vec![3; 16],
                wrapped: vec![4; 92],
            }),
            seen: true,
            duress: Some(vec![6; 32]),
            duress_all: Some(vec![8; 32]),
            pin: Some(PinSeal {
                k1: vec![1; 200],
                k2: vec![2; 200],
                wrapped: vec![3; 92],
            }),
            next: None,
            pin_next: Some(vec![5; 200]),
            fido2: Vec::new(),
            peers: (0..40).map(|n| format!("10.0.{n}.1:7443")).collect(),
        }
    }

    /// (credential id, salt, hmac-secret) of key `n`: the id 128 bytes, as long as CTAP2 has one.
    pub fn key(n: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (vec![n; 128], vec![n + 10; 32], vec![n + 20; 32])
    }

    pub fn two(record: &Record) -> Record {
        let (a, b) = (key(1), key(2));
        let new = [(&a.0[..], &a.1[..], &a.2[..]), (&b.0[..], &b.1[..], &b.2[..])];
        record.with_fido2(&KEY, &new).unwrap()
    }

    pub fn said(bytes: &[u8]) -> (Option<Record>, Vec<String>) {
        let mut said = Vec::new();
        let read = Record::parse_said(bytes, &mut |line| said.push(line.to_string()));
        (read, said)
    }
}

/// Two `fido2:` lines go through the record's writer and reader, within its room beside
/// every other line, and are written in an order a cut cannot take a line out of.
#[cfg(test)]
mod fido2_line {
    use super::fido2_fixture::*;
    use super::*;

    #[test]
    fn fido2_line_two_round_trip_beside_every_other_way() {
        let old = every_other_way();
        let new = two(&old);
        let text = new.text();
        let lines: Vec<&str> = text.lines().filter(|line| line.starts_with("fido2: ")).collect();
        assert_eq!(lines.len(), 2, "{text}");
        // (The ADR sizes a line at about 520 characters at its worst.)
        assert!(lines.iter().all(|line| line.len() <= 520), "{lines:?}");
        let [(_, copy), (_, record)] = new.order().unwrap();
        assert_eq!((copy.len(), record.len()), (ROOM, ROOM));
        assert!(
            text.len() < ROOM,
            "two lines and every other way take {} of {ROOM}",
            text.len()
        );
        let path = std::env::temp_dir().join(format!("kith-fido2-line-{}", std::process::id()));
        std::fs::write(&path, vec![0; AT as usize + 2 * ROOM]).unwrap();
        let disk = File::options().read(true).write(true).open(&path).unwrap();
        new.write(&disk, AT).unwrap();
        let read = Record::read(&path).unwrap().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(read, new);
        assert_eq!(read.fido2.len(), 2);
        // Every other line is as it was.
        assert_eq!(
            Record {
                fido2: Vec::new(),
                ..read
            },
            old
        );
        // Not as a Vec in another order: the first key stays the first.
        assert_eq!(Record::parse(&record).unwrap().fido2[0], new.fido2[0]);
    }

    #[test]
    fn fido2_line_refuses_what_would_not_fit_before_a_write() {
        // A record that fits as it is, and does not once two keys are in: the keys do not
        // fit, and it is said which line would be cut; nothing was written.
        let long = Record {
            tpm: Some(vec![5; 500]),
            ..every_other_way()
        };
        assert!(long.order().is_ok(), "the record fits without its fido2 lines");
        let (a, b) = (key(1), key(2));
        let new = [(&a.0[..], &a.1[..], &a.2[..]), (&b.0[..], &b.1[..], &b.2[..])];
        let refused = long.with_fido2(&KEY, &new).unwrap_err();
        assert!(refused.contains("would not fit"), "{refused}");
        // One key alone, the same key twice (by its id, or by what it gave) and a salt or a
        // secret of the wrong size are not enrolled.
        let held = every_other_way();
        assert!(held.with_fido2(&KEY, &new[..1]).is_err());
        assert!(held.with_fido2(&KEY, &[new[0], new[0]]).is_err());
        assert!(
            held.with_fido2(&KEY, &[new[0], (&b.0[..], &b.1[..], &a.2[..])])
                .unwrap_err()
                .contains("same key")
        );
        assert!(
            held.with_fido2(&KEY, &[new[0], (&a.0[..], &b.1[..], &b.2[..])])
                .unwrap_err()
                .contains("same key")
        );
        assert!(
            held.with_fido2(&KEY, &[new[0], (&b.0[..], &b.1[..], &b.2[..16])])
                .is_err()
        );
        assert!(
            held.with_fido2(&KEY, &[new[0], (&b.0[..], &b.1[..8], &b.2[..])])
                .is_err()
        );
    }

    /// The new record goes over the old in the order pinned here (the copy at ROOM, then the
    /// record at 0), cut at some 70 places of the 8192 bytes: the region not being written
    /// is whole, and what is read is the old record or the new, both seen. This is a write
    /// cut short, not a disk that puts sectors down in another order
    /// (`lock_record_cut_at_any_sector_reads_as_old_or_new` is the one near it).
    #[test]
    fn fido2_line_cut_anywhere_leaves_the_old_record_or_the_new() {
        let without = every_other_way();
        let with = two(&without);
        let path = std::env::temp_dir().join(format!("kith-fido2-cut-{}", std::process::id()));
        assert_eq!(with.without_fido2().unwrap(), without);
        for (old, new) in [(&without, &with), (&with, &without)] {
            let disk = {
                std::fs::write(&path, vec![0; AT as usize + 2 * ROOM]).unwrap();
                File::options().read(true).write(true).open(&path).unwrap()
            };
            old.write(&disk, AT).unwrap();
            // (The order is pinned here, from a literal: the copy at ROOM, then the record at
            // 0. `order` must say the same, or the cuts below are not the writes made.)
            let (before, after) = (old.order().unwrap(), new.order().unwrap());
            assert_eq!((before[0].0, before[1].0, after[0].0, after[1].0), (ROOM, 0, ROOM, 0));
            let (old_bytes, new_bytes) = (&before[1].1, &after[1].1);
            let (mut total, mut seen) = (0, [false; 2]);
            for cut in (0..=2 * ROOM).step_by(61).chain([ROOM - 1, ROOM, ROOM + 1, 2 * ROOM]) {
                // Back to the old on the disk, then the new put over it up to `cut` bytes.
                disk.write_all_at(old_bytes, AT + ROOM as u64).unwrap();
                disk.write_all_at(old_bytes, AT).unwrap();
                let mut left = cut;
                for to in [ROOM, 0] {
                    let part = left.min(ROOM);
                    disk.write_all_at(&new_bytes[..part], AT + to as u64).unwrap();
                    left -= part;
                }
                let mut regions = vec![0; 2 * ROOM];
                disk.read_exact_at(&mut regions, AT).unwrap();
                let (record, copy) = regions.split_at(ROOM);
                // The region not being written is whole: the record while the copy is, and
                // the copy while the record is.
                if cut <= ROOM {
                    assert_eq!(Record::parse(record).as_ref(), Some(old), "cut at {cut}");
                }
                if cut >= ROOM {
                    assert_eq!(Record::parse(copy).as_ref(), Some(new), "cut at {cut}");
                }
                let read = Record::read(&path).unwrap().unwrap();
                assert!(
                    &read == old || &read == new,
                    "cut at {cut} read a record that is neither"
                );
                // (Where the new record is read whole, it is the new; where it is not, the old.)
                total += 1;
                assert_eq!(read.fido2.len(), if read == with { 2 } else { 0 });
                seen[usize::from(&read == new)] = true;
            }
            assert!(
                total > 100 && seen == [true, true],
                "a cut left the old at times, and the new at others"
            );
        }
        std::fs::remove_file(&path).unwrap();
    }

    /// One region torn (a byte flipped in it) while the other is whole: read falls back to
    /// the whole one, with its two keys; both torn is a damaged record, not an empty one.
    #[test]
    fn fido2_line_torn_record_is_read_from_the_copy_and_the_other_way() {
        let with = two(&every_other_way());
        let path = std::env::temp_dir().join(format!("kith-fido2-torn-{}", std::process::id()));
        std::fs::write(&path, vec![0; AT as usize + 2 * ROOM]).unwrap();
        let disk = File::options().read(true).write(true).open(&path).unwrap();
        with.write(&disk, AT).unwrap();
        let tear = |region: usize| {
            let at = AT + (region * ROOM) as u64 + 300;
            let mut byte = [0];
            disk.read_exact_at(&mut byte, at).unwrap();
            disk.write_all_at(&[byte[0] ^ 1], at).unwrap();
        };
        tear(0);
        let read = Record::read(&path).unwrap().unwrap();
        assert_eq!(
            (read.fido2.len(), &read),
            (2, &with),
            "the record is torn, the copy is whole"
        );
        tear(0);
        tear(1);
        let read = Record::read(&path).unwrap().unwrap();
        assert_eq!(read, with, "the copy is torn, the record is whole again");
        tear(0);
        assert!(Record::read(&path).unwrap_err().contains("damaged"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn fido2_line_come_off_both_and_after_the_recovery_key_was_shown() {
        let with = two(&every_other_way());
        let without = with.without_fido2().unwrap();
        assert!(without.fido2.is_empty() && !without.text().contains("fido2"));
        assert!(
            Record { seen: false, ..with }
                .without_fido2()
                .unwrap_err()
                .contains("recovery key")
        );
        assert!(without.without_fido2().is_err());
    }
}

/// A `fido2:` line that cannot be read is dropped and said, and a third is refused.
#[cfg(test)]
mod fido2_bad {
    use super::fido2_fixture::*;
    use super::*;

    const HEAD: &str = "kith-lock v1\nsecret: 0707070707070707070707070707070707070707070707070707070707070707\n"; // pragma: allowlist secret

    fn line(n: u8) -> String {
        let (id, salt, wrapped) = (vec![n + 1; 64], vec![n + 5; 32], vec![n + 9; 92]);
        format!("fido2: {}\n", Fido2 { id, salt, wrapped }.text())
    }

    #[test]
    fn fido2_bad_line_is_dropped_and_said_and_the_rest_stands() {
        let good = line(0);
        let id = hex(&[1; 8]);
        let salt = hex(&[2; 32]);
        let wrapped = hex(&[3; 92]);
        for bad in [
            format!("fido2: zz {salt} {wrapped}\n"),
            format!("fido2: {id} {salt}\n"),
            format!("fido2: {id} {} {wrapped}\n", hex(&[2; 31])),
            format!("fido2: {} {salt} {wrapped}\n", hex(&[1; 129])),
            format!("fido2: {id} {salt} {}\n", hex(&[3; 20])),
            format!("fido2: {} {salt} {wrapped}\n", ""),
            "fido2: 0\n".to_string(),
            "fido2: \n".to_string(),
            "fido2:\n".to_string(),
        ] {
            let (read, said) = said(format!("{HEAD}{bad}passphrase: 1 1 00 00\nseen: yes\n{good}").as_bytes());
            let read = read.unwrap_or_else(|| panic!("a bad line made the record damaged: {bad:?}"));
            assert_eq!(read.fido2.len(), 1, "{bad:?}");
            assert!(read.seen, "the rest of the record stands");
            let said: Vec<_> = said.iter().filter(|said| said.contains("fido2:")).collect();
            assert_eq!(said.len(), 1, "{bad:?}: {said:?}");
            assert!(said[0].contains("dropped"), "{said:?}");
        }
        // Said as the lines before are: a good record says nothing.
        let (read, said) = said(format!("{HEAD}{good}{}", line(1)).as_bytes());
        assert_eq!((read.unwrap().fido2.len(), said), (2, Vec::new()));
    }

    #[test]
    fn fido2_bad_third_line_is_refused_not_kept_and_not_silent() {
        let three = format!("{HEAD}{}{}{}", line(0), line(1), line(0));
        let (read, said) = said(three.as_bytes());
        let read = read.unwrap();
        assert_eq!(read.fido2.len(), 2, "a record holds two");
        assert_eq!(read.fido2[0].text(), line(0).trim_start_matches("fido2: ").trim_end());
        let said: Vec<_> = said.iter().filter(|said| said.contains("fido2:")).collect();
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(said[0].contains("more than 2"), "{said:?}");
        // And not enrolled: a record that holds two refuses two more, and one that holds one.
        let held = two(&every_other_way());
        let (a, b) = (key(3), key(4));
        let new = [(&a.0[..], &a.1[..], &a.2[..]), (&b.0[..], &b.1[..], &b.2[..])];
        assert!(held.with_fido2(&KEY, &new).unwrap_err().contains("already holds"));
        let one = Record {
            fido2: held.fido2[..1].to_vec(),
            ..held
        };
        assert!(one.with_fido2(&KEY, &new).unwrap_err().contains("already holds"));
        assert!(one.with_fido2(&KEY, &new[..1]).is_err());
    }
}

/// A cluster that locks or forgets a node takes its fido2 keys off, as it does a passphrase.
#[cfg(test)]
mod fido2_shut {
    use super::fido2_fixture::*;
    use super::*;

    #[test]
    fn fido2_shut_node_loses_its_keys_and_is_restarted_without_them() {
        let record = Record {
            // (A TPM seal beside the keys, as the console keeps one.)
            tpm: Some(vec![5; 40]),
            pin: None,
            ..two(&every_other_way())
        };
        // Not shut: kept, sealed or not.
        for seal in [false, true] {
            assert_eq!(ways_left(&record, seal, false).fido2, record.fido2);
        }
        // Locked or forgotten: gone, with the seal or without it.
        for seal in [false, true] {
            assert!(ways_left(&record, seal, true).fido2.is_empty(), "seal {seal}");
        }
        // A node locked with a key left restarts to wait (it would open by the key's touch); with
        // none left, it has nothing that opens it.
        assert!(!opens_nothing_asked(&record));
        let only_keys = Record {
            tpm: None,
            next: None,
            pass: None,
            pin: None,
            ..record.clone()
        };
        assert!(
            !opens_nothing_asked(&only_keys),
            "a record with only its keys has a way in"
        );
        assert!(opens_nothing_asked(&ways_left(&only_keys, false, true)));
        assert!(opens_nothing_asked(&Record {
            fido2: Vec::new(),
            ..only_keys
        }));
    }
}

/// The state's key wrapped under a key's derived secret opens with that secret only.
#[cfg(test)]
mod fido2_wrap {
    use super::fido2_fixture::*;
    use super::*;

    #[test]
    fn fido2_wrap_opens_with_its_secret_and_not_with_another() {
        let (a, b) = (key(1), key(2));
        let line = Fido2::new(&a.0, &a.1, &a.2, &KEY).unwrap();
        let kept = |opened: Option<zeroize::Zeroizing<Vec<u8>>>| opened.map(|key| key.to_vec());
        assert_eq!(kept(line.open(&a.2)), Some(KEY.to_vec()));
        assert_eq!(kept(line.open(&b.2)), None);
        assert_eq!(kept(line.open(&[0; 32])), None);
        assert_eq!(kept(line.open(&[])), None);
        // A secret that is not the 32 bytes hmac-secret gives is not wrapped under.
        assert_eq!(Fido2::new(&a.0, &a.1, &a.2[..16], &KEY), None);
        assert_eq!(Fido2::new(&a.0, &a.1, &[a.2.clone(), vec![0]].concat(), &KEY), None);
        // The key is not in the line, and the same secret wraps to another line each time.
        assert!(!line.text().contains(&hex(&KEY)));
        assert_ne!(line, Fido2::new(&a.0, &a.1, &a.2, &KEY).unwrap());
        // Through the record: each of the two lines opens with its own key's secret.
        let record = two(&every_other_way());
        let (first, second) = (&record.fido2[0], &record.fido2[1]);
        assert_eq!(
            (kept(first.open(&a.2)), kept(second.open(&b.2))),
            (Some(KEY.to_vec()), Some(KEY.to_vec()))
        );
        assert_eq!((kept(first.open(&b.2)), kept(second.open(&a.2))), (None, None));
        // What is read back proves the enrolment with the secrets still in memory, and a
        // line that stood for another key's does not.
        let mut read = Record::parse(record.text().as_bytes()).unwrap();
        assert!(read.fido2_proves(&KEY, &[&a.2, &b.2]));
        assert!(!read.fido2_proves(&KEY, &[&b.2, &a.2]));
        assert!(!read.fido2_proves(&[1; 64], &[&a.2, &b.2]));
        assert!(!read.fido2_proves(&KEY, &[&a.2]));
        read.fido2.pop();
        assert!(!read.fido2_proves(&KEY, &[&a.2, &b.2]));
    }
}

/// What the console's touch tests share: a node enrolled with two scripted security keys, and
/// the keys the console finds plugged in.
#[cfg(test)]
mod touch_fixture {
    use super::*;
    use crate::fido2::frame::Device;
    use crate::fido2::{flow, frame};
    use crate::fido2_test::auth::Key;

    pub const STATE: [u8; 64] = [5; 64];
    pub const PASS: &str = "correct horse battery";
    pub type Plugged = Box<dyn Device + Send>;

    /// A node that opens by a passphrase, or by either of two keys (made as `kith` makes them).
    pub fn enrolled() -> (Record, Key, Key) {
        let (mut a, mut b) = (Key::new(), Key::new());
        b.seed = 2;
        let mut lines = Vec::new();
        for key in [&mut a, &mut b] {
            let cid = frame::init(key, [1; 8]).unwrap().cid;
            let id = flow::make_credential(key, cid, flow::RP_ID, &[]).unwrap();
            let salt: [u8; 32] = random();
            let secret = flow::get_assertion(key, cid, flow::RP_ID, &id, &salt).unwrap();
            lines.push((id, salt.to_vec(), secret.to_vec()));
        }
        let new = [
            (&lines[0].0[..], &lines[0].1[..], &lines[0].2[..]),
            (&lines[1].0[..], &lines[1].1[..], &lines[1].2[..]),
        ];
        let record = Record {
            secret: vec![7; 32],
            recovery: wrap(&[1; 16], &STATE),
            pass: Pass::new(PASS, &STATE, (64, 1)),
            ..Record::default()
        };
        (record.with_fido2(&STATE, &new).unwrap(), a, b)
    }

    /// A key this node was never enrolled with.
    pub fn stranger() -> Key {
        let mut key = Key::new();
        key.seed = 3;
        key
    }

    /// Each of `keys` handed out once, as a key is when it is plugged in.
    pub fn once(keys: Vec<Plugged>) -> impl FnMut() -> Vec<Plugged> + Send {
        let mut slot = Some(keys);
        move || slot.take().unwrap_or_default()
    }

    pub fn touch(
        record: &Record,
        mut plugged: impl FnMut() -> Vec<Plugged> + Send + 'static,
    ) -> Option<Arc<std::sync::Mutex<Touch>>> {
        Some(Arc::new(std::sync::Mutex::new(Touch {
            lines: record.fido2.clone(),
            plugged: Box::new(move |_| {
                let keys = plugged();
                keys.into_iter()
                    .enumerate()
                    .map(|(n, key)| (format!("key{n}"), key))
                    .collect()
            }),
            present: Box::new(|| ()),
            retry: Vec::new(),
        })))
    }

    /// `touched`, with nothing to stop it.
    pub fn touch_once(touch: &mut Touch) -> Option<Typed> {
        touched(touch, &std::sync::atomic::AtomicBool::new(false))
    }

    /// A key that waits for `release` (a message, or its sender dropped) before it answers, as
    /// one waiting for a touch does; `started` is sent when it is first read, so a test goes
    /// on when the key is waiting, not after a time. Gives up after ten seconds.
    pub struct Gate {
        pub key: Plugged,
        pub started: std::sync::mpsc::Sender<()>,
        pub release: std::sync::mpsc::Receiver<()>,
        pub open: bool,
    }

    impl Device for Gate {
        fn write(&mut self, report: &[u8; frame::REPORT]) -> std::io::Result<()> {
            self.key.write(report)
        }
        fn read(&mut self) -> std::io::Result<Vec<u8>> {
            if !std::mem::replace(&mut self.open, true) {
                let _ = self.started.send(());
                let _ = self.release.recv_timeout(Duration::from_secs(10));
            }
            self.key.read()
        }
    }

    /// A `Gate` round `key`: the key, when it is first read, and what lets it go.
    pub fn gated(key: Key) -> (Plugged, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let ((started, waiting), (release, go)) = (std::sync::mpsc::channel(), std::sync::mpsc::channel());
        let gate = Gate {
            key: Box::new(key),
            started,
            release: go,
            open: false,
        };
        (Box::new(gate), waiting, release)
    }

    pub fn keyboard(lines: &[&str]) -> (std::sync::mpsc::Sender<String>, std::sync::mpsc::Receiver<String>) {
        let (type_it, typed) = std::sync::mpsc::channel();
        for line in lines {
            type_it.send(line.to_string()).unwrap();
        }
        (type_it, typed)
    }
}

/// A security key touched at the console opens the state, as a typed line does, and one that
/// is not this node's is refused like a wrong line (docs/adr-fido2.md section 6).
#[cfg(test)]
mod touch {
    use super::touch_fixture::*;
    use super::*;

    #[test]
    fn each_enrolled_key_opens_the_state_through_its_line() {
        let (record, a, b) = enrolled();
        for key in [a, b] {
            let touch = touch(&record, once(vec![Box::new(key)])).unwrap();
            let opened = touch_once(&mut touch.lock().unwrap());
            assert!(matches!(opened, Some(Typed::Opens(key, By::Key)) if *key == STATE));
            // (And handed out once: nothing is plugged in the next time.)
            assert!(touch_once(&mut touch.lock().unwrap()).is_none());
        }
    }

    /// A key that says nothing.
    struct Dead;
    impl crate::fido2::frame::Device for Dead {
        fn write(&mut self, _: &[u8; crate::fido2::frame::REPORT]) -> std::io::Result<()> {
            Ok(())
        }
        fn read(&mut self) -> std::io::Result<Vec<u8>> {
            Err(std::io::ErrorKind::TimedOut.into())
        }
    }

    #[test]
    fn a_key_that_timed_out_is_handed_out_again_after_the_gap() {
        let (record, ..) = enrolled();
        let asked = Arc::new(std::sync::Mutex::new(Vec::<Vec<String>>::new()));
        let log = Arc::clone(&asked);
        let mut dead = Some(Box::new(Dead) as Plugged);
        let mut touch = Touch {
            lines: record.fido2.clone(),
            plugged: Box::new(move |again| {
                log.lock().unwrap().push(again.to_vec());
                dead.take()
                    .map(|key| vec![("hidraw9".to_string(), key)])
                    .unwrap_or_default()
            }),
            present: Box::new(|| ()),
            retry: Vec::new(),
        };
        // A key that says nothing is a key that was tried, and is said of.
        assert!(matches!(touch_once(&mut touch), Some(Typed::Wrong)));
        assert_eq!(touch.retry.len(), 1);
        // Not asked for again at once, and then, after the gap, it is.
        assert!(touch_once(&mut touch).is_none());
        touch.retry[0].1 = std::time::Instant::now().checked_sub(RETRY_GAP).unwrap();
        assert!(touch_once(&mut touch).is_none());
        assert!(touch.retry.is_empty());
        let none = Vec::<String>::new();
        assert_eq!(
            *asked.lock().unwrap(),
            [none.clone(), none, vec!["hidraw9".to_string()]]
        );
    }

    #[test]
    fn each_find_of_keys_says_somebody_is_there_and_no_find_does_not() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (record, a, _) = enrolled();
        let said = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&said);
        let touch = touch(&record, once(vec![Box::new(a)])).unwrap();
        touch.lock().unwrap().present = Box::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        assert!(touch_once(&mut touch.lock().unwrap()).is_some());
        assert_eq!(said.load(Ordering::SeqCst), 1);
        assert!(touch_once(&mut touch.lock().unwrap()).is_none());
        assert_eq!(said.load(Ordering::SeqCst), 1, "no key, nobody there");
    }

    #[test]
    fn a_key_is_let_go_of_when_the_console_is_done_with_it() {
        let (record, a, _) = enrolled();
        let touch = touch(&record, once(vec![Box::new(a)])).unwrap();
        let stopped = std::sync::atomic::AtomicBool::new(true);
        assert!(touched(&mut touch.lock().unwrap(), &stopped).is_none());
        assert!(
            touch.lock().unwrap().retry.is_empty(),
            "a key let go of is not tried again"
        );
    }

    #[test]
    fn a_key_that_wants_its_pin_is_not_tried_again() {
        let running = std::sync::atomic::AtomicBool::new(false);
        let said = "the key answered status 0x36 (PIN_REQUIRED)";
        assert!(!unusable("hidraw0", said, &running));
        assert!(unusable("hidraw0", "reading from the key: timed out", &running));
        assert!(unusable(
            "hidraw0",
            "the key answered status 0x2f (USER_ACTION_TIMEOUT)",
            &running
        ));
        assert!(!unusable("hidraw0", "a report of 3 bytes: 64 expected", &running));
        let stopped = std::sync::atomic::AtomicBool::new(true);
        assert!(!unusable("hidraw0", "reading from the key: timed out", &stopped));
    }

    #[test]
    fn a_key_that_is_not_enrolled_opens_nothing() {
        let (record, ..) = enrolled();
        let touch = touch(&record, once(vec![Box::new(stranger())])).unwrap();
        assert!(matches!(touch_once(&mut touch.lock().unwrap()), Some(Typed::Wrong)));
        // None plugged in: nothing to say.
        let none = super::touch_fixture::touch(&record, Vec::new).unwrap();
        assert!(touch_once(&mut none.lock().unwrap()).is_none());
        // A node with no fido2 lines looks for no key.
        assert!(touch_of(&Record::default()).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn the_console_is_opened_by_the_key() {
        let (record, _, b) = enrolled();
        let said = std::cell::RefCell::new(Vec::new());
        let say = |line: &str| said.borrow_mut().push(line.to_string());
        let (told, _) = tokio::sync::watch::channel(None);
        let (_open, lines) = keyboard(&[]);
        let touch = touch(&record, once(vec![Box::new(b)]));
        let opened = console(record, lines, &say, &|| true, &told, None, touch).await;
        assert_eq!(opened, (STATE.to_vec(), By::Key));
        assert!(said.borrow().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_key_not_enrolled_is_refused_after_the_delay_of_a_wrong_passphrase() {
        let (record, ..) = enrolled();
        let began = tokio::time::Instant::now();
        let said = std::cell::RefCell::new(Vec::new());
        let say = |line: &str| said.borrow_mut().push((began.elapsed(), line.to_string()));
        let (told, _) = tokio::sync::watch::channel(None);
        // A wrong passphrase, typed as the stranger's key is found.
        let (_open, lines) = keyboard(&["correct horse batterz"]);
        let touch = touch(&record, once(vec![Box::new(stranger())]));
        let waiting = console(record, lines, &say, &|| true, &told, None, touch);
        assert!(tokio::time::timeout(Duration::from_secs(60), waiting).await.is_err());
        // Both answered ANSWER after they were found, in the same words; the key once.
        let both: Vec<(Duration, String)> = (1..=2).map(|_| (ANSWER, WRONG.to_string())).collect();
        assert_eq!(*said.borrow(), both);
    }
}

/// The console tries what is typed before a key, and a key that is not there, or that waits,
/// holds nothing up.
#[cfg(test)]
mod console_order {
    use super::touch_fixture::*;
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_passphrase_is_tried_before_the_key() {
        let (record, a, _) = enrolled();
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = asked.clone();
        let mut keys = once(vec![Box::new(a) as Plugged]);
        let touch = touch(&record, move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            keys()
        });
        let (told, _) = tokio::sync::watch::channel(None);
        let (_open, lines) = keyboard(&["correct horse battery"]);
        let opened = console(record, lines, &|_: &str| (), &|| true, &told, None, touch).await;
        assert_eq!(opened, (STATE.to_vec(), By::Owner));
        assert_eq!(
            asked.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no key was looked for"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_wrong_line_then_the_key() {
        let (record, a, _) = enrolled();
        let said = std::cell::RefCell::new(Vec::new());
        let say = |line: &str| said.borrow_mut().push(line.to_string());
        let (told, _) = tokio::sync::watch::channel(None);
        let (_open, lines) = keyboard(&["correct horse batterz"]);
        let touch = touch(&record, once(vec![Box::new(a)]));
        let opened = console(record, lines, &say, &|| true, &told, None, touch).await;
        assert_eq!(opened, (STATE.to_vec(), By::Key));
        assert!(said.borrow().is_empty(), "the key opened before the line was answered");
    }

    #[tokio::test(start_paused = true)]
    async fn a_missing_key_does_not_stall_a_passphrase() {
        let (record, ..) = enrolled();
        let looked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = looked.clone();
        let touch = touch(&record, move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Vec::new()
        });
        let (told, _) = tokio::sync::watch::channel(None);
        let (type_it, lines) = keyboard(&[]);
        let later = async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            type_it.send(PASS.to_string()).unwrap();
            std::future::pending::<()>().await
        };
        let said = std::cell::RefCell::new(Vec::new());
        let say = |line: &str| said.borrow_mut().push(line.to_string());
        let opened = tokio::select! {
            opened = console(record, lines, &say, &|| true, &told, None, touch) => opened,
            () = later => unreachable!(),
        };
        assert_eq!(opened, (STATE.to_vec(), By::Owner));
        assert!(said.borrow().is_empty(), "a missing key is not answered");
        assert!(
            looked.load(std::sync::atomic::Ordering::SeqCst) >= 3,
            "looked for each second"
        );
    }

    /// (Real time, no margins: the passphrase is typed once the key is waiting for its touch, which
    /// is not given until the console has opened.)
    #[tokio::test]
    async fn a_key_waiting_for_its_touch_does_not_hold_a_passphrase() {
        let (record, a, _) = enrolled();
        let (gated, waiting, _release) = gated(a);
        let touch = touch(&record, once(vec![gated]));
        let (told, _) = tokio::sync::watch::channel(None);
        let (type_it, lines) = keyboard(&[]);
        let typing = std::thread::spawn(move || {
            waiting.recv_timeout(Duration::from_secs(10)).unwrap();
            type_it.send(PASS.to_string()).unwrap();
        });
        let opened = console(record, lines, &|_: &str| (), &|| true, &told, None, touch).await;
        typing.join().unwrap();
        assert_eq!(opened, (STATE.to_vec(), By::Owner));
    }
}

/// After a duress code no security key opens the state: not one found later, not one being
/// tried, and not one the record keeps.
#[cfg(test)]
mod touch_duress {
    use super::touch_fixture::*;
    use super::*;
    use crate::fido2_test::auth::Key;

    /// `enrolled()`, with a duress code that was made for it: the code typed, as it is shown.
    fn with_duress() -> (Record, String, Key, Key) {
        use ring::signature::KeyPair;
        let (record, a, b) = enrolled();
        let code: [u8; 16] = random();
        let public = duress_key(&code).public_key().as_ref().to_vec();
        (
            Record {
                duress: Some(public),
                ..record
            },
            shown(&code),
            a,
            b,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_duress_code_leaves_no_key_to_look_for() {
        let (record, duress, a, _) = with_duress();
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = asked.clone();
        let mut keys = once(vec![Box::new(a) as Plugged]);
        let touch = touch(&record, move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            keys()
        });
        let said = std::cell::RefCell::new(Vec::new());
        let say = |line: &str| said.borrow_mut().push(line.to_string());
        let (told, _) = tokio::sync::watch::channel(None);
        let (_open, lines) = keyboard(&[&duress]);
        let waiting = console(record, lines, &say, &|| true, &told, None, touch);
        assert!(tokio::time::timeout(Duration::from_secs(60), waiting).await.is_err());
        assert_eq!(
            asked.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no key was looked for"
        );
        assert_eq!(*said.borrow(), [WRONG], "the code is answered as a wrong line");
        assert!(told.borrow().is_some());
    }

    /// (Real time, no margins: the code is typed once the key is waiting for its touch, and the key is
    /// touched once the console has acted on the code, which it says by erasing the record. A
    /// key in flight holds the paused clock still, so this one runs on the real one: two seconds.)
    #[tokio::test]
    async fn a_key_touched_after_a_duress_code_opens_nothing() {
        let (record, duress, a, _) = with_duress();
        let (gated, waiting_key, release) = gated(a);
        let touch = touch(&record, once(vec![gated]));
        let (say_it, said) = std::sync::mpsc::channel();
        let say = move |line: &str| {
            let _ = say_it.send(line.to_string());
        };
        let (told, _) = tokio::sync::watch::channel(None);
        let (type_it, lines) = keyboard(&[]);
        let (erased, erasing) = std::sync::mpsc::channel();
        let typing = std::thread::spawn(move || {
            waiting_key.recv_timeout(Duration::from_secs(10)).unwrap();
            type_it.send(duress).unwrap();
            erasing.recv_timeout(Duration::from_secs(10)).unwrap();
            release.send(()).unwrap();
            type_it
        });
        let erase = || {
            let _ = erased.send(());
            true
        };
        let waiting = console(record, lines, &say, &erase, &told, None, touch);
        // The code is answered, and so is the key (as a wrong line is): nothing opened.
        let heard = async {
            let mut heard = Vec::new();
            while heard.len() < 2 {
                heard.extend(said.try_iter());
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            heard
        };
        let heard = tokio::select! {
            opened = waiting => panic!("opened: {opened:?}"),
            heard = tokio::time::timeout(Duration::from_secs(20), heard) => heard.expect("two answers"),
        };
        let _kept = typing.join().unwrap();
        assert!(told.borrow().is_some());
        assert_eq!(heard, [WRONG, WRONG]);
    }

    #[test]
    fn a_shut_node_keeps_no_key() {
        let (record, ..) = with_duress();
        assert!(!record.fido2.is_empty());
        for seal in [false, true] {
            assert!(ways_left(&record, seal, true).fido2.is_empty());
        }
    }
}

/// A `fido2:` line is read as written and no other: a fourth word drops it, and a second line
/// of one credential is dropped, both said.
#[cfg(test)]
mod fido2_parse_strict {
    use super::fido2_fixture::*;
    use super::*;

    const HEAD: &str = "kith-lock v1\nsecret: 0707070707070707070707070707070707070707070707070707070707070707\n"; // pragma: allowlist secret

    fn line(n: u8) -> Fido2 {
        Fido2 {
            id: vec![n + 1; 64],
            salt: vec![n + 5; 32],
            wrapped: vec![n + 9; 92],
        }
    }

    #[test]
    fn a_trailing_word_drops_the_line() {
        let good = line(0).text();
        assert!(Fido2::parse(&good).is_some());
        for bad in [format!("{good} 00"), format!("{good} zz"), format!("{good} {good}")] {
            assert!(Fido2::parse(&bad).is_none(), "{bad}");
            let record = format!("{HEAD}fido2: {bad}\nfido2: {}\n", line(1).text());
            let (read, said) = said(record.as_bytes());
            let read = read.unwrap();
            assert_eq!(read.fido2.len(), 1, "only the line of three words stands");
            assert_eq!(said.len(), 1, "{said:?}");
            assert!(
                said[0].contains("cannot be read") && said[0].contains("dropped"),
                "{said:?}"
            );
        }
    }

    #[test]
    fn a_second_line_of_one_credential_is_dropped_and_said() {
        let (first, second) = (
            line(0),
            Fido2 {
                salt: vec![99; 32],
                ..line(0)
            },
        );
        let record = format!(
            "{HEAD}fido2: {}\nfido2: {}\nfido2: {}\n",
            first.text(),
            second.text(),
            line(1).text()
        );
        let (read, told) = said(record.as_bytes());
        let read = read.unwrap();
        assert_eq!(
            read.fido2,
            [first, line(1)],
            "the spare is the other key's line, not a copy"
        );
        assert_eq!(told.len(), 1, "{told:?}");
        assert!(told[0].contains("two fido2: lines of one key"), "{told:?}");
        // As two keys are written, never two of one.
        assert_eq!(
            said(format!("{HEAD}fido2: {}\nfido2: {}\n", line(0).text(), line(1).text()).as_bytes()).1,
            Vec::<String>::new()
        );
    }
}

#[cfg(test)]
mod encrypt_verb {
    use super::*;

    /// A config partition as a file of `size` bytes, at a path no other test uses.
    fn config(name: &str, size: u64) -> PathBuf {
        let path = std::env::temp_dir().join(format!("kith-encrypt-{name}-{}", std::process::id()));
        let disk = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        disk.set_len(size).unwrap();
        path
    }

    #[test]
    fn the_key_secret_and_recovery_key_are_the_installers_shape() {
        let (key, secret, recovery) = draw();
        assert_eq!((key.len(), secret.len(), recovery.len()), (64, 32, 16));
        let record = sealed_record(&key, &secret, &recovery);
        assert_eq!(record.plain_key(), Some(&key[..]));
        assert_eq!(record.secret, secret.to_vec());
        assert_eq!(unwrap(&recovery, &record.recovery).as_deref(), Some(&key[..]));
    }

    #[test]
    fn a_node_in_the_installer_or_not_drained_or_already_marked_or_encrypted_is_refused() {
        let path = config("refuse", 8 << 20);
        assert_eq!(may_encrypt(&path, true, false, "a"), Ok(()));
        assert!(may_encrypt(&path, true, true, "a").unwrap_err().contains("installer"));
        assert!(
            may_encrypt(&path, false, false, "a")
                .unwrap_err()
                .contains("drain a first")
        );
        let disk = File::options().read(true).write(true).open(&path).unwrap();
        crate::in_place::mark(&disk).unwrap();
        assert!(
            may_encrypt(&path, true, false, "a")
                .unwrap_err()
                .contains("already marked")
        );
        cancel_encrypt(&path).unwrap();
        begin_encrypt(&path).unwrap();
        assert!(
            may_encrypt(&path, true, false, "a")
                .unwrap_err()
                .contains("already encrypted")
        );
    }

    #[test]
    fn the_record_is_written_then_marked_and_its_recovery_key_is_the_one_shown() {
        let path = config("begin", 8 << 20);
        let text = begin_encrypt(&path).unwrap();
        let record = Record::read(&path).unwrap().expect("the lock record");
        let disk = File::open(&path).unwrap();
        assert!(crate::in_place::marked(&disk).unwrap());
        let recovery = typed(&text).expect("the recovery key, as it is shown");
        assert_eq!(unwrap(&recovery, &record.recovery).as_deref(), record.plain_key());
    }

    #[test]
    fn a_marker_that_cannot_be_put_takes_the_record_back() {
        // (A journal begun with no marker: `in_place::mark` will not put the marker over it, so
        // the record written before the marker is taken back.)
        let path = config("short", 8 << 20);
        let disk = File::options().write(true).open(&path).unwrap();
        disk.write_all_at(&[1], (128 << 10) + ROOM as u64).unwrap();
        assert!(begin_encrypt(&path).is_err());
        assert!(matches!(Record::read(&path), Ok(None)));
    }

    #[test]
    fn cancel_takes_an_unstarted_marker_and_its_record_away_and_refuses_with_none() {
        let path = config("cancel", 8 << 20);
        assert!(cancel_encrypt(&path).unwrap_err().contains("no encryption is marked"));
        begin_encrypt(&path).unwrap();
        cancel_encrypt(&path).unwrap();
        assert!(matches!(Record::read(&path), Ok(None)));
        assert!(!crate::in_place::marked(&File::open(&path).unwrap()).unwrap());
    }
}
