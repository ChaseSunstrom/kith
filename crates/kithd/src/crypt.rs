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
use std::time::Duration;

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
    /// Whether somebody was shown this disk's recovery key, or typed it.
    seen: bool,
    /// The public keys of the duress codes the cluster made for this node, and for all.
    duress: Option<Vec<u8>>,
    duress_all: Option<Vec<u8>>,
    peers: Vec<String>,
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
/// answer, by the machine's own TPM, or by its TPM and the PIN typed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum By {
    Owner,
    Recovery,
    Cluster,
    Tpm,
    Pin,
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
    let nonce: [u8; 12] = random();
    let mut sealed = key.to_vec();
    let nonced = aead::Nonce::assume_unique_for_key(nonce);
    let done = sealing(secret).seal_in_place_append_tag(nonced, aead::Aad::empty(), &mut sealed);
    done.expect("a key is short enough to seal");
    [&nonce[..], &sealed].concat()
}

fn unwrap(secret: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
    let (nonce, sealed) = wrapped.split_at_checked(12)?;
    let mut sealed = sealed.to_vec();
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
    let key = sealing(secret).open_in_place(nonce, aead::Aad::empty(), &mut sealed);
    key.ok().map(|key| key.to_vec())
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

impl Record {
    pub fn parse(bytes: &[u8]) -> Option<Record> {
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
            let (name, value) = line.split_once(": ")?;
            match name {
                "secret" => record.secret = unhex(value)?,
                "recovery" => record.recovery = unhex(value)?,
                "key" => record.key = Some(unhex(value)?),
                "tpm" => record.tpm = Some(unhex(value)?),
                "tpm-parent" => record.parent = Some(unhex(value).filter(|name| name.len() == 34).unwrap_or_default()),
                // (One that cannot be read opens nothing: the node asks as if it had none.)
                "passphrase" => record.pass = Pass::parse(value),
                "tpm-pin" => record.pin = Some(PinSeal::parse(value).unwrap_or_default()),
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
        if let Some(pin) = &self.pin {
            text += &format!("tpm-pin: {}\n", pin.text());
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

    /// The record of the node whose config partition is `config`, if its state is encrypted.
    /// A record that begins as one and cannot be read is an error: the state under it is
    /// not a file system to mount as it lies.
    pub fn read(config: &Path) -> Result<Option<Record>, String> {
        let mut bytes = vec![0; 2 * ROOM];
        let read = File::open(config).and_then(|config| config.read_exact_at(&mut bytes, AT));
        let (record, copy) = bytes.split_at(ROOM);
        // (The copy, where a write was cut in the record: it was written first.)
        Ok(match (read, Record::parse(record).or_else(|| Record::parse(copy))) {
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
        let mut back = vec![0; ROOM];
        let wrote = disk
            .write_all_at(&bytes, at + ROOM as u64)
            .and_then(|()| disk.sync_all())
            .and_then(|()| disk.write_all_at(&bytes, at))
            .and_then(|()| disk.sync_all());
        let read = wrote.and_then(|()| from_disk(disk, at).read_exact_at(&mut back, at));
        read.map_err(|e| format!("writing the lock record: {e}"))?;
        (back == bytes)
            .then_some(())
            .ok_or("the lock record did not stay on the disk as written".into())
    }

    /// What the cluster knows this disk by: says nothing of the secret it is made from.
    fn id(&self) -> String {
        hex(digest::digest(&digest::SHA256, &[b"kith-lock id", &self.secret[..]].concat()).as_ref())
    }
}

/// A device that the kernel has just made, opened: its name takes a moment to be there.
fn opened(device: &Path) -> std::io::Result<File> {
    for _ in 0..100 {
        match File::options().read(true).write(true).open(device) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::thread::sleep(Duration::from_millis(20)),
            opened => return opened,
        }
    }
    File::options().read(true).write(true).open(device)
}

/// The installer's part, once the image is on `disk`: write the state partition again,
/// through a key made here, and leave the lock record. Says the recovery key.
pub fn seal(image: &File, disk: &Path) -> Result<String, String> {
    let (at, length) = crate::install::named(image, "state")?;
    let (config, _) = crate::install::named(image, "config")?;
    let (key, secret, recovery): ([u8; 64], [u8; 32], [u8; 16]) = (random(), random(), random());
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
    // (Held for a moment after it is closed, at times.)
    let mut removed = kith_dm_sys::remove("kith-install");
    for _ in 0..50 {
        if removed.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
        removed = kith_dm_sys::remove("kith-install");
    }
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
    let record = Record {
        secret: secret.to_vec(),
        recovery: wrap(&recovery, &key),
        key: Some(key.to_vec()),
        tpm: None,
        parent: None,
        pass: None,
        pin: None,
        peers: Vec::new(),
        seen: false,
        duress: None,
        duress_all: None,
    };
    record.write(&disk, config + AT)?;
    Ok(shown(&recovery))
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
    Opens(Vec<u8>, By),
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
/// why not, as said at the console.
fn pin_way<T: std::io::Read + std::io::Write + Send + 'static>(
    seal: &PinSeal,
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
    let k1 = tpm
        .unseal(&seal.k1, parent)
        .map_err(|why| format!("this system is not the one the PIN's seal names, so no PIN is asked: {why}"))?;
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
        return Typed::Opens(key, By::Recovery);
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
        return Typed::Opens(key, By::Owner);
    }
    // (And a PIN last: a wrong one is counted. One the TPM refuses is said so, as the
    // right one is refused then too.)
    match pin.filter(|_| pin_shaped(line)).map(|pin| pin(line.as_bytes())) {
        Some(Ok(key)) => Typed::Opens(key, By::Pin),
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

/// A duress code that was typed: its key, for the cluster to be told with.
type Duressed = tokio::sync::watch::Sender<Option<Arc<ring::signature::Ed25519KeyPair>>>;

/// The waiting console: each of `lines` judged as it is read, until one opens the state.
/// A line that opens nothing is answered ([`ANSWER`] after it was read, by `say`) in the
/// same words whatever it was, and the next is judged meanwhile: a duress code does not
/// wait behind the answer to a wrong key. For a duress code the record is `erase`d
/// first (whether it is: tried again for as long as it is not) and `forget` is given its
/// key; nothing typed opens from then on. A PIN is tried by `pin`, if this node has one;
/// what was typed is zeroed once judged.
async fn console(
    mut record: Record,
    lines: std::sync::mpsc::Receiver<String>,
    say: impl Fn(&str),
    erase: impl Fn() -> bool,
    forget: &Duressed,
    mut pin: Option<Pin>,
) -> (Vec<u8>, By) {
    let (mut answers, mut erased) = (std::collections::VecDeque::new(), true);
    loop {
        while let Ok(line) = lines.try_recv() {
            let line = zeroize::Zeroizing::new(line);
            if line.is_empty() {
                continue;
            }
            let due = tokio::time::Instant::now() + ANSWER;
            let (judge, by) = (record.clone(), pin.clone());
            let judged = tokio::task::spawn_blocking(move || judged(&judge, &line, by.as_ref())).await;
            let gone = forget.borrow().is_some();
            let answer = match judged.unwrap_or(Typed::Wrong) {
                Typed::Opens(key, by) if !gone => return (key, by),
                Typed::Duress(pair) if !gone => {
                    erased = erase();
                    // (And from memory: what was typed before no longer opens either.)
                    (record.recovery, record.pass, pin) = (Vec::new(), None, None);
                    forget.send_replace(Some(Arc::new(pair)));
                    WRONG.to_string()
                }
                Typed::Refused(why) if !gone => format!("kithd: init: {why}"),
                _ => WRONG.to_string(),
            };
            answers.push_back((due, answer));
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
    let console = console(record.clone(), lines, |said| eprintln!("{said}"), erased, &forget, pin);
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

/// The seal the TPM opens `record`'s state by alone, if any: none where its key is still on
/// the disk, nor where a PIN guards it (a record with both lines, as the first PIN-setting
/// kithd could leave, never opens without the PIN).
fn tpm_alone(record: &Record) -> Option<&Vec<u8>> {
    record
        .tpm
        .as_ref()
        .filter(|_| record.key.is_none() && record.pin.is_none())
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
    let own = |sealed: &Vec<u8>| {
        match &record.parent {
            Some(name) if name.len() != 34 => return Err(UNREAD.to_string()),
            None => eprintln!(
                "kithd: init: this machine's TPM seal is of the old form (no tpm-parent: line): which storage key answers is not checked; once open, it is sealed again with its name"
            ),
            Some(_) => {}
        }
        crate::tpm::open().and_then(|mut tpm| tpm.unseal(sealed, record.parent.as_deref()))
    };
    let (key, by) = match (&record.key, tpm_alone(record).map(own)) {
        (Some(key), _) => {
            eprintln!(
                "kithd: init: the key of this node's encrypted state is still on its disk: no other node holds it yet"
            );
            (key.clone(), By::Owner)
        }
        (None, Some(Ok(key))) => {
            eprintln!("kithd: init: this machine's TPM gave the key of its state: no node was asked");
            (key, By::Tpm)
        }
        (None, refused) => {
            if let Some(Err(why)) = refused {
                eprintln!("kithd: init: {why}");
            }
            let pin =
                record
                    .pin
                    .as_ref()
                    .and_then(|seal| match pin_way(seal, record.parent.as_deref(), crate::tpm::open) {
                        Ok(pin) => Some(pin),
                        Err(why) => {
                            eprintln!("kithd: init: {why}");
                            None
                        }
                    });
            fetched(record, config, join, pin).await
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
/// passphrase and a PIN until the node is locked or forgotten (`shut`). The storage key's
/// name stays while either seal it checks may: a PIN's seal is checked by it as well.
fn ways_left(record: &Record, seal: bool, shut: bool) -> Record {
    let pin = record.pin.clone().filter(|_| !shut);
    Record {
        // (Beside a PIN, a plain seal would open the state with no PIN typed.)
        tpm: record.tpm.clone().filter(|_| seal && pin.is_none()),
        parent: record.parent.clone().filter(|_| seal || pin.is_some()),
        pass: record.pass.clone().filter(|_| !shut),
        pin,
        ..record.clone()
    }
}

/// What a `tpm-parent:` line that cannot be read is: present, so the seal beside it is not
/// opened without the check it stands for.
const UNREAD: &str = "the lock record's tpm-parent: line cannot be read, so its TPM seal is not opened (kith node seal NAME --off, then kith node seal NAME, makes a new one)";

/// `opened` sealed by this machine's TPM again (under the storage key whose name `record`
/// keeps, if it keeps one), written in place of `record`'s seal in one write, read back,
/// and unsealed from what was read: the record as it now is. When that does not open,
/// `record` is written back as it was.
fn sealed_anew<T: std::io::Read + std::io::Write>(
    tpm: &mut crate::tpm::Tpm<T>,
    record: &Record,
    opened: &[u8],
    config: &Path,
) -> Result<Record, String> {
    if record.parent.as_ref().is_some_and(|name| name.len() != 34) {
        return Err(UNREAD.into());
    }
    let (sealed, parent) = tpm.seal(opened, record.parent.as_deref())?;
    let with = Record {
        tpm: Some(sealed),
        parent: Some(parent),
        ..record.clone()
    };
    tried(record, &with, config, |back| {
        let key = tpm.unseal(back.tpm.as_deref().unwrap_or_default(), back.parent.as_deref())?;
        (key == opened)
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
/// away), a PIN (the same), or a new recovery key.
enum Change {
    Passphrase(Option<String>),
    Pin(Option<zeroize::Zeroizing<String>>),
    Recovery,
}

/// A change, and where to say how it went (a new recovery key: the key, as shown): from
/// [`pass`] and [`recovery`] to [`keep`], which alone writes the record.
type Chosen = (Change, tokio::sync::oneshot::Sender<Result<Option<String>, String>>);
static CHOSEN: std::sync::OnceLock<tokio::sync::mpsc::Sender<Chosen>> = std::sync::OnceLock::new();

/// For as long as the node runs: have the cluster hold the key and take it off the disk
/// once another node does; restart when the cluster locks this node, and end when it
/// wipes it. `opened`: the key the state was opened with, and who gave it at this start
/// (the cluster: so it was not locked). A NodeKey that is gone, or was written over with
/// what is not this key, is given again: without it the next start has no key.
///
/// And the TPM's seal: made while the cluster's NodeKey says `seal` and the node is not
/// locked (again after a start the TPM refused: the system is another now), dropped as
/// soon as it says otherwise; the NodeKey's status says which, and why not.
///
/// And the passphrase: its line is written when one is given ([`pass`]), and dropped when
/// one is taken away or the cluster locks this node.
pub async fn keep(
    shared: Arc<Shared>,
    config: PathBuf,
    mut record: Record,
    (opened, by): (Vec<u8>, By),
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
    let mut was_locked = (!matches!(by, By::Owner | By::Recovery)).then_some(false);
    // Whether the record's seal is one this system opens, and why none could be made.
    let (mut fits, mut unsealed) = (by == By::Tpm, None::<String>);
    let (chosen, mut chosen_here) = tokio::sync::mpsc::channel::<Chosen>(1);
    let _ = CHOSEN.set(chosen);
    let mut shut = false;
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
        match (&mine, &record.key) {
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
                    (record.tpm, record.parent, record.pass) = (left.tpm, left.parent, left.pass);
                    record.pin = left.pin;
                    (record.duress, record.duress_all) = (left.duress, left.duress_all);
                }
                // (A seal that could not be dropped is tried again: restarted beside it,
                // the node would open by its TPM, locked or not. And so a passphrase.)
                if locked
                    && was_locked == Some(false)
                    && record.tpm.is_none()
                    && record.pass.is_none()
                    && record.pin.is_none()
                {
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
                        if asked(&client, peer, &record).await.as_ref() == Ok(key) {
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
                    record.peers = peers;
                    write(&record);
                }
                // (Once the key is off the disk: beside it, a seal keeps nothing. A seal of
                // the old form, with no storage key's name, is made again with it. Beside a
                // PIN, none: it would open the state with no PIN typed.)
                let due = seal
                    && record.key.is_none()
                    && record.pin.is_none()
                    && !(fits && record.tpm.is_some() && record.parent.is_some());
                if due && unsealed.is_none() {
                    let tpm = crate::tpm::open();
                    let kept = tpm.and_then(|mut tpm| sealed_anew(&mut tpm, &record, &opened, &config));
                    match kept {
                        Ok(with) => {
                            eprintln!(
                                "kithd: this machine's TPM holds the key of its state, for this system: it opens with no node asked"
                            );
                            (record, fits) = (with, true);
                        }
                        Err(why) => {
                            eprintln!("kithd: the key of this node's state is not sealed: {why}");
                            unsealed = Some(why);
                        }
                    }
                }
                let sealed = record.tpm.is_some();
                let mut status = match unsealed.as_ref().filter(|_| seal && !sealed) {
                    Some(why) => json!({ "sealed": false, "message": why }),
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
                    let with = Record { pin: None, ..record.clone() };
                    let wrote = write(&with);
                    if wrote {
                        record = with;
                    }
                    let _ = done.send(wrote.then_some(None).ok_or("the lock record could not be written".into()));
                }
                Change::Pin(Some(_)) if shut => {
                    let _ = done.send(Err("the cluster does not hand this node's key out (locked, or forgotten): unlock it first".into()));
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
                let deleted = shared.submit(Command::Delete { key }).await;
                let said = json!({ "node": name, "locked": false, "wiped": false, "seal": false });
                return deleted.map(|_| said).map_err(|e| e.to_string());
            }
            "wipe" => {}
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
        let applied = shared.submit(Command::Apply { resources, at }).await;
        stays_forgotten(&shared, &applied.map_err(|e| e.to_string())?).await?;
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
async fn stays_forgotten(shared: &Shared, done: &kith_store::Done) -> Result<(), String> {
    let back = put_back(done);
    if back.is_empty() {
        return Ok(());
    }
    let names: Vec<String> = back.iter().map(|key| key.metadata.name.clone()).collect();
    let (resources, at) = (back, kith_api::store::now());
    let again = shared.submit(Command::Apply { resources, at }).await;
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
    let mut keys: Vec<kith_api::Resource> = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        state
            .store
            .list(Some("NodeKey"))
            .filter(|key| !gone(key))
            .cloned()
            .collect()
    };
    let unseen = never_shown(&keys);
    if !off && !unseen.is_empty() {
        let why = format!(
            "nobody was shown the recovery key of {}: `kith node recovery NAME` shows a new one, and with the cluster's key forgotten it alone opens a node",
            unseen.join(", ")
        );
        return refuse(StatusCode::CONFLICT, why).into_response();
    }
    for key in &mut keys {
        match (off, key.spec.as_object_mut()) {
            (true, Some(spec)) => drop(spec.remove("duressAll")),
            _ => key.spec["duressAll"] = public.clone().into(),
        }
    }
    let names: Vec<String> = keys.iter().map(|key| key.metadata.name.clone()).collect();
    let what = if off {
        "no duress code for all"
    } else {
        "duress code for all"
    };
    let done = async {
        if keys.is_empty() {
            return Err("the cluster holds no node's key: no node's state is encrypted".to_string());
        }
        let applied = shared
            .submit(Command::Apply {
                resources: keys,
                at: kith_api::store::now(),
            })
            .await;
        stays_forgotten(&shared, &applied.map_err(|e| e.to_string())?).await
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
    // cluster's code has its record still, and its recovery key: forgotten. Its own
    // code stays with it: typed at it later, that still erases its record.)
    let without = |key: &kith_api::Resource| {
        let mut spec = json!({ "id": key.spec["id"] });
        match key.spec["id"] == id {
            true => spec["wiped"] = true.into(),
            false => {
                spec["forgotten"] = true.into();
                if let Some(own) = key.spec.get("duress") {
                    spec["duress"] = own.clone();
                }
            }
        }
        kith_api::Resource { spec, ..key.clone() }
    };
    let live = || store.list(Some("NodeKey")).filter(|key| !gone(key));
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
    let applied = shared.submit(Command::Apply { resources, at }).await;
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

    fn holds(bytes: &[u8], secret: &[u8]) -> bool {
        bytes.windows(secret.len()).any(|window| window == secret)
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
        let way = pin_way(&seal, with.parent.as_deref(), || Ok(Tpm(wire))).unwrap();
        let opens = |line: &str| judged(&with, line, Some(&way));
        assert!(matches!(opens(pin), Typed::Opens(opened, By::Pin) if opened == key));
        assert!(matches!(opens("40917254"), Typed::Wrong));
        // (Not a PIN's shape: not tried, not counted.)
        assert!(matches!(opens("40917"), Typed::Wrong) && matches!(opens("4091725x"), Typed::Wrong));
        assert!(matches!(opens("00000000"), Typed::Wrong));
        match opens(pin) {
            Typed::Refused(why) => assert_eq!(why, format!("{LOCKED_OUT}: the next is taken within 40 seconds")),
            _ => panic!("the right PIN opened while the TPM refused every PIN"),
        }
        assert!(matches!(opens(&shown(&recovery)), Typed::Opens(opened, By::Recovery) if opened == key));
        drop(way);

        // Another system (a PCR moved): no PIN is asked, so none is counted.
        let mut tpm = Tpm(software.wire());
        tests::measured(&mut tpm);
        let counted = tpm.lockout().unwrap().counter;
        let Tpm(wire) = tpm;
        let refused = pin_way(&seal, with.parent.as_deref(), || Ok(Tpm(wire))).err().unwrap();
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
        let waiting = console(record.clone(), lines, &say, &|| true, &told, Some(pin.clone()));
        assert!(tokio::time::timeout(Duration::from_secs(60), waiting).await.is_err());
        let refused = format!(
            "kithd: init: {}: the next is taken within 40 seconds",
            crate::tpm::LOCKED_OUT
        );
        assert_eq!(*said.borrow(), [WRONG, refused.as_str(), WRONG, WRONG]);
        assert_eq!(*tried.lock().unwrap(), ["40917254", "40917253"]);
        let (type_it, lines) = std::sync::mpsc::channel();
        type_it.send("11111111".to_string()).unwrap();
        let opened = console(record, lines, &say, &|| true, &told, Some(pin)).await;
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
        assert_eq!(tpm_alone(&record), None);
        let alone = Record {
            pin: None,
            ..record.clone()
        };
        assert_eq!(tpm_alone(&alone), alone.tpm.as_ref());
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
            pin: Some(PinSeal {
                k1: vec![1; 200],
                k2: vec![2; 200],
                wrapped: vec![3; 104],
            }),
            peers: vec!["10.0.0.1:7443".into(), "[fd00::2]:7443".into()],
        };
        // A tpm-pin: that cannot be read counts as there, and asks no PIN; the rest is read.
        let unread = b"kith-lock v1\nsecret: 0707070707070707070707070707070707070707070707070707070707070707\ntpm-pin: 00 zz\nduress: 0606\n"; // pragma: allowlist secret
        let unread = Record::parse(unread).unwrap();
        assert_eq!(unread.pin, Some(PinSeal::default()));
        assert!(pin_way::<File>(&PinSeal::default(), Some(&[0; 34]), || unreachable!()).is_err());
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
        let waiting = console(record.clone(), lines, &say, &erase, &told, None);
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
            opened = console(record.clone(), lines, &say, &erase, &told, None) => opened,
            () = later => unreachable!(),
        };
        assert_eq!(opened, (key.to_vec(), By::Recovery));
        assert_eq!(*said.borrow(), [(began + ANSWER, WRONG.to_string())]);
        assert_eq!(erased.get(), 3);
        // A record that names no duress code takes that code for a wrong key.
        let none = Record { duress: None, ..record };
        assert!(matches!(judged(&none, &duress, None), Typed::Wrong));
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
        let forgotten = json!({ "id": "bb", "forgotten": true, "duress": bs_public });
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
        // And a code that was used forgets nothing more.
        assert!(keys(&store, "aa", &pair).is_empty() && keys(&store, "bb", &pair).is_empty());
        // b, forgotten, has its own code still: typed at b, its record goes too (wiped).
        let gone = ("b".to_string(), json!({ "id": "bb", "wiped": true }));
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
        assert!(matches!(judged(&record, &shown(&old), None), Typed::Opens(opened, By::Recovery) if opened == key));
        let (with, new) = renewed(&record, &key);
        assert!(matches!(judged(&with, &new, None), Typed::Opens(opened, By::Recovery) if opened == key));
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
