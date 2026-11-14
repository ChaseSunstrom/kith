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
/// and how long it may be.
pub const AT: u64 = 512 << 10;
const ROOM: usize = 4096;
const FIRST: &str = "kith-lock v1";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
    secret: Vec<u8>,
    recovery: Vec<u8>,
    key: Option<Vec<u8>>,
    /// The key as this machine's TPM sealed it (tpm.rs).
    tpm: Option<Vec<u8>>,
    peers: Vec<String>,
}

/// How a state was opened at a start: by its owner (the key was still on the disk, or
/// the recovery key was typed), by the cluster's answer, or by the machine's own TPM.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum By {
    Owner,
    Cluster,
    Tpm,
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |byte: &u8| (*byte as char).to_digit(16).map(|digit| digit as u8);
    let (pairs, rest) = text.trim().as_bytes().as_chunks::<2>();
    let bytes = pairs.iter().map(|[high, low]| Some(digit(high)? << 4 | digit(low)?));
    rest.is_empty().then(|| bytes.collect())?
}

fn random<const N: usize>() -> [u8; N] {
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
        // (Before the peers: what does not fit the record's room is cut from its end.)
        if let Some(sealed) = &self.tpm {
            text += &format!("tpm: {}\n", hex(sealed));
        }
        if !self.peers.is_empty() {
            text += &format!("peers: {}\n", self.peers.join(" "));
        }
        text
    }

    /// The record of the node whose config partition is `config`, if its state is encrypted.
    /// A record that begins as one and cannot be read is an error: the state under it is
    /// not a file system to mount as it lies.
    pub fn read(config: &Path) -> Result<Option<Record>, String> {
        let mut bytes = vec![0; ROOM];
        let read = File::open(config).and_then(|config| config.read_exact_at(&mut bytes, AT));
        Ok(match (read, Record::parse(&bytes)) {
            (Ok(()), None) if bytes.starts_with(FIRST.as_bytes()) => {
                return Err("this node's state is encrypted, and its lock record is damaged".into());
            }
            (Ok(()), record) => record,
            (Err(_), _) => None,
        })
    }

    /// Write it `at` this place of `disk` (a config partition's start and [`AT`]), over
    /// all of what was there, and read it back.
    fn write(&self, disk: &File, at: u64) -> Result<(), String> {
        let mut bytes = self.text().into_bytes();
        // (A zero ends it, so one byte less than the room; peers past it are left out.)
        bytes.truncate(ROOM - 1);
        bytes.resize(ROOM, 0);
        let mut back = vec![0; ROOM];
        let wrote = disk.write_all_at(&bytes, at).and_then(|()| disk.sync_all());
        let read = wrote.and_then(|()| disk.read_exact_at(&mut back, at));
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
        peers: Vec::new(),
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
        return Err(format!(
            "{peer} does not hand this node's key out: it is locked (`kith node unlock`), wiped, or not known there"
        ));
    }
    let said = reply.json::<Value>().await.ok();
    let wrapped = said.and_then(|said| unhex(said["wrapped"].as_str()?));
    let key = wrapped.and_then(|wrapped| unwrap(&record.secret, &wrapped));
    key.ok_or(format!("what {peer} answered is not this node's key"))
}

/// The key, from the cluster or from whoever types the recovery key: asked until one
/// gives it. And which did.
async fn fetched(record: &Record, join: Option<&String>) -> (Vec<u8>, By) {
    let (client, lines) = (client(), crate::install::keyboard());
    // (Read all the while: a peer that does not answer takes its time to say so.)
    let console = async {
        loop {
            while let Ok(line) = lines.try_recv() {
                match typed(&line).and_then(|recovery| unwrap(&recovery, &record.recovery)) {
                    Some(key) => return key,
                    None if !line.is_empty() => eprintln!("kithd: init: that is not this node's recovery key"),
                    None => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let cluster = async {
        let mut said = String::new();
        loop {
            let mut why = "it knows of no node to ask".to_string();
            for peer in record.peers.iter().chain(join) {
                match asked(&client, peer, record).await {
                    Ok(key) => return key,
                    Err(e) => why = e,
                }
            }
            if why != said {
                eprintln!("kithd: init: still locked: {why}");
                said = why;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    };
    eprintln!(
        "kithd: init: this node's state is encrypted: asking the cluster for its key. (Or type the recovery key here.)"
    );
    tokio::select! {
        key = cluster => (key, By::Cluster),
        key = console => {
            eprintln!("kithd: init: opened with the recovery key");
            (key, By::Owner)
        }
    }
}

/// Open and mount the state of a node that has `record`. Returns once it is mounted,
/// however long the key takes to come: the key, and who gave it.
pub async fn open(record: &Record, join: Option<&String>) -> Result<(Vec<u8>, By), String> {
    let device = init::labelled("state").ok_or("this node's state is encrypted, and no partition is labelled state")?;
    let name = device.file_name().unwrap_or_default().to_string_lossy();
    let sectors = std::fs::read_to_string(format!("/sys/class/block/{name}/size"));
    let sectors = sectors.ok().and_then(|size| size.trim().parse::<u64>().ok());
    let sectors = sectors.ok_or(format!("{}: how long is it?", device.display()))?;
    // (The TPM is asked first: it answers at once, and where no node is in reach.)
    let own = |sealed: &Vec<u8>| crate::tpm::open().and_then(|mut tpm| tpm.unseal(sealed));
    let sealed = record.tpm.as_ref().filter(|_| record.key.is_none());
    let (key, by) = match (&record.key, sealed.map(own)) {
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
            fetched(record, join).await
        }
    };
    let mapped = kith_dm_sys::crypt("kith-state", &device, 0, sectors, &key);
    let mapped = mapped.map_err(|e| format!("opening {} under its key: {e}", device.display()))?;
    drop(opened(&mapped));
    init::mount_state(&mapped);
    Ok((key, by))
}

/// For as long as the node runs: have the cluster hold the key and take it off the disk
/// once another node does; restart when the cluster locks this node, and end when it
/// wipes it. `opened`: the key the state was opened with, and who gave it at this start
/// (the cluster: so it was not locked). A NodeKey that is gone, or was written over with
/// what is not this key, is given again: without it the next start has no key.
///
/// And the TPM's seal: made while the cluster's NodeKey says `seal` and the node is not
/// locked (again after a start the TPM refused: the system is another now), dropped as
/// soon as it says otherwise; the NodeKey's status says which, and why not.
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
    let mut was_locked = (by != By::Owner).then_some(false);
    // Whether the record's seal is one this system opens, and why none could be made.
    let (mut fits, mut unsealed) = (by == By::Tpm, None::<String>);
    loop {
        let (mine, peers) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let this = |key: &&kith_api::Resource| {
                let wrapped = key.spec["wrapped"].as_str().and_then(unhex);
                let key_held = wrapped.and_then(|wrapped| unwrap(&record.secret, &wrapped));
                key.spec["id"] == id.as_str() && (key.spec["wiped"] == true || key_held.as_ref() == Some(&opened))
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
        match (&mine, &record.key) {
            (Some(spec), _) if spec["wiped"] == true => {
                eprintln!(
                    "kithd: the cluster has wiped this node: its lock record is erased and its state can no longer be opened"
                );
                let none = File::options().write(true).open(&config);
                let erased = none.and_then(|disk| disk.write_all_at(&[0; ROOM], AT).and_then(|()| disk.sync_all()));
                if let Err(e) = erased {
                    eprintln!("kithd: erasing the lock record: {e}");
                }
                init::POWER_OFF.store(true, std::sync::atomic::Ordering::Relaxed);
                shared.stop.send_replace(true);
                return;
            }
            (Some(spec), key) => {
                let locked = spec["locked"] == true;
                let seal = spec["seal"] == true && !locked;
                if !seal && record.tpm.is_some() {
                    let plain = Record {
                        tpm: None,
                        ..record.clone()
                    };
                    if write(&plain) {
                        eprintln!("kithd: this machine's TPM no longer holds the key of its state");
                        record.tpm = None;
                    }
                }
                // (A seal that could not be dropped is tried again: restarted beside it,
                // the node would open by its TPM, locked or not.)
                if locked && was_locked == Some(false) && record.tpm.is_none() {
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
                // (Once the key is off the disk: beside it, a seal keeps nothing.)
                let due = seal && record.key.is_none() && !(fits && record.tpm.is_some());
                if due && unsealed.is_none() {
                    let sealed = crate::tpm::open().and_then(|mut tpm| tpm.seal(&opened));
                    let kept = sealed.and_then(|sealed| {
                        let with = Record {
                            tpm: Some(sealed),
                            ..record.clone()
                        };
                        write(&with)
                            .then_some(with)
                            .ok_or("the lock record could not be written".into())
                    });
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
                let status = match unsealed.as_ref().filter(|_| seal && !sealed) {
                    Some(why) => json!({ "sealed": false, "message": why }),
                    None => json!({ "sealed": sealed }),
                };
                if said.flatten() != Some(status.clone()) {
                    let statuses = vec![(me.clone(), Some(status))];
                    if let Err(e) = shared.submit(Command::Status { statuses }).await {
                        eprintln!("kithd: saying whether this node's key is sealed: {e}");
                    }
                }
            }
            (None, _) => {
                let spec = json!({ "id": id, "wrapped": hex(&wrap(&record.secret, &opened)) });
                let held = json!({
                    "apiVersion": "kith.dev/v1", "kind": "NodeKey",
                    "metadata": { "name": cluster.me.name }, "spec": spec,
                });
                let resources = vec![serde_json::from_value(held).expect("a NodeKey")];
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
        }
    }
}

/// The node and wrapped key the store hands out for the disk of this `id`. Every NodeKey
/// of that id is asked: a second one, written beside a locked one, opens nothing.
fn handed_out<'a>(store: &'a kith_api::store::Store, id: &str) -> Option<(&'a str, &'a str)> {
    let held = || store.list(Some("NodeKey")).filter(|key| key.spec["id"] == id);
    let shut = held().any(|key| key.spec["locked"] == true || key.spec["wiped"] == true);
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

/// `POST /v1/lock/NAME?do=lock|unlock|wipe|seal|unseal` (`kith node lock`, `unlock`,
/// `wipe`, `seal`): for who may apply NodeKeys.
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
        match what {
            "lock" => held.spec["locked"] = true.into(),
            "unlock" if wiped => return Err(format!("{name} was wiped: its key is gone")),
            "unlock" => drop(held.spec.as_object_mut().and_then(|spec| spec.remove("locked"))),
            "wipe" => held.spec = json!({ "id": held.spec["id"], "wiped": true }),
            "seal" if wiped => return Err(format!("{name} was wiped: its key is gone")),
            "seal" => held.spec["seal"] = true.into(),
            "unseal" => drop(held.spec.as_object_mut().and_then(|spec| spec.remove("seal"))),
            _ => return Err("do=lock, unlock, wipe, seal or unseal".to_string()),
        }
        let said = json!({
            "node": name, "locked": held.spec["locked"] == true, "wiped": held.spec["wiped"] == true,
            "seal": held.spec["seal"] == true,
        });
        let (resources, at) = (vec![held], kith_api::store::now());
        let applied = shared.submit(Command::Apply { resources, at }).await;
        applied.map(|_| said).map_err(|e| e.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn crypt_records_are_read_as_written() {
        let record = Record {
            secret: vec![7; 32],
            recovery: vec![1, 2, 3],
            key: Some(vec![9; 64]),
            tpm: Some(vec![5; 300]),
            peers: vec!["10.0.0.1:7443".into(), "[fd00::2]:7443".into()],
        };
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
        assert!(read.tpm == held.tpm && read.peers.len() > 100 && read.peers.len() < 400);
        assert_ne!(held.id(), hex(&held.secret));

        // Nothing there, another format, a secret that is not one: no record.
        assert_eq!(Record::parse(&[0; ROOM]), None);
        assert_eq!(Record::parse(b"kith-lock v2\nsecret: 00\n"), None);
        assert_eq!(Record::parse(b"kith-lock v1\nsecret: 0707\n"), None);
        assert_eq!(Record::parse(b"kith-lock v1\nsecret: zz\n"), None);
        // On a disk, a record that begins as one and is not one is an error, not a plain state.
        disk.write_all_at(b"kith-lock v1\nsecret: zz\n\0", AT).unwrap();
        let path = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&disk));
        assert!(Record::read(Path::new(&path)).is_err());
        disk.write_all_at(&[0; ROOM], AT).unwrap();
        assert_eq!(Record::read(Path::new(&path)), Ok(None));
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
}
