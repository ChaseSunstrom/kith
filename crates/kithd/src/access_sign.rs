//! Signed callers (docs/adr-taken-node.md, "What a signature binds"): a node's word for who
//! asked is taken, under the Cluster's `spec.signing: required`, only with the asker's own
//! signature over the request, passed on unchanged. A taken node can still name anyone; it
//! cannot sign as them.
//!
//! The header: `x-kith-signed: v1; who=<name>; target=<node or *>; expires=<seconds>;
//! nonce=<32 hex>; sig=<base64>`, over [`bytes`]. `who` is "local socket" (checked against
//! the Cluster's `spec.adminKey`, Ed25519) or an Identity (its `publicKey`, P-256 ECDSA).

use crate::Shared;
use crate::access::Caller;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use kith_api::Resource;
use kith_api::store::Store;
use kith_store::Command;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

/// The header a signer puts on its request, and every node passes on unchanged.
pub const SIGNED: &str = "x-kith-signed";

/// How far past this node's clock a signature may say it lasts: a signer's clock that runs
/// fast. Past it the header is refused, so the nonce cache holds at most this long.
const AHEAD: u64 = 600;

/// The most of a signed request's body held to be hashed: the largest any route takes
/// (`/v1/netboot`).
// ponytail: a signed body is held whole while it is checked; hash it as it streams if large
// signed uploads become common.
const LIMIT: usize = 96 << 20;

/// The MiB of signed bodies held at once before their signatures are checked: callers whose
/// signatures do not hold (a taken node sending many large ones) wait for each other here,
/// instead of each holding [`LIMIT`].
static HOLDING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(128);

/// The MiB a body takes from [`HOLDING`] while it is read: what its `Content-Length` says, or
/// [`LIMIT`] where it says none; and the most of it read.
fn held(length: Option<&str>) -> (u32, usize) {
    let bytes = length
        .and_then(|length| length.parse().ok())
        .unwrap_or(LIMIT)
        .min(LIMIT);
    (bytes.div_ceil(1 << 20).max(1) as u32, bytes)
}

/// Why an unsigned hop is refused under `required`, naming the node that passed it.
pub fn unsigned(node: &str) -> String {
    format!(
        "refused: an unsigned caller passed on by node {node}; this cluster requires a signed one \
         (spec.signing: required), so update kith on {node}"
    )
}

/// The nonces this node has taken, each until the signature it came with expires: one seen
/// is refused. Held in memory, bounded by what comes in [`AHEAD`] seconds.
#[derive(Default)]
pub struct Nonces(Mutex<HashMap<String, u64>>);

impl Nonces {
    /// Takes `nonce`, good until `expires`: false where it was taken already.
    fn take(&self, nonce: &str, expires: u64, now: u64) -> bool {
        let mut seen = self.0.lock().expect("nothing panics holding the nonces");
        seen.retain(|_, until| *until >= now);
        match seen.contains_key(nonce) {
            true => false,
            false => seen.insert(nonce.to_string(), expires).is_none(),
        }
    }
}

/// The request a signature is checked against: as it came, before anything reads it.
pub struct Asked<'a> {
    pub method: &'a str,
    /// The path and query, as sent.
    pub path: &'a str,
    pub body: &'a [u8],
}

/// A header read ([`kith_store::header`]: a signed entry in the log carries one too), and
/// its signature decoded.
fn parse(header: &str) -> Result<(kith_store::Header<'_>, Vec<u8>), String> {
    let read = kith_store::header(header)?;
    let sig = base64::engine::general_purpose::STANDARD.decode(read.sig);
    let sig = sig.map_err(|e| format!("{SIGNED}: sig is not base64: {e}"))?;
    Ok((read, sig))
}

/// The bytes a signature is over, each field ending in one `\n`.
pub fn bytes(cluster: &str, target: &str, asked: &Asked, who: &str, expires: u64, nonce: &str) -> String {
    let body = crate::pki::hex(ring::digest::digest(&ring::digest::SHA256, asked.body).as_ref());
    let (method, path) = (asked.method, asked.path);
    format!("kith-signed-v1\n{cluster}\n{target}\n{method}\n{path}\n{body}\n{who}\n{expires}\n{nonce}\n")
}

/// The admin's keys: every Cluster's `spec.adminKey`.
fn admin_keys<'a>(clusters: impl Iterator<Item = &'a serde_json::Value>) -> BTreeSet<String> {
    let keys = clusters.filter_map(|spec| spec["adminKey"].as_str());
    keys.map(str::to_string).collect()
}

/// Does a Cluster say `spec.signing: required`?
pub fn required(store: &Store) -> bool {
    store
        .list(Some("Cluster"))
        .any(|cluster| cluster.spec["signing"] == "required")
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |b: u8| (b as char).to_digit(16);
    let pairs = text.as_bytes().chunks(2);
    pairs
        .map(|pair| Some((digit(pair[0])? * 16 + digit(*pair.get(1)?)?) as u8))
        .collect()
}

/// The DER of a P-256 public key's SubjectPublicKeyInfo, before the point.
const P256: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

type Key = (&'static dyn VerificationAlgorithm, Vec<u8>);

/// Who `who` is, and the keys that sign as them.
fn keys(store: &Store, who: &str) -> Result<(Caller, Vec<Key>), String> {
    use rustls::pki_types::pem::PemObject;
    match Caller::named(who) {
        Some(Caller::Admin) => {
            let keys = admin_keys(store.list(Some("Cluster")).map(|cluster| &cluster.spec));
            let keys: Vec<Key> = keys
                .iter()
                .filter_map(|key| unhex(key))
                .map(|key| (&signature::ED25519 as _, key))
                .collect();
            match keys.is_empty() {
                true => Err("no Cluster has spec.adminKey: nothing is signed as the local socket".into()),
                false => Ok((Caller::Admin, keys)),
            }
        }
        Some(Caller::Identity(name)) => {
            let identity = store.get(&format!("Identity/{name}"));
            let pem = identity.and_then(|identity| identity.spec["publicKey"].as_str());
            let spki =
                pem.and_then(|pem| rustls::pki_types::SubjectPublicKeyInfoDer::from_pem_slice(pem.as_bytes()).ok());
            let point = spki.and_then(|spki| Some(spki.as_ref().strip_prefix(&P256[..])?.to_vec()));
            match point {
                Some(point) => Ok((
                    Caller::Identity(name),
                    vec![(&signature::ECDSA_P256_SHA256_ASN1 as _, point)],
                )),
                None => Err(format!(
                    "who={name}: there is no Identity {name} with a P-256 publicKey"
                )),
            }
        }
        _ => Err(format!("who={who:?}: only the local socket and an Identity sign yet")),
    }
}

/// Who signed `header` for this request, to one of `targets`, on the cluster `cluster` (its
/// id: the SHA-256 print of its CA certificate), by `store`'s keys, and the header read; or why
/// the signature does not hold. The signature alone: no clock and no nonce, so every node that
/// asks it of a signed entry in the log decides alike ([`admit`]).
pub fn signature<'a>(
    header: &'a str,
    cluster: &str,
    targets: &[&str],
    asked: &Asked,
    store: &Store,
) -> Result<(Caller, kith_store::Header<'a>), String> {
    let (signed, sig) = parse(header)?;
    if !targets.contains(&signed.target) {
        return Err(format!(
            "signed for {}, not for {}",
            signed.target,
            targets.join(" or ")
        ));
    }
    let (caller, keys) = keys(store, signed.who)?;
    let message = bytes(cluster, signed.target, asked, signed.who, signed.expires, signed.nonce);
    let holds = |(algorithm, key): &Key| {
        UnparsedPublicKey::new(*algorithm, key)
            .verify(message.as_bytes(), &sig)
            .is_ok()
    };
    if !keys.iter().any(holds) {
        return Err(format!("the signature is not {}'s over this request", signed.who));
    }
    Ok((caller, signed))
}

/// [`signature`], and at the edge `now` and this node's `nonces` too: a signature that has
/// expired, lasts too far ahead or was used already does not hold. The nonce is taken only
/// once all else holds.
pub fn verify(
    header: &str,
    cluster: &str,
    targets: &[&str],
    asked: &Asked,
    store: &Store,
    now: u64,
    nonces: &Nonces,
) -> Result<Caller, String> {
    let (caller, signed) = signature(header, cluster, targets, asked, store)?;
    if signed.expires < now {
        return Err(format!("the signature expired {} s ago", now - signed.expires));
    }
    if signed.expires > now + AHEAD {
        return Err(format!(
            "the signature lasts past this node's clock by more than {AHEAD} s"
        ));
    }
    if !nonces.take(signed.nonce, signed.expires, now) {
        return Err("the signature was used already".into());
    }
    Ok(caller)
}

/// `text` with each `%XX` read as the byte it stands for, as the router reads a path's key; a
/// `%` that is not of two hex digits, or bytes that are not UTF-8, refuse it.
fn unescaped(text: &str) -> Result<String, String> {
    let (bytes, mut read) = (text.as_bytes(), Vec::with_capacity(text.len()));
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'%' {
            read.push(bytes[at]);
            at += 1;
            continue;
        }
        let byte = bytes
            .get(at + 1..at + 3)
            .and_then(|hex| unhex(std::str::from_utf8(hex).ok()?));
        let byte = byte.ok_or_else(|| format!("{text}: a % that is not two hex digits"))?;
        read.extend(byte);
        at += 3;
    }
    String::from_utf8(read).map_err(|e| format!("{text}: {e}"))
}

/// What a route's query may say.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Options {
    #[serde(default)]
    dry_run: bool,
    to: Option<u64>,
}

/// The change `method` on `path` with `body` makes of `store` for `signer`, as `api.rs`'s apply,
/// delete and rollback routes make it (before a kind's admission, and with `at` 0): what a
/// signed entry's command must be. Any other route makes none.
fn derived(store: &Store, signer: &Caller, method: &str, path: &str, body: &[u8]) -> Result<Command, String> {
    let uri: axum::http::Uri = path.parse().map_err(|e| format!("{path}: {e}"))?;
    let query = axum::extract::Query::<Options>::try_from_uri(&uri);
    let options = query.map_err(|e| format!("{path}: {}", e.body_text()))?.0;
    let route = uri.path();
    let applied = |resources: Vec<Resource>| -> Result<Command, String> {
        resources.iter().try_for_each(Resource::submitted_by_node)?;
        let resources = crate::api::stamped(store, signer, resources);
        Ok(Command::Apply { resources, at: 0 })
    };
    match method {
        "POST" if route == "/v1/apply" => {
            if options.dry_run {
                return Err("a dry run writes nothing".into());
            }
            let read = serde_json::from_slice(body).map_err(|e| format!("the body is not resources: {e}"));
            applied(read?)
        }
        "DELETE" if let Some(key) = route.strip_prefix("/v1/resources/") => {
            Ok(Command::Delete { key: unescaped(key)? })
        }
        "POST" if let Some(key) = route.strip_prefix("/v1/rollback/") => {
            let (key, to) = (unescaped(key)?, options.to.ok_or("a rollback names no revision (to)")?);
            if key.starts_with("NodeKey/") {
                return Err("a NodeKey is not rolled back".into());
            }
            if !["Release/", "Source/", "KindDefinition/", "Package/"]
                .iter()
                .any(|kind| key.starts_with(kind))
            {
                return Ok(Command::Rollback { key, to, at: 0 });
            }
            let history = store.history(&key).map_err(|e| e.to_string())?;
            let was = history.iter().find(|was| was.resource.metadata.revision == Some(to));
            let mut was = was
                .ok_or_else(|| format!("{key} has no revision {to}"))?
                .resource
                .clone();
            was.metadata.revision = None;
            applied(vec![was])
        }
        _ => Err(format!("{method} {route} is not a change a signed entry carries")),
    }
}

/// Is `carried` the change `derived` is? An apply's `at` is the leader's, and what a kind's
/// admission module may rewrite (a custom resource's spec, labels and annotations) is taken as
/// carried; all else is as derived.
fn same(store: &Store, derived: Command, carried: &Command) -> Result<(), String> {
    let differs = || "the command it carries is not what its method, path and body make".to_string();
    match (derived, carried) {
        (
            Command::Apply {
                resources: mut ours, ..
            },
            Command::Apply { resources: theirs, .. },
        ) => {
            if ours.len() != theirs.len() {
                return Err(differs());
            }
            for at in crate::controllers::admits(store, &mut ours)? {
                let (ours, theirs) = (&mut ours[at], &theirs[at]);
                ours.spec = theirs.spec.clone();
                ours.metadata.labels = theirs.metadata.labels.clone();
                ours.metadata.annotations = theirs.metadata.annotations.clone();
                // (A module that answers the resource changed drops its status.)
                if theirs.status.is_none() {
                    ours.status = None;
                }
            }
            (ours == *theirs).then_some(()).ok_or_else(differs)
        }
        (Command::Delete { key }, Command::Delete { key: theirs }) if key == *theirs => Ok(()),
        (
            Command::Rollback { key, to, .. },
            Command::Rollback {
                key: theirs, to: back, ..
            },
        ) if key == *theirs && to == *back => Ok(()),
        _ => Err(differs()),
    }
}

/// May a node apply `command`, an entry of the log the node `leader` wrote, to `store`? Anything
/// but a signed entry may. A signed one only where all of these hold, in this order: `store` is
/// in format 4 ([`Store::checking`]); its
/// signature holds by `store`'s keys, for `*` or for `leader`; its method, path and body make
/// its command ([`derived`], [`same`]); its signer may make it ([`crate::api::refused`], and
/// the admin's key and `spec.signing` change only by the admin's: [`guard`]); and the signer's
/// book takes its nonce ([`Store::takes_nonce`]). Deterministic: the entry and `store` alone,
/// no clock (its time is its `expires`, as the book reads it).
pub fn admit(store: &Store, cluster: &str, command: &Command, leader: kith_store::NodeId) -> Result<(), String> {
    let Command::Signed {
        header,
        method,
        path,
        body,
        command,
    } = command
    else {
        return Ok(());
    };
    // Before format 4 a member may be on a kithd that refuses every signed entry (T-0779's):
    // refused here too, so the stores stay alike.
    if !store.checking() {
        return Err("the store is not in format 4, where every member checks signed entries".into());
    }
    let target = kith_store::header(header)?.target;
    if target != "*" && kith_store::node_id(target) != leader {
        return Err(format!("signed for {target}, not for the node that wrote it"));
    }
    let body = base64::engine::general_purpose::STANDARD.decode(body);
    let body = body.map_err(|e| format!("its body is not base64: {e}"))?;
    let asked = Asked {
        method,
        path,
        body: &body,
    };
    let (signer, read) = signature(header, cluster, &[target], &asked, store)?;
    same(store, derived(store, &signer, method, path, &body)?, command)?;
    if let Some(why) = crate::api::refused(store, &signer, command) {
        return Err(why);
    }
    guard(store, command, signer == Caller::Admin)?;
    let taken = store.takes_nonce(read.who, read.expires, read.nonce);
    taken.map_err(|e| e.to_string())
}

/// What each entry of the log is asked once the store is in format 3 ([`admit`]), on the
/// cluster `cluster` (its id; none: nothing signed is applied). A refusal applies nothing, and
/// is written in `audit` as `signed`.
pub fn hook(cluster: Option<String>, audit: Arc<crate::audit::Audit>) -> kith_store::Check {
    Arc::new(move |store, command, leader| {
        let Command::Signed { header, path, .. } = command else {
            return Ok(());
        };
        let decided = match &cluster {
            Some(cluster) => admit(store, cluster, command, leader),
            None => Err("this kithd is not part of a cluster: nothing is signed for it".into()),
        };
        decided.map_err(|why| {
            let who = kith_store::header(header).map_or("unknown", |read| read.who);
            audit.record(&who, "signed", vec![path.clone()], Err(why.clone()));
            kith_api::store::Error::Invalid(format!("refused: a signed entry: {why}"))
        })
    })
}

fn now() -> u64 {
    kith_api::store::now()
}

/// This node's name.
pub fn me(shared: &Shared) -> &str {
    shared.cluster.as_ref().map_or("", |cluster| cluster.me.name.as_str())
}

/// Does this node's store say `spec.signing: required`?
pub fn requires(shared: &Shared) -> bool {
    required(&shared.store.lock().expect("a handler panicked holding the store").store)
}

/// A request's signer, the header to pass on with it, and the request itself where a change to
/// the log may be passed on as it came ([`Relay`]).
#[derive(Clone, Debug)]
pub struct Signed {
    pub header: String,
    pub who: Caller,
    pub relay: Option<Relay>,
}

/// A signed change as it came (`POST /v1/apply`, `DELETE /v1/resources/…` or `POST
/// /v1/rollback/…`): a control node that is not the leader sends the leader this method, path and
/// body, with the same header, and the leader checks them as signed.
#[derive(Clone, Debug)]
pub struct Relay {
    pub method: String,
    pub path: String,
    pub body: axum::body::Bytes,
    /// Who signed it, as the FOR header names them.
    pub who: Caller,
    /// The room this request holds in [`HOLDING`], kept while the relay is held: its body is
    /// held with it until the leader has answered.
    #[allow(dead_code, reason = "held for its drop: the room is given back when the relay is")]
    pub room: Arc<tokio::sync::SemaphorePermit<'static>>,
}

impl Relay {
    /// Is this request the route `command` is made by? Only then is it passed on as it came: a
    /// write a handler makes on its own (a `Mark`, a restore's, a lock's) is not this request. A
    /// Release, Source, KindDefinition or Package rollback is applied as it goes back, so it is an
    /// Apply made by a rollback route.
    pub fn carries(&self, command: &Command) -> bool {
        let route = self.path.split('?').next().unwrap_or("");
        match command {
            Command::Apply { .. } => {
                self.method == "POST" && (route == "/v1/apply" || route.starts_with("/v1/rollback/"))
            }
            Command::Delete { .. } => self.method == "DELETE" && route.starts_with("/v1/resources/"),
            Command::Rollback { .. } => self.method == "POST" && route.starts_with("/v1/rollback/"),
            _ => false,
        }
    }
}

impl Signed {
    /// This request as it came (`method`, `path`, `body`), to be passed on as it is.
    fn relayed(
        mut self,
        method: &str,
        path: &str,
        body: &axum::body::Bytes,
        room: tokio::sync::SemaphorePermit<'static>,
    ) -> Signed {
        self.relay = Some(Relay {
            method: method.into(),
            path: path.into(),
            body: body.clone(),
            who: self.who.clone(),
            room: Arc::new(room),
        });
        self
    }
}

/// [`verify`] on this node: its cluster, store, clock and nonces.
pub fn check(shared: &Shared, header: &str, targets: &[&str], asked: &Asked) -> Result<Signed, String> {
    let Some(cluster) = &shared.cluster else {
        return Err("this kithd is not part of a cluster: nothing is signed for it".into());
    };
    let id = crate::pki::fingerprint(&cluster.me.ca)?;
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let who = verify(header, &id, targets, asked, &state.store, now(), &shared.nonces)?;
    Ok(Signed {
        header: header.into(),
        who,
        relay: None,
    })
}

tokio::task_local! {
    /// The signature the request this task serves came with, once checked.
    static HELD: Signed;
}

/// The signature the request this task serves came with, once checked.
pub fn current() -> Option<Signed> {
    HELD.try_with(Signed::clone).ok()
}

/// Was this task's request signed by the admin's key?
pub fn by_admin() -> bool {
    current().is_some_and(|signed| signed.who == Caller::Admin)
}

/// `run`, with `signed` as the request's signature (none: as it is).
pub async fn within<T>(signed: Option<Signed>, run: impl Future<Output = T>) -> T {
    match signed {
        Some(signed) => HELD.scope(signed, run).await,
        None => run.await,
    }
}

/// `call`, with the signature this task's request came with, as it came.
pub fn pass_on(call: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match current() {
        Some(signed) => call.header(SIGNED, signed.header),
        None => call,
    }
}

/// The request back, its body read whole, and what it holds; and its room in [`HOLDING`],
/// held until the signature has been checked.
async fn read(request: Request) -> Result<(Request, axum::body::Bytes, tokio::sync::SemaphorePermit<'static>), String> {
    let (parts, body) = request.into_parts();
    let length = parts.headers.get(axum::http::header::CONTENT_LENGTH);
    let (room, most) = held(length.and_then(|length| length.to_str().ok()));
    let room = HOLDING.acquire_many(room).await.expect("HOLDING is never closed");
    let bytes = axum::body::to_bytes(body, most).await;
    let bytes = bytes.map_err(|e| format!("a signed request's body is at most {} MiB: {e}", LIMIT >> 20))?;
    Ok((Request::from_parts(parts, Body::from(bytes.clone())), bytes, room))
}

fn path(request: &Request) -> String {
    let uri = request.uri();
    uri.path_and_query()
        .map_or(uri.path(), |path| path.as_str())
        .to_string()
}

/// Who signed what the node `node` passed on to this one (`header`, over `asked`), where that
/// holds, for whoever it says asked (`named`; none: its own). Under `required` a node's word
/// for who asked stands only with their signature, for this node; under `open` a signature
/// that does not hold is taken as none, as a kithd from before signatures would. A write to
/// the log may be signed for `*` too (`log`): any node passes it to the leader.
pub fn hop(
    shared: &Shared,
    node: &str,
    header: Option<&str>,
    asked: &Asked,
    named: Option<&Caller>,
    log: bool,
) -> Result<Option<Signed>, String> {
    let required = named.is_some() && requires(shared);
    let targets: &[&str] = match log {
        true => &[me(shared), "*"],
        false => &[me(shared)],
    };
    let signed = match header.map(|header| check(shared, header, targets, asked)) {
        Some(Ok(signed)) => signed,
        Some(Err(why)) if required => {
            return Err(format!(
                "refused: the signature node {node} passed on does not hold: {why}"
            ));
        }
        None if required => return Err(unsigned(node)),
        _ => return Ok(None),
    };
    match named {
        Some(named) if *named != signed.who => Err(format!(
            "refused: node {node} says {named} asked, and passed on a signature by {}",
            signed.who
        )),
        _ => Ok(Some(signed)),
    }
}

fn header(request: &Request) -> Option<String> {
    let header = request.headers().get(SIGNED)?;
    // (A header that is not text is one that does not hold, not none.)
    Some(header.to_str().unwrap_or_default().to_string())
}

/// [`hop`] for a request on the TLS port (`access.rs`), its body read to be checked where it
/// is signed.
pub async fn passed(
    shared: &Shared,
    node: &str,
    named: &Caller,
    request: Request,
) -> (Request, Result<Option<Signed>, String>) {
    let (method, path) = (request.method().to_string(), path(&request));
    // (A write to the log may be signed for `*`: a control node passes it on to the leader.)
    let log = method != "GET";
    let Some(header) = header(&request) else {
        let asked = Asked {
            method: &method,
            path: &path,
            body: &[],
        };
        return (request, hop(shared, node, None, &asked, Some(named), log));
    };
    let (request, bytes, room) = match read(request).await {
        Ok(read) => read,
        // (The body is gone: refused, whatever the setting.)
        Err(why) => return (Request::new(Body::empty()), Err(why)),
    };
    let asked = Asked {
        method: &method,
        path: &path,
        body: &bytes,
    };
    let signed = hop(shared, node, Some(&header), &asked, Some(named), log);
    (
        request,
        signed.map(|signed| signed.map(|signed| signed.relayed(&method, &path, &bytes, room))),
    )
}

/// Is an unsigned call at the local socket taken under `required`, as the node, which reads?
/// (A POST that only reads, `/v1/diff`, is signed like any other: a handler that asks no
/// Grants is not trusted to read alone.)
fn console(method: &str) -> bool {
    matches!(method, "GET" | "HEAD")
}

/// Who is asking at the local socket. Whoever can open it runs this machine: under `open` it
/// is the admin, as it always was; under `required` it is the admin only with the admin's
/// signature, and the node itself (which reads) without one.
pub async fn local(State(shared): State<Arc<Shared>>, request: Request, next: Next) -> Response {
    let required = requires(&shared);
    let (method, path) = (request.method().to_string(), path(&request));
    let header = header(&request);
    let refused = |status: StatusCode, why: String| {
        shared
            .audit
            .record(&Caller::Admin, &method, vec![path.clone()], Err(why.clone()));
        crate::cluster::refuse(status, why).into_response()
    };
    let Some(header) = header else {
        let caller = match (required, console(&method)) {
            (false, _) => Caller::Admin,
            (true, true) => Caller::Console(me(&shared).into()),
            (true, false) => {
                return refused(
                    StatusCode::FORBIDDEN,
                    format!(
                        "this cluster requires the admin's signature (spec.signing: required): unsigned, \
                         the local socket is node {}, which only reads; sign it ({SIGNED})",
                        me(&shared)
                    ),
                );
            }
        };
        let mut request = request;
        request.extensions_mut().insert(caller);
        return next.run(request).await;
    };
    let (mut request, bytes, room) = match read(request).await {
        Ok(read) => read,
        Err(why) => return refused(StatusCode::PAYLOAD_TOO_LARGE, why),
    };
    let asked = Asked {
        method: &method,
        path: &path,
        body: &bytes,
    };
    let checked = check(&shared, &header, &[me(&shared), "*"], &asked);
    let checked = checked.and_then(|signed| match signed.who {
        Caller::Admin => Ok(signed),
        _ => Err(format!(
            "the local socket is signed for as \"local socket\", not as {}",
            signed.who
        )),
    });
    // (A signed request keeps its room while it is relayed, so the body's bound covers the forward.)
    let signed = match checked {
        Ok(signed) => Some(signed.relayed(&method, &path, &bytes, room)),
        Err(why) if required => return refused(StatusCode::UNAUTHORIZED, format!("refused: {why}")),
        Err(_) => {
            drop(room);
            None
        }
    };
    request.extensions_mut().insert(Caller::Admin);
    within(signed, next.run(request)).await
}

/// What each Cluster's spec is, by name, once `command` is applied to `store`; `None` for a
/// command that touches no Cluster, and `Err` where that cannot be told.
fn clusters_after(store: &Store, command: &Command) -> Result<Option<BTreeMap<String, serde_json::Value>>, String> {
    let is_cluster = |kind: &str| kind.eq_ignore_ascii_case("Cluster");
    let specs = |store: &Store| -> BTreeMap<String, serde_json::Value> {
        let clusters = store.list(Some("Cluster"));
        clusters
            .map(|cluster| (cluster.metadata.name.clone(), cluster.spec.clone()))
            .collect()
    };
    let named = |key: &str| {
        key.split_once('/')
            .filter(|(kind, _)| is_cluster(kind))
            .map(|(_, name)| name.to_string())
    };
    let mut after = specs(store);
    match command {
        Command::Apply { resources, .. } => {
            let touched: Vec<&Resource> = resources.iter().filter(|resource| is_cluster(&resource.kind)).collect();
            if touched.is_empty() {
                return Ok(None);
            }
            for cluster in touched {
                after.insert(cluster.metadata.name.clone(), cluster.spec.clone());
            }
        }
        Command::Delete { key } => match named(key) {
            Some(name) => drop(after.remove(&name)),
            None => return Ok(None),
        },
        Command::Rollback { key, to, .. } => {
            let Some(name) = named(key) else { return Ok(None) };
            let history = store.history(key).ok().into_iter().flatten();
            let was = history
                .into_iter()
                .find(|was| was.resource.metadata.revision == Some(*to));
            let Some(was) = was else {
                return Err(format!("{key} has no revision {to} to say what it would be"));
            };
            after.insert(name, was.resource.spec.clone());
        }
        Command::Import { store } => after = specs(store),
        Command::Signed { command, .. } => return clusters_after(store, command),
        Command::Status { .. }
        | Command::Patch { .. }
        | Command::Report { .. }
        | Command::Mark
        | Command::MarkSigned
        | Command::MarkChecked => return Ok(None),
    }
    Ok(Some(after))
}

/// Refuses a change to the admin's key (once there is one) or to `spec.signing` that the
/// admin did not sign (`signed`): a taken node cannot put its own key in, or turn signing off.
/// The first key is written unsigned, while the cluster is `open`: trust on first use.
pub fn guard(store: &Store, command: &Command, signed: bool) -> Result<(), String> {
    if signed {
        return Ok(());
    }
    let after = match clusters_after(store, command) {
        Ok(None) => return Ok(()),
        Ok(Some(after)) => after,
        Err(why) => {
            return Err(format!(
                "refused unsigned: a Cluster's spec.adminKey may change and {why}"
            ));
        }
    };
    let clusters = store.list(Some("Cluster"));
    let (keys, required) = (admin_keys(clusters.map(|cluster| &cluster.spec)), required(store));
    let (keys_after, required_after) = (
        admin_keys(after.values()),
        after.values().any(|spec| spec["signing"] == "required"),
    );
    if (!keys.is_empty() && keys != keys_after) || required != required_after {
        return Err(format!(
            "a Cluster's spec.adminKey, once set, and its spec.signing are changed only by a write the admin \
             signed ({SIGNED}, who=local socket)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use rustls::pki_types::pem::PemObject;

    const CLUSTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NONCE: &str = "00112233445566778899aabbccddeeff";
    const NOW: u64 = 1_800_000_000;

    fn admin() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
    }

    fn store_with(key: &[u8], signing: &str) -> Store {
        let mut store = Store::default();
        let text = format!(
            "apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {}{signing} }}\n",
            crate::pki::hex(key)
        );
        store
            .apply(Resource::from_source(&text).unwrap().remove(0).unwrap())
            .unwrap();
        store
    }

    fn asked() -> Asked<'static> {
        Asked {
            method: "POST",
            path: "/v1/logs/Workload/default/web?follow=true",
            body: b"abc",
        }
    }

    /// The header, signed by `sign` over `message` (as [`bytes`] makes it, or changed).
    fn header(sign: impl Fn(&[u8]) -> Vec<u8>, who: &str, target: &str, expires: u64, message: &str) -> String {
        let sig = base64::engine::general_purpose::STANDARD.encode(sign(message.as_bytes()));
        format!("v1; who={who}; target={target}; expires={expires}; nonce={NONCE}; sig={sig}")
    }

    fn by_admin(message: &str) -> String {
        header(
            |m| admin().sign(m).as_ref().to_vec(),
            "local socket",
            "n2",
            NOW + 300,
            message,
        )
    }

    fn good() -> String {
        bytes(CLUSTER, "n2", &asked(), "local socket", NOW + 300, NONCE)
    }

    fn check(header: &str) -> Result<Caller, String> {
        let store = store_with(admin().public_key().as_ref(), "");
        verify(header, CLUSTER, &["n2"], &asked(), &store, NOW, &Nonces::default())
    }

    /// The bytes are the ADR's, field by field, and the fixed seed's signature over them is
    /// this one (Ed25519 is deterministic): a signer elsewhere can be held to it.
    #[test]
    fn signed_bodies_hold_what_they_say_up_to_the_limit() {
        assert_eq!(held(Some("0")), (1, 0));
        assert_eq!(held(Some("1048577")), (2, 1048577));
        // No length, one that is not a number, or one past the limit: the limit.
        for length in [None, Some("lots"), Some("1000000000")] {
            assert_eq!(held(length), (96, LIMIT), "{length:?}");
        }
    }

    #[test]
    fn signed_bytes_are_the_adrs() {
        assert_eq!(
            good(),
            format!(
                "kith-signed-v1\n{CLUSTER}\nn2\nPOST\n/v1/logs/Workload/default/web?follow=true\n\
                 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\nlocal socket\n1800000300\n{NONCE}\n"
            )
        );
        let sig = base64::engine::general_purpose::STANDARD.encode(admin().sign(good().as_bytes()));
        assert_eq!(
            sig,
            "xg8X9H2TtapH9pPFxpL8y5SUjEDAGR8N1xg9mYUfgt9JmMTgu5/oya1QhKFhcZumr6GWD9t3gCVuOfrlOflGDQ=="
        );
        assert_eq!(check(&by_admin(&good())), Ok(Caller::Admin));
    }

    /// kith-cli's pinned header (its `signed_cross_vector_is_kithds`): from its passphrase, the
    /// key kith derives here as kith does, and kithd's own `verify` takes the header as it is.
    #[test]
    fn signed_header_from_the_cli_verifies() {
        let mut seed = [0u8; 32];
        let rounds = std::num::NonZeroU32::new(600_000).unwrap();
        let passphrase = b"correct horse battery staple";
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            rounds,
            CLUSTER.as_bytes(),
            passphrase,
            &mut seed,
        );
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        assert_eq!(
            crate::pki::hex(key.public_key().as_ref()),
            "45adefd230fccdc0edc77acb13998359d12eeb0ab7a4fdd1c49a2203fb8eb183"
        );
        let header = "v1; who=local socket; target=*; expires=1800000300; nonce=00112233445566778899aabbccddeeff; sig=a70zVltHfKC0JVo4PtNzEiwAsqr/KLbBg1ITbXFjm/5TA4bG8PX3zj/35f76yW68aScPFOH4Ks62okBH8wDvBQ==";
        let store = store_with(key.public_key().as_ref(), "");
        let asked = Asked {
            method: "POST",
            path: "/v1/apply",
            body: b"[]",
        };
        let checked = verify(header, CLUSTER, &["*"], &asked, &store, NOW, &Nonces::default());
        assert_eq!(checked, Ok(Caller::Admin));
    }

    fn refused(header: &str, why: &str) {
        let said = check(header).unwrap_err();
        assert!(said.contains(why), "{said}");
    }

    #[test]
    fn signed_for_another_cluster_is_refused() {
        let other = bytes(
            &CLUSTER.replace('0', "f"),
            "n2",
            &asked(),
            "local socket",
            NOW + 300,
            NONCE,
        );
        refused(&by_admin(&other), "not local socket's over this request");
    }

    #[test]
    fn signed_for_another_target_is_refused() {
        let message = bytes(CLUSTER, "n3", &asked(), "local socket", NOW + 300, NONCE);
        let sign = |m: &[u8]| admin().sign(m).as_ref().to_vec();
        refused(
            &header(sign, "local socket", "n3", NOW + 300, &message),
            "signed for n3, not for n2",
        );
        // (Saying n2 over bytes for n3 is no better.)
        refused(&by_admin(&message), "not local socket's");
    }

    #[test]
    fn signed_for_another_method_is_refused() {
        let asked = Asked {
            method: "GET",
            ..asked()
        };
        refused(
            &by_admin(&bytes(CLUSTER, "n2", &asked, "local socket", NOW + 300, NONCE)),
            "not local socket's",
        );
    }

    #[test]
    fn signed_for_another_path_is_refused() {
        let asked = Asked {
            path: "/v1/logs/Workload/default/web?follow=false",
            ..asked()
        };
        refused(
            &by_admin(&bytes(CLUSTER, "n2", &asked, "local socket", NOW + 300, NONCE)),
            "not local socket's",
        );
    }

    #[test]
    fn signed_for_another_body_is_refused() {
        let asked = Asked {
            body: b"abd",
            ..asked()
        };
        refused(
            &by_admin(&bytes(CLUSTER, "n2", &asked, "local socket", NOW + 300, NONCE)),
            "not local socket's",
        );
    }

    #[test]
    fn signed_as_another_who_is_refused() {
        // The admin's signature over bytes that say who=alice, sent as the local socket.
        let message = bytes(CLUSTER, "n2", &asked(), "alice", NOW + 300, NONCE);
        refused(&by_admin(&message), "not local socket's");
        // And who=alice itself: there is no such Identity to check it by.
        let sign = |m: &[u8]| admin().sign(m).as_ref().to_vec();
        refused(&header(sign, "alice", "n2", NOW + 300, &message), "no Identity alice");
        refused(
            &header(sign, "node:n1", "n2", NOW + 300, &message),
            "only the local socket and an Identity",
        );
    }

    #[test]
    fn signed_and_expired_is_refused() {
        let message = bytes(CLUSTER, "n2", &asked(), "local socket", NOW - 1, NONCE);
        let sign = |m: &[u8]| admin().sign(m).as_ref().to_vec();
        refused(
            &header(sign, "local socket", "n2", NOW - 1, &message),
            "expired 1 s ago",
        );
        // (To the second: one that expires now still stands.)
        let message = bytes(CLUSTER, "n2", &asked(), "local socket", NOW, NONCE);
        assert_eq!(
            check(&header(sign, "local socket", "n2", NOW, &message)),
            Ok(Caller::Admin)
        );
    }

    #[test]
    fn signed_too_far_ahead_is_refused() {
        let message = bytes(CLUSTER, "n2", &asked(), "local socket", NOW + 601, NONCE);
        let sign = |m: &[u8]| admin().sign(m).as_ref().to_vec();
        refused(
            &header(sign, "local socket", "n2", NOW + 601, &message),
            "more than 600 s",
        );
        let message = bytes(CLUSTER, "n2", &asked(), "local socket", NOW + 600, NONCE);
        assert_eq!(
            check(&header(sign, "local socket", "n2", NOW + 600, &message)),
            Ok(Caller::Admin)
        );
    }

    #[test]
    fn signed_twice_with_one_nonce_is_refused() {
        let store = store_with(admin().public_key().as_ref(), "");
        let nonces = Nonces::default();
        let once = || verify(&by_admin(&good()), CLUSTER, &["n2"], &asked(), &store, NOW, &nonces);
        assert_eq!(once(), Ok(Caller::Admin));
        assert_eq!(once(), Err("the signature was used already".into()));
        // A refused signature takes no nonce: the real one still comes in after it.
        let nonces = Nonces::default();
        let forged = by_admin(&good()).replace("sig=", "sig=AA");
        assert!(verify(&forged, CLUSTER, &["n2"], &asked(), &store, NOW, &nonces).is_err());
        assert_eq!(
            verify(&by_admin(&good()), CLUSTER, &["n2"], &asked(), &store, NOW, &nonces),
            Ok(Caller::Admin)
        );
        // Kept until it expires, and let go after.
        assert!(nonces.take("n", NOW + 10, NOW));
        assert!(!nonces.take("n", NOW + 10, NOW + 10));
        assert!(nonces.take("n", NOW + 20, NOW + 11));
    }

    #[test]
    fn signed_with_another_key_is_refused() {
        let other = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
        let header = header(
            |m| other.sign(m).as_ref().to_vec(),
            "local socket",
            "n2",
            NOW + 300,
            &good(),
        );
        refused(&header, "not local socket's over this request");
        // Nor is anything signed as the local socket where no Cluster has a key.
        let none = verify(
            &by_admin(&good()),
            CLUSTER,
            &["n2"],
            &asked(),
            &Store::default(),
            NOW,
            &Nonces::default(),
        );
        assert!(none.unwrap_err().contains("no Cluster has spec.adminKey"));
    }

    #[test]
    fn signed_but_malformed_is_refused() {
        let good = by_admin(&good());
        for (header, why) in [
            (good.replace("v1;", "v2;"), "not v1"),
            (good.replace("expires=", "expires=+"), "in digits"),
            (good.replace("expires=", "expires=99999999999999999999"), "too large"),
            (good.replace(NONCE, "0011"), "32 lower-case hex"),
            (good.replace(NONCE, &NONCE.to_uppercase()), "32 lower-case hex"),
            (good.replace("sig=", "sig=!"), "not base64"),
            (good.replace("; target=n2", ""), "no target"),
            (format!("{good}; who=alice"), "said twice"),
            (format!("{good}; extra=1"), "unknown"),
            (format!("{good}; who="), "empty"),
            (format!("{good}; who"), "no name=value"),
            (String::new(), "not v1"),
        ] {
            refused(&header, why);
        }
    }

    /// An Identity signs with the P-256 key its certificate was made for.
    #[test]
    fn signed_by_an_identity_is_that_identity() {
        let ca = crate::pki::Ca::create().unwrap();
        let (_, key, public) = ca.issue_user("alice").unwrap();
        let mut store = Store::default();
        let text = "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: { name: alice }\nspec: {}\n";
        let mut identity = Resource::from_source(text).unwrap().remove(0).unwrap();
        identity.spec = serde_json::json!({ "publicKey": public });
        store.apply(identity).unwrap();
        let der = rustls::pki_types::PrivatePkcs8KeyDer::from_pem_slice(key.as_bytes()).unwrap();
        let rng = ring::rand::SystemRandom::new();
        let pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            der.secret_pkcs8_der(),
            &rng,
        )
        .unwrap();
        let message = bytes(CLUSTER, "n2", &asked(), "alice", NOW + 300, NONCE);
        let header = header(
            |m| pair.sign(&rng, m).unwrap().as_ref().to_vec(),
            "alice",
            "n2",
            NOW + 300,
            &message,
        );
        let said = verify(&header, CLUSTER, &["n2"], &asked(), &store, NOW, &Nonces::default());
        assert_eq!(said, Ok(Caller::Identity("alice".into())));
    }

    /// The first key is written unsigned (trust on first use); after that the key, and the
    /// setting either way, change only by a write the admin signed.
    #[test]
    fn signed_key_and_setting_change_only_signed() {
        let cluster = |spec: &str| {
            let text = format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {spec}\n");
            Resource::from_source(&text).unwrap().remove(0).unwrap()
        };
        let apply = |spec: &str| Command::Apply {
            resources: vec![cluster(spec)],
            at: 0,
        };
        let (one, two) = ("a".repeat(64), "b".repeat(64));
        let empty = Store::default();
        assert_eq!(guard(&empty, &apply(&format!("{{ adminKey: {one} }}")), false), Ok(()));
        let mut keyed = Store::default();
        keyed.apply(cluster(&format!("{{ adminKey: {one} }}"))).unwrap();
        // The same key, unsigned: nothing changes that matters here.
        assert_eq!(
            guard(&keyed, &apply(&format!("{{ adminKey: {one}, images: [] }}")), false),
            Ok(())
        );
        let changes = [
            apply(&format!("{{ adminKey: {two} }}")),
            apply("{}"),
            apply(&format!("{{ adminKey: {one}, signing: required }}")),
            Command::Delete {
                key: "Cluster/home".into(),
            },
            Command::Import {
                store: Store::default(),
            },
            Command::Rollback {
                key: "Cluster/home".into(),
                to: 99,
                at: 0,
            },
        ];
        for change in &changes {
            let said = guard(&keyed, change, false).unwrap_err();
            assert!(said.contains("adminKey"), "{said}");
            assert_eq!(guard(&keyed, change, true), Ok(()));
        }
        // Back to open, unsigned: refused too.
        let mut required = Store::default();
        required
            .apply(cluster(&format!("{{ adminKey: {one}, signing: required }}")))
            .unwrap();
        assert!(
            guard(
                &required,
                &apply(&format!("{{ adminKey: {one}, signing: open }}")),
                false
            )
            .is_err()
        );
        // What touches no Cluster is never asked.
        let other = Command::Delete {
            key: "Node/home".into(),
        };
        assert_eq!(guard(&required, &other, false), Ok(()));
    }

    /// Unsigned at the local socket under `required`: the node, which reads; nobody else.
    #[test]
    fn signed_or_the_console_reads() {
        assert!(console("GET") && console("HEAD"));
        assert!(!console("POST") && !console("DELETE") && !console("PUT"));
        let grants = crate::access::Grants::of(&Caller::Console("n1".into()), &Store::default());
        assert!(grants.may(&kith_api::kinds::Verb::Get, "Secret", Some("default")));
        assert!(!grants.may(&kith_api::kinds::Verb::Apply, "Workload", Some("default")));
        assert!(!grants.anywhere(&kith_api::kinds::Verb::Exec, None));
    }

    /// [`signature`] asks neither the clock nor the nonces (a node applying the log has neither
    /// to go by); [`verify`], the edge's, asks both still.
    #[test]
    fn signed_signature_holds_without_clock_or_nonce() {
        let store = store_with(admin().public_key().as_ref(), "");
        let good = by_admin(&good());
        for _ in 0..2 {
            let (who, read) = signature(&good, CLUSTER, &["n2"], &asked(), &store).unwrap();
            assert_eq!((who, read.nonce), (Caller::Admin, NONCE));
        }
        let nonces = Nonces::default();
        assert_eq!(
            verify(&good, CLUSTER, &["n2"], &asked(), &store, NOW, &nonces),
            Ok(Caller::Admin)
        );
        let again = verify(&good, CLUSTER, &["n2"], &asked(), &store, NOW, &nonces);
        assert_eq!(again, Err("the signature was used already".into()));
        let message = bytes(CLUSTER, "n2", &asked(), "local socket", NOW - 1000, NONCE);
        let sign = |m: &[u8]| admin().sign(m).as_ref().to_vec();
        let old = header(sign, "local socket", "n2", NOW - 1000, &message);
        assert!(signature(&old, CLUSTER, &["n2"], &asked(), &store).is_ok());
        refused(&old, "expired 1000 s ago");
        // What is not the signer's, or not for this node, does not hold here either.
        let forged = good.replace("sig=", "sig=AA");
        assert!(signature(&forged, CLUSTER, &["n2"], &asked(), &store).is_err());
        let said = signature(&good, CLUSTER, &["n3"], &asked(), &store).err().unwrap();
        assert!(said.contains("not for n3"), "{said}");
    }

    /// The leader every entry of these tests is written by.
    const LEADER: &str = "n2";

    /// A store in format 4 whose Cluster has the admin's key.
    fn signing_store() -> Store {
        let mut store = store_with(admin().public_key().as_ref(), "");
        kith_store::run(&mut store, Command::MarkChecked).unwrap();
        store
    }

    fn resource(text: &str) -> Resource {
        Resource::from_source(text).unwrap().remove(0).unwrap()
    }

    fn map(name: &str) -> Resource {
        resource(&format!(
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{ name: {name} }}\nspec: {{ data: {{ a: b }} }}\n"
        ))
    }

    /// The body of `POST /v1/apply` with a ConfigMap of each name.
    fn maps(names: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&names.iter().map(|name| map(name)).collect::<Vec<_>>()).unwrap()
    }

    fn applies(resources: Vec<Resource>) -> Command {
        Command::Apply { resources, at: 7 }
    }

    fn nonce(n: u32) -> String {
        format!("{n:032x}")
    }

    /// A signed entry of `POST /v1/apply`: `who`'s signature (by `sign`) over `signed`, for
    /// `target`, carrying the body `carried` and `command`.
    #[allow(clippy::too_many_arguments)]
    fn entry(
        sign: impl Fn(&[u8]) -> Vec<u8>,
        who: &str,
        target: &str,
        expires: u64,
        nonce: &str,
        signed: &[u8],
        carried: &[u8],
        command: Command,
    ) -> Command {
        let asked = Asked {
            method: "POST",
            path: "/v1/apply",
            body: signed,
        };
        let message = bytes(CLUSTER, target, &asked, who, expires, nonce);
        let sig = base64::engine::general_purpose::STANDARD.encode(sign(message.as_bytes()));
        Command::Signed {
            header: format!("v1; who={who}; target={target}; expires={expires}; nonce={nonce}; sig={sig}"),
            method: "POST".into(),
            path: "/v1/apply".into(),
            body: base64::engine::general_purpose::STANDARD.encode(carried),
            command: Box::new(command),
        }
    }

    /// [`entry`] by the admin.
    fn by_admin_entry(
        target: &str,
        expires: u64,
        nonce: &str,
        signed: &[u8],
        carried: &[u8],
        command: Command,
    ) -> Command {
        let sign = |m: &[u8]| admin().sign(m).as_ref().to_vec();
        entry(sign, "local socket", target, expires, nonce, signed, carried, command)
    }

    /// What a node does with each entry of `log`: [`admit`], then runs it. Taken or not.
    fn feed(store: &mut Store, log: &[Command]) -> Vec<bool> {
        let leader = kith_store::node_id(LEADER);
        let taken = |store: &mut Store, command: &Command| {
            admit(store, CLUSTER, command, leader).is_ok() && kith_store::run(store, command.clone()).is_ok()
        };
        log.iter().map(|command| taken(store, command)).collect()
    }

    /// Two nodes fed one log, a forgery of each sort in it, take the same entries and end the
    /// same, without the forgeries; and no clock is asked: the same an hour either way.
    #[test]
    fn signed_apply_two_stores_end_equal_without_forgeries() {
        let other = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
        let (a, x) = (maps(&["a"]), maps(&["x"]));
        let now = kith_api::store::now();
        for expires in [NOW, now - 3600, now + 3600] {
            let good = by_admin_entry(LEADER, expires, &nonce(1), &a, &a, applies(vec![map("a")]));
            let log = [
                good.clone(),
                // Another body than was signed.
                by_admin_entry(LEADER, expires, &nonce(2), &a, &x, applies(vec![map("x")])),
                // Another command than the body says.
                by_admin_entry(LEADER, expires, &nonce(3), &a, &a, applies(vec![map("x")])),
                // The good one again.
                good,
                // Signed for another node than led the term.
                by_admin_entry("n3", expires, &nonce(5), &a, &a, applies(vec![map("a")])),
                // A key not the signer's.
                entry(
                    |m: &[u8]| other.sign(m).as_ref().to_vec(),
                    "local socket",
                    LEADER,
                    expires,
                    &nonce(6),
                    &a,
                    &a,
                    applies(vec![map("a")]),
                ),
                // For any node.
                by_admin_entry(
                    "*",
                    expires,
                    &nonce(7),
                    &maps(&["b"]),
                    &maps(&["b"]),
                    applies(vec![map("b")]),
                ),
            ];
            let (mut one, mut two) = (signing_store(), signing_store());
            let taken = [true, false, false, false, false, false, true];
            assert_eq!(feed(&mut one, &log), taken, "expires {expires}");
            assert_eq!(feed(&mut two, &log), taken, "expires {expires}");
            assert_eq!(one, two);
            let names: Vec<_> = one.list(Some("ConfigMap")).map(|m| m.metadata.name.clone()).collect();
            assert_eq!(names, ["a", "b"]);
            // In format 3 none is taken: a T-0779 kithd, a member then, refuses them all.
            let mut three = store_with(admin().public_key().as_ref(), "");
            kith_store::run(&mut three, Command::MarkSigned).unwrap();
            assert_eq!(feed(&mut three, &log), [false; 7], "expires {expires}");
        }
    }

    /// What a kind's admission module may change (the spec, labels and annotations of a custom
    /// kind's resource) the carried command may differ in; nothing else.
    #[test]
    fn signed_apply_takes_what_admission_may_rewrite() {
        let mut store = signing_store();
        store
            .apply(resource(
                "apiVersion: kith.dev/v1\nkind: KindDefinition\nmetadata: { name: gameserver }\n\
                 spec: { group: games.example.com, version: v1, kind: GameServer, schema: { type: object }, \
                 admission: { wasm: AGFzbQEAAAA= } }\n",
            ))
            .unwrap();
        let server = |name: &str| {
            resource(&format!(
                "apiVersion: games.example.com/v1\nkind: GameServer\nmetadata: {{ name: {name} }}\nspec: {{ map: dust }}\n"
            ))
        };
        let body = serde_json::to_vec(&[server("one")]).unwrap();
        let leader = kith_store::node_id(LEADER);
        let asked = |n: u32, command: Command| {
            let entry = by_admin_entry(LEADER, NOW, &nonce(n), &body, &body, command);
            admit(&store, CLUSTER, &entry, leader)
        };
        // As admission makes it: in the default namespace, its spec and labels its own.
        let mut rewritten = server("one");
        rewritten.metadata.namespace = Some("default".into());
        rewritten.spec = serde_json::json!({ "map": "rewritten" });
        rewritten.metadata.labels.insert("by".into(), "admission".into());
        assert_eq!(asked(1, applies(vec![rewritten.clone()])), Ok(()));
        // Not another resource.
        let mut renamed = rewritten.clone();
        renamed.metadata.name = "two".into();
        assert!(asked(2, applies(vec![renamed])).is_err());
        assert!(asked(3, applies(vec![rewritten.clone(), rewritten])).is_err());
        // A built-in kind has no admission: its spec is as signed.
        let a = maps(&["a"]);
        let mut changed = map("a");
        changed.spec = serde_json::json!({ "data": { "a": "c" } });
        let entry = by_admin_entry(LEADER, NOW, &nonce(4), &a, &a, applies(vec![changed]));
        assert!(admit(&store, CLUSTER, &entry, leader).is_err());
    }

    /// A signer is held to its Roles where the entry is applied, as the store then stands.
    #[test]
    fn signed_apply_asks_the_signers_rights() {
        let ca = crate::pki::Ca::create().unwrap();
        let (_, key, public) = ca.issue_user("alice").unwrap();
        let mut store = signing_store();
        let mut identity = resource("apiVersion: kith.dev/v1\nkind: Identity\nmetadata: { name: alice }\nspec: {}\n");
        identity.spec = serde_json::json!({ "publicKey": public });
        store.apply(identity).unwrap();
        for text in [
            "apiVersion: kith.dev/v1\nkind: Role\nmetadata: {name: maps}\nspec: {rules: [{kinds: [ConfigMap], verbs: [apply]}]}\n",
            "apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {name: alice-writes}\nspec: {role: maps, subjects: [alice]}\n",
        ] {
            store.apply(resource(text)).unwrap();
        }
        let der = rustls::pki_types::PrivatePkcs8KeyDer::from_pem_slice(key.as_bytes()).unwrap();
        let rng = ring::rand::SystemRandom::new();
        let pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            der.secret_pkcs8_der(),
            &rng,
        )
        .unwrap();
        let by_alice = |n: u32, resources: Vec<Resource>| {
            let body = serde_json::to_vec(&resources).unwrap();
            let sign = |m: &[u8]| pair.sign(&rng, m).unwrap().as_ref().to_vec();
            entry(sign, "alice", LEADER, NOW, &nonce(n), &body, &body, applies(resources))
        };
        let leader = kith_store::node_id(LEADER);
        assert_eq!(admit(&store, CLUSTER, &by_alice(1, vec![map("a")]), leader), Ok(()));
        let secret = resource("apiVersion: kith.dev/v1\nkind: Secret\nmetadata: { name: s }\nspec: { data: {} }\n");
        let said = admit(&store, CLUSTER, &by_alice(2, vec![secret]), leader).unwrap_err();
        assert!(said.contains("may not"), "{said}");
    }

    /// A signer's book of nonces holds at most [`SIGNED_NONCES`] at once: past that its entries
    /// are refused, nothing taken, until a later `expires` lets the old ones go.
    #[test]
    fn raft_write_refuses_past_a_signers_nonce_cap() {
        use kith_api::store::{SIGNED_NONCES, SIGNED_SKEW};
        let mut store = signing_store();
        for n in 0..SIGNED_NONCES as u32 {
            store.nonce("local socket", NOW, &nonce(n)).unwrap();
        }
        let full = nonce(SIGNED_NONCES as u32);
        let said = store.takes_nonce("local socket", NOW, &full).unwrap_err().to_string();
        assert!(said.contains("full"), "{said}");
        let before = store.clone();
        assert!(store.nonce("local socket", NOW, &full).is_err());
        assert_eq!(store, before, "nothing taken");
        // Another signer's book is its own; and later, the old ones go.
        assert_eq!(store.nonce("alice", NOW, &full), Ok(()));
        assert_eq!(store.nonce("local socket", NOW + SIGNED_SKEW, &full), Ok(()));
    }

    /// The leader writes a signed request it applies as a signed entry once the store is in
    /// format 4, and bare before (in 3 a member may refuse every signed entry); one whose
    /// command is not what its body says is nothing.
    #[tokio::test]
    async fn signed_wrap_at_format_4_and_bare_below() {
        use crate::cluster::pinned_peer::{node, shared_with};
        let ca = crate::pki::Ca::create().unwrap();
        let shared = shared_with("signed-wrap", node(&ca, "wrap-c"), &[]).await;
        let id = shared.raft.metrics().borrow().id;
        let one = BTreeMap::from([(id, kith_store::openraft::BasicNode::new(""))]);
        shared.raft.initialize(one).await.unwrap();
        let leads = shared.raft.wait(Some(std::time::Duration::from_secs(30)));
        leads.current_leader(id, "leads").await.unwrap();
        let key = crate::pki::hex(admin().public_key().as_ref());
        let cluster = resource(&format!(
            "apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {{ adminKey: {key} }}\n"
        ));
        shared.write(applies(vec![cluster])).await.unwrap();
        let id = crate::pki::fingerprint(&shared.cluster.as_ref().unwrap().me.ca).unwrap();
        let expires = now() + 300;
        let signed = |n: u32, body: &[u8]| {
            let asked = Asked {
                method: "POST",
                path: "/v1/apply",
                body,
            };
            let message = bytes(&id, "*", &asked, "local socket", expires, &nonce(n));
            let sig = base64::engine::general_purpose::STANDARD.encode(admin().sign(message.as_bytes()));
            let n = nonce(n);
            Signed {
                header: format!("v1; who=local socket; target=*; expires={expires}; nonce={n}; sig={sig}"),
                who: Caller::Admin,
                relay: Some(Relay {
                    method: "POST".into(),
                    path: "/v1/apply".into(),
                    body: axum::body::Bytes::copy_from_slice(body),
                    who: Caller::Admin,
                    room: Arc::new(HOLDING.try_acquire_many(1).unwrap()),
                }),
            }
        };
        let apply = |n: u32, body: &[&str], written: &str| {
            let command = applies(vec![map(written)]);
            within(
                Some(signed(n, &maps(body))),
                shared.submit_as(command, Some(&Caller::Admin)),
            )
        };
        let book = |n: u32| {
            let state = shared.store.lock().unwrap();
            state.store.takes_nonce("local socket", expires, &nonce(n)).is_ok()
        };
        // Format 1: written bare (a signed entry would be refused there).
        apply(1, &["a"], "a").await.unwrap();
        // Format 3: bare too, a member may be a T-0779 kithd that refuses every signed entry.
        shared.write(Command::MarkSigned).await.unwrap();
        assert!(book(1), "below format 3 no nonce is taken");
        apply(4, &["d"], "d").await.unwrap();
        assert!(book(4), "at format 3 the entry is bare, and no nonce taken");
        shared.write(Command::MarkChecked).await.unwrap();
        apply(2, &["b"], "b").await.unwrap();
        assert!(!book(2), "at format 4 the entry is signed, and its nonce taken");
        // Its command is not what its body says: refused on every node, and written down.
        assert!(apply(3, &["c"], "x").await.is_err());
        let state = shared.store.lock().unwrap();
        assert!(state.store.get("ConfigMap/default/x").is_none() && state.store.get("ConfigMap/x").is_none());
        drop(state);
        let tail = shared.audit.tail(20).unwrap();
        let refused = tail.iter().any(|line| line["verb"] == "signed" && line["ok"] == false);
        assert!(refused, "{tail:?}");
    }
}
