//! Images made in the cluster, and the registry that serves them.
//!
//! An `Image` names a Volume. The volume's node packs its directory as the one layer of an
//! OCI image (when the Job the Image names, if any, has succeeded) and keeps the layer, the
//! image's config and its manifest as Blobs, which other nodes hold too. Nothing runs to
//! build: the steps of a build are the containers of an ordinary Job that fill the volume.
//!
//! Every node serves the cluster's Images to itself, as a registry that can only be read:
//! `localhost:PORT/NAMESPACE/NAME:TAG` is the Image `NAME` of `NAMESPACE`, on any node.
//! "Itself" is kithd's own pull and nothing else on the node: an Image is a packed Volume,
//! and every process and container of the node can reach its loopback (see [`Door`]).
//
// ponytail: one layer and no base image (the volume holds the whole root); made once for a
// spec (a new tag is a new image: nodes keep a tag they have pulled); nothing is pushed
// with the registry protocol; an Image that is deleted leaves its Blobs to be deleted by
// hand; an Image that waits (no Volume, its Job not done) says nothing in its status.
// Each is left for later.

use crate::Shared;
use crate::blobs::Incoming;
use crate::volumes::Dir;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use kith_api::kinds::ImageSpec;
use kith_api::store::Store;
use kith_store::Command;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::watch;

/// How often a node looks for an image to make.
const ROUND: Duration = Duration::from_secs(5);
/// One that failed is tried again after this long.
const AGAIN: u64 = 60;
const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// An image to make now.
#[derive(Debug)]
struct Job {
    key: String,
    namespace: String,
    dir: Dir,
    spec: ImageSpec,
    /// What it is made of (the spec and the Job's run), hashed.
    of: String,
    /// The Blobs of the image it was before.
    old: Vec<String>,
}

/// The Images of volumes on `me` that are to be made at `now`.
fn due(store: &Store, me: &str, now: u64) -> Vec<Job> {
    let job = |image: &kith_api::Resource| {
        let spec: ImageSpec = serde_json::from_value(image.spec.clone()).ok()?;
        let namespace = image.metadata.namespace.clone().unwrap_or_else(|| "default".into());
        let dir = crate::volumes::dir(store, &namespace, &spec.volume).filter(|dir| dir.node == me)?;
        // (The Job as it is now: a status from before it was changed says nothing of this run.)
        let ran = match &spec.job {
            Some(job) => {
                let job = store.get(&format!("Job/{namespace}/{job}"))?;
                let status = job.status.as_ref()?;
                let current = status["observedRevision"].as_u64() == job.metadata.revision;
                (current && status["state"] == "succeeded").then_some(job.metadata.revision)?
            }
            None => None,
        };
        // What it is made of: the spec, and which run of the Job filled the volume.
        let of = format!("{}/{}", image.spec, ran.unwrap_or(0));
        let of = blake3::hash(of.as_bytes()).to_hex()[..16].to_string();
        let status = image.status.clone().unwrap_or_default();
        if status["of"] == of.as_str() || status["tried"].as_u64().is_some_and(|tried| now < tried + AGAIN) {
            return None;
        }
        let old = status["blobs"].as_object().into_iter().flatten();
        let old = old.filter_map(|(_, blob)| Some(blob.as_str()?.to_string())).collect();
        Some(Job {
            key: image.key(),
            namespace,
            dir,
            spec,
            of,
            old,
        })
    };
    store.list(Some("Image")).filter_map(job).collect()
}

/// A piece of an image in the blob store: its sha256 (hex), the blob it is, its size.
type Piece = (String, String, u64);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `bytes` kept as a blob.
fn keep(blobs: &Path, bytes: &[u8]) -> Result<Piece, String> {
    let mut incoming = Incoming::new(blobs).map_err(|e| format!("the blob store: {e}"))?;
    incoming.write(bytes).map_err(|e| format!("the blob store: {e}"))?;
    let (blob, size) = incoming.keep(None)?;
    Ok((hex(&Sha256::digest(bytes)), blob, size))
}

/// The directory `dir` as an OCI image in the blob store at `blobs`: its layer (a plain
/// tar: its digest is its diff id), its config and its manifest.
fn pack(dir: &Path, blobs: &Path, spec: &ImageSpec) -> Result<[Piece; 3], String> {
    let (blob, size) = crate::backups::archive(dir, blobs)?;
    let failed = |e: std::io::Error| format!("reading the layer: {e}");
    let mut file = std::fs::File::open(blobs.join(&blob)).map_err(failed)?;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0; 64 << 10];
    loop {
        match std::io::Read::read(&mut file, &mut chunk).map_err(failed)? {
            0 => break,
            n => hasher.update(&chunk[..n]),
        }
    }
    let layer = (hex(&hasher.finalize()), blob, size);
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let mut run = json!({ "Entrypoint": spec.entrypoint, "Cmd": spec.cmd, "Env": spec.env });
    if let Some(dir) = &spec.working_dir {
        run["WorkingDir"] = dir.as_str().into();
    }
    let config = json!({
        "architecture": architecture, "os": "linux", "config": run,
        "rootfs": { "type": "layers", "diff_ids": [format!("sha256:{}", layer.0)] },
    });
    let config = keep(blobs, config.to_string().as_bytes())?;
    let manifest = json!({
        "schemaVersion": 2, "mediaType": MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": format!("sha256:{}", config.0), "size": config.2 },
        "layers": [{ "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": format!("sha256:{}", layer.0), "size": layer.2 }],
    });
    let manifest = keep(blobs, manifest.to_string().as_bytes())?;
    Ok([layer, config, manifest])
}

/// Makes the image: its pieces in the blob store, a Blob for each, and the status that says so.
async fn make(shared: &Shared, state: &Path, job: &Job) -> Result<Value, String> {
    let from = crate::root_part::volume(state, &job.dir)?;
    let (blobs, spec) = (crate::blobs::dir(shared), job.spec.clone());
    let packed = tokio::task::spawn_blocking(move || pack(from.held(), &blobs, &spec)).await;
    let pieces = packed.map_err(|e| e.to_string())??;
    let mut resources = Vec::new();
    for (_, blob, size) in &pieces {
        let key = format!("Blob/{}/{blob}", job.namespace);
        let state = shared.store.lock().expect("a handler panicked holding the store");
        // (The same bytes as a Blob that is there: it is that Blob, whoever made it.)
        if state.store.get(&key).is_some() {
            continue;
        }
        let mut spec = json!({ "size": size });
        if let Some(copies) = job.spec.copies {
            spec["copies"] = copies.into();
        }
        let wanted = json!({
            "apiVersion": "kith.dev/v1", "kind": "Blob",
            "metadata": { "name": blob, "namespace": job.namespace, "annotations": { crate::blobs::MADE_BY: crate::blobs::IMAGE } },
            "spec": spec,
        });
        resources.push(serde_json::from_value(wanted).map_err(|e| e.to_string())?);
    }
    if !resources.is_empty() {
        let at = kith_api::store::now();
        let applied = crate::raft::as_node(shared.write(Command::Apply { resources, at })).await;
        applied.map_err(|e| e.to_string())?;
    }
    let [layer, config, manifest] = &pieces;
    let named: serde_json::Map<String, Value> = pieces
        .iter()
        .map(|(sha, blob, _)| (sha.clone(), blob.as_str().into()))
        .collect();
    Ok(json!({
        "digest": format!("sha256:{}", manifest.0), "size": layer.2 + config.2 + manifest.2,
        "blobs": named, "of": job.of, "message": null, "tried": null,
    }))
}

/// Lets go of the Blobs of the image `job` was before, but for those `kept`, those kith
/// did not make and those another Image or a Backup of the namespace has too. (When the
/// image's bytes are a backup's identical bytes, the Blob is the backup's, made by whichever
/// came first: it is left behind when the image lets go of it, not deleted.)
async fn forget(shared: &Shared, job: &Job, kept: &Value) {
    let keeps = |blob: &str| {
        kept["blobs"]
            .as_object()
            .is_some_and(|blobs| blobs.values().any(|name| name == blob))
    };
    for blob in job.old.iter().filter(|blob| !keeps(blob)) {
        let key = format!("Blob/{}/{blob}", job.namespace);
        let ours = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            let made = state
                .store
                .get(&key)
                .is_some_and(|blob| crate::blobs::made_by(blob, crate::blobs::IMAGE));
            made && !crate::backups::listed(&state.store, &job.namespace, &job.key, blob)
        };
        if ours && let Err(e) = shared.submit_node(Command::Delete { key: key.clone() }).await {
            eprintln!("kithd: image {}: {key} was not removed: {e}", job.key);
        }
    }
}

/// How long a Blob an Image made may be listed by no Image and no Backup before it is let go of.
/// (A running `make` puts its Blobs before it writes the status that lists them.)
const UNLISTED: u64 = 600;

/// The keys of the Blobs an Image made that no Image or Backup has listed for `UNLISTED` seconds:
/// those of an Image that was deleted. `seen` is when each was first seen unlisted.
fn released(store: &Store, seen: &mut BTreeMap<String, u64>, now: u64) -> Vec<String> {
    let mut made = BTreeSet::new();
    let mut out = Vec::new();
    for blob in store
        .list(Some("Blob"))
        .filter(|b| crate::blobs::made_by(b, crate::blobs::IMAGE))
    {
        let namespace = blob.metadata.namespace.as_deref().unwrap_or("default");
        let key = blob.key();
        if crate::backups::listed(store, namespace, "", &blob.metadata.name) {
            seen.remove(&key);
        } else if now.saturating_sub(*seen.entry(key.clone()).or_insert(now)) >= UNLISTED {
            out.push(key.clone());
        }
        made.insert(key);
    }
    seen.retain(|key, _| made.contains(key));
    out
}

/// Makes the images that are due of the volumes on this node.
pub async fn run(shared: Arc<Shared>, state: PathBuf, mut stopping: watch::Receiver<bool>) {
    // When the leader first saw each Blob of an Image unlisted (kept by the leader only).
    let mut unlisted = BTreeMap::new();
    loop {
        tokio::select! {
            _ = stopping.changed() => return,
            () = tokio::time::sleep(ROUND) => {}
        }
        let now = kith_api::store::now();
        // One node lets go of the Blobs of deleted Images: the leader (blob gc does the files).
        if crate::dns::leads(&shared) {
            let gone = {
                let state = shared.store.lock().expect("a handler panicked holding the store");
                released(&state.store, &mut unlisted, now)
            };
            for key in gone {
                match shared.submit_node(Command::Delete { key: key.clone() }).await {
                    Ok(_) | Err(kith_api::store::Error::NotFound(_)) => {}
                    Err(e) => eprintln!("kithd: {key} of a deleted image was not removed: {e}"),
                }
            }
        } else {
            unlisted.clear();
        }
        let jobs = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            due(&state.store, shared.members.me(), now)
        };
        // ponytail: one at a time; a large volume holds up the next image.
        for job in jobs {
            let fields = match make(&shared, &state, &job).await {
                Ok(made) => {
                    eprintln!(
                        "kithd: image {} made ({})",
                        job.key,
                        made["digest"].as_str().unwrap_or_default()
                    );
                    forget(&shared, &job, &made).await;
                    made
                }
                Err(e) => {
                    eprintln!("kithd: image {} was not made: {e}", job.key);
                    json!({ "message": e, "tried": now })
                }
            };
            let statuses = vec![(job.key.clone(), fields.as_object().expect("an object").clone())];
            if let Err(e) = shared.submit(Command::Patch { statuses }).await {
                eprintln!("kithd: image {}: its status was not written: {e}", job.key);
                // (Refused whole, as a worker's that names a blob another node made is: said
                // on it and tried again later, not made anew each round.)
                let failed = json!({ "message": e.to_string(), "tried": now });
                let statuses = vec![(job.key.clone(), failed.as_object().expect("an object").clone())];
                drop(shared.submit(Command::Patch { statuses }).await);
            }
        }
    }
}

// ---- The registry ----

/// What a request to the registry asks for: (namespace, name, a manifest or a blob, which).
fn asked(path: &str) -> Option<(&str, &str, bool, &str)> {
    let mut parts = path.strip_prefix("/v2/")?.split('/');
    let (namespace, name, what, which) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let manifest = match what {
        "manifests" => true,
        "blobs" => false,
        _ => return None,
    };
    (parts.next().is_none() && !which.is_empty()).then_some((namespace, name, manifest, which))
}

/// The Blob (its key) and the sha256 of what `path` asks for, as the Images in `store` have it.
fn found(store: &Store, path: &str) -> Option<(String, String)> {
    let (namespace, name, manifest, which) = asked(path)?;
    let image = store.get(&format!("Image/{namespace}/{name}"))?;
    let status = image.status.as_ref()?;
    let spec: ImageSpec = serde_json::from_value(image.spec.clone()).ok()?;
    let digest = status["digest"].as_str()?.strip_prefix("sha256:")?;
    let sha = match which.strip_prefix("sha256:") {
        Some(sha) if manifest => (sha == digest).then_some(sha)?,
        Some(sha) => sha,
        // (A tag: the manifest's, and only while the image is what the spec says.)
        None => (manifest && which == spec.tag()).then_some(digest)?,
    };
    let blob = status["blobs"][sha].as_str()?;
    Some((format!("Blob/{namespace}/{blob}"), sha.to_string()))
}

async fn answer(shared: Arc<Shared>, uri: Uri) -> Response {
    if uri.path() == "/v2/" || uri.path() == "/v2" {
        return ([(header::CONTENT_TYPE, "application/json")], "{}").into_response();
    }
    let unknown = || {
        let said = json!({ "errors": [{ "code": "MANIFEST_UNKNOWN", "message": "no Image of the cluster is that" }] });
        (StatusCode::NOT_FOUND, axum::Json(said)).into_response()
    };
    let known = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        found(&state.store, uri.path())
    };
    let Some((key, sha)) = known else { return unknown() };
    let file = match crate::blobs::here(&shared, &key).await {
        Ok(path) => std::fs::File::open(path),
        Err(e) => Err(std::io::Error::other(e)),
    };
    if let Err(e) = &file {
        eprintln!("kithd: registry: {key}: {e}");
    }
    piece(uri.path(), &sha, file)
}

/// The piece `sha` of an image as the registry sends it, asked for at `path`.
fn piece(path: &str, sha: &str, file: std::io::Result<std::fs::File>) -> Response {
    match file.and_then(|file| Ok((file.metadata()?.len(), file))) {
        Ok((size, file)) => {
            let kind = if path.contains("/manifests/") {
                MANIFEST
            } else {
                "application/octet-stream"
            };
            let head = [
                (header::CONTENT_LENGTH, size.to_string()),
                (header::CONTENT_TYPE, kind.to_string()),
                (
                    header::HeaderName::from_static("docker-content-digest"),
                    format!("sha256:{sha}"),
                ),
            ];
            (head, Body::from_stream(crate::blobs::chunks(file))).into_response()
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}

/// The registry's certificate (DER) and the server that shows it, or why there is neither.
type Tls = Result<(Vec<u8>, Arc<rustls::ServerConfig>), String>;

/// What stands between this node's registry and everything on the node that is not
/// kithd's own pull. Made anew for every start and written nowhere: a certificate only
/// that pull trusts (so nothing of a pull is read off the loopback, and whoever takes the
/// port in kithd's place is shown no password), and a password only it is given.
pub struct Door {
    pub local: kith_runtime::Local,
    /// Made when the registry is first asked, by the pull or by whoever connects: making
    /// a key at start cost a node that serves no Image half a megabyte of resident memory.
    tls: Arc<OnceLock<Tls>>,
    /// SHA-256 of the `authorization` a request must carry.
    wanted: [u8; 32],
    /// Why the registry's port is not this kithd's, where it could not be taken.
    shut: Arc<OnceLock<String>>,
}

impl Door {
    pub fn new(port: u16) -> Result<Door, String> {
        let mut secret = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut secret)
            .map_err(|_| "no random bytes from the system")?;
        let password = hex(&secret);
        let tls = Arc::new(OnceLock::new());
        let shut = Arc::new(OnceLock::<String>::new());
        let (made, why) = (tls.clone(), shut.clone());
        // (No port, no certificate: the pull stops here, with the reason, and asks no one.)
        let certificate = move || match why.get() {
            Some(why) => Err(why.clone()),
            None => Door::made(&made).clone().map(|(certificate, _)| certificate),
        };
        let said = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("kithd:{password}"));
        Ok(Door {
            wanted: Sha256::digest(format!("Basic {said}")).into(),
            tls,
            shut,
            local: kith_runtime::Local {
                port,
                password,
                certificate: Arc::new(certificate),
            },
        })
    }

    /// Take the registry's port ([`bind`]). Where it cannot be taken, every pull of an own
    /// Image from now on is told why.
    pub fn bind(&self) -> std::io::Result<std::net::TcpListener> {
        let port = self.local.port;
        let taken = bind(port);
        if let Err(e) = &taken {
            let _ = self.shut.set(format!(
                "127.0.0.1:{port} could not be taken ({e}): this node serves no Image"
            ));
        }
        taken
    }

    fn made(tls: &OnceLock<Tls>) -> &Tls {
        tls.get_or_init(crate::pki::local_config)
    }

    /// What a request that does not carry this start's password is told; `None` lets it in.
    // Digests are compared, so how long that takes says nothing about the password.
    fn refusal(&self, headers: &HeaderMap) -> Option<Response> {
        let said = headers.get(header::AUTHORIZATION).map(|said| said.as_bytes());
        if <[u8; 32]>::from(Sha256::digest(said.unwrap_or_default())) == self.wanted {
            return None;
        }
        let why =
            json!({ "errors": [{ "code": "UNAUTHORIZED", "message": "this registry answers its node's kithd only" }] });
        // (Basic, and no token realm: there is nowhere else to send the password. And the
        // connection closes after it: nothing more is answered on one that was refused.)
        let ask = [
            (header::WWW_AUTHENTICATE, "Basic realm=\"kithd\""),
            (header::CONNECTION, "close"),
        ];
        Some((StatusCode::UNAUTHORIZED, ask, axum::Json(why)).into_response())
    }
}

/// The registry's connections, shaken or not, at a time (a slot is taken before a connection
/// is accepted and kept until it closes; kithd pulls a handful of layers at a time), and
/// the time a connection may move no byte, from its handshake's end, before it is closed
/// (while it is answering a request, that time does not run).
// ponytail: a process of the node can still take the registry's slots in turn (a few seconds
// each), or hold one on a request, and slow Image pulls: telling peers apart needs their identity,
// which SO_PEERCRED does not give on TCP. A limit per user, or a Unix socket, if that is seen.
const CONNECTIONS: usize = 64;
const IDLE: Duration = Duration::from_secs(5);
/// How long a TLS handshake may take (on the loopback it is milliseconds), and how long a
/// request's head may take to arrive whole (hyper's header read time; a head past 64 KiB is
/// refused by hyper, too).
const HANDSHAKE: Duration = Duration::from_secs(2);
const HEAD: Duration = Duration::from_secs(5);
/// How long a stopping registry waits for its open connections to finish their answers before
/// they are dropped.
const DRAIN: Duration = Duration::from_secs(3);

type Secured = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

/// The requests a connection is answering now. While one is, the connection's idle time does
/// not run: an answer may wait on a copy from another node far longer than the idle time.
#[derive(Clone, Default)]
struct Busy(Arc<std::sync::atomic::AtomicUsize>);

impl Busy {
    /// Counts a request as answered until the returned guard is dropped (a dropped handler too).
    fn answering(&self) -> Answering {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Answering(self.clone())
    }

    fn is_answering(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst) > 0
    }
}

struct Answering(Busy);

impl Drop for Answering {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A connection the registry serves: its TLS stream, which closes once no byte moves for
/// the idle time (`Idle`, counted from the handshake's end), and the slot it has held since
/// before it was accepted, given back when it closes.
struct Slotted {
    stream: crate::ingress::Idle<Secured>,
    busy: Busy,
    _slot: tokio::sync::OwnedSemaphorePermit,
}

impl Slotted {
    /// While a request is answered, the idle time starts over at every poll of the stream.
    fn renew_if_answering(&mut self) {
        if self.busy.is_answering() {
            self.stream.renew();
        }
    }
}

impl tokio::io::AsyncRead for Slotted {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.renew_if_answering();
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Slotted {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.renew_if_answering();
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.renew_if_answering();
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.renew_if_answering();
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// The registry's connections, each once its handshake is done.
fn listen(
    tcp: tokio::net::TcpListener,
    tls: Arc<OnceLock<Tls>>,
    bound: usize,
    idle: Duration,
) -> tokio::sync::mpsc::Receiver<Slotted> {
    let (tx, ready) = tokio::sync::mpsc::channel(bound);
    let slots = Arc::new(tokio::sync::Semaphore::new(bound));
    tokio::spawn(async move {
        loop {
            // (Nobody serves any more: the port is given back, even with every slot taken.)
            let slot = tokio::select! {
                () = tx.closed() => return,
                slot = slots.clone().acquire_owned() => slot,
            };
            let Ok(slot) = slot else {
                return;
            };
            let accepted = tokio::select! {
                () = tx.closed() => return,
                accepted = tcp.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else {
                // Out of file descriptors, most likely: let some close.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            let (tls, tx) = (tls.clone(), tx.clone());
            tokio::spawn(async move {
                // (No certificate: nobody is let in, and the pull says why.)
                let Ok((_, tls)) = Door::made(&tls) else { return };
                let acceptor = tokio_rustls::TlsAcceptor::from(tls.clone());
                let shaken = tokio::time::timeout(HANDSHAKE, acceptor.accept(stream)).await;
                // (A connection that did not shake hands gives its slot back here.)
                if let Ok(Ok(stream)) = shaken {
                    let stream = Slotted {
                        stream: crate::ingress::Idle::new(stream, idle, None),
                        busy: Busy::default(),
                        _slot: slot,
                    };
                    let _ = tx.send(stream).await;
                }
            });
        }
    });
    ready
}

/// `app` on `tcp` behind the door: TLS, and the password before anything of a request
/// (its path, too) is looked at, whatever it asks for. Each connection is served by hyper
/// itself, so a request's head must arrive whole within `head`.
async fn behind(
    tcp: tokio::net::TcpListener,
    door: Arc<Door>,
    app: axum::Router,
    mut stopping: watch::Receiver<bool>,
    bound: usize,
    idle: Duration,
    head: Duration,
) {
    let mut accepted = listen(tcp, door.tls.clone(), bound, idle);
    let guard = move |request: axum::extract::Request, next: axum::middleware::Next| {
        let door = door.clone();
        async move {
            match door.refusal(request.headers()) {
                Some(refused) => refused,
                None => {
                    // (A refused request is not answered, so it does not hold the idle time off.)
                    let busy = request.extensions().get::<Busy>();
                    debug_assert!(busy.is_some(), "a connection of the registry carries its Busy");
                    // ponytail: the answering mark ends when the handler returns, before a body
                    // has gone out. That holds while a body's bytes come without waiting (a blob
                    // is a file of this node by then, see `blobs::chunks`): the idle time then
                    // starts over as bytes move and runs out only on a client that stops reading.
                    // A body that waits on something else would need the mark carried in it.
                    let _answering = busy.map(|busy| busy.answering());
                    next.run(request).await
                }
            }
        }
    };
    let app = app.layer(axum::middleware::from_fn(guard));
    // ponytail: hyper's limits, a head within 64 KiB and within `head` of starting to read it;
    // no other request limit. A slow answer is not bounded here (the copy of a blob may take as long).
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(head)
        .max_buf_size(64 * 1024);
    let mut open = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = stopping.changed() => break,
            Some(stream) = accepted.recv() => {
                // (Each connection carries its own Busy, read by the guard.)
                let service = hyper_util::service::TowerToHyperService::new(
                    app.clone().layer(axum::Extension(stream.busy.clone())),
                );
                let http = http.clone();
                let mut stopped = stopping.clone();
                open.spawn(async move {
                    let connection = http.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
                    let mut connection = std::pin::pin!(connection);
                    tokio::select! {
                        _ = connection.as_mut() => {}
                        // (Told to close once its answer, if any, is out: an idle one closes now.)
                        _ = async { let _ = stopped.wait_for(|stopped| *stopped).await; } => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
            // (Finished connections are let go as they finish, not kept until the end.)
            Some(_) = open.join_next(), if !open.is_empty() => {}
        }
    }
    // (Nothing more is accepted; what is open is answered out, for `DRAIN` at most.)
    drop(accepted);
    let drained = tokio::time::timeout(DRAIN, async { while open.join_next().await.is_some() {} }).await;
    if drained.is_err() {
        open.shutdown().await;
    }
}

/// Serves the cluster's Images on this node's loopback, to kithd's own pulls (no door:
/// not at all).
/// The registry's port, taken at kithd's start and before anything is started: a start from
/// one of the node's own Images asks this registry whatever its pull policy, and one asked
/// before [`serve`] runs waits in the kernel's queue where it would have been refused.
pub fn bind(port: u16) -> std::io::Result<std::net::TcpListener> {
    let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    tcp.set_nonblocking(true)?;
    Ok(tcp)
}

/// Serve the node's Images behind `door` on the port [`bind`] took. Where it could not be
/// taken, the door stays the runtime's (see main): a start from an own Image then fails
/// rather than ask whatever else has the port.
pub async fn serve(
    shared: Arc<Shared>,
    door: Option<(Arc<Door>, std::io::Result<std::net::TcpListener>)>,
    stopping: watch::Receiver<bool>,
) {
    let Some((door, tcp)) = door else { return };
    let port = door.local.port;
    let tcp = match tcp.and_then(tokio::net::TcpListener::from_std) {
        Ok(tcp) => tcp,
        Err(e) => return eprintln!("kithd: registry: 127.0.0.1:{port}: {e}: Images are not served on this node"),
    };
    // (`get` answers HEAD too, without the body.)
    let app = axum::Router::new().fallback(axum::routing::get(move |uri: Uri| answer(shared.clone(), uri)));
    behind(tcp, door, app, stopping, CONNECTIONS, IDLE, HEAD).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_api::Resource;

    fn store(resources: Value) -> Store {
        let mut store = Store::default();
        let resources: Vec<Resource> = serde_json::from_value(resources).unwrap();
        // (An apply drops the status: it is written apart, as the controllers do.)
        let statuses: Vec<_> = resources.iter().map(|r| (r.key(), r.status.clone())).collect();
        store.apply_all(resources).unwrap();
        for (key, status) in statuses.into_iter().filter(|(_, status)| status.is_some()) {
            store.set_status(&key, status).unwrap();
        }
        store
    }

    fn blob(name: &str, by: &str) -> Value {
        json!({ "apiVersion": "kith.dev/v1", "kind": "Blob",
            "metadata": { "name": name, "namespace": "team", "annotations": { crate::blobs::MADE_BY: by } },
            "spec": { "size": 1 } })
    }

    fn lister(kind: &str, name: &str, status: Value) -> Value {
        json!({ "apiVersion": "kith.dev/v1", "kind": kind,
            "metadata": { "name": name, "namespace": "team" }, "spec": if kind == "Image" { json!({ "volume": "v" }) } else { json!({ "volume": "v", "every": "1h" }) },
            "status": status })
    }

    /// An Image's Blobs are let go of ten minutes after nothing lists them (it was deleted), and
    /// no sooner; a Blob another Image or a Backup lists, one a Backup made and one put by hand stay.
    #[test]
    fn images_released() {
        let all = |image: bool| {
            let mut all = vec![
                blob("gone", "image"),
                blob("shared", "image"),
                blob("backups", "backup"),
                blob("byhand", "other"),
                blob("backed", "image"),
                lister("Image", "other", json!({ "blobs": { "s": "shared" } })),
                lister("Backup", "daily", json!({ "backups": [{ "blob": "backed" }] })),
            ];
            if image {
                all.push(lister("Image", "app", json!({ "blobs": { "g": "gone" } })));
            }
            store(Value::Array(all))
        };
        let mut seen = BTreeMap::new();
        // (The Image is there: its Blob is listed, and nothing is let go of however long.)
        assert!(released(&all(true), &mut seen, 0).is_empty());
        assert!(released(&all(true), &mut seen, 100_000).is_empty());
        // (Deleted: the clock starts when it is first seen unlisted.)
        let gone = all(false);
        assert!(released(&gone, &mut seen, 100_000).is_empty());
        assert!(released(&gone, &mut seen, 100_000 + UNLISTED - 1).is_empty());
        assert_eq!(released(&gone, &mut seen, 100_000 + UNLISTED), ["Blob/team/gone"]);
        // (Once it is gone from the store, nothing is remembered of it.)
        let none = store(Value::Array(vec![
            blob("shared", "image"),
            lister("Image", "other", json!({ "blobs": { "s": "shared" } })),
        ]));
        assert!(released(&none, &mut seen, 200_000).is_empty());
        assert!(seen.is_empty());
    }

    fn sha_of(path: &Path) -> String {
        hex(&Sha256::digest(std::fs::read(path).unwrap()))
    }

    /// A directory becomes an image a registry can serve: the manifest names the config and
    /// the layer by what their bytes hash to, the config names the layer, and the layer is
    /// the directory.
    /// `app` behind a door of its own, on a port of this machine; the sender stops it.
    async fn opened(app: axum::Router) -> (Arc<Door>, watch::Sender<bool>) {
        bounded(app, CONNECTIONS, IDLE).await
    }

    /// `opened`, with the test's own bound and idle time.
    async fn bounded(app: axum::Router, bound: usize, idle: Duration) -> (Arc<Door>, watch::Sender<bool>) {
        bounded_head(app, bound, idle, HEAD).await
    }

    /// `bounded`, with the test's own head time too.
    async fn bounded_head(
        app: axum::Router,
        bound: usize,
        idle: Duration,
        head: Duration,
    ) -> (Arc<Door>, watch::Sender<bool>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let door = Arc::new(Door::new(tcp.local_addr().unwrap().port()).unwrap());
        let (stop, stopping) = watch::channel(false);
        tokio::spawn(behind(tcp, door.clone(), app, stopping, bound, idle, head));
        (door, stop)
    }

    /// A TLS connection to the registry on `port`, trusting `certificate`, its handshake done.
    async fn shaken(port: u16, certificate: Vec<u8>) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.into()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        connector.connect(name, tcp).await.unwrap()
    }

    /// Twenty-four pieces of 1 KB, each 200 ms after the one before: the whole takes longer than
    /// the tests' idle time, and no gap between bytes is as long as it.
    fn trickled() -> axum::body::Body {
        let pieces = futures_util::stream::unfold(0u8, |n| async move {
            if n == 24 {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            Some((Ok::<Vec<u8>, std::io::Error>(vec![b'#'; 1024]), n + 1))
        });
        axum::body::Body::from_stream(pieces)
    }

    /// Nothing is said to who does not carry this start's password, whatever is asked
    /// for and however: every path there is and those there are not, with no password,
    /// a wrong one, the right one under another name or as a token. And nothing at all
    /// to who does not speak TLS, or does not trust the certificate of this start.
    #[tokio::test]
    async fn the_registry_needs_the_nodes_password_whatever_is_asked() {
        let inside = axum::Router::new().fallback(axum::routing::get(|| async { "inside" }));
        let (door, _stop) = opened(inside).await;
        let (port, password) = (door.local.port, door.local.password.clone());
        assert!(
            door.tls.get().is_none(),
            "a key was made before anybody asked the registry"
        );
        let trusted = reqwest::Certificate::from_der(&(door.local.certificate)().unwrap()).unwrap();
        let client = reqwest::Client::builder().tls_certs_only([trusted]).build().unwrap();
        let sha = "a".repeat(64);
        for path in [
            "/v2/".to_string(),
            "/v2".into(),
            "/v2/team/hello/manifests/1".into(),
            format!("/v2/team/hello/manifests/sha256:{sha}"),
            format!("/v2/team/hello/blobs/sha256:{sha}"),
            "/v2/team/hello/tags/list".into(),
            "/v2/_catalog".into(),
            "/v2/team/hello/blobs/uploads/".into(),
            "/".into(),
            "/v1/apply".into(),
        ] {
            let url = format!("https://localhost:{port}{path}");
            for method in [reqwest::Method::GET, reqwest::Method::HEAD, reqwest::Method::POST] {
                let ask = || client.request(method.clone(), &url);
                let outside = [
                    ask(),
                    ask().basic_auth("kithd", Some("not-it")),
                    ask().basic_auth("kithd", None::<&str>),
                    ask().basic_auth("root", Some(&password)),
                    ask().bearer_auth(&password),
                    ask().header("authorization", &password),
                ];
                for (n, request) in outside.into_iter().enumerate() {
                    let said = request.send().await.unwrap();
                    assert_eq!(said.status(), 401, "{method} {path} (try {n})");
                    let how = said.headers()["www-authenticate"].to_str().unwrap().to_string();
                    assert!(how.starts_with("Basic "), "{how}");
                    assert!(!said.text().await.unwrap().contains("inside"), "{method} {path}");
                }
            }
            let said = client
                .get(&url)
                .basic_auth("kithd", Some(&password))
                .send()
                .await
                .unwrap();
            assert_eq!(
                (said.status().as_u16(), said.text().await.unwrap().as_str()),
                (200, "inside"),
                "{path}"
            );
        }
        // The password of another start (another door) opens nothing here.
        let other = Door::new(port).unwrap();
        let url = format!("https://127.0.0.1:{port}/v2/");
        let said = client.get(&url).basic_auth("kithd", Some(&other.local.password));
        assert_eq!(said.send().await.unwrap().status(), 401);
        // Without TLS there is no answer at all, with the password or without.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut plain = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("kithd:{password}"));
        let request = format!("GET /v2/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {basic}\r\n\r\n");
        plain.write_all(request.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), plain.read_to_end(&mut reply)).await;
        let reply = String::from_utf8_lossy(&reply);
        assert!(!reply.contains("HTTP/1.1") && !reply.contains("inside"), "{reply}");
        // And who trusts the usual authorities, or another start's certificate, hangs up.
        for roots in [
            None,
            Some(reqwest::Certificate::from_der(&(other.local.certificate)().unwrap()).unwrap()),
        ] {
            let builder = reqwest::Client::builder();
            let stranger = match roots {
                Some(root) => builder.tls_certs_only([root]),
                None => builder,
            };
            let asked = stranger.build().unwrap().get(&url).basic_auth("kithd", Some(&password));
            assert!(asked.send().await.is_err());
        }
    }

    /// kithd's own pull, given what the door was made with, gets the image by either name
    /// of the registry; a pull without it, with another password or trusting another
    /// certificate gets nothing.
    #[tokio::test]
    async fn the_registry_serves_kithds_own_pull_and_no_other() {
        let root = std::env::temp_dir().join(format!("kith-registry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (dir, blobs) = (root.join("volume"), root.join("blobs"));
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin/hello"), "#!/bin/sh\necho hello\n").unwrap();
        let spec: ImageSpec = serde_json::from_value(json!({ "volume": "out", "entrypoint": ["/bin/hello"] })).unwrap();
        let [layer, config, manifest] = pack(&dir, &blobs, &spec).unwrap();
        let at = |what: &str, which: &str| format!("/v2/team/hello/{what}/{which}");
        let files: std::collections::HashMap<String, (String, PathBuf)> = [
            (at("manifests", "1"), &manifest),
            (at("manifests", &format!("sha256:{}", manifest.0)), &manifest),
            (at("blobs", &format!("sha256:{}", config.0)), &config),
            (at("blobs", &format!("sha256:{}", layer.0)), &layer),
        ]
        .into_iter()
        .map(|(path, (sha, blob, _))| (path, (sha.clone(), blobs.join(blob))))
        .collect();
        let files = Arc::new(files);
        let serve = move |uri: Uri| {
            let files = files.clone();
            async move {
                match files.get(uri.path()) {
                    Some((sha, file)) => piece(uri.path(), sha, std::fs::File::open(file)),
                    None if uri.path() == "/v2/" => "{}".into_response(),
                    None => StatusCode::NOT_FOUND.into_response(),
                }
            }
        };
        let (door, _stop) = opened(axum::Router::new().fallback(axum::routing::get(serve))).await;
        let port = door.local.port;
        let store = |name: &str, local: Option<kith_runtime::Local>| {
            let mut store = kith_runtime::ImageStore::new(root.join(name)).unwrap();
            store.local = local;
            store
        };
        let always = kith_runtime::PullPolicy::Always;
        let own = store("own", Some(door.local.clone()));
        for name in ["localhost", "127.0.0.1"] {
            let image = own.pull(&format!("{name}:{port}/team/hello:1"), always).await.unwrap();
            assert_eq!(image.digest, format!("sha256:{}", manifest.0));
            assert_eq!(image.entrypoint, ["/bin/hello"]);
            let run = std::fs::read_to_string(image.rootfs.join("bin/hello")).unwrap();
            assert!(run.contains("echo hello"), "{run}");
        }
        let other = Door::new(port).unwrap().local;
        let wrong_password = kith_runtime::Local {
            password: other.password.clone(),
            ..door.local.clone()
        };
        let wrong_certificate = kith_runtime::Local {
            certificate: other.certificate.clone(),
            ..door.local.clone()
        };
        for (name, local) in [
            ("none", None),
            ("password", Some(wrong_password)),
            ("certificate", Some(wrong_certificate)),
            ("neither", Some(other)),
        ] {
            let stranger = store(name, local);
            let pulled = stranger.pull(&format!("localhost:{port}/team/hello:1"), always).await;
            assert!(pulled.is_err(), "a pull with {name} of the door's was served");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Where something else has the registry's port, a start from an own Image says so: the
    /// port and why it could not be taken, not that a connection was refused or not trusted.
    #[tokio::test]
    async fn registry_port_taken() {
        let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = other.local_addr().unwrap().port();
        let door = Door::new(port).unwrap();
        let bind = door.bind().unwrap_err().to_string();
        let root = std::env::temp_dir().join(format!("kith-port-taken-{}", std::process::id()));
        let mut store = kith_runtime::ImageStore::new(root.clone()).unwrap();
        store.local = Some(door.local.clone());
        let own = format!("localhost:{port}/team/hello:1");
        let pull = store.pull(&own, kith_runtime::PullPolicy::Always);
        // (Whoever has the port here never answers: a pull that asked it would wait.)
        let pull = tokio::time::timeout(Duration::from_secs(5), pull).await;
        let why = pull
            .expect("the pull asked whoever has the port")
            .unwrap_err()
            .to_string();
        assert!(
            why.contains(&format!("127.0.0.1:{port}")) && why.contains(&bind),
            "{why}"
        );
        assert!(
            door.tls.get().is_none(),
            "a key was made for a registry that is not served"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The node's own registry is asked for an Image on every pull, as kithd's own store
    /// answers it: one deleted from the store is not started from the copy the node kept,
    /// and the pull says which Image it was. (The ask of an unchanged one is timed.)
    #[tokio::test]
    async fn cached_image_is_asked_for_again_after_it_is_deleted() {
        let root = std::env::temp_dir().join(format!("kith-cached-image-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (dir, blobs) = (root.join("volume"), root.join("blobs"));
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin/hello"), "#!/bin/sh\necho hello\n").unwrap();
        let spec: ImageSpec = serde_json::from_value(json!({ "volume": "out", "entrypoint": ["/bin/hello"] })).unwrap();
        let [layer, config, manifest] = pack(&dir, &blobs, &spec).unwrap();
        let mut kept = store(json!([
            { "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "out" }, "spec": { "node": "n1", "path": "out" } },
            { "apiVersion": "kith.dev/v1", "kind": "Image", "metadata": { "name": "hello" },
              "spec": { "volume": "out", "tag": "1", "entrypoint": ["/bin/hello"] } },
        ]));
        // (What `make` records for a made Image: its manifest's digest, and the blob each piece is.)
        let names: serde_json::Map<String, Value> = [&layer, &config, &manifest]
            .into_iter()
            .map(|(sha, name, _)| (sha.clone(), json!(name)))
            .collect();
        let digest = format!("sha256:{}", manifest.0);
        kept.set_status("Image/default/hello", Some(json!({ "digest": digest, "blobs": names })))
            .unwrap();
        let state = Arc::new(std::sync::Mutex::new(kept));
        let serve = {
            let state = state.clone();
            move |uri: Uri| {
                let (state, blobs) = (state.clone(), blobs.clone());
                async move {
                    let known = found(&state.lock().unwrap(), uri.path());
                    match known {
                        Some((key, sha)) => {
                            let name = key.rsplit('/').next().unwrap_or_default();
                            piece(uri.path(), &sha, std::fs::File::open(blobs.join(name)))
                        }
                        None if uri.path() == "/v2/" => "{}".into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            }
        };
        let (door, _stop) = opened(axum::Router::new().fallback(axum::routing::get(serve))).await;
        let mut own = kith_runtime::ImageStore::new(root.join("own")).unwrap();
        own.local = Some(door.local.clone());
        let reference = format!("localhost:{}/default/hello:1", door.local.port);
        let always = kith_runtime::PullPolicy::Always;
        let first = own
            .pull(&reference, kith_runtime::PullPolicy::IfNotPresent)
            .await
            .unwrap();
        assert_eq!(first.downloaded, 1, "the first pull did not fetch the Image's layer");
        let asking = std::time::Instant::now();
        let again = own.pull(&reference, always).await.unwrap();
        eprintln!(
            "kithd cached_image: an unchanged Image asked for in {} ms",
            asking.elapsed().as_millis()
        );
        assert_eq!(again.digest, digest);
        assert_eq!(again.downloaded, 0, "an unchanged Image's layer was downloaded again");
        // And the root part is not asked to unpack what is here.
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let hook = |_: String, _: String, _: Vec<std::fs::File>| -> kith_runtime::Unpacking {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Err("nothing to unpack".to_string()) })
        };
        own.pull_with(&reference, always, &[], &hook).await.unwrap();
        assert_eq!(
            asked.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a cached Image was unpacked again"
        );
        state.lock().unwrap().delete("Image/default/hello").unwrap();
        for policy in [
            kith_runtime::PullPolicy::IfNotPresent,
            always,
            kith_runtime::PullPolicy::Never,
        ] {
            let reason = own.pull(&reference, policy).await.unwrap_err().to_string();
            assert!(reason.contains("default/hello:1"), "{policy:?}: {reason}");
            // The registry's refusal of the manifest it was asked for, not the store's copy.
            assert!(
                reason.contains("manifests/1"),
                "{policy:?}: the registry was not asked: {reason}"
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Two connections that shake hands and say nothing hold the registry's bound; a third
    /// waits in the kernel's queue, and is served once the idle time has closed one of them.
    #[tokio::test]
    async fn registry_bounds_connections_shaken_or_not() {
        let idle = Duration::from_secs(5);
        let app = axum::Router::new().fallback(axum::routing::get(|| async { "inside" }));
        let (door, _stop) = bounded(app, 2, idle).await;
        let (port, certificate) = (door.local.port, (door.local.certificate)().unwrap());
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(shaken(port, certificate.clone()).await);
        }
        let third = tokio::spawn(shaken(port, certificate.clone()));
        use tokio::io::AsyncReadExt;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !third.is_finished(),
            "a third connection shook hands with the bound held"
        );
        let mut first = held.remove(0);
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(20), first.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "no connection of the bound was closed: {closed:?}"
        );
        let served = tokio::time::timeout(Duration::from_secs(20), third).await;
        assert!(
            matches!(served, Ok(Ok(_))),
            "the third was not served once a slot was given back"
        );
    }

    /// No byte moves for the idle time after the handshake: the registry closes the connection.
    #[tokio::test]
    async fn registry_bounds_a_silent_connection_is_closed_after_the_idle_time() {
        let idle = Duration::from_millis(300);
        let app = axum::Router::new().fallback(axum::routing::get(|| async { "inside" }));
        let (door, _stop) = bounded(app, 2, idle).await;
        use tokio::io::AsyncReadExt;
        let mut silent = shaken(door.local.port, (door.local.certificate)().unwrap()).await;
        let began = std::time::Instant::now();
        let mut byte = [0u8; 1];
        let said = tokio::time::timeout(Duration::from_secs(10), silent.read(&mut byte)).await;
        assert!(
            matches!(said, Ok(Ok(0)) | Ok(Err(_))),
            "a silent connection was not closed: {said:?}"
        );
        assert!(
            began.elapsed() >= idle / 2,
            "a connection was closed before the idle time"
        );
    }

    /// A request the registry is answering is not cut by the idle time: a handler that takes
    /// longer than the idle time answers on the same connection, and once it has answered,
    /// the connection, idle again, is closed and gives its slot back (the bound is 1, so a
    /// second connection is served only after the first has gone).
    #[tokio::test]
    async fn registry_bounds_a_request_being_answered_is_not_cut_by_the_idle_time() {
        let idle = Duration::from_secs(2);
        let app = axum::Router::new().fallback(axum::routing::get(|uri: axum::http::Uri| async move {
            if uri.path().ends_with("/slow") {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            "inside"
        }));
        let (door, _stop) = bounded(app, 1, idle).await;
        let (port, password) = (door.local.port, door.local.password.clone());
        let certificate = (door.local.certificate)().unwrap();
        use tokio::io::AsyncWriteExt;
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("kithd:{password}"));
        let get =
            |path: &str| format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {basic}\r\n\r\n");
        let mut first = shaken(port, certificate.clone()).await;
        first.write_all(get("/v2/team/slow").as_bytes()).await.unwrap();
        let said = tokio::time::timeout(Duration::from_secs(20), read_inside(&mut first)).await;
        assert!(
            matches!(&said, Ok(said) if said.ends_with(b"inside")),
            "an answer that took longer than the idle time was cut: {said:?}"
        );
        use tokio::io::AsyncReadExt;
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(10), first.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "the answered connection was not closed once idle: {closed:?}"
        );
        let mut second = tokio::time::timeout(Duration::from_secs(20), shaken(port, certificate))
            .await
            .expect("the answered connection's slot was not given back");
        second.write_all(get("/v2/team/quick").as_bytes()).await.unwrap();
        let said = tokio::time::timeout(Duration::from_secs(20), read_inside(&mut second)).await;
        assert!(
            matches!(&said, Ok(said) if said.ends_with(b"inside")),
            "the second connection was not answered: {said:?}"
        );
    }

    /// Reads a kept-alive connection until the body `inside` of its answer has come.
    async fn read_inside(tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut said = Vec::new();
        let mut piece = [0u8; 1024];
        while !said.ends_with(b"inside") {
            match tls.read(&mut piece).await {
                Ok(0) | Err(_) => break,
                Ok(n) => said.extend_from_slice(&piece[..n]),
            }
        }
        said
    }

    /// Bytes that keep moving, each within the idle time, keep a connection: a request sent
    /// a piece at a time and a body that comes a piece at a time, both longer than the idle time.
    #[tokio::test]
    async fn registry_bounds_steady_bytes_keep_a_connection() {
        let idle = Duration::from_secs(2);
        let app = axum::Router::new().fallback(axum::routing::get(|| async { trickled() }));
        let (door, _stop) = bounded_head(app, 2, idle, Duration::from_secs(30)).await;
        let (port, password) = (door.local.port, door.local.password.clone());
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tls = shaken(port, (door.local.certificate)().unwrap()).await;
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("kithd:{password}"));
        let request = format!(
            "GET /v2/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Basic {basic}\r\n\r\n"
        );
        for piece in request.as_bytes().chunks(8) {
            tls.write_all(piece).await.unwrap();
            tls.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let mut reply = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(20), tls.read_to_end(&mut reply)).await;
        assert!(
            reply.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        assert_eq!(reply.iter().filter(|&&b| b == b'#').count(), 24 * 1024);
    }

    /// kithd's pull keeps a connection pooled between its requests: one that is answered,
    /// then left past the idle time, is closed by the registry, and the next request
    /// (a GET, so safe to send again) is still answered on a new connection. A proxy in
    /// between counts the connections the client opens and sees the registry close the first.
    #[tokio::test]
    async fn registry_bounds_a_pull_waits_past_the_idle_time_and_pulls_again() {
        let idle = Duration::from_secs(2);
        let app = axum::Router::new().fallback(axum::routing::get(|| async { "inside" }));
        let (door, _stop) = bounded(app, 2, idle).await;
        let (port, password) = (door.local.port, door.local.password.clone());
        let (opened_by_client, closed_by_registry) = (
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = proxy.local_addr().unwrap().port();
        let (counted, closed) = (opened_by_client.clone(), closed_by_registry.clone());
        tokio::spawn(async move {
            while let Ok((mut from_client, _)) = proxy.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let closed = closed.clone();
                tokio::spawn(async move {
                    if let Ok(mut to_registry) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                        let _ = tokio::io::copy_bidirectional(&mut from_client, &mut to_registry).await;
                    }
                    closed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                });
            }
        });
        let trusted = reqwest::Certificate::from_der(&(door.local.certificate)().unwrap()).unwrap();
        let client = reqwest::Client::builder().tls_certs_only([trusted]).build().unwrap();
        let url = format!("https://localhost:{front}/v2/team/hello/manifests/1");
        let pull = || async {
            let said = client
                .get(&url)
                .basic_auth("kithd", Some(&password))
                .send()
                .await
                .unwrap();
            assert_eq!(said.status(), 200);
            assert_eq!(said.text().await.unwrap(), "inside");
        };
        pull().await;
        let began = std::time::Instant::now();
        while closed_by_registry.load(std::sync::atomic::Ordering::SeqCst) < 1
            && began.elapsed() < Duration::from_secs(10)
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            closed_by_registry.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the registry did not close the connection the first pull left idle"
        );
        pull().await;
        assert_eq!(
            opened_by_client.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the second pull did not open a connection of its own"
        );
    }

    /// A request head that is not complete within the head time closes its connection, which
    /// gives its slot back: a connection that drips a head one byte a second (the idle time
    /// is long, so it is not the idle time that closes it) is closed in about the head time,
    /// and the next connection, on a bound of 1, is then served.
    #[tokio::test]
    async fn registry_bounds_a_head_dripped_past_the_head_time_is_closed() {
        let app = axum::Router::new().fallback(axum::routing::get(|| async { "inside" }));
        let (door, _stop) = bounded_head(app, 1, Duration::from_secs(60), Duration::from_secs(2)).await;
        let (port, password) = (door.local.port, door.local.password.clone());
        let certificate = (door.local.certificate)().unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut read, mut write) = tokio::io::split(shaken(port, certificate.clone()).await);
        write
            .write_all(b"GET /v2/team/quick HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();
        let dripping = tokio::spawn(async move {
            for _ in 0..20 {
                if write.write_all(b"X-Drip: a").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let began = std::time::Instant::now();
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(20), read.read(&mut byte)).await;
        dripping.abort();
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "a head dripped past the head time was not closed: {closed:?}"
        );
        assert!(
            (Duration::from_secs(1)..Duration::from_secs(5)).contains(&began.elapsed()),
            "the head was closed after {:?}, not about the head time",
            began.elapsed()
        );
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("kithd:{password}"));
        let mut second = tokio::time::timeout(Duration::from_secs(10), shaken(port, certificate))
            .await
            .expect("the dripped connection's slot was not given back");
        second
            .write_all(
                format!("GET /v2/team/quick HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {basic}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let said = tokio::time::timeout(Duration::from_secs(10), read_inside(&mut second)).await;
        assert!(
            matches!(&said, Ok(said) if said.ends_with(b"inside")),
            "the connection after the dripped head was not answered: {said:?}"
        );
    }

    /// An answer that refuses the password closes its connection: nothing more is said on it,
    /// so a client that sends a request without a password cannot keep the slot it holds.
    #[tokio::test]
    async fn registry_bounds_a_refused_request_closes_its_connection() {
        let app = axum::Router::new().fallback(axum::routing::get(|| async { "inside" }));
        let (door, _stop) = bounded(app, 2, Duration::from_secs(60)).await;
        let port = door.local.port;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tls = shaken(port, (door.local.certificate)().unwrap()).await;
        tls.write_all(b"GET /v2/team/quick HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reply = Vec::new();
        let ended = tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut reply)).await;
        assert!(ended.is_ok(), "the connection of a refused request was left open");
        assert!(
            reply.starts_with(b"HTTP/1.1 401"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
    }

    /// The port is taken before the registry is served (kithd's start takes it before the
    /// controller's first pass): who asks in between waits and is answered, not refused.
    #[tokio::test]
    async fn asked_before_it_is_served_waits_and_is_answered() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tcp = bind(0).unwrap();
        let door = Arc::new(Door::new(tcp.local_addr().unwrap().port()).unwrap());
        let early = tokio::spawn(shaken(door.local.port, (door.local.certificate)().unwrap()));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!early.is_finished(), "a handshake ended with nothing serving");
        let (_stop, stopping) = watch::channel(false);
        let app = axum::Router::new().fallback(axum::routing::get(|| async { "inside" }));
        let tcp = tokio::net::TcpListener::from_std(tcp).unwrap();
        tokio::spawn(behind(tcp, door, app, stopping, 2, IDLE, HEAD));
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tls = tokio::time::timeout(Duration::from_secs(5), early)
            .await
            .unwrap()
            .unwrap();
        tls.write_all(b"GET /v2/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).await.unwrap();
        assert!(
            reply.starts_with(b"HTTP/1.1 401"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
    }

    /// Stopping does not wait for an idle kept-alive connection: it is told to close (its answer
    /// is out already), so the registry stops in well under the idle time, which is a minute here.
    #[tokio::test]
    async fn registry_bounds_stopping_does_not_wait_for_an_idle_connection() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let app = axum::Router::new().fallback(axum::routing::get(|| async { "inside" }));
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let door = Arc::new(Door::new(tcp.local_addr().unwrap().port()).unwrap());
        let (port, password) = (door.local.port, door.local.password.clone());
        let certificate = (door.local.certificate)().unwrap();
        let (stop, stopping) = watch::channel(false);
        let serving = tokio::spawn(behind(tcp, door, app, stopping, 2, Duration::from_secs(60), HEAD));
        use tokio::io::AsyncWriteExt;
        let mut kept = shaken(port, certificate).await;
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("kithd:{password}"));
        kept.write_all(
            format!("GET /v2/team/quick HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {basic}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let said = tokio::time::timeout(Duration::from_secs(10), read_inside(&mut kept)).await;
        assert!(
            matches!(&said, Ok(said) if said.ends_with(b"inside")),
            "the kept-alive connection was not answered: {said:?}"
        );
        let began = std::time::Instant::now();
        stop.send(true).unwrap();
        let stopped = tokio::time::timeout(Duration::from_secs(10), serving).await;
        assert!(matches!(stopped, Ok(Ok(()))), "stopping waited for the idle connection");
        // (Without the close, the drain would run to `DRAIN`, which is over this.)
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "stopping took {:?} with one idle connection",
            began.elapsed()
        );
    }

    /// A raw TCP connection that says nothing holds a slot for the handshake time only: the
    /// next connection, shaken, is served once that time has run out (the bound is 1).
    #[tokio::test]
    async fn registry_bounds_a_connection_that_says_nothing_gives_its_slot_back_after_the_handshake() {
        let app = axum::Router::new().fallback(axum::routing::get(|| async { "inside" }));
        let (door, _stop) = bounded(app, 1, Duration::from_secs(60)).await;
        let (port, password) = (door.local.port, door.local.password.clone());
        let certificate = (door.local.certificate)().unwrap();
        let _silent = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        use tokio::io::AsyncWriteExt;
        let mut next = tokio::time::timeout(Duration::from_secs(10), shaken(port, certificate))
            .await
            .expect("a connection that said nothing held its slot past the handshake time");
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("kithd:{password}"));
        next.write_all(
            format!("GET /v2/team/quick HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {basic}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let said = tokio::time::timeout(Duration::from_secs(10), read_inside(&mut next)).await;
        assert!(
            matches!(&said, Ok(said) if said.ends_with(b"inside")),
            "the connection after the silent one was not answered: {said:?}"
        );
    }

    #[test]
    fn an_image_packed_from_a_directory_is_a_whole_oci_image() {
        let root = std::env::temp_dir().join(format!("kith-image-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (dir, blobs) = (root.join("volume"), root.join("blobs"));
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin/hello"), "#!/bin/sh\necho hello\n").unwrap();
        std::os::unix::fs::symlink("/etc/shadow", dir.join("link")).unwrap();
        let spec: ImageSpec = serde_json::from_value(json!({
            "volume": "out", "entrypoint": ["/bin/hello"], "env": ["A=b"], "workingDir": "/srv",
        }))
        .unwrap();
        let [layer, config, manifest] = pack(&dir, &blobs, &spec).unwrap();
        for (sha, blob, size) in [&layer, &config, &manifest] {
            let file = blobs.join(blob);
            assert_eq!((&sha_of(&file), std::fs::metadata(&file).unwrap().len()), (sha, *size));
        }
        let read =
            |piece: &Piece| -> Value { serde_json::from_slice(&std::fs::read(blobs.join(&piece.1)).unwrap()).unwrap() };
        let (said, made) = (read(&manifest), read(&config));
        assert_eq!(said["config"]["digest"], format!("sha256:{}", config.0));
        assert_eq!(said["config"]["size"], config.2);
        assert_eq!(
            said["layers"],
            json!([{ "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": format!("sha256:{}", layer.0), "size": layer.2 }])
        );
        assert_eq!(made["rootfs"]["diff_ids"], json!([format!("sha256:{}", layer.0)]));
        assert_eq!(
            made["config"],
            json!({ "Entrypoint": ["/bin/hello"], "Cmd": [], "Env": ["A=b"], "WorkingDir": "/srv" })
        );
        assert_eq!(made["os"], "linux");
        // The layer: the files, and a link as a link (never what it points at).
        let mut tar = tar::Archive::new(std::fs::File::open(blobs.join(&layer.1)).unwrap());
        let mut entries: Vec<(String, bool)> = tar
            .entries()
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.path().unwrap().to_string_lossy().into_owned(),
                    entry.header().entry_type().is_symlink(),
                )
            })
            .collect();
        entries.sort();
        assert!(
            entries.contains(&("bin/hello".into(), false)) && entries.contains(&("link".into(), true)),
            "{entries:?}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn cluster(image_status: Value, job_state: &str) -> Store {
        let mut store = store(json!([
            { "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "out" }, "spec": { "node": "n1", "path": "out" } },
            { "apiVersion": "kith.dev/v1", "kind": "Job", "metadata": { "name": "build" },
              "spec": { "template": { "exec": [{ "name": "x", "command": ["true"] }] } } },
            { "apiVersion": "kith.dev/v1", "kind": "Image", "metadata": { "name": "hello" },
              "spec": { "volume": "out", "tag": "1", "job": "build" } },
        ]));
        let ran = json!({ "state": job_state, "observedRevision": 1 });
        store.set_status("Job/default/build", Some(ran)).unwrap();
        if !image_status.is_null() {
            store.set_status("Image/default/hello", Some(image_status)).unwrap();
        }
        store
    }

    /// An image is made on its volume's node, when its Job has succeeded, once for a spec;
    /// one that failed is tried again later.
    #[test]
    fn an_image_is_made_once_its_job_has_succeeded_on_the_volumes_node() {
        let made = cluster(Value::Null, "succeeded");
        let jobs = due(&made, "n1", 100);
        assert_eq!(jobs.len(), 1);
        assert_eq!(
            (jobs[0].key.as_str(), jobs[0].dir.node.as_str()),
            ("Image/default/hello", "n1")
        );
        assert!(due(&made, "n2", 100).is_empty(), "only the volume's node makes it");
        assert!(due(&cluster(Value::Null, "running"), "n1", 100).is_empty());
        // A Job that was changed and has not run again yet: what its status says is of before.
        let mut changed = cluster(Value::Null, "succeeded");
        let mut job = changed.get("Job/default/build").unwrap().clone();
        (job.spec["retries"], job.metadata.revision) = (1.into(), None);
        changed.apply(job).unwrap();
        assert!(due(&changed, "n1", 100).is_empty());
        let of = jobs[0].of.clone();
        let done = cluster(json!({ "of": of, "blobs": { "aa": "b1" } }), "succeeded");
        assert!(due(&done, "n1", 100).is_empty(), "made once");
        let stale = cluster(json!({ "of": "another spec", "blobs": { "aa": "b1" } }), "succeeded");
        assert_eq!(due(&stale, "n1", 100)[0].old, ["b1"]);
        let failed = cluster(json!({ "tried": 90, "message": "no" }), "succeeded");
        assert!(due(&failed, "n1", 100).is_empty());
        assert_eq!(due(&failed, "n1", 90 + AGAIN).len(), 1);
    }

    /// The registry answers for an Image's tag and for its pieces by digest, in its own
    /// namespace and name only.
    #[test]
    fn an_image_is_served_by_its_tag_and_its_digests_and_nothing_else_is() {
        let status = json!({ "digest": "sha256:mm", "blobs": { "mm": "blob-m", "cc": "blob-c", "ll": "blob-l" } });
        let store = cluster(status, "succeeded");
        let blob = |path: &str| found(&store, path).map(|(key, sha)| (key.replace("Blob/default/", ""), sha));
        assert_eq!(
            blob("/v2/default/hello/manifests/1"),
            Some(("blob-m".into(), "mm".into()))
        );
        assert_eq!(
            blob("/v2/default/hello/manifests/sha256:mm"),
            Some(("blob-m".into(), "mm".into()))
        );
        assert_eq!(
            blob("/v2/default/hello/blobs/sha256:ll"),
            Some(("blob-l".into(), "ll".into()))
        );
        for none in [
            "/v2/default/hello/manifests/latest",
            "/v2/default/hello/manifests/sha256:cc",
            "/v2/default/hello/blobs/sha256:zz",
            "/v2/default/hello/blobs/1",
            "/v2/other/hello/manifests/1",
            "/v2/default/hello/tags/list",
            "/v2/default/hello/blobs/sha256:ll/more",
            "/v2/default/hello/blobs/",
            "/v1/default/hello/blobs/sha256:ll",
        ] {
            assert_eq!(blob(none), None, "{none}");
        }
        // What an Image is made of is not a Backup's to remove, nor the other way round.
        let listed = |but: &str, blob: &str| crate::backups::listed(&store, "default", but, blob);
        assert!(listed("Backup/default/nightly", "blob-l") && !listed("Image/default/hello", "blob-l"));
        assert!(!listed("Backup/default/nightly", "blob-x"));
        assert!(
            found(&cluster(Value::Null, "succeeded"), "/v2/default/hello/manifests/1").is_none(),
            "not made yet"
        );
    }

    #[tokio::test]
    async fn an_image_forget_leaves_a_blob_of_another_maker() {
        use crate::blobs::{BACKUP, IMAGE};
        let (own, theirs, hand) = ("aa".repeat(31), "bb".repeat(31), "cc".repeat(31));
        let blobs = [(&*own, IMAGE), (&*theirs, BACKUP), (&*hand, "mine")];
        let (shared, _dir) = crate::blobs::shared_with_blobs("image-forget", &blobs).await;
        let job = Job {
            key: "Image/default/hello".into(),
            namespace: "default".into(),
            dir: Dir {
                namespace: "default".into(),
                name: "data".into(),
                path: "d".into(),
                node: "n".into(),
                encrypted: false,
            },
            spec: serde_json::from_value(json!({ "volume": "data" })).unwrap(),
            of: "x".into(),
            old: vec![theirs.clone(), hand.clone(), own.clone()],
        };
        forget(&shared, &job, &json!({ "blobs": {} })).await;
        let has = |name: &str| {
            shared
                .store
                .lock()
                .unwrap()
                .store
                .get(&format!("Blob/default/{name}"))
                .is_some()
        };
        assert!(!has(&own), "an image's own Blob is let go");
        assert!(has(&theirs), "a backup's Blob is not an image's to delete");
        assert!(has(&hand), "nor is one put by hand");
    }
}
