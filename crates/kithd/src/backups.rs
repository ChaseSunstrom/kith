//! Backups: a Volume's directory as an archive, kept somewhere else, every so often.
//!
//! POST /v1/backups/NS/NAME/restore[?at=SECONDS]   the backup back into its (empty) volume
//!
//! A `Backup` names a Volume, how often (`every: 24h`) and how many to keep. The node the
//! volume is on makes a tar of its directory when one is due and keeps it as a blob (so
//! other nodes hold it too: [`crate::blobs`]), or sends it to the S3 bucket the Backup
//! names. `status.backups` lists them, oldest first: `{at, size, blob | object}`.
//!
//! The archive is of the directory as it is while it is read: what a crash at that moment
//! would have left. (A snapshot first needs a filesystem that has them.)

use crate::Shared;
use crate::access::Caller;
use crate::api::{ApiError, permit};
use crate::blobs::Incoming;
use crate::volumes::Dir;
use axum::Json;
use axum::extract::{Extension, Path as UrlPath, Query, State};
use kith_api::kinds::{BackupSpec, S3, SecretSpec, Verb, every};
use kith_api::store::{Error, Store};
use kith_store::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// How often a node looks for a backup that is due.
const ROUND: Duration = Duration::from_secs(10);
/// How many are kept, when the Backup does not say.
const KEEP: usize = 7;
/// A backup that failed is tried again after this long, or after `every` if that is less.
const AGAIN: u64 = 600;
/// A bucket that says nothing for this long is given up on.
const QUIET: Duration = Duration::from_secs(60);

/// A backup to make now.
#[derive(Debug)]
struct Job {
    key: String,
    namespace: String,
    name: String,
    dir: Dir,
    spec: BackupSpec,
    /// Those there are, oldest first.
    backups: Vec<Value>,
}

/// The Backups of volumes on `me` that are due at `now`.
fn due(store: &Store, me: &str, now: u64) -> Vec<Job> {
    let job = |backup: &kith_api::Resource| {
        let spec: BackupSpec = serde_json::from_value(backup.spec.clone()).ok()?;
        let namespace = backup.metadata.namespace.clone().unwrap_or_else(|| "default".into());
        let dir = crate::volumes::dir(store, &namespace, &spec.volume).filter(|dir| dir.node == me)?;
        let status = backup.status.clone().unwrap_or_default();
        let backups = status["backups"].as_array().cloned().unwrap_or_default();
        let last = backups.last().and_then(|last| last["at"].as_u64());
        let tried = status["tried"].as_u64();
        let wait = every(&spec.every)?;
        let wait = if tried > last { wait.min(AGAIN) } else { wait };
        let since = tried.max(last);
        since.is_none_or(|since| now >= since + wait).then(|| Job {
            key: backup.key(),
            namespace,
            name: backup.metadata.name.clone(),
            dir,
            spec,
            backups,
        })
    };
    store.list(Some("Backup")).filter_map(job).collect()
}

/// `backups` with `new` at its end and no more than `keep` of them: (kept, let go). One let
/// go whose blob a kept one has too (nothing changed between them) is not in the second.
fn kept(mut backups: Vec<Value>, new: Value, keep: usize) -> (Vec<Value>, Vec<Value>) {
    backups.push(new);
    let over = backups.len().saturating_sub(keep.max(1));
    let kept = backups.split_off(over);
    let held = |old: &Value| !old["blob"].is_null() && kept.iter().any(|kept| kept["blob"] == old["blob"]);
    backups.retain(|old| !held(old));
    (kept, backups)
}

/// `dir` as a tar in the blob store at `blobs`: the blob's name and size.
///
/// Whatever runs in the volume can change it while it is read, so nothing in it is reached
/// by a path the volume could turn elsewhere: every directory is held open and its entries
/// are opened from that handle, never through a link. A link is kept as the link it is
/// (what it points at is not this volume's to read); an entry that became a link while it
/// was looked at is left out. Entries go in by name, so the same files make the same blob.
pub(crate) fn archive(dir: &Path, blobs: &Path) -> Result<(String, u64), String> {
    let failed = |e: std::io::Error| format!("archiving {}: {e}", dir.display());
    let mut tar = tar::Builder::new(Incoming::new(blobs).map_err(failed)?);
    let root = std::fs::File::open(dir).map_err(failed)?;
    let mut header = tar::Header::new_gnu();
    header.set_metadata(&root.metadata().map_err(failed)?);
    tar.append_data(&mut header, ".", std::io::empty()).map_err(failed)?;
    pack(&mut tar, &root, Path::new(".")).map_err(failed)?;
    tar.into_inner().map_err(failed)?.keep(None)
}

/// `name` in the directory `dir` is open at, as a path through that handle.
fn within(dir: &std::fs::File, name: &std::ffi::OsStr) -> PathBuf {
    use std::os::fd::AsRawFd;
    Path::new("/proc/self/fd").join(dir.as_raw_fd().to_string()).join(name)
}

/// Open `name` in `dir`: not if it is a link, and without waiting on a pipe put there.
fn open_in(dir: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
    use nix::fcntl::OFlag;
    use std::os::unix::fs::OpenOptionsExt;
    let flags = OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_NOCTTY;
    let mut open = std::fs::OpenOptions::new();
    open.read(true).custom_flags(flags.bits()).open(within(dir, name))
}

/// How many directories deep an archive goes.
// ponytail: a directory inside another is a call inside another and one more open file,
// and a volume's own program can nest them without end (a held directory has no longest
// path), so the walk stops here and the archive fails with these words. Walk with a list
// of its own instead if a real volume is ever deeper.
const DEEPEST: usize = 128;

/// Every entry of the directory `dir` is open at into `tar`, under `at`.
fn pack(tar: &mut tar::Builder<Incoming>, dir: &std::fs::File, at: &Path) -> std::io::Result<()> {
    if at.components().count() > DEEPEST {
        let said = format!("{} is more than {DEEPEST} directories deep", at.display());
        return Err(std::io::Error::other(said));
    }
    let listed = std::fs::read_dir(within(dir, ".".as_ref()))?;
    let mut names = listed
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    for name in names {
        // (One that is gone since it was listed is no part of the archive.)
        if let Ok(seen) = std::fs::symlink_metadata(within(dir, &name)) {
            put(tar, dir, &name, &at.join(&name), &seen)?;
        }
    }
    Ok(())
}

/// What opening an entry says when it is no longer the file or directory it was: a link
/// now, gone, or a socket.
const SWAPPED: [nix::errno::Errno; 3] = [
    nix::errno::Errno::ELOOP,
    nix::errno::Errno::ENOENT,
    nix::errno::Errno::ENXIO,
];

/// `name` in `dir` into `tar` as `path`. `seen` is what it looked like a moment ago, and
/// decides only how it is opened: what is written is what was opened.
fn put(
    tar: &mut tar::Builder<Incoming>,
    dir: &std::fs::File,
    name: &std::ffi::OsStr,
    path: &Path,
    seen: &std::fs::Metadata,
) -> std::io::Result<()> {
    let mut header = tar::Header::new_gnu();
    if seen.file_type().is_symlink() {
        if let Ok(to) = std::fs::read_link(within(dir, name)) {
            header.set_metadata(seen);
            tar.append_link(&mut header, path, to)?;
        }
    } else if seen.is_dir() || seen.is_file() {
        // (A link put there since, or gone since: nothing of it goes in. Anything else
        // that keeps a file from being read is an archive that was not made.)
        let file = match open_in(dir, name) {
            Ok(file) => file,
            Err(e) if SWAPPED.iter().any(|gone| e.raw_os_error() == Some(*gone as i32)) => return Ok(()),
            Err(e) => return Err(std::io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
        };
        let found = file.metadata()?;
        header.set_metadata(&found);
        if found.is_dir() {
            tar.append_data(&mut header, path, std::io::empty())?;
            pack(tar, &file, path)?;
        } else if found.is_file() {
            // (As long as it was a moment ago, whether it grows or is cut short meanwhile:
            // an entry of another length than its header says breaks every entry after it.)
            let whole = std::io::Read::chain(file, std::io::repeat(0));
            tar.append_data(&mut header, path, std::io::Read::take(whole, found.len()))?;
        }
    }
    // (Pipes, sockets and devices are no part of an archive, and are never opened.)
    Ok(())
}

/// The tar at `archive` into `dir`, which must have nothing in it. Unpacked beside it and
/// moved into its place when all of it is there: a restore that fails leaves `dir` as it was.
fn unpack(archive: &Path, dir: &Path) -> Result<(), String> {
    let failed = |e: std::io::Error| format!("restoring into {}: {e}", dir.display());
    let full = || "the volume has files in it: a backup is restored into an empty volume".to_string();
    if std::fs::read_dir(dir).map_err(failed)?.next().is_some() {
        return Err(full());
    }
    // (An archive may come from a bucket others can write: nothing in it becomes a program
    // that runs as its owner.)
    unpack_beside(archive, dir, 0o6000).and_then(|beside| {
        // (`remove_dir` takes only a directory that is still empty.)
        let moved = std::fs::remove_dir(dir).map_err(|_| full());
        let moved = moved.and_then(|()| std::fs::rename(&beside, dir).map_err(failed));
        if moved.is_err() {
            let _ = std::fs::remove_dir_all(&beside);
            let _ = std::fs::create_dir(dir);
        }
        moved
    })
}

/// The tar at `archive` unpacked into a new directory beside `dir`: where it is. Nothing is
/// left there if it fails.
pub(crate) fn unpack_beside(archive: &Path, dir: &Path, mask: u32) -> Result<PathBuf, String> {
    let failed = |e: std::io::Error| format!("unpacking for {}: {e}", dir.display());
    let mut beside = dir.as_os_str().to_owned();
    beside.push(".restoring");
    let beside = PathBuf::from(beside);
    let _ = std::fs::remove_dir_all(&beside);
    let unpacked = (|| {
        std::fs::create_dir(&beside)?;
        let mut tar = tar::Archive::new(std::fs::File::open(archive)?);
        tar.set_preserve_permissions(true);
        tar.set_preserve_mtime(true);
        tar.set_mask(mask);
        // (Whose each file is, where kithd may say: as root, which it is on a node.)
        tar.set_preserve_ownerships(std::fs::metadata("/proc/self").is_ok_and(|me| {
            use std::os::unix::fs::MetadataExt;
            me.uid() == 0
        }));
        // (The tar crate lets no entry out of where it unpacks: no `..`, no absolute path,
        // no way through a link.)
        tar.unpack(&beside)
    })();
    if unpacked.is_err() {
        let _ = std::fs::remove_dir_all(&beside);
    }
    unpacked.map(|()| beside).map_err(failed)
}

// ---- S3 ----

/// A bucket and who to be there.
struct Bucket {
    /// `https://host[:port]`
    endpoint: String,
    bucket: String,
    region: String,
    prefix: String,
    access: String,
    secret: String,
    /// The cluster's mesh, which no bucket is on.
    mesh: Option<std::net::Ipv6Addr>,
    /// (A test's bucket is on this machine.)
    anywhere: bool,
}

/// The bucket `s3` names, with the keys in its Secret (`accessKey`, `secretKey`).
fn bucket(shared: &Shared, namespace: &str, s3: &S3) -> Result<Bucket, String> {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let key = format!("Secret/{namespace}/{}", s3.secret);
    let secret = state.store.get(&key).ok_or(format!("{key} is not there"))?;
    let secret: SecretSpec = serde_json::from_value(secret.spec.clone()).map_err(|e| e.to_string())?;
    let field = |name: &str| secret.data.get(name).cloned().ok_or(format!("{key} has no {name}"));
    Ok(Bucket {
        endpoint: s3.endpoint.trim_end_matches('/').to_string(),
        bucket: s3.bucket.clone(),
        region: s3.region.clone().unwrap_or_else(|| "us-east-1".into()),
        prefix: s3.prefix.clone().unwrap_or_default(),
        access: field("accessKey")?,
        secret: field("secretKey")?,
        mesh: shared
            .cluster
            .as_ref()
            .map(|cluster| crate::mesh::prefix(&cluster.me.ca)),
        anywhere: false,
    })
}

/// May a bucket be at `address`? Whoever may write a Backup names the endpoint kithd then
/// talks to, as the node: not this machine, not a link-local address (where a cloud's
/// metadata service is) and not the cluster's own mesh. An address on the LAN may: that is
/// where a NAS is.
fn outside(address: std::net::IpAddr, mesh: Option<std::net::Ipv6Addr>) -> bool {
    use std::net::IpAddr;
    match address.to_canonical() {
        IpAddr::V4(at) => {
            !(at.is_loopback() || at.is_link_local() || at.is_unspecified() || at.is_multicast() || at.is_broadcast())
        }
        IpAddr::V6(at) => {
            let local = at.is_loopback() || at.is_unspecified() || at.is_multicast() || at.is_unicast_link_local();
            !local && mesh.is_none_or(|mesh| mesh.octets()[..6] != at.octets()[..6])
        }
    }
}

/// Seconds since 1970 as S3 wants a time: `20130524T000000Z`.
fn stamp(at: u64) -> String {
    let (days, rest) = ((at / 86400) as i64, at % 86400);
    // (Days to a date, after Howard Hinnant's `civil_from_days`.)
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The `Authorization` of a request to S3 (AWS Signature Version 4). `headers`: every header
/// that is signed, names in lower case and in order; `path` needs no escaping (ours do not).
fn authorization(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    payload: &str,
    stamp: &str,
    bucket: &Bucket,
) -> String {
    use ring::{digest, hmac};
    let hex = crate::pki::hex;
    let sign = |key: &[u8], text: &str| hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), text.as_bytes());
    let names: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();
    let names = names.join(";");
    let lines: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let request = format!("{method}\n{path}\n\n{lines}\n{names}\n{payload}");
    let day = &stamp[..8];
    let scope = format!("{day}/{}/s3/aws4_request", bucket.region);
    let request = hex(digest::digest(&digest::SHA256, request.as_bytes()).as_ref());
    let text = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{request}");
    let mut key = sign(format!("AWS4{}", bucket.secret).as_bytes(), day);
    for part in [bucket.region.as_str(), "s3", "aws4_request"] {
        key = sign(key.as_ref(), part);
    }
    let signature = hex(sign(key.as_ref(), &text).as_ref());
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
        bucket.access
    )
}

/// One request for `object` in the bucket (path style: `endpoint/bucket/object`).
async fn s3(
    bucket: &Bucket,
    method: reqwest::Method,
    object: &str,
    body: Option<(reqwest::Body, u64)>,
) -> Result<reqwest::Response, String> {
    let said = |e: reqwest::Error| format!("{} {object} in bucket {}: {e}", method.as_str(), bucket.bucket);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let path = format!("/{}/{object}", bucket.bucket);
    let url = reqwest::Url::parse(&format!("{}{path}", bucket.endpoint)).map_err(|e| e.to_string())?;
    let name = url.host_str().unwrap_or_default().trim_matches(['[', ']']).to_string();
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    // Looked up here, checked, and the connection made to what was checked: a name cannot
    // say one address now and another when the request is sent. No redirect is followed.
    let port = url.port_or_known_default().unwrap_or(443);
    let found = tokio::net::lookup_host((name.as_str(), port)).await;
    let found: Vec<std::net::SocketAddr> = found.map_err(|e| format!("looking up {name}: {e}"))?.collect();
    let refused = found
        .iter()
        .find(|at| !bucket.anywhere && !outside(at.ip(), bucket.mesh));
    if let Some(at) = refused {
        return Err(format!(
            "{name} is at {}: a bucket is not on this machine, a link-local address or the mesh",
            at.ip()
        ));
    }
    let at = *found.first().ok_or(format!("{name} has no address"))?;
    // ponytail: a client a request; they are minutes apart. Keep one when they are not.
    let client = reqwest::Client::builder()
        .connect_timeout(QUIET)
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&name, at)
        .build()
        .map_err(said)?;
    let stamp = stamp(kith_api::store::now());
    // (The body is not hashed into the signature: it is as long as a volume, and goes over TLS.)
    let payload = "UNSIGNED-PAYLOAD";
    let headers = [
        ("host", host.as_str()),
        ("x-amz-content-sha256", payload),
        ("x-amz-date", stamp.as_str()),
    ];
    let authorization = authorization(method.as_str(), &path, &headers, payload, &stamp, bucket);
    let mut request = client
        .request(method.clone(), url)
        .header("x-amz-content-sha256", payload)
        .header("x-amz-date", &stamp)
        .header("authorization", authorization);
    // How long until the answer starts: a minute, and what the body takes at 100 kB/s or better.
    let mut patience = QUIET;
    if let Some((body, size)) = body {
        patience += Duration::from_secs(size / 100_000);
        request = request.header("content-length", size).body(body);
    }
    let slow = |_| {
        format!(
            "{} {object} in bucket {}: no answer in {} s",
            method.as_str(),
            bucket.bucket,
            patience.as_secs()
        )
    };
    let answer = tokio::time::timeout(patience, request.send()).await.map_err(slow)?;
    answer.and_then(reqwest::Response::error_for_status).map_err(said)
}

// ---- Making them ----

/// One at a time on a node, a backup or a restore: neither reads what the other half wrote.
static BUSY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Said of a Blob a backup made, so that pruning never takes one that was put by hand.
const MADE: &str = "kith.dev/made-by";

/// One backup of `job`: what `status.backups` says of it.
async fn make(shared: &Shared, state: &Path, job: &Job, at: u64) -> Result<Value, String> {
    // (Before the volume is read: a Secret that is not there fails at once, every time.)
    let bucket = job
        .spec
        .s3
        .as_ref()
        .map(|s3| bucket(shared, &job.namespace, s3))
        .transpose()?;
    let _alone = BUSY.lock().await;
    let from = crate::volumes::host_dir(state, &job.dir)?;
    let blobs = crate::blobs::dir(shared);
    let into = blobs.clone();
    let archived = tokio::task::spawn_blocking(move || archive(&from, &into)).await;
    let (blob, size) = archived.map_err(|e| e.to_string())??;
    let Some(bucket) = bucket else {
        let key = format!("Blob/{}/{blob}", job.namespace);
        let there = shared
            .store
            .lock()
            .expect("a handler panicked holding the store")
            .store
            .get(&key)
            .is_some();
        // (The same bytes as a Blob that is there: it is that Blob, whoever made it.)
        if !there {
            let mut spec = json!({ "size": size });
            if let Some(copies) = job.spec.copies {
                spec["copies"] = copies.into();
            }
            let wanted = json!({
                "apiVersion": "kith.dev/v1", "kind": "Blob",
                "metadata": { "name": blob, "namespace": job.namespace, "annotations": { MADE: "backup" } },
                "spec": spec,
            });
            let resources = vec![serde_json::from_value(wanted).map_err(|e| e.to_string())?];
            let applied = shared
                .write(Command::Apply {
                    resources,
                    at: kith_api::store::now(),
                })
                .await;
            applied.map_err(|e| e.to_string())?;
        }
        return Ok(json!({ "at": at, "size": size, "blob": blob }));
    };
    // (The file is no Blob's: the blob store removes it in ten minutes.)
    let object = format!("{}{}/{}-{}.tar", bucket.prefix, job.namespace, job.name, stamp(at));
    let file = std::fs::File::open(blobs.join(&blob)).map_err(|e| e.to_string())?;
    let body = reqwest::Body::wrap_stream(crate::blobs::chunks(file));
    s3(&bucket, reqwest::Method::PUT, &object, Some((body, size))).await?;
    Ok(json!({ "at": at, "size": size, "object": object }))
}

/// Does a Backup or an Image of `namespace` other than `but` still list `blob`? (The same
/// bytes are one blob, whichever of them made it first.)
pub(crate) fn listed(store: &Store, namespace: &str, but: &str, blob: &str) -> bool {
    let lists = |other: &kith_api::Resource| {
        let Some(status) = &other.status else { return false };
        let backups = status["backups"].as_array().into_iter().flatten();
        let pieces = status["blobs"].as_object().into_iter().flatten();
        backups.into_iter().any(|entry| entry["blob"] == blob) || pieces.into_iter().any(|(_, piece)| piece == blob)
    };
    let others = store.list(Some("Backup")).chain(store.list(Some("Image")));
    others
        .filter(|other| other.key() != but)
        .filter(|other| other.metadata.namespace.as_deref().unwrap_or("default") == namespace)
        .any(lists)
}

/// Lets go of a backup that is no longer kept. (What fails here is left behind, and said.)
async fn forget(shared: &Shared, job: &Job, old: &Value) -> Result<(), String> {
    if let Some(blob) = old["blob"].as_str() {
        let key = format!("Blob/{}/{blob}", job.namespace);
        // Only a Blob a backup made, and that no other Backup has too (the same volume
        // backed up daily and weekly, with nothing changed, is one blob).
        let ours = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            let made = state
                .store
                .get(&key)
                .is_some_and(|blob| blob.metadata.annotations.contains_key(MADE));
            made && !listed(&state.store, &job.namespace, &job.key, blob)
        };
        if !ours {
            return Ok(());
        }
        return match shared.submit(Command::Delete { key }).await {
            Ok(_) | Err(Error::NotFound(_)) => Ok(()),
            Err(e) => Err(e.to_string()),
        };
    }
    let (Some(object), Some(s3_spec)) = (old["object"].as_str(), &job.spec.s3) else {
        return Ok(());
    };
    let bucket = bucket(shared, &job.namespace, s3_spec)?;
    s3(&bucket, reqwest::Method::DELETE, object, None).await.map(drop)
}

/// Makes the backups that are due of the volumes on this node.
pub async fn run(shared: Arc<Shared>, state: PathBuf, mut stopping: watch::Receiver<bool>) {
    let me = shared.members.me().to_string();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ROUND) => {}
            _ = stopping.changed() => return,
        }
        let now = kith_api::store::now();
        let jobs = {
            let state = shared.store.lock().expect("a handler panicked holding the store");
            due(&state.store, &me, now)
        };
        // ponytail: one at a time; a long archive holds up the next volume's.
        for job in jobs {
            let fields = match make(&shared, &state, &job, now).await {
                Ok(new) => {
                    let keep = job.spec.keep.map_or(KEEP, |keep| keep as usize);
                    let (kept, gone) = kept(job.backups.clone(), new, keep);
                    let mut message = Value::Null;
                    for old in &gone {
                        if let Err(e) = forget(&shared, &job, old).await {
                            message = format!("an old backup was not removed: {e}").into();
                        }
                    }
                    eprintln!("kithd: backup {} made ({} kept)", job.key, kept.len());
                    json!({ "backups": kept, "message": message, "tried": null })
                }
                Err(e) => {
                    eprintln!("kithd: backup {} was not made: {e}", job.key);
                    json!({ "message": e, "tried": now })
                }
            };
            let statuses = vec![(job.key.clone(), fields.as_object().expect("an object").clone())];
            if let Err(e) = shared.submit(Command::Patch { statuses }).await {
                eprintln!("kithd: backup {}: its status was not written: {e}", job.key);
            }
        }
    }
}

// ---- Restoring ----

#[derive(serde::Deserialize)]
pub struct Restore {
    /// Which: the `at` of one in `status.backups`. None: the last.
    at: Option<u64>,
}

/// `POST /v1/backups/NS/NAME/restore`: a backup back into its volume, on the volume's node.
pub async fn restore(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    UrlPath((namespace, name)): UrlPath<(String, String)>,
    Query(which): Query<Restore>,
) -> Result<Json<Value>, ApiError> {
    let both = [
        ("Backup".to_string(), Some(namespace.clone())),
        ("Volume".into(), Some(namespace.clone())),
    ];
    permit(&shared, &caller, Verb::Apply, |_| both.to_vec())?;
    let key = format!("Backup/{namespace}/{name}");
    let invalid = |why: String| ApiError::Store(Error::Invalid(why));
    let io = |why: String| ApiError::Store(Error::Io(why));
    let me = shared.members.me();
    let (spec, dir, entry, address) = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let backup = state
            .store
            .get(&key)
            .ok_or_else(|| ApiError::Store(Error::NotFound(key.clone())))?;
        let spec: BackupSpec = serde_json::from_value(backup.spec.clone()).map_err(|e| invalid(e.to_string()))?;
        let dir = crate::volumes::dir(&state.store, &namespace, &spec.volume);
        let dir = dir.ok_or_else(|| invalid(format!("{key}: there is no Volume {} to restore into", spec.volume)))?;
        let backups = backup.status.as_ref().and_then(|status| status["backups"].as_array());
        let mut backups = backups.into_iter().flatten();
        let entry = match which.at {
            Some(at) => backups.find(|entry| entry["at"].as_u64() == Some(at)),
            None => backups.next_back(),
        };
        let entry = entry
            .cloned()
            .ok_or_else(|| invalid(format!("{key} has no such backup")))?;
        let there = state.store.get(&format!("Node/{}", dir.node));
        let address = there.and_then(|node| Some(node.status.as_ref()?["address"].as_str()?.to_string()));
        (spec, dir, entry, address)
    };
    let what = vec![format!(
        "{key} at {} into Volume/{namespace}/{}",
        entry["at"], spec.volume
    )];
    // The volume is another node's: it is asked, as this node (which has just checked the caller).
    if dir.node != me {
        let (Some(cluster), Some(address)) = (&shared.cluster, address) else {
            return Err(io(format!("node {} that has the volume has no address yet", dir.node)));
        };
        let url = format!(
            "https://{address}/v1/backups/{namespace}/{name}/restore?at={}",
            entry["at"]
        );
        // (As long as a volume takes to unpack, and no longer than an hour.)
        let asked = cluster.client.post(url).timeout(Duration::from_secs(3600)).send().await;
        let failed = |e: reqwest::Error| io(format!("asking node {} to restore: {e}", dir.node));
        let answer = asked.map_err(failed)?;
        let (fine, status) = (answer.status().is_success(), answer.status());
        let said: Value = answer.json().await.map_err(failed)?;
        let outcome = if fine {
            Ok(())
        } else {
            Err(said["error"]
                .as_str()
                .map_or(format!("node {} answered {status}", dir.node), String::from))
        };
        shared.audit.record(&caller, "restore", what, outcome.clone());
        return outcome.map(|()| Json(said)).map_err(invalid);
    }
    let restored = async {
        let _alone = BUSY.lock().await;
        let state = shared.logs.parent().ok_or("kithd has no state directory")?;
        let into = crate::volumes::host_dir(state, &dir)?;
        let archive = match (entry["blob"].as_str(), entry["object"].as_str(), &spec.s3) {
            (Some(blob), _, _) => crate::blobs::here(&shared, &format!("Blob/{namespace}/{blob}")).await?,
            (None, Some(object), Some(s3_spec)) => {
                let bucket = bucket(&shared, &namespace, s3_spec)?;
                let mut answer = s3(&bucket, reqwest::Method::GET, object, None).await?;
                let blobs = crate::blobs::dir(&shared);
                let mut incoming = Incoming::new(&blobs).map_err(|e| e.to_string())?;
                loop {
                    let chunk = tokio::time::timeout(QUIET, answer.chunk()).await;
                    let chunk = chunk.map_err(|_| format!("the bucket sent nothing for {} s", QUIET.as_secs()))?;
                    let Some(chunk) = chunk.map_err(|e| e.to_string())? else {
                        break;
                    };
                    incoming.write(&chunk).map_err(|e| e.to_string())?;
                }
                let kept = tokio::task::spawn_blocking(move || incoming.keep(None)).await;
                blobs.join(kept.map_err(|e| e.to_string())??.0)
            }
            _ => return Err("the backup says neither which blob nor which object it is".to_string()),
        };
        let unpacked = tokio::task::spawn_blocking(move || unpack(&archive, &into)).await;
        unpacked.map_err(|e| e.to_string())?
    };
    let restored: Result<(), String> = restored.await;
    shared.audit.record(&caller, "restore", what, restored.clone());
    restored.map_err(invalid)?;
    Ok(Json(
        json!({ "restored": entry, "volume": spec.volume, "node": dir.node }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kith-backup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_backup_archive_restores_byte_for_byte_and_only_into_an_empty_volume() {
        let root = temp("archive");
        let (from, blobs, into) = (root.join("from"), root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(from.join("deep/er")).unwrap();
        std::fs::create_dir_all(&into).unwrap();
        std::fs::write(from.join("a"), b"one").unwrap();
        std::fs::write(from.join("deep/er/b"), vec![7u8; 100_000]).unwrap();
        std::fs::set_permissions(from.join("a"), std::fs::Permissions::from_mode(0o640)).unwrap();
        // A link out of the volume is kept as the link it is; what it points at is not read.
        std::os::unix::fs::symlink("/etc/hostname", from.join("link")).unwrap();

        let (name, size) = archive(&from, &blobs).unwrap();
        assert!(crate::blobs::named(&name) && size > 100_000);
        unpack(&blobs.join(&name), &into).unwrap();
        assert_eq!(std::fs::read(into.join("a")).unwrap(), b"one");
        assert_eq!(std::fs::read(into.join("deep/er/b")).unwrap(), vec![7u8; 100_000]);
        assert_eq!(
            std::fs::metadata(into.join("a")).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            std::fs::read_link(into.join("link")).unwrap(),
            Path::new("/etc/hostname")
        );

        // Not over what is there.
        let refused = unpack(&blobs.join(&name), &into).unwrap_err();
        assert!(refused.contains("restored into an empty volume"), "{refused}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// What a workload does to its volume while the node archives it: a directory or a
    /// file swapped for a link out of the volume. The walk holds each directory open and
    /// opens nothing through a link, so the link is left out and never followed.
    #[test]
    fn archive_follows_no_link_put_in_its_way() {
        let root = temp("swap");
        let (from, blobs, outside) = (root.join("from"), root.join("blobs"), root.join("outside"));
        std::fs::create_dir_all(from.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(from.join("sub/inner"), b"the volume's own").unwrap();
        std::fs::write(from.join("file"), b"the volume's own").unwrap();
        std::fs::write(outside.join("secret"), b"the node's").unwrap();
        let held = std::fs::File::open(&from).unwrap();
        let seen = |name: &str| std::fs::symlink_metadata(from.join(name)).unwrap();
        let (was_dir, was_file) = (seen("sub"), seen("file"));
        let sub = open_in(&held, "sub".as_ref()).unwrap();

        // Swapped after they were looked at, and after `sub` was walked into.
        std::fs::rename(from.join("sub"), root.join("moved")).unwrap();
        std::os::unix::fs::symlink(&outside, from.join("sub")).unwrap();
        std::fs::remove_file(from.join("file")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), from.join("file")).unwrap();
        assert!(open_in(&held, "sub".as_ref()).is_err() && open_in(&held, "file".as_ref()).is_err());

        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        put(&mut tar, &held, "sub".as_ref(), Path::new("./sub"), &was_dir).unwrap();
        put(&mut tar, &held, "file".as_ref(), Path::new("./file"), &was_file).unwrap();
        // The directory that was walked into is still the volume's, wherever its name points now.
        pack(&mut tar, &sub, Path::new("./walked")).unwrap();
        let (name, _) = tar.into_inner().unwrap().keep(None).unwrap();
        let mut packed = tar::Archive::new(std::fs::File::open(blobs.join(name)).unwrap());
        let mut found = Vec::new();
        for entry in packed.entries().unwrap() {
            let mut entry = entry.unwrap();
            let mut text = String::new();
            std::io::Read::read_to_string(&mut entry, &mut text).unwrap();
            found.push((entry.path().unwrap().display().to_string(), text));
        }
        assert_eq!(found, [("walked/inner".to_string(), "the volume's own".to_string())]);

        // As it is now, links and all: each link is kept as a link, and nothing it names is read.
        let (name, _) = archive(&from, &blobs).unwrap();
        let mut packed = tar::Archive::new(std::fs::File::open(blobs.join(name)).unwrap());
        let kinds: Vec<_> = packed
            .entries()
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.path().unwrap().display().to_string(),
                    entry.header().entry_type().is_symlink(),
                    entry.size(),
                )
            })
            .collect();
        assert_eq!(
            kinds,
            [
                (".".to_string(), false, 0),
                ("file".to_string(), true, 0),
                ("sub".to_string(), true, 0)
            ]
        );

        // Directories without end are not walked without end.
        let deep = root.join("deep");
        std::fs::create_dir_all(deep.join("d/".repeat(DEEPEST + 1))).unwrap();
        let said = archive(&deep, &blobs).unwrap_err();
        assert!(said.contains("more than 128 directories deep"), "{said}");
        std::fs::create_dir_all(root.join("fits").join("d/".repeat(DEEPEST - 1))).unwrap();
        archive(&root.join("fits"), &blobs).unwrap();

        // A file that cannot be read is an archive that is not made, not one without it.
        // (Root reads whatever the mode: nothing to see there.)
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(root.join("fits/shut"), b"x").unwrap();
        std::fs::set_permissions(root.join("fits/shut"), std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(root.join("fits/shut")).is_err() {
            let said = archive(&root.join("fits"), &blobs).unwrap_err();
            assert!(said.contains("shut: "), "{said}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_backup_archive_cannot_write_outside_the_volume() {
        let root = temp("escape");
        let (blobs, into) = (root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(&into).unwrap();
        // An archive nobody made with kith: an entry that names a path above the volume.
        let mut tar = tar::Builder::new(Incoming::new(&blobs).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        let path = b"../escaped";
        header.as_old_mut().name[..path.len()].copy_from_slice(path);
        header.set_cksum();
        tar.append(&header, &b"out!"[..]).unwrap();
        let (name, _) = tar.into_inner().unwrap().keep(None).unwrap();
        let _ = unpack(&blobs.join(name), &into);
        assert!(!root.join("escaped").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn store(status: Value) -> Store {
        let mut store = Store::default();
        let resources = [
            json!({ "apiVersion": "kith.dev/v1", "kind": "Volume", "metadata": { "name": "data" },
                    "spec": { "node": "a", "path": "d" } }),
            json!({ "apiVersion": "kith.dev/v1", "kind": "Backup", "metadata": { "name": "nightly" },
                    "spec": { "volume": "data", "every": "1h", "keep": 2 } }),
            json!({ "apiVersion": "kith.dev/v1", "kind": "Backup", "metadata": { "name": "of-nothing" },
                    "spec": { "volume": "none", "every": "1h" } }),
        ];
        let resources = resources
            .into_iter()
            .map(|r| serde_json::from_value(r).unwrap())
            .collect();
        kith_store::run(&mut store, Command::Apply { resources, at: 0 }).unwrap();
        let statuses = vec![(
            "Backup/default/nightly".to_string(),
            status.as_object().unwrap().clone(),
        )];
        kith_store::run(&mut store, Command::Patch { statuses }).unwrap();
        store
    }

    #[test]
    fn a_backup_is_due_on_its_volumes_node_when_its_time_has_come() {
        let never = store(json!({}));
        let due_on = |store: &Store, node: &str, now: u64| due(store, node, now).len();
        // None yet: due at once, on the node that has the volume and no other.
        assert_eq!((due_on(&never, "a", 5), due_on(&never, "b", 5)), (1, 0));
        assert_eq!(due(&never, "a", 5)[0].key, "Backup/default/nightly");
        let made = store(json!({ "backups": [{ "at": 1000, "blob": "x", "size": 1 }] }));
        assert_eq!((due_on(&made, "a", 4599), due_on(&made, "a", 4600)), (0, 1));
        // One that failed is tried again in ten minutes, not in an hour and not at once.
        let failed = store(json!({ "backups": [{ "at": 1000, "blob": "x", "size": 1 }], "tried": 4600 }));
        assert_eq!((due_on(&failed, "a", 5199), due_on(&failed, "a", 5200)), (0, 1));
    }

    #[test]
    fn a_backup_blob_another_backup_lists_is_not_let_go() {
        let both = store(json!({ "backups": [{ "at": 1, "blob": "same", "size": 1 }] }));
        assert!(listed(&both, "default", "Backup/default/of-nothing", "same"));
        // Not its own listing, not another namespace's, not another blob.
        assert!(!listed(&both, "default", "Backup/default/nightly", "same"));
        assert!(!listed(&both, "other", "Backup/other/x", "same"));
        assert!(!listed(&both, "default", "Backup/default/of-nothing", "else"));
    }

    #[test]
    fn a_restored_backup_has_no_setuid_program_and_a_failed_one_leaves_the_volume_empty() {
        let root = temp("mask");
        let (from, blobs, into) = (root.join("from"), root.join("blobs"), root.join("into"));
        std::fs::create_dir_all(&from).unwrap();
        std::fs::create_dir_all(&into).unwrap();
        std::fs::write(from.join("tool"), b"#!/bin/sh").unwrap();
        std::fs::set_permissions(from.join("tool"), std::fs::Permissions::from_mode(0o6755)).unwrap();
        let (name, _) = archive(&from, &blobs).unwrap();
        unpack(&blobs.join(&name), &into).unwrap();
        assert_eq!(
            std::fs::metadata(into.join("tool")).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        // Not an archive at all: nothing is left in the volume, which can be restored into again.
        let empty = root.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::write(root.join("junk"), vec![0xffu8; 4096]).unwrap();
        assert!(unpack(&root.join("junk"), &empty).is_err());
        assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0);
        assert!(!root.join("empty.restoring").exists());
        unpack(&blobs.join(&name), &empty).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn backups_beyond_keep_are_let_go_but_never_a_blob_a_kept_one_has() {
        let entry = |at: u64, blob: &str| json!({ "at": at, "blob": blob, "size": 1 });
        let (kept2, gone) = kept(vec![entry(1, "a"), entry(2, "b")], entry(3, "c"), 2);
        assert_eq!((kept2, gone), (vec![entry(2, "b"), entry(3, "c")], vec![entry(1, "a")]));
        // Nothing changed in the volume: the same blob, which stays for the one that is kept.
        let (kept1, gone) = kept(vec![entry(1, "a")], entry(2, "a"), 1);
        assert_eq!((kept1, gone), (vec![entry(2, "a")], vec![]));
        assert_eq!(kept(vec![], entry(1, "a"), 0).0.len(), 1);
    }

    fn example() -> Bucket {
        Bucket {
            endpoint: String::new(),
            bucket: "examplebucket".into(),
            region: "us-east-1".into(),
            prefix: String::new(),
            access: "AKIAIOSFODNN7EXAMPLE".into(), // pragma: allowlist secret
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(), // pragma: allowlist secret
            mesh: None,
            anywhere: true,
        }
    }

    #[test]
    fn an_s3_signature_is_the_one_amazons_own_example_has() {
        // "Example: GET Object" of Amazon's "Signature Calculations for the Authorization Header".
        assert_eq!(stamp(1_369_353_600), "20130524T000000Z");
        // (The store's clock is in seconds, which is what a stamp is made of.)
        assert!(stamp(kith_api::store::now()).as_str() > "2025");
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let headers = [
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", empty),
            ("x-amz-date", "20130524T000000Z"),
        ];
        let signed = authorization("GET", "/test.txt", &headers, empty, "20130524T000000Z", &example());
        assert_eq!(
            signed,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41" // pragma: allowlist secret
        );
        assert_eq!(stamp(951_782_400 + 86399), "20000229T235959Z");
    }

    #[test]
    fn an_s3_bucket_is_not_this_machine_a_link_local_address_or_the_mesh() {
        let mesh: std::net::Ipv6Addr = "fd12:3456:789a::".parse().unwrap();
        let may = |at: &str| outside(at.parse().unwrap(), Some(mesh));
        for at in ["192.168.1.20", "10.0.0.5", "93.184.216.34", "2001:db8::1", "fd00:1::1"] {
            assert!(may(at), "{at}");
        }
        let not = [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ];
        for at in not
            .into_iter()
            .chain(["::ffff:169.254.169.254", "fd12:3456:789a:1::1", "224.0.0.1"])
        {
            assert!(!may(at), "{at}");
        }
    }

    #[tokio::test]
    async fn an_s3_request_to_this_machine_is_refused_before_anything_is_sent() {
        let mut bucket = example();
        (bucket.endpoint, bucket.anywhere) = ("https://localhost:1".into(), false);
        let refused = s3(&bucket, reqwest::Method::DELETE, "x.tar", None).await.unwrap_err();
        assert!(refused.contains("a bucket is not on this machine"), "{refused}");
    }

    /// What a bucket would do, on 127.0.0.1: keeps what is put, gives it back, forgets it,
    /// and takes nothing whose signature is not the one its own sum comes to.
    async fn fake_s3() -> (
        Bucket,
        Arc<std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    ) {
        use axum::http::{HeaderMap, Method, StatusCode, Uri};
        let kept = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut bucket = example();
        bucket.endpoint = format!("http://127.0.0.1:{port}");
        let objects = kept.clone();
        let serve = move |method: Method, uri: Uri, headers: HeaderMap, body: axum::body::Bytes| {
            let objects = objects.clone();
            async move {
                let header = |name: &str| {
                    headers
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string()
                };
                let (host, payload, date) = (header("host"), header("x-amz-content-sha256"), header("x-amz-date"));
                let signed = [
                    ("host", host.as_str()),
                    ("x-amz-content-sha256", payload.as_str()),
                    ("x-amz-date", date.as_str()),
                ];
                let mut bucket = example();
                bucket.endpoint = String::new();
                // (And nothing dated long ago: a real bucket takes a request of the last minutes only.)
                if date.as_str() < "2025"
                    || header("authorization")
                        != authorization(method.as_str(), uri.path(), &signed, &payload, &date, &bucket)
                {
                    return (StatusCode::FORBIDDEN, Vec::new());
                }
                let mut objects = objects.lock().unwrap();
                match method {
                    Method::PUT => drop(objects.insert(uri.path().to_string(), body.to_vec())),
                    Method::DELETE => drop(objects.remove(uri.path())),
                    _ => {
                        return objects
                            .get(uri.path())
                            .map_or((StatusCode::NOT_FOUND, Vec::new()), |found| {
                                (StatusCode::OK, found.clone())
                            });
                    }
                }
                (StatusCode::OK, Vec::new())
            }
        };
        let app = axum::Router::new()
            .fallback(serve)
            .layer(axum::extract::DefaultBodyLimit::disable());
        tokio::spawn(async move { axum::serve(listener, app).await });
        (bucket, kept)
    }

    #[tokio::test]
    async fn an_s3_bucket_is_sent_the_archive_gives_it_back_and_forgets_it() {
        let (mut bucket, kept) = fake_s3().await;
        let root = temp("s3");
        let bytes = vec![42u8; 300_000];
        std::fs::write(root.join("archive"), &bytes).unwrap();
        let body = || {
            let file = std::fs::File::open(root.join("archive")).unwrap();
            reqwest::Body::wrap_stream(crate::blobs::chunks(file))
        };
        s3(
            &bucket,
            reqwest::Method::PUT,
            "pre/nightly-1.tar",
            Some((body(), 300_000)),
        )
        .await
        .unwrap();
        assert!(kept.lock().unwrap()["/examplebucket/pre/nightly-1.tar"] == bytes);
        let got = s3(&bucket, reqwest::Method::GET, "pre/nightly-1.tar", None)
            .await
            .unwrap();
        assert!(got.bytes().await.unwrap() == bytes[..]);
        s3(&bucket, reqwest::Method::DELETE, "pre/nightly-1.tar", None)
            .await
            .unwrap();
        assert!(kept.lock().unwrap().is_empty());
        // Somebody else's key: refused, and said with the object's name but never the key.
        bucket.secret = "not-the-key".into(); // pragma: allowlist secret
        let refused = s3(&bucket, reqwest::Method::PUT, "x.tar", Some((body(), 300_000)))
            .await
            .unwrap_err();
        assert!(
            refused.contains("x.tar") && refused.contains("403") && !refused.contains("not-the-key"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
