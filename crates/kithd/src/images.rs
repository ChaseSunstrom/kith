//! Images made in the cluster, and the registry that serves them.
//!
//! An `Image` names a Volume. The volume's node packs its directory as the one layer of an
//! OCI image (when the Job the Image names, if any, has succeeded) and keeps the layer, the
//! image's config and its manifest as Blobs, which other nodes hold too. Nothing runs to
//! build: the steps of a build are the containers of an ordinary Job that fill the volume.
//!
//! Every node serves the cluster's Images to itself, as a registry that can only be read:
//! `localhost:PORT/NAMESPACE/NAME:TAG` is the Image `NAME` of `NAMESPACE`, on any node.
//
// ponytail: one layer and no base image (the volume holds the whole root); made once for a
// spec (a new tag is a new image: nodes keep a tag they have pulled); nothing is pushed
// with the registry protocol; an Image that is deleted leaves its Blobs to be deleted by
// hand; an Image that waits (no Volume, its Job not done) says nothing in its status. Each
// has its own day.

use crate::Shared;
use crate::blobs::Incoming;
use crate::volumes::Dir;
use axum::body::Body;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use kith_api::kinds::ImageSpec;
use kith_api::store::Store;
use kith_store::Command;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// How often a node looks for an image to make.
const ROUND: Duration = Duration::from_secs(5);
/// One that failed is tried again after this long.
const AGAIN: u64 = 60;
/// On the Blobs an Image made (as a backup's are marked).
const MADE: &str = "kith.dev/made-by";
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
    let from = crate::volumes::host_dir(state, &job.dir)?;
    let (blobs, spec) = (crate::blobs::dir(shared), job.spec.clone());
    let packed = tokio::task::spawn_blocking(move || pack(&from, &blobs, &spec)).await;
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
            "metadata": { "name": blob, "namespace": job.namespace, "annotations": { MADE: "image" } },
            "spec": spec,
        });
        resources.push(serde_json::from_value(wanted).map_err(|e| e.to_string())?);
    }
    if !resources.is_empty() {
        let at = kith_api::store::now();
        let applied = shared.write(Command::Apply { resources, at }).await;
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
/// did not make and those another Image or a Backup of the namespace has too.
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
                .is_some_and(|blob| blob.metadata.annotations.contains_key(MADE));
            made && !crate::backups::listed(&state.store, &job.namespace, &job.key, blob)
        };
        if ours && let Err(e) = shared.submit(Command::Delete { key: key.clone() }).await {
            eprintln!("kithd: image {}: {key} was not removed: {e}", job.key);
        }
    }
}

/// Makes the images that are due of the volumes on this node.
pub async fn run(shared: Arc<Shared>, state: PathBuf, mut stopping: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = stopping.changed() => return,
            () = tokio::time::sleep(ROUND) => {}
        }
        let now = kith_api::store::now();
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
        Ok(path) => std::fs::File::open(path).and_then(|file| Ok((file.metadata()?.len(), file))),
        Err(e) => Err(std::io::Error::other(e)),
    };
    match file {
        Ok((size, file)) => {
            let kind = if uri.path().contains("/manifests/") {
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
        Err(e) => {
            eprintln!("kithd: registry: {key}: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response()
        }
    }
}

/// Serves the cluster's Images on this node's loopback, to read (0: not at all).
pub async fn serve(shared: Arc<Shared>, port: u16, mut stopping: watch::Receiver<bool>) {
    if port == 0 {
        return;
    }
    let listener = match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await {
        Ok(listener) => listener,
        Err(e) => return eprintln!("kithd: registry: 127.0.0.1:{port}: {e}: Images are not served on this node"),
    };
    // (`get` answers HEAD too, without the body.)
    let app = axum::Router::new().fallback(axum::routing::get(move |uri: Uri| answer(shared.clone(), uri)));
    let served = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = stopping.changed().await;
    });
    if let Err(e) = served.await {
        eprintln!("kithd: registry: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_api::Resource;

    fn store(resources: Value) -> Store {
        let mut store = Store::default();
        let resources: Vec<Resource> = serde_json::from_value(resources).unwrap();
        store.apply_all(resources).unwrap();
        store
    }

    fn sha_of(path: &Path) -> String {
        hex(&Sha256::digest(std::fs::read(path).unwrap()))
    }

    /// A directory becomes an image a registry can serve: the manifest names the config and
    /// the layer by what their bytes hash to, the config names the layer, and the layer is
    /// the directory.
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
}
