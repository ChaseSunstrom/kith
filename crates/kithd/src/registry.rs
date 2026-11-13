//! Packages in OCI registries (PLAN.md §4.8): `oci://HOST/PATH` holds the package NAME
//! as the repository `PATH/NAME`, each version an artifact tagged with it. The artifact
//! is what [`kith_packages::artifact`] says: one blob, the signature an annotation.
//
// ponytail: no credentials (public registries, or ones that trust the network they are
// on); plain HTTP only to this machine. Logins when a private registry is first wanted.
// A registry is one an admin named, but not trusted to drown us or to send us inward:
// the blob is capped (and pulled by oci-client), the manifest, the list of tags and the
// token's answer are our own capped requests, a token is asked for only at the registry's
// own scheme, host and port, and a redirect stays there too (T-0054). A registry whose
// tokens come from another host (Docker Hub's auth.docker.io) is refused for it.

use crate::Shared;
use crate::releases::REPOSITORY;
use kith_api::Resource;
use kith_api::kinds::{ReleaseSpec, RepositorySpec};
use kith_api::store::Store;
use kith_packages::Package;
use kith_packages::artifact::{LAYER, SIGNATURE};
use kith_store::Command;
use oci_client::client::{ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use oci_client::secrets::RegistryAuth::Anonymous;
use oci_client::{Client, Reference, RegistryOperation};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

type Fallible<T> = Result<T, String>;

/// The most a package's blob is taken to be: its files' 4 MB, as JSON.
const BLOB_LIMIT: i64 = 8 << 20;
/// How long a registry gets for one thing asked of it.
const PATIENCE: Duration = Duration::from_secs(60);
/// The artifact's (empty) configuration: what says the artifact is a kith package.
const CONFIG: &str = "application/vnd.kith.package.config.v1+json";

/// The most a manifest or a list of tags is taken to be (registries cap theirs at 4 MB).
const MANIFEST_LIMIT: usize = 1 << 20;
/// The most a token's answer is taken to be.
const TOKEN_LIMIT: usize = 64 << 10;
/// What a manifest is asked for as: one artifact's, not an index.
const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// Where `name` at `version` is in the repository `url`, and clients for there.
fn place(url: &str, name: &str, version: &str) -> Fallible<(Client, Reference, Web)> {
    let path = url
        .strip_prefix("oci://")
        .ok_or(format!("{url}: not oci://HOST/PATH"))?;
    let reference = format!("{}/{name}:{version}", path.trim_end_matches('/'));
    let reference: Reference = reference.parse().map_err(|e| format!("{reference}: {e}"))?;
    // (As container tools do: no TLS to a registry on this very machine.)
    let registry = reference.registry();
    let host = match registry.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        Some((v6, _)) => v6,
        None => registry.rsplit_once(':').map_or(registry, |(host, _)| host),
    };
    let local = ["localhost", "127.0.0.1", "::1"].contains(&host);
    let protocol = match local {
        true => ClientProtocol::Http,
        false => ClientProtocol::Https,
    };
    // (Errors only if a provider is already installed, which is just as good.)
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = ClientConfig {
        protocol,
        ..ClientConfig::default()
    };
    // For what oci-client reads whole or follows anywhere: a redirect stays on the
    // registry's own host, port and scheme (a blob's, which is large and may sit on a
    // CDN, is left to oci-client).
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        let (to, from) = (attempt.url(), attempt.previous().first());
        let same = from.is_some_and(|from| {
            (to.scheme(), to.host_str(), to.port_or_known_default())
                == (from.scheme(), from.host_str(), from.port_or_known_default())
        });
        match same && attempt.previous().len() < 5 {
            true => attempt.follow(),
            false => attempt.stop(),
        }
    });
    let http = reqwest::Client::builder()
        .redirect(policy)
        .timeout(PATIENCE)
        .build()
        .map_err(|e| format!("setting up the registry client: {e}"))?;
    let scheme = if local { "http" } else { "https" };
    Ok((Client::new(config), reference, Web { http, scheme }))
}

/// The client for what [`capped`] asks, and the scheme the registry is reached by.
struct Web {
    http: reqwest::Client,
    scheme: &'static str,
}

/// `path` of the repository `reference` is in (`manifests/TAG`, `tags/list?n=1000`), as
/// what the registry answers with, at most `limit` bytes of it. A token is fetched when
/// the registry asks for one, only from the registry's own host (and handed to `oci`, as
/// the blob is pulled by it).
async fn capped(
    oci: &Client,
    web: &Web,
    reference: &Reference,
    path: &str,
    accept: &str,
    limit: usize,
) -> Fallible<Vec<u8>> {
    let what = |e: &dyn std::fmt::Display| format!("{reference}: {e}");
    let registry = reference.resolve_registry();
    let url = format!("{}://{registry}/v2/{}/{path}", web.scheme, reference.repository());
    let mut token: Option<String> = None;
    loop {
        let mut request = web.http.get(&url).header("accept", accept);
        if let Some(token) = &token {
            request = request.bearer_auth(token);
        }
        let reply = request.send().await.map_err(|e| what(&e))?;
        if reply.status() == 401 && token.is_none() {
            let challenge = reply.headers().get("www-authenticate").and_then(|h| h.to_str().ok());
            token = Some(
                bearer(oci, web, reference, challenge.unwrap_or_default())
                    .await
                    .map_err(|e| what(&e))?,
            );
            continue;
        }
        if !reply.status().is_success() {
            return Err(what(&format!("{}: {}", reply.url(), reply.status())));
        }
        return read(reply, limit).await.map_err(|e| what(&format!("{path}: {e}")));
    }
}

/// What `reply` says, at most `limit` bytes of it.
async fn read(mut reply: reqwest::Response, limit: usize) -> Fallible<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = reply.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > limit {
            return Err(format!("more than {limit} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// A token for pulling `reference`, from the realm a `challenge` (the registry's
/// `WWW-Authenticate`) names, if that is the registry's own: same scheme, host and port.
async fn bearer(oci: &Client, web: &Web, reference: &Reference, challenge: &str) -> Fallible<String> {
    let param = |key: &str| {
        let rest = challenge.split(&format!("{key}=\"")).nth(1)?;
        rest.split('"').next().map(str::to_string)
    };
    if !challenge
        .get(..6)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Bearer"))
    {
        return Err(format!("not authorized, and no Bearer token to ask for: {challenge}"));
    }
    let own = reqwest::Url::parse(&format!("{}://{}/", web.scheme, reference.resolve_registry()))
        .map_err(|e| e.to_string())?;
    let mut realm =
        reqwest::Url::parse(&param("realm").unwrap_or_default()).map_err(|e| format!("token realm: {e}"))?;
    let key = |url: &reqwest::Url| {
        (
            url.scheme().to_string(),
            url.host_str().map(str::to_string),
            url.port_or_known_default(),
        )
    };
    if key(&realm) != key(&own) {
        return Err(format!("token realm {realm} is not the registry's own ({own})"));
    }
    {
        let mut query = realm.query_pairs_mut();
        query.append_pair("scope", &format!("repository:{}:pull", reference.repository()));
        if let Some(service) = param("service") {
            query.append_pair("service", &service);
        }
    }
    let reply = web.http.get(realm).send().await.map_err(|e| e.to_string())?;
    if !reply.status().is_success() {
        return Err(format!("token: {}", reply.status()));
    }
    let body = read(reply, TOKEN_LIMIT).await.map_err(|e| format!("token: {e}"))?;
    let said: Value = serde_json::from_slice(&body).map_err(|e| format!("token: {e}"))?;
    let token = said["token"]
        .as_str()
        .or(said["access_token"].as_str())
        .ok_or("token: none in the answer")?;
    // (What oci-client sends with the blob's request, as if it had asked for it itself.)
    oci.auth(
        reference,
        &oci_client::secrets::RegistryAuth::Bearer(token.to_string()),
        RegistryOperation::Pull,
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(token.to_string())
}

async fn patiently<T>(what: &Reference, asked: impl Future<Output = oci_client::errors::Result<T>>) -> Fallible<T> {
    match tokio::time::timeout(PATIENCE, asked).await {
        Ok(done) => done.map_err(|e| format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: no answer in {} s", PATIENCE.as_secs())),
    }
}

/// Put a blob (a package's, a Source's files) in the repository `url` as `name` at
/// `version`, with its signature if it has one. Says where.
pub async fn push(url: &str, name: &str, version: &str, blob: Vec<u8>, signature: Option<String>) -> Fallible<String> {
    let (client, reference, _) = place(url, name, version)?;
    let layers = [ImageLayer::new(blob, LAYER.to_string(), None)];
    let config = Config::new(b"{}".to_vec(), CONFIG.to_string(), None);
    let annotations = signature.map(|signature| BTreeMap::from([(SIGNATURE.to_string(), signature)]));
    let manifest = OciImageManifest::build(&layers, &config, annotations);
    let pushing = client.push(&reference, &layers, config, &Anonymous, Some(manifest));
    patiently(&reference, pushing).await?;
    Ok(reference.to_string())
}

/// The blob and the signature of `name` at `version` in the repository `url`: not yet
/// checked against any key, only against the digest the registry's manifest gives.
pub async fn pull(url: &str, name: &str, version: &str) -> Fallible<(Vec<u8>, Option<String>)> {
    let (client, reference, web) = place(url, name, version)?;
    let tag = format!("manifests/{version}");
    let manifest = capped(&client, &web, &reference, &tag, MANIFEST_TYPE, MANIFEST_LIMIT).await?;
    let manifest: OciImageManifest = serde_json::from_slice(&manifest).map_err(|e| format!("{reference}: {e}"))?;
    let [layer] = manifest.layers.as_slice() else {
        return Err(format!("{reference}: not a kith package (not one layer)"));
    };
    if layer.media_type != LAYER || !(0..=BLOB_LIMIT).contains(&layer.size) {
        return Err(format!(
            "{reference}: not a kith package, or one over {BLOB_LIMIT} bytes"
        ));
    }
    // (Room for what the manifest says and no more: a registry that sends more fails.)
    let mut blob = vec![0; usize::try_from(layer.size).unwrap_or_default()];
    patiently(
        &reference,
        client.pull_blob(&reference, layer, std::io::Cursor::new(blob.as_mut_slice())),
    )
    .await?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &blob);
    let digest: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    if layer.digest != format!("sha256:{digest}") {
        return Err(format!("{reference}: the blob is not the one its manifest names"));
    }
    let signature = manifest
        .annotations
        .and_then(|mut annotations| annotations.remove(SIGNATURE));
    Ok((blob, signature))
}

/// The versions of `name` in the repository `url`.
pub async fn versions(url: &str, name: &str) -> Fallible<Vec<String>> {
    let (client, reference, web) = place(url, name, "latest")?;
    // ponytail: the first 1000 tags; a package with more versions gets pages.
    let listed = capped(
        &client,
        &web,
        &reference,
        "tags/list?n=1000",
        "application/json",
        MANIFEST_LIMIT,
    )
    .await?;
    let listed: Value = serde_json::from_slice(&listed).map_err(|e| format!("{reference}: {e}"))?;
    let tags: Option<Vec<String>> =
        serde_json::from_value(listed["tags"].clone()).map_err(|e| format!("{reference}: tags: {e}"))?;
    Ok(tags.unwrap_or_default())
}

/// The package in a pulled `blob`: signed by `public` when there is one, and the
/// `name` and `version` it was asked for as (a registry does not get to swap them).
pub fn checked(
    blob: &[u8],
    signature: Option<&str>,
    public: Option<&str>,
    name: &str,
    version: &str,
) -> Fallible<Package> {
    let package = match public {
        Some(public) => kith_packages::artifact::verified(blob, signature, public)?,
        None => Package::from_blob(blob)?,
    };
    if (package.meta.name.as_str(), package.meta.version.as_str()) != (name, version) {
        let (is, at) = (&package.meta.name, &package.meta.version);
        return Err(format!("asked for {name} {version}, and what came is {is} {at}"));
    }
    Ok(package)
}

/// One thing to ask a registry: which version of `name` a Release should be on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Wanted {
    /// What Packages from there are annotated with (see [`crate::releases::origin`]).
    origin: String,
    repository: String,
    url: String,
    public_key: Option<String>,
    name: String,
    asked: Option<String>,
}

/// What the Releases in `store` want from Repositories, and the Repositories named
/// that are not there. A Release that is installed and does not follow the newest
/// (`autoUpgrade`) wants nothing more.
fn wanted(store: &Store) -> BTreeSet<Wanted> {
    let mut all = BTreeSet::new();
    for release in store.list(Some("Release")) {
        let Ok(spec) = serde_json::from_value::<ReleaseSpec>(release.spec.clone()) else {
            continue;
        };
        let Some(repository) = spec.package.repo else {
            continue;
        };
        let installed = release.status.as_ref().and_then(|status| status["version"].as_str());
        let name = spec.package.name;
        let Some(origin) = crate::releases::origin(store, &repository) else {
            continue;
        };
        let settled = |installed: &str| {
            let there = store.get(&format!("Package/{name}-{installed}"));
            let ours = there.is_some_and(|package| package.metadata.annotations.get(REPOSITORY) == Some(&origin));
            ours && crate::releases::fits(spec.package.version.as_deref(), installed)
        };
        if spec.auto_upgrade != Some(true) && installed.is_some_and(settled) {
            continue;
        }
        let Some(from) = store.get(&format!("Repository/{repository}")) else {
            continue;
        };
        let Ok(from) = serde_json::from_value::<RepositorySpec>(from.spec.clone()) else {
            continue;
        };
        all.insert(Wanted {
            origin,
            repository,
            url: from.url,
            public_key: from.public_key,
            name,
            asked: spec.package.version,
        });
    }
    all
}

/// How many versions that do not check out are passed over for an older one that does.
const PASSED_OVER: usize = 5;

/// Ask the registry for `wanted`: the newest version that fits and checks out, as a
/// Package to store (none when the store has it already), and what was passed over on
/// the way to it (a newer version that is not signed as it must be stops no one from
/// installing an older one that is).
async fn fetch(shared: &Shared, wanted: &Wanted) -> Fallible<(Option<Resource>, Vec<String>)> {
    let mut versions = versions(&wanted.url, &wanted.name).await?;
    versions.retain(|version| crate::releases::fits(wanted.asked.as_deref(), version));
    versions.sort_by_cached_key(|version| std::cmp::Reverse(semver::Version::parse(version).ok()));
    let asked = wanted.asked.as_deref().unwrap_or("*");
    let mut wrong = Vec::new();
    for version in versions.iter().take(PASSED_OVER) {
        let key = format!("Package/{}-{version}", wanted.name);
        let from = |package: &Resource| package.metadata.annotations.get(REPOSITORY).cloned();
        let there = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            state.store.get(&key).map(from)
        };
        // (From this repository as it was, with another key or address: fetched again.)
        let ours = |origin: &String| origin.split('@').next() == Some(&wanted.repository);
        match there {
            Some(Some(origin)) if origin == wanted.origin => return Ok((None, wrong)),
            Some(Some(origin)) if ours(&origin) => {}
            // ponytail: one Package per name and version in a cluster, wherever it is from.
            Some(_) => return Err(format!("{key} is there already, and not from this repository")),
            None => {}
        }
        let pulled = pull(&wanted.url, &wanted.name, version).await?;
        let (blob, signature) = pulled;
        match checked(
            &blob,
            signature.as_deref(),
            wanted.public_key.as_deref(),
            &wanted.name,
            version,
        ) {
            Ok(package) => {
                let mut package = package.resource()?;
                package
                    .metadata
                    .annotations
                    .insert(REPOSITORY.into(), wanted.origin.clone());
                return Ok((Some(package), wrong));
            }
            Err(e) => wrong.push(e),
        }
    }
    wrong.insert(
        0,
        format!(
            "{}: no version of {} that fits {asked} checks out",
            wanted.url, wanted.name
        ),
    );
    Err(wrong.join("; "))
}

/// Keep the Releases that name a Repository supplied with Packages from it, as long as
/// this node leads the store: asked when what is wanted changes, and every `poll`.
pub async fn run(shared: Arc<Shared>, poll: Duration, mut stopping: watch::Receiver<bool>) {
    let mut generation = shared.generation.subscribe();
    let mut asked: BTreeMap<Wanted, tokio::time::Instant> = BTreeMap::new();
    loop {
        let metrics = shared.raft.metrics().borrow().clone();
        if metrics.current_leader == Some(metrics.id) {
            let wanted = {
                let state = shared.store.lock().expect("nothing panics holding the store");
                wanted(&state.store)
            };
            asked.retain(|was, at| wanted.contains(was) && at.elapsed() < poll);
            let mut said: BTreeMap<String, (&str, Option<String>)> = BTreeMap::new();
            for wanted in wanted {
                if asked.contains_key(&wanted) {
                    continue;
                }
                let (state, message) = match fetch(&shared, &wanted).await {
                    Err(e) => ("error", Some(e)),
                    Ok((package, passed)) => {
                        let stored = match package {
                            None => Ok(()),
                            Some(package) => {
                                let at = kith_api::store::now();
                                let resources = vec![package];
                                let stored = shared.submit(Command::Apply { resources, at }).await;
                                stored.map(|_| ()).map_err(|e| e.to_string())
                            }
                        };
                        match (stored, passed.is_empty()) {
                            (Err(e), _) => ("error", Some(e)),
                            (Ok(()), true) => ("ok", None),
                            (Ok(()), false) => ("ok", Some(format!("passed over: {}", passed.join("; ")))),
                        }
                    }
                };
                // (The first thing wrong with a repository is what its status says.)
                let now = said
                    .entry(format!("Repository/{}", wanted.repository))
                    .or_insert(("ok", None));
                if now.1.is_none() {
                    *now = (state, message);
                }
                asked.insert(wanted, tokio::time::Instant::now());
            }
            report(&shared, said).await;
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(poll) => {}
            _ = stopping.changed() => break,
        }
    }
}

/// Say in each Repository's status how asking it went, if that is news.
async fn report(shared: &Shared, said: BTreeMap<String, (&str, Option<String>)>) {
    let mut statuses = Vec::new();
    {
        let state = shared.store.lock().expect("nothing panics holding the store");
        for (key, (state_now, message)) in said {
            let status = json!({ "state": state_now, "message": message });
            let live = state.store.get(&key).and_then(|repository| repository.status.as_ref());
            if live.is_none_or(|live| live["state"] != status["state"] || live["message"] != status["message"])
                && let Value::Object(status) = status
            {
                statuses.push((key, status));
            }
        }
    }
    if !statuses.is_empty()
        && let Err(e) = shared.submit(Command::Patch { statuses }).await
    {
        eprintln!("kithd: repositories: {e}");
    }
}

/// Registries here are all on 127.0.0.1: nothing reaches outside this machine.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// What a fake registry says: status, header lines, body.
    type Reply = (u16, Vec<String>, Vec<u8>);
    const BLOB: &[u8] = b"a package";

    /// A registry answering each request (its port, its path, whether it came with the
    /// token `tok`) with `answer`. Says its port and the paths it was asked for.
    async fn fake(answer: impl Fn(u16, &str, bool) -> Reply + Send + Sync + 'static) -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (answer, asked) = (Arc::new(answer), Arc::new(Mutex::new(Vec::new())));
        let log = asked.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (answer, log) = (answer.clone(), log.clone());
                tokio::spawn(async move {
                    let (mut head, mut buf) = (Vec::new(), [0u8; 1024]);
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&head).to_lowercase();
                    let path = head.split(' ').nth(1).unwrap_or_default().to_string();
                    let authed = head.lines().any(|line| line == "authorization: bearer tok");
                    log.lock().unwrap().push(path.clone());
                    let (status, headers, body) = answer(port, &path, authed);
                    let mut reply = format!(
                        "HTTP/1.1 {status} x\r\ncontent-length: {}\r\nconnection: close\r\n",
                        body.len()
                    );
                    reply += &headers.iter().map(|h| format!("{h}\r\n")).collect::<String>();
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.write_all(b"\r\n").await;
                    let _ = socket.write_all(&body).await;
                });
            }
        });
        (port, asked)
    }

    fn digest(blob: &[u8]) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, blob);
        let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
        format!("sha256:{hex}")
    }

    /// The manifest of a package, with an annotation `padding` bytes long.
    fn manifest(padding: usize) -> Vec<u8> {
        json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": CONFIG, "digest": digest(b"{}"), "size": 2 },
            "layers": [{ "mediaType": LAYER, "digest": digest(BLOB), "size": BLOB.len() }],
            "annotations": { SIGNATURE: "sig", "pad": "x".repeat(padding) },
        })
        .to_string()
        .into_bytes()
    }

    /// A registry that wants a token from its own `/token`, holding one package
    /// (its manifest as given) and the tags `tags`.
    fn registry(manifest: Vec<u8>, tags: Vec<u8>) -> impl Fn(u16, &str, bool) -> Reply + Send + Sync + 'static {
        move |port, path, authed| match path {
            _ if path.starts_with("/token") => (200, vec![], br#"{"token":"tok"}"#.to_vec()),
            _ if !authed => {
                let challenge =
                    format!("www-authenticate: Bearer realm=\"http://127.0.0.1:{port}/token\",service=\"fake\"");
                (401, vec![challenge], vec![])
            }
            _ if path.contains("/manifests/") => (200, vec![], manifest.clone()),
            _ if path.contains("/blobs/") => (200, vec![], BLOB.to_vec()),
            _ if path.contains("/tags/list") => (200, vec![], tags.clone()),
            _ => (404, vec![], vec![]),
        }
    }

    fn url(port: u16) -> String {
        format!("oci://127.0.0.1:{port}/kith")
    }

    #[tokio::test]
    async fn registry_serves_a_package_and_its_versions() {
        let tags = br#"{"name":"kith/pkg","tags":["1.0.0","1.1.0"]}"#.to_vec();
        let (port, _) = fake(registry(manifest(0), tags)).await;
        let (blob, signature) = pull(&url(port), "pkg", "1.0.0").await.unwrap();
        assert_eq!((blob.as_slice(), signature.as_deref()), (BLOB, Some("sig")));
        assert_eq!(versions(&url(port), "pkg").await.unwrap(), ["1.0.0", "1.1.0"]);
    }

    #[tokio::test]
    async fn registry_refuses_an_oversized_manifest() {
        let (port, _) = fake(registry(manifest(2 << 20), vec![])).await;
        let e = pull(&url(port), "pkg", "1.0.0").await.unwrap_err();
        assert!(e.contains("more than"), "{e}");
    }

    #[tokio::test]
    async fn registry_refuses_an_oversized_tag_list() {
        let tags = json!({ "name": "kith/pkg", "tags": ["1.0.0".repeat(300_000)] }).to_string();
        let (port, _) = fake(registry(vec![], tags.into_bytes())).await;
        let e = versions(&url(port), "pkg").await.unwrap_err();
        assert!(e.contains("more than"), "{e}");
    }

    #[tokio::test]
    async fn registry_refuses_a_token_realm_of_another_host() {
        let (elsewhere, reached) = fake(|_, _, _| (200, vec![], br#"{"token":"tok"}"#.to_vec())).await;
        // (Another host by name, another scheme, another port: none is the registry's own.)
        for realm in [
            format!("http://localhost:{elsewhere}/token"),
            format!("http://127.0.0.1:{elsewhere}/token"),
            "https://127.0.0.1/token".to_string(),
        ] {
            let challenge = format!("www-authenticate: Bearer realm=\"{realm}\",service=\"fake\"");
            let (port, asked) = fake(move |_, _, _| (401, vec![challenge.clone()], vec![])).await;
            let e = pull(&url(port), "pkg", "1.0.0").await.unwrap_err();
            assert!(e.contains("token realm"), "{realm}: {e}");
            assert_eq!(asked.lock().unwrap().len(), 1, "{realm}: one request, the manifest's");
        }
        assert!(reached.lock().unwrap().is_empty(), "the other host was asked");
    }

    #[tokio::test]
    async fn registry_does_not_follow_a_redirect_to_another_host() {
        let (elsewhere, reached) = fake(|_, _, _| (200, vec![], manifest(0))).await;
        let location = format!("location: http://localhost:{elsewhere}/v2/kith/pkg/manifests/1.0.0");
        let (port, _) = fake(move |_, _, _| (302, vec![location.clone()], vec![])).await;
        assert!(pull(&url(port), "pkg", "1.0.0").await.is_err());
        assert!(versions(&url(port), "pkg").await.is_err());
        assert!(reached.lock().unwrap().is_empty(), "the other host was asked");
    }
}
