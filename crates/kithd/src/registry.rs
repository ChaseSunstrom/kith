//! Packages in OCI registries (PLAN.md §4.8): `oci://HOST/PATH` holds the package NAME
//! as the repository `PATH/NAME`, each version an artifact tagged with it. The artifact
//! is what [`kith_packages::artifact`] says: one blob, the signature an annotation.
//
// ponytail: no credentials (public registries, or ones that trust the network they are
// on); plain HTTP only to this machine. Logins when a private registry is first wanted.
// A registry is one an admin named, and is trusted not to drown us: the blob is capped,
// the manifest and the list of tags are not (oci-client reads them whole), nor is where
// it sends us for a token. Our own capped requests when that trust is too much (T-0054).

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
use oci_client::{Client, Reference};
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

/// Where `name` at `version` is in the repository `url`, and a client for there.
fn place(url: &str, name: &str, version: &str) -> Fallible<(Client, Reference)> {
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
    let config = ClientConfig {
        protocol,
        ..ClientConfig::default()
    };
    Ok((Client::new(config), reference))
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
    let (client, reference) = place(url, name, version)?;
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
    let (client, reference) = place(url, name, version)?;
    let (manifest, _) = patiently(&reference, client.pull_image_manifest(&reference, &Anonymous)).await?;
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
    let (client, reference) = place(url, name, "latest")?;
    // ponytail: the first 1000 tags; a package with more versions gets pages.
    let listed = patiently(&reference, client.list_tags(&reference, &Anonymous, Some(1000), None)).await?;
    Ok(listed.tags)
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
