//! Packages in OCI registries (PLAN.md §4.8): `oci://HOST/PATH` holds the package NAME
//! as the repository `PATH/NAME`, each version an artifact tagged with it. The artifact
//! is what [`kith_packages::artifact`] says: one blob, the signature an annotation.
//
// ponytail: no credentials (public registries, or ones that trust the network they are
// on); plain HTTP only to this machine. Logins when a private registry is first wanted.
// A registry is one an admin named, but not trusted to drown us or to send us inward:
// the blob is capped (and pulled by oci-client), the manifest, the list of tags and the
// token's answer are our own capped requests, a token is asked for only at the registry's
// own scheme, host and port, or at an https one that is outside this node and its
// networks (Docker Hub's auth.docker.io), and a redirect stays on the registry (T-0054).
// For a Source that is not the cluster's own (`outward`), every connection is made to an
// address that was just vetted (sources::vetted), the blob's and each redirect's too; and
// so is every request of a push an Identity asks for, where the registry sends each blob
// included.

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
fn place(url: &str, name: &str, version: &str, outward: bool) -> Fallible<(Client, Reference, Web)> {
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
    let patience = kith_runtime::Patience::default();
    let config = ClientConfig {
        protocol,
        connect_timeout: Some(patience.connect),
        read_timeout: Some(patience.read),
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
        .connect_timeout(patience.connect)
        .read_timeout(patience.read)
        .timeout(PATIENCE)
        .build()
        .map_err(|e| format!("setting up the registry client: {e}"))?;
    let scheme = if local { "http" } else { "https" };
    let web = Web {
        http,
        scheme,
        outward,
        token: Default::default(),
        login: None,
    };
    Ok((Client::new(config), reference, web))
}

/// A user name and a password.
pub type Login = (String, String);

/// `Authorization: Basic …` for `login`.
fn basic(login: &Login) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", login.0, login.1))
    )
}

/// The client for what [`capped`] asks, and the scheme the registry is reached by.
struct Web {
    http: reqwest::Client,
    scheme: &'static str,
    /// See the module's note.
    outward: bool,
    /// What the registry wanted to be sent (an `Authorization` header's value), once it was
    /// known: a Bearer token fetched, or Basic.
    token: std::sync::Mutex<Option<String>>,
    /// What a Repository's Secret says to ask with, to the registry's token service or, where
    /// it challenges Basic, the registry. None: Anonymous.
    login: Option<Login>,
}

/// A client that connects only where `url`'s host was just seen to be: outside this node
/// and its networks. It follows nothing.
async fn held(url: &reqwest::Url) -> Fallible<reqwest::Client> {
    // (Its origin only: what follows, a query too, is not what is connected to.)
    let (host, _, addresses) = crate::sources::vetted(&url.origin().ascii_serialization(), false).await?;
    let patience = kith_runtime::Patience::default();
    let client = reqwest::Client::builder()
        .resolve_to_addrs(&host, &addresses)
        // (Nor a proxy, which would look the name up again itself.)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(patience.connect)
        .read_timeout(patience.read)
        .timeout(PATIENCE);
    client
        .build()
        .map_err(|e| format!("setting up the registry client: {e}"))
}

/// GET `url` as `web` does: with its client, or, `outward`, hop by hop through [`held`]
/// ones (five at most, never from https to less, the `token`, an `Authorization` header's
/// value (a Bearer or a Basic one), only to the first host).
async fn get(web: &Web, url: &str, accept: &str, token: Option<&str>) -> Fallible<reqwest::Response> {
    let authorized = |request: reqwest::RequestBuilder, token: Option<&str>| match token {
        Some(token) => request.header("accept", accept).header("authorization", token),
        None => request.header("accept", accept),
    };
    if !web.outward {
        let sent = authorized(web.http.get(url), token).send().await;
        return sent.map_err(|e| e.to_string());
    }
    let mut url = reqwest::Url::parse(url).map_err(|e| format!("{url}: {e}"))?;
    let mut token = token;
    for _ in 0..5 {
        let client = held(&url).await?;
        let reply = authorized(client.get(url.clone()), token).send().await;
        let reply = reply.map_err(|e| e.to_string())?;
        if !reply.status().is_redirection() {
            return Ok(reply);
        }
        let to = reply.headers().get("location").and_then(|to| to.to_str().ok());
        let to = to.and_then(|to| url.join(to).ok()).ok_or("a redirect to nowhere")?;
        if url.scheme() == "https" && to.scheme() != "https" {
            return Err(format!("a redirect from https to {to}"));
        }
        if to.host_str() != url.host_str() {
            token = None;
        }
        url = to;
    }
    Err("more than five redirects".into())
}

/// Where `path` of the repository `reference` is in (`manifests/TAG`, `tags/list?n=1000`).
fn at(web: &Web, reference: &Reference, path: &str) -> String {
    format!(
        "{}://{}/v2/{}/{path}",
        web.scheme,
        reference.resolve_registry(),
        reference.repository()
    )
}

/// What the registry answers `url` with (see [`at`]), at most `limit` bytes of it, and the
/// next page it names in a `Link` header, if it does: only on the registry's own scheme,
/// host and port, else an error. A token is fetched when the registry asks for one, only
/// from the registry's own host (and handed to `oci`, as the blob is pulled by it); one
/// that was is used again.
async fn capped(
    oci: &Client,
    web: &Web,
    reference: &Reference,
    url: &str,
    accept: &str,
    limit: usize,
) -> Fallible<(Vec<u8>, Option<String>)> {
    let what = |e: &dyn std::fmt::Display| format!("{reference}: {e}");
    let mut token = web.token.lock().expect("nothing panics holding it").clone();
    loop {
        let reply = get(web, url, accept, token.as_deref()).await.map_err(|e| what(&e))?;
        if reply.status() == 401 && token.is_none() {
            let challenge = reply.headers().get("www-authenticate").and_then(|h| h.to_str().ok());
            token = Some(
                answer(oci, web, reference, challenge.unwrap_or_default())
                    .await
                    .map_err(|e| what(&e))?,
            );
            continue;
        }
        if !reply.status().is_success() {
            return Err(what(&format!("{}: {}", reply.url(), reply.status())));
        }
        let next = reply.headers().get("link").and_then(|link| link.to_str().ok());
        let next = next.and_then(next_link).map(|next| {
            let own = reqwest::Url::parse(url).map_err(|e| what(&e))?;
            let next = own.join(next).map_err(|e| what(&format!("link {next}: {e}")))?;
            let key = |url: &reqwest::Url| {
                (
                    url.scheme().to_string(),
                    url.host_str().map(str::to_string),
                    url.port_or_known_default(),
                )
            };
            match key(&next) == key(&own) {
                true => Ok(next.to_string()),
                false => Err(what(&format!("link {next} is not the registry's own ({own})"))),
            }
        });
        let next = next.transpose()?;
        let body = read(reply, limit).await.map_err(|e| what(&format!("{url}: {e}")))?;
        return Ok((body, next));
    }
}

/// The target of the `rel="next"` link in a `Link` header's value.
fn next_link(link: &str) -> Option<&str> {
    let part = link.split(',').find(|part| {
        let part = part.replace(' ', "").to_lowercase();
        part.contains("rel=\"next\"") || part.contains("rel=next")
    })?;
    Some(part.split_once('<')?.1.split_once('>')?.0)
}

/// What to send a registry that answered 401 with `challenge` (its `WWW-Authenticate`): a
/// token from the service it names, which a login is sent to as Basic, or, where the
/// registry itself asks for Basic and there is a login, that. Kept in `web` for what follows.
async fn answer(oci: &Client, web: &Web, reference: &Reference, challenge: &str) -> Fallible<String> {
    let basically = challenge
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Basic"));
    let Some(login) = web.login.as_ref().filter(|_| basically) else {
        return bearer(oci, web, reference, challenge).await;
    };
    let header = basic(login);
    // (As the token is: what oci-client sends with the blob's request.)
    let auth = oci_client::secrets::RegistryAuth::Basic(login.0.clone(), login.1.clone());
    oci.auth(reference, &auth, RegistryOperation::Pull)
        .await
        .map_err(|e| e.to_string())?;
    *web.token.lock().expect("nothing panics holding it") = Some(header.clone());
    Ok(header)
}

/// What `reply` says, at most `limit` bytes of it (kith-runtime reads the same way for its own).
async fn read(reply: reqwest::Response, limit: usize) -> Fallible<Vec<u8>> {
    kith_runtime::read_capped(reply, limit).await.map_err(|e| e.to_string())
}

/// A token for pulling `reference` (as the `Authorization` value `Bearer …`), from the realm
/// a `challenge` (the registry's `WWW-Authenticate`) names, if that is the registry's own
/// (same scheme, host and port) or one that is https and outside this node's networks.
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
    // (Its own, or one that is https and outside this node's networks: asked where it was seen to be.)
    let elsewhere = key(&realm) != key(&own);
    if elsewhere && realm.scheme() != "https" {
        return Err(format!(
            "token realm {realm} is not the registry's own ({own}), nor https"
        ));
    }
    {
        let mut query = realm.query_pairs_mut();
        query.append_pair("scope", &format!("repository:{}:pull", reference.repository()));
        if let Some(service) = param("service") {
            query.append_pair("service", &service);
        }
    }
    // (A login goes to the token service as Basic, as a container tool's does: where the
    // registry points, which is no more than its own word for whom to trust with it.)
    let login = web.login.as_ref().map(basic);
    let reply = match elsewhere {
        true => {
            let client = held(&realm).await.map_err(|e| format!("token realm {realm}: {e}"))?;
            let asked = client.get(realm);
            let asked = match &login {
                Some(login) => asked.header("authorization", login),
                None => asked,
            };
            asked.send().await.map_err(|e| e.to_string())?
        }
        false => get(web, realm.as_str(), "application/json", login.as_deref()).await?,
    };
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
    let header = format!("Bearer {token}");
    *web.token.lock().expect("nothing panics holding it") = Some(header.clone());
    Ok(header)
}

async fn patiently<T>(what: &Reference, asked: impl Future<Output = oci_client::errors::Result<T>>) -> Fallible<T> {
    match tokio::time::timeout(PATIENCE, asked).await {
        Ok(done) => done.map_err(|e| format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: no answer in {} s", PATIENCE.as_secs())),
    }
}

/// One request of an outward push: to an address that was just vetted, following nothing.
async fn sent(method: reqwest::Method, url: &reqwest::Url, kind: &str, body: Vec<u8>) -> Fallible<reqwest::Response> {
    let asked = held(url).await?.request(method, url.clone());
    let asked = asked.header("content-type", kind).body(body);
    asked.send().await.map_err(|e| e.to_string())
}

/// `blob` into the repository at `base` (`…/v2/REPOSITORY/`) as a registry takes one:
/// asked where it goes, then put there, if that is outside this node's networks too.
async fn upload(base: &reqwest::Url, digest: &str, blob: Vec<u8>) -> Fallible<()> {
    const BYTES: &str = "application/octet-stream";
    let start = base.join("blobs/uploads/").map_err(|e| e.to_string())?;
    let started = sent(reqwest::Method::POST, &start, BYTES, Vec::new()).await?;
    let to = started.headers().get("location").and_then(|to| to.to_str().ok());
    let (202, Some(mut to)) = (started.status().as_u16(), to.and_then(|to| start.join(to).ok())) else {
        // (No login to give: see the module's note.)
        return Err(format!("{start}: {}, not where to send it", started.status()));
    };
    if start.scheme() == "https" && to.scheme() != "https" {
        return Err(format!("sent on from https to {to}"));
    }
    to.query_pairs_mut().append_pair("digest", digest);
    let done = sent(reqwest::Method::PUT, &to, BYTES, blob).await?;
    match done.status().is_success() {
        true => Ok(()),
        false => Err(format!("{to}: {}", done.status())),
    }
}

/// Put a blob (a package's, a Source's files) in the repository `url` as `name` at
/// `version`, with its signature if it has one. Says where.
///
/// `outward`: whoever asks is not the node, and may send only where a pull may come from:
/// every request (the registry's, and where it says each blob goes) is made by a client
/// that connects only to an address just vetted, and oci-client, which goes wherever it
/// is sent, is not used.
pub async fn push(
    url: &str,
    name: &str,
    version: &str,
    blob: Vec<u8>,
    signature: Option<String>,
    outward: bool,
) -> Fallible<String> {
    let (client, reference, web) = place(url, name, version, outward)?;
    let layers = [ImageLayer::new(blob, LAYER.to_string(), None)];
    let config = Config::new(b"{}".to_vec(), CONFIG.to_string(), None);
    let annotations = signature.map(|signature| BTreeMap::from([(SIGNATURE.to_string(), signature)]));
    let manifest = OciImageManifest::build(&layers, &config, annotations);
    if !outward {
        let pushing = client.push(&reference, &layers, config, &Anonymous, Some(manifest));
        patiently(&reference, pushing).await?;
        return Ok(reference.to_string());
    }
    let what = |e: String| format!("{reference}: {e}");
    let registry = reference.resolve_registry();
    let base = format!("{}://{registry}/v2/{}/", web.scheme, reference.repository());
    let base = reqwest::Url::parse(&base).map_err(|e| what(e.to_string()))?;
    let [layer] = layers;
    let blobs = [
        (layer.sha256_digest(), layer.data.to_vec()),
        (config.sha256_digest(), config.data.to_vec()),
    ];
    for (digest, blob) in blobs {
        upload(&base, &digest, blob).await.map_err(what)?;
    }
    let to = base
        .join(&format!("manifests/{version}"))
        .map_err(|e| what(e.to_string()))?;
    let body = serde_json::to_vec(&manifest).map_err(|e| what(e.to_string()))?;
    let done = sent(reqwest::Method::PUT, &to, MANIFEST_TYPE, body)
        .await
        .map_err(what)?;
    match done.status().is_success() {
        true => Ok(reference.to_string()),
        false => Err(what(format!("{to}: {}", done.status()))),
    }
}

/// The blob and the signature of `name` at `version` in the repository `url`: not yet
/// checked against any key, only against the digest the registry's manifest gives.
///
/// `outward`: see the module's note.
pub async fn pull(url: &str, name: &str, version: &str, outward: bool) -> Fallible<(Vec<u8>, Option<String>)> {
    pull_as(url, name, version, outward, None).await
}

/// [`pull`], asking as `login` where the registry wants one (Anonymous when none).
pub async fn pull_as(
    url: &str,
    name: &str,
    version: &str,
    outward: bool,
    login: Option<&Login>,
) -> Fallible<(Vec<u8>, Option<String>)> {
    let (client, reference, mut web) = place(url, name, version, outward)?;
    web.login = login.cloned();
    let tag = at(&web, &reference, &format!("manifests/{version}"));
    let (manifest, _) = capped(&client, &web, &reference, &tag, MANIFEST_TYPE, MANIFEST_LIMIT).await?;
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
    let size = usize::try_from(layer.size).unwrap_or_default();
    let mut blob = vec![0; size];
    if web.outward {
        // (Not by oci-client, which goes wherever a name or a redirect leads.)
        let at = format!(
            "{}://{}/v2/{}/blobs/{}",
            web.scheme,
            reference.resolve_registry(),
            reference.repository(),
            layer.digest
        );
        let token = web.token.lock().expect("nothing panics holding it").clone();
        let what = |e: String| format!("{reference}: the blob: {e}");
        let reply = get(&web, &at, "application/octet-stream", token.as_deref())
            .await
            .map_err(what)?;
        if !reply.status().is_success() {
            return Err(what(reply.status().to_string()));
        }
        blob = read(reply, size).await.map_err(what)?;
    } else {
        let pulled = client.pull_blob(&reference, layer, std::io::Cursor::new(blob.as_mut_slice()));
        patiently(&reference, pulled).await?;
    }
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

/// The most pages of tags, and the most tags, a registry gets to send of one package.
const MAX_PAGES: usize = 50;
const MAX_TAGS: usize = 50_000;

/// The versions of `name` in the repository `url`, asking as `login` where the registry
/// wants one: every page of its tag list, as far as the `Link` headers go.
pub async fn versions(url: &str, name: &str, login: Option<&Login>) -> Fallible<Vec<String>> {
    let (client, reference, mut web) = place(url, name, "latest", false)?;
    web.login = login.cloned();
    let mut page = at(&web, &reference, "tags/list?n=1000");
    let mut tags: Vec<String> = Vec::new();
    for _ in 0..MAX_PAGES {
        let (listed, next) = capped(&client, &web, &reference, &page, "application/json", MANIFEST_LIMIT).await?;
        let listed: Value = serde_json::from_slice(&listed).map_err(|e| format!("{reference}: {e}"))?;
        let more: Option<Vec<String>> =
            serde_json::from_value(listed["tags"].clone()).map_err(|e| format!("{reference}: tags: {e}"))?;
        tags.extend(more.unwrap_or_default());
        if tags.len() > MAX_TAGS {
            return Err(format!("{reference}: more than {MAX_TAGS} tags"));
        }
        match next {
            Some(next) => page = next,
            None => return Ok(tags),
        }
    }
    Err(format!("{reference}: more than {MAX_PAGES} pages of tags"))
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
        // (Whose right fell short is in the Release's status: `releases::package`.)
        if crate::releases::supplied(store, release).is_err() {
            continue;
        }
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

/// The login the Repository `name` names a Secret for, if it does: read as whoever applied
/// the Repository may read that Secret (never more than that one's rights), so a Repository
/// is no way to a Secret its writer could not `get`. One with nobody written down, or a
/// Secret that is not there or has no `username` and `password`, is an error.
fn credentials(store: &Store, name: &str) -> Fallible<Option<Login>> {
    use crate::access::{Caller, Grants};
    use crate::releases::WRITER;
    use kith_api::kinds::{RegistryCredentials, SecretSpec, Verb};
    let Some(repository) = store.get(&format!("Repository/{name}")) else {
        return Ok(None);
    };
    let Ok(spec) = serde_json::from_value::<RepositorySpec>(repository.spec.clone()) else {
        return Ok(None);
    };
    let Some(RegistryCredentials { namespace, secret }) = spec.credentials else {
        return Ok(None);
    };
    let Some(writer) = repository.metadata.annotations.get(WRITER) else {
        return Err(format!(
            "nobody is written down as having applied Repository/{name} (it was applied before kithd wrote \
             that down), so its credentials are not read: apply it again"
        ));
    };
    let Some(caller) = Caller::named(writer) else {
        return Err(format!(
            "Repository/{name} was applied by {writer}, as whom kithd reads no Secret"
        ));
    };
    crate::releases::same_writer(store, repository, &caller)?;
    if !Grants::of(&caller, store).may(&Verb::Get, "Secret", Some(&namespace), Some(&secret)) {
        return Err(format!(
            "Repository/{name} was applied by {writer}, and {writer} may not get Secret in namespace {namespace}"
        ));
    }
    let Some(found) = store.get(&format!("Secret/{namespace}/{secret}")) else {
        return Err(format!("Secret {secret} in namespace {namespace} is not there"));
    };
    let data = serde_json::from_value::<SecretSpec>(found.spec.clone())
        .map_err(|e| format!("Secret {secret} in namespace {namespace}: {e}"))?
        .data;
    let field = |key: &str| {
        data.get(key)
            .cloned()
            .ok_or_else(|| format!("Secret {secret} in namespace {namespace} has no {key}"))
    };
    Ok(Some((field("username")?, field("password")?)))
}

/// How many versions that do not check out are passed over for an older one that does.
const PASSED_OVER: usize = 5;

/// Ask the registry for `wanted`: the newest version that fits and checks out, as a
/// Package to store (none when the store has it already), and what was passed over on
/// the way to it (a newer version that is not signed as it must be stops no one from
/// installing an older one that is).
async fn fetch(shared: &Shared, wanted: &Wanted) -> Fallible<(Option<Resource>, Vec<String>)> {
    let login = {
        let state = shared.store.lock().expect("nothing panics holding the store");
        credentials(&state.store, &wanted.repository)?
    };
    let mut versions = versions(&wanted.url, &wanted.name, login.as_ref()).await?;
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
        let pulled = pull_as(&wanted.url, &wanted.name, version, false, login.as_ref()).await?;
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
                                let stored = shared.submit_node(Command::Apply { resources, at }).await;
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

    /// Registries are asked only for Releases whose writer may apply Packages (T-0546):
    /// one who may write Releases alone has kithd ask no Repository.
    #[test]
    fn fetch_rights_only_a_writer_that_may_apply_packages_has_a_registry_asked() {
        let release = |name: &str, writer: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: Release\n\
                 metadata: {{ name: {name}, namespace: shop{writer} }}\n\
                 spec: {{ package: {{ name: {name}, repo: hub }} }}\n---\n"
            )
        };
        // (ann has a key, as one who applies through the API has: her print is written with her name.)
        let (ann_key, ann_print) = crate::releases::bobs_key(0);
        let by = |who: &str| {
            let print = if who == "ann" {
                format!(", 'kith.dev/written-key': '{ann_print}'")
            } else {
                String::new()
            };
            format!(", annotations: {{ 'kith.dev/written-by': '{who}'{print} }}")
        };
        let source = format!(
            "apiVersion: kith.dev/v1\nkind: Repository\nmetadata: {{ name: hub }}\nspec: {{ url: 'oci://127.0.0.1:1/kith' }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {{ name: bob }}\nspec: {{}}\n---\n\
             apiVersion: kith.dev/v1\nkind: Role\nmetadata: {{ name: shop }}\n\
             spec: {{ rules: [{{ kinds: [Release, Package], verbs: [apply], namespaces: [shop] }}] }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Role\nmetadata: {{ name: packages }}\n\
             spec: {{ rules: [{{ kinds: [Package], verbs: [apply] }}] }}\n---\n\
             apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{ name: shop }}\nspec: {{ role: shop, subjects: [bob, ann] }}\n---\n\
             apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{ name: packages }}\nspec: {{ role: packages, subjects: [ann] }}\n---\n\
             {}{}{}{}",
            release("bobs", &by("bob")),
            release("anns", &by("ann")),
            release("sockets", &by("local socket")),
            release("nobodys", ""),
        );
        let mut store = Store::default();
        for resource in Resource::from_source(&source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let ann = json!({
            "apiVersion": kith_api::API_VERSION, "kind": "Identity",
            "metadata": { "name": "ann" }, "spec": { "publicKey": ann_key },
        });
        store.apply(serde_json::from_value(ann).unwrap()).unwrap();
        let names: Vec<String> = wanted(&store).into_iter().map(|wanted| wanted.name).collect();
        assert_eq!(names, ["anns", "sockets"]);
    }

    /// What a fake registry says: status, header lines, body.
    type Reply = (u16, Vec<String>, Vec<u8>);
    const BLOB: &[u8] = b"a package";

    /// A registry answering each request (its port, its path, whether it came with the
    /// token `tok`) with `answer`. Says its port and the paths it was asked for.
    async fn fake(answer: impl Fn(u16, &str, bool) -> Reply + Send + Sync + 'static) -> (u16, Arc<Mutex<Vec<String>>>) {
        headed(move |port, path, authorization| answer(port, path, authorization == "Bearer tok")).await
    }

    /// [`fake`], told the request's `Authorization` header as it came (empty: none).
    async fn headed(
        answer: impl Fn(u16, &str, &str) -> Reply + Send + Sync + 'static,
    ) -> (u16, Arc<Mutex<Vec<String>>>) {
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
                    let sent = head.len() - head.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) - 4;
                    let head = String::from_utf8_lossy(&head).to_string();
                    let authorization = head
                        .lines()
                        .find_map(|line| {
                            line.to_lowercase()
                                .starts_with("authorization: ")
                                .then(|| line[15..].to_string())
                        })
                        .unwrap_or_default();
                    let head = head.to_lowercase();
                    // (What is sent with it is read to its end, and thrown away.)
                    let length = head.lines().find_map(|line| line.strip_prefix("content-length: "));
                    let mut left = length
                        .and_then(|n| n.parse::<usize>().ok())
                        .unwrap_or(0)
                        .saturating_sub(sent);
                    while left > 0 {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => left = left.saturating_sub(n),
                        }
                    }
                    let path = head.split(' ').nth(1).unwrap_or_default().to_string();
                    log.lock().unwrap().push(path.clone());
                    let (status, headers, body) = answer(port, &path, &authorization);
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
        let (blob, signature) = pull(&url(port), "pkg", "1.0.0", false).await.unwrap();
        assert_eq!((blob.as_slice(), signature.as_deref()), (BLOB, Some("sig")));
        assert_eq!(versions(&url(port), "pkg", None).await.unwrap(), ["1.0.0", "1.1.0"]);
    }

    /// For a Source that is not the cluster's own: nothing is asked of an address that is
    /// not outside, and the blob is followed hop by hop to where it was moved.
    #[tokio::test]
    async fn pinned_oci_connects_only_where_it_was_vetted() {
        let (port, asked) = fake(registry(manifest(0), vec![])).await;
        let e = pull(&url(port), "pkg", "1.0.0", true).await.unwrap_err();
        assert!(e.contains("its own networks"), "{e}");
        assert!(asked.lock().unwrap().is_empty(), "an inward registry was asked");

        // (From here this thread takes loopback for outside.)
        crate::sources::LOOPBACK_IS_OUTSIDE.set(true);
        let (blob, _) = pull(&url(port), "pkg", "1.0.0", true).await.unwrap();
        assert_eq!(blob.as_slice(), BLOB);
        // The blob moved to another host: asked there, without the token.
        let (elsewhere, reached) = fake(|_, _, authed| (if authed { 400 } else { 200 }, vec![], BLOB.to_vec())).await;
        let inner = registry(manifest(0), vec![]);
        let (port, _) = fake(move |port, path, authed| match path.contains("/blobs/") {
            true => (
                307,
                vec![format!("location: http://localhost:{elsewhere}/moved")],
                vec![],
            ),
            false => inner(port, path, authed),
        })
        .await;
        let (blob, _) = pull(&url(port), "pkg", "1.0.0", true).await.unwrap();
        assert_eq!(blob.as_slice(), BLOB);
        assert_eq!(*reached.lock().unwrap(), ["/moved"]);
    }

    #[tokio::test]
    async fn registry_refuses_an_oversized_manifest() {
        let (port, _) = fake(registry(manifest(2 << 20), vec![])).await;
        let e = pull(&url(port), "pkg", "1.0.0", false).await.unwrap_err();
        assert!(e.contains("more than"), "{e}");
    }

    #[tokio::test]
    async fn registry_refuses_an_oversized_tag_list() {
        let tags = json!({ "name": "kith/pkg", "tags": ["1.0.0".repeat(300_000)] }).to_string();
        let (port, _) = fake(registry(vec![], tags.into_bytes())).await;
        let e = versions(&url(port), "pkg", None).await.unwrap_err();
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
            let e = pull(&url(port), "pkg", "1.0.0", false).await.unwrap_err();
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
        assert!(pull(&url(port), "pkg", "1.0.0", false).await.is_err());
        assert!(versions(&url(port), "pkg", None).await.is_err());
        assert!(reached.lock().unwrap().is_empty(), "the other host was asked");
    }

    /// Whoever is not the node pushes only where a pull may come from: never to this
    /// node or its networks, whatever listens there.
    #[tokio::test]
    async fn push_outward_goes_to_no_address_of_this_node_or_its_networks() {
        for inward in [
            "oci://127.0.0.1:1/x",
            "oci://localhost:1/x",
            "oci://10.0.0.7/x",
            "oci://169.254.169.254/x",
        ] {
            let refused = push(inward, "p", "1.0.0", b"{}".to_vec(), None, true)
                .await
                .unwrap_err();
            assert!(refused.contains("this node or its own networks"), "{inward}: {refused}");
        }
        // The node itself may: that one is tried, and nothing listens there.
        let tried = push("oci://127.0.0.1:1/x", "p", "1.0.0", b"{}".to_vec(), None, false)
            .await
            .unwrap_err();
        assert!(!tried.contains("its own networks"), "{tried}");
    }

    /// A registry says where each blob of a push goes. For whoever is not the node, the
    /// blob goes there only if that is outside too: asked hop by hop, as a pull is.
    #[tokio::test]
    async fn push_outward_is_sent_on_only_to_where_a_pull_may_come_from() {
        crate::sources::LOOPBACK_IS_OUTSIDE.set(true);
        let (port, asked) = fake(|_, path, _| match path.ends_with("/blobs/uploads/") {
            true => (202, vec!["location: /up/1?state=x".to_string()], vec![]),
            false => (201, vec![], vec![]),
        })
        .await;
        let at = push(&url(port), "pkg", "1.0.0", BLOB.to_vec(), Some("sig".into()), true).await;
        assert!(at.unwrap().ends_with("pkg:1.0.0"));
        let asked = asked.lock().unwrap().clone();
        let put = |blob: &[u8]| format!("/up/1?state=x&digest={}", digest(blob).replace(':', "%3a"));
        assert_eq!(asked.len(), 5, "{asked:?}");
        assert!(
            asked[0].ends_with("/pkg/blobs/uploads/") && asked[2] == asked[0],
            "{asked:?}"
        );
        assert_eq!([&asked[1], &asked[3]], [&put(BLOB), &put(b"{}")]);
        assert!(asked[4].ends_with("/pkg/manifests/1.0.0"), "{asked:?}");

        // Sent on to this node's own side: not followed, and nothing arrives there.
        let (elsewhere, reached) = fake(|_, _, _| (201, vec![], vec![])).await;
        let location = format!("location: http://0.0.0.0:{elsewhere}/up");
        let (port, _) = fake(move |_, _, _| (202, vec![location.clone()], vec![])).await;
        let refused = push(&url(port), "pkg", "1.0.0", BLOB.to_vec(), None, true).await;
        let refused = refused.unwrap_err();
        assert!(refused.contains("its own networks"), "{refused}");
        assert!(
            reached.lock().unwrap().is_empty(),
            "this node's own side was sent the blob"
        );
    }

    /// A registry (behind its token) that lists `tags` 1000 at a time, each page with a
    /// `Link` to the next as registries send it.
    fn paged(tags: Vec<String>) -> impl Fn(u16, &str, bool) -> Reply + Send + Sync + 'static {
        move |port, path, authed| {
            if path.starts_with("/token") {
                return (200, vec![], br#"{"token":"tok"}"#.to_vec());
            }
            if !authed {
                let challenge = format!("www-authenticate: Bearer realm=\"http://127.0.0.1:{port}/token\"");
                return (401, vec![challenge], vec![]);
            }
            let last = path.split("last=").nth(1).and_then(|rest| rest.split('&').next());
            let start = last.map_or(0, |last| {
                tags.iter().position(|tag| tag == last).map_or(tags.len(), |at| at + 1)
            });
            let page = &tags[start..(start + 1000).min(tags.len())];
            let link = (start + 1000 < tags.len()).then(|| {
                format!(
                    "link: </v2/kith/pkg/tags/list?last={}&n=1000>; rel=\"next\"",
                    page.last().unwrap()
                )
            });
            let body = json!({ "name": "kith/pkg", "tags": page }).to_string();
            (200, link.into_iter().collect(), body.into_bytes())
        }
    }

    #[tokio::test]
    async fn registry_tags_follow_the_link_header_until_it_ends() {
        let tags: Vec<String> = (0..2500).map(|n| format!("1.0.{n}")).collect();
        let (port, asked) = fake(paged(tags.clone())).await;
        assert_eq!(versions(&url(port), "pkg", None).await.unwrap(), tags);
        let asked = asked.lock().unwrap().clone();
        // (A token once, for the three pages.)
        assert_eq!(
            asked.iter().filter(|path| path.starts_with("/token")).count(),
            1,
            "{asked:?}"
        );
        assert_eq!(
            asked.iter().filter(|path| path.contains("/tags/list")).count(),
            4,
            "{asked:?}"
        );
    }

    #[tokio::test]
    async fn registry_tags_follow_a_link_only_on_the_registrys_own_host() {
        let (elsewhere, reached) = fake(|_, _, _| (200, vec![], br#"{"tags":["9.9.9"]}"#.to_vec())).await;
        for next in [
            format!("http://localhost:{elsewhere}/v2/kith/pkg/tags/list?last=a"),
            format!("http://127.0.0.1:{elsewhere}/v2/kith/pkg/tags/list?last=a"),
            "https://127.0.0.1/v2/kith/pkg/tags/list?last=a".to_string(),
        ] {
            let link = format!("link: <{next}>; rel=\"next\"");
            let (port, _) = fake(move |_, _, _| (200, vec![link.clone()], br#"{"tags":["1.0.0"]}"#.to_vec())).await;
            let e = versions(&url(port), "pkg", None).await.unwrap_err();
            assert!(e.contains("not the registry's own"), "{next}: {e}");
        }
        assert!(reached.lock().unwrap().is_empty(), "the other host was asked");
    }

    #[tokio::test]
    async fn registry_tags_follow_no_more_than_a_page_cap_of_links() {
        let (port, asked) = fake(|_, path, _| {
            let link = format!("link: <{path}>; rel=\"next\"");
            (200, vec![link], br#"{"tags":["1.0.0"]}"#.to_vec())
        })
        .await;
        let e = versions(&url(port), "pkg", None).await.unwrap_err();
        assert!(e.contains("pages"), "{e}");
        assert_eq!(asked.lock().unwrap().len(), MAX_PAGES);
    }

    fn ann() -> Login {
        ("ann".into(), "s3cret".into()) // pragma: allowlist secret
    }

    fn basic(login: &Login) -> String {
        use base64::Engine;
        let both = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", login.0, login.1));
        format!("Basic {both}")
    }

    /// A registry whose token service, or the registry itself (`bare`), wants ann's login as Basic.
    fn guarded(bare: bool) -> impl Fn(u16, &str, &str) -> Reply + Send + Sync + 'static {
        let (manifest, tags) = (manifest(0), br#"{"tags":["1.0.0"]}"#.to_vec());
        move |port, path, authorization| {
            let (token, ours) = (path.starts_with("/token"), authorization == basic(&ann()));
            match (bare, token, ours) {
                (false, true, true) => (200, vec![], br#"{"token":"tok"}"#.to_vec()),
                (false, true, false) => (401, vec![], vec![]),
                (false, false, _) if authorization != "Bearer tok" => {
                    let challenge = format!("www-authenticate: Bearer realm=\"http://127.0.0.1:{port}/token\"");
                    (401, vec![challenge], vec![])
                }
                (true, false, false) => (401, vec!["www-authenticate: Basic realm=\"fake\"".into()], vec![]),
                _ if path.contains("/manifests/") => (200, vec![], manifest.clone()),
                _ if path.contains("/blobs/") => (200, vec![], BLOB.to_vec()),
                _ if path.contains("/tags/list") => (200, vec![], tags.clone()),
                _ => (404, vec![], vec![]),
            }
        }
    }

    #[tokio::test]
    async fn registry_credentials_are_sent_as_basic_to_the_token_realm_or_to_the_registry() {
        for bare in [false, true] {
            let (port, asked) = headed(guarded(bare)).await;
            let login = ann();
            assert_eq!(
                versions(&url(port), "pkg", Some(&login)).await.unwrap(),
                ["1.0.0"],
                "{bare}"
            );
            let (blob, _) = pull_as(&url(port), "pkg", "1.0.0", false, Some(&login)).await.unwrap();
            assert_eq!(blob.as_slice(), BLOB, "{bare}");
            // (Without them: refused, as an anonymous pull always was.)
            assert!(versions(&url(port), "pkg", None).await.is_err(), "{bare}");
            let wrong = ("ann".to_string(), "other".to_string()); // pragma: allowlist secret
            assert!(versions(&url(port), "pkg", Some(&wrong)).await.is_err(), "{bare}");
            assert!(!asked.lock().unwrap().is_empty());
        }
    }

    /// The Secret behind a Repository is read as the Repository's writer may read it.
    #[test]
    fn registry_credentials_a_secret_is_read_only_as_the_repository_writer_may_read_it() {
        let repository = |name: &str, writer: &str, namespace: &str, secret: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: Repository\n\
                 metadata: {{ name: {name}, {writer} }}\n\
                 spec: {{ url: 'oci://127.0.0.1:1/kith', credentials: {{ namespace: {namespace}, secret: {secret} }} }}\n---\n"
            )
        };
        let admin = "annotations: { 'kith.dev/written-by': 'local socket' }";
        let source = format!(
            "apiVersion: kith.dev/v1\nkind: Secret\nmetadata: {{ name: login, namespace: ops }}\n\
             spec: {{ data: {{ username: ann, password: s3cret }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Secret\nmetadata: {{ name: login, namespace: locked }}\n\
             spec: {{ data: {{ username: ann, password: s3cret }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Secret\nmetadata: {{ name: half, namespace: ops }}\n\
             spec: {{ data: {{ username: ann }} }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Role\nmetadata: {{ name: reads }}\n\
             spec: {{ rules: [{{ kinds: [Secret], verbs: [get], namespaces: [ops] }}] }}\n---\n\
             apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: {{ name: reads }}\nspec: {{ role: reads, subjects: [bob] }}\n---\n\
             apiVersion: kith.dev/v1\nkind: Repository\nmetadata: {{ name: plain, {admin} }}\n\
             spec: {{ url: 'oci://127.0.0.1:1/kith' }}\n---\n\
             {}{}{}{}{}{}",
            repository("byadmin", admin, "locked", "login"),
            repository("bybob", &crate::releases::bobs_note(0), "ops", "login"),
            repository("bobsnot", &crate::releases::bobs_note(0), "locked", "login"),
            repository("unwritten", "labels: {}", "ops", "login"),
            repository("halved", admin, "ops", "half"),
            repository("gone", admin, "ops", "nothere"),
        );
        let mut store = Store::default();
        for resource in Resource::from_source(&source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        crate::releases::bob_is(&mut store, 0);
        assert_eq!(credentials(&store, "plain"), Ok(None));
        // (The local socket may read any Secret.)
        assert_eq!(credentials(&store, "byadmin"), Ok(Some(ann())));
        assert_eq!(credentials(&store, "bybob"), Ok(Some(ann())));
        let refused = credentials(&store, "bobsnot").unwrap_err();
        assert!(
            refused.contains("bob may not get Secret in namespace locked"),
            "{refused}"
        );
        // (Not read for a Repository nobody is written down for: it was applied before kithd wrote that down.)
        let refused = credentials(&store, "unwritten").unwrap_err();
        assert!(refused.contains("nobody is written down"), "{refused}");
        let refused = credentials(&store, "halved").unwrap_err();
        assert!(refused.contains("password"), "{refused}");
        let refused = credentials(&store, "gone").unwrap_err();
        assert!(refused.contains("is not there"), "{refused}");
        // (Bob made again under his name, with another key: no longer who applied it.)
        crate::releases::bob_is(&mut store, 1);
        assert!(credentials(&store, "bybob").is_err());
    }
}
