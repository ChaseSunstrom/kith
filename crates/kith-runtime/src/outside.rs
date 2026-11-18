//! How long a pull from a registry outside the node is waited for, and how much of what it sends
//! is read. A registry that accepts a connection and never answers, or sends a byte a second,
//! must not hold a pull for ever; one that streams gigabytes must not fill the node.

use crate::keyless;
use crate::{Context, Result, err};
use oci_client::client::{Certificate, CertificateEncoding, ClientConfig, ClientProtocol, current_platform_resolver};
use oci_client::errors::OciEnvelope;
use oci_client::manifest::{OciImageIndex, OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference, RegistryOperation};
use reqwest::StatusCode;
use reqwest::header::ACCEPT;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::io::AsyncWrite;

/// The waits on a registry outside the node: a connection, each read, and the whole of one
/// metadata fetch (a manifest, its config, the referrers of an image). Tests shorten them.
#[derive(Clone, Copy, Debug)]
pub struct Patience {
    pub connect: Duration,
    pub read: Duration,
    pub metadata: Duration,
}

impl Default for Patience {
    fn default() -> Patience {
        Patience {
            connect: Duration::from_secs(10),
            read: Duration::from_secs(30),
            metadata: Duration::from_secs(60),
        }
    }
}

/// The most a manifest, a config or a referrers index is read as: registries cap theirs at 4 MB.
const METADATA_LIMIT: usize = 4 << 20;
/// What a manifest is asked for as: an image's or an index's, in either format.
const MANIFEST_TYPES: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json";
const INDEX_TYPE: &str = "application/vnd.oci.image.index.v1+json";
/// The most of an error's answer is read to be shown: its envelope is a few hundred bytes.
const ERROR_LIMIT: usize = 64 << 10;

/// What a registry said of a thing asked for: the thing, or that it has no such thing (or refused),
/// with what it said of it.
pub(crate) enum Lookup<T> {
    Found(T),
    Missing(String),
}

/// `fetch`, given at most `wait` (the metadata deadline). One still going then is given up on,
/// its error saying so; otherwise its error is `what: <error>`.
pub(crate) async fn within<T, E: std::fmt::Display>(
    wait: Duration,
    what: String,
    fetch: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    match tokio::time::timeout(wait, fetch).await {
        Ok(fetched) => fetched.ctx(what),
        Err(_) => err(format!("{what}: no answer in {wait:?}")),
    }
}

/// What `reply` says, at most `limit` bytes of it: more is an error naming the limit, and nothing
/// past the chunk that crossed it is read.
pub async fn read_capped(mut reply: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = reply.chunk().await.ctx("reading the registry's answer")? {
        if body.len() + chunk.len() > limit {
            return err(format!("more than {}", human(limit)));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// `bytes` as `4 MiB`, `64 KiB` or `100 bytes`.
fn human(bytes: usize) -> String {
    match bytes {
        b if b >= 1 << 20 && b % (1 << 20) == 0 => format!("{} MiB", b >> 20),
        b if b >= 1 << 10 && b % (1 << 10) == 0 => format!("{} KiB", b >> 10),
        b => format!("{b} bytes"),
    }
}

/// `bytes`' digest, as `sha256:HEX`.
fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", keyless::hex(&keyless::sha256(bytes)))
}

/// The registry an image is pulled from, asked for its metadata by kith's own reads: a manifest,
/// a config and a referrers index are read with a cap (oci-client reads each whole), within the
/// connect and read waits. Blobs stay with oci-client, which checks their digests as they stream
/// and keeps the registry's token.
pub(crate) struct Remote {
    pub(crate) oci: Client,
    http: reqwest::Client,
    plain: bool,
    auth: RegistryAuth,
}

impl Remote {
    /// `plain`: over http, not https (a registry on this machine). `certificate`: the one the
    /// node's own registry is trusted by, and no other root.
    pub(crate) fn new(
        plain: bool,
        certificate: Option<Vec<u8>>,
        auth: RegistryAuth,
        patience: Patience,
    ) -> Result<Remote> {
        let config = ClientConfig {
            protocol: match plain {
                true => ClientProtocol::Http,
                false => ClientProtocol::Https,
            },
            tls_certs_only: certificate
                .iter()
                .map(|data| Certificate {
                    encoding: CertificateEncoding::Der,
                    data: data.clone(),
                })
                .collect(),
            connect_timeout: Some(patience.connect),
            read_timeout: Some(patience.read),
            ..ClientConfig::default()
        };
        // (Not `Client::new`: it falls back to a client with every usual root when it is
        // given a certificate it cannot read.)
        let oci = Client::try_from(config).ctx("setting up the registry client")?;
        let mut http = reqwest::Client::builder()
            .connect_timeout(patience.connect)
            .read_timeout(patience.read);
        if let Some(der) = &certificate {
            let der = reqwest::Certificate::from_der(der).ctx("setting up the registry client")?;
            http = http.tls_certs_only([der]);
        }
        let http = http.build().ctx("setting up the registry client")?;
        Ok(Remote { oci, http, plain, auth })
    }

    /// `path` of `at`'s repository (`manifests/NAME`, `blobs/DIGEST`), as the registry answers it:
    /// at most `limit` bytes of it, or what it said when it has no such thing (a 404) or refused
    /// (its error envelope, when it sent one). A token is fetched as oci-client fetches one, and
    /// sent as it is asked for; a password is sent with each request.
    async fn get(
        &self,
        at: &Reference,
        path: &str,
        query: &[(&str, &str)],
        accept: &str,
        limit: usize,
    ) -> Result<Lookup<Vec<u8>>> {
        let registry = at.resolve_registry();
        let token = self
            .oci
            .auth(at, &self.auth, RegistryOperation::Pull)
            .await
            .ctx(format!("asking {registry} for a token"))?;
        let scheme = match self.plain {
            true => "http",
            false => "https",
        };
        let url = format!("{scheme}://{registry}/v2/{}/{path}", at.repository());
        let request = self.http.get(&url).query(query).header(ACCEPT, accept);
        let request = match (token, &self.auth) {
            (Some(token), _) => request.bearer_auth(token),
            (None, RegistryAuth::Basic(user, password)) => request.basic_auth(user, Some(password)),
            (None, _) => request,
        };
        let reply = request.send().await.ctx(format!("asking {url}"))?;
        let status = reply.status();
        if status.is_success() {
            return read_capped(reply, limit).await.map(Lookup::Found);
        }
        let body = read_capped(reply, ERROR_LIMIT).await.unwrap_or_default();
        let said = match serde_json::from_slice::<OciEnvelope>(&body) {
            Ok(envelope) => format!("{url}: {status}: {envelope}"),
            Err(_) => format!("{url}: {status}"),
        };
        match status {
            StatusCode::NOT_FOUND => Ok(Lookup::Missing(said)),
            _ => err(said),
        }
    }

    /// The manifest `at` names (by digest, or else by tag: `latest` when neither) and its digest.
    /// A digest that is named must be the manifest's.
    pub(crate) async fn manifest(&self, at: &Reference) -> Result<Lookup<(OciManifest, String)>> {
        let name = at.digest().or(at.tag()).unwrap_or("latest");
        let body = match self
            .get(at, &format!("manifests/{name}"), &[], MANIFEST_TYPES, METADATA_LIMIT)
            .await?
        {
            Lookup::Found(body) => body,
            Lookup::Missing(said) => return Ok(Lookup::Missing(said)),
        };
        let digest = digest_of(&body);
        if name.starts_with("sha256:") && name != digest {
            return err(format!("the manifest of {at} is {digest}, not {name}"));
        }
        let manifest: OciManifest = serde_json::from_slice(&body).ctx(format!("reading the manifest of {at}"))?;
        Ok(Lookup::Found((manifest, digest)))
    }

    /// What `pull_signed` needs of the image `at`: its manifest and that manifest's digest, its
    /// config (as JSON text), and, when `at` is an index, the index's digest (the manifest is
    /// the entry picked for this platform).
    pub(crate) async fn image(&self, at: &Reference) -> Result<(OciImageManifest, String, String, Option<String>)> {
        let (top, top_digest) = match self.manifest(at).await? {
            Lookup::Found(found) => found,
            Lookup::Missing(said) => return err(said),
        };
        let (manifest, digest, list) = match top {
            OciManifest::Image(manifest) => (manifest, top_digest, None),
            OciManifest::ImageIndex(index) => {
                let Some(platform) = current_platform_resolver(&index.manifests) else {
                    return err(format!("no entry of {at} is for this platform"));
                };
                match self.manifest(&at.clone_with_digest(platform)).await? {
                    Lookup::Found((OciManifest::Image(manifest), digest)) => (manifest, digest, Some(top_digest)),
                    Lookup::Found(_) => return err(format!("the entry of {at} for this platform is not an image")),
                    Lookup::Missing(said) => return err(said),
                }
            }
        };
        let config = &manifest.config.digest;
        let body = match self
            .get(
                at,
                &format!("blobs/{config}"),
                &[],
                "application/octet-stream",
                METADATA_LIMIT,
            )
            .await?
        {
            Lookup::Found(body) => body,
            Lookup::Missing(said) => return err(said),
        };
        if digest_of(&body) != *config {
            return err(format!("the config of {at} is not {config}"));
        }
        let config = String::from_utf8(body).ctx(format!("the config of {at} is not UTF-8"))?;
        Ok((manifest, digest, config, list))
    }

    /// The referrers of `digest` in `at`'s repository of `artifact_type`, as the registry's index
    /// of them. A registry that has none (a 404) is `Missing`; one that cannot say is an error.
    pub(crate) async fn referrers(
        &self,
        at: &Reference,
        digest: &str,
        artifact_type: &str,
    ) -> Result<Lookup<OciImageIndex>> {
        match self
            .get(
                at,
                &format!("referrers/{digest}"),
                &[("artifactType", artifact_type)],
                INDEX_TYPE,
                METADATA_LIMIT,
            )
            .await?
        {
            Lookup::Found(body) => serde_json::from_slice::<OciImageIndex>(&body)
                .map(Lookup::Found)
                .ctx(format!("reading the referrers of {digest}")),
            Lookup::Missing(said) => Ok(Lookup::Missing(said)),
        }
    }
}

/// The most of a blob's bytes are taken as its layer's size says, and no more: one byte past that
/// is an error naming the size, and nothing past it is written. (oci-client checks a blob's
/// digest as it streams, not its size, so a registry could send on for ever.)
pub(crate) struct Capped<W> {
    inner: W,
    left: u64,
    size: u64,
}

impl<W> Capped<W> {
    pub(crate) fn new(inner: W, size: i64) -> Capped<W> {
        let size = u64::try_from(size).unwrap_or(0);
        Capped {
            inner,
            left: size,
            size,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Capped<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.len() as u64 > this.left {
            let size = this.size;
            return Poll::Ready(Err(io::Error::other(format!(
                "more than the {size} bytes its descriptor gives"
            ))));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.left -= n as u64;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
