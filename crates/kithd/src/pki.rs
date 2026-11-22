//! Cluster identity (PLAN.md §4.13): a CA made by the first node, one
//! certificate per node, and the join tokens that get a new node its own.
//!
//! Every node certificate names `<node>.node.kith` and `kith`. Nodes reach each
//! other by address, so a client checks that the server's certificate is from the
//! cluster CA and valid for `kith`: any member, not one member in particular.
//
// ponytail: the node that holds the CA key also makes each joiner's key pair, and sends
// it back over the pinned TLS channel. A signing request would keep the key on the
// joiner, but reading one needs an X.509 parser nothing else uses; the CA node can mint
// any certificate anyway. Certificates last ten years, and a node asks for a new one for its
// own key at under a third of that (`renew`); the ten years are not shortened. (A Workload's
// pod's lasts two hours, for a key its node made: `workload_identity`.) The dates of a
// certificate are read by hand (`validity`): the one parser that would do it is a dev
// dependency of rcgen's, and the walk to them is a few lines.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use ring::rand::SecureRandom;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme,
};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The name every node certificate is valid for.
const ANY_NODE: &str = "kith";
/// What a node's own name is filed under in its certificate.
const NODE_SUFFIX: &str = ".node.kith";
/// And an Identity's. A name is one label, so neither can be made to look like the other.
const USER_SUFFIX: &str = ".user.kith";
/// In the certificate a node is given as it joins: `INDEX.born.kith`, an index of the store
/// by which its Node was there. A store that is past it and has no such Node had it deleted.
const BORN_SUFFIX: &str = ".born.kith";
/// A Workload's certificate names the Identity it runs as (`<identity>.runs.kith`), the
/// Workload (`<name>.<namespace>.workload.kith`) and the node it was made for
/// (`<node>.on.kith`): no node's and no Identity's own, so a kithd that knows none reads
/// no subject in it.
const RUNS_SUFFIX: &str = ".runs.kith";
const WORKLOAD_SUFFIX: &str = ".workload.kith";
const ON_SUFFIX: &str = ".on.kith";
/// How long a Workload's certificate lasts: it is made again at half.
pub const WORKLOAD_LIFE: Duration = Duration::from_secs(2 * 3600);
/// How long a node's certificate lasts when it is made, or made again: ten years. (One made
/// before dates are written by `issue` reads as ten years too, whatever its `notBefore`.)
pub const NODE_LIFE: Duration = Duration::from_secs(10 * 365 * 24 * 3600);
/// A P-256 public key's SubjectPublicKeyInfo (DER) up to its point, as `KeyPair::generate`
/// makes them: the one kind of key a node may send for a Workload's certificate.
pub(crate) const P256_SPKI: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The point of a P-256 key a node made: rcgen signs for it without its private half.
struct NodeKey<'a>(&'a [u8]);

impl rcgen::PublicKeyData for NodeKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
/// The point of the P-256 key `public` (SubjectPublicKeyInfo, DER), as `KeyPair::generate` makes them.
fn p256_point(public: &[u8]) -> Fallible<&[u8]> {
    let point = public
        .strip_prefix(&P256_SPKI)
        .filter(|point| point.len() == 65 && point[0] == 4);
    point.ok_or("the key is not a P-256 public key".into())
}

const TOKEN_LIFE: Duration = Duration::from_secs(3600);

type Fallible<T> = Result<T, String>;

fn tls<T>(what: &str, result: Result<T, impl std::fmt::Display>) -> Fallible<T> {
    result.map_err(|e| format!("{what}: {e}"))
}

/// A node name is one DNS label: it becomes `<name>.node.kith` (and that of an Identity
/// with a certificate `<name>.user.kith`).
pub fn valid_name(name: &str) -> Fallible<()> {
    let ok = (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    ok.then_some(()).ok_or(format!(
        "`{name}` cannot be named in a certificate: use 1 to 63 of a-z, 0-9 and `-`, not starting or ending with `-`"
    ))
}

/// What a node is: its name, its certificate and key, and the CA it trusts. All PEM.
#[derive(Clone)]
pub struct Identity {
    pub name: String,
    pub ca: String,
    pub cert: String,
    pub key: String,
}

/// The year `years` from now, for a certificate's last day.
fn year_in(years: i32) -> i32 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    1970 + (now / 31_556_952) as i32 + years
}

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "kith cluster CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    params.not_after = rcgen::date_time_ymd(year_in(20), 1, 1);
    params
}

/// The longest a host certificate may last.
const HOST_LIFE_MAX: Duration = Duration::from_secs(90 * 86_400);

/// `host` is a name the cluster CA will sign a server certificate for: two or more labels of
/// lowercase letters, digits and `-` (so no wildcard, `_` or space), the last not all digits (an
/// address), and not `kith` or under it (a node's or an Identity's name must not be had by a host).
fn host_name(host: &str) -> Fallible<()> {
    let label = |l: &str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let last = host.rsplit('.').next().unwrap_or_default();
    let fine = host.len() <= 253
        && host.contains('.')
        && host.split('.').all(label)
        && !last.bytes().all(|b| b.is_ascii_digit())
        && last != "kith";
    match fine {
        true => Ok(()),
        false => Err(format!(
            "`{host}` is not a name for a host certificate: lowercase labels of a-z, 0-9 and `-`, two or more, not an address, not under `kith`"
        )
        .into()),
    }
}

/// The cluster's certificate authority: only a node that holds its key can admit nodes.
pub struct Ca {
    key: KeyPair,
    pub cert: String,
}

impl Ca {
    pub fn create() -> Fallible<Ca> {
        let key = tls("making the CA key", KeyPair::generate())?;
        let cert = tls("making the CA certificate", ca_params().self_signed(&key))?.pem();
        Ok(Ca { key, cert })
    }

    /// A key pair and certificate for the node `name`, as (certificate, key).
    pub fn issue(&self, name: &str) -> Fallible<(String, String)> {
        self.issue_node(name, None)
    }

    /// The same, for a node whose Node was in the store by its index `born`.
    pub fn issue_born(&self, name: &str, born: u64) -> Fallible<(String, String)> {
        self.issue_node(name, Some(born))
    }

    fn issue_node(&self, name: &str, born: Option<u64>) -> Fallible<(String, String)> {
        let mut names = vec![format!("{name}{NODE_SUFFIX}"), ANY_NODE.into()];
        names.extend(born.map(|born| format!("{born}{BORN_SUFFIX}")));
        let both = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let (cert, key) = self.sign(name, names, both)?;
        Ok((cert, key.serialize_pem()))
    }

    /// A key pair and certificate for the Identity `name`: good for calling the API, not
    /// for being a node. As (certificate, key, public key), the last to go in the Identity.
    pub fn issue_user(&self, name: &str) -> Fallible<(String, String, String)> {
        let names = vec![format!("{name}{USER_SUFFIX}")];
        let (cert, key) = self.sign(name, names, vec![ExtendedKeyUsagePurpose::ClientAuth])?;
        Ok((cert, key.serialize_pem(), key.public_key_pem()))
    }

    /// The certificate of the Workload `namespace/name` on the node `node`, running as the
    /// Identity `identity`, for the P-256 key `public` (SubjectPublicKeyInfo, DER) the node
    /// made: good for calling the API for [`WORKLOAD_LIFE`] from `now` (seconds since 1970).
    pub fn issue_workload(
        &self,
        identity: &str,
        (namespace, name): (&str, &str),
        node: &str,
        public: &[u8],
        now: u64,
    ) -> Fallible<String> {
        let point = p256_point(public)?;
        for part in [namespace, name, node] {
            valid_name(part)?;
        }
        let names = vec![
            format!("{identity}{RUNS_SUFFIX}"),
            format!("{name}.{namespace}{WORKLOAD_SUFFIX}"),
            format!("{node}{ON_SUFFIX}"),
        ];
        let mut params = self.params(identity, names, vec![ExtendedKeyUsagePurpose::ClientAuth])?;
        // A minute before, for a clock behind the CA holder's.
        params.not_before = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(now.saturating_sub(60));
        params.not_after = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(now) + WORKLOAD_LIFE;
        let issuer = Issuer::new(ca_params(), &self.key);
        Ok(tls("signing the certificate", params.signed_by(&NodeKey(point), &issuer))?.pem())
    }

    /// A server certificate for the LAN name `host` (no wildcard, no address, nothing under
    /// `kith`: those names are the cluster's own) and a new key, as (certificate, key): good from a
    /// minute before `now` (seconds since 1970) for `life`, and for serving TLS only. It names no
    /// node, Identity or Workload. A short life is the only revocation there is.
    pub fn issue_host(&self, host: &str, now: u64, life: Duration) -> Fallible<(String, String)> {
        host_name(host)?;
        if life.is_zero() || life > HOST_LIFE_MAX {
            return Err("a host certificate lasts more than 0 and at most 90 days".into());
        }
        let mut params = tls("naming the certificate", CertificateParams::new(vec![host.to_string()]))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        // A minute before, for a clock behind the CA holder's.
        params.not_before = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(now.saturating_sub(60));
        params.not_after = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(now) + life;
        let key = tls("making the key", KeyPair::generate())?;
        let issuer = Issuer::new(ca_params(), &self.key);
        let cert = tls("signing the certificate", params.signed_by(&key, &issuer))?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// The certificate of the node `name` (born by the index `born`, if its certificate says) made
    /// again for the same key `public` (SubjectPublicKeyInfo, DER, P-256): so what the store
    /// keeps of the key, and every token and pin made of it, still holds. Good from a minute
    /// before `now` (seconds since 1970) for `life`.
    pub fn renew_node(
        &self,
        name: &str,
        born: Option<u64>,
        public: &[u8],
        now: u64,
        life: Duration,
    ) -> Fallible<String> {
        let point = p256_point(public)?;
        let mut names = vec![format!("{name}{NODE_SUFFIX}"), ANY_NODE.into()];
        names.extend(born.map(|born| format!("{born}{BORN_SUFFIX}")));
        let both = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let mut params = self.params(name, names, both)?;
        params.not_before = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(now.saturating_sub(60));
        params.not_after = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(now) + life;
        let issuer = Issuer::new(ca_params(), &self.key);
        Ok(tls("signing the certificate", params.signed_by(&NodeKey(point), &issuer))?.pem())
    }

    fn params(
        &self,
        name: &str,
        names: Vec<String>,
        usages: Vec<ExtendedKeyUsagePurpose>,
    ) -> Fallible<CertificateParams> {
        valid_name(name)?;
        let mut params = tls("naming the certificate", CertificateParams::new(names))?;
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = usages;
        params.use_authority_key_identifier_extension = true;
        params.not_after = rcgen::date_time_ymd(year_in(10), 1, 1);
        Ok(params)
    }

    fn sign(
        &self,
        name: &str,
        names: Vec<String>,
        usages: Vec<ExtendedKeyUsagePurpose>,
    ) -> Fallible<(String, KeyPair)> {
        let params = self.params(name, names, usages)?;
        let key = tls("making the key", KeyPair::generate())?;
        // The issuer is rebuilt from the same parameters the CA certificate was made with.
        let issuer = Issuer::new(ca_params(), &self.key);
        let cert = tls("signing the certificate", params.signed_by(&key, &issuer))?;
        Ok((cert.pem(), key))
    }
}

fn write_private(path: &Path, text: &str) -> Fallible<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    let file = options.write(true).create(true).truncate(true).mode(0o600).open(path);
    tls(
        &format!("writing {}", path.display()),
        // (On the disk before the next file: a machine that loses power a moment after
        // its first start must not come back with a certificate and half a key.)
        file.and_then(|mut file| file.write_all(text.as_bytes()).and_then(|()| file.sync_all())),
    )
}

/// `bytes` into `path` whole or not at all: a temp file beside it, synced, renamed over it, and
/// the directory synced after. A power cut leaves the old file or the new one, never a torn
/// one, and a read of a torn or empty file (from before) is the caller's to call none.
pub fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let new = path.with_extension("new");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&new)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&new, path)?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    std::fs::File::open(dir)?.sync_all()
}

/// Load what `save` wrote into `dir`: the identity, and the CA if this node holds its key.
pub fn load(dir: &Path) -> Fallible<Option<(Identity, Option<Ca>)>> {
    if !dir.join("node.crt").exists() {
        return Ok(None);
    }
    let read = |file: &str| {
        let path = dir.join(file);
        tls(&format!("reading {}", path.display()), std::fs::read_to_string(&path))
    };
    let identity = Identity {
        name: read("name")?.trim().to_string(),
        ca: read("ca.crt")?,
        cert: read("node.crt")?,
        key: read("node.key")?,
    };
    let ca = match dir.join("ca.key").exists() {
        true => Some(Ca {
            key: tls("reading the CA key", KeyPair::from_pem(&read("ca.key")?))?,
            cert: identity.ca.clone(),
        }),
        false => None,
    };
    Ok(Some((identity, ca)))
}

pub fn save(dir: &Path, identity: &Identity, ca: Option<&Ca>) -> Fallible<()> {
    let made = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir);
    tls(&format!("creating {}", dir.display()), made)?;
    if let Some(ca) = ca {
        write_private(&dir.join("ca.key"), &ca.key.serialize_pem())?;
    }
    write_private(&dir.join("node.key"), &identity.key)?;
    write_private(&dir.join("ca.crt"), &identity.ca)?;
    write_private(&dir.join("name"), &identity.name)?;
    // Last: `load` takes its presence to mean the rest is there.
    write_private(&dir.join("node.crt"), &identity.cert)?;
    tls(
        &format!("writing {}", dir.display()),
        std::fs::File::open(dir).and_then(|dir| dir.sync_all()),
    )
}

fn certs(pem: &str) -> Fallible<Vec<CertificateDer<'static>>> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem.as_bytes()).collect();
    let certs = tls("reading a certificate", certs)?;
    (!certs.is_empty())
        .then_some(certs)
        .ok_or("no certificate in the PEM text".into())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The cluster CA is one certificate. Text with more is refused: a second one would be
/// trusted without being what the join token pinned.
fn ca_cert(ca: &str) -> Fallible<CertificateDer<'static>> {
    let mut certs = certs(ca)?;
    match certs.len() {
        1 => Ok(certs.remove(0)),
        more => Err(format!("a cluster CA is one certificate, not {more}")),
    }
}

/// SHA-256 of the CA certificate: what a join token pins.
pub fn fingerprint(ca: &str) -> Fallible<String> {
    Ok(hex(ring::digest::digest(&ring::digest::SHA256, &ca_cert(ca)?).as_ref()))
}

fn roots(ca: &str) -> Fallible<Arc<RootCertStore>> {
    let mut roots = RootCertStore::empty();
    tls("trusting the cluster CA", roots.add(ca_cert(ca)?))?;
    Ok(Arc::new(roots))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// TLS for the node API: a client may come without a certificate (to join), and one it
/// does present must be from the cluster CA. (Tests: kithd serves [`served`] with its [`Live`].)
#[cfg_attr(not(test), allow(dead_code))]
pub fn server_config(identity: &Identity) -> Fallible<Arc<ServerConfig>> {
    served(&identity.ca, Live::new(identity)?, None)
}

/// Says whether the certificate of a client has been revoked: asked of each one that is
/// verified, in the handshake, so a revoked one is refused before a request is sent.
pub type Revoked = Arc<dyn Fn(&CertificateDer<'_>) -> bool + Send + Sync>;

/// [`server_config`] showing `live` (so a certificate made again is shown at the next handshake),
/// and refusing in the handshake a client certificate `revoked` says is.
pub fn served(ca: &str, live: Arc<Live>, revoked: Option<Revoked>) -> Fallible<Arc<ServerConfig>> {
    let verifier = WebPkiClientVerifier::builder_with_provider(roots(ca)?, provider())
        .allow_unauthenticated()
        .build();
    let verifier = Refusing(tls("setting up TLS", verifier)?, revoked);
    let mut config = tls(
        "setting up TLS",
        ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
    )?
    .with_client_cert_verifier(Arc::new(verifier))
    .with_cert_resolver(live);
    // No sessions to resume (and so no tickets sent): a resumed connection takes the client's
    // certificate from its session and does not verify it again, so a certificate revoked after
    // its first handshake would go on getting in. (The server's default is a cache of 256.)
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

/// The CA's own check of a client certificate, and then the node's: nothing the CA signed is
/// let in once `Revoked` says it is not good.
struct Refusing(Arc<dyn ClientCertVerifier>, Option<Revoked>);

impl std::fmt::Debug for Refusing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Refusing").field("revoked", &self.1.is_some()).finish()
    }
}

impl ClientCertVerifier for Refusing {
    fn offer_client_auth(&self) -> bool {
        self.0.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.0.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self.0.verify_client_cert(end_entity, intermediates, now)?;
        match &self.1 {
            Some(revoked) if revoked(end_entity) => Err(rustls::Error::InvalidCertificate(CertificateError::Revoked)),
            _ => Ok(verified),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// The certificate a node shows, as a server and as a client, and the key it signs with.
/// Both configurations hold the one of these, so a certificate made again is shown at the
/// next handshake, with no restart: connections already open keep the one they began with.
#[derive(Debug)]
pub struct Live {
    key: Arc<dyn SigningKey>,
    shown: RwLock<Arc<CertifiedKey>>,
}

/// The chain `pem` with `key`, if the key is the one the leaf is for.
fn pair(key: &Arc<dyn SigningKey>, pem: &str) -> Fallible<Arc<CertifiedKey>> {
    let certified = CertifiedKey::new(certs(pem)?, key.clone());
    tls("a certificate and its key", certified.keys_match())?;
    Ok(Arc::new(certified))
}

impl Live {
    pub fn new(me: &Identity) -> Fallible<Arc<Live>> {
        let key = tls("reading the node key", PrivateKeyDer::from_pem_slice(me.key.as_bytes()))?;
        let key = tls("reading the node key", provider().key_provider.load_private_key(key))?;
        let shown = RwLock::new(pair(&key, &me.cert)?);
        Ok(Arc::new(Live { key, shown }))
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        self.shown
            .read()
            .expect("nothing panics holding the certificate")
            .clone()
    }

    /// Show the certificate `pem` from now on. Only one for the key held is taken.
    pub fn swap(&self, pem: &str) -> Fallible<()> {
        self.show(self.parse(pem)?);
        Ok(())
    }

    /// The certificate `pem`, if it is for the key held: to be kept on disk before it is shown.
    pub fn parse(&self, pem: &str) -> Fallible<Arc<CertifiedKey>> {
        pair(&self.key, pem)
    }

    pub fn show(&self, new: Arc<CertifiedKey>) {
        *self.shown.write().expect("nothing panics holding the certificate") = new;
    }
}

impl ResolvesServerCert for Live {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

impl ResolvesClientCert for Live {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The `notBefore` and `notAfter` of a certificate (DER), in seconds since 1970. Read by
/// walking the DER to them (certificate, TBS, version, serial, algorithm, issuer, validity),
/// as no parser here gives them; none if it does not read as one.
pub fn validity(cert: &[u8]) -> Option<(u64, u64)> {
    /// One DER element: its tag, its content and what follows it.
    fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, der) = der.split_first()?;
        let (&first, der) = der.split_first()?;
        let (len, der) = match first {
            0..=0x7f => (first as usize, der),
            0x81..=0x84 => {
                let width = (first & 0x7f) as usize;
                let (len, der) = der.split_at_checked(width)?;
                (len.iter().fold(0, |len, byte| len << 8 | *byte as usize), der)
            }
            _ => return None,
        };
        let (content, rest) = der.split_at_checked(len)?;
        Some((tag, content, rest))
    }
    /// A UTCTime (`YYMMDDHHMMSSZ`, 1950 to 2049) or a GeneralizedTime (`YYYYMMDDHHMMSSZ`).
    fn time(der: &[u8]) -> Option<(u64, &[u8])> {
        let (tag, text, rest) = element(der)?;
        let digits = match (tag, text) {
            (0x17, [digits @ .., b'Z']) if digits.len() == 12 => digits,
            (0x18, [digits @ .., b'Z']) if digits.len() == 14 => digits,
            _ => return None,
        };
        let number = |at: usize, width: usize| -> Option<i64> {
            digits[at..at + width]
                .iter()
                .try_fold(0i64, |n, b| b.is_ascii_digit().then(|| n * 10 + (b - b'0') as i64))
        };
        let (year, at) = match tag {
            0x17 => (number(0, 2)?, 2),
            _ => (number(0, 4)?, 4),
        };
        let year = if tag == 0x17 {
            year + if year >= 50 { 1900 } else { 2000 }
        } else {
            year
        };
        let (month, day) = (number(at, 2)?, number(at + 2, 2)?);
        let (hour, minute, second) = (number(at + 4, 2)?, number(at + 6, 2)?, number(at + 8, 2)?);
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        // Days from 1970 by the civil calendar (March first, so February's end is the year's).
        let y = if month <= 2 { year - 1 } else { year };
        let era = y.div_euclid(400);
        let year_of_era = y - era * 400;
        let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
        Some((u64::try_from(seconds).ok()?, rest))
    }
    let (_, certificate, _) = element(cert)?;
    let (_, tbs, _) = element(certificate)?;
    // (A version is [0] and left out in v1; then serial, signature algorithm and issuer.)
    let mut rest = tbs;
    if let (0xa0, _, after) = element(rest)? {
        rest = after;
    }
    for _ in 0..3 {
        rest = element(rest)?.2;
    }
    let (_, dates, _) = element(rest)?;
    let (from, rest) = time(dates)?;
    let (to, _) = time(rest)?;
    Some((from, to))
}

/// Whether a certificate good from `from` to `to` (seconds since 1970) is to be made again at
/// `now`: it has under a third of its life left, or none. Its life is at most [`NODE_LIFE`]:
/// a certificate made before its dates were written down began in 1975 and ends on the first
/// of January ten years on, and counts as ten years, not as fifty.
pub fn renewal_due(from: u64, to: u64, now: u64) -> bool {
    let life = to.saturating_sub(from).min(NODE_LIFE.as_secs());
    to.saturating_sub(now) * 3 < life
}

/// TLS for the node's own registry, for this start only: a certificate for `localhost`
/// that nobody signed and no file holds (DER, for the one client that is to trust it),
/// and the server that shows it.
pub fn local_config() -> Fallible<(Vec<u8>, Arc<ServerConfig>)> {
    let key = tls("making the registry's key", KeyPair::generate())?;
    let names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let params = tls("making the registry's certificate", CertificateParams::new(names))?;
    let cert = tls("making the registry's certificate", params.self_signed(&key))?;
    let der = cert.der().clone();
    let config = tls(
        "setting up TLS",
        ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
    )?
    .with_no_client_auth()
    .with_single_cert(vec![der.clone()], PrivateKeyDer::Pkcs8(key.serialize_der().into()));
    Ok((der.to_vec(), Arc::new(tls("setting up TLS", config)?)))
}

/// A certificate chain and its key (both PEM) as a server shows them for `host`. Not if the
/// key is another certificate's, or the leaf does not name `host`.
pub fn certified(chain: &str, key: &str, host: &str) -> Fallible<rustls::sign::CertifiedKey> {
    let key = tls("reading a key", PrivateKeyDer::from_pem_slice(key.as_bytes()))?;
    let key = tls("reading a key", provider().key_provider.load_private_key(key))?;
    let chain = certs(chain)?;
    {
        let leaf = tls("reading a certificate", webpki::EndEntityCert::try_from(&chain[0]))?;
        let name = tls(&format!("a certificate for {host}"), ServerName::try_from(host))?;
        tls(
            &format!("a certificate for {host}"),
            leaf.verify_is_valid_for_subject_name(&name),
        )?;
    }
    let certified = rustls::sign::CertifiedKey::new(chain, key);
    tls("a certificate and its key", certified.keys_match())?;
    Ok(certified)
}

/// TLS for clients from anywhere: which certificate they get is up to `certificates`
/// (by the name they ask for). HTTP/1.1 is all that is offered: what is behind is not
/// asked what else it speaks.
pub fn ingress_config(certificates: Arc<dyn rustls::server::ResolvesServerCert>) -> Fallible<Arc<ServerConfig>> {
    let config = tls(
        "setting up TLS",
        ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
    )?;
    let mut config = config.with_no_client_auth().with_cert_resolver(certificates);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Checks a server like any other, but for the name every node has rather than the address dialled.
/// With a pin, it has to be that node besides: its name, and the key its Node names if it names one.
#[derive(Debug)]
struct AnyNode(Arc<WebPkiServerVerifier>, Option<Held>);

/// A node a join names (a worker's first): its name, and the print of its key ([`key_print`]).
pub type Pin = (String, Option<String>);

/// The one node a client will talk to: who it is, and the print of its key.
pub type Held = (Who, Option<String>);

/// A node by its name, or by its id in Raft (which its name gives, `kith_store::node_id`).
#[derive(Clone, Debug, PartialEq)]
pub enum Who {
    Name(String),
    /// For a voter that has no Node in the store, which is all a Raft link has then. Weaker than
    /// a name: the id is a 64-bit hash, so any name of the CA's that hashes to it is taken for the
    /// voter. (Only a Node's name and key pin a voter that has a Node; `join` refuses a name
    /// whose id a Node already has.)
    Id(kith_store::NodeId),
}

impl Who {
    fn is(&self, name: &str) -> bool {
        match self {
            Who::Name(called) => called == name,
            Who::Id(id) => kith_store::node_id(name) == *id,
        }
    }
}

impl std::fmt::Display for Who {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Who::Name(name) => write!(f, "node {name}"),
            Who::Id(id) => write!(f, "the voter with raft id {id}"),
        }
    }
}

/// Is the certificate `cert` the node's that `pin` names?
fn pinned(cert: &CertificateDer<'_>, pin: &Held) -> bool {
    let Some(Subject::Node(name, key, _)) = subject_of(cert) else {
        return false;
    };
    pin.0.is(&name) && pin.1.as_ref().is_none_or(|print| *print == key_print(&key))
}

/// Why a certificate is not the pinned node's: names the node that was called and who answered.
fn unpinned(cert: &CertificateDer<'_>, pin: &Held) -> String {
    let called = &pin.0;
    match subject_of(cert) {
        Some(Subject::Node(name, ..)) if called.is(&name) => {
            format!("{called} answered with another key than its Node names")
        }
        Some(Subject::Node(name, ..)) => format!("{called} was called, and node {name} answered"),
        _ => format!("{called} was called, and what answered is no node of the cluster"),
    }
}

impl ServerCertVerifier for AnyNode {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _dialled: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let name = ServerName::try_from(ANY_NODE).expect("a DNS name");
        let verified = self.0.verify_server_cert(end_entity, intermediates, &name, ocsp, now)?;
        match &self.1 {
            Some(pin) if !pinned(end_entity, pin) => Err(rustls::Error::General(unpinned(end_entity, pin))),
            _ => Ok(verified),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// TLS for calling a node: its certificate must be from `ca`. With `me`, ours is presented (the
/// one it holds at each handshake). With `pin`, only the node it names is called, whoever
/// answers at the address.
pub fn client_config(ca: &str, me: Option<Arc<Live>>, pin: Option<Held>) -> Fallible<ClientConfig> {
    let verifier = WebPkiServerVerifier::builder_with_provider(roots(ca)?, provider()).build();
    let builder = tls(
        "setting up TLS",
        ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
    )?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AnyNode(tls("setting up TLS", verifier)?, pin)));
    Ok(match me {
        None => builder.with_no_client_auth(),
        Some(live) => builder.with_client_cert_resolver(live),
    })
}

/// TLS for asking the node that made a join token (`maker`: its name and key print) for the
/// CA, which the joiner does not have yet: only that node is taken (the handshake shows it
/// holds that key). Nothing else of its certificate is checked here: the CA it hands over is
/// checked against the token, and the join itself goes through [`client_config`] with both.
/// With no maker (a token from before tokens named one), whoever answers is taken.
pub fn maker_config(maker: Option<(&str, &str)>) -> Fallible<ClientConfig> {
    let held = maker.map(|(name, print)| (Who::Name(name.into()), Some(print.into())));
    let maker = Maker(held, provider());
    let builder = tls(
        "setting up TLS",
        ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
    )?;
    Ok(builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(maker))
        .with_no_client_auth())
}

#[derive(Debug)]
struct Maker(Option<Held>, Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for Maker {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _dialled: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let Some(pin) = self.0.as_ref().filter(|pin| !pinned(end_entity, pin)) else {
            return Ok(ServerCertVerified::assertion());
        };
        // (Nobody has checked this certificate: the name in it is only what it says.)
        let said = match subject_of(end_entity) {
            Some(Subject::Node(name, ..)) if pin.0.is(&name) => {
                format!("a certificate naming {name} answered, with another key than the token names")
            }
            Some(Subject::Node(name, ..)) => format!("a certificate naming {name} answered"),
            _ => "what answered shows no node's certificate".to_string(),
        };
        Err(rustls::Error::General(format!("{} was called, and {said}", pin.0)))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.1.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.1.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

/// Whose a verified client certificate is.
#[derive(Clone, Debug, PartialEq)]
pub enum Subject {
    /// A node, the public key (DER) the certificate is for, and the index of the store by
    /// which its Node was there, if the certificate says: it stands for the node only
    /// while that node's Node names the same key (`cluster::admitted`).
    Node(String, Vec<u8>, Option<u64>),
    /// An Identity, and the public key (DER) the certificate is for: it stands for the
    /// Identity only while that names the same key.
    User(String, Vec<u8>),
    /// A Workload's pod: the Identity it runs as, and the Workload's namespace and name, and
    /// the node the certificate was made for. It stands for the Identity only while the store
    /// says that Workload, placed on that node, runs as it ([`crate::workload_identity::stands`]).
    Workload {
        identity: String,
        namespace: String,
        name: String,
        node: String,
    },
}

pub fn subject_of(cert: &CertificateDer<'_>) -> Option<Subject> {
    let cert = webpki::EndEntityCert::try_from(cert).ok()?;
    let named = |suffix| cert.valid_dns_names().find_map(|name| name.strip_suffix(suffix));
    match (named(NODE_SUFFIX), named(USER_SUFFIX)) {
        (Some(node), _) => Some(Subject::Node(
            node.into(),
            cert.subject_public_key_info().to_vec(),
            named(BORN_SUFFIX).and_then(|born| born.parse().ok()),
        )),
        (None, Some(user)) => Some(Subject::User(user.into(), cert.subject_public_key_info().to_vec())),
        (None, None) => {
            let (name, namespace) = named(WORKLOAD_SUFFIX)?.split_once('.')?;
            Some(Subject::Workload {
                identity: named(RUNS_SUFFIX)?.into(),
                namespace: namespace.into(),
                name: name.into(),
                node: named(ON_SUFFIX)?.into(),
            })
        }
    }
}

/// What a Node keeps of its node's certificate (`status.certificate`): SHA-256 of the
/// public key (DER) it is for.
pub fn key_print(der: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, der).as_ref())
}

/// [`key_print`] of the certificate `pem`.
pub fn print_of(pem: &str) -> Fallible<String> {
    let der = ca_cert(pem)?;
    let cert = tls("reading a certificate", webpki::EndEntityCert::try_from(&der))?;
    Ok(key_print(&cert.subject_public_key_info()))
}

/// [`key_print`] of the key `pem` (an Identity's `publicKey`); none if it is not a key.
pub fn print_of_key(pem: &str) -> Option<String> {
    let key = rustls::pki_types::SubjectPublicKeyInfoDer::from_pem_slice(pem.as_bytes()).ok()?;
    Some(key_print(key.as_ref()))
}

/// Is `pem` (an Identity's `publicKey`) the key `der`?
pub fn same_key(pem: &str, der: &[u8]) -> bool {
    rustls::pki_types::SubjectPublicKeyInfoDer::from_pem_slice(pem.as_bytes()).is_ok_and(|key| key.as_ref() == der)
}

/// Join tokens: `kith1.<secret>.<CA fingerprint>.<maker's key print>.<maker's name>`. The
/// secret is good once, for an hour, on the node that made it; the rest lets the joiner
/// check it is talking to that node, and no other node of the CA, before it sends anything.
/// A token from before (and a claim token) is the first three parts alone. Whoever made it
/// says what the node it lets in is ([`Lets`]): the node that joins does not.
#[derive(Default)]
pub struct Tokens(Mutex<Vec<([u8; 32], Instant, Lets)>>);

/// What a join token's maker said of the node it lets in.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Lets {
    Control,
    /// A worker (`spec.trust`): it is sent a view of the store, never the store.
    Worker,
    /// A worker that serves ingress: its view holds the certificates of the cluster's
    /// exposed hosts as well (`spec.ingress`, written by the node that admits it).
    WorkerIngress,
}

fn digest(secret: &str) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
    digest.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

/// A token's secret, its CA's fingerprint, and the node that made it (name, key print).
pub type TokenParts<'a> = (&'a str, &'a str, Option<(&'a str, &'a str)>);

/// The secret and the CA fingerprint of a token, and the node that made it (its name and
/// key print) where the token names one.
pub fn token_parts(token: &str) -> Fallible<TokenParts<'_>> {
    let mut parts = token.trim().split('.');
    let mut next = || parts.next();
    // (Lowercase only: the key print is compared as `key_print` writes it.)
    let hash = |part: &str| part.len() == 64 && part.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    match (next(), next(), next(), next(), next(), next()) {
        (Some("kith1"), Some(secret), Some(ca), None, ..) if secret.len() == 64 && ca.len() == 64 => {
            Ok((secret, ca, None))
        }
        (Some("kith1"), Some(secret), Some(ca), Some(print), Some(name), None)
            if secret.len() == 64 && ca.len() == 64 && hash(print) && valid_name(name).is_ok() =>
        {
            Ok((secret, ca, Some((name, print))))
        }
        _ => Err("that is not a join token (`kith node token` prints one)".into()),
    }
}

impl Tokens {
    /// A token of the CA `ca`; `maker` (this node) is named in it if given: a claim token,
    /// which is sent by hand, names none.
    pub fn mint(&self, ca: &str, maker: Option<&Identity>, lets: Lets) -> Fallible<String> {
        let maker = match maker {
            Some(me) => format!(".{}.{}", print_of(&me.cert)?, me.name),
            None => String::new(),
        };
        let mut secret = [0u8; 32];
        let filled = ring::rand::SystemRandom::new().fill(&mut secret);
        filled.map_err(|_| "no random bytes from the system")?;
        let secret = hex(&secret);
        let mut tokens = self.0.lock().expect("nothing panics holding the tokens");
        tokens.retain(|(_, made, _)| made.elapsed() < TOKEN_LIFE);
        tokens.push((digest(&secret), Instant::now(), lets));
        Ok(format!("kith1.{secret}.{}{maker}", fingerprint(ca)?))
    }

    /// Whether `token` is good, and then what its maker said of its node; with `spend`, it is
    /// not good again.
    // Digests are compared, so how long the comparison takes says nothing about the secret.
    pub fn good(&self, token: &str, spend: bool) -> Option<Lets> {
        let (secret, ..) = token_parts(token).ok()?;
        let wanted = digest(secret);
        let mut tokens = self.0.lock().expect("nothing panics holding the tokens");
        tokens.retain(|(_, made, _)| made.elapsed() < TOKEN_LIFE);
        let found = tokens.iter().position(|(digest, ..)| *digest == wanted)?;
        let lets = tokens[found].2;
        if spend {
            tokens.remove(found);
        }
        Some(lets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_certificate_names_its_node_and_checks_against_the_ca() {
        let ca = Ca::create().unwrap();
        let (cert, key) = ca.issue("alpha").unwrap();
        let der = certs(&cert).unwrap().remove(0);
        let Some(Subject::Node(name, public, None)) = subject_of(&der) else {
            panic!("a node's certificate");
        };
        assert_eq!((name.as_str(), key_print(&public)), ("alpha", print_of(&cert).unwrap()));
        // One from a join says by which index of the store its Node was there.
        let joined = certs(&ca.issue_born("beta", 41).unwrap().0).unwrap().remove(0);
        assert!(matches!(subject_of(&joined), Some(Subject::Node(name, _, Some(41))) if name == "beta"));

        // An Identity's certificate names it and its key, and no server would be believed with it.
        let (user, _, public) = ca.issue_user("alice").unwrap();
        let user = certs(&user).unwrap().remove(0);
        let Some(Subject::User(name, shown)) = subject_of(&user) else {
            panic!("not a user's certificate")
        };
        assert!(name == "alice" && same_key(&public, &shown));
        let other = ca.issue_user("alice").unwrap().2;
        assert!(!same_key(&other, &shown) && !same_key("not a key", &shown));

        let me = Identity {
            name: "alpha".into(),
            ca: ca.cert.clone(),
            cert,
            key,
        };
        server_config(&me).unwrap();
        client_config(&ca.cert, Some(Live::new(&me).unwrap()), None).unwrap();
        // The cluster's verifier takes it for `kith`; another cluster's CA does not.
        let verify = |trusted: &str| {
            let verifier = WebPkiServerVerifier::builder_with_provider(roots(trusted).unwrap(), provider());
            let dialled = ServerName::try_from("10.0.0.7").unwrap();
            AnyNode(verifier.build().unwrap(), None).verify_server_cert(&der, &[], &dialled, &[], UnixTime::now())
        };
        assert!(verify(&ca.cert).is_ok());
        let verifier = WebPkiServerVerifier::builder_with_provider(roots(&ca.cert).unwrap(), provider());
        let dialled = ServerName::try_from("kith").unwrap();
        let as_server =
            AnyNode(verifier.build().unwrap(), None).verify_server_cert(&user, &[], &dialled, &[], UnixTime::now());
        assert!(as_server.is_err());
        assert!(verify(&Ca::create().unwrap().cert).is_err());

        // Two CAs in one text are not a CA: the second would be trusted unpinned.
        let two = format!("{}{}", ca.cert, Ca::create().unwrap().cert);
        assert!(fingerprint(&two).is_err() && client_config(&two, None, None).is_err());

        assert!(ca.issue("Not A Name").is_err());
        assert!(valid_name("-x").is_err() && valid_name("").is_err() && valid_name("node-1").is_ok());
    }

    #[test]
    fn a_workload_certificate_is_for_a_key_the_ca_never_saw_and_lasts_two_hours() {
        use rcgen::PublicKeyData;
        let ca = Ca::create().unwrap();
        // The node makes the key; the CA holder is sent its public half alone.
        let key = KeyPair::generate().unwrap();
        let public = key.subject_public_key_info();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let cert = ca
            .issue_workload("reader", ("web", "proxy"), "beta", &public, now)
            .unwrap();
        let der = certs(&cert).unwrap().remove(0);
        let end = webpki::EndEntityCert::try_from(&der).unwrap();
        assert_eq!(end.subject_public_key_info().as_ref(), public.as_slice());
        let names: Vec<_> = end.valid_dns_names().collect();
        assert_eq!(names, ["reader.runs.kith", "proxy.web.workload.kith", "beta.on.kith"]);
        let subject = Subject::Workload {
            identity: "reader".into(),
            namespace: "web".into(),
            name: "proxy".into(),
            node: "beta".into(),
        };
        assert_eq!(subject_of(&der), Some(subject));
        // It names no node and no Identity the way their own certificates do: a kithd that
        // knows no Workload's certificate reads no subject in it.
        assert!(
            !names
                .iter()
                .any(|name| name.ends_with(NODE_SUFFIX) || name.ends_with(USER_SUFFIX) || *name == ANY_NODE)
        );

        // The cluster takes it from a client for two hours, and not after.
        let verifier = WebPkiClientVerifier::builder_with_provider(roots(&ca.cert).unwrap(), provider())
            .build()
            .unwrap();
        let at = |secs| verifier.verify_client_cert(&der, &[], UnixTime::since_unix_epoch(Duration::from_secs(secs)));
        assert!(at(now + 60).is_ok() && at(now + 7100).is_ok());
        assert!(at(now + 7300).is_err());

        // A P-256 key, whole, and names that can be named.
        assert!(
            ca.issue_workload("reader", ("web", "proxy"), "beta", &public[1..], now)
                .is_err()
        );
        assert!(
            ca.issue_workload(
                "reader",
                ("web", "proxy"),
                "beta",
                &[public.clone(), vec![0]].concat(),
                now
            )
            .is_err()
        );
        assert!(
            ca.issue_workload("Reader", ("web", "proxy"), "beta", &public, now)
                .is_err()
        );
        assert!(
            ca.issue_workload("reader", ("web", "a.b"), "beta", &public, now)
                .is_err()
        );
    }

    #[test]
    fn identities_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("kith-pki-{}", std::process::id()));
        assert!(load(&dir).unwrap().is_none());
        let ca = Ca::create().unwrap();
        let (cert, key) = ca.issue("alpha").unwrap();
        let me = Identity {
            name: "alpha".into(),
            ca: ca.cert.clone(),
            cert,
            key,
        };
        save(&dir, &me, Some(&ca)).unwrap();
        let (loaded, loaded_ca) = load(&dir).unwrap().unwrap();
        assert_eq!((loaded.name, loaded.cert), (me.name, me.cert));
        // The reloaded CA key still signs certificates the old CA certificate vouches for.
        let (cert, _) = loaded_ca.unwrap().issue("beta").unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(roots(&ca.cert).unwrap(), provider());
        let verified = AnyNode(verifier.build().unwrap(), None).verify_server_cert(
            &certs(&cert).unwrap()[0],
            &[],
            &ServerName::try_from("x").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(verified.is_ok());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("ca.key")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tokens_are_good_once() {
        let ca = Ca::create().unwrap();
        let tokens = Tokens::default();
        let token = tokens.mint(&ca.cert, None, Lets::Control).unwrap();
        assert_eq!(token_parts(&token).unwrap().1, fingerprint(&ca.cert).unwrap());
        assert_eq!(token_parts(&token).unwrap().2, None);
        assert_eq!(tokens.good("kith1.nope.nope", true), None);
        let other = tokens
            .mint(&ca.cert, None, Lets::Control)
            .unwrap()
            .replace("kith1.", "kith1.0");
        assert_eq!(tokens.good(&other, true), None);
        assert_eq!(tokens.good(&token, false), Some(Lets::Control));
        assert_eq!(tokens.good(&token, true), Some(Lets::Control));
        assert_eq!(tokens.good(&token, true), None);
        // What its node is is what its maker said, kept here and not in the token.
        for lets in [Lets::Worker, Lets::WorkerIngress] {
            let worker = tokens.mint(&ca.cert, None, lets).unwrap();
            assert_eq!(tokens.good(&worker, true), Some(lets));
        }
        // One that names its maker: the name and key print come back, and it is good as well.
        let (cert, key) = ca.issue("node-1").unwrap();
        let print = print_of(&cert).unwrap();
        let me = Identity {
            name: "node-1".into(),
            ca: ca.cert.clone(),
            cert,
            key,
        };
        let named = tokens.mint(&ca.cert, Some(&me), Lets::Control).unwrap();
        assert_eq!(token_parts(&named).unwrap().2, Some(("node-1", print.as_str())));
        // A maker part that is not a key print and a name is no token.
        let (head, _) = named.rsplit_once('.').unwrap();
        let (three, _) = head.rsplit_once('.').unwrap();
        for bad in [
            format!("{head}.Node"),
            format!("{head}."),
            format!("{three}.ab.node-1"),
            // (An uppercased print would never match the lowercase one it is compared with.)
            format!("{three}.{}.node-1", print.to_uppercase()),
            head.to_string(),
        ] {
            assert!(token_parts(&bad).is_err(), "{bad}");
        }
        assert_eq!(tokens.good(&named, true), Some(Lets::Control));
    }

    #[test]
    fn whole_write_replaces_the_file_and_leaves_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("kith-whole-pki-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("marker.json");
        // A torn file from before is replaced whole.
        std::fs::write(&path, r#"{"version":"2"#).unwrap();
        write_whole(&path, br#"{"version":"3"}"#).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"version":"3"}"#);
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from("marker.json")]);
        // Into a directory that is not there: an error, and nothing made.
        assert!(write_whole(&dir.join("gone/marker.json"), b"x").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The CA signs a server certificate for a LAN name, for the life asked and no longer: a client
    /// that trusts the CA takes it for that name only, in that time only. It is no node's, no
    /// Identity's, and the names a CA must not vouch for here (the cluster's own, a wildcard, an
    /// address) are not signed.
    #[test]
    fn pki_issue_host_signs_a_server_certificate_for_the_name_for_the_life_asked() {
        let ca = Ca::create().unwrap();
        let (now, life) = (1_900_000_000, Duration::from_secs(600));
        let (cert, key) = ca.issue_host("nas.home.lan", now, life).unwrap();
        certified(&cert, &key, "nas.home.lan").unwrap();
        let der = certs(&cert).unwrap().remove(0);
        assert!(
            subject_of(&der).is_none(),
            "a host's certificate names no node, Identity or Workload"
        );
        let verify = |trusted: &str, host: &str, at: u64| {
            let verifier = WebPkiServerVerifier::builder_with_provider(roots(trusted).unwrap(), provider());
            let name = ServerName::try_from(host.to_string()).unwrap();
            let at = UnixTime::since_unix_epoch(Duration::from_secs(at));
            verifier.build().unwrap().verify_server_cert(&der, &[], &name, &[], at)
        };
        // Good for its name, from a minute before it was made until the life is out.
        assert!(verify(&ca.cert, "nas.home.lan", now).is_ok());
        assert!(verify(&ca.cert, "nas.home.lan", now - 30).is_ok());
        assert!(verify(&ca.cert, "nas.home.lan", now + 599).is_ok());
        assert!(verify(&ca.cert, "nas.home.lan", now + 601).is_err());
        assert!(verify(&ca.cert, "nas.home.lan", now - 3600).is_err());
        // For no other name, and by no other CA.
        assert!(verify(&ca.cert, "other.home.lan", now).is_err());
        assert!(verify(&Ca::create().unwrap().cert, "nas.home.lan", now).is_err());
        // Never as a client or as a CA of its own: a server certificate and nothing more.
        let as_client = WebPkiClientVerifier::builder_with_provider(roots(&ca.cert).unwrap(), provider());
        let at = UnixTime::since_unix_epoch(Duration::from_secs(now));
        assert!(as_client.build().unwrap().verify_client_cert(&der, &[], at).is_err());
        for refused in [
            "*.home.lan",
            "kith",
            "x.node.kith",
            "10.0.0.7",
            "Nas.home.lan",
            "a_b.lan",
            "-a.lan",
            "a..lan",
            "",
        ] {
            assert!(ca.issue_host(refused, now, life).is_err(), "{refused:?} is signed");
        }
    }

    fn secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn a_certificate_is_due_for_renewal_with_under_a_third_of_its_life_left() {
        let year = 365 * 24 * 3600u64;
        let (from, to) = (1_000_000_000u64, 1_000_000_000 + 10 * year);
        assert!(!renewal_due(from, to, from));
        assert!(!renewal_due(from, to, to - 4 * year));
        assert!(renewal_due(from, to, to - 3 * year));
        // One that ended is due too, and no less so for being far past.
        assert!(renewal_due(from, to, to + 1) && renewal_due(from, to, to + 100 * year));
        // A short life is judged by its own: a third of an hour is twenty minutes.
        assert!(!renewal_due(0, 3600, 2300) && renewal_due(0, 3600, 2500));
        // A certificate made before they were dated at their making began in 1975: its life
        // counts as the ten years it was meant to have.
        assert!(!renewal_due(0, 40 * year, 36 * year) && renewal_due(0, 40 * year, 37 * year));
    }

    #[test]
    fn a_certificates_dates_are_read_from_it() {
        let ca = Ca::create().unwrap();
        let (cert, _) = ca.issue("alpha").unwrap();
        let der = certs(&cert).unwrap().remove(0);
        let (from, to) = validity(&der).unwrap();
        let (now, year) = (secs(), 365 * 24 * 3600);
        assert!(from < now && to > now + 9 * year && to < now + 11 * year, "{from} {to}");
        // To the second, in a year before 2050 (UTCTime) and after (GeneralizedTime) alike.
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["x.node.kith".into()]).unwrap();
        for (year, at) in [(2031, 1_924_992_000), (2051, 2_556_144_000)] {
            params.not_before = rcgen::date_time_ymd(year, 1, 1);
            params.not_after = rcgen::date_time_ymd(year + 1, 1, 1);
            let der = params.clone().self_signed(&key).unwrap();
            let (from, to) = validity(der.der()).unwrap();
            assert_eq!((from, to), (at, at + 365 * 24 * 3600), "{year}");
        }
        assert_eq!(validity(&CertificateDer::from(vec![0x30, 0x00])), None);
        assert_eq!(validity(&CertificateDer::from(Vec::new())), None);
    }

    #[test]
    fn a_node_certificate_is_made_again_for_the_same_key_name_and_birth() {
        let ca = Ca::create().unwrap();
        let (cert, _) = ca.issue_born("beta", 41).unwrap();
        let der = certs(&cert).unwrap().remove(0);
        let Some(Subject::Node(name, public, born)) = subject_of(&der) else {
            panic!("a node's certificate");
        };
        let now = secs();
        let again = ca
            .renew_node(&name, born, &public, now, Duration::from_secs(600))
            .unwrap();
        let new = certs(&again).unwrap().remove(0);
        assert_eq!(subject_of(&new), subject_of(&der));
        assert_eq!(print_of(&again).unwrap(), print_of(&cert).unwrap());
        // A minute before, for a clock behind; and the life it was asked for.
        assert_eq!(validity(&new), Some((now - 60, now + 600)));
        // Good as a node's, to the same checks: for a server and as a client, for its life only.
        let verifier = WebPkiClientVerifier::builder_with_provider(roots(&ca.cert).unwrap(), provider())
            .build()
            .unwrap();
        let at = |secs| verifier.verify_client_cert(&new, &[], UnixTime::since_unix_epoch(Duration::from_secs(secs)));
        assert!(at(now + 300).is_ok() && at(now + 700).is_err());
        let end = webpki::EndEntityCert::try_from(&new).unwrap();
        let named: Vec<_> = end.valid_dns_names().collect();
        assert_eq!(named, ["beta.node.kith", "kith", "41.born.kith"]);
        // A P-256 key, whole, and a name that can be named.
        let life = Duration::from_secs(60);
        assert!(ca.renew_node("beta", None, &public[1..], now, life).is_err());
        assert!(ca.renew_node("Beta", None, &public, now, life).is_err());
    }

    /// A handshake in memory between `server` and `client`: the certificate the server was
    /// shown (or why it refused), and the one the client was.
    async fn shake(
        server: Arc<ServerConfig>,
        client: ClientConfig,
    ) -> (
        Result<Option<CertificateDer<'static>>, String>,
        Option<CertificateDer<'static>>,
    ) {
        let (near, far) = tokio::io::duplex(1 << 16);
        let acceptor = tokio_rustls::TlsAcceptor::from(server);
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        // (Each keeps its end open until both are done: the server writes after the client is through.)
        let serving = async {
            let stream = acceptor.accept(far).await.map_err(|e| e.to_string())?;
            Ok((
                stream.get_ref().1.peer_certificates().and_then(|c| c.first().cloned()),
                stream,
            ))
        };
        let calling = async {
            let stream = connector
                .connect(ServerName::try_from("kith").unwrap(), near)
                .await
                .ok()?;
            Some((stream.get_ref().1.peer_certificates()?.first().cloned(), stream))
        };
        let (served, called) = tokio::join!(serving, calling);
        (served.map(|(cert, _)| cert), called.and_then(|(cert, _)| cert))
    }

    /// A client that was let in and is revoked after is refused on its next connection, though it
    /// holds the session of the first to resume: a server that kept sessions would take the
    /// certificate back from the session and not ask `Revoked` again.
    #[tokio::test]
    async fn a_revoked_certificate_cannot_resume_a_session() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let ca = Ca::create().unwrap();
        let identity = |name: &str| {
            let (cert, key) = ca.issue(name).unwrap();
            Identity {
                name: name.into(),
                ca: ca.cert.clone(),
                cert,
                key,
            }
        };
        let (a, b) = (identity("a"), identity("b"));
        let gone = Arc::new(AtomicBool::new(false));
        let flag = gone.clone();
        let revoked: Revoked = Arc::new(move |_| flag.load(Ordering::SeqCst));
        let server = served(&a.ca, Live::new(&a).unwrap(), Some(revoked)).unwrap();
        // (One configuration for both: it is what keeps the session between the connections.)
        let client = Arc::new(client_config(&b.ca, Some(Live::new(&b).unwrap()), None).unwrap());
        let connect = || async {
            let (near, far) = tokio::io::duplex(1 << 16);
            let acceptor = tokio_rustls::TlsAcceptor::from(server.clone());
            let connector = tokio_rustls::TlsConnector::from(client.clone());
            let serving = async {
                let mut stream = acceptor.accept(far).await.map_err(|e| e.to_string())?;
                stream.write_all(b"x").await.map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;
                drop(stream.read_to_end(&mut Vec::new()).await);
                Ok::<(), String>(())
            };
            let calling = async {
                let name = ServerName::try_from("kith").unwrap();
                let mut stream = connector.connect(name, near).await.map_err(|e| e.to_string())?;
                // (The session comes with what the server sends after the handshake.)
                stream.read_exact(&mut [0u8; 1]).await.map_err(|e| e.to_string())?;
                stream.shutdown().await.map_err(|e| e.to_string())
            };
            tokio::join!(serving, calling)
        };
        let (served, called) = connect().await;
        assert_eq!((served, called), (Ok(()), Ok(())));
        gone.store(true, Ordering::SeqCst);
        let (served, _) = connect().await;
        let said = served.unwrap_err();
        assert!(said.contains("Revoked"), "{said}");
    }

    /// The file that holds a certificate is made private, as the key beside it is, whatever the umask.
    #[test]
    fn write_whole_makes_a_private_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kithd-whole-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.crt");
        write_whole(&path, b"x").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn a_revoked_certificate_is_refused_in_the_handshake_not_only_per_request() {
        let ca = Ca::create().unwrap();
        let identity = |name: &str| {
            let (cert, key) = ca.issue(name).unwrap();
            Identity {
                name: name.into(),
                ca: ca.cert.clone(),
                cert,
                key,
            }
        };
        let (a, b, gone) = (identity("a"), identity("b"), identity("gone"));
        // What the node says is revoked: the node `gone`, and the Identity `mallory`.
        let revoked: Revoked = Arc::new(|cert| match subject_of(cert) {
            Some(Subject::Node(name, ..)) => name == "gone",
            Some(Subject::User(name, ..)) => name == "mallory",
            _ => false,
        });
        let server = served(&a.ca, Live::new(&a).unwrap(), Some(revoked)).unwrap();
        let call = |me: &Identity| client_config(&me.ca, Some(Live::new(me).unwrap()), None).unwrap();

        let (heard, _) = shake(server.clone(), call(&b)).await;
        assert_eq!(
            heard.unwrap().map(|c| key_print(&c)),
            Some(key_print(&certs(&b.cert).unwrap()[0]))
        );
        let (heard, _) = shake(server.clone(), call(&gone)).await;
        let said = heard.unwrap_err();
        assert!(said.contains("Revoked"), "{said}");

        let user = |name: &str| {
            let (cert, key, _) = ca.issue_user(name).unwrap();
            Identity {
                name: name.into(),
                ca: ca.cert.clone(),
                cert,
                key,
            }
        };
        assert!(shake(server.clone(), call(&user("alice"))).await.0.is_ok());
        assert!(shake(server.clone(), call(&user("mallory"))).await.0.is_err());
        // One with no certificate at all still comes in (to join), and a stranger's is no better.
        let bare = client_config(&a.ca, None, None).unwrap();
        assert!(shake(server, bare).await.0.unwrap().is_none());
        let other = Ca::create().unwrap().issue("b").unwrap();
        let stranger = Identity {
            name: "b".into(),
            ca: a.ca.clone(),
            cert: other.0,
            key: other.1,
        };
        let server = served(&a.ca, Live::new(&a).unwrap(), None).unwrap();
        assert!(shake(server, call(&stranger)).await.0.is_err());
    }

    #[tokio::test]
    async fn a_renewed_certificate_is_shown_by_server_and_client_alike_with_no_restart() {
        let ca = Ca::create().unwrap();
        let (cert, key) = ca.issue("b").unwrap();
        let der = certs(&cert).unwrap().remove(0);
        let Some(Subject::Node(_, public, _)) = subject_of(&der) else {
            panic!("a node's certificate");
        };
        // One an hour old with ten minutes left: the kind a node renews.
        let now = secs();
        let short = ca
            .renew_node("b", None, &public, now - 3540, Duration::from_secs(4140))
            .unwrap();
        let b = Identity {
            name: "b".into(),
            ca: ca.cert.clone(),
            cert: short.clone(),
            key: key.clone(),
        };
        let (a_cert, a_key) = ca.issue("a").unwrap();
        let a = Identity {
            name: "a".into(),
            ca: ca.cert.clone(),
            cert: a_cert,
            key: a_key,
        };
        let live = Live::new(&b).unwrap();
        let (listening, calling) = (
            served(&b.ca, live.clone(), None).unwrap(),
            client_config(&b.ca, Some(live.clone()), None).unwrap(),
        );
        let (sees_a, sees_b) = (
            served(&a.ca, Live::new(&a).unwrap(), None).unwrap(),
            client_config(&a.ca, Some(Live::new(&a).unwrap()), None).unwrap(),
        );
        let ends = |cert: &Option<CertificateDer<'_>>| validity(cert.as_ref().unwrap()).unwrap().1;
        // As a server, to a client that is the other node's, and as a client, to its server.
        let (_, shown) = shake(listening.clone(), sees_b.clone()).await;
        assert_eq!(ends(&shown), now + 600);
        let (took, _) = shake(sees_a.clone(), calling.clone()).await;
        assert_eq!(ends(&took.unwrap()), now + 600);

        // Made again: the very same configurations show the new one at the next handshake.
        let again = ca.renew_node("b", None, &public, now, NODE_LIFE).unwrap();
        live.swap(&again).unwrap();
        let (_, shown) = shake(listening, sees_b).await;
        assert_eq!(ends(&shown), now + NODE_LIFE.as_secs());
        let (took, _) = shake(sees_a, calling).await;
        assert_eq!(ends(&took.unwrap()), now + NODE_LIFE.as_secs());

        // Only a certificate for the key it holds is taken: not another's, nor a stranger's.
        let (other, _) = ca.issue("b").unwrap();
        assert!(live.swap(&other).is_err() && live.swap("not a certificate").is_err());
        let (mine, _) = Ca::create().unwrap().issue("b").unwrap();
        assert!(live.swap(&mine).is_err());
        assert_eq!(live.current().cert.len(), 1);
    }
}
