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
// any certificate anyway. Certificates last ten years: there is no renewal yet.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use ring::rand::SecureRandom;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};
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

    fn sign(
        &self,
        name: &str,
        names: Vec<String>,
        usages: Vec<ExtendedKeyUsagePurpose>,
    ) -> Fallible<(String, KeyPair)> {
        valid_name(name)?;
        let mut params = tls("naming the certificate", CertificateParams::new(names))?;
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = usages;
        params.use_authority_key_identifier_extension = true;
        params.not_after = rcgen::date_time_ymd(year_in(10), 1, 1);
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
/// does present must be from the cluster CA.
pub fn server_config(identity: &Identity) -> Fallible<Arc<ServerConfig>> {
    let verifier = WebPkiClientVerifier::builder_with_provider(roots(&identity.ca)?, provider())
        .allow_unauthenticated()
        .build();
    let key = tls(
        "reading the node key",
        PrivateKeyDer::from_pem_slice(identity.key.as_bytes()),
    )?;
    let config = tls(
        "setting up TLS",
        ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
    )?
    .with_client_cert_verifier(tls("setting up TLS", verifier)?)
    .with_single_cert(certs(&identity.cert)?, key);
    Ok(Arc::new(tls("setting up TLS", config)?))
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

/// TLS for calling a node: its certificate must be from `ca`. With `me`, ours is presented.
/// With `pin`, only the node it names is called, whoever answers at the address.
pub fn client_config(ca: &str, me: Option<&Identity>, pin: Option<Held>) -> Fallible<ClientConfig> {
    let verifier = WebPkiServerVerifier::builder_with_provider(roots(ca)?, provider()).build();
    let builder = tls(
        "setting up TLS",
        ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
    )?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AnyNode(tls("setting up TLS", verifier)?, pin)));
    match me {
        None => Ok(builder.with_no_client_auth()),
        Some(me) => {
            let key = tls("reading the node key", PrivateKeyDer::from_pem_slice(me.key.as_bytes()))?;
            tls("setting up TLS", builder.with_client_auth_cert(certs(&me.cert)?, key))
        }
    }
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
        (None, None) => None,
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
        client_config(&ca.cert, Some(&me), None).unwrap();
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
}
