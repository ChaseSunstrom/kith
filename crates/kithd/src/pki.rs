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
        let names = vec![format!("{name}{NODE_SUFFIX}"), ANY_NODE.into()];
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
        file.and_then(|mut file| file.write_all(text.as_bytes())),
    )
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
    write_private(&dir.join("node.crt"), &identity.cert)
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

/// A certificate chain and its key (both PEM) as a server shows them. Not if the key is
/// another certificate's.
pub fn certified(chain: &str, key: &str) -> Fallible<rustls::sign::CertifiedKey> {
    let key = tls("reading a key", PrivateKeyDer::from_pem_slice(key.as_bytes()))?;
    let key = tls("reading a key", provider().key_provider.load_private_key(key))?;
    let certified = rustls::sign::CertifiedKey::new(certs(chain)?, key);
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
#[derive(Debug)]
struct AnyNode(Arc<WebPkiServerVerifier>);

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
        self.0.verify_server_cert(end_entity, intermediates, &name, ocsp, now)
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
pub fn client_config(ca: &str, me: Option<&Identity>) -> Fallible<ClientConfig> {
    let verifier = WebPkiServerVerifier::builder_with_provider(roots(ca)?, provider()).build();
    let builder = tls(
        "setting up TLS",
        ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
    )?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AnyNode(tls("setting up TLS", verifier)?)));
    match me {
        None => Ok(builder.with_no_client_auth()),
        Some(me) => {
            let key = tls("reading the node key", PrivateKeyDer::from_pem_slice(me.key.as_bytes()))?;
            tls("setting up TLS", builder.with_client_auth_cert(certs(&me.cert)?, key))
        }
    }
}

/// Whose a verified client certificate is.
#[derive(Clone, Debug, PartialEq)]
pub enum Subject {
    Node(String),
    /// An Identity, and the public key (DER) the certificate is for: it stands for the
    /// Identity only while that names the same key.
    User(String, Vec<u8>),
}

pub fn subject_of(cert: &CertificateDer<'_>) -> Option<Subject> {
    let cert = webpki::EndEntityCert::try_from(cert).ok()?;
    let named = |suffix| cert.valid_dns_names().find_map(|name| name.strip_suffix(suffix));
    match (named(NODE_SUFFIX), named(USER_SUFFIX)) {
        (Some(node), _) => Some(Subject::Node(node.into())),
        (None, Some(user)) => Some(Subject::User(user.into(), cert.subject_public_key_info().to_vec())),
        (None, None) => None,
    }
}

/// Is `pem` (an Identity's `publicKey`) the key `der`?
pub fn same_key(pem: &str, der: &[u8]) -> bool {
    rustls::pki_types::SubjectPublicKeyInfoDer::from_pem_slice(pem.as_bytes()).is_ok_and(|key| key.as_ref() == der)
}

/// Join tokens: `kith1.<secret>.<CA fingerprint>`. The secret is good once, for an hour,
/// on the node that made it; the fingerprint lets the joiner check who it is talking to
/// before it sends the secret.
#[derive(Default)]
pub struct Tokens(Mutex<Vec<([u8; 32], Instant)>>);

fn digest(secret: &str) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
    digest.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

/// The secret and the CA fingerprint of a token.
pub fn token_parts(token: &str) -> Fallible<(&str, &str)> {
    let mut parts = token.trim().split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("kith1"), Some(secret), Some(ca), None) if secret.len() == 64 && ca.len() == 64 => Ok((secret, ca)),
        _ => Err("that is not a join token (`kith node token` prints one)".into()),
    }
}

impl Tokens {
    pub fn mint(&self, ca: &str) -> Fallible<String> {
        let mut secret = [0u8; 32];
        let filled = ring::rand::SystemRandom::new().fill(&mut secret);
        filled.map_err(|_| "no random bytes from the system")?;
        let secret = hex(&secret);
        let mut tokens = self.0.lock().expect("nothing panics holding the tokens");
        tokens.retain(|(_, made)| made.elapsed() < TOKEN_LIFE);
        tokens.push((digest(&secret), Instant::now()));
        Ok(format!("kith1.{secret}.{}", fingerprint(ca)?))
    }

    /// Whether `token` is good; with `spend`, it is not good again.
    // Digests are compared, so how long the comparison takes says nothing about the secret.
    pub fn good(&self, token: &str, spend: bool) -> bool {
        let Ok((secret, _)) = token_parts(token) else {
            return false;
        };
        let wanted = digest(secret);
        let mut tokens = self.0.lock().expect("nothing panics holding the tokens");
        tokens.retain(|(_, made)| made.elapsed() < TOKEN_LIFE);
        let found = tokens.iter().position(|(digest, _)| *digest == wanted);
        if let (Some(at), true) = (found, spend) {
            tokens.remove(at);
        }
        found.is_some()
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
        assert_eq!(subject_of(&der), Some(Subject::Node("alpha".into())));

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
        client_config(&ca.cert, Some(&me)).unwrap();
        // The cluster's verifier takes it for `kith`; another cluster's CA does not.
        let verify = |trusted: &str| {
            let verifier = WebPkiServerVerifier::builder_with_provider(roots(trusted).unwrap(), provider());
            let dialled = ServerName::try_from("10.0.0.7").unwrap();
            AnyNode(verifier.build().unwrap()).verify_server_cert(&der, &[], &dialled, &[], UnixTime::now())
        };
        assert!(verify(&ca.cert).is_ok());
        let verifier = WebPkiServerVerifier::builder_with_provider(roots(&ca.cert).unwrap(), provider());
        let dialled = ServerName::try_from("kith").unwrap();
        let as_server =
            AnyNode(verifier.build().unwrap()).verify_server_cert(&user, &[], &dialled, &[], UnixTime::now());
        assert!(as_server.is_err());
        assert!(verify(&Ca::create().unwrap().cert).is_err());

        // Two CAs in one text are not a CA: the second would be trusted unpinned.
        let two = format!("{}{}", ca.cert, Ca::create().unwrap().cert);
        assert!(fingerprint(&two).is_err() && client_config(&two, None).is_err());

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
        let verified = AnyNode(verifier.build().unwrap()).verify_server_cert(
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
        let token = tokens.mint(&ca.cert).unwrap();
        assert_eq!(token_parts(&token).unwrap().1, fingerprint(&ca.cert).unwrap());
        assert!(!tokens.good("kith1.nope.nope", true));
        assert!(!tokens.good(&tokens.mint(&ca.cert).unwrap().replace("kith1.", "kith1.0"), true));
        assert!(tokens.good(&token, false));
        assert!(tokens.good(&token, true));
        assert!(!tokens.good(&token, true));
    }
}
