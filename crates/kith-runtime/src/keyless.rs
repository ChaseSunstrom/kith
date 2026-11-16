//! Image signatures made without a kept key (cosign's default): a certificate of ten minutes
//! from an authority that names who signed, and a transparency log's promise of when it
//! saw the signature. What is checked, byte by byte, is in docs/adr-keyless.md.

use crate::{Result, err};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use rustls::pki_types::{CertificateDer, UnixTime};
use serde_json::Value;

/// What a bundle kept among an image's referrers is (cosign 3's default).
pub const BUNDLE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
/// id-kp-codeSigning, 1.3.6.1.5.5.7.3.3, as the bytes of its OID.
const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
/// The OIDs of the extensions read here: the names (2.5.29.17), and who signed the signer in
/// (Fulcio's 1.3.6.1.4.1.57264.1.8, a UTF8String, and the older 57264.1.1, the bytes alone).
const NAMES: &[u8] = &[0x55, 0x1d, 0x11];
const ISSUER: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x08];
const ISSUER_V1: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x01];
/// A P-256 public key's DER, before its point (the same as signed.rs's).
const P256: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// The most certificates an identity's authority is given as.
const AUTHORITY: usize = 4;

/// Who an image may be signed by without a kept key: whom the authority certified, as whom
/// the issuer signed them in, and the authority's certificates and the log's key that say so.
pub struct Identity {
    /// The identity as it is remembered: its names, and a hash of all it was given.
    pub id: String,
    issuer: String,
    subject: String,
    authority: Vec<CertificateDer<'static>>,
    /// The log's key (its point), and its id: SHA-256 of its DER, in hex.
    log: Vec<u8>,
    log_id: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes).as_ref().to_vec()
}

/// A PEM text's bytes (or the base64 alone), whatever its kind.
fn pem(text: &str) -> Option<Vec<u8>> {
    let lines = text.lines().filter(|line| !line.trim_start().starts_with("-----"));
    let base64: String = lines.flat_map(str::chars).filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(base64).ok().filter(|der| !der.is_empty())
}

/// Reads an identity as a rule gives it (its JSON text: `issuer`, `subject`, `authority`, `log`).
pub fn identity(said: &str) -> Result<Identity> {
    let said: Value = serde_json::from_str(said).unwrap_or_default();
    let text = |key: &str| said[key].as_str().filter(|text| !text.is_empty()).map(String::from);
    let (Some(issuer), Some(subject)) = (text("issuer"), text("subject")) else {
        return err("signedBy: an identity names its `issuer` and its `subject`");
    };
    let given = said["authority"].as_array().cloned().unwrap_or_default();
    if given.is_empty() || given.len() > AUTHORITY {
        return err(format!(
            "signedBy: the identity {subject} gives 1 to {AUTHORITY} certificates of its authority"
        ));
    }
    let mut authority = Vec::new();
    for cert in &given {
        let der = cert.as_str().and_then(pem).map(CertificateDer::from);
        match der.filter(|der| webpki::anchor_from_trusted_cert(der).is_ok()) {
            Some(der) => authority.push(der),
            None => {
                return err(format!(
                    "signedBy: the identity {subject}'s authority holds what is no certificate"
                ));
            }
        }
    }
    let log = text("log").as_deref().and_then(pem);
    let Some(point) = log
        .as_ref()
        .and_then(|der| der.strip_prefix(P256))
        .filter(|point| point.len() == 65)
    else {
        return err(format!(
            "signedBy: the identity {subject}'s `log` is not an ECDSA P-256 public key"
        ));
    };
    let log_id = hex(&sha256(log.as_deref().unwrap_or_default()));
    let all = [issuer.as_bytes(), subject.as_bytes(), log_id.as_bytes()].into_iter();
    let all: Vec<u8> = all
        .chain(authority.iter().map(|der| der.as_ref()))
        .flat_map(sha256)
        .collect();
    Ok(Identity {
        id: format!("{subject} ({issuer}) #{}", &hex(&sha256(&all))[..32]),
        log: point.to_vec(),
        issuer,
        subject,
        authority,
        log_id,
    })
}

/// A log's promise that it saw an entry: the entry, when, where, by which log, and the
/// log's signature over those.
pub struct Promise {
    body: Vec<u8>,
    time: i64,
    index: i64,
    log_id: String,
    signature: Vec<u8>,
}

/// What a signature of an image without a kept key is made of, wherever it was kept.
pub struct Signed {
    /// The certificate (DER) whose key signed.
    cert: Vec<u8>,
    signature: Vec<u8>,
    /// The bytes the signature is over: a DSSE envelope's, or the payload itself.
    signed: Vec<u8>,
    payload: Vec<u8>,
    /// Whether the payload is an in-toto statement (a bundle's) or cosign's simple text.
    statement: bool,
    promise: Option<Promise>,
}

/// A number protobuf's JSON writes as a string (int64), or a JSON number.
fn number(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_str()?.parse().ok())
}

fn base64(value: &Value) -> Option<Vec<u8>> {
    STANDARD.decode(value.as_str()?).ok()
}

/// Text a registry gave, as a refusal shows it: its first 80 characters, none a control.
fn shown(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(80).collect()
}

/// DSSE's pre-authentication encoding: what a DSSE envelope's signature is over.
fn pae(kind: &str, payload: &[u8]) -> Vec<u8> {
    let head = format!("DSSEv1 {} {kind} {} ", kind.len(), payload.len());
    [head.as_bytes(), payload].concat()
}

/// Reads a bundle (cosign 3's, kept among an image's referrers).
pub fn bundle(bytes: &[u8]) -> std::result::Result<Signed, String> {
    let said: Value = serde_json::from_slice(bytes).map_err(|e| format!("a bundle that is not JSON ({e})"))?;
    if said["mediaType"] != BUNDLE {
        return Err(format!(
            "a bundle of a kind kith does not read ({})",
            shown(&said["mediaType"].to_string())
        ));
    }
    let material = &said["verificationMaterial"];
    let cert = base64(&material["certificate"]["rawBytes"])
        .or_else(|| base64(&material["x509CertificateChain"]["certificates"][0]["rawBytes"]))
        .ok_or("a bundle with no certificate (signed with a kept key?)")?;
    let envelope = &said["dsseEnvelope"];
    let kind = envelope["payloadType"]
        .as_str()
        .ok_or("a bundle with no DSSE envelope")?;
    if kind != "application/vnd.in-toto+json" {
        return Err(format!(
            "a bundle whose envelope holds what is no in-toto statement ({})",
            shown(kind)
        ));
    }
    let payload = base64(&envelope["payload"]).ok_or("a bundle whose envelope has no payload")?;
    let signatures = envelope["signatures"].as_array().map(Vec::as_slice).unwrap_or_default();
    let [signature] = signatures else {
        return Err(format!(
            "a bundle whose envelope has {} signatures, not one",
            signatures.len()
        ));
    };
    let signature = base64(&signature["sig"]).ok_or("a bundle whose signature is not base64")?;
    let entries = material["tlogEntries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let promise = match entries {
        [] => None,
        [entry, ..] => {
            let promise = &entry["inclusionPromise"]["signedEntryTimestamp"];
            let read = || {
                Some(Promise {
                    body: base64(&entry["canonicalizedBody"])?,
                    time: number(&entry["integratedTime"])?,
                    index: number(&entry["logIndex"])?,
                    log_id: hex(&base64(&entry["logId"]["keyId"])?),
                    signature: base64(promise)?,
                })
            };
            Some(read().ok_or(match promise.is_null() {
                true => "its log entry has no promise from the log (a log of Rekor v2, which kith does not read yet)",
                false => "its log entry is not one kith can read",
            })?)
        }
    };
    Ok(Signed {
        cert,
        signed: pae(kind, &payload),
        signature,
        payload,
        statement: true,
        promise,
    })
}

/// Reads a signature kept under the tag `sha256-HEX.sig`: the signed text, its signature, and
/// the certificate and the log's promise kept with them.
pub fn tagged(
    payload: &[u8],
    signature: Vec<u8>,
    cert: &str,
    promise: Option<&str>,
) -> std::result::Result<Signed, String> {
    let cert = pem(cert).ok_or("its certificate is not PEM")?;
    let promise = match promise.map(serde_json::from_str::<Value>) {
        None => None,
        Some(Ok(said)) => {
            let at = &said["Payload"];
            let read = || {
                Some(Promise {
                    body: base64(&at["body"])?,
                    time: number(&at["integratedTime"])?,
                    index: number(&at["logIndex"])?,
                    log_id: at["logID"].as_str()?.to_string(),
                    signature: base64(&said["SignedEntryTimestamp"])?,
                })
            };
            Some(read().ok_or("its log entry is not one kith can read")?)
        }
        Some(Err(_)) => return Err("its log entry is not JSON".into()),
    };
    let signed = payload.to_vec();
    Ok(Signed {
        cert,
        signature,
        signed,
        payload: payload.to_vec(),
        statement: false,
        promise,
    })
}

/// Whether `signed` is a signature of the image `digest` by `who`; why not, if not.
pub fn check(signed: &Signed, digest: &str, who: &Identity) -> std::result::Result<(), String> {
    let promise = signed.promise.as_ref().ok_or("it has no entry in a log")?;
    // The log's promise, by the log's key: the time is now the log's word.
    if promise.log_id != who.log_id {
        return Err(format!(
            "its log entry is from another log (key id {})",
            shown(&promise.log_id)
        ));
    }
    let promised = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        STANDARD.encode(&promise.body),
        promise.time,
        promise.log_id,
        promise.index
    );
    let log = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &who.log);
    if log.verify(promised.as_bytes(), &promise.signature).is_err() {
        return Err("its log entry's promise is not signed by the log's key".into());
    }
    // The entry the log promised is this signature, by this certificate, of this payload.
    entry(signed, &promise.body)?;
    // The certificate, from the authority, for code signing, when the log saw it.
    let cert = CertificateDer::from(signed.cert.as_slice());
    let leaf = webpki::EndEntityCert::try_from(&cert).map_err(|e| format!("its certificate cannot be read ({e})"))?;
    // The authority's roots (those that sign themselves) are where a chain ends; the rest are
    // its intermediates, each held to its own time as the leaf is (a root's is not read).
    let root =
        |der: &&CertificateDer| webpki::EndEntityCert::try_from(*der).is_ok_and(|cert| cert.issuer() == cert.subject());
    let (roots, intermediates): (Vec<_>, Vec<_>) = who.authority.iter().partition(root);
    let anchors: Vec<_> = roots
        .iter()
        .filter_map(|der| webpki::anchor_from_trusted_cert(der).ok())
        .collect();
    let intermediates: Vec<CertificateDer> = intermediates.into_iter().cloned().collect();
    let algorithms = [webpki::ring::ECDSA_P256_SHA256, webpki::ring::ECDSA_P384_SHA384];
    let at = u64::try_from(promise.time).map_err(|_| "its log entry's time is before 1970")?;
    let when = UnixTime::since_unix_epoch(std::time::Duration::from_secs(at));
    let usage = webpki::KeyUsage::required(CODE_SIGNING);
    if let Err(e) = leaf.verify_for_usage(&algorithms, &anchors, &intermediates, when, usage, None, None) {
        return Err(match e {
            webpki::Error::CertNotValidYet { .. } | webpki::Error::CertExpired { .. } => {
                format!("the log saw it at {at}, outside its certificate's time")
            }
            webpki::Error::RequiredEkuNotFoundContext(_) => "its certificate is not for code signing".into(),
            e => format!("its certificate is not from the authority named ({e:?})"),
        });
    }
    // Whom it names.
    let (subject, issuer) = names(&signed.cert).ok_or("its certificate names no one kith can read")?;
    if (subject.as_str(), issuer.as_str()) != (who.subject.as_str(), who.issuer.as_str()) {
        return Err(format!("it was signed by {subject} ({issuer})"));
    }
    // The signature, by the certificate's key.
    let by = |algorithm| {
        leaf.verify_signature(algorithm, &signed.signed, &signed.signature)
            .is_ok()
    };
    if !by(webpki::ring::ECDSA_P256_SHA256) && !by(webpki::ring::ECDSA_P384_SHA384) {
        return Err("its signature is not by its certificate's key".into());
    }
    of(signed, digest)
}

/// That what was signed says it is a signature of the image `digest` (and not, say, an
/// attestation of it: what that says is another matter).
fn of(signed: &Signed, digest: &str) -> std::result::Result<(), String> {
    let said: Value = serde_json::from_slice(&signed.payload).unwrap_or_default();
    let hex = digest.strip_prefix("sha256:").unwrap_or_default();
    let of = match signed.statement {
        true => {
            const SIGNATURE: &str = "https://sigstore.dev/cosign/sign/v1";
            if said["_type"] != "https://in-toto.io/Statement/v1" || said["predicateType"] != SIGNATURE {
                let predicate = said["predicateType"].as_str().unwrap_or("none");
                return Err(format!(
                    "it is no signature but a statement of another kind ({})",
                    shown(predicate)
                ));
            }
            let subjects = said["subject"].as_array().map(Vec::as_slice).unwrap_or_default();
            subjects.iter().any(|subject| subject["digest"]["sha256"] == hex)
        }
        false => said["critical"]["image"]["docker-manifest-digest"] == digest,
    };
    match of {
        true => Ok(()),
        false => Err("it is a signature of another image".into()),
    }
}

/// That the log's entry `body` is of `signed`: its signature, its certificate and what it signed.
fn entry(signed: &Signed, body: &[u8]) -> std::result::Result<(), String> {
    let body: Value = serde_json::from_slice(body).unwrap_or_default();
    let spec = &body["spec"];
    let cert = |text: &Value| base64(text).and_then(|pem_text| pem(&String::from_utf8_lossy(&pem_text)));
    let ours = match (body["kind"].as_str(), body["apiVersion"].as_str()) {
        (Some("dsse"), Some("0.0.1")) => {
            let signatures = spec["signatures"].as_array().map(Vec::as_slice).unwrap_or_default();
            signatures.len() == 1
                && base64(&signatures[0]["signature"]).as_ref() == Some(&signed.signature)
                && cert(&signatures[0]["verifier"]).as_ref() == Some(&signed.cert)
                && spec["payloadHash"]["algorithm"] == "sha256"
                && spec["payloadHash"]["value"] == hex(&sha256(&signed.payload))
        }
        (Some("hashedrekord"), Some("0.0.1")) => {
            base64(&spec["signature"]["content"]).as_ref() == Some(&signed.signature)
                && cert(&spec["signature"]["publicKey"]["content"]).as_ref() == Some(&signed.cert)
                && spec["data"]["hash"]["algorithm"] == "sha256"
                && spec["data"]["hash"]["value"] == hex(&sha256(&signed.signed))
        }
        (kind, version) => {
            return Err(format!(
                "its log entry is of a kind kith does not read ({} {})",
                kind.unwrap_or("none"),
                version.unwrap_or("")
            ));
        }
    };
    match ours {
        true => Ok(()),
        false => Err("its log entry is of another signature".into()),
    }
}

/// One DER element at the start of `input`: its tag, its contents, and what follows it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81..=0x83 => {
            let (bytes, rest) = rest.split_at_checked(usize::from(first & 0x7f))?;
            (
                bytes.iter().fold(0usize, |len, &byte| len << 8 | usize::from(byte)),
                rest,
            )
        }
        _ => return None,
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// The elements one after another in `input`.
fn elements(mut input: &[u8]) -> impl Iterator<Item = Option<(u8, &[u8])>> {
    std::iter::from_fn(move || {
        if input.is_empty() {
            return None;
        }
        let Some((tag, contents, rest)) = element(input) else {
            input = &[];
            return Some(None);
        };
        input = rest;
        Some(Some((tag, contents)))
    })
}

/// Whom a certificate (DER) names: its one email address or URI, and the issuer its signer
/// signed in at. None where there is not exactly one such name, or no issuer.
fn names(der: &[u8]) -> Option<(String, String)> {
    let (0x30, cert, _) = element(der)? else { return None };
    let (0x30, tbs, _) = element(cert)? else { return None };
    let extensions = elements(tbs).find_map(|part| match part {
        Some((0xa3, extensions)) => Some(Some(extensions)),
        None => Some(None),
        _ => None,
    })??;
    let (0x30, extensions, _) = element(extensions)? else {
        return None;
    };
    let (mut subject, mut issuer, mut issuer_v1) = (None, None, None);
    let mut seen = Vec::new();
    for extension in elements(extensions) {
        let (0x30, extension) = extension? else { return None };
        let mut parts = elements(extension);
        let (0x06, oid) = parts.next()?? else { return None };
        // (Each extension once: a second of the same is not a certificate read here.)
        if seen.contains(&oid) {
            return None;
        }
        seen.push(oid);
        // (A critical flag may come between: the value is the last part.)
        let value = parts.last()??;
        let (0x04, value) = value else { return None };
        match oid {
            NAMES => {
                let (0x30, names, _) = element(value)? else { return None };
                let names: Vec<_> = elements(names).collect::<Option<_>>()?;
                let [(0x81 | 0x86, name)] = names.as_slice() else {
                    return None;
                };
                subject = Some(String::from_utf8(name.to_vec()).ok()?);
            }
            ISSUER => {
                let (0x0c, said, _) = element(value)? else { return None };
                issuer = Some(String::from_utf8(said.to_vec()).ok()?);
            }
            ISSUER_V1 => issuer_v1 = Some(String::from_utf8(value.to_vec()).ok()?),
            _ => {}
        }
    }
    Some((subject?, issuer.or(issuer_v1)?))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, SanType,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
    use std::time::Duration;

    /// 2026-01-01T00:00:00Z, when the tests' certificates start.
    pub const START: u64 = 1_767_225_600;

    /// An authority as Fulcio is: a P-384 root that signs P-256 certificates of ten minutes.
    pub struct Authority {
        pub root: CertificateDer<'static>,
        issuer: Issuer<'static, KeyPair>,
    }

    impl Authority {
        pub fn new() -> Authority {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::OrganizationName, "sigstore.test");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let root = params.self_signed(&key).unwrap().der().clone();
            Authority {
                root,
                issuer: Issuer::new(params, key),
            }
        }

        /// An intermediate of this authority's, good until the start of `until` (a year), as
        /// an authority of its own: its certificate is `root`.
        pub fn intermediate(&self, until: i32) -> Authority {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::OrganizationName, "sigstore.test intermediate");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            params.not_after = rcgen::date_time_ymd(until, 1, 1);
            // (As Fulcio's intermediate: for code signing too, which a path for it needs.)
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
            let root = params.signed_by(&key, &self.issuer).unwrap().der().clone();
            Authority {
                root,
                issuer: Issuer::new(params, key),
            }
        }

        /// A certificate of ten minutes from `at` for `subject` (an email address, or a URI)
        /// signed in at `issuer`, for `usage`; and its key. As Fulcio's: no subject name, so
        /// the names are critical.
        pub fn leaf(
            &self,
            at: u64,
            subject: &str,
            issuer: &str,
            usage: ExtendedKeyUsagePurpose,
        ) -> (CertificateDer<'static>, KeyPair) {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::default();
            params.distinguished_name = rcgen::DistinguishedName::new();
            let name = match subject.contains("://") {
                true => SanType::URI(subject.try_into().unwrap()),
                false => SanType::Rfc822Name(subject.try_into().unwrap()),
            };
            params.subject_alt_names = vec![name];
            params.extended_key_usages = vec![usage];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let start = rcgen::date_time_ymd(2026, 1, 1);
            params.not_before = start + Duration::from_secs(at - START);
            params.not_after = start + Duration::from_secs(at - START + 600);
            // The issuer as 1.3.6.1.4.1.57264.1.8: a DER UTF8String.
            let said = [&[0x0c, issuer.len() as u8][..], issuer.as_bytes()].concat();
            let oid = [1, 3, 6, 1, 4, 1, 57264, 1, 8];
            params.custom_extensions = vec![CustomExtension::from_oid_content(&oid, said)];
            (params.signed_by(&key, &self.issuer).unwrap().der().clone(), key)
        }
    }

    /// What step 1 of the design asks of webpki before anything is built on it: a
    /// certificate as Fulcio's is checked to a given root, for code signing, at a given time.
    #[test]
    fn keyless_webpki_checks_code_signing_at_a_given_time() {
        let (authority, other) = (Authority::new(), Authority::new());
        let at = START + 3_600;
        let issuer = "https://token.actions.githubusercontent.com";
        let (leaf, _) = authority.leaf(at, "dev@example.test", issuer, ExtendedKeyUsagePurpose::CodeSigning);
        let check = |leaf: &CertificateDer, root: &CertificateDer, when: u64| {
            let anchor = webpki::anchor_from_trusted_cert(root).unwrap();
            let algorithms = [webpki::ring::ECDSA_P256_SHA256, webpki::ring::ECDSA_P384_SHA384];
            let cert = webpki::EndEntityCert::try_from(leaf).unwrap();
            cert.verify_for_usage(
                &algorithms,
                &[anchor],
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(when)),
                webpki::KeyUsage::required(CODE_SIGNING),
                None,
                None,
            )
            .map(|_| ())
        };
        // Within its ten minutes, by its authority: good, its critical names and the
        // authority's own extension notwithstanding.
        assert_eq!(check(&leaf, &authority.root, at + 300), Ok(()));
        // A second before, or after: not.
        assert!(matches!(
            check(&leaf, &authority.root, at - 1),
            Err(webpki::Error::CertNotValidYet { .. })
        ));
        assert!(matches!(
            check(&leaf, &authority.root, at + 601),
            Err(webpki::Error::CertExpired { .. })
        ));
        // Another authority's root: not.
        assert!(check(&leaf, &other.root, at + 300).is_err());
        // Not for code signing: not.
        let (web, _) = authority.leaf(at, "dev@example.test", issuer, ExtendedKeyUsagePurpose::ServerAuth);
        assert!(matches!(
            check(&web, &authority.root, at + 300),
            Err(webpki::Error::RequiredEkuNotFoundContext(_))
        ));
        // An authority's own certificate is no signer's.
        assert!(check(&authority.root, &authority.root, at + 300).is_err());
        // And a URI as its name is read the same.
        let workflow = "https://github.com/acme/tool/.github/workflows/release.yml@refs/heads/main";
        let (uri, _) = authority.leaf(at, workflow, issuer, ExtendedKeyUsagePurpose::CodeSigning);
        assert_eq!(check(&uri, &authority.root, at + 300), Ok(()));
    }

    pub fn pem_of(label: &str, der: &[u8]) -> String {
        let text = STANDARD.encode(der);
        let lines: Vec<&str> = text
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect();
        format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
    }

    /// A transparency log as Rekor v1 is: a P-256 key that promises when it saw an entry.
    pub struct Log {
        pair: EcdsaKeyPair,
        pub pem: String,
        pub id: String,
    }

    impl Log {
        pub fn new() -> Log {
            let rng = SystemRandom::new();
            let made = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, made.as_ref(), &rng).unwrap();
            let der = [P256, pair.public_key().as_ref()].concat();
            Log {
                pem: pem_of("PUBLIC KEY", &der),
                id: hex(&sha256(&der)),
                pair,
            }
        }

        /// The log's promise over `body`, seen at `time`, as log `id` says it is.
        pub fn promise(&self, body: &[u8], time: u64, id: &str) -> Vec<u8> {
            let promised = format!(
                r#"{{"body":"{}","integratedTime":{time},"logID":"{id}","logIndex":7}}"#,
                STANDARD.encode(body)
            );
            self.pair
                .sign(&SystemRandom::new(), promised.as_bytes())
                .unwrap()
                .as_ref()
                .to_vec()
        }
    }

    fn sign(key: &KeyPair, bytes: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.serialize_der(), &rng).unwrap();
        pair.sign(&rng, bytes).unwrap().as_ref().to_vec()
    }

    pub const ISSUED: &str = "https://token.actions.githubusercontent.com";
    pub const WHO: &str = "https://github.com/acme/tool/.github/workflows/release.yml@refs/heads/main";

    /// What a bundle is made of, each part of which a test may change.
    pub struct Making<'a> {
        pub authority: &'a Authority,
        pub subject: &'a str,
        pub usage: ExtendedKeyUsagePurpose,
        /// When the certificate starts, and when the log saw the signature.
        pub at: u64,
        pub seen: u64,
        /// The digest the statement names.
        pub digest: &'a str,
        pub log: &'a Log,
    }

    impl Making<'_> {
        pub fn new<'a>(authority: &'a Authority, log: &'a Log, digest: &'a str) -> Making<'a> {
            Making {
                authority,
                log,
                digest,
                subject: WHO,
                usage: ExtendedKeyUsagePurpose::CodeSigning,
                at: START,
                seen: START + 60,
            }
        }

        /// A bundle as cosign 3 writes one for an image.
        pub fn bundle(&self) -> Value {
            let (cert, key) = self.authority.leaf(self.at, self.subject, ISSUED, self.usage.clone());
            let statement = serde_json::json!({
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{ "digest": { "sha256": self.digest.trim_start_matches("sha256:") } }],
                "predicateType": "https://sigstore.dev/cosign/sign/v1",
                "predicate": {},
            });
            let payload = statement.to_string().into_bytes();
            let kind = "application/vnd.in-toto+json";
            let signature = sign(&key, &pae(kind, &payload));
            let body = serde_json::json!({
                "apiVersion": "0.0.1", "kind": "dsse",
                "spec": {
                    "envelopeHash": { "algorithm": "sha256", "value": hex(&sha256(b"(not read)")) },
                    "payloadHash": { "algorithm": "sha256", "value": hex(&sha256(&payload)) },
                    "signatures": [{
                        "signature": STANDARD.encode(&signature),
                        "verifier": STANDARD.encode(pem_of("CERTIFICATE", &cert)),
                    }],
                },
            });
            let body = body.to_string().into_bytes();
            let id = hex_to_base64(&self.log.id);
            serde_json::json!({
                "mediaType": BUNDLE,
                "verificationMaterial": {
                    "certificate": { "rawBytes": STANDARD.encode(&cert) },
                    "tlogEntries": [{
                        "logIndex": "7",
                        "logId": { "keyId": id },
                        "kindVersion": { "kind": "dsse", "version": "0.0.1" },
                        "integratedTime": self.seen.to_string(),
                        "inclusionPromise": {
                            "signedEntryTimestamp": STANDARD.encode(self.log.promise(&body, self.seen, &self.log.id)),
                        },
                        "canonicalizedBody": STANDARD.encode(&body),
                    }],
                },
                "dsseEnvelope": {
                    "payload": STANDARD.encode(&payload),
                    "payloadType": kind,
                    "signatures": [{ "sig": STANDARD.encode(&signature), "keyid": "" }],
                },
            })
        }

        /// The same signature as cosign 2 keeps it under the tag `sha256-HEX.sig`: the
        /// signed text, and the layer's annotations.
        pub fn tagged(&self) -> (Vec<u8>, Value) {
            let (cert, key) = self.authority.leaf(self.at, self.subject, ISSUED, self.usage.clone());
            let text = serde_json::json!({
                "critical": {
                    "identity": { "docker-reference": "registry.test/tool" },
                    "image": { "docker-manifest-digest": self.digest },
                    "type": "cosign container image signature",
                },
                "optional": null,
            });
            let text = text.to_string().into_bytes();
            let signature = sign(&key, &text);
            let cert = pem_of("CERTIFICATE", &cert);
            let body = serde_json::json!({
                "apiVersion": "0.0.1", "kind": "hashedrekord",
                "spec": {
                    "data": { "hash": { "algorithm": "sha256", "value": hex(&sha256(&text)) } },
                    "signature": {
                        "content": STANDARD.encode(&signature),
                        "publicKey": { "content": STANDARD.encode(&cert) },
                    },
                },
            });
            let body = body.to_string().into_bytes();
            let promise = serde_json::json!({
                "SignedEntryTimestamp": STANDARD.encode(self.log.promise(&body, self.seen, &self.log.id)),
                "Payload": {
                    "body": STANDARD.encode(&body),
                    "integratedTime": self.seen,
                    "logIndex": 7,
                    "logID": self.log.id,
                },
            });
            let notes = serde_json::json!({
                "dev.cosignproject.cosign/signature": STANDARD.encode(&signature),
                "dev.sigstore.cosign/certificate": cert,
                "dev.sigstore.cosign/bundle": promise.to_string(),
            });
            (text, notes)
        }
    }

    fn hex_to_base64(hex: &str) -> String {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect();
        STANDARD.encode(bytes)
    }

    /// An identity's text, as a rule gives it.
    pub fn named(subject: &str, issuer: &str, authority: &Authority, log: &Log) -> String {
        serde_json::json!({
            "issuer": issuer,
            "subject": subject,
            "authority": [pem_of("CERTIFICATE", &authority.root)],
            "log": log.pem,
        })
        .to_string()
    }

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn verdict(bundle: &Value, digest: &str, who: &str) -> std::result::Result<(), String> {
        let signed = super::bundle(bundle.to_string().as_bytes())?;
        check(&signed, digest, &identity(who).unwrap())
    }

    #[test]
    fn keyless_signatures_pass_only_for_whom_the_rule_names() {
        let (authority, log) = (Authority::new(), Log::new());
        let who = named(WHO, ISSUED, &authority, &log);
        let made = Making::new(&authority, &log, DIGEST);
        let good = made.bundle();
        assert_eq!(verdict(&good, DIGEST, &who), Ok(()));
        // As kept under the tag, too.
        let (text, notes) = made.tagged();
        let note = |key: &str| notes[key].as_str().unwrap();
        let signature = STANDARD.decode(note("dev.cosignproject.cosign/signature")).unwrap();
        let tagged = |notes_bundle: Option<&str>| {
            let signed = tagged(
                &text,
                signature.clone(),
                note("dev.sigstore.cosign/certificate"),
                notes_bundle,
            )?;
            check(&signed, DIGEST, &identity(&who).unwrap())
        };
        assert_eq!(tagged(Some(note("dev.sigstore.cosign/bundle"))), Ok(()));
        assert_eq!(tagged(None), Err("it has no entry in a log".into()));

        let refused = |bundle: &Value, digest: &str, who: &str, why: &str| {
            let said = verdict(bundle, digest, who).unwrap_err();
            assert!(said.contains(why), "expected `{why}`, got `{said}`");
        };
        // Another subject; another issuer.
        refused(
            &good,
            DIGEST,
            &named("someone@example.test", ISSUED, &authority, &log),
            &format!("it was signed by {WHO} ({ISSUED})"),
        );
        refused(
            &good,
            DIGEST,
            &named(WHO, "https://accounts.example.test", &authority, &log),
            "it was signed by",
        );
        // A certificate of another authority.
        let other = Authority::new();
        refused(
            &good,
            DIGEST,
            &named(WHO, ISSUED, &other, &log),
            "not from the authority named",
        );
        // A certificate not for code signing.
        let web = Making {
            usage: ExtendedKeyUsagePurpose::ServerAuth,
            ..Making::new(&authority, &log, DIGEST)
        };
        refused(&web.bundle(), DIGEST, &who, "not for code signing");
        // A signature of another image.
        refused(
            &Making::new(&authority, &log, OTHER).bundle(),
            DIGEST,
            &who,
            "a signature of another image",
        );
        // No log entry.
        let mut none = good.clone();
        none["verificationMaterial"]["tlogEntries"] = serde_json::json!([]);
        refused(&none, DIGEST, &who, "no entry in a log");
        // A log entry with no promise (Rekor v2's).
        let mut v2 = good.clone();
        v2["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"] = Value::Null;
        refused(&v2, DIGEST, &who, "Rekor v2");
        // A log entry by another key: a log of its own, or a promise forged as this log's.
        let forger = Log::new();
        refused(
            &Making::new(&authority, &forger, DIGEST).bundle(),
            DIGEST,
            &who,
            "from another log",
        );
        let mut forged = good.clone();
        let entry = &mut forged["verificationMaterial"]["tlogEntries"][0];
        let body = STANDARD.decode(entry["canonicalizedBody"].as_str().unwrap()).unwrap();
        entry["inclusionPromise"]["signedEntryTimestamp"] =
            STANDARD.encode(forger.promise(&body, START + 60, &log.id)).into();
        refused(&forged, DIGEST, &who, "not signed by the log's key");
        // A log time outside the certificate's ten minutes: after, and before.
        refused(
            &Making {
                seen: START + 601,
                ..Making::new(&authority, &log, DIGEST)
            }
            .bundle(),
            DIGEST,
            &who,
            "outside its certificate's time",
        );
        refused(
            &Making {
                at: START + 120,
                ..Making::new(&authority, &log, DIGEST)
            }
            .bundle(),
            DIGEST,
            &who,
            "outside its certificate's time",
        );
        // A log entry for another signature: another bundle's entry, promise and all.
        let mut swapped = good.clone();
        let theirs = Making::new(&authority, &log, DIGEST).bundle();
        swapped["verificationMaterial"]["tlogEntries"] = theirs["verificationMaterial"]["tlogEntries"].clone();
        refused(&swapped, DIGEST, &who, "of another signature");
        // A promise moved in time is no longer the log's.
        let mut moved = good.clone();
        moved["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = (START + 30).to_string().into();
        refused(&moved, DIGEST, &who, "not signed by the log's key");
    }

    /// An authority given as its root and an intermediate: a signature through the
    /// intermediate passes while the intermediate is good, and not once it is retired.
    #[test]
    fn keyless_intermediates_are_held_to_their_own_time() {
        let (authority, log) = (Authority::new(), Log::new());
        let who = |intermediate: &Authority| {
            let said = serde_json::json!({
                "issuer": ISSUED, "subject": WHO, "log": log.pem,
                "authority": [pem_of("CERTIFICATE", &authority.root), pem_of("CERTIFICATE", &intermediate.root)],
            });
            identity(&said.to_string()).unwrap()
        };
        for (until, passes) in [(2030, true), (2025, false)] {
            let intermediate = authority.intermediate(until);
            let bundle = Making::new(&intermediate, &log, DIGEST).bundle();
            let signed = super::bundle(bundle.to_string().as_bytes()).unwrap();
            let said = check(&signed, DIGEST, &who(&intermediate));
            assert_eq!(said.is_ok(), passes, "{until}: {said:?}");
        }
    }

    #[test]
    fn keyless_identities_that_are_not_ones_are_said_to_be_not() {
        let (authority, log) = (Authority::new(), Log::new());
        let good = named(WHO, ISSUED, &authority, &log);
        assert!(identity(&good).unwrap().id.starts_with(&format!("{WHO} ({ISSUED}) #")));
        let mut said: Value = serde_json::from_str(&good).unwrap();
        for (key, value, why) in [
            ("issuer", Value::Null, "names its `issuer` and its `subject`"),
            ("subject", "".into(), "names its `issuer` and its `subject`"),
            ("authority", serde_json::json!([]), "gives 1 to 4 certificates"),
            ("authority", serde_json::json!(["AAAA"]), "holds what is no certificate"),
            ("log", "not a key".into(), "is not an ECDSA P-256 public key"),
            (
                "log",
                pem_of("CERTIFICATE", &authority.root).into(),
                "is not an ECDSA P-256 public key",
            ),
        ] {
            let kept = std::mem::replace(&mut said[key], value);
            let refused = identity(&said.to_string())
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(refused.contains(why), "{key}: {refused}");
            said[key] = kept;
        }
    }

    /// The reader of a certificate's names, fed every cut and many altered certificates: it
    /// says none or the names, and never panics.
    #[test]
    fn keyless_names_of_a_certificate_cut_or_altered() {
        let authority = Authority::new();
        let (cert, _) = authority.leaf(START, WHO, ISSUED, ExtendedKeyUsagePurpose::CodeSigning);
        assert_eq!(names(&cert), Some((WHO.to_string(), ISSUED.to_string())));
        let (mail, _) = authority.leaf(START, "dev@example.test", ISSUED, ExtendedKeyUsagePurpose::CodeSigning);
        assert_eq!(names(&mail).unwrap().0, "dev@example.test");
        for cut in 0..cert.len() {
            let _ = names(&cert[..cut]);
        }
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..20_000 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let mut altered = cert.to_vec();
            let at = (seed >> 33) as usize % altered.len();
            altered[at] = (seed >> 13) as u8;
            let _ = names(&altered);
        }
        // A DNS name, or two names, is no one this reads.
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["example.test".to_string()]).unwrap();
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 57264, 1, 8],
            [&[0x0c, ISSUED.len() as u8][..], ISSUED.as_bytes()].concat(),
        )];
        let dns = params.signed_by(&key, &authority.issuer).unwrap();
        assert_eq!(names(dns.der()), None);
        params
            .subject_alt_names
            .push(SanType::Rfc822Name("dev@example.test".try_into().unwrap()));
        let two = params.signed_by(&key, &authority.issuer).unwrap();
        assert_eq!(names(two.der()), None);
    }

    /// A bundle a real cosign wrote, with the public instance's authority (Fulcio) and log
    /// (Rekor v1), checked against that instance's own roots as a rule would give them. It is
    /// an attestation, not a signature: every check holds up to what it says, and that is
    /// refused for what it is.
    ///
    /// (Both files are sigstore/cosign's `pkg/cosign/testdata/oci-attestation.sigstore.json`
    /// and `trusted_root_pgi.json`, Apache-2.0.)
    #[test]
    fn keyless_real_bundle_from_cosign_verifies_against_its_own_roots() {
        let bytes = include_bytes!("testdata/cosign-attestation.sigstore.json");
        let root: Value = serde_json::from_str(include_str!("testdata/cosign-trusted-root.json")).unwrap();
        let raw = |value: &Value| STANDARD.decode(value["rawBytes"].as_str().unwrap()).unwrap();
        let authorities = root["certificateAuthorities"].as_array().unwrap();
        let chains = authorities
            .iter()
            .flat_map(|ca| ca["certChain"]["certificates"].as_array().unwrap());
        let authority: Vec<String> = chains.map(|cert| pem_of("CERTIFICATE", &raw(cert))).collect();
        let log = pem_of("PUBLIC KEY", &raw(&root["tlogs"][0]["publicKey"]));
        let signed = bundle(bytes).unwrap();
        let (subject, issuer) = names(&signed.cert).unwrap();
        // (Its signer signed in with GitHub, as an email address.)
        assert_eq!(issuer, "https://github.com/login/oauth");
        assert!(subject.contains('@'), "{subject}");
        let who = |subject: &str| {
            let said = serde_json::json!({ "issuer": issuer, "subject": subject, "authority": authority, "log": log });
            identity(&said.to_string()).unwrap()
        };
        let statement: Value = serde_json::from_slice(&signed.payload).unwrap();
        let digest = format!(
            "sha256:{}",
            statement["subject"][0]["digest"]["sha256"].as_str().unwrap()
        );
        // Its log's promise, the entry's binding, its certificate at the log's time, whom it
        // names and its signature all hold: only what it says is not a signature.
        let said = check(&signed, &digest, &who(&subject)).unwrap_err();
        assert_eq!(
            said,
            "it is no signature but a statement of another kind (https://cosign.sigstore.dev/attestation/v1)"
        );
        // Another subject is refused before that; a promise altered by a bit, before that.
        let said = check(&signed, &digest, &who("someone@example.test")).unwrap_err();
        assert_eq!(said, format!("it was signed by {subject} ({issuer})"));
        let mut altered: Value = serde_json::from_slice(bytes).unwrap();
        let entry = &mut altered["verificationMaterial"]["tlogEntries"][0];
        entry["logIndex"] = (number(&entry["logIndex"]).unwrap() + 1).to_string().into();
        let said = check(
            &bundle(altered.to_string().as_bytes()).unwrap(),
            &digest,
            &who(&subject),
        )
        .unwrap_err();
        assert_eq!(said, "its log entry's promise is not signed by the log's key");
    }
}
