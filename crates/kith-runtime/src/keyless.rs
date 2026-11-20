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
/// RFC 3161's OIDs: id-kp-timeStamping (1.3.6.1.5.5.7.3.8), SignedData (1.2.840.113549.1.7.2),
/// TSTInfo (1.2.840.113549.1.9.16.1.4), the signed attribute messageDigest
/// (1.2.840.113549.1.9.4), SHA-256 and SHA-384 (2.16.840.1.101.3.4.2.1 and .2).
const TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const TST_INFO: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04];
const MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA384_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
#[cfg(test)]
const CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
/// The most bytes of a timestamp, certificates in it, and levels of DER nesting that are read.
const STAMP: usize = 16 * 1024;
const STAMP_CERTS: usize = 4;
const STAMP_DEPTH: usize = 8;

/// Who an image may be signed by without a kept key: whom the authority certified, as whom
/// the issuer signed them in, and the authority's certificates and the log's key that say so.
pub struct Identity {
    /// The identity as it is remembered: its names, and a hash of all it was given.
    pub id: String,
    issuer: String,
    subject: String,
    authority: Vec<CertificateDer<'static>>,
    /// The roots of the timestamp authority whose RFC 3161 timestamps the rule takes (none: it
    /// takes the log's promise alone, and refuses a bundle that is of Rekor v2).
    tsa: Vec<CertificateDer<'static>>,
    /// The log's key (its point), and its id: SHA-256 of its DER, in hex.
    log: Vec<u8>,
    log_id: String,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes).as_ref().to_vec()
}

/// A PEM text's bytes (or the base64 alone), whatever its kind.
fn pem(text: &str) -> Option<Vec<u8>> {
    let lines = text.lines().filter(|line| !line.trim_start().starts_with("-----"));
    let base64: String = lines.flat_map(str::chars).filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(base64).ok().filter(|der| !der.is_empty())
}

/// 1 to `AUTHORITY` PEM certificates, as the identity's field `key` gives them: that and the
/// first thing wrong, said.
fn certificates(given: &Value, key: &str, subject: &str) -> Result<Vec<CertificateDer<'static>>> {
    let given = given.as_array().map(Vec::as_slice).unwrap_or_default();
    if given.is_empty() || given.len() > AUTHORITY {
        let of = if key == "tsa" {
            "as its `tsa`"
        } else {
            "of its authority"
        };
        return err(format!(
            "signedBy: the identity {subject} gives 1 to {AUTHORITY} certificates {of}"
        ));
    }
    let mut certs = Vec::new();
    for cert in given {
        let der = cert.as_str().and_then(pem).map(CertificateDer::from);
        match der.filter(|der| webpki::anchor_from_trusted_cert(der).is_ok()) {
            Some(der) => certs.push(der),
            None => {
                return err(format!(
                    "signedBy: the identity {subject}'s `{key}` holds what is no certificate"
                ));
            }
        }
    }
    Ok(certs)
}

/// Reads an identity as a rule gives it (its JSON text: `issuer`, `subject`, `authority`, `log`,
/// and a `tsa` if the rule takes a timestamp authority's word on when).
pub fn identity(said: &str) -> Result<Identity> {
    let said: Value = serde_json::from_str(said).unwrap_or_default();
    let text = |key: &str| said[key].as_str().filter(|text| !text.is_empty()).map(String::from);
    let (Some(issuer), Some(subject)) = (text("issuer"), text("subject")) else {
        return err("signedBy: an identity names its `issuer` and its `subject`");
    };
    let authority = certificates(&said["authority"], "authority", &subject)?;
    // (A rule stored before there was a `tsa` has none, or null: a field given as anything else is read.)
    let tsa = match said.get("tsa") {
        None | Some(Value::Null) => Vec::new(),
        Some(given) => certificates(given, "tsa", &subject)?,
    };
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
    // (The tsa's roots are in the hash only when given, after a mark: an identity without one has
    // the id it had before there was a field, and one with is not another's with the roots moved.)
    let marked = (!tsa.is_empty()).then_some(b"tsa".as_slice());
    let all: Vec<u8> = all
        .chain(authority.iter().map(|der| der.as_ref()))
        .chain(marked)
        .chain(tsa.iter().map(|der| der.as_ref()))
        .flat_map(sha256)
        .collect();
    Ok(Identity {
        id: format!("{subject} ({issuer}) #{}", &hex(&sha256(&all))[..32]),
        log: point.to_vec(),
        issuer,
        subject,
        authority,
        tsa,
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
    /// A Rekor v2 bundle's RFC 3161 timestamp (a DER TimeStampResp) over the signature, and the
    /// time it was found to give once `timestamp` checked it against the TSA.
    stamp: Option<Vec<u8>>,
    stamped: Option<i64>,
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
    let stamp = base64(&material["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"]);
    let promise = match entries {
        [] => None,
        // Rekor v2's: no promise, the timestamp is what says when.
        [entry, ..] if stamp.is_some() && entry["inclusionPromise"].is_null() => None,
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
            Some(read().ok_or(match (promise.is_null(), stamp.is_some()) {
                (true, true) => "its log entry's promise is not one kith can read (and the bundle has a timestamp)",
                (true, false) => {
                    "its log entry has no promise from the log, nor has the bundle a timestamp (a log of Rekor v2)"
                }
                (false, _) => "its log entry is not one kith can read",
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
        stamp,
        stamped: None,
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
        stamp: None,
        stamped: None,
    })
}

/// Whether `signed` is a signature of the image `digest` by `who`; why not, if not.
pub fn check(signed: &Signed, digest: &str, who: &Identity) -> std::result::Result<(), String> {
    // When it was signed: the log's word (its promise, checked here), or else a timestamp's
    // (checked against its TSA by `timestamp` before this).
    let (time, said) = match (&signed.promise, signed.stamped) {
        (Some(promise), _) => {
            promised(signed, promise, who)?;
            (promise.time, "the log saw it")
        }
        (None, Some(time)) => (time, "the timestamp is of"),
        (None, None) => return Err("it has no entry in a log".into()),
    };
    // The certificate, from the authority, for code signing, at that time.
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
    let at = u64::try_from(time).map_err(|_| "its signing time is before 1970")?;
    let when = UnixTime::since_unix_epoch(std::time::Duration::from_secs(at));
    let usage = webpki::KeyUsage::required(CODE_SIGNING);
    if let Err(e) = leaf.verify_for_usage(&algorithms, &anchors, &intermediates, when, usage, None, None) {
        return Err(match e {
            webpki::Error::CertNotValidYet { .. } | webpki::Error::CertExpired { .. } => {
                format!("{said} {at}, outside its certificate's time")
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

/// That a log's `promise` is by the log `who` names, of this signature (and so when it was
/// seen is the log's word).
fn promised(signed: &Signed, promise: &Promise, who: &Identity) -> std::result::Result<(), String> {
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
    entry(signed, &promise.body)
}

/// Whether `signed` is a signature of the image `digest` by `who`, with the timestamp the rule
/// asks for: a rule without a `tsa` takes the log's promise as before and refuses a bundle of
/// Rekor v2 (a timestamp and no promise), naming the field; one with takes only a bundle whose
/// timestamp is from one of its roots, a v1 bundle's too (its time is still the log's).
/// Why not, if not. What a bundle was found to be timed by a rule is not kept for the next.
pub fn verify(signed: &mut Signed, digest: &str, who: &Identity) -> std::result::Result<(), String> {
    signed.stamped = None;
    if who.tsa.is_empty() {
        if signed.promise.is_none() && signed.stamp.is_some() {
            return Err(
                "its log is Rekor v2 (a timestamp and no promise), and the rule names no `tsa`: the root of \
                 the timestamp authority to take its time from"
                    .into(),
            );
        }
        return check(signed, digest, who);
    }
    if signed.stamp.is_none() {
        return Err("the rule names a `tsa`, and the bundle has no timestamp from it".into());
    }
    let mut refused = Vec::new();
    for root in &who.tsa {
        match timestamp(signed, root) {
            Ok(_) => return check(signed, digest, who),
            Err(why) => refused.push(why),
        }
    }
    refused.dedup();
    Err(refused.join("; "))
}

/// Checks a Rekor v2 bundle's RFC 3161 timestamp against the root `tsa` (a certificate's
/// DER) of the timestamp authority a rule names; on success the bundle is taken to have been
/// signed at the timestamp's time (`check` then holds its certificate to that), which is
/// returned. Why not, if not.
fn timestamp(signed: &mut Signed, tsa: &[u8]) -> std::result::Result<i64, String> {
    let time = stamped(signed, tsa)?;
    signed.stamped = Some(time);
    Ok(time)
}

/// What an RFC 3161 timestamp (a TimeStampResp) holds, read and not yet checked.
struct Stamp<'a> {
    /// The certificates it carries, each whole.
    certs: Vec<&'a [u8]>,
    /// The TSTInfo (DER) it says, and the digest of it that the signed attributes say.
    content: &'a [u8],
    message_digest: &'a [u8],
    algorithm: &'static ring::digest::Algorithm,
    /// The signed attributes as what is signed: a SET OF, not the [0] they are written as.
    attributes: Vec<u8>,
    signature: &'a [u8],
    /// The SHA-256 the TSTInfo says it is of, and its time (seconds since 1970).
    imprint: &'a [u8],
    time: i64,
}

/// One DER element of kind `tag` at the start of `input`: its contents, and what follows.
fn expect(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (got, contents, rest) = element(input)?;
    (got == tag).then_some((contents, rest))
}

/// Seconds since 1970 of a GeneralizedTime as DER has it: YYYYMMDDHHMMSS, a fraction of a
/// second perhaps, and Z.
fn unix(text: &[u8]) -> Option<i64> {
    let text = text.strip_suffix(b"Z")?;
    let (whole, fraction) = match text.iter().position(|&byte| byte == b'.') {
        Some(at) => (text.get(..at)?, text.get(at + 1..)?),
        None => (text, &[][..]),
    };
    let digits = |part: &[u8]| part.iter().all(u8::is_ascii_digit);
    if whole.len() != 14 || !digits(whole) || !digits(fraction) || (fraction.is_empty() && text.len() != 14) {
        return None;
    }
    let number = |from: usize, to: usize| {
        let part = whole.get(from..to)?;
        Some(part.iter().fold(0i64, |n, &digit| n * 10 + i64::from(digit - b'0')))
    };
    let (year, month, day) = (number(0, 4)?, number(4, 6)?, number(6, 8)?);
    let (hour, minute, second) = (number(8, 10)?, number(10, 12)?, number(12, 14)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let longest = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let longest = *longest.get(usize::try_from(month - 1).ok()?)?;
    if year < 1970 || !(1..=longest).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days since 1970-01-01 (the civil calendar's, March first as a year's start).
    let y = if month <= 2 { year - 1 } else { year };
    let (era, yoe) = (y / 400, y % 400);
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Whether a timestamp (DER) is within the limits: at most STAMP bytes, constructed elements
/// nested at most STAMP_DEPTH deep (the response is depth 0), at most STAMP_CERTS certificates,
/// and no BER. Else why not, to follow "its timestamp".
fn limits(der: &[u8]) -> std::result::Result<(), &'static str> {
    if der.len() > STAMP {
        return Err("is over 16 KiB");
    }
    nest(der, 0)
}

/// The elements of `input`, each at `depth`, and what they hold. The certificates (the SignedData's
/// [0], at depth 4) are counted and not entered, nor are an attribute's values (a SET after its
/// OID): real tokens carry deep ones there, and the reader takes only the digest from them.
fn nest(input: &[u8], depth: usize) -> std::result::Result<(), &'static str> {
    let (mut rest, mut last) = (input, 0);
    while !rest.is_empty() {
        let Some((tag, contents, after)) = element(rest) else {
            return Err(match rest.get(1) {
                Some(0x80) => "is BER, not DER (an indefinite length)",
                _ => "cannot be read",
            });
        };
        if tag == 0xa0 && depth == 4 {
            if elements(contents).count() > STAMP_CERTS {
                return Err("holds more than 4 certificates");
            }
        } else if tag & 0x20 != 0 && !(tag == 0x31 && last == 0x06) {
            if depth > STAMP_DEPTH {
                return Err("nests deeper than 8");
            }
            nest(contents, depth + 1)?;
        }
        (rest, last) = (after, tag);
    }
    Ok(())
}

/// Reads a TimeStampResp: granted, a SignedData of one SignerInfo with signed attributes and
/// a TSTInfo of a SHA-256 imprint. None for anything else, or bytes cut or past its end.
fn stamp(der: &[u8]) -> Option<Stamp<'_>> {
    limits(der).ok()?;
    let (response, rest) = expect(der, 0x30)?;
    let (status, token) = expect(response, 0x30)?;
    let (status, _) = expect(status, 0x02)?;
    // (Granted, or granted with modifications.)
    if !rest.is_empty() || !matches!(status, [0] | [1]) {
        return None;
    }
    let (token, rest) = expect(token, 0x30)?;
    let (kind, explicit) = expect(token, 0x06)?;
    let (explicit, _) = expect(explicit, 0xa0)?;
    let (signed, _) = expect(explicit, 0x30)?;
    if !rest.is_empty() || kind != SIGNED_DATA {
        return None;
    }
    let (_version, rest) = expect(signed, 0x02)?;
    let (_algorithms, rest) = expect(rest, 0x31)?;
    let (encap, rest) = expect(rest, 0x30)?;
    let (kind, encap) = expect(encap, 0x06)?;
    let (encap, _) = expect(encap, 0xa0)?;
    let (content, _) = expect(encap, 0x04)?;
    if kind != TST_INFO {
        return None;
    }
    let mut certs = Vec::new();
    let mut rest = rest;
    if let Some((0xa0, mut left, after)) = element(rest) {
        while !left.is_empty() {
            let (0x30, _, after) = element(left)? else { return None };
            if certs.len() == STAMP_CERTS {
                return None;
            }
            certs.push(left.get(..left.len() - after.len())?);
            left = after;
        }
        rest = after;
    }
    // (Revocation lists, if any, are not read.)
    if let Some((0xa1, _, after)) = element(rest) {
        rest = after;
    }
    let (infos, rest) = expect(rest, 0x31)?;
    let (info, more) = expect(infos, 0x30)?;
    if !rest.is_empty() || !more.is_empty() {
        return None;
    }
    let (_version, rest) = expect(info, 0x02)?;
    let (_sid, _, rest) = element(rest)?;
    let (hash, rest) = expect(rest, 0x30)?;
    let (oid, _) = expect(hash, 0x06)?;
    let algorithm = match oid {
        SHA256_OID => &ring::digest::SHA256,
        SHA384_OID => &ring::digest::SHA384,
        _ => return None,
    };
    let (0xa0, attributes, after) = element(rest)? else {
        return None;
    };
    let written = rest.get(..rest.len() - after.len())?;
    let attributes_der = [&[0x31][..], written.get(1..)?].concat();
    let (_signature_algorithm, after) = expect(after, 0x30)?;
    let (signature, _) = expect(after, 0x04)?;
    // The attribute messageDigest, once.
    let mut digest = None;
    for attribute in elements(attributes) {
        let (0x30, attribute) = attribute? else { return None };
        let (oid, values) = expect(attribute, 0x06)?;
        if oid == MESSAGE_DIGEST {
            let (values, _) = expect(values, 0x31)?;
            let (value, _) = expect(values, 0x04)?;
            if digest.replace(value).is_some() {
                return None;
            }
        }
    }
    // The TSTInfo: its imprint, hashed with SHA-256, and its time.
    let (tst, _) = expect(content, 0x30)?;
    let (_version, tst) = expect(tst, 0x02)?;
    let (_policy, _, tst) = element(tst)?;
    let (imprint, tst) = expect(tst, 0x30)?;
    let (_serial, tst) = expect(tst, 0x02)?;
    let (time, _) = expect(tst, 0x18)?;
    let (hashed_with, imprint) = expect(imprint, 0x30)?;
    let (oid, _) = expect(hashed_with, 0x06)?;
    let (hashed, _) = expect(imprint, 0x04)?;
    if oid != SHA256_OID {
        return None;
    }
    Some(Stamp {
        certs,
        content,
        message_digest: digest?,
        algorithm,
        attributes: attributes_der,
        signature,
        imprint: hashed,
        time: unix(time)?,
    })
}

/// Whether `signed`'s timestamp is of the signature, by a certificate that chains to `tsa`
/// for timestamping at the time it gives; that time.
fn stamped(signed: &Signed, tsa: &[u8]) -> std::result::Result<i64, String> {
    let der = signed.stamp.as_deref().ok_or("it has no timestamp")?;
    limits(der).map_err(|why| format!("its timestamp {why}"))?;
    let read = stamp(der).ok_or("its timestamp cannot be read")?;
    let carried: Vec<CertificateDer> = read.certs.iter().map(|der| CertificateDer::from(*der)).collect();
    // The signer is the certificate whose key signed the attributes.
    let algorithms = [
        webpki::ring::ECDSA_P256_SHA256,
        webpki::ring::ECDSA_P384_SHA384,
        webpki::ring::ECDSA_P256_SHA384,
        webpki::ring::ECDSA_P384_SHA256,
        webpki::ring::RSA_PKCS1_2048_8192_SHA256,
        webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    ];
    let by = |cert: &webpki::EndEntityCert| {
        let signed = |algorithm| cert.verify_signature(algorithm, &read.attributes, read.signature);
        algorithms.iter().any(|&algorithm| signed(algorithm).is_ok())
    };
    let signer = carried
        .iter()
        .find(|der| webpki::EndEntityCert::try_from(*der).is_ok_and(|cert| by(&cert)))
        .ok_or("its timestamp's signature is not by its certificate's key")?;
    let leaf = webpki::EndEntityCert::try_from(signer)
        .map_err(|e| format!("its timestamp's certificate cannot be read ({e})"))?;
    // The attributes are of this content.
    if ring::digest::digest(read.algorithm, read.content).as_ref() != read.message_digest {
        return Err("its timestamp's signed attributes are not of its content".into());
    }
    // The signer chains to the TSA's root, for timestamping, when it says.
    let root = CertificateDer::from(tsa);
    let anchor =
        webpki::anchor_from_trusted_cert(&root).map_err(|_| "the timestamp authority's root is no certificate")?;
    let others: Vec<CertificateDer> = carried.iter().filter(|der| *der != signer).cloned().collect();
    let at = u64::try_from(read.time).map_err(|_| "its timestamp is of before 1970")?;
    let when = UnixTime::since_unix_epoch(std::time::Duration::from_secs(at));
    let usage = webpki::KeyUsage::required(TIME_STAMPING);
    let chain = [webpki::ring::ECDSA_P256_SHA256, webpki::ring::ECDSA_P384_SHA384];
    if let Err(e) = leaf.verify_for_usage(&chain, &[anchor], &others, when, usage, None, None) {
        return Err(match e {
            webpki::Error::CertNotValidYet { .. } | webpki::Error::CertExpired { .. } => {
                format!("its timestamp is of {at}, outside its authority's certificate's time")
            }
            webpki::Error::RequiredEkuNotFoundContext(_) => {
                "its timestamp's certificate is not for timestamping".into()
            }
            e => format!("its timestamp is not from the authority named ({e:?})"),
        });
    }
    // The imprint is a hash of this signature (the one the timestamp is for).
    if read.imprint != sha256(&signed.signature) {
        return Err("its timestamp is of another signature".into());
    }
    Ok(read.time)
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
            let len = bytes.iter().fold(0usize, |len, &byte| len << 8 | usize::from(byte));
            // DER writes a length in the fewest bytes: a long form for under 128 is BER.
            if len < 0x80 || bytes[0] == 0 {
                return None;
            }
            (len, rest)
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

    /// One DER element: `tag`, its length, `body`.
    fn der(tag: u8, body: Vec<u8>) -> Vec<u8> {
        let len = match body.len() {
            n if n < 0x80 => vec![n as u8],
            n if n < 0x100 => vec![0x81, n as u8],
            n => vec![0x82, (n >> 8) as u8, n as u8],
        };
        [vec![tag], len, body].concat()
    }

    /// A GeneralizedTime, `secs` after the tests' start (within January).
    fn generalized(secs: u64) -> String {
        format!(
            "202601{:02}{:02}{:02}{:02}Z",
            1 + secs / 86_400,
            secs / 3_600 % 24,
            secs / 60 % 60,
            secs % 60
        )
    }

    /// A TimeStampResp as a TSA writes one: a TSTInfo of the hash of `imprint`, made `at`
    /// (seconds after the start), signed by `key` whose certificate is `cert`. `fault` says
    /// what it gets wrong: "digest" (the signed attributes' messageDigest) or "signature".
    fn response(cert: &[u8], key: &KeyPair, imprint: &[u8], at: u64, fault: &str) -> Vec<u8> {
        let oid = |bytes: &[u8]| der(0x06, bytes.to_vec());
        let int = |n: u8| der(0x02, vec![n]);
        let sha256_alg = der(0x30, [oid(SHA256_OID), vec![0x05, 0]].concat());
        let tst = der(
            0x30,
            [
                int(1),
                oid(&[0x2a, 0x03, 0x04]),
                der(0x30, [sha256_alg.clone(), der(0x04, sha256(imprint))].concat()),
                int(7),
                der(0x18, generalized(at).into_bytes()),
            ]
            .concat(),
        );
        let digest = sha256(if fault == "digest" { b"another content" } else { &tst });
        let attrs = [
            der(0x30, [oid(CONTENT_TYPE), der(0x31, oid(TST_INFO))].concat()),
            der(0x30, [oid(MESSAGE_DIGEST), der(0x31, der(0x04, digest))].concat()),
        ]
        .concat();
        let over = der(0x31, attrs.clone());
        let signature = sign(
            key,
            if fault == "signature" {
                b"another attributes"
            } else {
                &over
            },
        );
        let sid = der(0x30, [der(0x30, vec![]), int(1)].concat());
        let ecdsa = der(0x30, oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
        let info = der(
            0x30,
            [
                int(1),
                sid,
                sha256_alg.clone(),
                der(0xa0, attrs),
                ecdsa,
                der(0x04, signature),
                // Unsigned attributes, which the reader skips: `levels` of nesting or a blob.
                match fault {
                    "deep" | "edge" => {
                        let levels = if fault == "deep" { 3 } else { 2 };
                        der(0xa1, (0..levels).fold(vec![5, 0], |inner, _| der(0x30, inner)))
                    }
                    "big" => der(0xa1, der(0x04, vec![0; STAMP])),
                    _ => vec![],
                },
            ]
            .concat(),
        );
        let encap = der(0x30, [oid(TST_INFO), der(0xa0, der(0x04, tst))].concat());
        let signed = der(
            0x30,
            [
                int(3),
                der(0x31, sha256_alg),
                encap,
                der(0xa0, cert.repeat(if fault == "certs" { 5 } else { 1 })),
                der(0x31, info),
            ]
            .concat(),
        );
        let token = der(0x30, [oid(SIGNED_DATA), der(0xa0, signed)].concat());
        der(0x30, [der(0x30, int(0)), token].concat())
    }

    /// A bundle of Rekor v2's kind: no promise from the log, and the TSA's timestamp over its
    /// signature instead (made by `tsa`'s certificate `cert`, `at` seconds after the start).
    fn v2(made: &Making, cert: &[u8], key: &KeyPair, imprint: Option<&[u8]>, at: u64, fault: &str) -> Value {
        let mut bundle = made.bundle();
        let signature = STANDARD
            .decode(bundle["dsseEnvelope"]["signatures"][0]["sig"].as_str().unwrap())
            .unwrap();
        let stamp = response(cert, key, imprint.unwrap_or(&signature), at, fault);
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"] = Value::Null;
        bundle["verificationMaterial"]["timestampVerificationData"] =
            serde_json::json!({ "rfc3161Timestamps": [{ "signedTimestamp": STANDARD.encode(stamp) }] });
        bundle
    }

    /// A bundle with a timestamp from the TSA root given is taken at the timestamp's time
    /// (and its certificate held to that time, not to a log's).
    #[test]
    fn a_rekor_v2_bundle_takes_its_time_from_the_tsa() {
        let (authority, tsa, log) = (Authority::new(), Authority::new(), Log::new());
        let who = named(WHO, ISSUED, &authority, &log);
        // The signer's certificate: START + 120 to START + 720. The TSA's: START + 100 to + 700.
        let made = Making {
            at: START + 120,
            ..Making::new(&authority, &log, DIGEST)
        };
        let (cert, key) = tsa.leaf(
            START + 100,
            "tsa@example.test",
            ISSUED,
            ExtendedKeyUsagePurpose::TimeStamping,
        );
        let taken = |bundle: &Value| -> std::result::Result<i64, String> {
            let mut signed = super::bundle(bundle.to_string().as_bytes())?;
            // Untimed until the TSA is asked.
            assert_eq!(
                check(&signed, DIGEST, &identity(&who).unwrap()),
                Err("it has no entry in a log".into())
            );
            let time = timestamp(&mut signed, &tsa.root)?;
            check(&signed, DIGEST, &identity(&who).unwrap())?;
            Ok(time)
        };
        // Made at START + 300: in both certificates' time.
        assert_eq!(taken(&v2(&made, &cert, &key, None, 300, "")), Ok((START + 300) as i64));
        // Made at START + 110: the TSA's certificate is good, the signer's is not yet.
        let early = v2(&made, &cert, &key, None, 110, "");
        let said = taken(&early).unwrap_err();
        assert!(said.contains("outside its certificate's time"), "{said}");
        // Without any timestamp a promise-less entry is still Rekor v2, unread.
        let mut bare = made.bundle();
        bare["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"] = Value::Null;
        let said = super::bundle(bare.to_string().as_bytes()).err().unwrap();
        assert!(said.contains("Rekor v2"), "{said}");
    }

    /// An identity's text with the `tsa` field: the roots' certificates (PEM).
    fn with_tsa(who: &str, roots: &[&CertificateDer]) -> String {
        let mut said: Value = serde_json::from_str(who).unwrap();
        said["tsa"] = roots.iter().map(|root| pem_of("CERTIFICATE", root)).collect();
        said.to_string()
    }

    /// What a rule without `tsa` and one with it make of a bundle with a log's promise (Rekor
    /// v1's), one without (Rekor v2's), and one of v1's that carries a timestamp too.
    #[test]
    fn tsa_field_decides_which_bundles_are_taken() {
        let (authority, tsa, log) = (Authority::new(), Authority::new(), Log::new());
        let who = named(WHO, ISSUED, &authority, &log);
        let made = Making {
            at: START + 120,
            seen: START + 300,
            ..Making::new(&authority, &log, DIGEST)
        };
        let (cert, key) = tsa.leaf(
            START + 100,
            "tsa@example.test",
            ISSUED,
            ExtendedKeyUsagePurpose::TimeStamping,
        );
        let (v1, v2) = (made.bundle(), v2(&made, &cert, &key, None, 300, ""));
        // v1 with a timestamp (over its own signature) as well.
        let mut both = v1.clone();
        let sig = STANDARD
            .decode(v1["dsseEnvelope"]["signatures"][0]["sig"].as_str().unwrap())
            .unwrap();
        both["verificationMaterial"]["timestampVerificationData"] = serde_json::json!({ "rfc3161Timestamps": [{ "signedTimestamp": STANDARD.encode(response(&cert, &key, &sig, 300, "")) }] });
        let verdict = |bundle: &Value, who: &str| {
            let mut signed = super::bundle(bundle.to_string().as_bytes())?;
            verify(&mut signed, DIGEST, &identity(who).unwrap())
        };
        let (without, with) = (who.clone(), with_tsa(&who, &[&tsa.root]));
        // No tsa: v1 as before, v2 refused naming the field (and not "no entry in a log").
        assert_eq!(verdict(&v1, &without), Ok(()));
        assert_eq!(verdict(&both, &without), Ok(()));
        let said = verdict(&v2, &without).unwrap_err();
        assert!(said.contains("`tsa`") && said.contains("Rekor v2"), "{said}");
        // A tsa: v2 is taken at the timestamp's time; v1 needs a timestamp too.
        assert_eq!(verdict(&v2, &with), Ok(()));
        assert_eq!(verdict(&both, &with), Ok(()));
        let said = verdict(&v1, &with).unwrap_err();
        assert!(said.contains("`tsa`") && said.contains("timestamp"), "{said}");
        // A timestamp of another authority is no timestamp: refused for v1 as for v2.
        let other = with_tsa(&who, &[&Authority::new().root]);
        for bundle in [&both, &v2] {
            let said = verdict(bundle, &other).unwrap_err();
            assert!(said.contains("not from the authority named"), "{said}");
        }
        // The authority's own leaf given as the root is no root: its timestamp is refused.
        let said = verdict(&v2, &with_tsa(&who, &[&cert])).unwrap_err();
        assert!(said.contains("not from the authority named"), "{said}");
        // An unreadable promise next to a timestamp is said so, not "no timestamp".
        let mut broken = v2.clone();
        broken["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"] = serde_json::json!({});
        let said = super::bundle(broken.to_string().as_bytes()).err().unwrap();
        assert!(said.contains("promise is not one kith can read"), "{said}");
        // Any of up to four roots may be the authority's.
        let roots = with_tsa(&who, &[&Authority::new().root, &tsa.root]);
        assert_eq!(verdict(&v2, &roots), Ok(()));
        // `verify` resets what a previous identity found (this alone does not pin that: the
        // no-tsa branch never reads `stamped`, so the reset is belt and braces).
        let mut signed = super::bundle(v2.to_string().as_bytes()).unwrap();
        assert_eq!(verify(&mut signed, DIGEST, &identity(&with).unwrap()), Ok(()));
        let said = verify(&mut signed, DIGEST, &identity(&without).unwrap()).unwrap_err();
        assert!(said.contains("`tsa`"), "{said}");
    }

    /// The `tsa` field is 1 to 4 PEM certificates, optional, and part of what an identity is.
    #[test]
    fn tsa_rule_reads_one_to_four_certificates() {
        let (authority, tsa, log) = (Authority::new(), Authority::new(), Log::new());
        let who = named(WHO, ISSUED, &authority, &log);
        let read = |said: &str| identity(said).map(|read| read.id).map_err(|e| e.to_string());
        let plain = read(&who).unwrap();
        // (A rule that stored no tsa is `who` itself: its id has no tsa in it, as before.)
        let one = read(&with_tsa(&who, &[&tsa.root])).unwrap();
        assert_ne!(one, plain);
        let four = [&tsa.root; 4];
        assert_ne!(read(&with_tsa(&who, &four)).unwrap(), one);
        // DER inside the PEM is a certificate; the PEM's own label is not read.
        assert!(read(&with_tsa(&who, &[&authority.root])).is_ok());
        for (said, why) in [
            (with_tsa(&who, &[]), "gives 1 to 4 certificates as its `tsa`"),
            (
                with_tsa(&who, &[&tsa.root; 5]),
                "gives 1 to 4 certificates as its `tsa`",
            ),
            (
                with_tsa(&who, &[&CertificateDer::from(&b"not a certificate"[..])]),
                "`tsa` holds what is no certificate",
            ),
            // A certificate with bytes after it is no certificate.
            (
                with_tsa(
                    &who,
                    &[&CertificateDer::from([tsa.root.as_ref(), &b"junk"[..]].concat())],
                ),
                "`tsa` holds what is no certificate",
            ),
        ] {
            let got = read(&said).unwrap_err();
            assert!(got.contains(why), "expected `{why}`, got `{got}`");
        }
        // Not a list of text: refused too, not taken as no tsa.
        let mut said: Value = serde_json::from_str(&who).unwrap();
        said["tsa"] = Value::from("tsa.pem");
        assert!(read(&said.to_string()).unwrap_err().contains("`tsa`"));
    }

    #[test]
    fn timestamps_that_are_not_the_tsas_are_refused() {
        let (authority, tsa, log) = (Authority::new(), Authority::new(), Log::new());
        let made = Making::new(&authority, &log, DIGEST);
        let (cert, key) = tsa.leaf(START, "tsa@example.test", ISSUED, ExtendedKeyUsagePurpose::TimeStamping);
        let refused = |bundle: &Value, root: &CertificateDer, why: &str| {
            let mut signed = super::bundle(bundle.to_string().as_bytes()).unwrap();
            let said = timestamp(&mut signed, root).unwrap_err();
            assert!(said.contains(why), "expected `{why}`, got `{said}`");
        };
        let good = v2(&made, &cert, &key, None, 60, "");
        let mut signed = super::bundle(good.to_string().as_bytes()).unwrap();
        assert_eq!(timestamp(&mut signed, &tsa.root), Ok((START + 60) as i64));
        // Another TSA: its root is not the one given.
        refused(&good, &Authority::new().root, "not from the authority named");
        // Another signature's imprint.
        refused(
            &v2(&made, &cert, &key, Some(b"another signature"), 60, ""),
            &tsa.root,
            "is of another signature",
        );
        // A time outside the TSA certificate's own, after and before.
        refused(
            &v2(&made, &cert, &key, None, 3_600, ""),
            &tsa.root,
            "outside its authority's certificate's time",
        );
        let (late, late_key) = tsa.leaf(
            START + 7_200,
            "tsa@example.test",
            ISSUED,
            ExtendedKeyUsagePurpose::TimeStamping,
        );
        refused(
            &v2(&made, &late, &late_key, None, 60, ""),
            &tsa.root,
            "outside its authority's certificate's time",
        );
        // Signed attributes whose signature is not the certificate's, or whose digest is not
        // of the content.
        refused(
            &v2(&made, &cert, &key, None, 60, "signature"),
            &tsa.root,
            "not by its certificate's key",
        );
        refused(
            &v2(&made, &cert, &key, None, 60, "digest"),
            &tsa.root,
            "not of its content",
        );
        // A certificate that is not for timestamping.
        let (code, code_key) = tsa.leaf(START, "tsa@example.test", ISSUED, ExtendedKeyUsagePurpose::CodeSigning);
        refused(
            &v2(&made, &code, &code_key, None, 60, ""),
            &tsa.root,
            "not for timestamping",
        );
        // A root that is no certificate; a timestamp that is none; one cut short.
        refused(&good, &CertificateDer::from(&[1u8, 2, 3][..]), "is no certificate");
        let mut none = good.clone();
        none["verificationMaterial"]["timestampVerificationData"] = Value::Null;
        let said = super::bundle(none.to_string().as_bytes()).err().unwrap();
        assert!(said.contains("Rekor v2"), "{said}");
        let response = response(&cert, &key, b"x", 60, "");
        for cut in [0, 1, 5, response.len() / 2, response.len() - 1] {
            let mut cuts = super::bundle(good.to_string().as_bytes()).unwrap();
            cuts.stamp = Some(response[..cut].to_vec());
            let said = timestamp(&mut cuts, &tsa.root).unwrap_err();
            assert!(said.contains("cannot be read"), "{cut}: {said}");
        }
    }

    /// A token the test builds reads back its signer, signed attributes, digest, imprint and time.
    #[test]
    fn the_timestamp_reader_reads_a_token() {
        let (tsa, imprint) = (Authority::new(), b"what was stamped");
        let (cert, key) = tsa.leaf(START, "tsa@example.test", ISSUED, ExtendedKeyUsagePurpose::TimeStamping);
        let response = response(&cert, &key, imprint, 90, "");
        let read = stamp(&response).unwrap();
        assert_eq!(read.certs, [cert.as_ref()]);
        assert_eq!(read.imprint, sha256(imprint));
        assert_eq!(read.time, (START + 90) as i64);
        // The digest in the signed attributes is of the TSTInfo, and the attributes are what
        // the signature covers: a SET OF holding that digest.
        assert_eq!(read.message_digest, sha256(read.content));
        assert_eq!(read.attributes[0], 0x31);
        assert!(read.attributes.windows(32).any(|w| w == read.message_digest));
        assert!(std::ptr::eq(read.algorithm, &ring::digest::SHA256));
        assert!(!read.signature.is_empty());
        // The unsigned attributes at the depth limit are skipped, as a wider SET of certs is not.
        assert_eq!(
            stamp(&self::response(&cert, &key, imprint, 90, "edge")).unwrap().time,
            read.time
        );
    }

    /// Over 16 KiB, nesting past 8, a fifth certificate and BER are each refused, saying why.
    fn refuses_what_is_past_the_limits() {
        let (authority, tsa, log) = (Authority::new(), Authority::new(), Log::new());
        let made = Making::new(&authority, &log, DIGEST);
        let (cert, key) = tsa.leaf(START, "tsa@example.test", ISSUED, ExtendedKeyUsagePurpose::TimeStamping);
        let good = v2(&made, &cert, &key, None, 60, "");
        let refused = |der: Vec<u8>, why: &str| {
            assert!(stamp(&der).is_none(), "{why}");
            let mut bundle = super::bundle(good.to_string().as_bytes()).unwrap();
            bundle.stamp = Some(der);
            let said = timestamp(&mut bundle, &tsa.root).unwrap_err();
            assert!(said.contains(why), "expected `{why}`, got `{said}`");
        };
        let imprint = super::bundle(good.to_string().as_bytes()).unwrap().signature;
        let with = |fault: &str| response(&cert, &key, &imprint, 60, fault);
        refused(with("big"), "is over 16 KiB");
        refused(vec![0x30; STAMP + 1], "is over 16 KiB");
        refused(with("deep"), "nests deeper than 8");
        refused(with("certs"), "holds more than 4 certificates");
        // BER: an indefinite length on the outer sequence, and a length written longer than needed.
        let ok = with("");
        let ber = [&[0x30, 0x80][..], &ok[4..], &[0, 0]].concat();
        refused(ber, "is BER, not DER");
        assert_eq!(ok[1], 0x82);
        let long = [&[0x30, 0x83, 0, ok[2], ok[3]][..], &ok[4..]].concat();
        refused(long, "cannot be read");
        // Nesting to the limit is not refused.
        assert!(stamp(&with("edge")).is_some());
    }

    /// The reader fed every cut and 2000 altered responses: it says why not, never panics.
    #[test]
    fn the_timestamp_reader_survives_damaged_bytes() {
        refuses_what_is_past_the_limits();
        let (authority, tsa, log) = (Authority::new(), Authority::new(), Log::new());
        let made = Making::new(&authority, &log, DIGEST);
        let (cert, key) = tsa.leaf(START, "tsa@example.test", ISSUED, ExtendedKeyUsagePurpose::TimeStamping);
        let good = v2(&made, &cert, &key, None, 60, "");
        let signed = super::bundle(good.to_string().as_bytes()).unwrap();
        let response = signed.stamp.clone().unwrap();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut inputs: Vec<Vec<u8>> = (0..response.len()).map(|cut| response[..cut].to_vec()).collect();
        for _ in 0..2_000 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let mut altered = response.clone();
            let at = (seed >> 33) as usize % altered.len();
            altered[at] = (seed >> 13) as u8;
            if seed & 7 == 0 {
                altered.truncate(at + 1);
                altered.extend_from_slice(&seed.to_be_bytes()[..(seed as usize >> 5) % 8]);
            }
            inputs.push(altered);
        }
        let mut read = 0;
        for input in inputs {
            read += usize::from(stamp(&input).is_some());
            let mut damaged = super::bundle(good.to_string().as_bytes()).unwrap();
            damaged.stamp = Some(input);
            let _ = timestamp(&mut damaged, &tsa.root);
        }
        // (Some alterations leave it readable, say a byte of the certificate's name: they
        // are refused by the checks, not the reader. None of the cuts is readable.)
        assert!(stamp(&response).is_some());
        assert!(read < 2_000, "{read}");
        // Times as GeneralizedTime: leap days and the ends of the range.
        assert_eq!(unix(b"19700101000000Z"), Some(0));
        assert_eq!(unix(b"20240229120000.5Z"), Some(1_709_208_000));
        assert_eq!(unix(b"20230229120000Z"), None);
        assert_eq!(unix(b"20260101000000"), None);
        assert_eq!(unix(b"2026010100000Z"), None);
        assert_eq!(unix(b"20261301000000Z"), None);
    }
}
