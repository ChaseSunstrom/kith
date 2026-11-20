//! Whose image this is: signatures as cosign writes them, checked before a layer is fetched.
//!
//! A signature of the image whose manifest has the digest `sha256:HEX` is in the image's
//! own repository under the tag `sha256-HEX.sig`: a manifest whose layers are each a small
//! JSON text naming that digest, with the signature over the text's bytes in the layer's
//! annotations. (`cosign sign --key cosign.key IMAGE` writes that.)
//!
//! A signature made without a kept key (cosign's default) is checked against an identity
//! instead: see [`crate::keyless`]. cosign 3 keeps it as a bundle among the image's
//! referrers; older cosigns keep it under the same tag, with its certificate and the log's
//! promise in the layer's annotations.

use crate::outside::{Lookup, Remote};
use crate::{Result, err};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oci_client::Reference;
use oci_client::manifest::OciManifest;
use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519, UnparsedPublicKey, VerificationAlgorithm};

const SIGNATURE: &str = "dev.cosignproject.cosign/signature";
const CERTIFICATE: &str = "dev.sigstore.cosign/certificate";
const PROMISE: &str = "dev.sigstore.cosign/bundle";
/// The most of a bundle that is read: cosign's are some 5 kB.
const BUNDLE: usize = 64 << 10;
/// The most of a signed text that is read: cosign's are some 250 bytes.
const TEXT: usize = 16 << 10;
/// The most signatures of one image that are looked at.
const SIGNATURES: usize = 32;

/// What a public key file starts with (its DER), before the key itself: for a point of
/// the curve P-256, and for an Ed25519 key.
const P256: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const ED: &[u8] = &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// A key an image may be signed by, or an identity it may be signed as without a kept key.
pub struct Key {
    /// The key as it is remembered: its file's base64, with nothing around it; or the
    /// identity's names and a hash of all it was given.
    pub id: String,
    kind: Kind,
}

enum Kind {
    Public(&'static dyn VerificationAlgorithm, Vec<u8>),
    Identity(crate::keyless::Identity),
}

/// Reads a public key: a PEM file's text (`-----BEGIN PUBLIC KEY-----` …), or its base64
/// alone. ECDSA on P-256 (what `cosign generate-key-pair` makes) or Ed25519. Or an identity,
/// as its JSON text (`{"issuer": …, "subject": …, "authority": […], "log": …}`).
pub fn key(said: &str) -> Result<Key> {
    if said.trim_start().starts_with('{') {
        let identity = crate::keyless::identity(said)?;
        return Ok(Key {
            id: identity.id.clone(),
            kind: Kind::Identity(identity),
        });
    }
    let lines = said.lines().filter(|line| !line.trim_start().starts_with("-----"));
    let id: String = lines.flat_map(str::chars).filter(|c| !c.is_whitespace()).collect();
    let der = STANDARD.decode(&id).ok();
    let read = |start: &[u8], len: usize| {
        let key = der.as_ref()?.strip_prefix(start)?;
        (key.len() == len).then(|| key.to_vec())
    };
    let (algorithm, key): (&'static dyn VerificationAlgorithm, _) = match (read(P256, 65), read(ED, 32)) {
        (Some(key), _) => (&ECDSA_P256_SHA256_ASN1, key),
        (_, Some(key)) => (&ED25519, key),
        _ => {
            let shown: String = said.trim().chars().take(40).collect();
            return err(format!(
                "signedBy: `{shown}` is not a public key kith can check: an ECDSA P-256 or Ed25519 key, as its PEM file's text or the base64 in it"
            ));
        }
    };
    Ok(Key {
        id,
        kind: Kind::Public(algorithm, key),
    })
}

/// The key (its `id`) that signed one of `digests`: the image's manifest, or the list of
/// manifests it was picked from. An error says what was found instead. The signatures are
/// looked for for at most `wait` (the metadata deadline): a registry that answers slowly, or
/// never, is not waited on for ever.
pub(crate) async fn signer(
    remote: &Remote,
    reference: &Reference,
    digests: &[&str],
    keys: &[Key],
    wait: std::time::Duration,
) -> Result<String> {
    let mut found = Vec::new();
    let looked = tokio::time::timeout(wait, look(remote, reference, digests, keys, &mut found)).await;
    match looked {
        Ok(Ok(Some(by))) => return Ok(by),
        Ok(Err(e)) => return Err(e),
        Ok(Ok(None)) => {}
        Err(_) => found.push(format!(
            "its signatures were looked for for {wait:?}, and that is the most"
        )),
    }
    found.dedup();
    err(format!(
        "image `{reference}` ({}) is not signed by a key its template or the Cluster's rule for it names: {}",
        digests.last().copied().unwrap_or_default(),
        found.join("; ")
    ))
}

/// Whether `signed` is by one of `identities`: the first that it is by, or why not (in `found`).
fn by_identity(
    signed: &mut crate::keyless::Signed,
    digest: &str,
    identities: &[(&Key, &crate::keyless::Identity)],
    found: &mut Vec<String>,
    kept: &str,
) -> Option<String> {
    for (key, identity) in identities {
        // (Each identity's own `tsa` times the bundle, if it names one.)
        match crate::keyless::verify(signed, digest, identity) {
            Ok(()) => return Some(key.id.clone()),
            Err(why) => found.push(format!("{kept}: {why}")),
        }
    }
    None
}

/// cosign 3's bundles among `digest`'s referrers: the identity one is by.
async fn referred(
    remote: &Remote,
    reference: &Reference,
    digest: &str,
    identities: &[(&Key, &crate::keyless::Identity)],
    found: &mut Vec<String>,
) -> Option<String> {
    let (registry, repository) = (reference.registry().to_string(), reference.repository().to_string());
    let subject = Reference::with_digest(registry.clone(), repository.clone(), digest.to_string());
    // (A registry with no referrers of it has none: the tag is looked at next. One whose index is
    // too big, or that cannot be asked, is said so, and the tag is looked at next too.)
    let index = match remote.referrers(&subject, digest, crate::keyless::BUNDLE).await {
        Ok(Lookup::Found(index)) => index,
        Ok(Lookup::Missing(_)) => return None,
        Err(e) => {
            found.push(format!("the referrers of {digest} could not be read: {e}"));
            return None;
        }
    };
    // Bundles only, whatever else the registry answered with, and of a bundle's size.
    let bundles = index.manifests.iter().filter(|described| {
        described.artifact_type.as_deref() == Some(crate::keyless::BUNDLE)
            && described.size <= BUNDLE as i64
            && crate::image::sha256_hex(&described.digest).is_ok()
    });
    for described in bundles.take(SIGNATURES) {
        let at = Reference::with_digest(registry.clone(), repository.clone(), described.digest.clone());
        let Ok(Lookup::Found((OciManifest::Image(manifest), _))) = remote.manifest(&at).await else {
            continue;
        };
        if manifest.subject.as_ref().map(|subject| subject.digest.as_str()) != Some(digest) {
            found.push("a bundle among its referrers says it is of another image".into());
            continue;
        }
        let Some(layer) = manifest
            .layers
            .first()
            .filter(|layer| layer.media_type == crate::keyless::BUNDLE)
        else {
            continue;
        };
        let mut room = vec![0u8; BUNDLE];
        let mut into = std::io::Cursor::new(&mut room[..]);
        if remote.oci.pull_blob(&at, layer, &mut into).await.is_err() {
            continue;
        }
        let bytes = &into.get_ref()[..into.position() as usize];
        match crate::keyless::bundle(bytes) {
            Ok(mut signed) => {
                if let Some(by) = by_identity(&mut signed, digest, identities, found, "a bundle among its referrers") {
                    return Some(by);
                }
            }
            Err(why) => found.push(format!("a bundle among its referrers: {why}")),
        }
    }
    None
}

async fn look(
    remote: &Remote,
    reference: &Reference,
    digests: &[&str],
    keys: &[Key],
    found: &mut Vec<String>,
) -> Result<Option<String>> {
    let identities: Vec<_> = keys
        .iter()
        .filter_map(|key| match &key.kind {
            Kind::Identity(identity) => Some((key, identity)),
            Kind::Public(..) => None,
        })
        .collect();
    for digest in digests {
        let hex = crate::image::sha256_hex(digest)?;
        if !identities.is_empty()
            && let Some(by) = referred(remote, reference, digest, &identities, found).await
        {
            return Ok(Some(by));
        }
        let (registry, repository) = (reference.registry().to_string(), reference.repository().to_string());
        let at = Reference::with_tag(registry, repository, format!("sha256-{hex}.sig"));
        let manifest = match remote.manifest(&at).await {
            Ok(Lookup::Found((OciManifest::Image(manifest), _))) => manifest,
            Err(e) => {
                found.push(format!(
                    "its signatures (the tag sha256-{hex}.sig) could not be asked for: {e}"
                ));
                continue;
            }
            _ => {
                found.push(format!("no signature in its repository (the tag sha256-{hex}.sig)"));
                continue;
            }
        };
        let mut others = 0;
        for layer in manifest.layers.iter().take(SIGNATURES) {
            let note = |name: &str| layer.annotations.as_ref().and_then(|notes| notes.get(name));
            let signature = note(SIGNATURE);
            let Some(signature) = signature.and_then(|signature| STANDARD.decode(signature).ok()) else {
                continue;
            };
            // (As much as fits: more is not a text cosign wrote, and its digest is checked as it comes.)
            let mut room = vec![0u8; TEXT];
            let mut into = std::io::Cursor::new(&mut room[..]);
            if remote.oci.pull_blob(&at, layer, &mut into).await.is_err() {
                continue;
            }
            let text = &into.get_ref()[..into.position() as usize];
            // Made without a kept key: its certificate and the log's promise are with it.
            if let Some(cert) = note(CERTIFICATE) {
                if identities.is_empty() {
                    others += 1;
                    continue;
                }
                let kept = "a signature there made without a kept key";
                match crate::keyless::tagged(text, signature, cert, note(PROMISE).map(String::as_str)) {
                    Ok(mut signed) => {
                        if let Some(by) = by_identity(&mut signed, digest, &identities, found, kept) {
                            return Ok(Some(by));
                        }
                    }
                    Err(why) => found.push(format!("{kept}: {why}")),
                }
                continue;
            }
            let signed = |key: &&Key| match &key.kind {
                Kind::Public(algorithm, public) => UnparsedPublicKey::new(*algorithm, public)
                    .verify(text, &signature)
                    .is_ok(),
                Kind::Identity(_) => false,
            };
            let Some(by) = keys.iter().find(signed) else {
                others += 1;
                continue;
            };
            // By a key that was named: now what the text says is its signer's word. It is a
            // signature of this image if it names this digest, wherever else it is kept.
            let said: serde_json::Value = serde_json::from_slice(text).unwrap_or_default();
            match said["critical"]["image"]["docker-manifest-digest"].as_str() {
                Some(of) if of == *digest => return Ok(Some(by.id.clone())),
                of => found.push(format!(
                    "a signature by a named key there is of another image ({})",
                    of.unwrap_or("it names none")
                )),
            }
        }
        if others > 0 {
            found.push(format!("{others} signature(s) there, none by a key that is named"));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ImageStore, PullPolicy};
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    type Files = Arc<Mutex<HashMap<String, (&'static str, Vec<u8>)>>>;

    /// A registry on this machine: what was put in it, by path, and what it was asked.
    struct Registry {
        at: String,
        files: Files,
        asked: Arc<Mutex<Vec<String>>>,
        sent: Arc<std::sync::atomic::AtomicUsize>,
    }

    fn digest(bytes: &[u8]) -> String {
        let hash = ring::digest::digest(&ring::digest::SHA256, bytes);
        format!(
            "sha256:{}",
            hash.as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    impl Registry {
        fn start() -> Registry {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let at = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
            let (files, asked) = (Files::default(), Arc::new(Mutex::new(Vec::new())));
            let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (served, noted, counted) = (files.clone(), asked.clone(), sent.clone());
            std::thread::spawn(move || {
                for mut stream in listener.incoming().flatten() {
                    // (A client that stops reading is given up on, not waited for.)
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
                    let (mut request, mut byte) = (Vec::new(), [0u8]);
                    while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
                        request.push(byte[0]);
                    }
                    let request = String::from_utf8_lossy(&request).to_string();
                    let path = request.split(' ').nth(1).unwrap_or_default().to_string();
                    noted.lock().unwrap().push(path.clone());
                    // (What is asked of the referrers API is filtered by kind: one answer here.)
                    let without = path.split('?').next().unwrap_or_default();
                    let found = served.lock().unwrap().get(without).cloned();
                    let (status, kind, body) = match found {
                        Some(("broken", body)) => ("500 Internal Server Error", "text/plain", body),
                        Some((kind, body)) => ("200 OK", kind, body),
                        None if path == "/v2/" => ("200 OK", "application/json", b"{}".to_vec()),
                        None => (
                            "404 Not Found",
                            "application/json",
                            br#"{"errors":[{"code":"MANIFEST_UNKNOWN","message":"not here"}]}"#.to_vec(),
                        ),
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nDocker-Content-Digest: {}\r\nConnection: close\r\n\r\n",
                        body.len(),
                        digest(&body)
                    );
                    let _ = stream.write_all(head.as_bytes());
                    // Counted as it goes: a client that closes early stops the count there.
                    for chunk in body.chunks(64 << 10) {
                        if stream.write_all(chunk).is_err() {
                            break;
                        }
                        counted.fetch_add(chunk.len(), std::sync::atomic::Ordering::SeqCst);
                    }
                }
            });
            Registry { at, files, asked, sent }
        }

        /// The bytes of response bodies handed to a client so far.
        fn sent(&self) -> usize {
            self.sent.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn put(&self, path: String, kind: &'static str, body: &[u8]) -> String {
            self.files.lock().unwrap().insert(path, (kind, body.to_vec()));
            digest(body)
        }

        fn blob(&self, repository: &str, body: &[u8]) -> serde_json::Value {
            let digest = self.put(
                format!("/v2/{repository}/blobs/{}", digest(body)),
                "application/octet-stream",
                body,
            );
            serde_json::json!({ "digest": digest, "size": body.len() })
        }

        fn manifest(
            &self,
            repository: &str,
            tag: &str,
            config: &[u8],
            layer: (&str, &[u8], serde_json::Value),
        ) -> String {
            const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
            let mut config = self.blob(repository, config);
            config["mediaType"] = "application/vnd.oci.image.config.v1+json".into();
            let mut described = self.blob(repository, layer.1);
            (described["mediaType"], described["annotations"]) = (layer.0.into(), layer.2);
            let manifest = serde_json::json!({ "schemaVersion": 2, "mediaType": MANIFEST, "config": config, "layers": [described] });
            let manifest = manifest.to_string();
            let digest = self.put(
                format!("/v2/{repository}/manifests/{tag}"),
                MANIFEST,
                manifest.as_bytes(),
            );
            self.put(
                format!("/v2/{repository}/manifests/{digest}"),
                MANIFEST,
                manifest.as_bytes(),
            )
        }

        /// An image of one file, `/hello`, that says `word`: its digest, and its layer's.
        fn image(&self, name: &str, word: &str) -> (String, String) {
            let mut tar = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_size(word.len() as u64);
            header.set_mode(0o644);
            tar.append_data(&mut header, "hello", word.as_bytes()).unwrap();
            let layer = tar.into_inner().unwrap();
            let config = serde_json::json!({
                "architecture": "amd64", "os": "linux", "config": { "Cmd": ["/hello"] },
                "rootfs": { "type": "layers", "diff_ids": [digest(&layer)] },
            });
            let kind = "application/vnd.oci.image.layer.v1.tar";
            let made = self.manifest(
                name,
                "1",
                config.to_string().as_bytes(),
                (kind, &layer, serde_json::Value::Null),
            );
            (made, digest(&layer))
        }

        /// A signature kept as the signature of the image `kept`: a text that names `names`,
        /// signed, and (`shown`) the text that is kept with it.
        fn sign(&self, name: &str, kept: &str, names: &str, sign: &dyn Fn(&[u8]) -> Vec<u8>, shown: Option<&str>) {
            let text = |digest: &str| {
                serde_json::json!({
                    "critical": {
                        "identity": { "docker-reference": format!("{}/{name}", self.at) },
                        "image": { "docker-manifest-digest": digest },
                        "type": "cosign container image signature",
                    },
                    "optional": null,
                })
                .to_string()
            };
            let signature = STANDARD.encode(sign(text(names).as_bytes()));
            let kind = "application/vnd.dev.cosign.simplesigning.v1+json";
            let tag = format!("{}.sig", kept.replace(':', "-"));
            let layer = (
                kind,
                text(shown.unwrap_or(names)),
                serde_json::json!({ SIGNATURE: signature }),
            );
            self.manifest(name, &tag, b"{}", (layer.0, layer.1.as_bytes(), layer.2));
        }

        /// `bundle` kept as cosign 3 keeps it: a manifest among the image `of`'s referrers.
        fn refer(&self, name: &str, of: &str, bundle: &[u8]) {
            const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
            let kind = crate::keyless::BUNDLE;
            let mut config = self.blob(name, b"{}");
            config["mediaType"] = "application/vnd.oci.empty.v1+json".into();
            let mut layer = self.blob(name, bundle);
            layer["mediaType"] = kind.into();
            let subject = serde_json::json!({ "mediaType": MANIFEST, "digest": of, "size": 1 });
            let manifest = serde_json::json!({
                "schemaVersion": 2, "mediaType": MANIFEST, "artifactType": kind,
                "config": config, "layers": [layer], "subject": subject,
            })
            .to_string();
            let digest = digest(manifest.as_bytes());
            self.put(format!("/v2/{name}/manifests/{digest}"), MANIFEST, manifest.as_bytes());
            let index = serde_json::json!({
                "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [{ "mediaType": MANIFEST, "digest": digest, "size": manifest.len(), "artifactType": kind }],
            })
            .to_string();
            let at = format!("/v2/{name}/referrers/{of}");
            self.put(at, "application/vnd.oci.image.index.v1+json", index.as_bytes());
        }

        fn asked(&self, part: &str) -> usize {
            self.asked
                .lock()
                .unwrap()
                .iter()
                .filter(|path| path.contains(part))
                .count()
        }
    }

    /// An ECDSA key as cosign makes one: how it signs, and its public key's PEM text.
    fn ecdsa() -> (impl Fn(&[u8]) -> Vec<u8>, String) {
        let rng = ring::rand::SystemRandom::new();
        let made = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, made.as_ref(), &rng).unwrap();
        let der = [P256, pair.public_key().as_ref()].concat();
        let (begin, end) = ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
        let text = STANDARD.encode(der);
        let (first, rest) = text.split_at(64);
        let pem = format!("{begin}\n{first}\n{rest}\n{end}\n");
        (move |text: &[u8]| pair.sign(&rng, text).unwrap().as_ref().to_vec(), pem)
    }

    #[tokio::test]
    async fn signed_images_run_and_no_others_where_a_template_names_keys() {
        let dir = std::env::temp_dir().join(format!("kith-signed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (store, registry) = (ImageStore::new(&dir).unwrap(), Registry::start());
        let name = |image: &str| format!("{}/{image}:1", registry.at);
        let ((ours, ours_pem), (_, theirs_pem)) = (ecdsa(), ecdsa());
        let refused = |pulled: Result<crate::Image>| pulled.err().map(|e| e.to_string()).unwrap_or_default();

        // Signed by the key that is named: pulled, and its layer only once that was known.
        let (good, _) = registry.image("good", "signed");
        registry.sign("good", &good, &good, &ours, None);
        let keys = [theirs_pem.clone(), ours_pem.clone()];
        let image = store
            .pull_signed(&name("good"), PullPolicy::IfNotPresent, &keys)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(image.rootfs.join("hello")).unwrap(), "signed");
        assert_eq!((image.digest.as_str(), image.from_cache), (good.as_str(), false));
        // What was checked is remembered: the registry is not asked again for the same key,
        assert_eq!(image.signed_by, [key(&ours_pem).unwrap().id]);
        let asked = registry.asked("");
        let again = store
            .pull_signed(&name("good"), PullPolicy::IfNotPresent, std::slice::from_ref(&ours_pem))
            .await
            .unwrap();
        assert_eq!((again.from_cache, registry.asked("")), (true, asked));
        // and for another key it is, the image being here or not: a key that did not sign
        // it does not run it, and what the first key was good for stays so.
        let only_theirs = [theirs_pem.clone()];
        for policy in [PullPolicy::IfNotPresent, PullPolicy::Always] {
            let said = refused(store.pull_signed(&name("good"), policy, &only_theirs).await);
            assert!(
                said.contains("1 signature(s) there, none by a key that is named"),
                "{said}"
            );
        }
        assert!(registry.asked(".sig") > 1);
        let said = refused(store.pull_signed(&name("good"), PullPolicy::Never, &only_theirs).await);
        assert!(said.contains("not been checked") && said.contains("`never`"), "{said}");
        let again = store
            .pull_signed(&name("good"), PullPolicy::Never, std::slice::from_ref(&ours_pem))
            .await
            .unwrap();
        assert!(again.from_cache);

        // Not signed at all: nothing of it is fetched but its manifest and its config.
        let (plain, layer) = registry.image("plain", "anyone's");
        let said = refused(store.pull_signed(&name("plain"), PullPolicy::IfNotPresent, &keys).await);
        assert!(
            said.contains(&format!(
                "image `{}` ({plain}) is not signed by a key its template or the Cluster's rule for it names",
                name("plain")
            )),
            "{said}"
        );
        assert!(
            said.contains("no signature in its repository (the tag sha256-"),
            "{said}"
        );
        assert_eq!(
            registry.asked(&layer),
            0,
            "a layer of an image nobody signed was fetched"
        );
        // Where no key is named it runs, as before; and having it here signs nothing.
        store.pull(&name("plain"), PullPolicy::IfNotPresent).await.unwrap();
        assert_eq!(registry.asked(&layer), 1);
        let said = refused(store.pull_signed(&name("plain"), PullPolicy::IfNotPresent, &keys).await);
        assert!(said.contains("no signature in its repository"), "{said}");

        // A registry that cannot say whether there is one has not said there is none.
        let (down, _) = registry.image("down", "whose?");
        let tag = format!("/v2/down/manifests/{}.sig", down.replace(':', "-"));
        registry.put(tag, "broken", b"down for a while");
        let said = refused(store.pull_signed(&name("down"), PullPolicy::IfNotPresent, &keys).await);
        assert!(
            said.contains("could not be asked for") && !said.contains("no signature in its repository"),
            "{said}"
        );

        // A true signature of another image, kept as this one's (what a registry can do by
        // itself: it has the other's signature): the text names the image it was made for.
        let (moved, layer) = registry.image("good", "swapped");
        registry.sign("good", &moved, &good, &ours, None);
        let said = refused(store.pull_signed(&name("good"), PullPolicy::Always, &keys).await);
        assert!(
            said.contains(&format!(
                "a signature by a named key there is of another image ({good})"
            )),
            "{said}"
        );
        // And that text made to name this one is no longer what was signed.
        registry.sign("good", &moved, &good, &ours, Some(&moved));
        let said = refused(store.pull_signed(&name("good"), PullPolicy::Always, &keys).await);
        assert!(said.contains("none by a key that is named"), "{said}");
        assert_eq!(registry.asked(&layer), 0);
        // (The tag is now the swapped image for everyone: what ran before is not what
        // `ifNotPresent` asks about again, which is why a key is remembered with a digest.)

        // An Ed25519 key, given as the base64 alone, among keys that did not sign.
        let rng = ring::rand::SystemRandom::new();
        let made = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(made.as_ref()).unwrap();
        let bare = STANDARD.encode([ED, pair.public_key().as_ref()].concat());
        let (ed, _) = registry.image("ed", "by another kind of key");
        registry.sign("ed", &ed, &ed, &|text| pair.sign(text).as_ref().to_vec(), None);
        let image = store
            .pull_signed(&name("ed"), PullPolicy::IfNotPresent, &[theirs_pem, bare.clone()])
            .await
            .unwrap();
        assert_eq!(image.signed_by, [bare]);

        // What is no key is said to be none, before the registry hears of it.
        let asked = registry.asked("");
        for bad in [
            "",
            "not a key",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
            &STANDARD.encode(P256),
        ] {
            let said = refused(
                store
                    .pull_signed(&name("ed"), PullPolicy::Always, &[bad.to_string()])
                    .await,
            );
            assert!(said.contains("is not a public key kith can check"), "{bad}: {said}");
        }
        assert_eq!(registry.asked(""), asked);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn keyless_signed_images_run_for_the_identity_named_and_no_others() {
        use crate::keyless::tests::{Authority, ISSUED, Log, Making, WHO, named};
        let dir = std::env::temp_dir().join(format!("kith-keyless-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (store, registry) = (ImageStore::new(&dir).unwrap(), Registry::start());
        let name = |image: &str| format!("{}/{image}:1", registry.at);
        let refused = |pulled: Result<crate::Image>| pulled.err().map(|e| e.to_string()).unwrap_or_default();
        let (authority, log) = (Authority::new(), Log::new());
        let who = named(WHO, ISSUED, &authority, &log);

        // A bundle among its referrers, by the identity named: it runs, as signed by it.
        let (image, _) = registry.image("referred", "by a workflow");
        registry.refer(
            "referred",
            &image,
            Making::new(&authority, &log, &image).bundle().to_string().as_bytes(),
        );
        let pulled = store
            .pull_signed(&name("referred"), PullPolicy::Always, std::slice::from_ref(&who))
            .await
            .unwrap();
        assert_eq!(pulled.signed_by, [key(&who).unwrap().id]);
        assert_eq!(
            (registry.asked("/referrers/"), registry.asked("/manifests/sha256-")),
            (1, 0)
        );
        // Named by a key only, it does not.
        let (_, pem) = ecdsa();
        let said = refused(
            store
                .pull_signed(&name("referred"), PullPolicy::Always, std::slice::from_ref(&pem))
                .await,
        );
        assert!(said.contains("no signature in its repository"), "{said}");
        // Nor for someone else.
        let them = named("someone@example.test", ISSUED, &authority, &log);
        let said = refused(
            store
                .pull_signed(&name("referred"), PullPolicy::Always, std::slice::from_ref(&them))
                .await,
        );
        assert!(
            said.contains(&format!(
                "a bundle among its referrers: it was signed by {WHO} ({ISSUED})"
            )),
            "{said}"
        );

        // Kept under the tag, as cosign 2 keeps it: it runs too.
        let (image, _) = registry.image("tagged", "by a workflow, the old way");
        let (text, notes) = Making::new(&authority, &log, &image).tagged();
        let tag = format!("{}.sig", image.replace(':', "-"));
        registry.manifest(
            "tagged",
            &tag,
            b"{}",
            ("application/vnd.dev.cosign.simplesigning.v1+json", &text, notes),
        );
        let pulled = store
            .pull_signed(&name("tagged"), PullPolicy::Always, std::slice::from_ref(&who))
            .await
            .unwrap();
        assert_eq!(pulled.signed_by, [key(&who).unwrap().id]);
        // And a key named alongside does not count its signature as the key's.
        let said = refused(
            store
                .pull_signed(&name("tagged"), PullPolicy::Always, std::slice::from_ref(&pem))
                .await,
        );
        assert!(
            said.contains("1 signature(s) there, none by a key that is named"),
            "{said}"
        );

        // A rule of identities alone, and an image nobody signed: it does not run.
        let (_, layer) = registry.image("plain", "anyone's");
        let said = refused(
            store
                .pull_signed(&name("plain"), PullPolicy::Always, std::slice::from_ref(&who))
                .await,
        );
        assert!(said.contains("no signature in its repository"), "{said}");
        assert_eq!(registry.asked(&layer), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A referrers index of 64 MiB from an outside registry is refused naming the limit, and not
    /// more than the limit (and a buffer or two) of it is taken from the registry.
    #[tokio::test]
    async fn outside_capped_referrers_index_is_refused_naming_the_limit() {
        let dir = std::env::temp_dir().join(format!("kith-outside-referrers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (store, registry) = (ImageStore::new(&dir).unwrap(), Registry::start());
        let name = format!("{}/huge:1", registry.at);
        let (made, _) = registry.image("huge", "signed");
        let mut index =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#.to_vec();
        index.resize(64 << 20, b' ');
        registry.put(
            format!("/v2/huge/referrers/{made}"),
            "application/vnd.oci.image.index.v1+json",
            &index,
        );
        // (Only an identity has its referrers looked at: a key is checked by its signatures alone.)
        let (authority, log) = (
            crate::keyless::tests::Authority::new(),
            crate::keyless::tests::Log::new(),
        );
        let who = crate::keyless::tests::named(
            crate::keyless::tests::WHO,
            crate::keyless::tests::ISSUED,
            &authority,
            &log,
        );
        let pulled = store.pull_signed(&name, PullPolicy::Always, std::slice::from_ref(&who));
        let Ok(result) = tokio::time::timeout(std::time::Duration::from_secs(20), pulled).await else {
            panic!("the pull was still reading the referrers after 20 s");
        };
        let Err(reason) = result else {
            panic!("pulled an image whose referrers were 64 MiB");
        };
        assert!(reason.to_string().contains("4 MiB"), "{reason}");
        let sent = registry.sent();
        assert!(
            sent <= 16 << 20,
            "{sent} bytes of the referrers index were sent before it was refused"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
