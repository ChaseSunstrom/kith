//! Whose image this is: signatures as cosign writes them, checked before a layer is fetched.
//!
//! A signature of the image whose manifest has the digest `sha256:HEX` is in the image's
//! own repository under the tag `sha256-HEX.sig`: a manifest whose layers are each a small
//! JSON text naming that digest, with the signature over the text's bytes in the layer's
//! annotations. (`cosign sign --key cosign.key IMAGE` writes that.)
//
// ponytail: keys only. No certificates (cosign's keyless signing), no transparency log,
// no signatures kept as referrers (cosign's newer bundle format): each when asked for.

use crate::{Result, err};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oci_client::errors::OciDistributionError;
use oci_client::manifest::OciManifest;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519, UnparsedPublicKey, VerificationAlgorithm};

const SIGNATURE: &str = "dev.cosignproject.cosign/signature";
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

/// A key an image may be signed by.
pub struct Key {
    /// The key as it is remembered: its file's base64, with nothing around it.
    pub id: String,
    algorithm: &'static dyn VerificationAlgorithm,
    key: Vec<u8>,
}

/// Reads a public key: a PEM file's text (`-----BEGIN PUBLIC KEY-----` …), or its base64
/// alone. ECDSA on P-256 (what `cosign generate-key-pair` makes) or Ed25519.
pub fn key(said: &str) -> Result<Key> {
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
    Ok(Key { id, algorithm, key })
}

/// Whether a registry said it has no such manifest (and not: that it could not say).
fn absent(e: &OciDistributionError) -> bool {
    use oci_client::errors::OciErrorCode::{ManifestUnknown, NameUnknown, NotFound};
    match e {
        OciDistributionError::ImageManifestNotFoundError(_) | OciDistributionError::ServerError { code: 404, .. } => {
            true
        }
        OciDistributionError::RegistryError { envelope, .. } => {
            let codes = &mut envelope.errors.iter().map(|error| &error.code);
            codes.any(|code| matches!(code, ManifestUnknown | NameUnknown | NotFound))
        }
        _ => false,
    }
}

/// The key (its `id`) that signed one of `digests`: the image's manifest, or the list of
/// manifests it was picked from. An error says what was found instead.
pub async fn signer(client: &Client, reference: &Reference, digests: &[&str], keys: &[Key]) -> Result<String> {
    let mut found = Vec::new();
    for digest in digests {
        let hex = crate::image::sha256_hex(digest)?;
        let (registry, repository) = (reference.registry().to_string(), reference.repository().to_string());
        let at = Reference::with_tag(registry, repository, format!("sha256-{hex}.sig"));
        let manifest = match client.pull_manifest(&at, &RegistryAuth::Anonymous).await {
            Ok((OciManifest::Image(manifest), _)) => manifest,
            Err(e) if !absent(&e) => {
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
            let signature = layer.annotations.as_ref().and_then(|notes| notes.get(SIGNATURE));
            let Some(signature) = signature.and_then(|signature| STANDARD.decode(signature).ok()) else {
                continue;
            };
            // (As much as fits: more is not a text cosign wrote, and its digest is checked as it comes.)
            let mut room = vec![0u8; TEXT];
            let mut into = std::io::Cursor::new(&mut room[..]);
            if client.pull_blob(&at, layer, &mut into).await.is_err() {
                continue;
            }
            let text = &into.get_ref()[..into.position() as usize];
            let signed = |key: &&Key| {
                UnparsedPublicKey::new(key.algorithm, &key.key)
                    .verify(text, &signature)
                    .is_ok()
            };
            let Some(by) = keys.iter().find(signed) else {
                others += 1;
                continue;
            };
            // By a key that was named: now what the text says is its signer's word. It is a
            // signature of this image if it names this digest, wherever else it is kept.
            let said: serde_json::Value = serde_json::from_slice(text).unwrap_or_default();
            match said["critical"]["image"]["docker-manifest-digest"].as_str() {
                Some(of) if of == *digest => return Ok(by.id.clone()),
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
    err(format!(
        "image `{reference}` ({}) is not signed by a key its template names: {}",
        digests.last().copied().unwrap_or_default(),
        found.join("; ")
    ))
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
            let (served, noted) = (files.clone(), asked.clone());
            std::thread::spawn(move || {
                for mut stream in listener.incoming().flatten() {
                    let (mut request, mut byte) = (Vec::new(), [0u8]);
                    while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
                        request.push(byte[0]);
                    }
                    let request = String::from_utf8_lossy(&request).to_string();
                    let path = request.split(' ').nth(1).unwrap_or_default().to_string();
                    noted.lock().unwrap().push(path.clone());
                    let found = served.lock().unwrap().get(&path).cloned();
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
                    let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(&body));
                }
            });
            Registry { at, files, asked }
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
                "image `{}` ({plain}) is not signed by a key its template names",
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
}
