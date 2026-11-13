//! A package as it travels (PLAN.md §4.8): one blob, its files by path as JSON, and a
//! signature that says whose it is. In an OCI registry the blob is the one layer of an
//! artifact tagged with the package's version, and the signature an annotation on it.
//!
//! What is signed is the package's name, its version and the blob's SHA-256, so a
//! signature is of this package at this version and of no other, wherever it is put.
//
// ponytail: one Ed25519 key signs; no certificates, no transparency log, no key
// rotation (a Repository names one key). Sigstore when someone needs what it adds.

use crate::{Fallible, Package};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use std::collections::BTreeMap;

/// The blob's media type in a registry.
pub const LAYER: &str = "application/vnd.kith.package.v1+json";
/// The annotation the signature is in, on the artifact's manifest.
pub const SIGNATURE: &str = "dev.kith.signature";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str, what: &str) -> Fallible<Vec<u8>> {
    let text = text.trim();
    let digit = |at: usize| text.get(at..at + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok());
    let bytes: Option<Vec<u8>> = (0..text.len()).step_by(2).map(digit).collect();
    bytes
        .filter(|_| text.len().is_multiple_of(2))
        .ok_or(format!("{what} is not hex"))
}

/// A new signing key and the public key that checks what it signs, both as hex: the
/// first is a secret (PKCS#8), the second goes in a Repository's `publicKey`.
pub fn keygen() -> Fallible<(String, String)> {
    let failed = |_| "making a key failed".to_string();
    let secret = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).map_err(failed)?;
    let pair = Ed25519KeyPair::from_pkcs8(secret.as_ref()).map_err(|e| e.to_string())?;
    Ok((hex(secret.as_ref()), hex(pair.public_key().as_ref())))
}

fn signed(name: &str, version: &str, blob: &[u8]) -> Vec<u8> {
    let digest = ring::digest::digest(&ring::digest::SHA256, blob);
    format!("kith package v1\n{name}\n{version}\n{}\n", hex(digest.as_ref())).into_bytes()
}

/// Are `files` few and small enough, and every path one inside a directory? (Paths come
/// from registries too, and are written to disk by `package pull`.)
pub fn plain(files: &BTreeMap<String, String>) -> Fallible<()> {
    let (most, bytes) = (crate::FILES_LIMIT, crate::PACKAGE_LIMIT);
    if files.len() > most || files.values().map(String::len).sum::<usize>() > bytes {
        return Err(format!("more than {most} files, or more than {bytes} bytes in them"));
    }
    let plain = |path: &str| {
        let part = |part: &str| !matches!(part, "" | "." | "..") && !part.contains(['\\', '\0']);
        path.split('/').all(part)
    };
    match files.keys().find(|path| !plain(path)) {
        Some(path) => Err(format!("{path:?}: not a path inside a package")),
        None => Ok(()),
    }
}

/// The files in a blob that need not be a package's (a Source's artifact), checked
/// the same way.
pub fn files(blob: &[u8]) -> Fallible<BTreeMap<String, String>> {
    let files: BTreeMap<String, String> =
        serde_json::from_slice(blob).map_err(|e| format!("not files by path: {e}"))?;
    plain(&files).map(|()| files)
}

impl Package {
    /// The package as one blob: the same bytes for the same files.
    pub fn blob(&self) -> Vec<u8> {
        serde_json::to_vec(&self.files).expect("text by text")
    }

    /// The package in `blob`, checked like one read from a directory.
    pub fn from_blob(blob: &[u8]) -> Fallible<Package> {
        let files: BTreeMap<String, String> =
            serde_json::from_slice(blob).map_err(|e| format!("not a package: {e}"))?;
        Package::from_files(files)
    }

    /// Sign this package with the secret key `secret` (hex, from [`keygen`]).
    pub fn sign(&self, secret: &str) -> Fallible<String> {
        let pair = Ed25519KeyPair::from_pkcs8(&unhex(secret, "the signing key")?)
            .map_err(|e| format!("the signing key: {e}"))?;
        let message = signed(&self.meta.name, &self.meta.version, &self.blob());
        Ok(hex(pair.sign(&message).as_ref()))
    }
}

/// The package in `blob`, if `signature` is `public`'s over it: over these bytes, and
/// the name and version they say they are.
pub fn verified(blob: &[u8], signature: Option<&str>, public: &str) -> Fallible<Package> {
    let package = Package::from_blob(blob)?;
    let (name, version) = (&package.meta.name, &package.meta.version);
    let signature = signature.ok_or(format!("{name} {version} is not signed"))?;
    if !signed_by(&signed(name, version, blob), signature, public)? {
        return Err(format!(
            "{name} {version}: the signature is not this key's over this package"
        ));
    }
    Ok(package)
}

/// Is `signature` (hex) the key `public`'s (hex, from [`keygen`]) over `message`?
pub fn signed_by(message: &[u8], signature: &str, public: &str) -> Fallible<bool> {
    let key = UnparsedPublicKey::new(&ED25519, unhex(public, "the public key")?);
    Ok(key.verify(message, &unhex(signature, "the signature")?).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(version: &str) -> Package {
        let files = [
            ("package.yaml", format!("name: maps\nversion: {version}\n")),
            ("templates/a.yaml", "# nothing\n".to_string()),
        ];
        Package::from_files(files.into_iter().map(|(path, text)| (path.to_string(), text)).collect()).unwrap()
    }

    #[test]
    fn a_signature_is_of_one_package_by_one_key() {
        let (secret, public) = keygen().unwrap();
        let package = package("1.0.0");
        let (blob, signature) = (package.blob(), package.sign(&secret).unwrap());
        assert_eq!(
            blob,
            Package::from_blob(&blob).unwrap().blob(),
            "the same bytes there and back"
        );
        assert_eq!(
            verified(&blob, Some(&signature), &public).unwrap().meta.version,
            "1.0.0"
        );

        let refused =
            |blob: &[u8], signature: Option<&str>, public: &str| verified(blob, signature, public).err().unwrap();
        // Not signed; signed by someone else; not what was signed.
        assert!(refused(&blob, None, &public).contains("is not signed"));
        let (_, other) = keygen().unwrap();
        assert!(refused(&blob, Some(&signature), &other).contains("not this key's"));
        let tampered = String::from_utf8(blob.clone())
            .unwrap()
            .replace("# nothing", "# something");
        assert!(refused(tampered.as_bytes(), Some(&signature), &public).contains("not this key's"));
        // Another version passed off under this one's signature.
        let newer = self::package("2.0.0");
        assert!(refused(&newer.blob(), Some(&signature), &public).contains("maps 2.0.0: the signature"));
        // Nonsense for a key or a signature is said, not panicked over.
        assert!(refused(&blob, Some("zz"), &public).contains("the signature is not hex"));
        assert!(refused(&blob, Some(&signature), "abc").contains("the public key is not hex"));
        assert!(package.sign("00").unwrap_err().contains("the signing key"));
        assert!(Package::from_blob(b"[]").unwrap_err().contains("not a package"));
        // A blob whose files would land outside the package's directory.
        let outside = br#"{"package.yaml":"name: maps\nversion: 1.0.0\n","../../etc/x":"","/abs":""}"#;
        assert!(
            Package::from_blob(outside)
                .unwrap_err()
                .contains("not a path inside a package")
        );
    }
}
