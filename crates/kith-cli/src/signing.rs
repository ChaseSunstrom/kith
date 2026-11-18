//! Cluster writes signed with the admin's key (docs/adr-taken-node.md, "What a signature
//! binds"), which kithd checks against the Cluster's `spec.adminKey`. The key comes from the
//! passphrase (PBKDF2, salted with the cluster id) and is kept nowhere: nothing on disk.

use crate::base64;
use ring::digest::{self, SHA256};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::num::NonZeroU32;

/// The header a signed request carries (kithd's `access_sign::SIGNED`).
pub const SIGNED: &str = "x-kith-signed";

/// The rounds the passphrase is stretched by before it is a key: changing them changes every key.
const ROUNDS: u32 = 600_000;

/// What a signed request is over: as it is sent.
pub struct Request<'a> {
    pub method: &'a str,
    /// The path and query, as sent.
    pub path: &'a str,
    pub body: &'a [u8],
}

/// The admin's key for `cluster`, from the passphrase typed: the first 32 bytes of its
/// PBKDF2-HMAC-SHA256 are the Ed25519 seed.
pub fn key(passphrase: &str, cluster: &str) -> Ed25519KeyPair {
    let mut seed = [0u8; 32];
    let rounds = NonZeroU32::new(ROUNDS).expect("the rounds are not zero");
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        rounds,
        cluster.as_bytes(),
        passphrase.as_bytes(),
        &mut seed,
    );
    Ed25519KeyPair::from_seed_unchecked(&seed).expect("32 bytes are a seed")
}

/// The public half of `key`, in hex: what Cluster `spec.adminKey` holds.
pub fn public(key: &Ed25519KeyPair) -> String {
    hex(key.public_key().as_ref())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bytes a signature is over: kithd's `access_sign::bytes`, to the byte, for the local
/// socket (the only signer this kith is).
fn message(cluster: &str, target: &str, asked: &Request, expires: u64, nonce: &str) -> String {
    let body = hex(digest::digest(&SHA256, asked.body).as_ref());
    let (method, path) = (asked.method, asked.path);
    format!("kith-signed-v1\n{cluster}\n{target}\n{method}\n{path}\n{body}\nlocal socket\n{expires}\n{nonce}\n")
}

/// The `x-kith-signed` header that signs `asked` for `target` on `cluster`, until `expires`.
pub fn header(key: &Ed25519KeyPair, cluster: &str, target: &str, asked: &Request, expires: u64, nonce: &str) -> String {
    let sig = key.sign(message(cluster, target, asked, expires, nonce).as_bytes());
    format!(
        "v1; who=local socket; target={target}; expires={expires}; nonce={nonce}; sig={}",
        base64(sig.as_ref())
    )
}

/// A nonce no other request has: 16 random bytes, in hex.
pub fn nonce() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "error: no randomness for a nonce".to_string())?;
    Ok(hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";
    const CLUSTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NONCE: &str = "00112233445566778899aabbccddeeff";
    const EXPIRES: u64 = 1_800_000_300;

    fn asked() -> Request<'static> {
        Request {
            method: "POST",
            path: "/v1/apply",
            body: b"[]",
        }
    }

    #[test]
    fn signed_key_comes_from_the_passphrase_and_the_cluster() {
        let public = public(&key(PASSPHRASE, CLUSTER));
        assert_eq!(public, self::public(&key(PASSPHRASE, CLUSTER)));
        assert_ne!(public, self::public(&key(PASSPHRASE, &CLUSTER.replace('0', "f"))));
        assert_ne!(public, self::public(&key("another", CLUSTER)));
    }

    #[test]
    fn signed_bytes_are_the_adrs() {
        // SHA-256 of "[]" is the body's line.
        assert_eq!(
            message(CLUSTER, "*", &asked(), EXPIRES, NONCE),
            format!(
                "kith-signed-v1\n{CLUSTER}\n*\nPOST\n/v1/apply\n\
                 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945\n\
                 local socket\n{EXPIRES}\n{NONCE}\n"
            )
        );
    }

    #[test]
    fn signed_header_is_the_form_kithd_reads() {
        let key = key(PASSPHRASE, CLUSTER);
        let sig = base64(key.sign(message(CLUSTER, "*", &asked(), EXPIRES, NONCE).as_bytes()).as_ref());
        assert_eq!(
            header(&key, CLUSTER, "*", &asked(), EXPIRES, NONCE),
            format!("v1; who=local socket; target=*; expires={EXPIRES}; nonce={NONCE}; sig={sig}")
        );
    }

    #[test]
    fn signed_nonces_are_32_lower_case_hex_and_differ() {
        let (a, b) = (nonce().unwrap(), nonce().unwrap());
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
        assert_ne!(a, b);
    }

    /// The same passphrase, cluster and request, pinned here and in kithd's
    /// `signed_header_from_the_cli_verifies` (`access_sign.rs`): the two agree or one is wrong.
    const PUBLIC: &str = "45adefd230fccdc0edc77acb13998359d12eeb0ab7a4fdd1c49a2203fb8eb183";
    const HEADER: &str = "v1; who=local socket; target=*; expires=1800000300; nonce=00112233445566778899aabbccddeeff; sig=a70zVltHfKC0JVo4PtNzEiwAsqr/KLbBg1ITbXFjm/5TA4bG8PX3zj/35f76yW68aScPFOH4Ks62okBH8wDvBQ==";

    #[test]
    fn signed_cross_vector_is_kithds() {
        assert_eq!(public(&key(PASSPHRASE, CLUSTER)), PUBLIC);
        assert_eq!(header(&key(PASSPHRASE, CLUSTER), CLUSTER, "*", &asked(), EXPIRES, NONCE), HEADER);
    }
}
