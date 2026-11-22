//! A transparency log's two checks, pure: an RFC 9162 (RFC 6962) inclusion proof against a tree
//! root, and a C2SP signed-note checkpoint (tlog-checkpoint) read only when the named Ed25519
//! key signed it. Together they say a leaf is in the log the key vouches for.

// ponytail: nothing calls this yet; T-0669 slice 2 adds the rule field with the log's
// checkpoint key and calls it from the Rekor v2 path in keyless.rs.
#![cfg_attr(not(test), allow(dead_code))]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::digest::{Context, SHA256};
use ring::signature::{ED25519, UnparsedPublicKey};

type Hash = [u8; 32];

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut ctx = Context::new(&SHA256);
    parts.iter().for_each(|part| ctx.update(part));
    ctx.finish().as_ref().try_into().expect("a SHA-256 digest is 32 bytes")
}

/// A leaf's hash: SHA-256 of 0x00 and the leaf (RFC 9162 section 2.1.1).
fn leaf_hash(leaf: &[u8]) -> Hash {
    sha256(&[&[0], leaf])
}

/// An inner node's hash: SHA-256 of 0x01 and its two children.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[1], left, right])
}

/// True when `proof` takes `leaf`, the `index`th of `size`, to `root` (RFC 9162 section 2.1.3.2).
pub(crate) fn verify_inclusion(leaf: &[u8], index: u64, size: u64, proof: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnode, mut snode, mut hash) = (index, size - 1, leaf_hash(leaf));
    for sibling in proof {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            hash = node_hash(sibling, &hash);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            hash = node_hash(&hash, sibling);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && hash == *root
}

/// The tree size and root hash a checkpoint (a signed note) states, when `key` (an Ed25519 public
/// key the log is known by, named `name` in the note's signature line) signed it and the note is
/// of `origin`, the log's name. A note carries the origin, the size, the base64 root and maybe more
/// lines, a blank line, then signature lines `— name base64(4-byte key hash, signature)`; the
/// signature covers every line before the blank. Lines end in `\n` alone: a `\r` fails the parse.
pub(crate) fn checkpoint(note: &str, origin: &str, name: &str, key: &Hash) -> Option<(u64, Hash)> {
    let (text, signatures) = note.split_once("\n\n")?;
    let text = &note[..text.len() + 1];
    let mut lines = text.split('\n');
    lines.next().filter(|first| !origin.is_empty() && *first == origin)?;
    let size = lines.next()?;
    let size: u64 = size.parse().ok().filter(|n: &u64| n.to_string() == size)?;
    let root: Hash = STANDARD.decode(lines.next()?).ok()?.try_into().ok()?;
    // The key's id: the first four bytes of SHA-256 of the name, a newline, 0x01 (Ed25519), the key.
    let id = sha256(&[name.as_bytes(), b"\n\x01", key]);
    let signed = signatures
        .split('\n')
        .filter_map(|line| line.strip_prefix("\u{2014} ")?.split_once(' '))
        .any(|(who, body)| {
            let body = STANDARD
                .decode(body)
                .ok()
                .filter(|b| b.len() == 68 && b[..4] == id[..4]);
            who == name
                && body.is_some_and(|b| {
                    UnparsedPublicKey::new(&ED25519, key)
                        .verify(text.as_bytes(), &b[4..])
                        .is_ok()
                })
        });
    signed.then_some((size, root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("leaf {i}").into_bytes()).collect()
    }

    /// The tree's root, RFC 9162 section 2.1.1: split at the largest power of two below n.
    fn root(d: &[Vec<u8>]) -> Hash {
        match d.len() {
            0 => sha256(&[]),
            1 => leaf_hash(&d[0]),
            n => {
                let (l, r) = d.split_at(n.next_power_of_two() / 2);
                node_hash(&root(l), &root(r))
            }
        }
    }

    /// The audit path of leaf `m`, RFC 9162 section 2.1.3.1.
    fn path(m: usize, d: &[Vec<u8>]) -> Vec<Hash> {
        if d.len() <= 1 {
            return vec![];
        }
        let k = d.len().next_power_of_two() / 2;
        if m < k {
            [path(m, &d[..k]), vec![root(&d[k..])]].concat()
        } else {
            [path(m - k, &d[k..]), vec![root(&d[..k])]].concat()
        }
    }

    #[test]
    fn tlog_every_leaf_of_small_trees_proves_inclusion() {
        for size in 1..=17 {
            let d = leaves(size);
            for (i, leaf) in d.iter().enumerate() {
                let ok = verify_inclusion(leaf, i as u64, size as u64, &path(i, &d), &root(&d));
                assert!(ok, "leaf {i} of {size}");
            }
        }
    }

    #[test]
    fn tlog_a_proof_that_does_not_reach_the_root_is_refused() {
        let d = leaves(11);
        let (i, good, r) = (5, path(5, &d), root(&d));
        let check = verify_inclusion;
        assert!(check(&d[i], 5, 11, &good, &r));
        assert!(!check(b"other", 5, 11, &good, &r), "wrong leaf");
        assert!(!check(&d[i], 4, 11, &good, &r), "wrong index");
        assert!(!check(&d[i], 11, 11, &good, &r), "index past the size");
        // Sizes 9 to 16 give leaf 5 the same path shape, so only the checkpoint's size binds those.
        assert!(!check(&d[i], 5, 17, &good, &r), "larger size");
        assert!(!check(&d[i], 5, 6, &good, &r), "smaller size");
        let mut changed = good.clone();
        changed[1][0] ^= 1;
        assert!(!check(&d[i], 5, 11, &changed, &r), "changed hash");
        assert!(
            !check(&d[i], 5, 11, &[good.clone(), vec![[0; 32]]].concat(), &r),
            "extra hash"
        );
        assert!(!check(&d[i], 5, 11, &good[..good.len() - 1], &r), "missing hash");
        assert!(!check(&d[i], 5, 11, &[], &r), "no proof");
        let mut bad = r;
        bad[31] ^= 1;
        assert!(!check(&d[i], 5, 11, &good, &bad), "bad root");
        // A lone leaf is its own root, and only with no proof.
        assert!(check(&d[0], 0, 1, &[], &leaf_hash(&d[0])));
        assert!(!check(&d[0], 0, 0, &[], &leaf_hash(&d[0])), "empty tree");
    }

    const ORIGIN: &str = "log.example/1";
    const BODY: &str = "log.example/1\n7\n";

    fn read(note: &str, name: &str, key: &Hash) -> Option<(u64, Hash)> {
        checkpoint(note, ORIGIN, name, key)
    }

    /// The note with its first signature line's decoded body (key id, signature) changed by `edit`.
    fn resigned(note: &str, edit: impl Fn(&mut Vec<u8>)) -> String {
        let (text, line) = note.split_once("\n\n").unwrap();
        let (who, body) = line.trim_end().rsplit_once(' ').unwrap();
        let mut body = STANDARD.decode(body).unwrap();
        edit(&mut body);
        format!("{text}\n\n{who} {}\n", STANDARD.encode(body))
    }

    fn note(seed: u8, name: &str, text: &str) -> (String, Hash) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let key: Hash = pair.public_key().as_ref().try_into().unwrap();
        let id = sha256(&[name.as_bytes(), b"\n\x01", &key]);
        let body = [&id[..4], pair.sign(text.as_bytes()).as_ref()].concat();
        (format!("{text}\n\u{2014} {name} {}\n", STANDARD.encode(body)), key)
    }

    #[test]
    fn tlog_a_checkpoint_is_read_only_when_its_key_signed_it() {
        let hash = [9u8; 32];
        let text = format!("{BODY}{}\n", STANDARD.encode(hash));
        let (signed, key) = note(1, "log.example", &text);
        assert_eq!(read(&signed, "log.example", &key), Some((7, hash)));
        let (_, other) = note(2, "log.example", &text);
        assert_eq!(read(&signed, "log.example", &other), None, "another key");
        assert_eq!(read(&signed, "other.example", &key), None, "another name");
        assert_eq!(
            read(&signed.replace("\n7\n", "\n8\n"), "log.example", &key),
            None,
            "changed size"
        );
        assert_eq!(
            read(&signed.replace("log.example/1", "log.example/2"), "log.example", &key),
            None,
            "origin"
        );
        let unsigned = format!("{text}\n");
        assert_eq!(read(&unsigned, "log.example", &key), None, "no signature");
        assert_eq!(read(&text, "log.example", &key), None, "no blank line");
        // A second signer's line beside the key's own is fine; a lone foreign line is not.
        let (foreign, _) = note(2, "witness", &text);
        let foreign_line = foreign.rsplit_once("\n\n").unwrap().1;
        assert_eq!(
            read(&format!("{signed}{foreign_line}"), "log.example", &key),
            Some((7, hash))
        );
        assert_eq!(
            read(&format!("{text}\n{foreign_line}"), "log.example", &key),
            None,
            "foreign signer only"
        );
        // Another origin, signed by the same key, is not this log's checkpoint.
        let (elsewhere, key) = note(1, "log.example", &text.replace("log.example/1", "log.example/9"));
        assert_eq!(read(&elsewhere, "log.example", &key), None, "another origin");
        assert_eq!(
            checkpoint(&elsewhere, "log.example/9", "log.example", &key),
            Some((7, hash))
        );
        assert_eq!(checkpoint(&signed, "", "log.example", &key), None, "no origin named");
        // A CRLF note is refused, signed or not.
        let (crlf, key) = note(1, "log.example", &text.replace('\n', "\r\n"));
        assert_eq!(read(&crlf, "log.example", &key), None, "CRLF");
        let (cr_size, key) = note(1, "log.example", &text.replace("\n7\n", "\n7\r\n"));
        assert_eq!(read(&cr_size, "log.example", &key), None, "CR after the size");
        // A signature body of 67 bytes, or of a flipped key id byte (the signature itself valid).
        assert_eq!(
            read(&resigned(&signed, |b| b.truncate(67)), "log.example", &key),
            None,
            "67 bytes"
        );
        assert_eq!(
            read(&resigned(&signed, |b| b.push(0)), "log.example", &key),
            None,
            "69 bytes"
        );
        assert_eq!(
            read(&resigned(&signed, |b| b[0] ^= 1), "log.example", &key),
            None,
            "flipped key id"
        );
        assert_eq!(
            read(&resigned(&signed, |b| b[4] ^= 1), "log.example", &key),
            None,
            "flipped signature"
        );
        // A size that is not canonical decimal, a short root, and a signature of the wrong length.
        for bad in ["07", "+7", "-7", "7 "] {
            let (n, key) = note(1, "log.example", &text.replace("\n7\n", &format!("\n{bad}\n")));
            assert_eq!(read(&n, "log.example", &key), None, "size {bad:?}");
        }
        let (short, key) = note(1, "log.example", &format!("{BODY}{}\n", STANDARD.encode([9u8; 31])));
        assert_eq!(read(&short, "log.example", &key), None, "short root");
    }
}
