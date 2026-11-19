//! What PCR 4 and PCR 9 will read after an update, from a TCG event log and the two boot
//! files alone (docs/adr-unlock.md, "How the new values are predicted", steps 1 to 3).
//!
//! Pure functions over bytes: no TPM command, no file, no device. The log is the TCG
//! crypto-agile one the kernel gives (SHA-256 digests); it is replayed, and only where the
//! replay is what TPM2_PCR_Read gave is anything predicted. The event that holds the
//! running boot file's PE Authenticode hash (PCR 4) is then made again from the new file,
//! and so is the one that holds its command line (PCR 9), in the form the running log's
//! event proves: where no event matches the running file's command line in any of the
//! four forms, nothing is predicted.

use sha2::{Digest, Sha256};

type Hash = [u8; 32];

/// What a refusal says when the replay is not what the TPM reads.
pub const UNEXPLAINED: &str = "the event log does not explain this start";
const NO_BOOT_FILE: &str = "the event log has no event for the running boot file";
const NO_CMDLINE: &str =
    "the event log has no event in PCR 9 that is the running boot file's command line in any of the four forms tried";
const ALG_SHA256: u16 = 0x000B;
const EV_NO_ACTION: u32 = 3;
const PCRS: usize = 24;
/// A digest no algorithm makes is longer than this: a size above it is a corrupt log.
const MAX_DIGEST: usize = 64;

/// One extend the firmware logged: the PCR, the event's type and its SHA-256 digest.
#[derive(Debug, PartialEq)]
pub struct Event {
    pub pcr: u32,
    pub kind: u32,
    pub digest: Hash,
}

fn le16(b: &[u8], at: usize) -> Result<usize, String> {
    Ok(u16::from_le_bytes(take(b, at, 2)?.try_into().unwrap()) as usize)
}

fn le32(b: &[u8], at: usize) -> Result<usize, String> {
    Ok(u32::from_le_bytes(take(b, at, 4)?.try_into().unwrap()) as usize)
}

/// `n` bytes of `b` from `at`, or an error where the input ends first.
fn take(b: &[u8], at: usize, n: usize) -> Result<&[u8], String> {
    at.checked_add(n)
        .and_then(|end| b.get(at..end))
        .ok_or_else(|| "truncated".to_string())
}

/// The Authenticode SHA-256 of a PE file: the whole file but the checksum, the certificate
/// table's entry in the data directory and the certificate table itself. This is the hash
/// the firmware measures an application it starts as.
pub fn authenticode(pe: &[u8]) -> Result<Hash, String> {
    let bad = |why: &str| format!("not a PE file: {why}");
    if take(pe, 0, 2)? != b"MZ" {
        return Err(bad("no MZ header"));
    }
    let nt = le32(pe, 0x3c)?;
    if take(pe, nt, 4)? != b"PE\0\0" {
        return Err(bad("no PE signature"));
    }
    let sections = le16(pe, nt + 6)?;
    let opt = nt + 24;
    let dirs_at = match le16(pe, opt)? {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return Err(bad("unknown optional header")),
    };
    let checksum = opt + 64;
    let headers = le32(pe, opt + 60)?;
    // The certificate table is directory 4, when the file has that many directories.
    let (cert_entry, cert_size) = if le32(pe, dirs_at - 4)? > 4 {
        (Some(dirs_at + 32), le32(pe, dirs_at + 36)?)
    } else {
        (None, 0)
    };
    let mut hashed = Sha256::new();
    hashed.update(take(pe, 0, checksum)?);
    let mut sum = checksum + 4;
    if let Some(entry) = cert_entry {
        hashed.update(take(pe, sum, entry.saturating_sub(sum))?);
        sum = entry + 8;
    }
    hashed.update(take(pe, sum, headers.checked_sub(sum).ok_or_else(|| bad("headers"))?)?);
    sum = headers;
    // Then each section's bytes, in the order they lie in the file.
    let table = opt + le16(pe, nt + 20)?;
    let mut raw = Vec::new();
    for i in 0..sections {
        let at = table + 40 * i;
        raw.push((le32(pe, at + 20)?, le32(pe, at + 16)?));
    }
    raw.sort();
    for (start, size) in raw.into_iter().filter(|r| r.1 > 0) {
        hashed.update(take(pe, start, size)?);
        sum += size;
    }
    // Anything after the sections but the certificate table.
    let tail = pe
        .len()
        .checked_sub(sum + cert_size)
        .ok_or_else(|| bad("certificate table"))?;
    hashed.update(take(pe, sum, tail)?);
    Ok(hashed.finalize().into())
}

/// The events of a crypto-agile log, SHA-256 digests only; `EV_NO_ACTION` ones (the header
/// event, the startup locality) are not extends and are left out.
pub fn parse_log(log: &[u8]) -> Result<Vec<Event>, String> {
    // The first event is the old format's, and its data says which digests follow.
    let size = le32(log, 28)?;
    let spec = take(log, 32, size)?;
    if take(spec, 0, 16)? != b"Spec ID Event03\0" {
        return Err("not a crypto-agile event log".into());
    }
    let mut sizes = Vec::new();
    for i in 0..le32(spec, 24)? {
        // A huge count runs off the end of the data here: take() refuses.
        sizes.push((le16(spec, 28 + 4 * i)?, le16(spec, 30 + 4 * i)?));
    }
    let mut at = 32 + size;
    let mut events = Vec::new();
    while at < log.len() {
        let (pcr, kind) = (le32(log, at)?, le32(log, at + 4)?);
        let mut digest = None;
        let mut next = at + 12;
        for _ in 0..le32(log, at + 8)? {
            let alg = le16(log, next)?;
            let len = sizes
                .iter()
                .find(|s| s.0 == alg)
                .map(|s| s.1)
                .ok_or("a digest of an unknown algorithm")?;
            if len > MAX_DIGEST {
                return Err("a digest too long".into());
            }
            if alg == ALG_SHA256 as usize {
                digest = Some(
                    take(log, next + 2, len)?
                        .try_into()
                        .map_err(|_| "a SHA-256 digest of the wrong size")?,
                );
            }
            next += 2 + len;
        }
        at = next + 4 + le32(log, next)?;
        take(log, 0, at)?;
        if kind != EV_NO_ACTION as usize {
            let digest = digest.ok_or("an event with no SHA-256 digest")?;
            events.push(Event {
                pcr: pcr as u32,
                kind: kind as u32,
                digest,
            });
        }
    }
    Ok(events)
}

fn extend(pcr: &Hash, digest: &Hash) -> Hash {
    Sha256::digest([&pcr[..], &digest[..]].concat()).into()
}

/// Each PCR after the log's extends, from zero (PCRs 17 to 22 start at ones and are not
/// predicted: a replay that includes them is refused where it is compared).
pub fn replay(events: &[Event]) -> Result<[Hash; PCRS], String> {
    let mut pcrs = [[0u8; 32]; PCRS];
    for e in events {
        let pcr = pcrs
            .get_mut(e.pcr as usize)
            .ok_or("an event for a PCR the TPM does not have")?;
        *pcr = extend(pcr, &e.digest);
    }
    Ok(pcrs)
}

/// Whether the log's replay is each of the PCR values read.
pub fn explains(events: &[Event], read: &[(u32, Hash)]) -> Result<(), String> {
    let replayed = replay(events)?;
    for (pcr, value) in read {
        if replayed.get(*pcr as usize) != Some(value) {
            return Err(UNEXPLAINED.into());
        }
    }
    Ok(())
}

/// The command line a boot file (a unified kernel image) carries: its `.cmdline` section,
/// as text, without the zeros that pad it. A line with a zero inside it is refused.
fn cmdline(pe: &[u8]) -> Result<&str, String> {
    let nt = le32(pe, 0x3c)?;
    let table = nt + 24 + le16(pe, nt + 20)?;
    for i in 0..le16(pe, nt + 6)? {
        let at = table + 40 * i;
        if take(pe, at, 8)? != b".cmdline" {
            continue;
        }
        let (virtual_size, raw_size, start) = (le32(pe, at + 8)?, le32(pe, at + 16)?, le32(pe, at + 20)?);
        // (What the section holds is VirtualSize long; the file pads it to SizeOfRawData.)
        let size = if virtual_size == 0 {
            raw_size
        } else {
            virtual_size.min(raw_size)
        };
        let padded = take(pe, start, size)?;
        let line = &padded[..padded.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1)];
        if line.contains(&0) {
            return Err("a command line with a zero in it".into());
        }
        return std::str::from_utf8(line).map_err(|_| "a command line that is not UTF-8".to_string());
    }
    Err("the boot file has no .cmdline section".into())
}

/// What the firmware or the stub may have extended for `text`: the SHA-256 of it as UTF-16
/// little-endian or as UTF-8, with the ending zero or without (the ADR's four forms).
fn forms(text: &str) -> [Hash; 4] {
    let wide: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let of = |bytes: &[u8], zero: &[u8]| -> Hash { Sha256::digest([bytes, zero].concat()).into() };
    [
        of(&wide, &[0, 0]),
        of(&wide, &[]),
        of(text.as_bytes(), &[0]),
        of(text.as_bytes(), &[]),
    ]
}

/// The one event of `pcr` whose digest is `from`, made `to`; any other count is `why`.
fn swap(events: &mut [Event], pcr: u32, from: &Hash, to: Hash, why: &str) -> Result<(), String> {
    let mut held = events.iter_mut().filter(|e| e.pcr == pcr && e.digest == *from);
    match (held.next(), held.next()) {
        (Some(e), None) => {
            e.digest = to;
            Ok(())
        }
        _ => Err(why.into()),
    }
}

/// The PCR 4 and PCR 9 a start will read with `new` as the boot file instead of `running`
/// (the files as they lie on the ESP, whose PCRs `read4` and `read9` are the TPM's now).
/// The log must explain both values, and hold exactly one event for the running file in
/// PCR 4 (its Authenticode hash) and one in PCR 9 (its `.cmdline` in one of the four forms:
/// the form that is there makes the new one). Anything else predicts nothing.
pub fn predict_pcrs(
    log: &[u8],
    read4: &Hash,
    read9: &Hash,
    running: &[u8],
    new: &[u8],
) -> Result<(Hash, Hash), String> {
    let mut events = parse_log(log)?;
    explains(&events, &[(4, *read4), (9, *read9)])?;
    let (old_hash, new_hash) = (authenticode(running)?, authenticode(new)?);
    swap(&mut events, 4, &old_hash, new_hash, NO_BOOT_FILE)?;
    let (old, new) = (forms(cmdline(running)?), forms(cmdline(new)?));
    let present = |form: &usize| events.iter().any(|e| e.pcr == 9 && e.digest == old[*form]);
    let mut found = (0..4).filter(present);
    let form = found.next().ok_or(NO_CMDLINE)?;
    // (Two forms that are both there and would make different events: which one the stub
    // made is not known. An empty line is one such: UTF-16 and UTF-8 of it are the same.)
    if found.any(|other| old[other] != old[form] || new[other] != new[form]) {
        return Err(NO_CMDLINE.into());
    }
    swap(&mut events, 9, &old[form], new[form], NO_CMDLINE)?;
    let replayed = replay(&events)?;
    Ok((replayed[4], replayed[9]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADERS: usize = 0x200;
    const CHECKSUM: usize = 0x98; // e_lfanew 0x40, PE signature and COFF header 24, 64 in
    const CERT_ENTRY: usize = 0xE8; // data directories at 0xC8 (PE32+), the fifth 32 on

    fn put(b: &mut [u8], at: usize, v: &[u8]) {
        b[at..at + v.len()].copy_from_slice(v);
    }

    /// A PE32+ with two sections, listed in the opposite order to where they lie, after a
    /// header whose checksum and certificate entry are `noise`, an overlay and a
    /// certificate table. Returns the file and what the Authenticode hash is hashed from.
    fn pe(noise: u8, cert: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut head = vec![0x11u8; HEADERS];
        put(&mut head, 0, b"MZ");
        put(&mut head, 0x3c, &0x40u32.to_le_bytes());
        put(&mut head, 0x40, b"PE\0\0");
        put(&mut head, 0x46, &2u16.to_le_bytes()); // sections
        put(&mut head, 0x54, &240u16.to_le_bytes()); // SizeOfOptionalHeader
        put(&mut head, 0x58, &0x20bu16.to_le_bytes());
        put(&mut head, 0x58 + 60, &(HEADERS as u32).to_le_bytes());
        put(&mut head, 0xC8 - 4, &16u32.to_le_bytes()); // directories
        let table = 0x58 + 240;
        for (i, (start, size)) in [(0x400u32, 0x100u32), (0x200, 0x200)].iter().enumerate() {
            put(&mut head, table + 40 * i + 16, &size.to_le_bytes());
            put(&mut head, table + 40 * i + 20, &start.to_le_bytes());
        }
        let (a, b, overlay) = ([0xAAu8; 0x200], [0xBBu8; 0x100], b"overlay");
        let mut hashed = [
            &head[..CHECKSUM],
            &head[CHECKSUM + 4..CERT_ENTRY],
            &head[CERT_ENTRY + 8..],
        ]
        .concat();
        hashed.extend_from_slice(&[&a[..], &b[..], &overlay[..]].concat());
        put(&mut head, CHECKSUM, &[noise; 4]);
        put(&mut head, CERT_ENTRY, &(0x600u32).to_le_bytes());
        put(&mut head, CERT_ENTRY + 4, &(cert.len() as u32).to_le_bytes());
        ([&head[..], &a[..], &b[..], &overlay[..], cert].concat(), hashed)
    }

    #[test]
    fn tpm_predict_authenticode() {
        let (file, hashed) = pe(0x55, &[0xCC; 24]);
        let want: Hash = Sha256::digest(&hashed).into();
        assert_eq!(authenticode(&file).unwrap(), want);
        // another checksum and another certificate table: the same hash
        let (other, _) = pe(0x99, &[0xDD; 40]);
        assert_eq!(authenticode(&other).unwrap(), want);
        let (none, _) = pe(0, &[]);
        assert_eq!(authenticode(&none).unwrap(), want);
        // a changed section byte is another hash
        let mut changed = file.clone();
        changed[0x210] ^= 1;
        assert_ne!(authenticode(&changed).unwrap(), want);
        // truncated at the headers, at a section, and with the certificate table cut short
        // of what the entry says
        for cut in [0x40, 0x100, 0x300, 0x500] {
            assert!(authenticode(&file[..cut]).is_err(), "cut at {cut}");
        }
        assert!(authenticode(&file[..file.len() - 30]).is_err());
        // bad headers
        for (at, v) in [(0, 0x4Eu8), (0x40, b'X'), (0x58, 7), (0x3c, 0xFF)] {
            let mut bad = file.clone();
            bad[at] = v;
            assert!(authenticode(&bad).is_err(), "byte {at}");
        }
    }

    const SPEC: &[u8] = b"Spec ID Event03\0";

    /// A log of the events `(pcr, kind, digest)`, SHA-256 and SHA-1 digests in each (the
    /// SHA-1 ones as the firmware has them when it extends both banks), after a header
    /// event and a startup locality one.
    fn log(events: &[(u32, u32, Hash)]) -> Vec<u8> {
        let mut spec = SPEC.to_vec();
        spec.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 2]); // class, minor, major, errata, uintn
        spec.extend_from_slice(&2u32.to_le_bytes());
        for (alg, len) in [(4u16, 20u16), (0xB, 32)] {
            spec.extend_from_slice(&alg.to_le_bytes());
            spec.extend_from_slice(&len.to_le_bytes());
        }
        spec.push(0);
        let mut out = [
            &0u32.to_le_bytes()[..],
            &3u32.to_le_bytes(),
            &[0; 20],
            &(spec.len() as u32).to_le_bytes(),
            &spec,
        ]
        .concat();
        let mut one = |pcr: u32, kind: u32, digest: Hash, data: &[u8]| {
            out.extend_from_slice(&pcr.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&2u32.to_le_bytes());
            out.extend_from_slice(&4u16.to_le_bytes());
            out.extend_from_slice(&[7; 20]);
            out.extend_from_slice(&0xBu16.to_le_bytes());
            out.extend_from_slice(&digest);
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        };
        one(0, 3, [0; 32], b"StartupLocality\0\x03");
        for (pcr, kind, digest) in events {
            one(*pcr, *kind, *digest, b"event data");
        }
        out
    }

    fn chain(digests: &[Hash]) -> Hash {
        digests
            .iter()
            .fold([0; 32], |pcr, d| Sha256::digest([&pcr[..], &d[..]].concat()).into())
    }

    fn sha(s: &str) -> Hash {
        Sha256::digest(s).into()
    }

    #[test]
    fn tpm_predict_replay() {
        let (a, b, c, d) = (sha("a"), sha("b"), sha("c"), sha("d"));
        let bytes = log(&[(0, 1, a), (4, 0x8000_0003, b), (7, 1, c), (4, 0x8000_0003, d)]);
        let events = parse_log(&bytes).unwrap();
        assert_eq!(events.len(), 4, "the NO_ACTION event is not an extend");
        assert_eq!(
            events[1],
            Event {
                pcr: 4,
                kind: 0x8000_0003,
                digest: b
            }
        );
        let pcrs = replay(&events).unwrap();
        assert_eq!(pcrs[4], chain(&[b, d]));
        assert_eq!(pcrs[0], chain(&[a]));
        assert_eq!(pcrs[1], [0; 32]);
        assert_eq!(explains(&events, &[(4, chain(&[b, d])), (7, chain(&[c]))]), Ok(()));
        // a start the log does not describe
        assert_eq!(explains(&events, &[(4, chain(&[b]))]), Err(UNEXPLAINED.into()));
        assert_eq!(
            explains(&events, &[(4, chain(&[b, d])), (7, [0; 32])]),
            Err(UNEXPLAINED.into())
        );
        // an event for a PCR the TPM has not, a log that is not crypto-agile, a cut one
        assert!(
            replay(&[Event {
                pcr: 24,
                kind: 1,
                digest: a
            }])
            .is_err()
        );
        let mut old = bytes.clone();
        old[32] = b'X';
        assert!(parse_log(&old).is_err());
        for cut in [10, 40, 80, bytes.len() - 1, bytes.len() - 20] {
            assert!(parse_log(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        // a digest count that runs past the end, and a spec naming a million algorithms
        let mut many = bytes.clone();
        let first = 32 + le32(&bytes, 28).unwrap();
        many[first + 8..first + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_log(&many).is_err());
        let mut algs = bytes.clone();
        algs[32 + 24..32 + 28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_log(&algs).is_err());
    }

    /// A boot file like `pe`'s with `line` for its `.cmdline` section (the first, at
    /// 0x400, padded with zeros), and a byte of the other section flipped by `flip`.
    fn uki(line: &str, flip: u8) -> Vec<u8> {
        let (mut file, _) = pe(1, &[]);
        put(&mut file, 0x148, b".cmdline");
        put(&mut file, 0x148 + 8, &(line.len() as u32).to_le_bytes());
        file[0x400..0x500].fill(0);
        put(&mut file, 0x400, line.as_bytes());
        file[0x210] ^= flip;
        file
    }

    #[test]
    fn tpm_next_predict_changed() {
        let running = uki("root=/dev/vda quiet", 0);
        let new = uki("root=/dev/vdb quiet", 0xFF);
        let (r, n) = (authenticode(&running).unwrap(), authenticode(&new).unwrap());
        assert_ne!(r, n);
        let (fw, other) = (sha("firmware"), sha("other"));
        let (c9, c9n) = (forms("root=/dev/vda quiet")[0], forms("root=/dev/vdb quiet")[0]);
        let read9 = chain(&[c9, other]);
        let bytes = log(&[
            (4, 0x8000_0003, fw),
            (4, 0x8000_0003, r),
            (4, 0x8000_0003, other),
            (7, 1, r),
            (9, 0x0D, c9),
            (9, 0x0D, other),
        ]);
        let read = chain(&[fw, r, other]);
        // the event for the running file is the new file's, and PCR 7 is not touched
        assert_eq!(
            predict_pcrs(&bytes, &read, &read9, &running, &new),
            Ok((chain(&[fw, n, other]), chain(&[c9n, other])))
        );
        // a log that is not this start's predicts nothing: not in PCR 4, not in PCR 9
        assert_eq!(
            predict_pcrs(&bytes, &chain(&[fw, r]), &read9, &running, &new),
            Err(UNEXPLAINED.into())
        );
        assert_eq!(
            predict_pcrs(&bytes, &read, &chain(&[c9]), &running, &new),
            Err(UNEXPLAINED.into())
        );
        // no event for the running boot file
        let mut moved = running.clone();
        moved[0x210] ^= 1;
        assert_eq!(
            predict_pcrs(&bytes, &read, &read9, &moved, &new),
            Err(NO_BOOT_FILE.into())
        );
        // the running file's digest in PCR 7 only is no event of PCR 4
        let seven = log(&[(4, 1, fw), (7, 1, r), (9, 1, c9)]);
        assert_eq!(
            predict_pcrs(&seven, &chain(&[fw]), &chain(&[c9]), &running, &new),
            Err(NO_BOOT_FILE.into())
        );
        // two events for it: which one is the boot file is not known
        let twice = log(&[(4, 1, r), (4, 1, r), (9, 1, c9)]);
        assert_eq!(
            predict_pcrs(&twice, &chain(&[r, r]), &chain(&[c9]), &running, &new),
            Err(NO_BOOT_FILE.into())
        );
        // a new file that is not a PE
        assert!(predict_pcrs(&bytes, &read, &read9, &running, b"not a PE").is_err());
    }

    #[test]
    fn tpm_next_predict_forms() {
        let (running, new) = (uki("root=/dev/vda quiet", 0), uki("root=/dev/vdb quiet", 0xFF));
        let (r, n) = (authenticode(&running).unwrap(), authenticode(&new).unwrap());
        let (old, next) = (forms("root=/dev/vda quiet"), forms("root=/dev/vdb quiet"));
        let (read4, other) = (chain(&[r]), sha("other"));
        // each of the four forms is matched, and the new line is made in that form
        for form in 0..4 {
            for first in [0, 1] {
                let mut nine = [other, other];
                nine[first] = old[form];
                let bytes = log(&[(4, 0x8000_0003, r), (9, 1, nine[0]), (9, 1, nine[1])]);
                let mut want = nine;
                want[first] = next[form];
                assert_eq!(
                    predict_pcrs(&bytes, &read4, &chain(&nine), &running, &new),
                    Ok((chain(&[n]), chain(&want))),
                    "form {form}"
                );
            }
        }
        // the form is told by the event: a line measured in no form tried predicts nothing
        let at = |events: &[(u32, u32, Hash)]| {
            let nine: Vec<Hash> = events.iter().filter(|e| e.0 == 9).map(|e| e.2).collect();
            let bytes = log(&[&[(4, 0x8000_0003, r)][..], events].concat());
            predict_pcrs(&bytes, &read4, &chain(&nine), &running, &new)
        };
        assert_eq!(at(&[(9, 1, other)]), Err(NO_CMDLINE.into()));
        assert_eq!(at(&[(9, 1, forms("root=/dev/vda debug")[0])]), Err(NO_CMDLINE.into()));
        assert_eq!(at(&[]), Err(NO_CMDLINE.into()));
        // an event of another PCR is not the command line's
        assert_eq!(at(&[(8, 1, old[0]), (9, 1, other)]), Err(NO_CMDLINE.into()));
        // two forms both there, or one form twice: which one is the stub's is not known
        assert_eq!(at(&[(9, 1, old[0]), (9, 1, old[3])]), Err(NO_CMDLINE.into()));
        assert_eq!(at(&[(9, 1, old[1]), (9, 1, old[1])]), Err(NO_CMDLINE.into()));
        // an empty running line has one digest for UTF-16 without its zero and UTF-8
        // without its zero alike: a new line that would differ between them is refused
        let empty = uki("", 0);
        let e = authenticode(&empty).unwrap();
        let blank = forms("");
        assert_eq!(blank[1], blank[3]);
        let measured = log(&[(4, 1, e), (9, 1, blank[3])]);
        assert_eq!(
            predict_pcrs(&measured, &chain(&[e]), &chain(&[blank[3]]), &empty, &new),
            Err(NO_CMDLINE.into())
        );
        // and one that is the same in both is predicted
        let still = uki("", 0xFF);
        let s = authenticode(&still).unwrap();
        assert_eq!(
            predict_pcrs(&measured, &chain(&[e]), &chain(&[blank[3]]), &empty, &still),
            Ok((chain(&[s]), chain(&[blank[3]])))
        );
        // a boot file without a .cmdline, with a zero in it, or that is not UTF-8
        let (plain, _) = pe(1, &[]);
        assert!(cmdline(&plain).is_err());
        let mut inner = uki("abc", 0);
        inner[0x401] = 0;
        assert!(cmdline(&inner).is_err());
        let mut bad = uki("ab", 0);
        bad[0x400] = 0xFF;
        assert!(cmdline(&bad).is_err());
        // padding after the line is not the line, and a section cut short is no line
        assert_eq!(cmdline(&running), Ok("root=/dev/vda quiet"));
        assert!(cmdline(&running[..0x410]).is_err());
        assert!(cmdline(b"MZ").is_err());
    }

    #[test]
    fn tpm_next_forms_by_hand() {
        let h = |b: &[u8]| -> Hash { Sha256::digest(b).into() };
        // "ab" in the four forms, written out by hand, in the order forms() lists them
        assert_eq!(
            forms("ab"),
            [
                h(&[0x61, 0, 0x62, 0, 0, 0]),
                h(&[0x61, 0, 0x62, 0]),
                h(&[0x61, 0x62, 0]),
                h(&[0x61, 0x62]),
            ]
        );
        // U+1F600 is past the BMP: a surrogate pair, D83D DE00, little-endian 3D D8 00 DE
        assert_eq!(forms("\u{1F600}")[1], h(&[0x3D, 0xD8, 0x00, 0xDE]));
        // é is one UTF-16 unit and two UTF-8 bytes
        assert_eq!(forms("é")[1], h(&[0xE9, 0]));
        assert_eq!(forms("é")[3], h(&[0xC3, 0xA9]));
    }
}
