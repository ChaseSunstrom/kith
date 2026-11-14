//! The machine's own TPM, asked to keep a key for this very system.
//!
//! A key is *sealed*: the TPM wraps it under a key of its own that never leaves the chip,
//! with a policy that names the values some of its PCRs must have. The firmware and what
//! it starts extend those PCRs with a hash of each thing before running it, so they come
//! to the same values only when the same firmware started the same boot loader, the same
//! boot file (kith OS's kernel and its command line, which names the system image by its
//! hash) with no command line given in its place, under the same Secure Boot state. kithd
//! adds what no firmware measures and it still obeys: the words of the node's config
//! partition (its name, its addresses, kithd's own arguments), before it asks for any
//! key. Then, and only then, the TPM gives the key back. What is kept on the disk (the sealed blob)
//! opens nothing on another machine, nor on this one started with anything else.
//!
//! The TPM is spoken to as the kernel offers it (`/dev/tpmrm0`: commands in, replies
//! out), in the few commands this takes: no library, no tool of the image.
//
// ponytail: the key crosses the TPM's bus as it is (no encrypted session): whoever probes
// the pins of a discrete TPM while the machine starts reads it. A salted session with
// parameter encryption (an ECDH with the storage key, AES-CFB) if that is to be closed.

use sha2::{Digest, Sha256};
use std::io::{Read, Write};

/// What a key is sealed to, in the SHA-256 bank: 0 the firmware; 4 what it started (the
/// boot loader, and the boot file with the kernel and its command line); 7 whether Secure
/// Boot is on and whose keys it trusts; 9 and 12 a command line (or an initramfs) given
/// from outside the boot file; 15 what kithd itself measured at this start ([`measure`]).
pub const PCRS: [u8; 6] = [0, 4, 7, 9, 12, MEASURED];
/// The PCR kithd extends.
const MEASURED: u8 = 15;
/// Those that hold something on any machine whose firmware (and kithd) measured at all.
const NEVER_EMPTY: [u8; 3] = [0, 4, MEASURED];

const NO_SESSIONS: u16 = 0x8001;
const SESSIONS: u16 = 0x8002;
const SHA256: u16 = 0x000b;
const NULL: u16 = 0x0010;
/// The owner's hierarchy, nobody's handle, and "the password is in this very field".
const OWNER: u32 = 0x4000_0001;
const NOBODY: u32 = 0x4000_0007;
const PASSWORD: u32 = 0x4000_0009;
/// The commands.
const CREATE_PRIMARY: u32 = 0x131;
const CREATE: u32 = 0x153;
const LOAD: u32 = 0x157;
const UNSEAL: u32 = 0x15e;
const FLUSH: u32 = 0x165;
const START_SESSION: u32 = 0x176;
const PCR_READ: u32 = 0x17e;
const PCR_EXTEND: u32 = 0x182;
const POLICY_PCR: u32 = 0x17f;
/// What a policy session that the PCRs do not satisfy is refused with.
const POLICY_FAILED: u32 = 0x99d;

pub struct Tpm<T>(pub T);

/// The machine's TPM, if it has one.
pub fn open() -> Result<Tpm<std::fs::File>, String> {
    let device = std::fs::File::options().read(true).write(true).open("/dev/tpmrm0");
    device
        .map(Tpm)
        .map_err(|e| format!("this machine has no TPM to ask (/dev/tpmrm0: {e})"))
}

/// What this start was told from where no firmware measures (the node's config partition,
/// as read), put into the TPM before any key is asked of it: a key sealed under other
/// words is then not given. Where there is no TPM, nothing.
pub fn measure(told: &[u8]) {
    let Ok(mut tpm) = open() else { return };
    if let Err(why) = tpm.extend(MEASURED.into(), &Sha256::digest(told).into()) {
        eprintln!("kithd: init: {why}");
    }
}

/// `bytes` with their length before them, as the TPM reads most things.
fn sized(bytes: &[u8]) -> Vec<u8> {
    [&(bytes.len() as u16).to_be_bytes()[..], bytes].concat()
}

/// An authorization with an empty password, for what asks one of the owner or of a key.
fn password() -> Vec<u8> {
    [&9u32.to_be_bytes()[..], &PASSWORD.to_be_bytes(), &[0; 5]].concat()
}

/// The PCRs as the TPM is told them: one bank, and a bit for each.
fn selection() -> Vec<u8> {
    let mut bits = [0u8; 3];
    for pcr in PCRS {
        bits[usize::from(pcr / 8)] |= 1 << (pcr % 8);
    }
    [&1u32.to_be_bytes()[..], &SHA256.to_be_bytes(), &[3], &bits].concat()
}

/// A reply, read from its start.
struct Reply<'a>(&'a [u8]);

impl<'a> Reply<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let (taken, rest) = self.0.split_at_checked(length).ok_or("the TPM's reply is cut short")?;
        self.0 = rest;
        Ok(taken)
    }

    fn number(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    /// Something with its length before it; `whole`: the length too, as it is given back.
    fn sized(&mut self, whole: bool) -> Result<&'a [u8], String> {
        let all = self.0;
        let length = usize::from(u16::from_be_bytes(self.take(2)?.try_into().expect("two bytes")));
        let inside = self.take(length)?;
        Ok(if whole { &all[..2 + length] } else { inside })
    }
}

impl<T: Read + Write> Tpm<T> {
    /// One command: what the reply holds after its header, or the TPM's refusal.
    fn run(&mut self, tag: u16, command: u32, body: &[u8]) -> Result<Vec<u8>, String> {
        let length = (10 + body.len()) as u32;
        let said = [
            &tag.to_be_bytes()[..],
            &length.to_be_bytes(),
            &command.to_be_bytes(),
            body,
        ]
        .concat();
        let io = |e: std::io::Error| format!("asking the TPM: {e}");
        self.0.write_all(&said).map_err(io)?;
        // (The device gives a reply whole; a socket may give it in parts.)
        let (mut reply, mut have) = (vec![0; 4096], 0);
        let whole = loop {
            let whole = reply
                .get(2..6)
                .map(|length| u32::from_be_bytes(length.try_into().expect("four bytes")) as usize);
            match whole.filter(|whole| have >= 10 && have >= *whole) {
                Some(whole) => break whole.max(10),
                None => match self.0.read(&mut reply[have..]).map_err(io)? {
                    0 => return Err("the TPM's reply is cut short".into()),
                    more => have += more,
                },
            }
        };
        match u32::from_be_bytes(reply[6..10].try_into().expect("four bytes")) {
            0 => Ok(reply[10..whole].to_vec()),
            POLICY_FAILED => Err("the TPM does not give the key: this is not the system it was sealed for".into()),
            refused => Err(format!("the TPM refuses (its code {refused:#x})")),
        }
    }

    /// A PCR extended with `digest`, as firmware does with what it is about to start.
    pub fn extend(&mut self, pcr: u32, digest: &[u8; 32]) -> Result<(), String> {
        let body = [
            &pcr.to_be_bytes()[..],
            &password(),
            &1u32.to_be_bytes(),
            &SHA256.to_be_bytes(),
            digest,
        ]
        .concat();
        self.run(SESSIONS, PCR_EXTEND, &body).map(drop)
    }

    /// Have the TPM forget a key or a session it holds for this.
    fn flush(&mut self, handle: u32) {
        let _ = self.run(NO_SESSIONS, FLUSH, &handle.to_be_bytes());
    }

    /// The key under which things are sealed: the TPM makes the same one each time it is
    /// asked this way, from a seed it never shows, so none is kept anywhere.
    fn parent(&mut self) -> Result<u32, String> {
        // An elliptic-curve key (P-256) that only wraps what is under it (AES-128-CFB).
        let public = [
            &0x0023u16.to_be_bytes()[..],
            &SHA256.to_be_bytes(),
            // (Of this TPM and this parent only, its secret made by the TPM, used with its
            // password (empty), not counted against guesses; restricted, decrypting.)
            &0x0003_0472u32.to_be_bytes(),
            &sized(&[]),
            &[0x00, 0x06, 0x00, 0x80, 0x00, 0x43],
            &NULL.to_be_bytes(),
            &0x0003u16.to_be_bytes(),
            &NULL.to_be_bytes(),
            &sized(&[]),
            &sized(&[]),
        ]
        .concat();
        let nothing = [sized(&[]), sized(&[])].concat();
        let body = [
            &OWNER.to_be_bytes()[..],
            &password(),
            &sized(&nothing),
            &sized(&public),
            &sized(&[]),
            &0u32.to_be_bytes(),
        ]
        .concat();
        let made = self.run(SESSIONS, CREATE_PRIMARY, &body)?;
        Reply(&made).number()
    }

    /// What a policy session comes to once it has been shown the PCRs as they are now:
    /// what a key sealed now asks of whoever wants it back.
    fn policy(&mut self) -> Result<[u8; 32], String> {
        let read = self.run(NO_SESSIONS, PCR_READ, &selection())?;
        let mut read = Reply(&read);
        read.number()?;
        let all = read.take(10)? == selection() && read.number()? as usize == PCRS.len();
        if !all {
            return Err("this TPM does not keep the PCRs in SHA-256".into());
        }
        let mut values = Vec::new();
        for pcr in PCRS {
            let value = read.sized(false)?;
            if NEVER_EMPTY.contains(&pcr) && value.iter().all(|byte| *byte == 0) {
                return Err(format!(
                    "PCR {pcr} of this machine's TPM holds nothing (its firmware, or this start, measured nothing into it): a key sealed here would open for any system"
                ));
            }
            values.extend(value);
        }
        let shown = [
            &[0; 32][..],
            &POLICY_PCR.to_be_bytes(),
            &selection(),
            &Sha256::digest(&values),
        ]
        .concat();
        Ok(Sha256::digest(shown).into())
    }

    /// `key` (128 bytes at most) sealed to this TPM and to the PCRs as they are now: what
    /// to keep, and to give [`Tpm::unseal`].
    pub fn seal(&mut self, key: &[u8]) -> Result<Vec<u8>, String> {
        let policy = self.policy()?;
        let parent = self.parent()?;
        let secret = [sized(&[]), sized(key)].concat();
        // Data kept under a hash, of this TPM and this parent only, with no password (so
        // none to guess, and no guess counted): the policy alone opens it.
        let public = [
            &0x0008u16.to_be_bytes()[..],
            &SHA256.to_be_bytes(),
            &0x0000_0412u32.to_be_bytes(),
            &sized(&policy),
            &NULL.to_be_bytes(),
            &sized(&[]),
        ]
        .concat();
        let body = [
            &parent.to_be_bytes()[..],
            &password(),
            &sized(&secret),
            &sized(&public),
            &sized(&[]),
            &0u32.to_be_bytes(),
        ]
        .concat();
        let made = self.run(SESSIONS, CREATE, &body);
        self.flush(parent);
        let made = made?;
        let mut made = Reply(&made);
        made.number()?;
        Ok([made.sized(true)?, made.sized(true)?].concat())
    }

    /// The key that was sealed as `sealed`, if this is the TPM and the system it was
    /// sealed for.
    pub fn unseal(&mut self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        let parent = self.parent()?;
        let loaded = self.run(
            SESSIONS,
            LOAD,
            &[&parent.to_be_bytes()[..], &password(), sealed].concat(),
        );
        self.flush(parent);
        let item = Reply(&loaded?).number()?;
        let key = self.shown(item);
        self.flush(item);
        key
    }

    /// The PCRs shown to a policy session, and what the TPM then gives of `item`.
    fn shown(&mut self, item: u32) -> Result<Vec<u8>, String> {
        // (Nothing is signed with the session, so what it is started with is no secret.)
        let start = [
            &NOBODY.to_be_bytes()[..],
            &NOBODY.to_be_bytes(),
            &sized(&[0; 16]),
            &sized(&[]),
            &[1],
            &NULL.to_be_bytes(),
            &SHA256.to_be_bytes(),
        ]
        .concat();
        let session = Reply(&self.run(NO_SESSIONS, START_SESSION, &start)?).number()?;
        let pcrs = [&session.to_be_bytes()[..], &sized(&[]), &selection()].concat();
        let by = [
            &item.to_be_bytes()[..],
            &9u32.to_be_bytes(),
            &session.to_be_bytes(),
            &[0; 5],
        ]
        .concat();
        let given = self.run(NO_SESSIONS, POLICY_PCR, &pcrs);
        let given = given.and_then(|_| self.run(SESSIONS, UNSEAL, &by));
        if given.is_err() {
            // (One that opened something ended with it.)
            self.flush(session);
        }
        let given = given?;
        let mut given = Reply(&given);
        given.number()?;
        Ok(given.sized(false)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn extend(tpm: &mut Tpm<UnixStream>, pcr: u32, with: u8) {
        tpm.extend(pcr, &[with; 32]).unwrap();
    }

    /// README.md and SECURITY.md name the PCRs a key is sealed to: these.
    #[test]
    fn tpm_pcrs_are_the_ones_the_documents_name() {
        let (last, first) = PCRS.split_last().unwrap();
        let first: Vec<String> = first.iter().map(u8::to_string).collect();
        let named = format!("PCRs {} and {last}", first.join(", "));
        for (name, text) in [
            ("README.md", include_str!("../../../README.md")),
            ("SECURITY.md", include_str!("../../../SECURITY.md")),
        ] {
            assert!(text.contains(&named), "{name} does not say: {named}");
        }
        let readme = include_str!("../../../README.md");
        assert!(readme.contains("What the seal does not cover"));
    }

    /// A software TPM, ended and its files removed with the test.
    struct Software(std::process::Child, std::path::PathBuf);

    impl Drop for Software {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }

    /// Against a software TPM (swtpm; a machine without one checks nothing here, which CI
    /// is not let to be, and `sh ci/vm.sh --test tpm` is what checks it whole): a key sealed comes back while the PCRs
    /// stand, and is refused once one has moved; sealed again, it comes back again.
    #[test]
    fn tpm_gives_a_sealed_key_back_to_the_same_system_only() {
        let dir = std::env::temp_dir().join(format!("kith-tpm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let at = |name: &str| format!("type=unixio,path={}", dir.join(name).display());
        let software = std::process::Command::new("swtpm")
            .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
            .args(["--tpmstate", &format!("dir={}", dir.display())])
            .args(["--server", &at("tpm"), "--ctrl", &at("ctrl")])
            .spawn();
        let Ok(software) = software else {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI has no swtpm: the TPM's commands would go unchecked"
            );
            return eprintln!("no swtpm on this machine: the TPM's commands were not checked here");
        };
        let _software = Software(software, dir.clone());
        let mut tries = 0;
        let stream = loop {
            match UnixStream::connect(dir.join("tpm")) {
                Ok(stream) => break stream,
                Err(e) if tries == 250 => panic!("swtpm does not answer: {e}"),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
            tries += 1;
        };
        let mut tpm = Tpm(stream);
        let key: Vec<u8> = (0..64).collect();

        // Nothing measured: nothing is sealed to that. Nor while the firmware has measured
        // and kithd has not, or the other way round.
        for measured in [None, Some(0), Some(4), Some(MEASURED)] {
            let refused = tpm.seal(&key).unwrap_err();
            assert!(refused.contains("holds nothing"), "{measured:?}: {refused}");
            if let Some(pcr) = measured {
                extend(&mut tpm, pcr.into(), pcr);
            }
        }
        for pcr in PCRS.into_iter().filter(|pcr| !NEVER_EMPTY.contains(pcr)) {
            extend(&mut tpm, pcr.into(), pcr);
        }
        let sealed = tpm.seal(&key).unwrap();
        assert!(
            !sealed.windows(8).any(|window| window == &key[..8]),
            "the key is in what is kept"
        );
        assert_eq!(tpm.unseal(&sealed).as_ref(), Ok(&key));
        assert_eq!(tpm.unseal(&sealed).as_ref(), Ok(&key), "a second time");
        // What is kept, changed anywhere, is nothing the TPM made.
        let mut other = sealed.clone();
        other[20] ^= 1;
        assert!(tpm.unseal(&other).is_err());
        // Each PCR on its own: once it has moved, the key is not given.
        for pcr in PCRS {
            let sealed = tpm.seal(&key).unwrap();
            assert_eq!(tpm.unseal(&sealed).as_ref(), Ok(&key));
            extend(&mut tpm, pcr.into(), 0xee);
            let refused = tpm.unseal(&sealed).unwrap_err();
            assert!(
                refused.contains("not the system it was sealed for"),
                "PCR {pcr}: {refused}"
            );
        }
        // And a PCR that is not one of them changes nothing.
        let sealed = tpm.seal(&key).unwrap();
        extend(&mut tpm, 14, 1);
        assert_eq!(tpm.unseal(&sealed).as_ref(), Ok(&key));
    }
}
