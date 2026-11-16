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
//!
//! The key crosses the TPM's bus (a discrete TPM's pins can be probed) only encrypted: the
//! commands that carry it, or answer with it, run in a session salted to the storage key
//! (an ECDH with it), their parameters in AES-128-CFB and each answer's HMAC checked before
//! anything in it is used. The storage key's name is kept with the seal, and an unseal
//! stops before anything is sent once the TPM's differs: another TPM, or something on the
//! bus handing out its own key. Not kept out: whoever was on the bus when the seal was made
//! (the name kept is then theirs; only the TPM's endorsement certificate would tell), and
//! whoever resets the TPM and replays the measurements.
//! (TPM 2.0 Library, Part 1: ECDH secret sharing, KDFa and KDFe, session key, HMAC,
//! parameter encryption.)

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use ring::{agreement, hmac};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

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
pub(crate) const UNSEAL: u32 = 0x15e;
const FLUSH: u32 = 0x165;
const START_SESSION: u32 = 0x176;
const PCR_READ: u32 = 0x17e;
const PCR_EXTEND: u32 = 0x182;
const POLICY_PCR: u32 = 0x17f;
const POLICY_AUTH_VALUE: u32 = 0x16b;
const GET_CAPABILITY: u32 = 0x17a;
const HIERARCHY_CHANGE_AUTH: u32 = 0x129;
const DA_RESET: u32 = 0x139;
#[cfg(test)]
const DA_PARAMETERS: u32 = 0x13a;
/// The lockout hierarchy: whoever holds its authorization can forgive wrong PINs, and set
/// how many are let through.
const LOCKOUT: u32 = 0x4000_000a;
/// What a policy session that the PCRs do not satisfy is refused with.
const POLICY_FAILED: u32 = 0x99d;
/// What a wrong authorization of something counted against guesses is refused with (the
/// first session's), and what every one is while the TPM is locked out.
const AUTH_FAIL: u32 = 0x98e;
const IN_LOCKOUT: u32 = 0x921;
/// What a wrong authorization not counted against guesses is refused with (the first
/// session's).
const BAD_AUTH: u32 = 0x9a2;
pub const NOT_THE_PIN: &str =
    "the TPM refuses that PIN: it is not the one this node's key was sealed with (each wrong one is counted)";
pub const LOCKED_OUT: &str = "the TPM refuses every PIN for now: too many wrong ones were tried";
/// What setting a PIN is refused with when somebody other than kithd took the lockout's
/// authorization, or the one kithd keeps is not the TPM's: it could forgive every wrong PIN.
pub const CLEAR_FIRST: &str = "somebody holds this TPM's lockout authorization, and kithd does not (it keeps none, or the TPM refused the one it keeps; a refused one also shuts the TPM's lockout hierarchy for its recovery time): whoever does could forgive every wrong PIN. Clear the TPM in the firmware's settings first";
/// A year, in seconds: what a PIN's guesses are counted over.
const YEAR: u32 = 31_536_000;
/// A session's kinds; its cipher (AES, 128 bits, CFB); and what it does for one command:
/// the first parameter crosses encrypted (`DECRYPT`, for the TPM to decrypt), the answer's
/// first does (`ENCRYPT`). Neither continues the session: it ends with that command.
const HMAC: u8 = 0;
const POLICY: u8 = 1;
const AES: [u8; 6] = [0x00, 0x06, 0x00, 0x80, 0x00, 0x43];
const DECRYPT: u8 = 0x20;
const ENCRYPT: u8 = 0x40;

/// What an unseal or a seal is refused with when the TPM's storage key is not the one the
/// seal was made under, and what the owner does when the TPM was cleared or the disk moved.
pub const ANOTHER: &str = "this is not the TPM the key was sealed with, or something sits between it and this machine \
     (if its TPM was cleared or its disk moved: kith node seal NAME --off, then kith node seal NAME, seals it to this one)";
/// What an answer is that comes without the session its command was sent with; that runs
/// on past its session; that comes in plain where it was asked to come encrypted.
const UNSESSIONED: &str = "the TPM answered without the session it was asked with";
const LONGER: &str = "the TPM's answer runs on past its session";
const PLAIN: &str = "the TPM answered in plain where it was asked to encrypt";
/// What an answer whose HMAC does not hold is.
pub const FORGED: &str =
    "an answer came from no TPM this machine has a session with: it was changed on its way (its HMAC does not hold)";

pub struct Tpm<T>(pub T);

/// The storage key, as this TPM made it now: its handle, its name (computed here from its
/// public area, never the one the TPM answers), and its public point (0x04, x, y).
struct Parent {
    handle: u32,
    name: Vec<u8>,
    point: Vec<u8>,
}

/// A session salted to the storage key: its handle, its key, and the TPM's last nonce.
struct Session {
    handle: u32,
    key: Vec<u8>,
    nonce: Vec<u8>,
}

/// KDFa with SHA-256, for 256 bits: one HMAC.
fn kdfa(key: &[u8], label: &[u8], u: &[u8], v: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let told = [&1u32.to_be_bytes()[..], label, &[0], u, v, &256u32.to_be_bytes()].concat();
    hmac::sign(&key, &told).as_ref().to_vec()
}

/// KDFe with SHA-256, for 256 bits: the salt from the ECDH's `z`, and the two x's.
fn kdfe(z: &[u8], u: &[u8], v: &[u8]) -> Vec<u8> {
    Sha256::digest([&1u32.to_be_bytes()[..], z, b"SECRET\0", u, v].concat()).to_vec()
}

/// `data` in AES-128-CFB (the key, then the IV, in `key_iv`), either way.
fn cfb(key_iv: &[u8], data: &mut [u8], encrypting: bool) {
    let aes = aes::Aes128::new_from_slice(&key_iv[..16]).expect("16 bytes");
    let mut chain: [u8; 16] = key_iv[16..32].try_into().expect("16 bytes");
    for block in data.chunks_mut(16) {
        let mut mask = aes::Block::from(chain);
        aes.encrypt_block(&mut mask);
        let crossed = if encrypting { None } else { Some(block.to_vec()) };
        for (byte, mask) in block.iter_mut().zip(mask) {
            *byte ^= mask;
        }
        let crossed = crossed.as_deref().unwrap_or(block);
        chain[..crossed.len()].copy_from_slice(crossed);
    }
}

/// What of `parameters` a session encrypts: the first one's bytes, after their length.
fn first(parameters: &mut [u8]) -> Result<&mut [u8], String> {
    let length = parameters.get(..2).ok_or("the TPM's reply is cut short")?;
    let length = usize::from(u16::from_be_bytes(length.try_into().expect("two bytes")));
    parameters
        .get_mut(2..2 + length)
        .ok_or("the TPM's reply is cut short".into())
}

/// The name of what the TPM keeps under `public` (its public area).
fn name(public: &[u8]) -> Vec<u8> {
    [&SHA256.to_be_bytes()[..], &Sha256::digest(public)].concat()
}

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

/// The TPM's count of wrong authorizations (a PIN's), and what it does with them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Lockout {
    /// Somebody holds the lockout hierarchy's authorization (it is not empty).
    pub set: bool,
    /// It refuses every PIN until `interval` has passed.
    pub locked: bool,
    pub counter: u32,
    /// M: the wrong ones it lets through; I: the seconds after which it forgets one; R: the
    /// seconds the lockout hierarchy waits after a wrong authorization of its own.
    pub max: u32,
    pub interval: u32,
    pub recovery: u32,
}

/// What a PIN of `digits` digits is under a TPM that lets `max` wrong ones through and
/// forgets one every `interval` seconds: refused unless a year of guessing at that pace
/// tries no more than one in a hundred of its PINs. The refusal names the bound it fails,
/// and the shortest PIN those settings take.
pub fn bounded(digits: usize, max: u32, interval: u32) -> Result<(), String> {
    if !(6..=32).contains(&digits) {
        return Err(format!("a PIN is 6 to 32 digits, not {digits}"));
    }
    if max == 0 || interval == 0 {
        return Err(format!(
            "this TPM's lockout bounds no guessing (it counts {max} wrong PINs, and forgets one every {interval} seconds): a PIN needs both above 0"
        ));
    }
    let guesses = u128::from(max) + u128::from(YEAR.div_ceil(interval));
    let room = |digits: usize| 10u128.pow(digits as u32) / 100;
    if guesses <= room(digits) {
        return Ok(());
    }
    // (At most 2^32 + a year's seconds: 12 digits always take them.)
    let shortest = (digits..=32).find(|digits| guesses <= room(*digits)).unwrap_or(32);
    Err(format!(
        "this TPM lets {max} wrong PINs through and one more every {interval} seconds: {guesses} guesses in a year, more than one in a hundred of the {} PINs of {digits} digits; the shortest PIN these settings take is {shortest} digits",
        10u128.pow(digits as u32)
    ))
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
            // (Asked with a session, a TPM that gives what was asked answers with it.)
            0 if tag == SESSIONS && reply[0..2] != SESSIONS.to_be_bytes() => Err(UNSESSIONED.into()),
            0 => Ok(reply[10..whole].to_vec()),
            POLICY_FAILED => Err("the TPM does not give the key: this is not the system it was sealed for".into()),
            AUTH_FAIL => Err(NOT_THE_PIN.into()),
            IN_LOCKOUT => Err(LOCKED_OUT.into()),
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
    /// asked this way, from a seed it never shows, so none is kept anywhere. `kept`: its
    /// name when the seal was made, which this one's must be.
    fn parent(&mut self, kept: Option<&[u8]>) -> Result<Parent, String> {
        // An elliptic-curve key (P-256) that only wraps what is under it (AES-128-CFB).
        let public = [
            &0x0023u16.to_be_bytes()[..],
            &SHA256.to_be_bytes(),
            // (Of this TPM and this parent only, its secret made by the TPM, used with its
            // password (empty), not counted against guesses; restricted, decrypting.)
            &0x0003_0472u32.to_be_bytes(),
            &sized(&[]),
            &AES,
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
        let mut made = Reply(&made);
        let handle = made.number()?;
        let found = (|| {
            made.number()?;
            let area = made.sized(false)?;
            let name = name(area);
            if kept.is_some_and(|kept| kept != name) {
                return Err(ANOTHER.to_string());
            }
            // (Its point is what the session's salt is agreed with: the rest is the template.)
            let other = || "the TPM made a storage key other than the one asked for".to_string();
            let mut point = Reply(area.strip_prefix(&public[..public.len() - 4]).ok_or_else(other)?);
            let (x, y) = (point.sized(false)?, point.sized(false)?);
            if x.len() != 32 || y.len() != 32 || !point.0.is_empty() {
                return Err(other());
            }
            let point = [&[4][..], x, y].concat();
            Ok(Parent { handle, name, point })
        })();
        if found.is_err() {
            self.flush(handle);
        }
        found
    }

    /// A session salted to `parent` (an ECDH with its point; the TPM alone can agree the
    /// same salt) whose parameters cross in AES-128-CFB: an HMAC session, or a policy one.
    fn start(&mut self, parent: &Parent, kind: u8) -> Result<Session, String> {
        let curve = &agreement::ECDH_P256;
        let own = agreement::EphemeralPrivateKey::generate(curve, &ring::rand::SystemRandom::new());
        let own = own.map_err(|_| "no random bytes for a session with the TPM")?;
        let point = own
            .compute_public_key()
            .map_err(|_| "no point for a session with the TPM")?;
        let point = point.as_ref().to_vec();
        let theirs = agreement::UnparsedPublicKey::new(curve, &parent.point);
        let salt = agreement::agree_ephemeral(own, &theirs, |z| kdfe(z, &point[1..33], &parent.point[1..33]));
        let salt = salt.map_err(|_| "the TPM's storage key is no point of its curve")?;
        let nonce = crate::crypt::random::<32>();
        let told = [sized(&point[1..33]), sized(&point[33..])].concat();
        let body = [
            &parent.handle.to_be_bytes()[..],
            &NOBODY.to_be_bytes(),
            &sized(&nonce),
            &sized(&told),
            &[kind],
            &AES,
            &SHA256.to_be_bytes(),
        ]
        .concat();
        let started = self.run(NO_SESSIONS, START_SESSION, &body)?;
        let mut started = Reply(&started);
        let handle = started.number()?;
        let theirs = started.sized(false);
        let theirs = theirs.inspect_err(|_| self.flush(handle))?.to_vec();
        let key = kdfa(&salt, b"ATH", &theirs, &nonce);
        Ok(Session {
            handle,
            key,
            nonce: theirs,
        })
    }

    /// `command` on `handle` (`name` its name, as computed here), authorized by `session`,
    /// which also encrypts its first parameter (`DECRYPT`) or its answer's (`ENCRYPT`): the
    /// answer's parameters, its HMAC checked before they are decrypted or used. `auth`:
    /// the authorization of what is on `handle` when the command is sent, and when it is
    /// answered (a command that changes it answers under the new one); both empty but for a
    /// PIN, or the lockout's.
    fn authorized(
        &mut self,
        command: u32,
        (handle, name): (u32, &[u8]),
        session: &Session,
        crypt: u8,
        mut parameters: Vec<u8>,
        auth: [&[u8]; 2],
    ) -> Result<Vec<u8>, String> {
        let nonce = crate::crypt::random::<32>();
        // (What a session authorizes with, and encrypts under: its key and that authorization.)
        let value = |auth: &[u8]| Zeroizing::new([&session.key[..], auth].concat());
        let (asked_with, answered_with) = (value(auth[0]), value(auth[1]));
        if crypt == DECRYPT {
            let key = kdfa(&asked_with, b"CFB", &nonce, &session.nonce);
            cfb(&key, first(&mut parameters)?, true);
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, &asked_with);
        let asked = Sha256::digest([&command.to_be_bytes()[..], name, &parameters].concat());
        let proof = hmac::sign(&key, &[&asked[..], &nonce, &session.nonce, &[crypt]].concat());
        let auth = [
            &session.handle.to_be_bytes()[..],
            &sized(&nonce),
            &[crypt],
            &sized(proof.as_ref()),
        ]
        .concat();
        let body = [
            &handle.to_be_bytes()[..],
            &(auth.len() as u32).to_be_bytes(),
            &auth,
            &parameters,
        ]
        .concat();
        let answer = self.run(SESSIONS, command, &body)?;
        let mut answer = Reply(&answer);
        let length = answer.number()? as usize;
        let mut parameters = answer.take(length)?.to_vec();
        let (theirs, attributes, proof) = (answer.sized(false)?, answer.take(1)?, answer.sized(false)?);
        let answered = Sha256::digest([&0u32.to_be_bytes()[..], &command.to_be_bytes(), &parameters].concat());
        if !answer.0.is_empty() {
            return Err(LONGER.into());
        }
        if crypt == ENCRYPT && attributes[0] & ENCRYPT == 0 {
            return Err(PLAIN.into());
        }
        let told = [&answered[..], theirs, &nonce, attributes].concat();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &answered_with);
        hmac::verify(&key, &told, proof).map_err(|_| FORGED)?;
        if crypt == ENCRYPT {
            let key = kdfa(&answered_with, b"CFB", theirs, &nonce);
            cfb(&key, first(&mut parameters)?, false);
        }
        Ok(parameters)
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
    /// to keep, and the storage key's name, to give [`Tpm::unseal`]. `kept`: the name of
    /// the one it was sealed under before, if it was.
    pub fn seal(&mut self, key: &[u8], kept: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), String> {
        let parent = self.parent(kept)?;
        let made = self.sealed(key, &parent, None);
        self.flush(parent.handle);
        Ok((made?, parent.name))
    }

    /// `key` sealed under `pin` (its digits, as typed), whatever the PCRs: only a policy
    /// session told the PIN (PolicyAuthValue) has it back, and the TPM counts each wrong PIN
    /// toward its lockout. Before it is given back: it opens with the PIN, and one wrong PIN
    /// tried is counted (a TPM that did not count one would let the PIN be guessed without
    /// end). What to keep, and the storage key's name, as [`Tpm::seal`] gives them.
    pub fn seal_pin(&mut self, key: &[u8], pin: &[u8], kept: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), String> {
        let parent = self.parent(kept)?;
        let made = self.sealed(key, &parent, Some(pin));
        self.flush(parent.handle);
        let (made, name) = (made?, parent.name);
        if self.unseal_pin(&made, pin, Some(&name))? != key {
            return Err("the TPM gave back another key than the one sealed under the PIN".into());
        }
        let before = self.lockout()?.counter;
        // (The last digit moved by one: another PIN of the same length.)
        let mut wrong = Zeroizing::new(pin.to_vec());
        if let Some(last) = wrong.last_mut() {
            *last = b'0' + (last.wrapping_sub(b'0') + 1) % 10;
        }
        match self.unseal_pin(&made, &wrong, Some(&name)) {
            Err(why) if why == NOT_THE_PIN || why == LOCKED_OUT => {}
            Err(why) => return Err(why),
            Ok(_) => return Err("the TPM gave the key for a wrong PIN".into()),
        }
        if self.lockout()?.counter <= before {
            return Err(
                "this TPM did not count a wrong PIN: it would let the PIN be guessed without end, so none is set"
                    .into(),
            );
        }
        Ok((made, name))
    }

    /// `key` sealed under `parent`: to the PCRs as they are now, or to `pin`.
    fn sealed(&mut self, key: &[u8], parent: &Parent, pin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let (policy, attributes) = match pin {
            // Data kept under a hash, of this TPM and this parent only, with no password (so
            // none to guess, and no guess counted): the policy alone opens it.
            None => (self.policy()?, 0x0000_0412u32),
            // Of this TPM and this parent only, its password the PIN, and each wrong one
            // counted; no password alone opens it, only a policy session told it.
            Some(_) => {
                let told = [&[0; 32][..], &POLICY_AUTH_VALUE.to_be_bytes()].concat();
                (Sha256::digest(told).into(), 0x0000_0012)
            }
        };
        let session = self.start(parent, HMAC)?;
        let secret = Zeroizing::new([sized(pin.unwrap_or_default()), sized(key)].concat());
        let public = [
            &0x0008u16.to_be_bytes()[..],
            &SHA256.to_be_bytes(),
            &attributes.to_be_bytes(),
            &sized(&policy),
            &NULL.to_be_bytes(),
            &sized(&[]),
        ]
        .concat();
        let parameters = [sized(&secret), sized(&public), sized(&[]), 0u32.to_be_bytes().into()].concat();
        let parameters = Zeroizing::new(parameters);
        let on = (parent.handle, &parent.name[..]);
        let made = self.authorized(CREATE, on, &session, DECRYPT, parameters.to_vec(), [&[], &[]]);
        if made.is_err() {
            // (One that did its command ended with it.)
            self.flush(session.handle);
        }
        let made = made?;
        let mut made = Reply(&made);
        Ok([made.sized(true)?, made.sized(true)?].concat())
    }

    /// The key that was sealed as `sealed`, if this is the TPM and the system it was
    /// sealed for; `kept`: the storage key's name when it was sealed, if it was kept.
    pub fn unseal(&mut self, sealed: &[u8], kept: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let parent = self.parent(kept)?;
        let key = self.opened(sealed, &parent, None);
        self.flush(parent.handle);
        key
    }

    /// The key that was sealed as `sealed` under `pin`, if this is the TPM it was sealed
    /// with and `pin` the PIN; a wrong one is [`NOT_THE_PIN`], and counted; while the TPM
    /// counts too many, every one is [`LOCKED_OUT`].
    pub fn unseal_pin(&mut self, sealed: &[u8], pin: &[u8], kept: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let parent = self.parent(kept)?;
        let key = self.opened(sealed, &parent, Some(pin));
        self.flush(parent.handle);
        key
    }

    fn opened(&mut self, sealed: &[u8], parent: &Parent, pin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        // Its name, from its public area as kept (the TPM loads nothing else under it).
        let mut kept = Reply(sealed);
        kept.sized(false)?;
        let named = name(kept.sized(false)?);
        let body = [&parent.handle.to_be_bytes()[..], &password(), sealed].concat();
        let item = Reply(&self.run(SESSIONS, LOAD, &body)?).number()?;
        let key = self.shown((item, &named), parent, pin);
        self.flush(item);
        key
    }

    /// The PCRs shown to a policy session (or, for one sealed under a PIN, the PIN), and
    /// what the TPM then gives of `item`.
    fn shown(&mut self, item: (u32, &[u8]), parent: &Parent, pin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let session = self.start(parent, POLICY)?;
        let handle = session.handle.to_be_bytes();
        let given = match pin {
            None => {
                let pcrs = [&handle[..], &sized(&[]), &selection()].concat();
                self.run(NO_SESSIONS, POLICY_PCR, &pcrs)
            }
            Some(_) => self.run(NO_SESSIONS, POLICY_AUTH_VALUE, &handle),
        };
        let pin = pin.unwrap_or_default();
        let given = given.and_then(|_| self.authorized(UNSEAL, item, &session, ENCRYPT, Vec::new(), [pin, pin]));
        if given.is_err() {
            self.flush(session.handle);
        }
        Ok(Reply(&given?).sized(false)?.to_vec())
    }

    /// What the TPM says of its lockout now (TPM2_GetCapability, its variable properties).
    pub fn lockout(&mut self) -> Result<Lockout, String> {
        let asked = [6u32, 0x200, 18].map(u32::to_be_bytes).concat();
        let told = self.run(NO_SESSIONS, GET_CAPABILITY, &asked)?;
        let mut told = Reply(&told);
        told.take(1)?;
        if told.number()? != 6 {
            return Err("the TPM answered another question than its properties".into());
        }
        let mut properties = Vec::new();
        for _ in 0..told.number()? {
            properties.push((told.number()?, told.number()?));
        }
        let value = |asked: u32| {
            let found = properties.iter().find(|(property, _)| *property == asked);
            found
                .map(|(_, value)| *value)
                .ok_or_else(|| format!("the TPM does not say its property {asked:#x}"))
        };
        let permanent = value(0x200)?;
        Ok(Lockout {
            set: permanent & 1 << 2 != 0,
            locked: permanent & 1 << 9 != 0,
            counter: value(0x20e)?,
            max: value(0x20f)?,
            interval: value(0x210)?,
            recovery: value(0x211)?,
        })
    }

    /// The TPM's lockout, made ready for a PIN of `digits` digits: its settings checked
    /// ([`bounded`]), and its authorization taken where nobody holds it. That one is made
    /// here, given to `keep` (which writes it into the state) before the TPM is told it, in
    /// a session salted to the storage key (`kept`: its name, as with a seal), and then read
    /// back. `held`: kithd keeps one already; where somebody holds it and kithd does not,
    /// [`CLEAR_FIRST`].
    pub fn guard(
        &mut self,
        digits: usize,
        held: Option<&[u8]>,
        kept: Option<&[u8]>,
        keep: impl FnOnce(&[u8]) -> Result<(), String>,
    ) -> Result<Lockout, String> {
        let lockout = self.lockout()?;
        bounded(digits, lockout.max, lockout.interval)?;
        if lockout.set {
            // Kept is not proof (a disk moved, a state put back): the TPM is shown it, by
            // forgiving its count (the PIN it guards is being set anew). A wrong one shuts
            // the lockout hierarchy for its recovery time, as CLEAR_FIRST says.
            let held = held.filter(|held| held.len() == 32).ok_or(CLEAR_FIRST)?;
            self.as_lockout(kept, DA_RESET, 0, Vec::new(), [held, held])
                .map_err(|why| unproved(why, lockout.recovery))?;
            return self.lockout();
        }
        // (A TPM drops an authorization's last zero bytes: none is last.)
        let mut auth = Zeroizing::new(crate::crypt::random::<32>());
        auth[31] |= 1;
        keep(&auth[..])?;
        let mut given = sized(&auth[..]);
        let taken = self.as_lockout(kept, HIERARCHY_CHANGE_AUTH, DECRYPT, given.clone(), [&[], &auth[..]]);
        given.zeroize();
        taken?;
        let lockout = self.lockout()?;
        if !lockout.set {
            return Err("the TPM did not take the lockout's authorization it was given".into());
        }
        Ok(lockout)
    }
}

/// What the proof of a kept lockout authorization failing is, the PIN refused on each: the
/// TPM refusing the value (its first session's AUTH_FAIL or BAD_AUTH), [`CLEAR_FIRST`]; its
/// lockout hierarchy shut by an earlier wrong one, a wait of its `recovery` seconds; anything
/// else (the bus, the storage key, a session), itself, so nobody clears a TPM for an I/O error.
fn unproved(why: String, recovery: u32) -> String {
    if why == NOT_THE_PIN || why == format!("the TPM refuses (its code {BAD_AUTH:#x})") {
        CLEAR_FIRST.into()
    } else if why == LOCKED_OUT {
        format!(
            "the TPM's lockout hierarchy is shut for now: a wrong lockout authorization was shown it. \
             Set the PIN again {recovery} s after that, with the machine powered all along"
        )
    } else {
        why
    }
}

impl<T: Read + Write> Tpm<T> {
    /// `command` on the lockout hierarchy, authorized by `auth` in a session salted to the
    /// storage key (`kept`: its name), so no authorization crosses the bus in plain.
    fn as_lockout(
        &mut self,
        kept: Option<&[u8]>,
        command: u32,
        crypt: u8,
        parameters: Vec<u8>,
        auth: [&[u8]; 2],
    ) -> Result<Vec<u8>, String> {
        let parent = self.parent(kept)?;
        let session = self.start(&parent, HMAC);
        self.flush(parent.handle);
        let session = session?;
        let on = (LOCKOUT, &LOCKOUT.to_be_bytes()[..]);
        let done = self.authorized(command, on, &session, crypt, parameters, auth);
        if done.is_err() {
            self.flush(session.handle);
        }
        done
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn extend<T: Read + Write>(tpm: &mut Tpm<T>, pcr: u32, with: u8) {
        tpm.extend(pcr, &[with; 32]).unwrap();
    }

    /// Every PCR a key is sealed to, made to hold something.
    pub(crate) fn measured<T: Read + Write>(tpm: &mut Tpm<T>) {
        for pcr in PCRS {
            extend(tpm, pcr.into(), pcr);
        }
    }

    /// The way to a TPM, every byte both ways kept, each answer with the command it
    /// answers; and one answer changed on its way, as a proxy on the bus would.
    pub(crate) struct Wire {
        stream: UnixStream,
        pub sent: Vec<u8>,
        pub answers: Vec<(u32, Vec<u8>)>,
        /// The command whose next answer is changed, at which byte, and its bits flipped.
        pub flip: Option<(u32, usize, u8)>,
        /// The command whose next answer gets one byte more at its end (its length too).
        pub tail: Option<u32>,
        /// What is left of the answer being read.
        waiting: Vec<u8>,
    }

    impl Wire {
        pub(crate) fn new(stream: UnixStream) -> Wire {
            Wire {
                stream,
                sent: Vec::new(),
                answers: Vec::new(),
                flip: None,
                tail: None,
                waiting: Vec::new(),
            }
        }

        pub(crate) fn got(&self) -> Vec<u8> {
            self.answers.iter().flat_map(|(_, answer)| answer.clone()).collect()
        }

        fn commands(&self) -> Vec<u32> {
            self.answers.iter().map(|(command, _)| *command).collect()
        }
    }

    impl Write for Wire {
        fn write(&mut self, said: &[u8]) -> std::io::Result<usize> {
            let command = said.get(6..10).map(|code| u32::from_be_bytes(code.try_into().unwrap()));
            self.answers.push((command.unwrap_or_default(), Vec::new()));
            self.stream.write_all(said)?;
            self.sent.extend(said);
            Ok(said.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.stream.flush()
        }
    }

    impl Read for Wire {
        fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
            // (Each answer is taken whole from swtpm, changed, then given in parts.)
            if self.waiting.is_empty() {
                let mut answer = vec![0; 10];
                self.stream.read_exact(&mut answer)?;
                let length = u32::from_be_bytes(answer[2..6].try_into().unwrap()) as usize;
                answer.resize(length.max(10), 0);
                self.stream.read_exact(&mut answer[10..])?;
                let (command, kept) = self.answers.last_mut().expect("a command before its answer");
                if let Some((flipped, at, bits)) = self.flip
                    && flipped == *command
                {
                    answer[at] ^= bits;
                    self.flip = None;
                }
                if self.tail == Some(*command) {
                    answer.push(0);
                    let length = answer.len() as u32;
                    answer[2..6].copy_from_slice(&length.to_be_bytes());
                    self.tail = None;
                }
                kept.extend(&answer);
                self.waiting = answer;
            }
            let given = into.len().min(self.waiting.len());
            into[..given].copy_from_slice(&self.waiting[..given]);
            self.waiting.drain(..given);
            Ok(given)
        }
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
            // (The session encrypts it: T-0585.)
            assert!(
                !text.contains("bus as it is"),
                "{name} says the key crosses the bus in plain"
            );
        }
        let readme = include_str!("../../../README.md");
        assert!(readme.contains("What the seal does not cover"));
    }

    /// A software TPM, ended and its files removed with the test.
    pub(crate) struct Software(std::process::Child, std::path::PathBuf);

    impl Drop for Software {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }

    impl Software {
        /// The way to it again, once the last one was let go (it answers one at a time).
        pub(crate) fn wire(&self) -> Wire {
            Wire::new(UnixStream::connect(self.1.join("tpm")).unwrap())
        }
    }

    static STARTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// A software TPM of its own (swtpm), with its own state, and the way to it. None on a
    /// machine without swtpm, which checks nothing here; CI is not let to be one, and
    /// `sh ci/vm.sh --test tpm` is what checks it whole.
    pub(crate) fn software() -> Option<(Software, Wire)> {
        let started = STARTED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("kith-tpm-{}-{started}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let at = |name: &str| format!("type=unixio,path={}", dir.join(name).display());
        let software = std::process::Command::new("swtpm")
            .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
            .args(["--tpmstate", &format!("dir={}", dir.display())])
            .args(["--server", &at("tpm"), "--ctrl", &at("ctrl")])
            .spawn();
        let Ok(software) = software else {
            let _ = std::fs::remove_dir_all(&dir);
            assert!(
                std::env::var_os("CI").is_none(),
                "CI has no swtpm: the TPM's commands would go unchecked"
            );
            eprintln!("no swtpm on this machine: the TPM's commands were not checked here");
            return None;
        };
        let software = Software(software, dir.clone());
        let mut tries = 0;
        let stream = loop {
            match UnixStream::connect(dir.join("tpm")) {
                Ok(stream) => break stream,
                Err(e) if tries == 250 => panic!("swtpm does not answer: {e}"),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
            tries += 1;
        };
        Some((software, Wire::new(stream)))
    }

    /// Against a software TPM: a key sealed comes back while the PCRs stand, and is
    /// refused once one has moved; sealed again, it comes back again.
    #[test]
    fn tpm_gives_a_sealed_key_back_to_the_same_system_only() {
        let Some((_software, wire)) = software() else { return };
        let mut tpm = Tpm(wire);
        let key: Vec<u8> = (0..64).collect();

        // Nothing measured: nothing is sealed to that. Nor while the firmware has measured
        // and kithd has not, or the other way round.
        for measured in [None, Some(0), Some(4), Some(MEASURED)] {
            let refused = tpm.seal(&key, None).unwrap_err();
            assert!(refused.contains("holds nothing"), "{measured:?}: {refused}");
            if let Some(pcr) = measured {
                extend(&mut tpm, pcr.into(), pcr);
            }
        }
        for pcr in PCRS.into_iter().filter(|pcr| !NEVER_EMPTY.contains(pcr)) {
            extend(&mut tpm, pcr.into(), pcr);
        }
        let (sealed, name) = tpm.seal(&key, None).unwrap();
        let name = Some(&name[..]);
        assert!(
            !sealed.windows(8).any(|window| window == &key[..8]),
            "the key is in what is kept"
        );
        assert_eq!(tpm.unseal(&sealed, name).as_ref(), Ok(&key));
        assert_eq!(tpm.unseal(&sealed, name).as_ref(), Ok(&key), "a second time");
        // What is kept, changed anywhere, is nothing the TPM made.
        let mut other = sealed.clone();
        other[20] ^= 1;
        assert!(tpm.unseal(&other, name).is_err());
        // Each PCR on its own: once it has moved, the key is not given.
        for pcr in PCRS {
            let (sealed, _) = tpm.seal(&key, name).unwrap();
            assert_eq!(tpm.unseal(&sealed, name).as_ref(), Ok(&key));
            extend(&mut tpm, pcr.into(), 0xee);
            let refused = tpm.unseal(&sealed, name).unwrap_err();
            assert!(
                refused.contains("not the system it was sealed for"),
                "PCR {pcr}: {refused}"
            );
        }
        // And a PCR that is not one of them changes nothing.
        let (sealed, _) = tpm.seal(&key, name).unwrap();
        extend(&mut tpm, 14, 1);
        assert_eq!(tpm.unseal(&sealed, name).as_ref(), Ok(&key));
    }

    /// The name the TPM itself gives the storage key, as the last of what CreatePrimary
    /// answers last (kithd computes its own and does not read this one).
    fn told_name(wire: &Wire) -> Vec<u8> {
        let (_, answer) = wire
            .answers
            .iter()
            .rfind(|(command, _)| *command == CREATE_PRIMARY)
            .unwrap();
        let mut answer = Reply(&answer[10..]);
        answer.take(8).unwrap();
        for _ in 0..3 {
            answer.sized(false).unwrap(); // outPublic, creationData, creationHash
        }
        answer.take(6).unwrap(); // the ticket's tag and hierarchy
        answer.sized(false).unwrap();
        answer.sized(false).unwrap().to_vec()
    }

    /// Whether any 8 bytes in a row of `secret` are anywhere in `bytes`.
    fn holds(bytes: &[u8], secret: &[u8]) -> bool {
        secret
            .windows(8)
            .any(|part| bytes.windows(8).any(|window| window == part))
    }

    /// Criterion 1: what crosses to the TPM and back while a key is sealed and unsealed
    /// holds no part of the key, nor of what it is sealed in; each answer's HMAC is checked,
    /// and one changed on its way is refused. (Lengths alone are printed.)
    #[test]
    fn tpm_session_carries_no_key_and_checks_each_answer() {
        let Some((_software, wire)) = software() else { return };
        let mut tpm = Tpm(wire);
        measured(&mut tpm);
        let key: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect(); // pragma: allowlist secret
        let (sealed, name) = tpm.seal(&key, None).unwrap();
        assert_eq!(name, told_name(&tpm.0), "the name kept is the storage key's");
        assert_eq!(name.len(), 34);
        assert_eq!(tpm.unseal(&sealed, Some(&name)).as_ref(), Ok(&key));
        // A seal kept with no name (made before names were kept) opens as well.
        assert_eq!(tpm.unseal(&sealed, None).as_ref(), Ok(&key));
        let in_sensitive = [sized(&[]), sized(&key)].concat();
        let (sent, got) = (&tpm.0.sent, tpm.0.got());
        for (what, bytes) in [("sent", sent), ("received", &got)] {
            assert!(!holds(bytes, &key), "the key is in what was {what}");
            assert!(!holds(bytes, &in_sensitive), "inSensitive is in what was {what}");
        }
        eprintln!(
            "recorded {} bytes sent and {} received; the sealed blob is {} bytes",
            sent.len(),
            got.len(),
            sealed.len()
        );

        // One byte of the answer changed (the first of the key, as it crosses encrypted):
        // refused before anything in it is used. So in TPM2_Create's answer (the blob).
        tpm.0.flip = Some((UNSEAL, 16, 1));
        let refused = tpm.unseal(&sealed, Some(&name)).unwrap_err();
        assert_eq!(refused, FORGED);
        tpm.0.flip = Some((CREATE, 20, 1));
        assert_eq!(tpm.seal(&key, Some(&name)).unwrap_err(), FORGED);
        // And nothing of it is left behind in the TPM: it opens as before.
        assert_eq!(tpm.unseal(&sealed, Some(&name)).as_ref(), Ok(&key));
    }

    /// Criterion 2: another TPM in this one's place is refused by the storage key's name,
    /// and nothing but the storage key is asked of it; so is a storage key's point changed
    /// on its way.
    #[test]
    fn tpm_parent_is_checked_before_anything_is_sent() {
        let (Some((_one, wire)), Some((_other, other))) = (software(), software()) else {
            return;
        };
        let mut tpm = Tpm(wire);
        measured(&mut tpm);
        let key = vec![7; 32]; // pragma: allowlist secret
        let (sealed, name) = tpm.seal(&key, None).unwrap();
        let mut other = Tpm(other);
        measured(&mut other);
        let before = other.0.answers.len();
        assert_eq!(other.unseal(&sealed, Some(&name)), Err(ANOTHER.to_string()));
        assert_eq!(other.seal(&key, Some(&name)), Err(ANOTHER.to_string()));
        let asked = &other.0.commands()[before..];
        assert_eq!(asked, [CREATE_PRIMARY, FLUSH, CREATE_PRIMARY, FLUSH], "{asked:x?}");

        // The storage key's x changed in CreatePrimary's answer (a proxy's own key).
        tpm.0.flip = Some((CREATE_PRIMARY, 50, 1));
        let before = tpm.0.answers.len();
        assert_eq!(tpm.unseal(&sealed, Some(&name)), Err(ANOTHER.to_string()));
        assert_eq!(tpm.0.commands()[before..], [CREATE_PRIMARY, FLUSH]);
        // The same TPM: sealed again under the name kept, and the same name.
        let (_, again) = tpm.seal(&key, Some(&name)).unwrap();
        assert_eq!(again, name);
    }

    /// An answer to a command sent with a session is refused unless it comes with one, ends
    /// where its session does, and says it is encrypted where that was asked; each is
    /// checked before its HMAC, so each says what it is.
    #[test]
    fn tpm_answer_out_of_its_shape_is_refused() {
        let Some((_software, wire)) = software() else { return };
        let mut tpm = Tpm(wire);
        measured(&mut tpm);
        let key = vec![9; 64]; // pragma: allowlist secret
        let (sealed, name) = tpm.seal(&key, None).unwrap();
        // Unseal's answer: header (10), parameterSize (4), outData (2 + 64), nonceTPM
        // (2 + 32), then the session's attributes.
        let attributes = 10 + 4 + 2 + key.len() + 2 + 32;
        for (change, refused) in [
            ((Some((UNSEAL, 1, 1)), None), UNSESSIONED),
            ((None, Some(UNSEAL)), LONGER),
            ((Some((UNSEAL, attributes, ENCRYPT)), None), PLAIN),
        ] {
            (tpm.0.flip, tpm.0.tail) = change;
            // (Compared, not printed: a failure shows no key.)
            assert_eq!(tpm.unseal(&sealed, Some(&name)).err().as_deref(), Some(refused));
        }
        assert!(tpm.unseal(&sealed, Some(&name)) == Ok(key));
    }

    /// A command on the lockout hierarchy with its authorization in plain, as the owner's
    /// tools send it (kithd sends it none of these).
    pub(crate) fn as_lockout<T: Read + Write>(tpm: &mut Tpm<T>, command: u32, auth: &[u8], parameters: &[u8]) {
        let password = [&PASSWORD.to_be_bytes()[..], &sized(&[]), &[0], &sized(auth)].concat();
        let body = [
            &LOCKOUT.to_be_bytes()[..],
            &(password.len() as u32).to_be_bytes(),
            &password,
            parameters,
        ]
        .concat();
        tpm.run(SESSIONS, command, &body).unwrap();
    }

    /// The lockout's settings, as the owner sets them before kithd takes its authorization:
    /// `max` wrong PINs let through, one forgotten every `interval` seconds.
    pub(crate) fn lockout_set<T: Read + Write>(tpm: &mut Tpm<T>, max: u32, interval: u32) {
        let parameters = [max, interval, 60].map(u32::to_be_bytes).concat();
        as_lockout(tpm, DA_PARAMETERS, &[], &parameters);
    }

    /// The bounds a PIN is held to: its length, and the lockout's settings for it.
    #[test]
    fn tpm_pin_bounds_name_what_they_refuse() {
        assert!(bounded(6, 10, 86_400).is_ok(), "10 + 365 guesses a year, of a million");
        for (digits, max, interval, named) in [
            (5, 10, 86_400, "6 to 32 digits, not 5"),
            (33, 10, 86_400, "6 to 32 digits, not 33"),
            (8, 0, 40, "both above 0"),
            (8, 3, 0, "both above 0"),
            (6, 3, 40, "the shortest PIN these settings take is 8 digits"),
            (7, 3, 40, "788403 guesses in a year"),
            (11, u32::MAX, 1, "the shortest PIN these settings take is 12 digits"),
        ] {
            let refused = bounded(digits, max, interval).unwrap_err();
            assert!(refused.contains(named), "{digits} {max} {interval}: {refused}");
        }
        assert!(bounded(8, 3, 40).is_ok());
        assert!(bounded(12, u32::MAX, 1).is_ok());
    }

    /// Against a software TPM: a key sealed under a PIN opens with it, whatever the PCRs; a
    /// wrong one is counted, and once the TPM counts M of them, the right one is refused as
    /// well, until whoever holds the lockout's authorization (kithd, which took it where it
    /// was empty) forgives them. Its settings too loose for a PIN that short: refused. The
    /// PIN and the lockout's authorization cross the bus encrypted.
    #[test]
    fn tpm_pin_opens_with_its_pin_and_counts_each_wrong_one() {
        let Some((_software, wire)) = software() else { return };
        let mut tpm = Tpm(wire);
        measured(&mut tpm);
        lockout_set(&mut tpm, 3, 40);
        let lockout = tpm.lockout().unwrap();
        assert_eq!(
            (lockout.set, lockout.counter, lockout.max, lockout.interval),
            (false, 0, 3, 40)
        );

        let mut kept = None;
        let refused = tpm
            .guard(6, None, None, |_| panic!("kept for a PIN refused"))
            .unwrap_err();
        assert!(
            refused.contains("the shortest PIN these settings take is 8 digits"),
            "{refused}"
        );
        tpm.guard(8, None, None, |auth| {
            kept = Some(auth.to_vec());
            Ok(())
        })
        .unwrap();
        let auth = kept.expect("the lockout's authorization, kept before the TPM was told it");
        assert_eq!(auth.len(), 32);
        assert!(tpm.lockout().unwrap().set, "the TPM holds it");
        // Held by kithd: the TPM takes it again. Held by somebody else (kithd keeps none, or
        // not 32 bytes): refused, the TPM not asked.
        tpm.guard(8, Some(&auth), None, |_| panic!("made again")).unwrap();
        for held in [None, Some(&auth[..31])] {
            assert_eq!(
                tpm.guard(8, held, None, |_| panic!("made again")),
                Err(CLEAR_FIRST.into())
            );
        }

        let (pin, key): (&[u8], Vec<u8>) = (b"40917253", (0..32).collect());
        let (sealed, name) = tpm.seal_pin(&key, pin, None).unwrap();
        let name = Some(&name[..]);
        assert_eq!(tpm.lockout().unwrap().counter, 1, "the wrong PIN tried when it was set");
        assert_eq!(tpm.unseal_pin(&sealed, pin, name).as_ref(), Ok(&key));
        // Not by its PCRs: a PIN's seal is the PIN's alone.
        extend(&mut tpm, MEASURED.into(), 0xee);
        assert_eq!(tpm.unseal_pin(&sealed, pin, name).as_ref(), Ok(&key));
        assert!(!holds(&tpm.0.sent, pin), "the PIN crossed the bus as typed");
        assert!(
            !holds(&tpm.0.sent, &auth),
            "the lockout's authorization crossed the bus in plain"
        );
        assert!(!holds(&tpm.0.got(), &key), "the key crossed the bus in plain");

        assert_eq!(tpm.unseal_pin(&sealed, b"40917254", name), Err(NOT_THE_PIN.into()));
        assert_eq!(tpm.lockout().unwrap().counter, 2);
        assert_eq!(tpm.unseal_pin(&sealed, b"00000000", name), Err(NOT_THE_PIN.into()));
        let lockout = tpm.lockout().unwrap();
        assert!(lockout.locked && lockout.counter == 3, "{lockout:?}");
        assert_eq!(tpm.unseal_pin(&sealed, pin, name), Err(LOCKED_OUT.into()));
        // Forgiven by the lockout's authorization kithd keeps: the PIN opens again.
        as_lockout(&mut tpm, DA_RESET, &auth, &[]);
        assert_eq!(tpm.unseal_pin(&sealed, pin, name).as_ref(), Ok(&key));
        // The PIN set anew with the right one kept: its proof forgives the count.
        assert_eq!(tpm.unseal_pin(&sealed, b"40917254", name), Err(NOT_THE_PIN.into()));
        assert_eq!(tpm.lockout().unwrap().counter, 1);
        let proved = tpm.guard(8, Some(&auth), None, |_| panic!("made again")).unwrap();
        assert_eq!((proved.counter, tpm.lockout().unwrap().counter), (0, 0));
        // A file of 32 bytes kept that are not the TPM's (a disk moved, a state put back):
        // the TPM is asked and says no, so refused. (Last: the TPM then shuts its lockout
        // hierarchy for its recovery time.)
        let mut other = auth.clone();
        other[0] ^= 1;
        assert_eq!(
            tpm.guard(8, Some(&other), None, |_| panic!("made again")),
            Err(CLEAR_FIRST.into())
        );
        // Its lockout hierarchy now shut: even the right one waits, and is not told to clear.
        let shut = tpm.guard(8, Some(&auth), None, |_| panic!("made again")).unwrap_err();
        assert!(shut.contains("Set the PIN again 60 s after"), "{shut}");
    }

    /// A failed proof of the kept lockout authorization: refused by the TPM, clear it; its
    /// hierarchy shut, wait; anything else, as it is. None of them sets a PIN.
    #[test]
    fn tpm_pin_tells_a_refused_lockout_from_a_shut_one_and_a_broken_bus() {
        for (code, said) in [
            (AUTH_FAIL, CLEAR_FIRST),
            (BAD_AUTH, CLEAR_FIRST),
            (IN_LOCKOUT, "Set the PIN again 60 s after"),
            (0x101, "the TPM refuses (its code 0x101)"),
        ] {
            // (A TPM that answers each command with `code` alone.)
            struct Answer(std::io::Cursor<Vec<u8>>);
            impl Write for Answer {
                fn write(&mut self, said: &[u8]) -> std::io::Result<usize> {
                    Ok(said.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            impl Read for Answer {
                fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
                    self.0.read(into)
                }
            }
            let answer = [&0x8001u16.to_be_bytes()[..], &10u32.to_be_bytes(), &code.to_be_bytes()].concat();
            let mut tpm = Tpm(Answer(std::io::Cursor::new(answer)));
            let why = tpm.run(NO_SESSIONS, DA_RESET, &[]).unwrap_err();
            let told = unproved(why, 60);
            assert!(told.contains(said), "{code:#x}: {told}");
        }
        let io = unproved("asking the TPM: broken pipe".into(), 60);
        assert_eq!(io, "asking the TPM: broken pipe");
    }
}
