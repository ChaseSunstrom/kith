//! A software FIDO2 authenticator, for tests only (docs/adr-fido2.md section 2, T-0970).
//!
//! **Never in a release.** This module is compiled only with the cargo feature `fido2-test`
//! (and in unit tests): `ci/musl.sh` builds that feature into a folder of its own, `os/build.sh`
//! lets such a kithd go into `target/os-fido2` alone, `ci/vm/tests.sh` gives it to the one
//! test that needs it, `main.rs` says so loudly at every start, and the shipped kithd is grepped
//! for the strings only this module has. It answers CTAPHID as a key that touches by a file,
//! with secrets that come from a seed, so a test can say what an `hmac-secret` must be.
//!
//! It is written beside the client (`fido2.rs`) by the same hand and from the same reading of the
//! specification, and shares its framing and CBOR: a misreading would agree with itself. NIST's
//! vectors check the cipher; `auth::tests::the_secret_is_the_hmac_of_the_salt_under_the_credentials_hmac`
//! pins the seed derivation to an HMAC computed outside Rust; one real key checks the rest.
#![cfg_attr(not(feature = "fido2-test"), allow(dead_code))]

/// The text only a build with this feature has, for the release guard of `ci/musl.sh` to look
/// for in a shipped kithd (it greps the same words).
pub const STARTUP_LINE: &[u8] = b"kithd: built with fido2-test: `kithd fido2-authenticator` answers as a security key on /dev/uhid; never ship this\n";

/// The authenticator's side of CTAPHID, getInfo, clientPIN, makeCredential and getAssertion
/// with `hmac-secret`, answering through the framing the client uses.
pub mod auth {
    use crate::fido2::cbor::{self, Value};
    use crate::fido2::frame::{self, BROADCAST, Device, REPORT};
    use crate::fido2::{cbc, hmac};
    use ring::{agreement, digest, hmac as ring_hmac, rand};
    use std::{collections::VecDeque, io, path::PathBuf};

    /// The channel INIT hands out.
    const CID: u32 = 0x0a0b_0c0d;
    const PING: u8 = 0x01;
    /// CTAPHID error codes: invalid length, channel busy, invalid channel.
    const ERR_LENGTH: u8 = 0x03;
    const ERR_BUSY: u8 = 0x06;
    const ERR_CHANNEL: u8 = 0x0b;
    /// KEEPALIVE status: the user's touch is needed.
    const UPNEEDED: u8 = 2;
    /// A credential id: 16 bytes of nonce and the first 16 of an HMAC of them under the seed.
    const ID_LEN: usize = 32;

    fn u(n: u64) -> Value {
        Value::Uint(n)
    }
    fn t(s: &str) -> Value {
        Value::text(s)
    }

    /// One way a getAssertion answer can be wrong.
    #[derive(Clone, Copy, PartialEq)]
    #[allow(dead_code)] // (only the client's tests pick a fault; the stand-in never does)
    pub enum Fault {
        None,
        /// ED set, but no extension data after the head.
        NoExtensions,
        /// ED set, but the extensions hold no `hmac-secret`.
        NoHmacSecret,
        /// `hmac-secret` is text, not the sealed bytes.
        HmacSecretNotBytes,
        /// authData for another relying party.
        WrongRp,
        /// Extension data present, ED flag clear.
        NoEdFlag,
    }

    pub struct Key {
        /// What the next getAssertion answer gets wrong.
        pub fault: Fault,
        pub seed: u8,
        pub pin: bool,
        pub protocols: Vec<u64>,
        pub extensions: Vec<&'static str>,
        /// What a made credential's extensions say about hmac-secret.
        pub grant_hmac: bool,
        /// The ids made, in order (the key itself is stateless: an id is its own proof).
        pub creds: Vec<Vec<u8>>,
        /// With a path: makeCredential and getAssertion wait, sending keep-alives, until that
        /// file exists, and remove it (one touch, one operation). Without: they answer at once.
        pub touch: Option<PathBuf>,
        /// Every CTAP2 request received: its command byte and its map.
        #[cfg(test)]
        pub seen: Vec<(u8, Value)>,
        agreement: Option<agreement::EphemeralPrivateKey>,
        incoming: Option<(u32, u8, usize, Vec<u8>)>,
        /// A request waiting for its touch: the channel and the request.
        pending: Option<(u32, Vec<u8>)>,
        out: VecDeque<Vec<u8>>,
    }

    /// Where the key's answers are framed to.
    struct Sink<'a>(&'a mut VecDeque<Vec<u8>>);
    impl Device for Sink<'_> {
        fn write(&mut self, r: &[u8; REPORT]) -> io::Result<()> {
            self.0.push_back(r.to_vec());
            Ok(())
        }
        fn read(&mut self) -> io::Result<Vec<u8>> {
            Err(io::Error::other("a sink is not read"))
        }
    }

    impl Default for Key {
        fn default() -> Key {
            Key::new()
        }
    }

    impl Key {
        pub fn new() -> Key {
            Key {
                fault: Fault::None,
                seed: 1,
                pin: false,
                protocols: vec![1],
                extensions: vec!["hmac-secret"],
                grant_hmac: true,
                creds: vec![],
                touch: None,
                #[cfg(test)]
                seen: vec![],
                agreement: None,
                incoming: None,
                pending: None,
                out: VecDeque::new(),
            }
        }

        fn seed_key(&self) -> ring_hmac::Key {
            ring_hmac::Key::new(ring_hmac::HMAC_SHA256, &[self.seed; 32])
        }

        /// The secret a credential's hmac-secret is made from: the seed's HMAC of its id.
        fn cred_random(&self, id: &[u8]) -> ring_hmac::Tag {
            ring_hmac::sign(&self.seed_key(), id)
        }

        /// What the key's hmac-secret is for `salt` under credential `id`.
        pub(crate) fn expected(&self, id: &[u8], salt: &[u8]) -> [u8; 32] {
            let tag = ring_hmac::sign(
                &ring_hmac::Key::new(ring_hmac::HMAC_SHA256, self.cred_random(id).as_ref()),
                salt,
            );
            let mut out = [0u8; 32];
            out.copy_from_slice(tag.as_ref());
            out
        }

        /// The id of the `n`th credential: its number and a proof it is this key's.
        fn make_id(&self, n: u64) -> Vec<u8> {
            let mut id = vec![0u8; 16];
            id[8..].copy_from_slice(&n.to_be_bytes());
            id.extend_from_slice(&hmac::mac16(&[self.seed; 32], &id));
            id
        }

        /// Whether `id` is one this key made (under this seed), so a restart keeps its credentials.
        fn knows(&self, id: &[u8]) -> bool {
            id.len() == ID_LEN && hmac::mac16(&[self.seed; 32], &id[..16]) == id[16..]
        }

        fn auth_data(rp: &str, flags: u8, tail: &[u8]) -> Vec<u8> {
            let mut a = digest::digest(&digest::SHA256, rp.as_bytes()).as_ref().to_vec();
            a.push(flags);
            a.extend_from_slice(&[0, 0, 0, 1]);
            a.extend_from_slice(tail);
            a
        }

        fn text_at<'a>(v: &'a Value, key: u64, inner: &str) -> Result<&'a str, u8> {
            match v.get(&u(key)).and_then(|m| m.get(&t(inner))) {
                Some(Value::Text(s)) => Ok(s),
                _ => Err(0x14), // MISSING_PARAMETER
            }
        }

        fn ids(v: Option<&Value>) -> Vec<Vec<u8>> {
            let Some(Value::Array(a)) = v else { return vec![] };
            a.iter()
                .filter_map(|d| match d.get(&t("id")) {
                    Some(Value::Bytes(b)) => Some(b.clone()),
                    _ => None,
                })
                .collect()
        }

        fn ctap(&mut self, cmd: u8, p: &Value) -> Result<Value, u8> {
            match cmd {
                0x04 => Ok(Value::Map(vec![
                    (u(1), Value::Array(vec![t("FIDO_2_0")])),
                    (u(2), Value::Array(self.extensions.iter().map(|e| t(e)).collect())),
                    (u(6), Value::Array(self.protocols.iter().map(|n| u(*n)).collect())),
                ])),
                0x06 => {
                    if p.get(&u(1)) != Some(&u(1)) || p.get(&u(2)) != Some(&u(2)) {
                        return Err(0x02);
                    }
                    let k = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rand::SystemRandom::new())
                        .map_err(|_| 0x7fu8)?; // OTHER
                    let public = k.compute_public_key().map_err(|_| 0x7fu8)?;
                    let public = public.as_ref();
                    if public.len() != 65 {
                        return Err(0x7f);
                    }
                    self.agreement = Some(k);
                    Ok(Value::Map(vec![(u(1), hmac::cose(&public[1..33], &public[33..]))]))
                }
                0x01 => {
                    let rp = Self::text_at(p, 2, "id")?;
                    if self.pin {
                        return Err(0x36);
                    }
                    if Self::ids(p.get(&u(5))).iter().any(|id| self.knows(id)) {
                        return Err(0x19);
                    }
                    let id = self.make_id(self.creds.len() as u64);
                    self.creds.push(id.clone());
                    let mut tail = vec![0xaa; 16];
                    tail.extend_from_slice(&(id.len() as u16).to_be_bytes());
                    tail.extend_from_slice(&id);
                    tail.extend_from_slice(&cbor::encode(&hmac::cose(&[1; 32], &[2; 32])));
                    tail.extend_from_slice(&cbor::encode(&Value::Map(vec![(
                        t("hmac-secret"),
                        Value::Bool(self.grant_hmac),
                    )])));
                    Ok(Value::Map(vec![
                        (u(1), t("none")),
                        (u(2), Value::Bytes(Self::auth_data(rp, 0xc1, &tail))),
                        (u(3), Value::Map(vec![])),
                    ]))
                }
                0x02 => {
                    let Value::Text(rp) = p.get(&u(1)).ok_or(0x14u8)? else {
                        return Err(0x14);
                    };
                    let id = Self::ids(p.get(&u(3)))
                        .into_iter()
                        .find(|id| self.knows(id))
                        .ok_or(0x2eu8)?;
                    let ext = p.get(&u(4)).and_then(|e| e.get(&t("hmac-secret"))).ok_or(0x14u8)?;
                    let (Some(cose), Some(Value::Bytes(enc)), Some(Value::Bytes(auth))) =
                        (ext.get(&u(1)), ext.get(&u(2)), ext.get(&u(3)))
                    else {
                        return Err(0x14);
                    };
                    let peer = hmac::point(cose).map_err(|_| 0x02u8)?;
                    let k = self.agreement.take().ok_or(0x21u8)?; // PROCESSING
                    let secret = agreement::agree_ephemeral(
                        k,
                        &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer[..]),
                        hmac::derive,
                    )
                    .map_err(|_| 0x02u8)?;
                    if hmac::mac16(&secret[..], enc) != auth[..] {
                        return Err(0x33); // PIN_AUTH_INVALID
                    }
                    let salt = cbc::run(&secret, &[0; 16], enc, false).map_err(|_| 0x02u8)?;
                    let sealed = cbc::run(&secret, &[0; 16], &self.expected(&id, &salt), true).map_err(|_| 0x7fu8)?;
                    let hmac_secret = match self.fault {
                        Fault::HmacSecretNotBytes => t("sealed"),
                        _ => Value::Bytes(sealed),
                    };
                    let ext = match self.fault {
                        Fault::NoExtensions => vec![],
                        Fault::NoHmacSecret => cbor::encode(&Value::Map(vec![(t("credProtect"), u(1))])),
                        _ => cbor::encode(&Value::Map(vec![(t("hmac-secret"), hmac_secret)])),
                    };
                    let flags = match self.fault {
                        Fault::NoEdFlag => 0x01,
                        _ => 0x81,
                    };
                    let rp = if self.fault == Fault::WrongRp { "elsewhere" } else { rp };
                    Ok(Value::Map(vec![
                        (
                            u(1),
                            Value::Map(vec![(t("id"), Value::Bytes(id)), (t("type"), t("public-key"))]),
                        ),
                        (u(2), Value::Bytes(Self::auth_data(rp, flags, &ext))),
                        (u(3), Value::Bytes(vec![0x30; 70])),
                    ]))
                }
                _ => Err(0x01),
            }
        }

        fn send(&mut self, cid: u32, cmd: u8, body: &[u8]) {
            // (Only fails for a body over the largest message: nothing this key says is.)
            let _ = frame::send(&mut Sink(&mut self.out), cid, cmd, body);
        }

        fn error(&mut self, cid: u32, code: u8) {
            self.send(cid, frame::ERROR, &[code]);
        }

        /// A CTAP2 request answered: its status byte, then its map if it has one.
        fn cbor(&mut self, cid: u32, data: &[u8]) {
            let Some((&cmd, rest)) = data.split_first() else {
                return self.error(cid, ERR_LENGTH);
            };
            // (An empty map is what a request with no parameters, like getInfo, sends: nothing.)
            let p = if rest.is_empty() {
                Value::Map(vec![])
            } else {
                match cbor::decode(rest) {
                    Ok(p) => p,
                    Err(_) => return self.send(cid, frame::CBOR, &[0x12]), // INVALID_CBOR
                }
            };
            #[cfg(test)]
            self.seen.push((cmd, p.clone()));
            let body = match self.ctap(cmd, &p) {
                Ok(v) => [&[0][..], &cbor::encode(&v)].concat(),
                Err(status) => vec![status],
            };
            self.send(cid, frame::CBOR, &body);
        }

        fn keepalive(&mut self, cid: u32) {
            self.send(cid, frame::KEEPALIVE, &[UPNEEDED]);
        }

        /// One touch, if there is one: the file is removed, so it is spent.
        fn touched(&self) -> bool {
            self.touch.as_ref().is_some_and(|p| std::fs::remove_file(p).is_ok())
        }

        /// Time passing: a request waiting for its touch is answered if the touch came, and
        /// otherwise given another keep-alive. The uhid loop calls this every 100 ms, and a
        /// read from the key with nothing to say does (so a test on a pipe needs no clock).
        pub fn poll(&mut self) {
            let Some((cid, _)) = &self.pending else { return };
            let cid = *cid;
            if self.touched() {
                if let Some((cid, data)) = self.pending.take() {
                    self.cbor(cid, &data);
                }
            } else {
                self.keepalive(cid);
            }
        }

        /// The reports to send to the client, oldest first.
        pub fn take(&mut self) -> Option<Vec<u8>> {
            self.out.pop_front()
        }

        fn answer(&mut self, cid: u32, cmd: u8, data: Vec<u8>) {
            // INIT is the one command a busy key takes: it drops what waits for a touch.
            if cmd == frame::INIT {
                if data.len() != 8 || (cid != BROADCAST && cid != CID) {
                    return self.error(cid, if data.len() != 8 { ERR_LENGTH } else { ERR_CHANNEL });
                }
                self.pending = None;
                let mut a = data;
                a.extend_from_slice(&CID.to_be_bytes());
                a.extend_from_slice(&[2, 5, 1, 0, 0x04]); // CTAPHID 2, version 5.1.0, CBOR and no MSG
                return self.send(cid, frame::INIT, &a);
            }
            if cid != CID {
                return self.error(cid, ERR_CHANNEL);
            }
            if self.pending.is_some() {
                return self.error(cid, ERR_BUSY);
            }
            match cmd {
                PING => self.send(cid, PING, &data),
                frame::CBOR if self.touch.is_some() && matches!(data.first(), Some(0x01 | 0x02)) => {
                    self.pending = Some((cid, data));
                    self.poll();
                }
                frame::CBOR => self.cbor(cid, &data),
                _ => self.error(cid, 0x01), // INVALID_CMD
            }
        }
    }

    impl Device for Key {
        fn write(&mut self, r: &[u8; REPORT]) -> io::Result<()> {
            let cid = u32::from_be_bytes([r[0], r[1], r[2], r[3]]);
            if r[4] & 0x80 != 0 {
                let len = usize::from(u16::from_be_bytes([r[5], r[6]]));
                if len > frame::MAX_MESSAGE {
                    self.incoming = None;
                    self.error(cid, ERR_LENGTH);
                    return Ok(());
                }
                self.incoming = Some((cid, r[4] & 0x7f, len, r[7..7 + len.min(REPORT - 7)].to_vec()));
            } else if let Some(m) = &mut self.incoming
                && m.0 == cid
            {
                let want = (m.2 - m.3.len()).min(REPORT - 5);
                m.3.extend_from_slice(&r[5..5 + want]);
            }
            if self.incoming.as_ref().is_some_and(|m| m.3.len() >= m.2)
                && let Some((cid, cmd, _, data)) = self.incoming.take()
            {
                self.answer(cid, cmd, data);
            }
            Ok(())
        }

        fn read(&mut self) -> io::Result<Vec<u8>> {
            if self.out.is_empty() {
                self.poll();
            }
            self.out
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "the key has nothing to say"))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::fido2::flow;

        const RP: &str = "kith.local";

        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        fn open(key: &mut Key) -> u32 {
            frame::init(key, *b"01234567").unwrap().cid
        }

        /// A unique file name to touch, in the test's own folder.
        fn touch_path(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!("kith-fido2-test-{}-{name}", std::process::id()));
            let _ = std::fs::remove_file(&dir);
            dir
        }

        /// What an init packet of command `cmd` on `cid` with `len` says, and `data` after it.
        fn packet(cid: u32, cmd: u8, len: u16, data: &[u8]) -> [u8; REPORT] {
            let mut r = [0u8; REPORT];
            r[..4].copy_from_slice(&cid.to_be_bytes());
            r[4] = 0x80 | cmd;
            r[5..7].copy_from_slice(&len.to_be_bytes());
            r[7..7 + data.len()].copy_from_slice(data);
            r
        }

        fn said(key: &mut Key) -> Vec<Vec<u8>> {
            std::iter::from_fn(|| key.take()).collect()
        }

        #[test]
        fn init_gives_a_channel_and_the_key_says_what_it_can() {
            let mut key = Key::new();
            let ch = frame::init(&mut key, *b"abcdefgh").unwrap();
            assert_eq!((ch.cid, ch.version, ch.caps), (CID, 2, 0x04));
            flow::check_key(&mut key, ch.cid).unwrap();
        }

        #[test]
        fn make_credential_then_get_assertion_gives_the_secret_the_seed_says() {
            let mut key = Key::new();
            let cid = open(&mut key);
            let id = flow::make_credential(&mut key, cid, RP, &[]).unwrap();
            assert_eq!(id, key.creds[0]);
            let salt = [0x42u8; 32];
            let secret = flow::get_assertion(&mut key, cid, RP, &id, &salt).unwrap();
            assert_eq!(secret[..], key.expected(&id, &salt)[..]);
            assert_eq!(
                flow::get_assertion(&mut key, cid, RP, &id, &salt).unwrap()[..],
                secret[..]
            );
            assert_ne!(
                flow::get_assertion(&mut key, cid, RP, &id, &[0x43; 32]).unwrap()[..],
                secret[..]
            );
        }

        /// The seed derivation against numbers computed outside Rust (Python's hmac): the
        /// credential's secret is HMAC(seed bytes, id) and the answer HMAC(that, salt); and the
        /// first credential's id is its number and the first 16 bytes of HMAC(seed bytes, number).
        #[test]
        fn the_secret_is_the_hmac_of_the_salt_under_the_credentials_hmac() {
            let key = Key::new(); // seed 1: thirty-two bytes of 0x01
            let id: Vec<u8> = (0..32).collect();
            assert_eq!(
                hex(&key.expected(&id, &[0x42; 32])),
                "c16f76ecde79a2932c1a0b519cfd4e892498b401a55d717e5c90610868220116"
            );
            assert_eq!(
                hex(&key.make_id(0)),
                "00000000000000000000000000000000".to_string() + "4445762421861c5cb822daf5a1757928"
            );
        }

        #[test]
        fn another_seed_is_another_key_and_does_not_know_the_first_ones_credentials() {
            let (mut a, mut b) = (Key::new(), Key::new());
            b.seed = 2;
            let (ca, cb) = (open(&mut a), open(&mut b));
            let ida = flow::make_credential(&mut a, ca, RP, &[]).unwrap();
            let idb = flow::make_credential(&mut b, cb, RP, std::slice::from_ref(&ida)).unwrap();
            assert_ne!(ida, idb);
            let salt = [9u8; 32];
            let sa = flow::get_assertion(&mut a, ca, RP, &ida, &salt).unwrap();
            let sb = flow::get_assertion(&mut b, cb, RP, &idb, &salt).unwrap();
            assert_ne!(sa[..], sb[..]);
            // a's credential is no use at b, and b's own is excluded at b
            let e = flow::get_assertion(&mut b, cb, RP, &ida, &salt).unwrap_err();
            assert!(e.contains("NO_CREDENTIALS"), "{e}");
            let e = flow::make_credential(&mut b, cb, RP, &[idb]).unwrap_err();
            assert!(e.contains(frame::CREDENTIAL_EXCLUDED), "{e}");
            assert_eq!(b.creds.len(), 1, "and made nothing");
        }

        #[test]
        fn a_restarted_key_with_the_same_seed_still_knows_its_credential() {
            let mut first = Key::new();
            let cid = open(&mut first);
            let id = flow::make_credential(&mut first, cid, RP, &[]).unwrap();
            let mut again = Key::new();
            let cid = open(&mut again);
            let secret = flow::get_assertion(&mut again, cid, RP, &id, &[5; 32]).unwrap();
            assert_eq!(secret[..], first.expected(&id, &[5; 32])[..]);
        }

        #[test]
        fn ping_comes_back_as_it_went() {
            let mut key = Key::new();
            let cid = open(&mut key);
            let data: Vec<u8> = (0..200).map(|i| i as u8).collect();
            frame::send(&mut key, cid, PING, &data).unwrap();
            assert_eq!(frame::recv(&mut key, cid, PING).unwrap(), data);
        }

        #[test]
        fn what_a_client_can_get_wrong_is_answered_and_never_panics() {
            let mut key = Key::new();
            // an INIT of the wrong length, on a channel it does not know, a CBOR with nothing,
            // bad CBOR, an unknown command, a length over the largest, a stray continuation
            key.write(&packet(BROADCAST, frame::INIT, 3, b"abc")).unwrap();
            key.write(&packet(0x1234_5678, frame::CBOR, 1, &[4])).unwrap();
            key.write(&packet(CID, frame::CBOR, 0, &[])).unwrap();
            key.write(&packet(CID, frame::CBOR, 3, &[1, 0xff, 0xff])).unwrap();
            key.write(&packet(CID, 0x2a, 0, &[])).unwrap();
            key.write(&packet(CID, frame::CBOR, 8000, &[])).unwrap();
            let mut cont = [0u8; REPORT];
            cont[..4].copy_from_slice(&CID.to_be_bytes());
            key.write(&cont).unwrap();
            let got = said(&mut key);
            let kinds: Vec<(u32, u8, u8)> = got
                .iter()
                .map(|r| (u32::from_be_bytes([r[0], r[1], r[2], r[3]]), r[4], r[7]))
                .collect();
            assert_eq!(
                kinds,
                [
                    (BROADCAST, 0x80 | frame::ERROR, ERR_LENGTH),
                    (0x1234_5678, 0x80 | frame::ERROR, ERR_CHANNEL),
                    (CID, 0x80 | frame::ERROR, ERR_LENGTH),
                    (CID, 0x80 | frame::CBOR, 0x12),
                    (CID, 0x80 | frame::ERROR, 0x01),
                    (CID, 0x80 | frame::ERROR, ERR_LENGTH),
                ]
            );
            // and it still works after all that
            let cid = open(&mut key);
            flow::check_key(&mut key, cid).unwrap();
        }

        #[test]
        fn a_key_with_a_pin_says_pin_required_and_a_key_without_hmac_secret_is_refused() {
            let mut key = Key::new();
            key.pin = true;
            let cid = open(&mut key);
            let e = flow::make_credential(&mut key, cid, RP, &[]).unwrap_err();
            assert!(e.contains(frame::PIN_REQUIRED), "{e}");
            let mut key = Key::new();
            key.extensions = vec![];
            let cid = open(&mut key);
            assert!(flow::check_key(&mut key, cid).is_err());
        }

        #[test]
        fn without_a_touch_the_client_gets_keepalives_and_gives_up_and_with_one_it_is_answered_once() {
            let path = touch_path("once");
            let mut key = Key::new();
            key.touch = Some(path.clone());
            let cid = open(&mut key);
            // getInfo needs no touch; makeCredential waits, and the client's bound on
            // keep-alives ends the wait (a pipe has no clock: each read gives one)
            flow::check_key(&mut key, cid).unwrap();
            let e = flow::make_credential(&mut key, cid, RP, &[]).unwrap_err();
            assert!(e.contains("no answer"), "{e}");
            assert!(key.creds.is_empty(), "nothing was made without a touch");
            // the request still waits (a second one is busy) until a new INIT drops it
            let e = flow::check_key(&mut key, cid).unwrap_err();
            assert!(e.contains("0x06"), "busy: {e}");
            let cid = open(&mut key);
            std::fs::write(&path, b"").unwrap();
            let id = flow::make_credential(&mut key, cid, RP, &[]).unwrap();
            assert!(!path.exists(), "the touch is spent");
            assert_eq!(key.creds, std::slice::from_ref(&id));
            // spent: the next operation waits again, and a touch later answers it
            assert!(flow::get_assertion(&mut key, cid, RP, &id, &[1; 32]).is_err());
            let cid = open(&mut key);
            std::fs::write(&path, b"").unwrap();
            assert!(flow::get_assertion(&mut key, cid, RP, &id, &[1; 32]).is_ok());
            assert!(!path.exists());
        }

        #[test]
        fn a_second_request_while_one_waits_is_busy() {
            let path = touch_path("busy");
            let mut key = Key::new();
            key.touch = Some(path);
            let cid = open(&mut key);
            frame::send(&mut key, cid, frame::CBOR, &[0x01]).unwrap();
            let first = said(&mut key);
            assert_eq!(first.len(), 1, "one keep-alive for the one that waits");
            assert_eq!(first[0][4], 0x80 | frame::KEEPALIVE);
            assert_eq!(first[0][7], UPNEEDED);
            frame::send(&mut key, cid, frame::CBOR, &[0x04]).unwrap();
            let busy = said(&mut key);
            assert_eq!((busy[0][4], busy[0][7]), (0x80 | frame::ERROR, ERR_BUSY));
        }
    }
}

/// `/dev/uhid`: the kernel makes a HID device from what this writes, and gives what the client
/// writes to it back as events. Plain reads and writes of `struct uhid_event` (linux/uhid.h):
/// no ioctl, no unsafe.
pub mod uhid {
    use super::auth::Key;
    use crate::fido2::frame::{Device, REPORT};
    use std::{
        fs::OpenOptions,
        io::{self, Read, Write},
        os::fd::AsFd,
    };

    pub const PATH: &str = "/dev/uhid";
    /// `sizeof(struct uhid_event)`: a 4-byte type and the largest of its union (create2: 4372).
    pub const EVENT: usize = 4 + 4372;
    const CREATE2: u32 = 11;
    const INPUT2: u32 = 12;
    const OUTPUT: u32 = 6;
    const DATA_MAX: usize = 4096;
    const BUS_USB: u16 = 3;
    /// The offset of create2's `rd_size`: after the type, name (128), phys (64) and uniq (64).
    const RD_SIZE: usize = 4 + 128 + 64 + 64;
    const RD_DATA: usize = RD_SIZE + 2 + 2 + 4 * 4;

    /// The report descriptor of a FIDO device: usage page 0xF1D0, usage 1 (CTAPHID), one
    /// 64-byte input report and one 64-byte output report, no report ids.
    pub const DESCRIPTOR: [u8; 34] = [
        0x06, 0xd0, 0xf1, // usage page (FIDO alliance)
        0x09, 0x01, // usage (CTAPHID)
        0xa1, 0x01, // collection (application)
        0x09, 0x20, // usage (data in)
        0x15, 0x00, // logical minimum 0
        0x26, 0xff, 0x00, // logical maximum 255
        0x75, 0x08, // report size 8
        0x95, 0x40, // report count 64
        0x81, 0x02, // input (data, variable, absolute)
        0x09, 0x21, // usage (data out)
        0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, //
        0x91, 0x02, // output
        0xc0, // end collection
    ];

    /// UHID_CREATE2: a USB device that is a FIDO key.
    pub fn create2(name: &str) -> Vec<u8> {
        let mut e = vec![0u8; EVENT];
        e[..4].copy_from_slice(&CREATE2.to_le_bytes());
        let name = &name.as_bytes()[..name.len().min(127)];
        e[4..4 + name.len()].copy_from_slice(name);
        e[RD_SIZE..RD_SIZE + 2].copy_from_slice(&(DESCRIPTOR.len() as u16).to_le_bytes());
        e[RD_SIZE + 2..RD_SIZE + 4].copy_from_slice(&BUS_USB.to_le_bytes());
        // vendor and product: a number of nobody's, version 1, country 0
        e[RD_SIZE + 4..RD_SIZE + 8].copy_from_slice(&0x1209u32.to_le_bytes());
        e[RD_SIZE + 8..RD_SIZE + 12].copy_from_slice(&0xf1d0u32.to_le_bytes());
        e[RD_SIZE + 12..RD_SIZE + 16].copy_from_slice(&1u32.to_le_bytes());
        e[RD_DATA..RD_DATA + DESCRIPTOR.len()].copy_from_slice(&DESCRIPTOR);
        e
    }

    /// UHID_INPUT2: one report for the client to read.
    pub fn input2(report: &[u8]) -> Vec<u8> {
        let mut e = vec![0u8; EVENT];
        e[..4].copy_from_slice(&INPUT2.to_le_bytes());
        let n = report.len().min(DATA_MAX);
        e[4..6].copy_from_slice(&(n as u16).to_le_bytes());
        e[6..6 + n].copy_from_slice(&report[..n]);
        e
    }

    /// The report a UHID_OUTPUT event carries: 64 bytes, or 65 with the report id 0 the kernel
    /// may leave in front of an unnumbered report. Anything else is not for the key.
    pub fn output(event: &[u8]) -> Option<[u8; REPORT]> {
        let data = event.get(4..4 + DATA_MAX)?;
        if event.get(..4)? != OUTPUT.to_le_bytes() {
            return None;
        }
        let size = usize::from(u16::from_le_bytes([
            *event.get(4 + DATA_MAX)?,
            *event.get(5 + DATA_MAX)?,
        ]));
        let report = match (size, data) {
            (REPORT, d) => &d[..REPORT],
            (65, [0, d @ ..]) => &d[..REPORT],
            _ => return None,
        };
        report.try_into().ok()
    }

    /// Make the device and answer until the kernel ends it (the file closes or errors).
    /// `poll` runs every 100 ms, which is the pace of a keep-alive.
    pub fn run(key: &mut Key, name: &str) -> io::Result<()> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        let mut f = OpenOptions::new().read(true).write(true).open(PATH)?;
        f.write_all(&create2(name))?;
        let mut buf = vec![0u8; EVENT];
        loop {
            let mut fds = [PollFd::new(f.as_fd(), PollFlags::POLLIN)];
            let ready = poll(&mut fds, PollTimeout::from(100u8)).map_err(io::Error::from)?;
            if ready > 0 {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    return Ok(());
                }
                if let Some(report) = output(&buf[..n]) {
                    key.write(&report)?;
                }
            }
            key.poll();
            while let Some(report) = key.take() {
                f.write_all(&input2(&report))?;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn create2_lays_out_name_descriptor_and_ids_where_the_kernel_reads_them() {
            let e = create2("kith test key");
            assert_eq!(e.len(), EVENT);
            assert_eq!(e[..4], 11u32.to_le_bytes());
            assert_eq!(&e[4..17], b"kith test key");
            assert_eq!(e[RD_SIZE..RD_SIZE + 2], 34u16.to_le_bytes());
            assert_eq!(e[RD_SIZE + 2..RD_SIZE + 4], 3u16.to_le_bytes(), "USB");
            assert_eq!(RD_DATA, 4 + 256 + 4 + 16, "the offset in linux/uhid.h's packed struct");
            assert_eq!(e[RD_DATA..RD_DATA + 34], DESCRIPTOR);
            // a name longer than the field is cut, and the descriptor is not touched
            let long = create2(&"n".repeat(500));
            assert_eq!(long[4 + 127], 0, "NUL-terminated at 128");
            assert_eq!(long[RD_DATA..RD_DATA + 34], DESCRIPTOR);
        }

        #[test]
        fn the_descriptor_is_fido_with_two_64_byte_reports() {
            assert_eq!(DESCRIPTOR[..3], [0x06, 0xd0, 0xf1], "usage page F1D0");
            assert_eq!(DESCRIPTOR.windows(2).filter(|w| *w == [0x95, 0x40]).count(), 2);
            assert_eq!(DESCRIPTOR[DESCRIPTOR.len() - 1], 0xc0, "closed");
        }

        #[test]
        fn input2_carries_its_size_then_the_report() {
            let e = input2(&[7; 64]);
            assert_eq!((e.len(), e[..4].to_vec()), (EVENT, 12u32.to_le_bytes().to_vec()));
            assert_eq!(e[4..6], 64u16.to_le_bytes());
            assert_eq!(e[6..70], [7; 64]);
        }

        fn out_event(kind: u32, data: &[u8], size: u16) -> Vec<u8> {
            let mut e = vec![0u8; EVENT];
            e[..4].copy_from_slice(&kind.to_le_bytes());
            e[4..4 + data.len()].copy_from_slice(data);
            e[4 + DATA_MAX..6 + DATA_MAX].copy_from_slice(&size.to_le_bytes());
            e
        }

        #[test]
        fn an_output_event_gives_its_64_bytes_with_or_without_a_report_id() {
            let report: Vec<u8> = (1..=64).collect();
            assert_eq!(output(&out_event(6, &report, 64)).unwrap()[..], report[..]);
            let mut numbered = vec![0u8];
            numbered.extend_from_slice(&report);
            assert_eq!(output(&out_event(6, &numbered, 65)).unwrap()[..], report[..]);
            // another report id, another size, another event, a short read: not for the key
            numbered[0] = 1;
            assert!(output(&out_event(6, &numbered, 65)).is_none());
            assert!(output(&out_event(6, &report, 63)).is_none());
            assert!(output(&out_event(6, &report, 5000)).is_none());
            assert!(output(&out_event(2, &report, 64)).is_none());
            assert!(output(&out_event(6, &report, 64)[..100]).is_none());
            assert!(output(&[]).is_none());
        }
    }
}

/// `kithd fido2-authenticator [--seed N] [--touch FILE]`: the stand-in as a process of its own,
/// started by the VM test. Without `--touch` it answers at once; with it, an operation waits for
/// the file to exist. Never returns when it is asked for.
#[cfg(feature = "fido2-test")]
pub fn shim() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("fido2-authenticator") {
        return;
    }
    let mut key = auth::Key::new();
    while let Some(a) = args.next() {
        match (a.as_str(), args.next()) {
            ("--seed", Some(n)) if n.parse::<u8>().is_ok() => key.seed = n.parse().unwrap_or(1),
            ("--touch", Some(p)) => key.touch = Some(p.into()),
            _ => {
                eprintln!("usage: kithd fido2-authenticator [--seed 0-255] [--touch FILE]");
                std::process::exit(2);
            }
        }
    }
    eprintln!(
        "kithd: fido2-authenticator: a security key (seed {}, {}) on {}",
        key.seed,
        key.touch
            .as_ref()
            .map_or("touched at once".into(), |p| format!("touch file {}", p.display())),
        uhid::PATH
    );
    let e = uhid::run(&mut key, "kith FIDO2 test key");
    eprintln!("kithd: fido2-authenticator: ended: {e:?}");
    std::process::exit(1);
}
