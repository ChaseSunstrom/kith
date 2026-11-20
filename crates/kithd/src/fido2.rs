//! The wire half of kithd's CTAP2 client (docs/adr-fido2.md, sections 1 and 6): CTAPHID
//! framing over a [`Device`] and the CBOR subset a key speaks. Everything a key sends is
//! untrusted bytes: each parser here refuses what it does not know, bounds what it reads
//! and never indexes or allocates from a length it has not checked.
//!
//! The device is a trait so a test can use a pipe; the hidraw one comes with the client.

/// Hex text to bytes, for the tests' NIST and RFC vectors.
#[cfg(test)]
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// CTAPHID: 64-byte reports, a message split over an initialization packet and up to 128
/// continuation packets.
pub mod frame {
    use std::io;

    /// A report is exactly this long on every HID device a key presents.
    pub const REPORT: usize = 64;
    /// 57 bytes in the initialization packet, 59 in each of at most 128 continuations.
    pub const MAX_MESSAGE: usize = 57 + 128 * 59;
    pub const BROADCAST: u32 = 0xffff_ffff;
    /// Reports for another channel and keep-alives are skipped, up to this many in all for
    /// one message: a key that never answers cannot hold the console for ever. (A touch
    /// wait of 30 s at one keep-alive per 100 ms is 300.)
    const MAX_SKIPPED: usize = 1024;
    /// INIT answers for another application's nonce, on the broadcast channel.
    const MAX_FOREIGN_INIT: usize = 16;

    pub const MSG: u8 = 0x03;
    pub const INIT: u8 = 0x06;
    pub const CBOR: u8 = 0x10;
    pub const KEEPALIVE: u8 = 0x3b;
    pub const ERROR: u8 = 0x3f;

    /// What a key is read and written through: whole reports. `write` gets exactly
    /// [`REPORT`] bytes (the hidraw device adds its report-id byte); `read` gives one
    /// report and fails with `TimedOut` when none comes in time. **The wall-clock bound of
    /// a [`recv`] is `MAX_SKIPPED` (1024) times the read timeout**, so the hidraw device
    /// must set a timeout of its own (a second or less), as nothing here has a clock.
    /// After any `Err` from this module the device may hold half a message: the caller
    /// reopens it or drains it before the next exchange.
    pub trait Device {
        fn write(&mut self, report: &[u8; REPORT]) -> io::Result<()>;
        fn read(&mut self) -> io::Result<Vec<u8>>;
    }

    /// Send one message, `cmd` being the command without its top bit.
    pub fn send(dev: &mut dyn Device, cid: u32, cmd: u8, data: &[u8]) -> Result<(), String> {
        if data.len() > MAX_MESSAGE {
            return Err(format!("a message of {} bytes: at most {MAX_MESSAGE}", data.len()));
        }
        if cmd & 0x80 != 0 {
            return Err(format!("command {cmd:#04x} has its top bit set"));
        }
        let mut report = [0u8; REPORT];
        report[..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = 0x80 | cmd;
        report[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes()); // <= 7609
        let (first, mut rest) = data.split_at(data.len().min(REPORT - 7));
        report[7..7 + first.len()].copy_from_slice(first);
        let put = |dev: &mut dyn Device, r: &[u8; REPORT]| dev.write(r).map_err(|e| format!("writing to the key: {e}"));
        put(dev, &report)?;
        for seq in 0..128u8 {
            if rest.is_empty() {
                break;
            }
            let (chunk, after) = rest.split_at(rest.len().min(REPORT - 5));
            rest = after;
            report = [0u8; REPORT];
            report[..4].copy_from_slice(&cid.to_be_bytes());
            report[4] = seq;
            report[5..5 + chunk.len()].copy_from_slice(chunk);
            put(dev, &report)?;
        }
        Ok(())
    }

    fn read_report(dev: &mut dyn Device) -> Result<Vec<u8>, String> {
        let report = dev.read().map_err(|e| format!("reading from the key: {e}"))?;
        if report.len() != REPORT {
            return Err(format!("a report of {} bytes: {REPORT} expected", report.len()));
        }
        Ok(report)
    }

    fn skip(skipped: &mut usize) -> Result<(), String> {
        *skipped += 1;
        if *skipped > MAX_SKIPPED {
            return Err(format!(
                "{MAX_SKIPPED} reports for another channel or keep-alives and no answer"
            ));
        }
        Ok(())
    }

    /// Read one message of command `want` on channel `cid`. Reports of other channels and
    /// keep-alives are skipped (bounded); an ERROR, another command, a length over
    /// [`MAX_MESSAGE`], a continuation out of order or a new message in the middle of one
    /// is refused. A continuation of ours before any message began (the tail of an answer
    /// to an earlier, abandoned request) is skipped like another channel's report.
    /// At most `MAX_SKIPPED` reports are skipped, so the wall-clock bound is that times
    /// the device's read timeout (see [`Device`]); after an `Err` the caller reopens or
    /// drains the device.
    pub fn recv(dev: &mut dyn Device, cid: u32, want: u8) -> Result<Vec<u8>, String> {
        let mut skipped = 0;
        let (len, mut msg) = loop {
            let r = read_report(dev)?;
            if r[..4] != cid.to_be_bytes() || r[4] & 0x80 == 0 {
                skip(&mut skipped)?;
                continue;
            }
            let len = usize::from(u16::from_be_bytes([r[5], r[6]]));
            match r[4] & 0x7f {
                KEEPALIVE => {
                    skip(&mut skipped)?;
                    continue;
                }
                ERROR if len == 1 => return Err(format!("the key answered with error {:#04x}", r[7])),
                ERROR => return Err("the key answered with an error of an odd length".into()),
                got if got != want => return Err(format!("command {got:#04x} answered, {want:#04x} expected")),
                _ if len > MAX_MESSAGE => return Err(format!("a message of {len} bytes: at most {MAX_MESSAGE}")),
                _ => break (len, r[7..7 + len.min(REPORT - 7)].to_vec()),
            }
        };
        let mut seq = 0u8;
        while msg.len() < len {
            let r = read_report(dev)?;
            if r[..4] != cid.to_be_bytes() {
                skip(&mut skipped)?;
                continue;
            }
            if r[4] != seq {
                return Err(format!("continuation {:#04x} where {seq} was due", r[4]));
            }
            msg.extend_from_slice(&r[5..5 + (len - msg.len()).min(REPORT - 5)]);
            seq += 1; // len <= MAX_MESSAGE: at most 128 continuations, seq stays under 0x80
        }
        Ok(msg)
    }

    /// A channel a key gave: its id, the capabilities byte, the protocol version.
    #[derive(Debug, PartialEq)]
    pub struct Channel {
        pub cid: u32,
        pub version: u8,
        pub caps: u8,
    }

    /// CTAPHID_INIT on the broadcast channel with `nonce` (the caller's random bytes).
    pub fn init(dev: &mut dyn Device, nonce: [u8; 8]) -> Result<Channel, String> {
        send(dev, BROADCAST, INIT, &nonce)?;
        for _ in 0..MAX_FOREIGN_INIT {
            let a = recv(dev, BROADCAST, INIT)?;
            if a.len() != 17 {
                return Err(format!("an INIT answer of {} bytes: 17 expected", a.len()));
            }
            if a[..8] != nonce {
                continue; // another application's INIT on the shared channel
            }
            let cid = u32::from_be_bytes([a[8], a[9], a[10], a[11]]);
            if cid == 0 || cid == BROADCAST {
                return Err(format!("the key gave channel {cid:#010x}"));
            }
            return Ok(Channel {
                cid,
                version: a[12],
                caps: a[16],
            });
        }
        Err("no INIT answer for this nonce".into())
    }

    /// One CTAPHID_CBOR exchange: `request` is the command byte and its map; the answer is
    /// the CBOR after the key's status byte, which must be 0.
    pub fn cbor_request(dev: &mut dyn Device, cid: u32, request: &[u8]) -> Result<Vec<u8>, String> {
        send(dev, cid, CBOR, request)?;
        let answer = recv(dev, cid, CBOR)?;
        match answer.split_first() {
            None => Err("an empty CBOR answer".into()),
            Some((0, body)) => Ok(body.to_vec()),
            Some((status, _)) => Err(format!("the key answered status {status:#04x}{}", status_name(*status))),
        }
    }

    pub const CREDENTIAL_EXCLUDED: &str = "CREDENTIAL_EXCLUDED";
    pub const PIN_REQUIRED: &str = "PIN_REQUIRED";
    /// What a key says when its touch was not given in time.
    pub const USER_ACTION_TIMEOUT: &str = "USER_ACTION_TIMEOUT";
    /// What a key says of a credential it does not hold (no touch asked).
    pub const NO_CREDENTIALS: &str = "NO_CREDENTIALS";

    /// The CTAP2 status codes a console has to tell apart, as ` (NAME)` after the number.
    fn status_name(status: u8) -> String {
        let name = match status {
            0x01 => "INVALID_COMMAND",
            0x02 => "INVALID_PARAMETER",
            0x03 => "INVALID_LENGTH",
            0x19 => CREDENTIAL_EXCLUDED,
            0x26 => "UNSUPPORTED_ALGORITHM",
            0x27 => "OPERATION_DENIED",
            0x2e => NO_CREDENTIALS,
            0x2f => USER_ACTION_TIMEOUT,
            0x31 => "PIN_INVALID",
            0x32 => "PIN_BLOCKED",
            0x35 => "PIN_NOT_SET",
            0x36 => PIN_REQUIRED,
            _ => return String::new(),
        };
        format!(" ({name})")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::VecDeque;

        /// A pipe: what the client writes is kept, what it reads is queued.
        #[derive(Default)]
        struct Pipe {
            written: Vec<[u8; REPORT]>,
            queued: VecDeque<Vec<u8>>,
        }

        impl Device for Pipe {
            fn write(&mut self, r: &[u8; REPORT]) -> io::Result<()> {
                self.written.push(*r);
                Ok(())
            }
            fn read(&mut self) -> io::Result<Vec<u8>> {
                self.queued
                    .pop_front()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "pipe empty"))
            }
        }

        /// The key's side: the reports `send` makes of a message, queued for the client.
        fn queue(pipe: &mut Pipe, cid: u32, cmd: u8, data: &[u8]) {
            let mut key = Pipe::default();
            send(&mut key, cid, cmd, data).unwrap();
            pipe.queued.extend(key.written.iter().map(|r| r.to_vec()));
        }

        fn report(cid: u32, byte4: u8, rest: &[u8]) -> Vec<u8> {
            let mut r = vec![0u8; REPORT];
            r[..4].copy_from_slice(&cid.to_be_bytes());
            r[4] = byte4;
            r[5..5 + rest.len()].copy_from_slice(rest);
            r
        }

        fn init_answer(nonce: [u8; 8], cid: u32) -> Vec<u8> {
            let mut a = nonce.to_vec();
            a.extend_from_slice(&cid.to_be_bytes());
            a.extend_from_slice(&[2, 5, 1, 0, 0x04]); // version, major, minor, build, caps (cbor)
            a
        }

        #[test]
        fn init_is_sent_on_the_broadcast_channel_and_answered() {
            let nonce = *b"01234567";
            let mut pipe = Pipe::default();
            queue(&mut pipe, BROADCAST, INIT, &init_answer(nonce, 0x1234_5678));
            let got = init(&mut pipe, nonce).unwrap();
            assert_eq!(
                got,
                Channel {
                    cid: 0x1234_5678,
                    version: 2,
                    caps: 0x04
                }
            );
            let w = &pipe.written;
            assert_eq!(w.len(), 1);
            assert_eq!(&w[0][..7], &[0xff, 0xff, 0xff, 0xff, 0x86, 0, 8]);
            assert_eq!(&w[0][7..15], &nonce);
            assert!(w[0][15..].iter().all(|b| *b == 0), "the rest is zero padding");
        }

        #[test]
        fn init_skips_another_applications_answer_but_not_forever() {
            let nonce = *b"01234567";
            let mut pipe = Pipe::default();
            queue(&mut pipe, BROADCAST, INIT, &init_answer(*b"someone!", 7));
            queue(&mut pipe, BROADCAST, INIT, &init_answer(nonce, 9));
            assert_eq!(init(&mut pipe, nonce).unwrap().cid, 9);
            let mut pipe = Pipe::default();
            for _ in 0..17 {
                queue(&mut pipe, BROADCAST, INIT, &init_answer(*b"someone!", 7));
            }
            assert!(init(&mut pipe, nonce).unwrap_err().contains("no INIT answer"));
        }

        #[test]
        fn init_refuses_a_short_answer_and_a_channel_it_cannot_use() {
            let nonce = *b"01234567";
            let mut pipe = Pipe::default();
            queue(&mut pipe, BROADCAST, INIT, &init_answer(nonce, 9)[..16]);
            assert!(init(&mut pipe, nonce).unwrap_err().contains("16 bytes"));
            for bad in [0, BROADCAST] {
                let mut pipe = Pipe::default();
                queue(&mut pipe, BROADCAST, INIT, &init_answer(nonce, bad));
                assert!(init(&mut pipe, nonce).unwrap_err().contains("gave channel"));
            }
        }

        #[test]
        fn a_message_splits_and_joins_at_every_size() {
            for len in [
                0,
                1,
                56,
                57,
                58,
                59,
                60,
                116,
                117,
                118,
                1000,
                MAX_MESSAGE - 1,
                MAX_MESSAGE,
            ] {
                let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let mut pipe = Pipe::default();
                send(&mut pipe, 0xdead_beef, CBOR, &data).unwrap();
                assert_eq!(pipe.written.len(), 1 + len.saturating_sub(57).div_ceil(59), "len {len}");
                for (n, r) in pipe.written.iter().skip(1).enumerate() {
                    assert_eq!(r[4] as usize, n, "sequence numbers count from 0");
                }
                pipe.queued = pipe.written.iter().map(|r| r.to_vec()).collect();
                assert_eq!(recv(&mut pipe, 0xdead_beef, CBOR).unwrap(), data, "len {len}");
            }
        }

        #[test]
        fn send_refuses_a_message_over_the_limit_and_a_command_with_the_top_bit() {
            let mut pipe = Pipe::default();
            assert!(send(&mut pipe, 1, CBOR, &vec![0; MAX_MESSAGE + 1]).is_err());
            assert!(send(&mut pipe, 1, 0x90, &[]).is_err());
            assert!(pipe.written.is_empty(), "nothing half sent");
        }

        #[test]
        fn recv_refuses_a_short_or_long_report() {
            for len in [0, 1, 63, 65] {
                let mut pipe = Pipe::default();
                pipe.queued.push_back(vec![0x11; len]);
                assert!(recv(&mut pipe, 1, CBOR).unwrap_err().contains("expected"), "len {len}");
            }
        }

        #[test]
        fn recv_skips_reports_of_another_channel_and_reads_ours() {
            let mut pipe = Pipe::default();
            queue(
                &mut pipe,
                2,
                CBOR,
                b"not for us, a long one: it is more than fifty-seven bytes of text",
            );
            queue(&mut pipe, 1, CBOR, b"ours");
            assert_eq!(recv(&mut pipe, 1, CBOR).unwrap(), b"ours");
            // another channel's report in the middle of ours is skipped too
            let mut pipe = Pipe::default();
            let data = vec![5u8; 100];
            let mut mine = Pipe::default();
            send(&mut mine, 1, CBOR, &data).unwrap();
            pipe.queued.push_back(mine.written[0].to_vec());
            pipe.queued.push_back(report(2, 0, b"theirs"));
            pipe.queued.push_back(mine.written[1].to_vec());
            assert_eq!(recv(&mut pipe, 1, CBOR).unwrap(), data);
        }

        #[test]
        fn recv_refuses_an_oversize_length_before_reading_more() {
            let mut r = report(1, 0x80 | CBOR, &[]);
            r[5..7].copy_from_slice(&(MAX_MESSAGE as u16 + 1).to_be_bytes());
            let mut pipe = Pipe::default();
            pipe.queued.push_back(r);
            assert!(recv(&mut pipe, 1, CBOR).unwrap_err().contains("at most"));
            let mut r = report(1, 0x80 | CBOR, &[]);
            r[5..7].copy_from_slice(&u16::MAX.to_be_bytes());
            pipe.queued.push_back(r);
            assert!(recv(&mut pipe, 1, CBOR).is_err());
        }

        #[test]
        fn recv_refuses_a_continuation_out_of_order_or_a_new_message_in_the_middle() {
            let data = vec![1u8; 200];
            let mut mine = Pipe::default();
            send(&mut mine, 1, CBOR, &data).unwrap();
            let w: Vec<Vec<u8>> = mine.written.iter().map(|r| r.to_vec()).collect();
            let mut pipe = Pipe::default();
            pipe.queued.extend([w[0].clone(), w[2].clone()]);
            assert!(recv(&mut pipe, 1, CBOR).unwrap_err().contains("where 0 was due"));
            pipe.queued.extend([w[0].clone(), w[0].clone()]);
            assert!(
                recv(&mut pipe, 1, CBOR).is_err(),
                "an initialization packet is not a continuation"
            );
        }

        #[test]
        fn a_stray_continuation_of_ours_is_skipped_and_counted() {
            let mut mine = Pipe::default();
            send(&mut mine, 1, CBOR, &[7; 100]).unwrap();
            let mut pipe = Pipe::default();
            pipe.queued.push_back(report(1, 3, b"tail of an abandoned answer"));
            pipe.queued.push_back(mine.written[0].to_vec());
            pipe.queued.push_back(mine.written[1].to_vec());
            assert_eq!(recv(&mut pipe, 1, CBOR).unwrap(), vec![7; 100]);

            struct Strays;
            impl Device for Strays {
                fn write(&mut self, _: &[u8; REPORT]) -> io::Result<()> {
                    Ok(())
                }
                fn read(&mut self) -> io::Result<Vec<u8>> {
                    Ok(report(1, 0, &[]))
                }
            }
            assert!(recv(&mut Strays, 1, CBOR).unwrap_err().contains("no answer"));
        }

        #[test]
        fn a_hard_coded_two_packet_message_is_what_send_makes() {
            // 100 bytes 0..100 of CBOR on channel ffffffff: 57 in the first packet, 43 in the second.
            let data: Vec<u8> = (0..100).collect();
            let mut first = vec![0xff, 0xff, 0xff, 0xff, 0x90, 0x00, 0x64];
            first.extend(0..57u8);
            let mut second = vec![0xff, 0xff, 0xff, 0xff, 0x00];
            second.extend(57..100u8);
            second.resize(REPORT, 0);
            let mut pipe = Pipe::default();
            send(&mut pipe, BROADCAST, CBOR, &data).unwrap();
            assert_eq!(
                pipe.written.iter().map(|r| r.to_vec()).collect::<Vec<_>>(),
                [first.clone(), second.clone()]
            );
            pipe.queued.extend([first, second]);
            assert_eq!(recv(&mut pipe, BROADCAST, CBOR).unwrap(), data);
        }

        #[test]
        fn recv_refuses_a_message_cut_short_and_a_wrong_command() {
            let mut mine = Pipe::default();
            send(&mut mine, 1, CBOR, &[9; 100]).unwrap();
            let mut pipe = Pipe::default();
            pipe.queued.push_back(mine.written[0].to_vec()); // the pipe then runs dry
            assert!(recv(&mut pipe, 1, CBOR).unwrap_err().contains("pipe empty"));
            queue(&mut pipe, 1, MSG, b"u2f");
            assert!(recv(&mut pipe, 1, CBOR).unwrap_err().contains("expected"));
        }

        #[test]
        fn recv_reads_an_error_report_and_refuses_an_odd_one() {
            let mut pipe = Pipe::default();
            queue(&mut pipe, 1, ERROR, &[0x06]);
            assert!(recv(&mut pipe, 1, CBOR).unwrap_err().contains("error 0x06"));
            queue(&mut pipe, 1, ERROR, &[1, 2]);
            assert!(recv(&mut pipe, 1, CBOR).unwrap_err().contains("odd length"));
        }

        #[test]
        fn keepalives_are_skipped_and_a_storm_of_them_is_refused() {
            let mut pipe = Pipe::default();
            for _ in 0..300 {
                queue(&mut pipe, 1, KEEPALIVE, &[1]); // processing, then upneeded
            }
            queue(&mut pipe, 1, CBOR, &[0, 0xa0]);
            assert_eq!(cbor_request(&mut pipe, 1, &[4]).unwrap(), vec![0xa0]);

            struct Storm;
            impl Device for Storm {
                fn write(&mut self, _: &[u8; REPORT]) -> io::Result<()> {
                    Ok(())
                }
                fn read(&mut self) -> io::Result<Vec<u8>> {
                    Ok(report(1, 0x80 | KEEPALIVE, &[0, 1, 1]))
                }
            }
            assert!(recv(&mut Storm, 1, CBOR).unwrap_err().contains("no answer"));
        }

        #[test]
        fn a_storm_of_another_channels_reports_is_refused_in_the_middle_of_a_message_too() {
            struct Noise(usize);
            impl Device for Noise {
                fn write(&mut self, _: &[u8; REPORT]) -> io::Result<()> {
                    Ok(())
                }
                fn read(&mut self) -> io::Result<Vec<u8>> {
                    self.0 += 1;
                    Ok(if self.0 == 1 {
                        report(1, 0x80 | CBOR, &[0, 100])
                    } else {
                        report(2, 0, &[])
                    })
                }
            }
            assert!(recv(&mut Noise(0), 1, CBOR).unwrap_err().contains("no answer"));
        }

        #[test]
        fn cbor_request_refuses_a_status_and_an_empty_answer() {
            let mut pipe = Pipe::default();
            queue(&mut pipe, 1, CBOR, &[0x2e]);
            assert!(cbor_request(&mut pipe, 1, &[4]).unwrap_err().contains("status 0x2e"));
            queue(&mut pipe, 1, CBOR, &[]);
            assert!(cbor_request(&mut pipe, 1, &[4]).unwrap_err().contains("empty"));
            assert_eq!(&pipe.written[0][..8], &[0, 0, 0, 1, 0x90, 0, 1, 4]);
        }
    }
}

/// The CBOR subset of docs/adr-fido2.md section 1: unsigned and negative integers, byte and
/// text strings, arrays and maps of definite length, `bool`. No tags, floats, indefinite
/// lengths or other simple values.
pub mod cbor {
    /// Nested arrays and maps deeper than this are refused.
    pub const MAX_DEPTH: usize = 8;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Uint(u64),
        /// The integer -1 - n.
        Neg(u64),
        Bytes(Vec<u8>),
        Text(String),
        Array(Vec<Value>),
        Map(Vec<(Value, Value)>),
        Bool(bool),
    }

    /// A map key or a small number, as a CBOR unsigned integer.
    pub fn uint(n: u64) -> Value {
        Value::Uint(n)
    }

    impl Value {
        pub fn int(n: i64) -> Value {
            if n >= 0 {
                Value::Uint(n as u64)
            } else {
                Value::Neg(!n as u64)
            }
        }
        pub fn text(s: &str) -> Value {
            Value::Text(s.to_string())
        }
        /// The value under `key` of a map.
        pub fn get(&self, key: &Value) -> Option<&Value> {
            match self {
                Value::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
    }

    fn head(out: &mut Vec<u8>, major: u8, n: u64) {
        let m = major << 5;
        match n {
            0..=23 => out.push(m | n as u8),
            24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(m | 26);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            _ => {
                out.push(m | 27);
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
    }

    /// The shortest form, with a map's entries in CTAP2's canonical order: by the key's
    /// major type, then its encoded length, then bytewise (so 24 sorts before -1). A
    /// map with a key twice is a caller's bug (checked in a debug build).
    pub fn encode(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, v);
        out
    }

    fn put(out: &mut Vec<u8>, v: &Value) {
        match v {
            Value::Uint(n) => head(out, 0, *n),
            Value::Neg(n) => head(out, 1, *n),
            Value::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(t) => {
                head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Value::Array(a) => {
                head(out, 4, a.len() as u64);
                a.iter().for_each(|x| put(out, x));
            }
            Value::Map(m) => {
                head(out, 5, m.len() as u64);
                let mut entries: Vec<(Vec<u8>, &Value)> = m.iter().map(|(k, v)| (encode(k), v)).collect();
                entries.sort_by(|a, b| (a.0[0] >> 5, a.0.len(), &a.0).cmp(&(b.0[0] >> 5, b.0.len(), &b.0)));
                debug_assert!(entries.windows(2).all(|w| w[0].0 != w[1].0), "a map with a key twice");
                for (k, v) in entries {
                    out.extend_from_slice(&k);
                    put(out, v);
                }
            }
            Value::Bool(b) => out.push(0xf4 | u8::from(*b)),
        }
    }

    /// One item, and nothing after it. At most [`super::frame::MAX_MESSAGE`] bytes, nesting
    /// at most [`MAX_DEPTH`], no duplicate map key; every length is checked against the
    /// bytes left before anything is allocated. It is lenient where the encoder is not: it
    /// accepts an integer or length in a longer form than the shortest, and a map in any
    /// order.
    pub fn decode(bytes: &[u8]) -> Result<Value, String> {
        let (v, rest) = decode_prefix(bytes)?;
        if !rest.is_empty() {
            return Err(format!("{} bytes after the CBOR item", rest.len()));
        }
        Ok(v)
    }

    /// The first item of `bytes` and what follows it (an authenticator's data holds a key
    /// and a map one after the other). The same bounds as [`decode`].
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Value, &[u8]), String> {
        if bytes.len() > super::frame::MAX_MESSAGE {
            return Err(format!(
                "{} bytes of CBOR: at most {}",
                bytes.len(),
                super::frame::MAX_MESSAGE
            ));
        }
        let mut rest = bytes;
        let v = item(&mut rest, 0)?;
        Ok((v, rest))
    }

    fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
        if n > rest.len() {
            return Err(format!("CBOR cut short: {n} bytes wanted, {} left", rest.len()));
        }
        let (got, after) = rest.split_at(n);
        *rest = after;
        Ok(got)
    }

    /// A count that is a length in bytes or (at least one byte each) in items.
    fn count(n: u64, rest: &[u8], per: usize) -> Result<usize, String> {
        match usize::try_from(n) {
            Ok(n) if n <= rest.len() / per => Ok(n),
            _ => Err(format!("CBOR claims {n} items or bytes with {} bytes left", rest.len())),
        }
    }

    fn item(rest: &mut &[u8], depth: usize) -> Result<Value, String> {
        let first = take(rest, 1)?[0];
        let (major, info) = (first >> 5, first & 0x1f);
        if major == 7 {
            return match info {
                20 | 21 => Ok(Value::Bool(info == 21)),
                _ => Err(format!("CBOR simple or float {first:#04x} is not in the subset")),
            };
        }
        let n = match info {
            0..=23 => u64::from(info),
            24 => u64::from(take(rest, 1)?[0]),
            25 => u64::from(u16::from_be_bytes(take(rest, 2)?.try_into().map_err(|_| "cut short")?)),
            26 => u64::from(u32::from_be_bytes(take(rest, 4)?.try_into().map_err(|_| "cut short")?)),
            27 => u64::from_be_bytes(take(rest, 8)?.try_into().map_err(|_| "cut short")?),
            31 => return Err("CBOR of indefinite length is not in the subset".into()),
            _ => return Err(format!("CBOR additional information {info} is reserved")),
        };
        match major {
            0 => Ok(Value::Uint(n)),
            1 => Ok(Value::Neg(n)),
            2 => Ok(Value::Bytes(take(rest, count(n, rest, 1)?)?.to_vec())),
            3 => String::from_utf8(take(rest, count(n, rest, 1)?)?.to_vec())
                .map(Value::Text)
                .map_err(|_| "CBOR text that is not UTF-8".into()),
            4 | 5 => {
                if depth >= MAX_DEPTH {
                    return Err(format!("CBOR nested deeper than {MAX_DEPTH}"));
                }
                if major == 4 {
                    let n = count(n, rest, 1)?;
                    let mut a = Vec::new();
                    for _ in 0..n {
                        a.push(item(rest, depth + 1)?);
                    }
                    return Ok(Value::Array(a));
                }
                let n = count(n, rest, 2)?;
                let mut m: Vec<(Value, Value)> = Vec::new();
                for _ in 0..n {
                    let k = item(rest, depth + 1)?;
                    if m.iter().any(|(seen, _)| *seen == k) {
                        return Err("CBOR map with a key twice".into());
                    }
                    m.push((k, item(rest, depth + 1)?));
                }
                Ok(Value::Map(m))
            }
            _ => Err("CBOR tags are not in the subset".into()), // major 6 (7 is above)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::Value::{self, *};
        use super::*;

        fn map(entries: Vec<(Value, Value)>) -> Value {
            Map(entries)
        }
        fn t(s: &str) -> Value {
            Value::text(s)
        }
        use super::uint as u;

        /// Encodes and decodes to the same value, and every proper prefix is refused.
        fn round_trip(v: &Value) -> Vec<u8> {
            let bytes = encode(v);
            assert_eq!(&decode(&bytes).unwrap(), v);
            for cut in 0..bytes.len() {
                assert!(
                    decode(&bytes[..cut]).is_err(),
                    "a prefix of {cut} of {} bytes",
                    bytes.len()
                );
            }
            bytes
        }

        fn get_info() -> Value {
            map(vec![
                (u(1), Array(vec![t("U2F_V2"), t("FIDO_2_0")])),
                (u(2), Array(vec![t("hmac-secret")])),
                (u(3), Bytes((0..16).collect())),
                (u(4), map(vec![(t("rk"), Bool(true)), (t("up"), Bool(true))])),
                (u(6), Array(vec![u(1)])),
            ])
        }

        fn make_credential() -> Value {
            map(vec![
                (u(1), Bytes(vec![0xaa; 32])),
                (u(2), map(vec![(t("id"), t("kith"))])),
                (
                    u(3),
                    map(vec![(t("id"), Bytes(vec![1, 2, 3, 4])), (t("name"), t("kith"))]),
                ),
                (
                    u(4),
                    Array(vec![map(vec![
                        (t("alg"), Value::int(-7)),
                        (t("type"), t("public-key")),
                    ])]),
                ),
                (u(6), map(vec![(t("hmac-secret"), Bool(true))])),
                (u(7), map(vec![(t("rk"), Bool(false))])),
            ])
        }

        fn get_assertion() -> Value {
            let cose = map(vec![
                (u(1), u(2)),
                (u(3), Value::int(-25)),
                (Value::int(-1), u(1)),
                (Value::int(-2), Bytes(vec![0x11; 32])),
                (Value::int(-3), Bytes(vec![0x22; 32])),
            ]);
            map(vec![
                (u(1), t("kith")),
                (u(2), Bytes(vec![0xbb; 32])),
                (
                    u(3),
                    Array(vec![map(vec![
                        (t("id"), Bytes(vec![9; 64])),
                        (t("type"), t("public-key")),
                    ])]),
                ),
                (
                    u(4),
                    map(vec![(
                        t("hmac-secret"),
                        map(vec![
                            (u(1), cose),
                            (u(2), Bytes(vec![3; 64])),
                            (u(3), Bytes(vec![4; 16])),
                        ]),
                    )]),
                ),
                (u(5), map(vec![(t("up"), Bool(true))])),
            ])
        }

        #[test]
        fn the_three_maps_round_trip_and_every_prefix_is_refused() {
            for v in [get_info(), make_credential(), get_assertion()] {
                round_trip(&v);
            }
        }

        #[test]
        fn a_known_encoding_is_what_the_encoder_makes() {
            // {1: ["FIDO_2_0"], 4: {"rk": true}}
            let v = map(vec![
                (u(1), Array(vec![t("FIDO_2_0")])),
                (u(4), map(vec![(t("rk"), Bool(true))])),
            ]);
            let hex = [
                0xa2, 0x01, 0x81, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'0', 0x04, 0xa1, 0x62, b'r', b'k',
                0xf5,
            ];
            assert_eq!(round_trip(&v), hex);
            // the shortest form of each size of integer, and the negative ones
            for (n, hex) in [
                (23u64, &[0x17][..]),
                (24, &[0x18, 24]),
                (255, &[0x18, 255]),
                (256, &[0x19, 1, 0]),
                (65536, &[0x1a, 0, 1, 0, 0]),
                (1 << 32, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
            ] {
                assert_eq!(round_trip(&u(n)), hex);
            }
            assert_eq!(round_trip(&Value::int(-1)), [0x20]);
            assert_eq!(round_trip(&Value::int(-7)), [0x26]);
            assert_eq!(round_trip(&Value::int(-25)), [0x38, 24]);
            assert_eq!(
                round_trip(&Neg(u64::MAX)),
                [0x3b, 255, 255, 255, 255, 255, 255, 255, 255]
            );
            assert_eq!(Value::int(i64::MIN), Neg(i64::MAX as u64));
        }

        #[test]
        fn the_encoder_sorts_a_map_as_ctap2_does() {
            let v = map(vec![
                (Value::int(-1), u(0)),
                (t("bb"), u(0)),
                (u(3), u(0)),
                (t("a"), u(0)),
                (u(1), u(0)),
            ]);
            let Map(sorted) = decode(&encode(&v)).unwrap() else {
                panic!()
            };
            let keys: Vec<&Value> = sorted.iter().map(|(k, _)| k).collect();
            assert_eq!(keys, [&u(1), &u(3), &Value::int(-1), &t("a"), &t("bb")]);
        }

        #[test]
        fn the_encoder_sorts_by_major_type_before_length() {
            // 24 encodes in two bytes, -1 in one: the major type decides, as CTAP2 says
            let v = map(vec![(Value::int(-1), u(0)), (u(24), u(0)), (u(1), u(0))]);
            assert_eq!(encode(&v), [0xa3, 0x01, 0x00, 0x18, 24, 0x00, 0x20, 0x00]);
        }

        #[test]
        fn decode_accepts_a_longer_form_and_any_order() {
            assert_eq!(decode(&[0x18, 0x01]).unwrap(), u(1));
            let Map(m) = decode(&[0xa2, 0x03, 0x00, 0x01, 0x00]).unwrap() else {
                panic!()
            };
            assert_eq!(m[0].0, u(3));
        }

        #[test]
        fn get_finds_a_key_and_only_in_a_map() {
            let v = get_info();
            assert_eq!(v.get(&u(6)), Some(&Array(vec![u(1)])));
            assert_eq!(v.get(&u(9)), None);
            assert_eq!(u(1).get(&u(1)), None);
        }

        #[test]
        fn nesting_to_the_limit_is_read_and_one_more_is_refused() {
            let nested = |levels: usize| {
                let mut bytes = vec![0x81; levels]; // arrays of one
                bytes.push(0x00);
                bytes
            };
            assert!(decode(&nested(MAX_DEPTH)).is_ok());
            assert!(decode(&nested(MAX_DEPTH + 1)).unwrap_err().contains("deeper"));
            assert!(
                decode(&nested(5000)).is_err(),
                "and a deep one cannot exhaust the stack"
            );
            let mut maps = [0xa1, 0x00].repeat(MAX_DEPTH + 1);
            maps.push(0x00);
            assert!(decode(&maps).unwrap_err().contains("deeper"));
        }

        #[test]
        fn a_truncated_item_is_refused() {
            for bytes in [
                &[][..],
                &[0x18],
                &[0x19, 1],
                &[0x1b, 0, 0, 0],
                &[0x42, 1],
                &[0x62, b'a'],
                &[0x82, 0x01],
                &[0xa1, 0x01],
            ] {
                let e = decode(bytes).unwrap_err();
                assert!(e.contains("cut short") || e.contains("claims"), "{bytes:02x?}: {e}");
            }
        }

        #[test]
        fn a_length_larger_than_the_bytes_left_is_refused() {
            for bytes in [
                &[0x5a, 0xff, 0xff, 0xff, 0xff, 1][..],                        // 4 GB of bytes
                &[0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],       // text of 2^64-1
                &[0x9a, 0x7f, 0xff, 0xff, 0xff, 0],                            // an array of 2^31 items
                &[0xbb, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0], // a map likewise
                &[0xa1, 0x00],                                                 // a map: one entry is two items
            ] {
                assert!(
                    decode(bytes).unwrap_err().contains("claims") || decode(bytes).unwrap_err().contains("cut"),
                    "{bytes:02x?}"
                );
            }
        }

        #[test]
        fn what_the_subset_leaves_out_is_refused() {
            for (bytes, why) in [
                (&[0x9f, 0xff][..], "indefinite"),
                (&[0x5f, 0xff], "indefinite"),
                (&[0xbf, 0xff], "indefinite"),
                (&[0xc1, 0x00], "tags"),
                (&[0xf9, 0, 0], "not in the subset"), // float 16
                (&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0], "not in the subset"),
                (&[0xf6], "not in the subset"), // null
                (&[0xe0], "not in the subset"), // simple value
                (&[0x1c], "reserved"),
                (&[0x7f, 0x61, b'a', 0xff], "indefinite"),
                (&[0x62, 0xc3, 0x28], "UTF-8"),
                (&[0xa2, 0x01, 0x01, 0x01, 0x02], "twice"),
                (&[0x00, 0x00], "after"),
            ] {
                let e = decode(bytes).unwrap_err();
                assert!(e.contains(why), "{bytes:02x?}: {e}");
            }
        }

        #[test]
        fn more_than_a_message_is_refused() {
            let mut bytes = vec![0x59, 0x1e, 0x00]; // 7680 bytes of bytes
            bytes.resize(3 + 7680, 0);
            assert!(decode(&bytes).unwrap_err().contains("at most"));
        }
    }
}

/// AES-256-CBC with no padding, over the `aes` block cipher kithd already links (tpm.rs):
/// what `hmac-secret` encrypts its salts and its answer with (docs/adr-fido2.md section 1).
pub mod cbc {
    use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use zeroize::{Zeroize, Zeroizing};

    pub const BLOCK: usize = 16;

    /// `data` encrypted or decrypted under `key` and `iv`. Its length must be a whole number
    /// of blocks, and not nothing: this is not a padding scheme, and a refused length is
    /// the caller's mistake, not something to round.
    pub fn run(key: &[u8; 32], iv: &[u8; BLOCK], data: &[u8], encrypting: bool) -> Result<Vec<u8>, String> {
        if data.is_empty() || !data.len().is_multiple_of(BLOCK) {
            return Err(format!(
                "{} bytes of CBC data: whole blocks of {BLOCK} expected",
                data.len()
            ));
        }
        let aes = aes::Aes256::new(key.into());
        // the running block holds plaintext when decrypting, and the chain value too
        let mut chain = Zeroizing::new(*iv);
        let mut b = aes::Block::default();
        let mut out = Vec::with_capacity(data.len());
        for block in data.as_chunks::<BLOCK>().0 {
            if encrypting {
                for (i, byte) in b.iter_mut().enumerate() {
                    *byte = block[i] ^ chain[i];
                }
                aes.encrypt_block(&mut b);
                chain.copy_from_slice(&b);
                out.extend_from_slice(&b);
            } else {
                b.copy_from_slice(block);
                aes.decrypt_block(&mut b);
                for (byte, c) in b.iter_mut().zip(chain.iter()) {
                    *byte ^= c;
                }
                chain.copy_from_slice(block);
                out.extend_from_slice(&b);
            }
        }
        b[..].zeroize();
        Ok(out)
    }

    #[cfg(test)]
    mod tests {
        use super::super::hex;
        use super::*;

        fn both(key: &str, iv: &str, plain: &str, cipher: &str) {
            let (key, iv): ([u8; 32], [u8; 16]) = (hex(key).try_into().unwrap(), hex(iv).try_into().unwrap());
            assert_eq!(run(&key, &iv, &hex(plain), true).unwrap(), hex(cipher), "encrypting");
            assert_eq!(run(&key, &iv, &hex(cipher), false).unwrap(), hex(plain), "decrypting");
        }

        /// NIST SP 800-38A, F.2.5 (CBC-AES256.Encrypt) and F.2.6 (CBC-AES256.Decrypt): four
        /// chained blocks under a chosen IV.
        #[test]
        fn sp_800_38a_cbc_aes256_both_ways() {
            both(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172a\
                 ae2d8a571e03ac9c9eb76fac45af8e51\
                 30c81c46a35ce411e5fbc1191a0a52ef\
                 f69f2445df4f9b17ad2b417be66c3710",
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
                 9cfc4e967edb808d679f777bc6702c7d\
                 39f23369a9d9bacfa530e26304231461\
                 b2eb05e2c39be9fcda6c19078c6a9d1b",
            );
        }

        /// NIST AESAVS, CBC GFSbox known answers for a 256-bit key: a zero key and a zero
        /// IV, which is what `hmac-secret` uses.
        #[test]
        fn aesavs_cbc_gfsbox_256_zero_key_and_iv_both_ways() {
            let zero = "0".repeat(64);
            let iv = "0".repeat(32);
            both(
                &zero,
                &iv,
                "014730f80ac625fe84f026c60bfd547d",
                "5c9d844ed46f9885085e5d6a4f94c7d7",
            );
            both(
                &zero,
                &iv,
                "0b24af36193ce4665f2825d7b4749c98",
                "a9ff75bd7cf6613d3731c77c3b6d0c04",
            );
            both(
                &zero,
                &iv,
                "761c1fe41a18acf20d241650611d90f1",
                "623a52fcea5d443e48d9181ab32c7421",
            );
            both(
                &zero,
                &iv,
                "8a560769d605868ad80d819bdba03771",
                "38f2c7ae10612415d27ca190d27da8b4",
            );
            both(
                &zero,
                &iv,
                "91fbef2d15a97816060bee1feaa49afe",
                "1bc704f1bce135ceb810341b216d7abe",
            );
        }

        #[test]
        fn a_length_that_is_not_whole_blocks_is_refused_either_way() {
            for len in [0, 1, 15, 17, 33] {
                for encrypting in [true, false] {
                    assert!(run(&[0; 32], &[0; 16], &vec![0; len], encrypting).is_err(), "len {len}");
                }
            }
        }

        #[test]
        fn a_changed_iv_or_key_changes_the_answer_and_never_decrypts_back() {
            let data = [7u8; 32];
            let c = run(&[1; 32], &[2; 16], &data, true).unwrap();
            assert_ne!(c, run(&[1; 32], &[3; 16], &data, true).unwrap());
            assert_ne!(c, run(&[9; 32], &[2; 16], &data, true).unwrap());
            assert_ne!(run(&[1; 32], &[3; 16], &c, false).unwrap(), data);
        }
    }
}

/// PIN protocol 1 for `hmac-secret` (docs/adr-fido2.md section 1): an ECDH P-256 agreement
/// with the key's agreement key, the shared secret as SHA-256 of the x coordinate, a zero IV,
/// and the first 16 bytes of an HMAC-SHA-256 as the salt's authentication. The key's agreement
/// key is untrusted bytes: it is checked before ring sees it, and ring checks the point.
/// Protocol 2 (a 64-byte secret, a random IV) is not here: the ADR requires it before a release.
pub mod hmac {
    use super::{
        cbc,
        cbor::{Value, uint},
    };
    use ring::{agreement, digest, hmac as ring_hmac, rand};
    use zeroize::Zeroizing;

    /// A salt, and so the secret it gives, is 32 bytes (one salt of the two `hmac-secret` takes).
    pub const SALT: usize = 32;

    /// The protocol 1 key from the x coordinate of the ECDH point.
    pub fn derive(x: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(digest::digest(&digest::SHA256, x).as_ref());
        key
    }

    /// The first 16 bytes of the HMAC-SHA-256 of `data`.
    pub fn mac16(key: &[u8], data: &[u8]) -> [u8; 16] {
        let tag = ring_hmac::sign(&ring_hmac::Key::new(ring_hmac::HMAC_SHA256, key), data);
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag.as_ref()[..16]);
        out
    }

    /// A COSE_Key for an ECDH P-256 public key (kty 2, alg -25, crv 1).
    pub(crate) fn cose(x: &[u8], y: &[u8]) -> Value {
        Value::Map(vec![
            (uint(1), uint(2)),
            (uint(3), Value::int(-25)),
            (Value::int(-1), uint(1)),
            (Value::int(-2), Value::Bytes(x.to_vec())),
            (Value::int(-3), Value::Bytes(y.to_vec())),
        ])
    }

    /// The uncompressed point (0x04, x, y) of a COSE key that is P-256 and nothing else.
    pub(crate) fn point(key: &Value) -> Result<[u8; 65], String> {
        if key.get(&uint(1)) != Some(&uint(2)) {
            return Err("the key's agreement key is not an EC2 key".into());
        }
        if key.get(&Value::int(-1)) != Some(&uint(1)) {
            return Err("the key's agreement key is not on P-256".into());
        }
        if key.get(&uint(3)).is_some_and(|alg| *alg != Value::int(-25)) {
            return Err("the key's agreement key is not for ECDH-ES (-25)".into());
        }
        let mut out = [0u8; 65];
        out[0] = 4;
        for (n, at) in [(-2, 1), (-3, 33)] {
            match key.get(&Value::int(n)) {
                Some(Value::Bytes(b)) if b.len() == 32 => out[at..at + 32].copy_from_slice(b),
                _ => return Err("the key's agreement key has no 32-byte coordinate".into()),
            }
        }
        Ok(out)
    }

    /// An agreement made with a key's agreement key: the shared secret, and our public key
    /// to send with it. The private half is gone once the secret is derived.
    pub struct Session {
        secret: Zeroizing<[u8; 32]>,
        key: Value,
    }

    impl Session {
        pub fn agree(peer: &Value) -> Result<Session, String> {
            let peer = point(peer)?;
            let rng = rand::SystemRandom::new();
            let mine = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
                .map_err(|_| "no random bytes for the key agreement")?;
            let public = mine
                .compute_public_key()
                .map_err(|_| "no public key for the key agreement")?;
            let public = public.as_ref();
            if public.len() != 65 {
                return Err("an agreement key of an unexpected size".into());
            }
            let secret = agreement::agree_ephemeral(
                mine,
                &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer[..]),
                derive,
            )
            .map_err(|_| "the key's agreement key is not a point on P-256")?;
            Ok(Session {
                secret,
                key: cose(&public[1..33], &public[33..]),
            })
        }

        /// The `hmac-secret` input of getAssertion for `salt`: our key (1), the salt
        /// encrypted (2) and its authentication (3).
        pub fn request(&self, salt: &[u8; SALT]) -> Result<Value, String> {
            let enc = cbc::run(&self.secret, &[0; cbc::BLOCK], salt, true)?;
            let auth = mac16(&self.secret[..], &enc);
            Ok(Value::Map(vec![
                (uint(1), self.key.clone()),
                (uint(2), Value::Bytes(enc)),
                (uint(3), Value::Bytes(auth.to_vec())),
            ]))
        }

        /// The secret out of the encrypted answer in the assertion's extensions.
        pub fn reply(&self, enc: &[u8]) -> Result<Zeroizing<[u8; SALT]>, String> {
            if enc.len() != SALT {
                return Err(format!("an hmac-secret answer of {} bytes: {SALT} expected", enc.len()));
            }
            let plain = Zeroizing::new(cbc::run(&self.secret, &[0; cbc::BLOCK], enc, false)?);
            let mut out = Zeroizing::new([0u8; SALT]);
            out.copy_from_slice(&plain);
            Ok(out)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::hex;
        use super::*;

        /// The P-256 generator, a point that is on the curve.
        const GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        const GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

        /// What a key does with our public key: its own agreement key, then the secret.
        fn key_side() -> (Value, impl FnOnce(&Value) -> Zeroizing<[u8; 32]>) {
            let rng = rand::SystemRandom::new();
            let k = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
            let p = k.compute_public_key().unwrap();
            let theirs = cose(&p.as_ref()[1..33], &p.as_ref()[33..]);
            (theirs, move |ours: &Value| {
                let ours = point(ours).unwrap();
                agreement::agree_ephemeral(
                    k,
                    &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &ours[..]),
                    derive,
                )
                .unwrap()
            })
        }

        #[test]
        fn the_shared_secret_is_sha256_of_the_x_coordinate() {
            // sha256sum of the bytes 00 01 .. 1f
            let x: Vec<u8> = (0..32).collect();
            assert_eq!(
                derive(&x)[..],
                hex("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd")[..]
            );
        }

        /// RFC 4231, test cases 1 and 2 (HMAC-SHA-256), cut to the 16 bytes protocol 1 keeps.
        #[test]
        fn the_salt_authentication_is_the_first_16_bytes_of_hmac_sha256() {
            assert_eq!(
                mac16(&[0x0b; 20], b"Hi There"),
                hex("b0344c61d8db38535ca8afceaf0bf12b")[..]
            );
            assert_eq!(
                mac16(b"Jefe", b"what do ya want for nothing?"),
                hex("5bdcc146bf60754e6a042426089575c7")[..]
            );
        }

        #[test]
        fn both_sides_of_the_agreement_reach_the_same_secret() {
            let (gx, gy) = (hex(GX), hex(GY));
            // the generator is a good peer; its agreement works and gives our key to send
            let s = Session::agree(&cose(&gx, &gy)).unwrap();
            let p = point(&s.key).unwrap();
            assert_eq!(p[0], 4);
            // a key with an agreement key of its own: both ends derive one secret
            let (theirs, key_secret) = key_side();
            let s = Session::agree(&theirs).unwrap();
            assert_eq!(s.secret[..], key_secret(&s.key)[..]);
        }

        /// Limit: the request and the reply are checked against this module's own reading of
        /// CTAP2.1 (and the cipher, derive and HMAC against NIST and RFC vectors), so a
        /// misreading shared by both sides would pass. A trial with a real key is the
        /// independent check. No slice of docs/adr-fido2.md section 6 runs one (T-0955's
        /// stand-in is ours too), so it stays a trial to make by hand before release.
        #[test]
        fn the_request_carries_our_key_the_encrypted_salt_and_its_authentication() {
            let (gx, gy) = (hex(GX), hex(GY));
            let s = Session::agree(&cose(&gx, &gy)).unwrap();
            let salt = [0x5a; SALT];
            let req = s.request(&salt).unwrap();
            let Some(Value::Bytes(enc)) = req.get(&uint(2)) else {
                panic!("no salt")
            };
            assert_eq!(enc.len(), 32);
            assert_ne!(enc[..], salt[..], "the salt does not travel plain");
            assert_eq!(cbc::run(&s.secret, &[0; 16], enc, false).unwrap(), salt);
            assert_eq!(
                req.get(&uint(3)),
                Some(&Value::Bytes(mac16(&s.secret[..], enc).to_vec()))
            );
            assert_eq!(req.get(&uint(1)), Some(&s.key));
            // the answer is the secret, encrypted the same way, and comes back as it was
            let secret = [0x77u8; 32];
            let sealed = cbc::run(&s.secret, &[0; 16], &secret, true).unwrap();
            assert_eq!(s.reply(&sealed).unwrap()[..], secret[..]);
        }

        #[test]
        fn an_answer_of_the_wrong_size_is_refused() {
            let s = Session::agree(&cose(&hex(GX), &hex(GY))).unwrap();
            for len in [0, 15, 16, 31, 33, 48, 64] {
                assert!(s.reply(&vec![1; len]).unwrap_err().contains("32 expected"), "len {len}");
            }
        }

        #[test]
        fn an_agreement_key_that_is_not_p256_or_not_a_point_is_refused() {
            let (gx, gy) = (hex(GX), hex(GY));
            let good = cose(&gx, &gy);
            assert!(Session::agree(&good).is_ok());
            let with = |n: i64, v: Value| {
                let Value::Map(m) = cose(&gx, &gy) else { panic!() };
                Value::Map(
                    m.into_iter()
                        .map(|(k, old)| if k == Value::int(n) { (k, v.clone()) } else { (k, old) })
                        .collect(),
                )
            };
            let mut off_curve = gy.clone();
            off_curve[31] ^= 1;
            for (bad, why) in [
                (with(1, uint(1)), "EC2"),
                (with(-1, uint(2)), "P-256"),
                (with(3, Value::int(-7)), "ECDH-ES"),
                (with(-2, Value::Bytes(gx[..31].to_vec())), "coordinate"),
                (with(-3, Value::Bytes([gy.clone(), vec![0]].concat())), "coordinate"),
                (with(-3, Value::text("y")), "coordinate"),
                (with(-2, Value::Bytes(vec![0; 32])), "point"),
                (with(-3, Value::Bytes(off_curve)), "point"),
                (Value::Map(vec![]), "EC2"),
                (uint(1), "EC2"),
            ] {
                assert!(Session::agree(&bad).err().unwrap().contains(why), "{bad:?}");
            }
        }
    }
}

/// The two CTAP2 calls the console needs, over a [`frame::Device`] with a channel from
/// [`frame::init`]: `makeCredential` with `hmac-secret` to enrol a key, and `getAssertion`
/// with a salt to get its 32-byte secret (docs/adr-fido2.md sections 1, 4 and 6). A key that
/// refuses answers with its status named (`CREDENTIAL_EXCLUDED`, `PIN_REQUIRED`, ...).
/// The assertion's signature is not checked: a key that lies gives a wrong secret, and
/// the state's key does not unwrap under it.
pub mod flow {
    use super::cbor::{self, Value, uint};
    use super::frame::{self, Device};
    use super::hmac::{self, Session};
    use ring::{digest, rand::SecureRandom, rand::SystemRandom};
    use zeroize::Zeroizing;

    /// The relying party every kith credential is made for (docs/adr-fido2.md section 4).
    pub const RP_ID: &str = "kith.local";
    const MAKE_CREDENTIAL: u8 = 0x01;
    const GET_ASSERTION: u8 = 0x02;
    const GET_INFO: u8 = 0x04;
    const CLIENT_PIN: u8 = 0x06;
    /// authData flags: user present, attested credential data, extension data.
    const UP: u8 = 0x01;
    const AT: u8 = 0x40;
    const ED: u8 = 0x80;
    /// CTAP2's limit on a credential id.
    const MAX_CREDENTIAL_ID: usize = 1023;
    /// rpIdHash, flags, signature counter.
    const AUTH_DATA_HEAD: usize = 37;

    fn call(dev: &mut dyn Device, cid: u32, cmd: u8, params: Option<&Value>) -> Result<Value, String> {
        let mut request = vec![cmd];
        if let Some(p) = params {
            request.extend(cbor::encode(p));
        }
        cbor::decode(&frame::cbor_request(dev, cid, &request)?)
    }

    fn random_32() -> Result<[u8; 32], String> {
        let mut out = [0u8; 32];
        SystemRandom::new().fill(&mut out).map_err(|_| "no random bytes")?;
        Ok(out)
    }

    fn descriptor(id: &[u8]) -> Value {
        Value::Map(vec![
            (Value::text("id"), Value::Bytes(id.to_vec())),
            (Value::text("type"), Value::text("public-key")),
        ])
    }

    /// The key must have `hmac-secret` and PIN protocol 1: this client speaks nothing else.
    pub fn check_key(dev: &mut dyn Device, cid: u32) -> Result<(), String> {
        let info = call(dev, cid, GET_INFO, None)?;
        match info.get(&uint(2)) {
            Some(Value::Array(ext)) if ext.contains(&Value::text("hmac-secret")) => {}
            _ => return Err("the key does not list the hmac-secret extension".into()),
        }
        match info.get(&uint(6)) {
            Some(Value::Array(p)) if p.contains(&uint(1)) => Ok(()),
            _ => Err("the key does not list pinUvAuthProtocols 1: protocol 2 alone is not supported yet".into()),
        }
    }

    fn key_agreement(dev: &mut dyn Device, cid: u32) -> Result<Session, String> {
        let request = Value::Map(vec![(uint(1), uint(1)), (uint(2), uint(2))]); // protocol 1, getKeyAgreement
        let answer = call(dev, cid, CLIENT_PIN, Some(&request))?;
        Session::agree(answer.get(&uint(1)).ok_or("the key sent no agreement key")?)
    }

    /// authData after its head, once its relying party hash and the `need`ed flags check out.
    fn auth_data<'a>(answer: &'a Value, rp_id: &str, need: u8) -> Result<&'a [u8], String> {
        let Some(Value::Bytes(auth)) = answer.get(&uint(2)) else {
            return Err("the key's answer has no authenticator data".into());
        };
        if auth.len() < AUTH_DATA_HEAD {
            return Err(format!("authenticator data of {} bytes is cut short", auth.len()));
        }
        if auth[..32] != *digest::digest(&digest::SHA256, rp_id.as_bytes()).as_ref() {
            return Err("the key's answer is for another relying party".into());
        }
        if auth[32] & need != need {
            return Err(format!("the key's flags {:#04x} lack {need:#04x}", auth[32]));
        }
        Ok(&auth[AUTH_DATA_HEAD..])
    }

    /// The credential id in the attested data of a makeCredential answer, once its
    /// extensions say `hmac-secret` was made.
    fn credential_id(answer: &Value, rp_id: &str) -> Result<Vec<u8>, String> {
        let rest = auth_data(answer, rp_id, UP | AT | ED)?;
        let short = || "the attested credential data is cut short".to_string();
        let (id_len, rest) = rest
            .get(16..)
            .and_then(|r| r.split_first_chunk::<2>())
            .ok_or_else(short)?;
        let id_len = usize::from(u16::from_be_bytes(*id_len));
        if id_len == 0 || id_len > MAX_CREDENTIAL_ID {
            return Err(format!("a credential id of {id_len} bytes"));
        }
        let (id, rest) = rest.split_at_checked(id_len).ok_or_else(short)?;
        let (_public_key, rest) = cbor::decode_prefix(rest)?;
        let extensions = cbor::decode(rest)?;
        if extensions.get(&Value::text("hmac-secret")) != Some(&Value::Bool(true)) {
            return Err("the key made the credential without hmac-secret".into());
        }
        Ok(id.to_vec())
    }

    /// Enrol: a credential for `rp_id` with `hmac-secret`, one touch, and its id. A key
    /// that has one of `exclude` answers CREDENTIAL_EXCLUDED, and one with a PIN set
    /// answers PIN_REQUIRED.
    pub fn make_credential(
        dev: &mut dyn Device,
        cid: u32,
        rp_id: &str,
        exclude: &[Vec<u8>],
    ) -> Result<Vec<u8>, String> {
        if let Some(bad) = exclude.iter().find(|id| id.is_empty() || id.len() > MAX_CREDENTIAL_ID) {
            return Err(format!("an excluded credential id of {} bytes", bad.len()));
        }
        check_key(dev, cid)?;
        let mut request = vec![
            (uint(1), Value::Bytes(random_32()?.to_vec())),
            (uint(2), Value::Map(vec![(Value::text("id"), Value::text(rp_id))])),
            (
                uint(3),
                Value::Map(vec![
                    (Value::text("id"), Value::Bytes(b"kith".to_vec())),
                    (Value::text("name"), Value::text("kith")),
                ]),
            ),
            (
                uint(4),
                Value::Array(vec![Value::Map(vec![
                    (Value::text("alg"), Value::int(-7)),
                    (Value::text("type"), Value::text("public-key")),
                ])]),
            ),
            (
                uint(6),
                Value::Map(vec![(Value::text("hmac-secret"), Value::Bool(true))]),
            ),
            (uint(7), Value::Map(vec![(Value::text("rk"), Value::Bool(false))])),
        ];
        if !exclude.is_empty() {
            request.push((uint(5), Value::Array(exclude.iter().map(|id| descriptor(id)).collect())));
        }
        credential_id(&call(dev, cid, MAKE_CREDENTIAL, Some(&Value::Map(request)))?, rp_id)
    }

    /// The key's `hmac-secret` for `salt` under `credential`: one touch.
    pub fn get_assertion(
        dev: &mut dyn Device,
        cid: u32,
        rp_id: &str,
        credential: &[u8],
        salt: &[u8; hmac::SALT],
    ) -> Result<Zeroizing<[u8; hmac::SALT]>, String> {
        if credential.is_empty() || credential.len() > MAX_CREDENTIAL_ID {
            return Err(format!("a credential id of {} bytes", credential.len()));
        }
        check_key(dev, cid)?;
        let session = key_agreement(dev, cid)?;
        let request = Value::Map(vec![
            (uint(1), Value::text(rp_id)),
            (uint(2), Value::Bytes(random_32()?.to_vec())),
            (uint(3), Value::Array(vec![descriptor(credential)])),
            (
                uint(4),
                Value::Map(vec![(Value::text("hmac-secret"), session.request(salt)?)]),
            ),
            (uint(5), Value::Map(vec![(Value::text("up"), Value::Bool(true))])),
        ]);
        let answer = call(dev, cid, GET_ASSERTION, Some(&request))?;
        let extensions = cbor::decode(auth_data(&answer, rp_id, UP | ED)?)?;
        match extensions.get(&Value::text("hmac-secret")) {
            Some(Value::Bytes(sealed)) => session.reply(sealed),
            _ => Err("the key's assertion has no hmac-secret".into()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::fido2_test::auth::{Fault, Key};

        const RP: &str = "kith.local";

        fn open(key: &mut Key) -> u32 {
            frame::init(key, *b"01234567").unwrap().cid
        }

        #[test]
        fn make_credential_then_get_assertion_gives_the_32_byte_secret() {
            let mut key = Key::new();
            let cid = open(&mut key);
            let id = make_credential(&mut key, cid, RP, &[]).unwrap();
            assert_eq!(id, key.creds[0]);
            let salt = [0x42u8; 32];
            let secret = get_assertion(&mut key, cid, RP, &id, &salt).unwrap();
            assert_eq!(secret.len(), 32);
            assert_eq!(secret[..], key.expected(&id, &salt)[..], "what the key's own seed says");
            // the same salt again is the same secret, another salt another
            assert_eq!(get_assertion(&mut key, cid, RP, &id, &salt).unwrap()[..], secret[..]);
            let other = get_assertion(&mut key, cid, RP, &id, &[0x43; 32]).unwrap();
            assert_ne!(other[..], secret[..]);
            assert_eq!(other[..], key.expected(&id, &[0x43; 32])[..]);
            // the salt never crossed in the clear
            for (_, req) in &key.seen {
                assert!(
                    !format!("{req:?}").contains("66, 66, 66, 66"),
                    "salt bytes in a request"
                );
            }
        }

        #[test]
        fn a_second_key_has_another_secret_and_the_same_key_is_excluded() {
            let (mut a, mut b) = (Key::new(), Key::new());
            b.seed = 2;
            let (ca, cb) = (open(&mut a), open(&mut b));
            let ida = make_credential(&mut a, ca, RP, &[]).unwrap();
            let idb = make_credential(&mut b, cb, RP, std::slice::from_ref(&ida)).unwrap();
            let salt = [9u8; 32];
            let sa = get_assertion(&mut a, ca, RP, &ida, &salt).unwrap();
            let sb = get_assertion(&mut b, cb, RP, &idb, &salt).unwrap();
            assert_ne!(sa[..], sb[..]);
            // the first key again, with its own credential excluded: the key says so by name
            let e = make_credential(&mut a, ca, RP, &[ida]).unwrap_err();
            assert!(e.contains(frame::CREDENTIAL_EXCLUDED), "{e}");
            assert_eq!(a.creds.len(), 1, "and made nothing");
        }

        #[test]
        fn a_key_with_a_pin_set_says_pin_required_by_name() {
            let mut key = Key::new();
            key.pin = true;
            let cid = open(&mut key);
            let e = make_credential(&mut key, cid, RP, &[]).unwrap_err();
            assert!(e.contains(frame::PIN_REQUIRED), "{e}");
            assert!(key.creds.is_empty());
        }

        #[test]
        fn a_credential_the_key_does_not_have_is_named() {
            let mut key = Key::new();
            let cid = open(&mut key);
            let e = get_assertion(&mut key, cid, RP, &[1; 40], &[0; 32]).unwrap_err();
            assert!(e.contains("NO_CREDENTIALS"), "{e}");
        }

        #[test]
        fn a_key_without_hmac_secret_or_protocol_1_is_refused_before_anything_is_made() {
            let mut key = Key::new();
            key.extensions = vec!["credProtect"];
            let cid = open(&mut key);
            assert!(
                make_credential(&mut key, cid, RP, &[])
                    .unwrap_err()
                    .contains("hmac-secret")
            );
            let mut key = Key::new();
            key.protocols = vec![2];
            let cid = open(&mut key);
            assert!(
                make_credential(&mut key, cid, RP, &[])
                    .unwrap_err()
                    .contains("pinUvAuthProtocols")
            );
            assert!(get_assertion(&mut key, cid, RP, &[1; 40], &[0; 32]).is_err());
            assert!(key.creds.is_empty());
            assert!(
                key.seen.iter().all(|(cmd, _)| *cmd == GET_INFO),
                "only getInfo was asked"
            );
        }

        #[test]
        fn a_credential_made_without_hmac_secret_is_refused() {
            let mut key = Key::new();
            key.grant_hmac = false;
            let cid = open(&mut key);
            assert!(
                make_credential(&mut key, cid, RP, &[])
                    .unwrap_err()
                    .contains("without hmac-secret")
            );
        }

        #[test]
        fn a_credential_id_out_of_bounds_is_refused_before_the_key_is_asked() {
            let mut key = Key::new();
            let cid = open(&mut key);
            for len in [0, MAX_CREDENTIAL_ID + 1] {
                assert!(get_assertion(&mut key, cid, RP, &vec![1; len], &[0; 32]).is_err());
            }
            assert!(key.seen.is_empty());
        }

        #[test]
        fn an_excluded_id_out_of_bounds_is_refused_before_the_key_is_asked() {
            let mut key = Key::new();
            let cid = open(&mut key);
            for len in [0, MAX_CREDENTIAL_ID + 1] {
                let e = make_credential(&mut key, cid, RP, &[vec![1; 40], vec![1; len]]).unwrap_err();
                assert!(e.contains("excluded credential id"), "{e}");
            }
            assert!(key.seen.is_empty());
            // the largest id is still sent
            assert!(make_credential(&mut key, cid, RP, &[vec![1; MAX_CREDENTIAL_ID]]).is_ok());
        }

        #[test]
        fn a_wrong_assertion_answer_is_refused_whichever_part_is_wrong() {
            for (fault, says) in [
                (Fault::NoExtensions, ""),
                (Fault::NoHmacSecret, "no hmac-secret"),
                (Fault::HmacSecretNotBytes, "no hmac-secret"),
                (Fault::WrongRp, "another relying party"),
                (Fault::NoEdFlag, "lack"),
            ] {
                let mut key = Key::new();
                let cid = open(&mut key);
                let id = make_credential(&mut key, cid, RP, &[]).unwrap();
                key.fault = fault;
                let e = get_assertion(&mut key, cid, RP, &id, &[7; 32]).unwrap_err();
                assert!(e.contains(says), "{e}");
            }
            // and with no fault the same key answers
            let mut key = Key::new();
            let cid = open(&mut key);
            let id = make_credential(&mut key, cid, RP, &[]).unwrap();
            assert!(get_assertion(&mut key, cid, RP, &id, &[7; 32]).is_ok());
        }

        fn attested(rp: &str, flags: u8, tail: &[u8]) -> Value {
            let mut auth = digest::digest(&digest::SHA256, rp.as_bytes()).as_ref().to_vec();
            auth.push(flags);
            auth.extend_from_slice(&[0; 4]);
            auth.extend_from_slice(tail);
            Value::Map(vec![(uint(2), Value::Bytes(auth))])
        }

        /// aaguid, a credential id of 3, a one-item key, `{"hmac-secret": true}`.
        fn good_tail() -> Vec<u8> {
            let mut t = vec![0u8; 16];
            t.extend_from_slice(&[0, 3, 7, 8, 9]);
            t.push(0x01); // the public key: 1
            t.extend_from_slice(&cbor::encode(&Value::Map(vec![(
                Value::text("hmac-secret"),
                Value::Bool(true),
            )])));
            t
        }

        #[test]
        fn attested_data_is_read_whole_and_every_cut_of_it_is_refused() {
            let tail = good_tail();
            assert_eq!(credential_id(&attested(RP, 0xc1, &tail), RP).unwrap(), [7, 8, 9]);
            for cut in 0..tail.len() {
                assert!(
                    credential_id(&attested(RP, 0xc1, &tail[..cut]), RP).is_err(),
                    "cut {cut}"
                );
            }
            let mut more = tail.clone();
            more.push(0);
            assert!(credential_id(&attested(RP, 0xc1, &more), RP).is_err(), "trailing bytes");
            assert!(
                credential_id(&attested("elsewhere", 0xc1, &tail), RP)
                    .unwrap_err()
                    .contains("another relying party")
            );
            for flags in [0x00, 0x41, 0x81, 0xc0, 0xc0 | 0x04] {
                if flags & 0xc1 != 0xc1 {
                    assert!(
                        credential_id(&attested(RP, flags, &tail), RP)
                            .unwrap_err()
                            .contains("lack")
                    );
                }
            }
            let mut zero_id = tail.clone();
            zero_id[17] = 0;
            assert!(
                credential_id(&attested(RP, 0xc1, &zero_id), RP)
                    .unwrap_err()
                    .contains("credential id")
            );
            let mut huge = tail;
            huge[16..18].copy_from_slice(&1024u16.to_be_bytes());
            assert!(
                credential_id(&attested(RP, 0xc1, &huge), RP)
                    .unwrap_err()
                    .contains("1024")
            );
            assert!(credential_id(&Value::Map(vec![]), RP).is_err());
            assert!(credential_id(&attested(RP, 0xc1, &[]), RP).is_err());
        }
    }
}

/// A security key on `/dev/hidraw*`, plain file I/O (docs/adr-fido2.md section 1): the
/// devices whose report descriptor opens with the FIDO usage page, each handed out once
/// while it stays plugged in.
pub mod hidraw {
    use super::frame::{Device, REPORT};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    /// How long a read waits for a report: a key waiting for a touch sends a keep-alive
    /// every 100 ms, so this is the bound on a key that says nothing (see [`Device`]).
    const READ_WAIT: u16 = 1000;
    /// A FIDO device's report descriptor begins `Usage Page (0xF1D0)`.
    const FIDO_PAGE: [u8; 3] = [0x06, 0xd0, 0xf1];

    pub struct Hid(File);

    impl Device for Hid {
        fn write(&mut self, report: &[u8; REPORT]) -> io::Result<()> {
            // (hidraw wants the report id first: 0 for a device that has none.)
            let mut out = [0u8; REPORT + 1];
            out[1..].copy_from_slice(report);
            self.0.write_all(&out)
        }

        fn read(&mut self) -> io::Result<Vec<u8>> {
            let mut ready = [PollFd::new(self.0.as_fd(), PollFlags::POLLIN)];
            if poll(&mut ready, PollTimeout::from(READ_WAIT)).map_err(io::Error::from)? == 0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let mut report = [0u8; REPORT];
            let got = self.0.read(&mut report)?;
            Ok(report[..got].to_vec())
        }
    }

    /// Whether `class`'s device `name` has a FIDO report descriptor.
    fn is_fido(class: &Path, name: &str) -> bool {
        let descriptor = std::fs::read(class.join(name).join("device/report_descriptor"));
        descriptor.is_ok_and(|descriptor| descriptor.starts_with(&FIDO_PAGE))
    }

    /// `dev/name`, opened, if the file opened is the device `class/name` names (its number
    /// is read off the open file, so a node swapped for another is refused) and that is
    /// still a FIDO device: nothing is written to what is not.
    fn open(class: &Path, dev: &Path, name: &str) -> io::Result<File> {
        let file = File::options().read(true).write(true).open(dev.join(name))?;
        let named = std::fs::read_to_string(class.join(name).join("dev"))?;
        let number = named.trim().split_once(':').and_then(|(major, minor)| {
            let (major, minor): (u64, u64) = (major.parse().ok()?, minor.parse().ok()?);
            Some(nix::sys::stat::makedev(major, minor))
        });
        if number != Some(file.metadata()?.rdev()) {
            return Err(io::Error::other("it is not the device the class names"));
        }
        if !is_fido(class, name) {
            return Err(io::Error::other("it is no longer a FIDO device"));
        }
        Ok(file)
    }

    /// The keys in `class` (`/sys/class/hidraw`) not in `tried`, by name, opened from `dev`
    /// (`/dev`), and `tried` as it is now: the names still plugged in. A missing `class` is
    /// no keys. One that cannot be opened is said, and is not tried again until it is
    /// unplugged (or its name is taken out of `tried`).
    pub fn plugged_in(class: &Path, dev: &Path, tried: &mut HashSet<String>) -> Vec<(String, Hid)> {
        let names: HashSet<String> = std::fs::read_dir(class)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| is_fido(class, name))
            .collect();
        tried.retain(|name| names.contains(name));
        let mut new: Vec<_> = names.into_iter().filter(|name| !tried.contains(name)).collect();
        new.sort();
        let mut keys = Vec::new();
        for name in new {
            tried.insert(name.clone());
            match open(class, dev, &name) {
                Ok(file) => keys.push((name, Hid(file))),
                Err(why) => eprintln!("kithd: init: the security key {name} cannot be opened: {why}"),
            }
        }
        keys
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_fido_device_is_handed_out_once_and_again_when_plugged_in_again() {
            let root = std::env::temp_dir().join(format!("kith-hidraw-{}", std::process::id()));
            let (class, dev) = (root.join("class"), root.join("dev"));
            let _ = std::fs::remove_dir_all(&root);
            let mut tried = HashSet::new();
            assert!(plugged_in(&class, &dev, &mut tried).is_empty(), "no class: no keys");
            std::fs::create_dir_all(&dev).unwrap();
            // (Every node here is /dev/null, the character device 1:3.)
            let add = |name: &str, descriptor: &[u8], number: &str| {
                std::fs::create_dir_all(class.join(name).join("device")).unwrap();
                std::fs::write(class.join(name).join("device/report_descriptor"), descriptor).unwrap();
                std::fs::write(class.join(name).join("dev"), number).unwrap();
                let _ = std::fs::remove_file(dev.join(name));
                std::os::unix::fs::symlink("/dev/null", dev.join(name)).unwrap();
            };
            add("hidraw0", &[0x05, 0x01, 0x09, 0x06], "1:3\n"); // a keyboard
            add("hidraw1", &[0x06, 0xd0, 0xf1, 0x09, 0x01], "1:3\n");
            let first = plugged_in(&class, &dev, &mut tried);
            assert_eq!(
                first.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(),
                ["hidraw1"]
            );
            assert!(plugged_in(&class, &dev, &mut tried).is_empty(), "handed out once");
            std::fs::remove_dir_all(class.join("hidraw1")).unwrap();
            assert!(plugged_in(&class, &dev, &mut tried).is_empty());
            add("hidraw1", &[0x06, 0xd0, 0xf1], "1:3");
            assert_eq!(plugged_in(&class, &dev, &mut tried).len(), 1, "plugged in again");
            // A node that is not the device the class names is not opened for a key, nor is
            // one whose number cannot be read.
            add("hidraw2", &[0x06, 0xd0, 0xf1], "1:4");
            add("hidraw3", &[0x06, 0xd0, 0xf1], "one:three");
            assert!(plugged_in(&class, &dev, &mut tried).is_empty());
            std::fs::remove_dir_all(&root).unwrap();
        }
    }
}
