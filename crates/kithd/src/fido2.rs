//! The wire half of kithd's CTAP2 client (docs/adr-fido2.md, sections 1 and 6): CTAPHID
//! framing over a [`Device`] and the CBOR subset a key speaks. Everything a key sends is
//! untrusted bytes: each parser here refuses what it does not know, bounds what it reads
//! and never indexes or allocates from a length it has not checked.
//!
//! The device is a trait so a test can use a pipe; the hidraw one comes with the client.

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
            Some((status, _)) => Err(format!("the key answered status {status:#04x}")),
        }
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
        if bytes.len() > super::frame::MAX_MESSAGE {
            return Err(format!(
                "{} bytes of CBOR: at most {}",
                bytes.len(),
                super::frame::MAX_MESSAGE
            ));
        }
        let mut rest = bytes;
        let v = item(&mut rest, 0)?;
        if !rest.is_empty() {
            return Err(format!("{} bytes after the CBOR item", rest.len()));
        }
        Ok(v)
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
        fn u(n: u64) -> Value {
            Uint(n)
        }

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
