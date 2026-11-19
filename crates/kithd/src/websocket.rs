//! The WebSocket framing (RFC 6455) that kubectl exec, attach and cp speak to kithd, written here
//! with no new dependency: the accept key, a frame decoder that refuses what is malformed and bounds
//! every length before any of its body is read, and the encoder. No extension (RSV bits stay 0).
//! A client's message may come as several frames (kubectl's gorilla client splits its writes over
//! a 4 KiB buffer): the decoder hands each one over as it is, a continuation (opcode 0) as
//! [`Op::Continue`], and what reads them keeps what the first one said. kithd sends each message whole.

use base64::Engine;

/// The GUID RFC 6455 section 1.3 appends to the client's key before the SHA-1.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    /// The rest of a message that an earlier frame began.
    Continue,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) op: Op,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FrameError {
    /// The header declares more payload than the caller allows. Refused before any body is read.
    TooLong {
        len: u64,
        max: usize,
    },
    Malformed(&'static str),
}

/// The Sec-WebSocket-Accept answer to a client's Sec-WebSocket-Key, or None when the key is not
/// 16 bytes in base64.
pub(crate) fn accept_key(client_key: &str) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD.decode(client_key).ok()?;
    if raw.len() != 16 {
        return None;
    }
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{client_key}{GUID}").as_bytes(),
    );
    Some(base64::engine::general_purpose::STANDARD.encode(digest))
}

/// Decodes the first frame of `buf`: Ok(None) when it is not all here yet, else the frame and the
/// bytes it took. `from_client` is set when kithd is the server: client frames must be masked and
/// server frames must not be. A declared length over `max` is refused as soon as the header shows it.
pub(crate) fn decode(buf: &[u8], from_client: bool, max: usize) -> Result<Option<(Frame, usize)>, FrameError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (b0, b1) = (buf[0], buf[1]);
    if b0 & 0x70 != 0 {
        return Err(FrameError::Malformed("a reserved bit is set"));
    }
    let fin = b0 & 0x80 != 0;
    let op = match b0 & 0x0f {
        0 => Op::Continue,
        1 => Op::Text,
        2 => Op::Binary,
        8 => Op::Close,
        9 => Op::Ping,
        10 => Op::Pong,
        _ => return Err(FrameError::Malformed("an opcode that is not used")),
    };
    if matches!(op, Op::Close | Op::Ping | Op::Pong) && b1 & 0x7f >= 126 {
        return Err(FrameError::Malformed("a control frame over 125 bytes"));
    }
    if matches!(op, Op::Close | Op::Ping | Op::Pong) && !fin {
        return Err(FrameError::Malformed("a fragmented control frame"));
    }
    let masked = b1 & 0x80 != 0;
    if masked != from_client {
        return Err(FrameError::Malformed(if from_client {
            "a client frame is not masked"
        } else {
            "a server frame is masked"
        }));
    }
    let (len, head) = match b1 & 0x7f {
        short @ 0..=125 => (u64::from(short), 2),
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            let len = u64::from(u16::from_be_bytes([buf[2], buf[3]]));
            if len < 126 {
                return Err(FrameError::Malformed("a length that is not the shortest"));
            }
            (len, 4)
        }
        _ => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let len = u64::from_be_bytes(buf[2..10].try_into().expect("8 bytes"));
            if len >> 63 != 0 {
                return Err(FrameError::Malformed("a length with its top bit set"));
            }
            if len <= 65535 {
                return Err(FrameError::Malformed("a length that is not the shortest"));
            }
            (len, 10)
        }
    };
    // Refused on the header alone: no body is waited for or copied past the caller's limit.
    if len > max as u64 {
        return Err(FrameError::TooLong { len, max });
    }
    let body_at = head + if masked { 4 } else { 0 };
    if buf.len() < body_at || buf.len() - body_at < len as usize {
        return Ok(None);
    }
    let end = body_at + len as usize;
    let mut payload = buf[body_at..end].to_vec();
    if masked {
        let key: [u8; 4] = buf[head..head + 4].try_into().expect("4 bytes");
        apply_mask(&mut payload, key);
    }
    if op == Op::Close {
        check_close(&payload)?;
    }
    Ok(Some((Frame { op, payload }, end)))
}

fn apply_mask(payload: &mut [u8], key: [u8; 4]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }
}

/// A close body is empty, or a status code the protocol allows and a UTF-8 reason.
fn check_close(body: &[u8]) -> Result<(), FrameError> {
    match body {
        [] => Ok(()),
        [_] => Err(FrameError::Malformed("a close body of one byte")),
        [high, low, reason @ ..] => {
            let code = u16::from_be_bytes([*high, *low]);
            if !matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999) {
                return Err(FrameError::Malformed("a close code that is not allowed"));
            }
            std::str::from_utf8(reason)
                .map(|_| ())
                .map_err(|_| FrameError::Malformed("a close reason that is not UTF-8"))
        }
    }
}

/// Encodes one frame with the shortest length form. `mask` is the client's masking key, or None
/// for a server frame.
pub(crate) fn encode(op: Op, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let opcode: u8 = match op {
        Op::Continue => 0,
        Op::Text => 1,
        Op::Binary => 2,
        Op::Close => 8,
        Op::Ping => 9,
        Op::Pong => 10,
    };
    let mask_bit: u8 = if mask.is_some() { 0x80 } else { 0 };
    let mut out = vec![0x80 | opcode];
    match payload.len() {
        n if n <= 125 => out.push(mask_bit | n as u8),
        n if n <= 65535 => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            let mut body = payload.to_vec();
            apply_mask(&mut body, key);
            out.extend_from_slice(&body);
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// The payload of a close frame: the status code (big-endian), then the reason's bytes.
pub(crate) fn close_body(code: u16, reason: &str) -> Vec<u8> {
    let mut body = code.to_be_bytes().to_vec();
    body.extend_from_slice(reason.as_bytes());
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 1 << 20;
    const KEY: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

    /// True when `buf` is refused as malformed (not merely too long, not merely incomplete).
    fn refused(buf: &[u8], from_client: bool) -> bool {
        matches!(decode(buf, from_client, MAX), Err(FrameError::Malformed(_)))
    }

    #[test]
    fn websocket_accept_key_is_the_rfc_6455_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".to_string())
        );
    }

    #[test]
    fn websocket_accept_key_refuses_what_is_not_a_16_byte_key() {
        assert_eq!(accept_key("c2hvcnQ="), None, "\"short\" is 5 bytes");
        assert_eq!(accept_key("not base64!"), None);
        assert_eq!(accept_key(""), None);
    }

    #[test]
    fn websocket_masked_client_frames_round_trip_at_every_length_class() {
        for len in [0usize, 1, 125, 126, 65535, 65536] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let wire = encode(Op::Binary, &payload, Some(KEY));
            let want = Frame {
                op: Op::Binary,
                payload,
            };
            assert_eq!(decode(&wire, true, MAX), Ok(Some((want, wire.len()))), "length {len}");
        }
    }

    #[test]
    fn websocket_server_frames_round_trip_unmasked() {
        for op in [Op::Text, Op::Binary, Op::Ping, Op::Pong] {
            let wire = encode(op, b"hello", None);
            let want = Frame {
                op,
                payload: b"hello".to_vec(),
            };
            assert_eq!(decode(&wire, false, MAX), Ok(Some((want, wire.len()))), "{op:?}");
        }
    }

    #[test]
    fn websocket_masking_is_applied_on_the_wire() {
        let wire = encode(Op::Binary, b"abc", Some([1, 2, 3, 4]));
        assert_eq!(
            &wire[..6],
            &[0x82, 0x83, 1, 2, 3, 4],
            "FIN binary, mask bit, length 3, key"
        );
        assert_eq!(&wire[6..], &[b'a' ^ 1, b'b' ^ 2, b'c' ^ 3]);
    }

    #[test]
    fn websocket_lengths_use_the_shortest_form() {
        assert_eq!(encode(Op::Binary, &[0; 125], None)[1], 125);
        assert_eq!(&encode(Op::Binary, &[0; 126], None)[..4], &[0x82, 126, 0, 126]);
        assert_eq!(
            &encode(Op::Binary, &vec![0; 65536], None)[..10],
            &[0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]
        );
    }

    #[test]
    fn websocket_a_length_over_the_limit_is_refused_before_its_body_arrives() {
        // A 64-bit length of 2^40 with only the 10-byte header in hand.
        let mut head = vec![0x82, 0x80 | 127];
        head.extend((1u64 << 40).to_be_bytes());
        assert_eq!(
            decode(&head, true, MAX),
            Err(FrameError::TooLong { len: 1 << 40, max: MAX })
        );
        // A 16-bit length over a small limit, header only.
        let head = [0x82, 0x80 | 126, 0xFF, 0xFF];
        assert_eq!(
            decode(&head, true, 1024),
            Err(FrameError::TooLong { len: 65535, max: 1024 })
        );
    }

    #[test]
    fn websocket_a_length_within_the_limit_waits_for_its_body() {
        let wire = encode(Op::Binary, b"hello", Some(KEY));
        assert_eq!(decode(&wire[..wire.len() - 1], true, MAX), Ok(None));
        assert_eq!(decode(&wire[..1], true, MAX), Ok(None));
        assert_eq!(decode(&[], true, MAX), Ok(None));
        let wide = encode(Op::Binary, &vec![0; 300], Some(KEY));
        assert_eq!(decode(&wide[..3], true, MAX), Ok(None), "half of a 16-bit length");
    }

    #[test]
    fn websocket_a_length_that_is_not_the_shortest_is_refused() {
        assert!(
            refused(&[0x82, 0x80 | 126, 0, 100, 1, 2, 3, 4], true),
            "100 fits in 7 bits"
        );
        let mut long = vec![0x82, 0x80 | 127];
        long.extend(1000u64.to_be_bytes());
        long.extend(KEY);
        assert!(refused(&long, true), "1000 fits in 16 bits");
    }

    #[test]
    fn websocket_a_length_with_its_top_bit_set_is_refused() {
        let mut huge = vec![0x82, 0x80 | 127];
        huge.extend((1u64 << 63 | 1 << 20).to_be_bytes());
        assert!(refused(&huge, true));
    }

    #[test]
    fn websocket_reserved_bits_opcodes_and_fragments_are_refused() {
        assert!(refused(&[0xC2, 0x80, 1, 2, 3, 4], true), "RSV1 set");
        assert!(refused(&[0x83, 0x80, 1, 2, 3, 4], true), "opcode 3 is reserved");
        assert!(refused(&[0x8B, 0x80, 1, 2, 3, 4], true), "opcode 11 is reserved");
    }

    /// A message that comes in parts (a data frame without FIN, then its continuations) is handed
    /// over frame by frame; a control frame may not be one of the parts.
    #[test]
    fn websocket_a_message_in_parts_is_handed_over_frame_by_frame() {
        let first = [0x02, 0x80 | 2, 1, 2, 3, 4, b'a' ^ 1, b'b' ^ 2];
        let last = [0x80, 0x80 | 1, 1, 2, 3, 4, b'c' ^ 1];
        let part = |wire: &[u8]| decode(wire, true, MAX).unwrap().unwrap().0;
        assert_eq!((part(&first).op, part(&first).payload), (Op::Binary, b"ab".to_vec()));
        assert_eq!((part(&last).op, part(&last).payload), (Op::Continue, b"c".to_vec()));
        assert!(refused(&[0x08, 0x80, 1, 2, 3, 4], true), "a close without FIN");
    }

    #[test]
    fn websocket_the_masking_direction_is_enforced() {
        assert!(
            refused(&[0x82, 0x03, b'a', b'b', b'c'], true),
            "a client frame must be masked"
        );
        let masked = encode(Op::Binary, b"abc", Some(KEY));
        assert!(refused(&masked, false), "a server frame must not be masked");
    }

    #[test]
    fn websocket_control_frames_are_short_and_unfragmented() {
        let ping = encode(Op::Ping, &[7; 125], Some(KEY));
        assert!(matches!(
            decode(&ping, true, MAX),
            Ok(Some((Frame { op: Op::Ping, .. }, _)))
        ));
        assert!(
            refused(&[0x89, 0x80 | 126, 0, 126, 1, 2, 3, 4], true),
            "a ping of 126 bytes"
        );
        assert!(refused(&[0x09, 0x80, 1, 2, 3, 4], true), "a ping without FIN");
    }

    #[test]
    fn websocket_close_frames_round_trip_with_a_valid_code_and_reason() {
        let body = close_body(1011, "replica gone");
        let wire = encode(Op::Close, &body, Some(KEY));
        assert_eq!(
            decode(&wire, true, MAX),
            Ok(Some((
                Frame {
                    op: Op::Close,
                    payload: body
                },
                wire.len()
            )))
        );
        let empty = encode(Op::Close, &[], None);
        assert_eq!(
            decode(&empty, false, MAX),
            Ok(Some((
                Frame {
                    op: Op::Close,
                    payload: vec![]
                },
                2
            )))
        );
    }

    #[test]
    fn websocket_close_frames_refuse_a_bad_code_or_reason() {
        assert!(
            refused(&encode(Op::Close, &[0x03], None), false),
            "a one-byte close body"
        );
        for code in [999u16, 1004, 1005, 1006, 1015, 2999, 5000] {
            assert!(
                refused(&encode(Op::Close, &close_body(code, ""), None), false),
                "code {code}"
            );
        }
        assert!(
            refused(&encode(Op::Close, &[0x03, 0xE8, 0xFF], None), false),
            "a reason that is not UTF-8"
        );
    }

    #[test]
    fn websocket_two_frames_in_one_buffer_decode_in_turn() {
        let mut wire = encode(Op::Binary, b"one", Some(KEY));
        let first = wire.len();
        wire.extend(encode(Op::Binary, b"two", Some(KEY)));
        let (frame, used) = decode(&wire, true, MAX).expect("valid").expect("whole");
        assert_eq!((used, frame.payload.as_slice()), (first, b"one".as_slice()));
        let (frame, _) = decode(&wire[used..], true, MAX).expect("valid").expect("whole");
        assert_eq!(frame.payload, b"two");
    }
}
