//! SPDY/3 as `kubectl port-forward` speaks it (the `SPDY/3.1+portforward.k8s.io` WebSocket
//! subprotocol): frames in a byte stream, read and written here and nothing more of SPDY.
//!
//! A control frame is `0x80 0x03`, a type, flags and a 24-bit length; a data frame is a stream id,
//! flags (1 is FIN) and a length. The header block of SYN_STREAM and HEADERS is deflated with one zlib
//! stream for the whole connection, a sync flush after each block, and a preset dictionary
//! (`spdy3.dict`: the one SPDY/3 names, adler32 `e3c6a7c2`). Each block begins on a byte, so it is
//! inflated alone, as raw deflate, over the last 32 KiB of what came before it. What kithd sends
//! needs no compressor: its SYN_REPLY carries no header, and an empty block is a stored one.
//!
//! Everything read is bounded: a frame's length, the bytes held for a frame, the header a block
//! inflates to (so a small block cannot be made to fill memory) and the pairs in it.

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};

const DICT: &[u8] = include_bytes!("spdy3.dict");
/// The adler32 of [`DICT`], which the first block names.
const DICT_ID: [u8; 4] = [0xe3, 0xc6, 0xa7, 0xc2];
/// How far back a deflate stream looks.
const WINDOW: usize = 32 << 10;
/// What a header block may inflate to, and the pairs in it: kubectl sends three.
const HEADERS_MAX: usize = 16 << 10;
const PAIRS_MAX: u32 = 32;
/// The longest control frame, and the longest data frame, a client may send.
const CONTROL_MAX: usize = 64 << 10;
/// (kubectl's are 32 KiB: what it copies with.)
const DATA_MAX: usize = 256 << 10;

/// RST_STREAM's status codes kithd says.
pub const PROTOCOL: u32 = 1;
pub const REFUSED: u32 = 3;

/// What a client sent.
#[derive(Debug, PartialEq)]
pub enum Frame {
    /// SYN_STREAM: a stream the client opens, with the pairs of its header.
    Open { id: u32, headers: Vec<(String, String)> },
    Data { id: u32, fin: bool, data: Vec<u8> },
    Reset { id: u32 },
    Ping(Vec<u8>),
    GoAway,
    /// A frame kithd has no use for (SETTINGS, WINDOW_UPDATE, HEADERS, a type it does not know).
    Skip,
}

/// Frames read from the bytes a client sent, as they come.
pub struct Reader {
    buf: Vec<u8>,
    /// The dictionary and what the blocks so far inflated to, the last [`WINDOW`] bytes of it.
    history: Vec<u8>,
    /// Whether the zlib header of the stream has been read.
    begun: bool,
}

impl Reader {
    pub fn new() -> Reader {
        Reader { buf: Vec::new(), history: DICT.to_vec(), begun: false }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next frame, if all of it has come. An error ends the connection: the stream's state
    /// (what its blocks inflated to) is not one to go on from.
    pub fn next(&mut self) -> Result<Option<Frame>, String> {
        let Some(head) = self.buf.get(..8) else {
            return Ok(None);
        };
        let control = head[0] & 0x80 != 0;
        let len = u32::from_be_bytes([0, head[5], head[6], head[7]]) as usize;
        if len > if control { CONTROL_MAX } else { DATA_MAX } {
            return Err(format!("a frame of {len} bytes is longer than kithd takes"));
        }
        if self.buf.len() < 8 + len {
            return Ok(None);
        }
        let (kind, flags) = (u16::from_be_bytes([head[2], head[3]]), head[4]);
        let id = u32::from_be_bytes([head[0] & 0x7f, head[1], head[2], head[3]]);
        let version = u16::from_be_bytes([head[0] & 0x7f, head[1]]);
        let body: Vec<u8> = self.buf.drain(..8 + len).skip(8).collect();
        if !control {
            return Ok(Some(Frame::Data { id, fin: flags & 1 != 0, data: body }));
        }
        if version != 3 {
            return Err(format!("SPDY version {version}: kithd speaks 3"));
        }
        let stream = |body: &[u8]| -> Result<u32, String> {
            let id = body.get(..4).ok_or("a frame too short for its stream id")?;
            Ok(u32::from_be_bytes([id[0] & 0x7f, id[1], id[2], id[3]]))
        };
        Ok(Some(match kind {
            1 => {
                let block = body.get(10..).ok_or("a SYN_STREAM too short")?;
                let headers = pairs(&self.inflate(block)?)?;
                Frame::Open { id: stream(&body)?, headers }
            }
            // (A block is inflated whether it is of use or not: the next one is made over it.)
            8 => {
                self.inflate(body.get(4..).ok_or("a HEADERS too short")?)?;
                Frame::Skip
            }
            2 => return Err("a client sends no SYN_REPLY".into()),
            3 => Frame::Reset { id: stream(&body)? },
            6 => Frame::Ping(body),
            7 => Frame::GoAway,
            _ => Frame::Skip,
        }))
    }

    /// A header block inflated: raw deflate over the history, after the zlib header the first has.
    fn inflate(&mut self, block: &[u8]) -> Result<Vec<u8>, String> {
        let mut block = block;
        if !self.begun {
            let [cmf, flg, id @ ..] = block.get(..6).ok_or("a header block too short")? else {
                unreachable!("six bytes were taken");
            };
            let sound = cmf & 0x0f == 8 && flg & 0x20 != 0 && u16::from_be_bytes([*cmf, *flg]) % 31 == 0;
            if !sound || id != DICT_ID {
                return Err("the header block is not deflated with SPDY/3's dictionary".into());
            }
            block = &block[6..];
            self.begun = true;
        }
        let from = self.history.len();
        let mut out = std::mem::take(&mut self.history);
        // (One byte more than may be kept: a block that fills it is over the cap.)
        out.resize(from + HEADERS_MAX + 1, 0);
        let mut state = Box::new(DecompressorOxide::new());
        let flags = inflate_flags::TINFL_FLAG_HAS_MORE_INPUT | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let (status, used, made) = decompress(&mut state, block, &mut out, from, flags);
        if status != TINFLStatus::NeedsMoreInput || used != block.len() || made > HEADERS_MAX {
            return Err(format!("a header block that does not inflate ({status:?})"));
        }
        out.truncate(from + made);
        let header = out[from..].to_vec();
        out.drain(..out.len().saturating_sub(WINDOW));
        self.history = out;
        Ok(header)
    }
}

/// The pairs of a name/value block: a count, then each name and value with a 32-bit length.
fn pairs(mut block: &[u8]) -> Result<Vec<(String, String)>, String> {
    fn take<'a>(block: &mut &'a [u8], len: usize) -> Result<&'a [u8], String> {
        let (head, rest) = block.split_at_checked(len).ok_or("a header block cut short")?;
        *block = rest;
        Ok(head)
    }
    fn number(block: &mut &[u8]) -> Result<usize, String> {
        Ok(u32::from_be_bytes(take(block, 4)?.try_into().expect("four bytes")) as usize)
    }
    fn text(block: &mut &[u8]) -> Result<String, String> {
        let len = number(block)?;
        String::from_utf8(take(block, len)?.to_vec()).map_err(|_| "a header that is not text".to_string())
    }
    let count = number(&mut block)?;
    if count > PAIRS_MAX as usize {
        return Err(format!("{count} header pairs"));
    }
    let mut found = Vec::new();
    for _ in 0..count {
        let name = text(&mut block)?;
        found.push((name, text(&mut block)?));
    }
    if !block.is_empty() {
        return Err("bytes after a header block's last pair".into());
    }
    Ok(found)
}

/// Frames to send. SYN_REPLY is the only one with a header block, and it has none.
pub struct Writer {
    begun: bool,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { begun: false }
    }

    /// SYN_REPLY for stream `id`: no pairs, in a stored block (the zlib header comes with the first) and an empty one
    /// after it, the sync flush: without it Go's inflater reads on past the block, fails and kills the connection.
    pub fn reply(&mut self, id: u32) -> Vec<u8> {
        let mut block = if self.begun { Vec::new() } else { vec![0x78, 0x01] };
        self.begun = true;
        block.extend_from_slice(&[0, 4, 0, 0xfb, 0xff, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        let mut frame = control(2, 0, 4 + block.len());
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&block);
        frame
    }

    pub fn reset(&self, id: u32, why: u32) -> Vec<u8> {
        let mut frame = control(3, 0, 8);
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&why.to_be_bytes());
        frame
    }

    pub fn ping(&self, payload: &[u8]) -> Vec<u8> {
        let mut frame = control(6, 0, payload.len());
        frame.extend_from_slice(payload);
        frame
    }

    /// DATA for stream `id`, the length of `data` at most 2^24 - 1.
    pub fn data(&self, id: u32, fin: bool, data: &[u8]) -> Vec<u8> {
        let mut frame = id.to_be_bytes().to_vec();
        frame.push(u8::from(fin));
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes()[1..]);
        frame.extend_from_slice(data);
        frame
    }
}

fn control(kind: u16, flags: u8, len: usize) -> Vec<u8> {
    let mut frame = vec![0x80, 3];
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.push(flags);
    frame.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap()).collect()
    }

    fn headers(frame: Option<Frame>) -> (u32, Vec<(String, String)>) {
        match frame {
            Some(Frame::Open { id, headers }) => (id, headers),
            other => panic!("a SYN_STREAM was to come, not {other:?}"),
        }
    }

    fn port_forward(id: &str, kind: &str) -> (u32, Vec<(String, String)>) {
        let pair = |name: &str, value: &str| (name.to_string(), value.to_string());
        (id.parse().unwrap(), vec![pair("requestid", "0"), pair("streamtype", kind), pair("port", "8080")])
    }

    /// What kubectl v1.37 sent for its first stream (captured), and two of a zlib's, the second over the first.
    #[test]
    fn spdy_reads_the_syn_streams_kubectl_sends() {
        let kubectl = hex("800300010000003e0000000100000000000078f9e3c6a7c202253a060606ce2248fc6482d22da30138e59514a526e6420b17d65450d0430aea22709eb030b03000000000ffff");
        let mut reader = Reader::new();
        reader.push(&kubectl);
        assert_eq!(headers(reader.next().unwrap()), port_forward("1", "error"));
        assert_eq!(reader.next().unwrap(), None);

        let two = "800300010000003d0000000100000000000078f9e3c6a7c202253a20e62c82c44f2628dd321a80535e49516a622eb470614d05053da4a02e02e7090b030b0300000000ffff\
            800300010000001800000003000000000000225233a8644a44d70b000000ffff";
        let two = hex(two);
        let mut reader = Reader::new();
        // (A piece at a time, as a WebSocket's frames come.)
        for piece in two.chunks(7) {
            reader.push(piece);
        }
        assert_eq!(headers(reader.next().unwrap()), port_forward("1", "error"));
        assert_eq!(headers(reader.next().unwrap()), port_forward("3", "data"));
    }

    #[test]
    fn spdy_reads_data_and_what_it_skips_and_refuses_what_is_hostile() {
        let writer = Writer::new();
        let mut reader = Reader::new();
        reader.push(&writer.data(3, true, b"hi"));
        reader.push(&writer.reset(5, 5));
        reader.push(&control(4, 0, 0));
        reader.push(&writer.ping(&[0, 0, 0, 1]));
        assert_eq!(reader.next().unwrap(), Some(Frame::Data { id: 3, fin: true, data: b"hi".to_vec() }));
        assert_eq!(reader.next().unwrap(), Some(Frame::Reset { id: 5 }));
        assert_eq!(reader.next().unwrap(), Some(Frame::Skip));
        assert_eq!(reader.next().unwrap(), Some(Frame::Ping(vec![0, 0, 0, 1])));
        assert_eq!(reader.next().unwrap(), None);

        // A length over the bound is refused before its body is waited for.
        let mut long = Reader::new();
        long.push(&[0, 0, 0, 1, 0, 0x20, 0, 0]);
        assert!(long.next().is_err());
        let mut long = Reader::new();
        long.push(&[0x80, 3, 0, 4, 0, 0x02, 0, 0]);
        assert!(long.next().is_err());
        // Another version, and a SYN_REPLY from a client.
        let mut old = Reader::new();
        old.push(&[0x80, 2, 0, 4, 0, 0, 0, 0]);
        assert!(old.next().is_err());
        let mut reply = Reader::new();
        reply.push(&Writer::new().reply(2));
        assert!(reply.next().is_err());
    }

    #[test]
    fn spdy_refuses_a_header_block_that_is_not_what_it_says() {
        // No dictionary named, then a block that is not deflate, then one that inflates past the cap.
        for block in [
            hex("7801000000"),
            hex("78f9e3c6a7c2ffffffffff"),
            [hex("78f9e3c6a7c2"), vec![0x00, 0x00, 0x00, 0xff, 0xff]].concat(),
        ] {
            let mut frame = control(1, 0, 10 + block.len());
            frame.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            frame.extend_from_slice(&block);
            let mut reader = Reader::new();
            reader.push(&frame);
            assert!(reader.next().is_err(), "{block:?}");
        }
        let mut bomb = hex("78f9e3c6a7c2");
        // (Stored blocks of zero bytes, a megabyte of them: the pairs it makes are not the point, its size is.)
        let full = [vec![0u8, 0xff, 0x3f, 0x00, 0xc0], vec![0u8; 16383]].concat();
        for _ in 0..2 {
            bomb.extend_from_slice(&full);
        }
        bomb.extend_from_slice(&[0, 0, 0, 0xff, 0xff]);
        let mut frame = control(1, 0, 10 + bomb.len());
        frame.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        frame.extend_from_slice(&bomb);
        let mut reader = Reader::new();
        reader.push(&frame);
        assert!(reader.next().is_err());
    }

    #[test]
    fn spdy_writes_a_reply_with_the_zlib_header_once() {
        let mut writer = Writer::new();
        let first = writer.reply(1);
        // (Each block ends with the empty stored block `0 0 0 ff ff` Go's inflater needs to stop at.)
        assert_eq!(first[..8], [0x80, 3, 0, 2, 0, 0, 0, 20]);
        assert_eq!(first[12..], [0x78, 0x01, 0, 4, 0, 0xfb, 0xff, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        let second = writer.reply(3);
        assert_eq!(second[..8], [0x80, 3, 0, 2, 0, 0, 0, 18]);
        assert_eq!(second[12..], [0, 4, 0, 0xfb, 0xff, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
    }
}
