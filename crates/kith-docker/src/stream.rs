//! What a container's output looks like on the wire (T-1261) and the types of the seam logs and exec
//! cross (`Store::logs`, `Store::exec`).
//!
//! Docker's streams (`logs`, `attach`, an exec's `start`) are one of two shapes: with a terminal
//! the raw bytes; without, frames of an 8-byte header (stream type 1 stdout or 2 stderr, three
//! zeros, the length as a big-endian u32) and the bytes. `logs` carries them in a chunked HTTP
//! answer that ends when the container does; `attach` and `start` hijack the connection: a 101
//! with `Upgrade: tcp`, and from then on the connection is the stream, both ways.

use super::API_VERSION;
use std::io::{self, Write};
use std::sync::mpsc;

pub const RAW_STREAM: &str = "application/vnd.docker.raw-stream";
pub const MULTIPLEXED_STREAM: &str = "application/vnd.docker.multiplexed-stream";
/// The most one frame holds: longer output is cut into several.
const FRAME_MAX: usize = 1 << 20;

/// Which of a container's two outputs a piece came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Stdout = 1,
    Stderr = 2,
}

/// `data` as the client reads it: raw with a terminal, else in frames of at most `FRAME_MAX`.
pub fn frames(kind: Kind, data: &[u8], tty: bool) -> Vec<u8> {
    if tty {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len() + 8);
    for piece in data.chunks(FRAME_MAX) {
        out.extend([kind as u8, 0, 0, 0]);
        out.extend((piece.len() as u32).to_be_bytes());
        out.extend(piece);
    }
    out
}

/// One piece of a chunked body. (None for no data: a chunk of length 0 ends the body.)
pub fn chunk(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    [format!("{:x}\r\n", data.len()).as_bytes(), data, b"\r\n"].concat()
}

/// The end of a chunked body.
pub const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

fn head_of(status: &str, content_type: &str, extra: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nApi-Version: {}.{}\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: kith-docker/{}\r\nContent-Type: {content_type}\r\n{extra}\r\n",
        API_VERSION.0,
        API_VERSION.1,
        env!("CARGO_PKG_VERSION"),
    )
    .into_bytes()
}

fn head(status: &str, tty: bool, extra: &str) -> Vec<u8> {
    head_of(status, if tty { RAW_STREAM } else { MULTIPLEXED_STREAM }, extra)
}

/// The head of a JSON answer whose body comes later and ends where the connection does (a `wait`
/// that must tell its client it is there before the container it waits for has started).
pub fn json_head() -> Vec<u8> {
    head_of("200 OK", "application/json", "Connection: close\r\n")
}

/// How a stream reaches the client.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// A chunked 200 that ends with the zero chunk (`logs`).
    Chunked,
    /// A 101 after which the connection is the stream (`attach`, exec `start`).
    Hijack,
}

/// A stream being written: its head first, then pieces, then its end.
pub struct Writer<W: Write> {
    out: W,
    carrier: Carrier,
    tty: bool,
}

impl<W: Write> Writer<W> {
    pub fn new(out: W, carrier: Carrier, tty: bool) -> Writer<W> {
        Writer { out, carrier, tty }
    }

    pub fn start(&mut self) -> io::Result<()> {
        let head = match self.carrier {
            Carrier::Chunked => head(
                "200 OK",
                self.tty,
                "Transfer-Encoding: chunked\r\nConnection: close\r\n",
            ),
            Carrier::Hijack => head("101 UPGRADED", self.tty, "Connection: Upgrade\r\nUpgrade: tcp\r\n"),
        };
        self.out.write_all(&head)?;
        self.out.flush()
    }

    pub fn put(&mut self, kind: Kind, data: &[u8]) -> io::Result<()> {
        let bytes = frames(kind, data, self.tty);
        let bytes = match self.carrier {
            Carrier::Chunked => chunk(&bytes),
            Carrier::Hijack => bytes,
        };
        self.out.write_all(&bytes)?;
        self.out.flush()
    }

    /// The end of the stream. (A hijacked connection ends when it is closed: the caller's.)
    pub fn finish(&mut self) -> io::Result<()> {
        if self.carrier == Carrier::Chunked {
            self.out.write_all(LAST_CHUNK)?;
        }
        self.out.flush()
    }
}

/// Where a log is read from, and what a read of it says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFrom {
    Start,
    /// The last this many lines.
    Tail(u64),
    /// The bytes after this offset (the `next` of the read before).
    Offset(u64),
}

pub struct LogChunk {
    pub data: Vec<u8>,
    pub next: u64,
}

/// What a command in a container does, as the client of an exec reads it.
pub enum Event {
    Out(Vec<u8>),
    Err(Vec<u8>),
    /// It ended with this code.
    Done(i64),
    /// It could not run, or the session broke: why.
    Failed(String),
}

/// What the client of an exec sends the command.
pub enum Input {
    Data(Vec<u8>),
    /// No more of it.
    End,
    /// The terminal is this wide and this high.
    Resize(u16, u16),
    /// The client is gone: end the session.
    Close,
}

/// A command running in a container: what it says, and what it is told.
pub struct Session {
    pub events: mpsc::Receiver<Event>,
    pub input: mpsc::Sender<Input>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_multiplexed_frame_is_an_8_byte_header_then_the_bytes() {
        assert_eq!(
            frames(Kind::Stdout, b"hi\n", false),
            [&[1, 0, 0, 0, 0, 0, 0, 3][..], b"hi\n"].concat()
        );
        assert_eq!(
            frames(Kind::Stderr, b"oops", false),
            [&[2, 0, 0, 0, 0, 0, 0, 4][..], b"oops"].concat()
        );
        // The length is big-endian and all four bytes of it.
        let long = vec![b'x'; 0x0102];
        assert_eq!(&frames(Kind::Stdout, &long, false)[..8], &[1, 0, 0, 0, 0, 0, 1, 2]);
        // Nothing is no frame; more than one frame holds is cut.
        assert!(frames(Kind::Stdout, b"", false).is_empty());
        let huge = vec![b'x'; FRAME_MAX + 5];
        let out = frames(Kind::Stdout, &huge, false);
        assert_eq!(out.len(), huge.len() + 16);
        assert_eq!(&out[4..8], &(FRAME_MAX as u32).to_be_bytes());
        assert_eq!(&out[8 + FRAME_MAX + 4..8 + FRAME_MAX + 8], &5u32.to_be_bytes());
    }

    #[test]
    fn a_terminal_stream_is_the_raw_bytes_whichever_output_they_came_from() {
        assert_eq!(frames(Kind::Stdout, b"\x1b[0mhi\r\n", true), b"\x1b[0mhi\r\n");
        assert_eq!(frames(Kind::Stderr, b"x", true), b"x");
    }

    #[test]
    fn a_chunk_has_its_length_in_hex_and_empty_is_never_the_end() {
        assert_eq!(chunk(b"hello"), b"5\r\nhello\r\n");
        assert_eq!(chunk(&[7u8; 26])[..4], *b"1a\r\n");
        assert!(chunk(b"").is_empty());
        assert_eq!(LAST_CHUNK, b"0\r\n\r\n");
    }

    #[test]
    fn a_logs_answer_is_chunked_frames_ended_by_the_zero_chunk() {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out, Carrier::Chunked, false);
        w.start().unwrap();
        w.put(Kind::Stdout, b"a").unwrap();
        w.put(Kind::Stderr, b"b").unwrap();
        w.finish().unwrap();
        let text = String::from_utf8_lossy(&out).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains("Transfer-Encoding: chunked"));
        assert!(head.contains("Content-Type: application/vnd.docker.multiplexed-stream"));
        assert!(head.contains("Connection: close"));
        assert!(!head.contains("Content-Length"));
        assert_eq!(
            body.as_bytes(),
            b"9\r\n\x01\0\0\0\0\0\0\x01a\r\n9\r\n\x02\0\0\0\0\0\0\x01b\r\n0\r\n\r\n"
        );
    }

    #[test]
    fn a_hijack_is_a_101_upgrade_to_tcp_and_then_only_the_stream() {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out, Carrier::Hijack, true);
        w.start().unwrap();
        w.put(Kind::Stdout, b"$ ").unwrap();
        w.finish().unwrap();
        let text = String::from_utf8_lossy(&out).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 101 UPGRADED\r\n"), "{head}");
        assert!(head.ends_with("Upgrade: tcp"));
        assert!(head.contains("Connection: Upgrade"));
        assert!(head.contains("Content-Type: application/vnd.docker.raw-stream"));
        assert_eq!(body, "$ ", "no chunking, no end marker");
    }
}
