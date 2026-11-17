//! The link between two kithds: one connection that carries many streams. A stream is
//! one client's connection to a Service passed on to a replica on the other node, and the
//! link is the connection between the nodes that every such stream shares, so that
//! requests of many clients that wait at once go out in one write (one segment, one
//! encrypted packet on the mesh) where a connection for each client wrote each of them
//! alone (T-0326).
//!
//! On the wire a frame is a stream number (u32), a kind (u8), a length (u16) and that many
//! bytes: `Open` (the opener's numbers are odd or even, as the two ends agreed in
//! [`link`]), `Data` (1 to [`MAX_DATA`] bytes), `End` (the sender writes no more; the
//! stream goes on the other way), `Reset` (the stream is over, both ways, whatever was in
//! flight is dropped) and `Credit` (4 bytes: that many bytes of the stream were read on
//! and may be sent). One writer task takes every frame that waits, of every stream, into
//! one write; one reader task hands each frame to its stream.
//!
//! A stream is held back by its own window and by nothing else: a sender may have
//! [`WINDOW`] bytes of a stream sent and not yet given back, and waits for credit for the
//! next; a receiver gives credit back when its reader asks for more after the last bytes,
//! that is, once they have been written on. A stream nobody reads thus holds at most its
//! window in memory, on the far side, and its sender waits on its own semaphore while the
//! other streams' frames pass. A peer that sends past a window (or frames this does not
//! know) has that stream reset, or the link taken down for a malformed frame.
//
// ponytail: the link lives until its connection ends or [`Link::close`]; a window is one
// size for every stream; a `Tx` dropped without [`Tx::end`] ends nothing (the stream is
// reset when its `Rx` goes too).

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::AbortHandle;

/// Bytes of a stream that may be sent and not yet read on.
pub const WINDOW: usize = 64 * 1024;
/// The most bytes in one `Data` frame.
const MAX_DATA: usize = 16 * 1024;
/// Streams open on one link at a time, and opened by the other end and not yet accepted.
const MAX_STREAMS: usize = 4096;
const ACCEPTING: usize = 64;
const HEADER: usize = 7;
/// The most frames the writer takes into one write.
const BATCH: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Kind {
    Open,
    Data,
    End,
    Reset,
    Credit,
}

impl Kind {
    fn from(byte: u8) -> Option<Kind> {
        [Kind::Open, Kind::Data, Kind::End, Kind::Reset, Kind::Credit]
            .into_iter()
            .find(|kind| *kind as u8 == byte)
    }

    /// How long this kind's bytes may be.
    fn lengths(self) -> std::ops::RangeInclusive<usize> {
        match self {
            Kind::Data => 1..=MAX_DATA,
            Kind::Credit => 4..=4,
            _ => 0..=0,
        }
    }
}

struct Frame {
    stream: u32,
    kind: Kind,
    bytes: Vec<u8>,
}

fn encode(out: &mut Vec<u8>, stream: u32, kind: Kind, bytes: &[u8]) {
    out.extend_from_slice(&stream.to_be_bytes());
    out.push(kind as u8);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

enum Event {
    Data(Vec<u8>),
    End,
    Reset,
}

/// What the reader hands a stream, and what it keeps of it.
struct Entry {
    events: mpsc::UnboundedSender<Event>,
    /// Bytes this side may still send.
    window: Arc<Semaphore>,
    /// Bytes received and not yet taken by the stream's reader.
    queued: Arc<AtomicUsize>,
    local_end: bool,
    remote_end: bool,
}

struct State {
    streams: HashMap<u32, Entry>,
    /// The number of the next stream opened here.
    next: u32,
    closed: bool,
}

struct Shared {
    state: Mutex<State>,
    frames: mpsc::UnboundedSender<Frame>,
    /// Frames and writes made, to see how many share one.
    counts: (AtomicU64, AtomicU64),
    tasks: Mutex<Vec<AbortHandle>>,
}

fn reset_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "the stream was reset")
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn send(&self, stream: u32, kind: Kind, bytes: Vec<u8>) {
        // (Failing, the link is down: its streams have been told.)
        let _ = self.frames.send(Frame { stream, kind, bytes });
    }

    /// A stream's two halves, entered in the table. The caller holds the table's lock.
    fn stream(self: &Arc<Self>, state: &mut State, id: u32) -> Stream {
        let (events, inbox) = mpsc::unbounded_channel();
        let (window, queued) = (Arc::new(Semaphore::new(WINDOW)), Arc::new(AtomicUsize::new(0)));
        let entry = Entry {
            events,
            window: window.clone(),
            queued: queued.clone(),
            local_end: false,
            remote_end: false,
        };
        state.streams.insert(id, entry);
        let guard = Arc::new(Guard { shared: self.clone(), id });
        Stream {
            tx: Tx { guard: guard.clone(), window, ended: false },
            rx: Rx { guard, inbox, queued, owed: 0, done: None },
        }
    }

    /// The stream is over both ways, if it was not already: its halves fail, and the other
    /// end is told.
    fn reset(&self, id: u32) {
        let gone = self.state().streams.remove(&id);
        if let Some(entry) = gone {
            entry.window.close();
            let _ = entry.events.send(Event::Reset);
            self.send(id, Kind::Reset, Vec::new());
        }
    }

    /// The link is down: every stream is reset and no more are opened.
    fn down(&self) {
        let mut state = self.state();
        state.closed = true;
        for (_, entry) in state.streams.drain() {
            entry.window.close();
            let _ = entry.events.send(Event::Reset);
        }
        drop(state);
        for task in self.tasks.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).iter() {
            task.abort();
        }
    }

    /// A frame from the other end. Never waits.
    fn arrived(self: &Arc<Self>, id: u32, kind: Kind, bytes: Vec<u8>, accepting: &mpsc::Sender<Stream>) {
        let mut state = self.state();
        match kind {
            Kind::Open => {
                // The other end's numbers have the other parity than ours (`next` keeps its).
                let ours = id & 1 == state.next & 1;
                if id == 0 || ours || state.streams.contains_key(&id) || state.streams.len() >= MAX_STREAMS {
                    drop(state);
                    return self.send(id, Kind::Reset, Vec::new());
                }
                let stream = self.stream(&mut state, id);
                // (A stream not taken is dropped, and so reset, with the lock let go.)
                let refused = accepting.try_send(stream).err();
                drop(state);
                drop(refused);
            }
            Kind::Data => {
                let Some(entry) = state.streams.get(&id) else { return };
                let queued = entry.queued.fetch_add(bytes.len(), Ordering::SeqCst) + bytes.len();
                if entry.remote_end || queued > WINDOW {
                    drop(state);
                    return self.reset(id);
                }
                let _ = entry.events.send(Event::Data(bytes));
            }
            Kind::End => {
                let Some(entry) = state.streams.get_mut(&id) else { return };
                if std::mem::replace(&mut entry.remote_end, true) {
                    drop(state);
                    return self.reset(id);
                }
                let _ = entry.events.send(Event::End);
                if entry.local_end {
                    state.streams.remove(&id);
                }
            }
            Kind::Reset => {
                if let Some(entry) = state.streams.remove(&id) {
                    entry.window.close();
                    let _ = entry.events.send(Event::Reset);
                }
            }
            Kind::Credit => {
                let Some(entry) = state.streams.get(&id) else { return };
                let more = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
                if entry.window.available_permits() + more > WINDOW {
                    drop(state);
                    return self.reset(id);
                }
                entry.window.add_permits(more);
            }
        }
    }
}

/// Resets the stream when its last half goes, if it was not finished both ways.
struct Guard {
    shared: Arc<Shared>,
    id: u32,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.shared.reset(self.id);
    }
}

/// One end of a link: opens streams. Clones are the same link.
#[derive(Clone)]
pub struct Link(Arc<Shared>);

/// The streams the other end opens, as they come.
pub struct Incoming(mpsc::Receiver<Stream>);

/// One stream, as the two halves that go to the tasks that write and read it.
pub struct Stream {
    pub tx: Tx,
    pub rx: Rx,
}

/// The writing half: bytes go to the other end's reader, in order.
pub struct Tx {
    guard: Arc<Guard>,
    window: Arc<Semaphore>,
    ended: bool,
}

/// The reading half.
pub struct Rx {
    guard: Arc<Guard>,
    inbox: mpsc::UnboundedReceiver<Event>,
    queued: Arc<AtomicUsize>,
    /// Bytes handed out by the last read, whose credit is given back on the next.
    owed: usize,
    done: Option<bool>,
}

/// A link over `io`, which the other end makes a link of too, with `odd` here and not there.
pub fn link<T: AsyncRead + AsyncWrite + Send + 'static>(io: T, odd: bool) -> (Link, Incoming) {
    let (read, write) = tokio::io::split(io);
    let (frames, waits) = mpsc::unbounded_channel();
    let (accepting, incoming) = mpsc::channel(ACCEPTING);
    let shared = Arc::new(Shared {
        state: Mutex::new(State { streams: HashMap::new(), next: if odd { 1 } else { 2 }, closed: false }),
        frames,
        counts: Default::default(),
        tasks: Mutex::new(Vec::new()),
    });
    let writer = tokio::spawn(write_frames(shared.clone(), write, waits));
    let reader = tokio::spawn(read_frames(shared.clone(), read, accepting));
    *shared.tasks.lock().unwrap() = vec![writer.abort_handle(), reader.abort_handle()];
    (Link(shared), Incoming(incoming))
}

/// The one writer: whatever waits, of every stream, in one write.
async fn write_frames<W: AsyncWrite + Unpin>(
    shared: Arc<Shared>,
    mut to: W,
    mut waits: mpsc::UnboundedReceiver<Frame>,
) {
    let (mut frames, mut out) = (Vec::new(), Vec::new());
    while waits.recv_many(&mut frames, BATCH).await > 0 {
        out.clear();
        for frame in frames.drain(..) {
            encode(&mut out, frame.stream, frame.kind, &frame.bytes);
            shared.counts.0.fetch_add(1, Ordering::Relaxed);
        }
        shared.counts.1.fetch_add(1, Ordering::Relaxed);
        if to.write_all(&out).await.is_err() {
            break;
        }
    }
    shared.down();
}

async fn read_frames<R: AsyncRead + Unpin>(shared: Arc<Shared>, from: R, accepting: mpsc::Sender<Stream>) {
    let _ = pump(&shared, from, accepting).await;
    shared.down();
}

/// Frames from the other end to the streams, until the connection ends or a frame is not one.
async fn pump<R: AsyncRead + Unpin>(shared: &Arc<Shared>, from: R, accepting: mpsc::Sender<Stream>) -> io::Result<()> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "not a frame of the link");
    let mut from = BufReader::new(from);
    loop {
        let mut head = [0; HEADER];
        from.read_exact(&mut head).await?;
        let id = u32::from_be_bytes(head[..4].try_into().unwrap());
        let kind = Kind::from(head[4]).ok_or_else(bad)?;
        let len = usize::from(u16::from_be_bytes([head[5], head[6]]));
        if !kind.lengths().contains(&len) {
            return Err(bad());
        }
        let mut bytes = vec![0; len];
        from.read_exact(&mut bytes).await?;
        shared.arrived(id, kind, bytes, &accepting);
    }
}

impl Link {
    /// A stream to the other end's [`Incoming`]. Fails when the link is down or has as
    /// many streams as it holds.
    pub fn open(&self) -> io::Result<Stream> {
        let mut state = self.0.state();
        if state.closed || state.streams.len() >= MAX_STREAMS {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "the link is down or full"));
        }
        let id = state.next;
        state.next = id.checked_add(2).ok_or_else(|| io::Error::other("the link has no stream numbers left"))?;
        let stream = self.0.stream(&mut state, id);
        drop(state);
        self.0.send(id, Kind::Open, Vec::new());
        Ok(stream)
    }

    /// Takes the link down: every stream is reset.
    pub fn close(&self) {
        self.0.down();
    }

    /// Frames and writes so far: how many frames share a write.
    pub fn counts(&self) -> (u64, u64) {
        (self.0.counts.0.load(Ordering::Relaxed), self.0.counts.1.load(Ordering::Relaxed))
    }

    /// Streams not yet over both ways.
    pub fn streams(&self) -> usize {
        self.0.state().streams.len()
    }
}

impl Incoming {
    /// The next stream the other end opened; none once the link is down.
    pub async fn accept(&mut self) -> Option<Stream> {
        self.0.recv().await
    }
}

impl Tx {
    /// Sends `bytes`; waits while the stream's window is full. Fails once the stream is
    /// ended (here) or reset (anywhere).
    pub async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        for chunk in bytes.chunks(MAX_DATA) {
            if self.ended {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let credit = self.window.acquire_many(chunk.len() as u32).await.map_err(|_| reset_error())?;
            credit.forget();
            self.guard.shared.send(self.guard.id, Kind::Data, chunk.to_vec());
        }
        Ok(())
    }

    /// No more bytes from here; the stream goes on the other way.
    pub fn end(&mut self) {
        if std::mem::replace(&mut self.ended, true) {
            return;
        }
        let (shared, id) = (&self.guard.shared, self.guard.id);
        let mut state = shared.state();
        let Some(entry) = state.streams.get_mut(&id) else { return };
        entry.local_end = true;
        if entry.remote_end {
            state.streams.remove(&id);
        }
        drop(state);
        shared.send(id, Kind::End, Vec::new());
    }

    /// The stream is over, both ways, for both ends.
    pub fn reset(&self) {
        self.guard.shared.reset(self.guard.id);
    }
}

impl Rx {
    /// The next bytes, or none at the other end's end. Asking for more is what gives the
    /// last bytes' window back. An error once the stream is reset.
    pub async fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.done {
            Some(true) => return Ok(None),
            Some(false) => return Err(reset_error()),
            None => {}
        }
        let owed = std::mem::take(&mut self.owed);
        if owed > 0 {
            self.guard.shared.send(self.guard.id, Kind::Credit, (owed as u32).to_be_bytes().to_vec());
        }
        match self.inbox.recv().await {
            Some(Event::Data(bytes)) => {
                self.queued.fetch_sub(bytes.len(), Ordering::SeqCst);
                self.owed = bytes.len();
                Ok(Some(bytes))
            }
            Some(Event::End) => {
                self.done = Some(true);
                Ok(None)
            }
            // (No event at all: the entry went with the link.)
            Some(Event::Reset) | None => {
                self.done = Some(false);
                Err(reset_error())
            }
        }
    }

    /// The stream is over, both ways, for both ends.
    pub fn reset(&self) {
        self.guard.shared.reset(self.guard.id);
    }
}

impl Stream {
    /// Passes `local`'s bytes to the other end and the other end's to it, until both ways
    /// have ended or the stream is reset.
    pub async fn join(self, local: TcpStream) {
        let _ = local.set_nodelay(true);
        let (mut read, mut write) = local.into_split();
        let Stream { mut tx, mut rx } = self;
        let up = async {
            let mut chunk = vec![0; MAX_DATA];
            loop {
                match read.read(&mut chunk).await {
                    Ok(n @ 1..) => {
                        if tx.write(&chunk[..n]).await.is_err() {
                            return;
                        }
                    }
                    Ok(0) => return tx.end(),
                    Err(_) => return tx.reset(),
                }
            }
        };
        let down = async {
            loop {
                match rx.read().await {
                    Ok(Some(bytes)) => {
                        if write.write_all(&bytes).await.is_err() {
                            return rx.reset();
                        }
                    }
                    Ok(None) => return drop(write.shutdown().await),
                    Err(_) => return,
                }
            }
        };
        tokio::join!(up, down);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    fn frame(stream: u32, kind: Kind, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&mut out, stream, kind, bytes);
        out
    }

    const WAIT: Duration = Duration::from_secs(20);

    /// Both ends of one link over a pipe of a small size (so the writer has to wait, and
    /// frames gather behind it, as on a busy connection).
    fn pair() -> ((Link, Incoming), (Link, Incoming)) {
        let (a, b) = tokio::io::duplex(8192);
        (link(a, true), link(b, false))
    }

    /// Everything a stream is sent until its end.
    async fn all(rx: &mut Rx) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while let Some(more) = rx.read().await? {
            bytes.extend_from_slice(&more);
        }
        Ok(bytes)
    }

    #[tokio::test]
    async fn many_clients_bytes_arrive_in_order_for_each_stream_never_mixed() {
        const STREAMS: u32 = 40;
        const CHUNKS: u32 = 150;
        let ((near, _), (_far, mut incoming)) = pair();
        // The far side reads each stream it is given to its end, and checks it.
        let reader = tokio::spawn(async move {
            let mut readers = Vec::new();
            for _ in 0..STREAMS {
                let Stream { tx, mut rx } = incoming.accept().await.unwrap();
                readers.push(tokio::spawn(async move {
                    let _tx = tx;
                    let bytes = all(&mut rx).await.unwrap();
                    // A chunk is its stream's number, its own number and filler of its own size.
                    let mut at = 0;
                    let (mut which, mut next) = (None, 0);
                    while at < bytes.len() {
                        let id = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
                        let seq = u32::from_be_bytes(bytes[at + 4..at + 8].try_into().unwrap());
                        let size = usize::from(bytes[at + 8]);
                        assert_eq!(*which.get_or_insert(id), id, "another stream's bytes");
                        assert_eq!(seq, next, "out of order");
                        assert!(bytes[at + 9..at + 9 + size].iter().all(|&b| b == id as u8));
                        (at, next) = (at + 9 + size, next + 1);
                    }
                    assert_eq!(next, CHUNKS);
                    which.unwrap()
                }));
            }
            let mut got = Vec::new();
            for reader in readers {
                got.push(reader.await.unwrap());
            }
            got.sort();
            got
        });
        for id in 0..STREAMS {
            let Stream { mut tx, .. } = near.open().unwrap();
            tokio::spawn(async move {
                for seq in 0..CHUNKS {
                    let size = (seq * 37 + id) % 200;
                    let mut chunk = [id.to_be_bytes().as_slice(), &seq.to_be_bytes(), &[size as u8]].concat();
                    chunk.resize(chunk.len() + size as usize, id as u8);
                    tx.write(&chunk).await.unwrap();
                }
                tx.end();
            });
        }
        let got = timeout(WAIT, reader).await.expect("a stream that never ended").unwrap();
        assert_eq!(got, (0..STREAMS).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn a_stream_not_read_holds_its_window_and_holds_back_no_other() {
        let ((near, _), (_far, mut incoming)) = pair();
        let (mut slow, _slow_rx) = {
            let Stream { tx, rx } = near.open().unwrap();
            (tx, rx)
        };
        let Stream { tx: _slow_far_tx, rx: mut slow_far } = incoming.accept().await.unwrap();
        let Stream { tx: mut busy, rx: mut busy_rx } = near.open().unwrap();
        let Stream { tx: mut busy_far, rx: mut busy_far_rx } = incoming.accept().await.unwrap();

        // The slow stream's sender: as much as it can, in chunks, counted as they pass.
        let sent = Arc::new(AtomicUsize::new(0));
        let sender = {
            let sent = sent.clone();
            tokio::spawn(async move {
                for _ in 0..(3 * WINDOW / 1000) {
                    slow.write(&[1; 1000]).await.unwrap();
                    sent.fetch_add(1000, Ordering::SeqCst);
                }
                slow.end();
            })
        };
        // It stops at its window (never past it) and waits: nobody reads it.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let held = sent.load(Ordering::SeqCst);
        assert!(held > 0 && held <= WINDOW, "{held} bytes passed with a window of {WINDOW}");

        // Another stream on the same link answers at once meanwhile, both ways.
        timeout(WAIT, async {
            for turn in 0..50u8 {
                busy.write(&[turn; 100]).await.unwrap();
                assert_eq!(busy_far_rx.read().await.unwrap().unwrap(), [turn; 100]);
                busy_far.write(&[turn; 10]).await.unwrap();
                assert_eq!(busy_rx.read().await.unwrap().unwrap(), [turn; 10]);
            }
        })
        .await
        .expect("a stream not read held back another");
        assert_eq!(sent.load(Ordering::SeqCst), held, "it went on past its window");

        // Read, and it goes on to its end, all of it.
        let bytes = timeout(WAIT, all(&mut slow_far)).await.expect("no credit given back").unwrap();
        assert_eq!(bytes.len(), 3 * WINDOW / 1000 * 1000);
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn a_peer_that_sends_past_a_window_has_its_stream_reset() {
        let (raw, theirs) = tokio::io::duplex(1 << 20);
        let (_link, mut incoming) = link(theirs, false);
        let (mut raw_read, mut raw_write) = tokio::io::split(raw);
        let mut frames = frame(1, Kind::Open, &[]);
        for _ in 0..(WINDOW / MAX_DATA + 1) {
            frames.extend(frame(1, Kind::Data, &[9; MAX_DATA]));
        }
        raw_write.write_all(&frames).await.unwrap();
        let Stream { mut rx, .. } = incoming.accept().await.unwrap();
        // Nobody reads: the window's worth is kept, and the stream is reset at the next.
        let mut header = [0; HEADER];
        timeout(WAIT, async {
            loop {
                raw_read.read_exact(&mut header).await.unwrap();
                if header[4] == Kind::Reset as u8 {
                    break;
                }
            }
        })
        .await
        .expect("no reset for a stream past its window");
        assert_eq!(&header[..4], &1u32.to_be_bytes());
        let mut kept = 0;
        while let Ok(Some(bytes)) = rx.read().await {
            kept += bytes.len();
        }
        assert!(kept <= WINDOW, "{kept} bytes kept");
        assert!(rx.read().await.is_err());
    }

    #[tokio::test]
    async fn an_end_is_passed_on_and_the_other_way_goes_on() {
        let ((near, _), (_far, mut incoming)) = pair();
        let Stream { mut tx, mut rx } = near.open().unwrap();
        let Stream { tx: mut far_tx, rx: mut far_rx } = incoming.accept().await.unwrap();
        tx.write(b"request").await.unwrap();
        tx.end();
        assert_eq!(timeout(WAIT, all(&mut far_rx)).await.unwrap().unwrap(), b"request");
        // The far side's end of the stream is open still: an answer, then its own end.
        far_tx.write(b"answer").await.unwrap();
        far_tx.end();
        assert_eq!(timeout(WAIT, all(&mut rx)).await.unwrap().unwrap(), b"answer");
        assert!(rx.read().await.unwrap().is_none());
        // Written on after its end: refused, and not passed on.
        assert!(tx.write(b"more").await.is_err());
    }

    #[tokio::test]
    async fn a_reset_is_passed_on_to_both_halves_and_no_other_stream() {
        let ((near, _), (_far, mut incoming)) = pair();
        let Stream { mut tx, mut rx } = near.open().unwrap();
        let Stream { tx: mut far_tx, rx: mut far_rx } = incoming.accept().await.unwrap();
        let Stream { tx: mut other, rx: mut other_rx } = near.open().unwrap();
        let Stream { tx: mut other_far, rx: mut other_far_rx } = incoming.accept().await.unwrap();
        tx.write(b"some").await.unwrap();
        tx.reset();
        // Its own side and the far side: errors, not an end.
        assert!(rx.read().await.is_err());
        assert!(tx.write(b"more").await.is_err());
        let far_ends = timeout(WAIT, async {
            while far_rx.read().await?.is_some() {}
            Ok::<(), std::io::Error>(())
        });
        assert!(far_ends.await.unwrap().is_err());
        assert!(far_tx.write(b"answer").await.is_err());
        // The other stream goes on.
        other.write(b"a").await.unwrap();
        assert_eq!(other_far_rx.read().await.unwrap().unwrap(), b"a");
        other_far.write(b"b").await.unwrap();
        assert_eq!(other_rx.read().await.unwrap().unwrap(), b"b");
    }

    #[tokio::test]
    async fn a_stream_dropped_before_its_end_resets_the_far_side_and_a_finished_one_does_not() {
        let ((near, _), (far, mut incoming)) = pair();
        let gone = near.open().unwrap();
        let Stream { rx: mut far_rx, .. } = incoming.accept().await.unwrap();
        drop(gone);
        assert!(timeout(WAIT, all(&mut far_rx)).await.unwrap().is_err());
        // Both ends passed: dropping then sends nothing, and the streams are forgotten.
        let Stream { mut tx, mut rx } = near.open().unwrap();
        let Stream { tx: mut far_tx, rx: mut far_rx } = incoming.accept().await.unwrap();
        tx.end();
        far_tx.end();
        assert!(all(&mut far_rx).await.unwrap().is_empty() && all(&mut rx).await.unwrap().is_empty());
        timeout(WAIT, async { while near.streams() + far.streams() > 0 { tokio::task::yield_now().await } })
            .await
            .expect("a finished stream kept in the table");
    }

    #[tokio::test]
    async fn a_link_that_goes_down_resets_its_streams_and_opens_no_more() {
        let (a, b) = tokio::io::duplex(8192);
        let (near, _) = link(a, true);
        let Stream { mut tx, mut rx } = near.open().unwrap();
        drop(b);
        assert!(timeout(WAIT, rx.read()).await.unwrap().is_err());
        assert!(tx.write(b"x").await.is_err());
        assert!(near.open().is_err());
    }

    #[tokio::test]
    async fn streams_are_capped_and_the_far_side_refuses_what_it_has_no_room_for() {
        let ((near, _), (_far, _incoming)) = pair();
        // Nobody accepts on the far side: its queue of waiting streams is short, the rest are reset.
        let mut opened = Vec::new();
        for _ in 0..(ACCEPTING + 10) {
            opened.push(near.open().unwrap());
        }
        for Stream { rx, .. } in &mut opened[ACCEPTING..] {
            assert!(timeout(WAIT, rx.read()).await.unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn one_writer_takes_what_waits_of_many_streams_in_one_write() {
        let ((near, _), (far, mut incoming)) = pair();
        let mut readers = Vec::new();
        for _ in 0..20 {
            let Stream { mut tx, .. } = near.open().unwrap();
            let Stream { rx: mut far_rx, .. } = incoming.accept().await.unwrap();
            readers.push(tokio::spawn(async move { all(&mut far_rx).await.unwrap().len() }));
            tokio::spawn(async move {
                for _ in 0..200 {
                    tx.write(&[3; 100]).await.unwrap();
                }
                tx.end();
            });
        }
        for reader in readers {
            assert_eq!(timeout(WAIT, reader).await.unwrap().unwrap(), 200 * 100);
        }
        let (frames, writes) = near.counts();
        assert!(frames >= 20 * 200 && frames > writes * 2, "{frames} frames in {writes} writes");
        let _ = far;
    }

    #[tokio::test]
    async fn a_socket_joined_to_a_stream_is_passed_both_ways_to_its_end() {
        use tokio::net::{TcpListener, TcpStream};
        let ((near, _), (_far, mut incoming)) = pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        // The far side's socket echoes; the near side's clients are five sockets.
        tokio::spawn(async move {
            while let Some(stream) = incoming.accept().await {
                tokio::spawn(async move {
                    stream.join(TcpStream::connect(at).await.unwrap()).await;
                });
            }
        });
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = client.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_at = echo.local_addr().unwrap();
        let near2 = near.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = echo.accept().await {
                near2.open().unwrap().join(client).await;
            }
        });
        let mut clients = Vec::new();
        for n in 0..5u8 {
            clients.push(tokio::spawn(async move {
                let mut to = TcpStream::connect(echo_at).await.unwrap();
                let sent: Vec<u8> = (0..200_000u32).map(|i| (i as u8) ^ n).collect();
                let (mut read, mut write) = to.split();
                let send = async {
                    write.write_all(&sent).await.unwrap();
                    write.shutdown().await.unwrap();
                };
                let mut got = Vec::new();
                let (_, read) = tokio::join!(send, read.read_to_end(&mut got));
                read.unwrap();
                assert!(got == sent, "client {n} got other bytes");
            }));
        }
        for client in clients {
            timeout(WAIT, client).await.expect("a client that got no end").unwrap();
        }
    }
}
