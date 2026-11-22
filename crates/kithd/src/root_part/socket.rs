//! The root part over a socket pair (docs/adr-privilege.md, "The transport"): [`Socket`] is the
//! serving part's end, a [`Root`] that sends each call as one message (JSON, at most
//! [`MAX_REQUEST`], with the files that go beside it as descriptors), and [`serve`] is the root
//! part's, which reads each message, does it with a [`Direct`] (so [`check`] and the Book are the
//! same as in one process) and answers.
//!
//! The root part's end is made for a peer it does not trust: one reader thread takes each message
//! whole (or refuses it, and the descriptors that came with it are closed), a queue of
//! [`Limits::queue`] holds what the one worker has not done yet (a request that finds it full is
//! told so at once), a request that waited past [`Limits::wait`] is refused unread by the worker,
//! a reply that the peer does not take within [`Limits::reply`] closes the socket, and so do
//! [`Limits::bad`] messages in a row that are not requests.
//
// ponytail: one worker, so a long Unpack holds back the calls behind it (they wait in the queue,
// and are told busy past it). A pool of workers is for when that is measured to matter (T-0812).

use super::*;
use kith_dm_sys::{MOST_FDS, recv_fds, send_fds, socketpair};
use std::io::ErrorKind;
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixDatagram;
use std::sync::OnceLock;
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

/// How long the serving part waits for the root part's answer to one call (an unpack: ten times).
pub const DEADLINE: Duration = Duration::from_secs(30);

/// The root part of this node as a second end of a socket pair, once `--split` has made one:
/// what [`Direct::new`] and [`Direct::today`] send a request to, in place of acting on it.
pub static SPLIT: OnceLock<Socket> = OnceLock::new();

/// What a peer may take of the root part's time and memory.
pub struct Limits {
    /// Requests read and not yet begun.
    pub queue: usize,
    /// How long one waits in the queue before it is refused as too old to be wanted.
    pub wait: Duration,
    /// How long the peer has to take one reply.
    pub reply: Duration,
    /// Messages in a row that are no request before the peer is closed.
    pub bad: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            queue: 16,
            wait: DEADLINE,
            reply: Duration::from_secs(10),
            bad: 8,
        }
    }
}

/// One call, as the serving part sends it. `seq` is the serving part's own count: the reply to
/// it carries it back, so that a reply that came late is not taken for the next call's.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ask {
    seq: u64,
    call: Call,
}

/// What is asked. The files beside the message: a `Create` and an `Exec` bring the unit's output
/// and error (two), a `Create` also the descriptor of each volume it holds (`volumes`: which of
/// the unit's mounts, in order, each after the two), an `Unpack` its layers, and nothing else any.
#[derive(Serialize, Deserialize)]
enum Call {
    Request(Request),
    Create {
        id: String,
        image: Box<Image>,
        unit: Unit,
        volumes: Vec<usize>,
    },
    Exec {
        id: String,
        unit: Unit,
    },
    Adopt,
    Start {
        id: String,
        mark: String,
    },
}

/// The root part's word on one call. `kept`: a `Delete` that failed and left the unit, which the
/// caller's handle still is.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Back {
    seq: u64,
    kept: bool,
    said: Result<Answer, String>,
}

/// [`Reply`] on the wire, with the descriptors a reply has beside the message and what a unit's
/// verb gives back.
#[derive(Serialize, Deserialize)]
enum Answer {
    Done,
    /// A Volume's directory as it was taken, with its descriptor beside the message: the path is
    /// for the peer to read, the descriptor is what it uses.
    Dir(PathBuf),
    Usage(Option<(u64, u64, u64)>),
    Freed(Option<u64>),
    Packages(crate::scan::Found),
    /// One descriptor beside the message.
    Socket,
    /// This many descriptors beside the message.
    Sockets(usize),
    Pod(Given),
    Key(kith_mesh::Key),
    Seen(Vec<kith_mesh::Seen>),
    /// What could not be written of a unit's arrangement.
    Notes(Vec<String>),
    /// The units taken back, by id with the mark each was started as.
    Adopted(BTreeMap<String, String>),
}

/// A unit made at the root part, as the serving part has it: the id alone (the handle is the
/// root part's own, and is asked of by this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held(pub String);

/// The serving part's end: [`Root`] for a root part that is on the other side of a socket pair.
pub struct Socket {
    end: UnixDatagram,
    /// The count of calls, held for the whole of one: a call is the only one in flight.
    call: Mutex<u64>,
    /// (The tests set it, to make a call give up while a slow one is done.)
    pub(super) deadline: Duration,
    /// The least time a call may have left once it holds the lock: with less, a unit made or
    /// started would be done at the root part with no one left to hear it. (The tests set it.)
    pub(super) floor: Duration,
}

impl Socket {
    pub fn new(end: OwnedFd, deadline: Duration) -> Socket {
        let end = UnixDatagram::from(end);
        // (A refusal leaves a send that waits; the peer's end is the one that is not trusted.)
        let _ = end.set_write_timeout(Some(deadline));
        Socket {
            end,
            call: Mutex::new(0),
            deadline,
            floor: Duration::from_secs(1),
        }
    }

    /// This end, and the root part's to give to [`serve`].
    pub fn pair(deadline: Duration) -> std::io::Result<(Socket, OwnedFd)> {
        let (mine, theirs) = socketpair()?;
        Ok((Socket::new(mine, deadline), theirs))
    }

    /// This end closed both ways: the root part's read ends and it returns, as it does when the
    /// serving part is gone. (The `confine-probe` build's way to end the root part alone.)
    #[cfg(feature = "confine-probe")]
    pub fn hangup(&self) {
        let _ = self.end.shutdown(Shutdown::Both);
    }

    /// The call lock, held: a call in flight that does not end. (For the tests.)
    #[cfg(test)]
    pub(super) fn stuck(&self) -> std::sync::MutexGuard<'_, u64> {
        self.call.lock().unwrap()
    }

    /// One call: sent with `fds` beside it, and the answer to it (and its descriptors) waited for
    /// as long as `wait`. A reply to an earlier call, that gave up, is read and let go.
    fn ask(&self, call: Call, fds: &[BorrowedFd], wait: Duration) -> Result<(Back, Vec<OwnedFd>), String> {
        // (One time for the whole call: the wait for the call in flight, a stuck one holds the lock,
        // and the wait for the answer share `wait`, and the send is bounded by the socket's own.)
        let until = Instant::now() + wait;
        // ponytail: a 5 ms poll of try_lock (std's Mutex has no timed lock); it runs only under
        // --split, and one call waits at most `wait`. A Condvar with a timeout if the polling shows.
        let mut count = loop {
            match self.call.try_lock() {
                Ok(count) => break count,
                Err(std::sync::TryLockError::Poisoned(e)) => break e.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    return Err("the root part's call in flight did not end in time".into());
                }
            }
        };
        // (A call whose lock came near its deadline sends nothing: a Create, Start or Unpack sent
        // now is done at the root part while this one gives up, and the unit is left unheld.)
        // The floor is no more than half of `wait`, so a short wait is not refused always.
        if until.saturating_duration_since(Instant::now()) < self.floor.min(wait / 2) {
            return Err("the root part's call in flight ended too late to send this one".into());
        }
        *count += 1;
        let seq = *count;
        let bytes = serde_json::to_vec(&Ask { seq, call }).map_err(|e| format!("the root part's request: {e}"))?;
        if bytes.len() > MAX_REQUEST {
            return Err(format!("request of {} bytes: at most {MAX_REQUEST}", bytes.len()));
        }
        send_fds(self.end.as_fd(), &bytes, fds).map_err(|e| format!("asking the root part: {e}"))?;
        let mut buf = vec![0u8; MAX_REQUEST];
        loop {
            let left = until
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or("the root part did not answer in time")?;
            self.end
                .set_read_timeout(Some(left))
                .map_err(|e| format!("the root part's socket: {e}"))?;
            match recv_fds(self.end.as_fd(), &mut buf, MOST_FDS) {
                Ok((0, _)) => return Err("the root part closed the socket".into()),
                Ok((n, fds)) => match serde_json::from_slice::<Back>(&buf[..n]) {
                    Ok(back) if back.seq == seq => return Ok((back, fds)),
                    // (An answer to a call that gave up: its descriptors are closed here.)
                    Ok(_) => {}
                    Err(e) => return Err(format!("the root part's answer: {e}")),
                },
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Err("the root part did not answer in time".into());
                }
                Err(e) => return Err(format!("the root part's answer: {e}")),
            }
        }
    }

    /// A call that brings no file and takes none back.
    fn said(&self, call: Call) -> Result<Answer, String> {
        self.ask(call, &[], self.deadline)?.0.said
    }

    /// `made` is the unit `id`: what is asked of by an id is not done to another unit's.
    fn bound(made: &Held, id: &str) -> Result<(), String> {
        match made.0 == id {
            true => Ok(()),
            false => Err(format!("this handle is not the unit `{id}`")),
        }
    }

    /// A unit made at the root part by `call`, with `fds` for its output and error.
    fn made(&self, call: Call, fds: &[BorrowedFd], id: &str) -> Result<Held, String> {
        match self.ask(call, fds, self.deadline)?.0.said? {
            Answer::Done => Ok(Held(id.into())),
            _ => Err("the root part answered a creation with another reply".into()),
        }
    }
}

/// What came back as [`Reply`], with the descriptors that came beside it: each answer takes as
/// many as it says, and a reply with another number is no reply.
fn reply(answer: Answer, fds: Vec<OwnedFd>) -> Result<Reply, String> {
    let odd = || "the root part's reply came with the wrong files".to_string();
    Ok(match answer {
        Answer::Socket => match <[OwnedFd; 1]>::try_from(fds) {
            Ok([fd]) => Reply::Socket(fd),
            Err(_) => return Err(odd()),
        },
        Answer::Dir(real) => match <[OwnedFd; 1]>::try_from(fds) {
            Ok([fd]) => Reply::Dir(crate::volumes::VolumeDir::from_parts(fd, real)),
            Err(_) => return Err(odd()),
        },
        Answer::Sockets(n) if n == fds.len() => Reply::Sockets(fds),
        Answer::Sockets(_) => return Err(odd()),
        _ if !fds.is_empty() => return Err(odd()),
        Answer::Done => Reply::Done,
        Answer::Usage(usage) => Reply::Usage(usage),
        Answer::Freed(freed) => Reply::Freed(freed),
        Answer::Packages(found) => Reply::Packages(found),
        Answer::Pod(given) => Reply::Pod(given),
        Answer::Key(key) => Reply::Key(key),
        Answer::Seen(seen) => Reply::Seen(seen),
        Answer::Notes(_) | Answer::Adopted(_) => {
            return Err("the root part answered a request with a unit's reply".into());
        }
    })
}

impl Root for Socket {
    type Made = Held;

    fn request(&self, request: Request) -> Result<Reply, String> {
        self.request_with(request, Vec::new())
    }

    fn request_with(&self, request: Request, files: Vec<File>) -> Result<Reply, String> {
        let wait = match request {
            Request::Unpack { .. } => self.deadline * 10,
            _ => self.deadline,
        };
        let fds: Vec<BorrowedFd> = files.iter().map(File::as_fd).collect();
        let (back, fds) = self.ask(Call::Request(request), &fds, wait)?;
        reply(back.said?, fds)
    }

    fn create(&self, create: Create) -> Result<Held, String> {
        let Create {
            id,
            image,
            unit,
            out,
            err,
        } = create;
        // A held volume's descriptor goes beside the unit (it is no JSON): the root part is handed
        // the directory itself, and the path in the unit is only a name for it.
        let held: Vec<(usize, BorrowedFd)> = unit
            .mounts
            .iter()
            .enumerate()
            .filter_map(|(n, mount)| mount.held.as_ref().map(|held| (n, held.fd())))
            .collect();
        if held.len() > MOST_FDS - 2 {
            return Err(format!(
                "a unit holds {} volumes, more than one call may bring",
                held.len()
            ));
        }
        let call = Call::Create {
            id: id.into(),
            image: Box::new(image.clone()),
            unit: unit.clone(),
            volumes: held.iter().map(|(n, _)| *n).collect(),
        };
        let fds: Vec<BorrowedFd> = [out.as_fd(), err.as_fd()]
            .into_iter()
            .chain(held.iter().map(|(_, fd)| *fd))
            .collect();
        self.made(call, &fds, id)
    }

    fn exec(&self, id: &str, unit: &Unit, out: File, err: File) -> Result<Held, String> {
        let call = Call::Exec {
            id: id.into(),
            unit: unit.clone(),
        };
        self.made(call, &[out.as_fd(), err.as_fd()], id)
    }

    fn adopt(&self) -> BTreeMap<String, (Held, String)> {
        match self.said(Call::Adopt) {
            Ok(Answer::Adopted(taken)) => taken
                .into_iter()
                .map(|(id, mark)| (id.clone(), (Held(id), mark)))
                .collect(),
            Ok(_) => {
                eprintln!("kithd: the root part answered an adopt with another reply");
                BTreeMap::new()
            }
            Err(why) => {
                eprintln!("kithd: taking units back from the root part: {why}");
                BTreeMap::new()
            }
        }
    }

    fn start(&self, made: Held, id: &str, mark: &str) -> Result<Held, (Held, String)> {
        let asked = Socket::bound(&made, id).and_then(|()| {
            self.said(Call::Start {
                id: id.into(),
                mark: mark.into(),
            })
        });
        match asked {
            Ok(_) => Ok(made),
            Err(why) => Err((made, why)),
        }
    }

    fn kill(&self, made: &mut Held, id: &str) -> Result<(), String> {
        Socket::bound(made, id)?;
        self.said(Call::Request(Request::Kill { id: id.into() })).map(drop)
    }

    fn delete(&self, made: Held, id: &str) -> Result<(), (Option<Held>, String)> {
        if let Err(why) = Socket::bound(&made, id) {
            return Err((Some(made), why));
        }
        // (A call that got no answer may or may not have deleted: the handle is kept to ask again.)
        match self.ask(Call::Request(Request::Delete { id: id.into() }), &[], self.deadline) {
            Ok((Back { said: Ok(_), .. }, _)) => Ok(()),
            Ok((
                Back {
                    said: Err(why), kept, ..
                },
                _,
            )) => Err((kept.then_some(made), why)),
            Err(why) => Err((Some(made), why)),
        }
    }

    fn tune(
        &self,
        made: &Held,
        id: &str,
        guaranteed: Option<u64>,
        cpu_millis: Option<u64>,
        idle: Option<Idle>,
    ) -> Result<Vec<String>, String> {
        Socket::bound(made, id)?;
        let tune = Request::Tune {
            id: id.into(),
            guaranteed,
            cpu_millis,
            idle,
        };
        match self.said(Call::Request(tune))? {
            Answer::Notes(notes) => Ok(notes),
            _ => Err("the root part answered a tune with another reply".into()),
        }
    }

    fn plug(&self, made: &Held, id: &str, device: &Path) -> Result<(), String> {
        Socket::bound(made, id)?;
        let (id, device) = (id.into(), device.into());
        self.said(Call::Request(Request::Plug { id, device })).map(drop)
    }

    fn unplug(&self, made: &Held, id: &str, device: &Path) -> Result<(), String> {
        Socket::bound(made, id)?;
        let (id, device) = (id.into(), device.into());
        self.said(Call::Request(Request::Unplug { id, device })).map(drop)
    }
}

/// One message read, and when.
struct Job {
    ask: Ask,
    fds: Vec<OwnedFd>,
    at: Instant,
}

/// Closes the socket (both ways) when it goes: the other thread's read ends, and so does the peer's.
struct Hangup<'a>(&'a UnixDatagram);

impl Drop for Hangup<'_> {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

/// One reply sent (its descriptors beside it), within the socket's send timeout.
fn tell(end: &UnixDatagram, back: &Back, fds: &[OwnedFd]) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(back).map_err(std::io::Error::other)?;
    if bytes.len() > MAX_REQUEST {
        let said = Err(format!("a reply of {} bytes: at most {MAX_REQUEST}", bytes.len()));
        let long = Back {
            seq: back.seq,
            kept: back.kept,
            said,
        };
        let bytes = serde_json::to_vec(&long).map_err(std::io::Error::other)?;
        return send_fds(end.as_fd(), &bytes, &[]);
    }
    let fds: Vec<BorrowedFd> = fds.iter().map(AsFd::as_fd).collect();
    send_fds(end.as_fd(), &bytes, &fds)
}

/// The reader: each message of the peer, whole, onto the queue; one that finds the queue full is
/// told so here, and one that is no request is told and counted. Ends, and closes the socket, when
/// the peer has gone, when too many in a row were no request, or when a reply could not be sent.
fn read(end: &UnixDatagram, queue: SyncSender<Job>, limits: &Limits) {
    let _hangup = Hangup(end);
    let mut buf = vec![0u8; MAX_REQUEST];
    let mut bad = 0;
    loop {
        // (The seq a refusal is told under: the message's own when it was read, else 0.)
        let mut seq = 0;
        let why = match recv_fds(end.as_fd(), &mut buf, MOST_FDS) {
            Ok((0, _)) => return,
            Ok((n, fds)) => match serde_json::from_slice::<Ask>(&buf[..n]) {
                // (More files than the call takes: refused here, closed with `fds`, not queued
                // holding them; counted as a bad message.)
                Ok(ask) if fds.len() > most_fds(&ask.call) => {
                    seq = ask.seq;
                    format!(
                        "{} files come with a call that takes at most {}",
                        fds.len(),
                        most_fds(&ask.call)
                    )
                }
                Ok(ask) => {
                    bad = 0;
                    match queue.try_send(Job {
                        ask,
                        fds,
                        at: Instant::now(),
                    }) {
                        Ok(()) => continue,
                        Err(TrySendError::Full(job)) => {
                            let said = Err("the root part is busy: its queue is full".into());
                            let back = Back {
                                seq: job.ask.seq,
                                kept: false,
                                said,
                            };
                            match tell(end, &back, &[]) {
                                Ok(()) => continue,
                                Err(_) => return,
                            }
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    }
                }
                Err(e) => format!("request: {e}"),
            },
            // (Longer than the room, or with more descriptors than may come: closed whole.)
            Err(e) if e.kind() == ErrorKind::InvalidData => format!("request: {e}"),
            Err(_) => return,
        };
        bad += 1;
        let back = Back {
            seq,
            kept: false,
            said: Err(why),
        };
        if tell(end, &back, &[]).is_err() || bad >= limits.bad {
            return;
        }
    }
}

/// What one call came to: the answer or what refused it, the descriptors that go beside it, and
/// whether the unit is still here (a `Delete` that failed).
struct Out {
    said: Result<Answer, String>,
    fds: Vec<OwnedFd>,
    kept: bool,
}

impl Out {
    fn ok(answer: Answer) -> Out {
        Out {
            said: Ok(answer),
            fds: Vec::new(),
            kept: false,
        }
    }

    fn err(why: impl Into<String>) -> Out {
        Out {
            said: Err(why.into()),
            fds: Vec::new(),
            kept: false,
        }
    }

    fn of<T>(done: Result<T, String>, answer: impl FnOnce(T) -> Answer) -> Out {
        done.map_or_else(Out::err, |done| Out::ok(answer(done)))
    }
}

/// The two files of a `Create` or an `Exec`: the unit's output and its error, and no others.
/// Each is a regular file, a pipe or a socket: not a directory, nor a device node, which a unit's
/// output is never and which the runtime would write to.
fn two(fds: Vec<OwnedFd>) -> Result<(File, File), String> {
    use std::os::unix::fs::FileTypeExt;
    let [out, err] =
        <[OwnedFd; 2]>::try_from(fds).map_err(|fds| format!("a unit comes with two files, not {}", fds.len()))?;
    let (out, err) = (File::from(out), File::from(err));
    for file in [&out, &err] {
        let kind = file
            .metadata()
            .map_err(|e| format!("a unit's output: {e}"))?
            .file_type();
        if !(kind.is_file() || kind.is_fifo() || kind.is_socket()) {
            return Err("a unit's output is not a file, a pipe or a socket".into());
        }
    }
    Ok((out, err))
}

/// The directories that came with a `Create`, one for each mount of `volumes` (strictly rising,
/// each a mount the unit has), put in the mounts as what they are held by. Each is a directory:
/// anything else is not a volume. Whether it is the directory its mount names is `check_mount`'s.
fn take_held(unit: &mut Unit, volumes: &[usize], dirs: Vec<OwnedFd>) -> Result<(), String> {
    if volumes.len() != dirs.len() {
        return Err(format!(
            "a unit names {} held volumes and brings {} directories",
            volumes.len(),
            dirs.len()
        ));
    }
    let mut last = None;
    for (n, dir) in volumes.iter().zip(dirs) {
        if last.is_some_and(|last| last >= *n) {
            return Err("a unit's held volumes are not each a mount of its own, in order".into());
        }
        last = Some(*n);
        let Some(mount) = unit.mounts.get_mut(*n) else {
            return Err(format!("a unit holds volume {n} and has {} mounts", unit.mounts.len()));
        };
        let file = File::from(dir);
        if !file.metadata().map_err(|e| format!("a held volume: {e}"))?.is_dir() {
            return Err(format!(
                "the held volume at `{}` is not a directory",
                mount.container.escape_debug()
            ));
        }
        mount.held = Some(kith_runtime::Held::new(file.into()));
    }
    Ok(())
}

/// How many descriptors a call may come with: two for a unit's output and error (and a directory
/// for each volume a create holds), a layer each for an unpack, none for the rest.
fn most_fds(call: &Call) -> usize {
    match call {
        Call::Create { volumes, .. } => 2 + volumes.len(),
        Call::Exec { .. } => 2,
        Call::Request(Request::Unpack { .. }) => MOST_LAYERS,
        _ => 0,
    }
}

/// One call done by `root`, which holds the units it made (by id) in `held`.
fn handle<H: Hands>(root: &Direct<H>, held: &mut BTreeMap<String, H::Made>, call: Call, fds: Vec<OwnedFd>) -> Out {
    match call {
        Call::Create {
            id,
            image,
            mut unit,
            volumes,
        } => {
            let mut fds = fds;
            if fds.len() < 2 + volumes.len() {
                return Out::err(format!(
                    "a unit comes with two files and a directory for each held volume, not {}",
                    fds.len()
                ));
            }
            let dirs = fds.split_off(2);
            let (out, err) = match two(fds) {
                Ok(files) => files,
                Err(why) => return Out::err(why),
            };
            if let Err(why) = take_held(&mut unit, &volumes, dirs) {
                return Out::err(why);
            }
            if held.contains_key(&id) {
                return Out::err(format!("`{id}` is a unit held here already"));
            }
            let create = Create {
                id: &id,
                image: &image,
                unit: &unit,
                out,
                err,
            };
            Out::of(root.create(create), |made| {
                held.insert(id, made);
                Answer::Done
            })
        }
        Call::Exec { id, unit } => {
            let (out, err) = match two(fds) {
                Ok(files) => files,
                Err(why) => return Out::err(why),
            };
            if held.contains_key(&id) {
                return Out::err(format!("`{id}` is a unit held here already"));
            }
            Out::of(root.exec(&id, &unit, out, err), |made| {
                held.insert(id, made);
                Answer::Done
            })
        }
        _ if !fds.is_empty() && !matches!(call, Call::Request(Request::Unpack { .. })) => {
            Out::err("only an unpack, a create and an exec come with files")
        }
        Call::Adopt => {
            let mut marks = BTreeMap::new();
            for (id, (made, mark)) in root.adopt() {
                marks.insert(id.clone(), mark);
                held.insert(id, made);
            }
            Out::ok(Answer::Adopted(marks))
        }
        Call::Start { id, mark } => {
            let Some(made) = held.remove(&id) else {
                return Out::err(format!("no unit `{id}` is held here"));
            };
            match root.start(made, &id, &mark) {
                Ok(made) => {
                    held.insert(id, made);
                    Out::ok(Answer::Done)
                }
                // (Not started: it is still a unit here, and the caller deletes it.)
                Err((made, why)) => {
                    held.insert(id, made);
                    Out::err(why)
                }
            }
        }
        Call::Request(request) => unit_or_request(root, held, request, fds),
    }
}

/// A request: of the Units family, done with the handle held for the id (a unit that is not held
/// is asked as a request, which counts and refuses it as [`Direct`] does); any other, as it is.
fn unit_or_request<H: Hands>(
    root: &Direct<H>,
    held: &mut BTreeMap<String, H::Made>,
    request: Request,
    fds: Vec<OwnedFd>,
) -> Out {
    let id = match &request {
        Request::Kill { id }
        | Request::Delete { id }
        | Request::Tune { id, .. }
        | Request::Plug { id, .. }
        | Request::Unplug { id, .. } => Some(id.clone()),
        _ => None,
    };
    if let Some(id) = id {
        let Some(mut made) = held.remove(&id) else {
            // (The same count, check and refusal as for a unit this part did not make.)
            return Out::err(
                root.request(request)
                    .err()
                    .unwrap_or_else(|| format!("no unit `{id}` is held here")),
            );
        };
        let out = match request {
            Request::Kill { .. } => Out::of(root.kill(&mut made, &id), |()| Answer::Done),
            Request::Tune {
                guaranteed,
                cpu_millis,
                idle,
                ..
            } => Out::of(root.tune(&made, &id, guaranteed, cpu_millis, idle), Answer::Notes),
            Request::Plug { device, .. } => Out::of(root.plug(&made, &id, &device), |()| Answer::Done),
            Request::Unplug { device, .. } => Out::of(root.unplug(&made, &id, &device), |()| Answer::Done),
            _ => {
                // A delete: the handle comes back only if the unit is still here.
                return match root.delete(made, &id) {
                    Ok(()) => Out::ok(Answer::Done),
                    Err((Some(made), why)) => {
                        held.insert(id, made);
                        Out {
                            kept: true,
                            ..Out::err(why)
                        }
                    }
                    Err((None, why)) => Out::err(why),
                };
            }
        };
        held.insert(id, made);
        return out;
    }
    let files: Vec<File> = fds.into_iter().map(File::from).collect();
    // A layer is read to its end by the one worker: a pipe or a socket of the peer's would hold it for ever.
    let plain = files
        .iter()
        .all(|file| file.metadata().is_ok_and(|meta| meta.is_file()));
    if matches!(request, Request::Unpack { .. }) && !plain {
        return Out::err("a layer is not a regular file");
    }
    match root.request_with(request, files) {
        Ok(Reply::Socket(fd)) => Out {
            fds: vec![fd],
            ..Out::ok(Answer::Socket)
        },
        Ok(Reply::Sockets(fds)) => Out {
            said: Ok(Answer::Sockets(fds.len())),
            fds,
            kept: false,
        },
        Ok(Reply::Done) => Out::ok(Answer::Done),
        Ok(Reply::Dir(dir)) => {
            let (fd, real) = dir.into_parts();
            Out {
                said: Ok(Answer::Dir(real)),
                fds: vec![fd],
                kept: false,
            }
        }
        Ok(Reply::Usage(usage)) => Out::ok(Answer::Usage(usage)),
        Ok(Reply::Freed(freed)) => Out::ok(Answer::Freed(freed)),
        Ok(Reply::Packages(found)) => Out::ok(Answer::Packages(found)),
        Ok(Reply::Pod(given)) => Out::ok(Answer::Pod(given)),
        Ok(Reply::Key(key)) => Out::ok(Answer::Key(key)),
        Ok(Reply::Seen(seen)) => Out::ok(Answer::Seen(seen)),
        Err(why) => Out::err(why),
    }
}

/// The root part's end of the socket pair: serves `end` with `root` on this thread, until the peer
/// has gone or has been closed on. A reader thread takes each message and one worker (this
/// thread) does them in turn, so one peer holds at most one request, a queue and a reply.
pub fn serve<H: Hands>(root: &Direct<H>, end: OwnedFd, limits: &Limits) {
    let end = UnixDatagram::from(end);
    // The reply's own deadline, for both threads' sends. (If it cannot be set a peer that takes
    // no reply holds a thread: the socket is not served.)
    if end.set_write_timeout(Some(limits.reply)).is_err() {
        return;
    }
    let (queue, jobs) = sync_channel(limits.queue.max(1));
    let mut held: BTreeMap<String, H::Made> = BTreeMap::new();
    std::thread::scope(|scope| {
        let _hangup = Hangup(&end);
        scope.spawn(|| read(&end, queue, limits));
        for Job { ask, fds, at } in jobs {
            let waited = at.elapsed();
            let out = match waited > limits.wait {
                true => Out::err(format!("waited {} s in the queue: past its deadline", waited.as_secs())),
                false => handle(root, &mut held, ask.call, fds),
            };
            let back = Back {
                seq: ask.seq,
                kept: out.kept,
                said: out.said,
            };
            if tell(&end, &back, &out.fds).is_err() {
                break;
            }
        }
    });
}
