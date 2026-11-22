//! The container calls that stream (T-1261): `logs`, `attach` (output only), a `wait` that answers
//! its head first, and `exec`. They write to the connection themselves (see `Containers::stream`).

use super::*;
use crate::stream::json_head;
use std::io::Write;
use std::net::Shutdown;

/// How often a followed log is looked at again, and how many failed reads in a row end it.
const LOG_POLL: Duration = Duration::from_millis(300);
const LOG_FAILS: u32 = 20;
/// How often `attach` looks at a container that is not started yet.
const START_POLL: Duration = Duration::from_millis(100);
/// How long it waits for the start before it lets the client go.
const START_WAIT: Duration = Duration::from_secs(600);

/// What a client of `attach` is told when it asks to send stdin.
const STDIN_REFUSED: &str = "kith: stdin to a container's main process is not supported (kithd starts it with no input and cannot attach to it): leave out -i, or give a command its input with docker exec -i";

/// A container's logs being read: which of its two outputs, each from where it was read to.
struct Tap {
    key: String,
    wants: [bool; 2],
    from: [LogFrom; 2],
}

impl Tap {
    /// What came since the last read, as pieces to send; and why a read failed, if one did.
    /// (ponytail: stdout and stderr are two files, so their interleaving is lost; kithd has no
    /// times to merge them by.)
    fn poll(&mut self, store: &dyn Store) -> (Vec<(Kind, Vec<u8>)>, Option<String>) {
        let (mut pieces, mut failed) = (Vec::new(), None);
        for (i, kind) in [Kind::Stdout, Kind::Stderr].into_iter().enumerate() {
            if !self.wants[i] {
                continue;
            }
            match store.logs(&self.key, i == 1, self.from[i]) {
                Ok(chunk) => {
                    self.from[i] = LogFrom::Offset(chunk.next);
                    if !chunk.data.is_empty() {
                        pieces.push((kind, chunk.data));
                    }
                }
                Err(e) => failed = Some(e),
            }
        }
        (pieces, failed)
    }
}

fn tty(doc: &Value) -> bool {
    annotation(doc, ANN_TTY) == "1"
}

/// `stdout=1&stderr=1` as the two flags; neither is a mistake of the client's.
fn wanted(query: &str) -> Result<[bool; 2], Reply> {
    let wants = [flag(query, "stdout"), flag(query, "stderr")];
    if wants == [false, false] {
        return Err(message(400, "you must choose at least one stream"));
    }
    Ok(wants)
}

fn hijacked(reader: &BufReader<Clocked>, tty: bool) -> Result<(UnixStream, Writer<UnixStream>), Reply> {
    let stream = reader
        .get_ref()
        .stream
        .try_clone()
        .map_err(|e| message(500, e.to_string()))?;
    let out = stream.try_clone().map_err(|e| message(500, e.to_string()))?;
    Ok((stream, Writer::new(out, Carrier::Hijack, tty)))
}

impl Containers {
    fn tap(&self, doc: &Value, wants: [bool; 2], from: LogFrom) -> Tap {
        let kind = doc["kind"].as_str().unwrap_or("Workload");
        Tap {
            key: key(kind, name_of(doc)),
            wants,
            from: [from; 2],
        }
    }

    /// Send what the container writes: what is there, and, with `follow`, what comes until it stops
    /// (or the client hangs up). A write that fails means the client is gone.
    fn follow(
        &self,
        name: &str,
        tap: &mut Tap,
        follow: bool,
        out: &mut Writer<UnixStream>,
        reader: &mut BufReader<Clocked>,
        hijack: bool,
    ) {
        let (mut fails, mut last) = (0, false);
        loop {
            let (pieces, failed) = tap.poll(&*self.store);
            fails = if failed.is_some() { fails + 1 } else { 0 };
            let more = !pieces.is_empty();
            for (kind, data) in pieces {
                if out.put(kind, &data).is_err() {
                    return;
                }
            }
            if more {
                continue;
            }
            if !follow || fails >= LOG_FAILS || if hijack { broken(reader) } else { hung_up(reader) } {
                return;
            }
            let running = match self.find(name) {
                Ok(doc) => state(&doc).running,
                Err(gone) if gone.status == 404 => return,
                Err(_) => {
                    fails += 1;
                    true
                }
            };
            if !running {
                // One more look when it has stopped: its last words may come after its state does.
                if last {
                    return;
                }
                last = true;
                continue;
            }
            last = false;
            std::thread::sleep(LOG_POLL);
        }
    }

    /// `GET /containers/{id}/logs`: a chunked answer of the container's output, `follow` until it stops.
    pub(super) fn logs(&self, id: &str, query: &str, reader: &mut BufReader<Clocked>) -> Result<(), Reply> {
        let doc = self.find(id)?;
        let wants = wanted(query)?;
        let unsupported = |k| param(query, k).is_some_and(|v| !v.is_empty() && v != "0");
        if flag(query, "timestamps") || unsupported("since") || unsupported("until") {
            return Err(message(
                501,
                "kith: log timestamps, --since and --until are not supported (what kithd keeps has no times)",
            ));
        }
        let from = match param(query, "tail") {
            None | Some("" | "all") => LogFrom::Start,
            Some(n) => LogFrom::Tail(
                n.parse()
                    .map_err(|_| message(400, format!("invalid tail value: {n}")))?,
            ),
        };
        let follow = flag(query, "follow");
        let st = state(&doc);
        let mut tap = self.tap(&doc, wants, from);
        // The first read is before the head, so a failure of it can still be a 500; where there is
        // simply nothing yet (never started) or it may come (running, followed), it is not one.
        let (first, failed) = tap.poll(&*self.store);
        if let Some(e) = failed.filter(|_| !(st.status == "created" || follow && st.running)) {
            return Err(message(500, e));
        }
        let stream = reader
            .get_ref()
            .stream
            .try_clone()
            .map_err(|e| message(500, e.to_string()))?;
        let mut out = Writer::new(stream, Carrier::Chunked, tty(&doc));
        if out.start().is_err() {
            return Ok(());
        }
        for (kind, data) in first {
            if out.put(kind, &data).is_err() {
                return Ok(());
            }
        }
        self.follow(name_of(&doc), &mut tap, follow, &mut out, reader, false);
        let _ = out.finish();
        Ok(())
    }

    /// `POST /containers/{id}/attach`: the output of a container as it is written. `docker run` asks
    /// before it starts the container, and waits for the answer's head: it is sent at once, and the
    /// output follows the start. Stdin is refused.
    pub(super) fn attach(&self, id: &str, query: &str, reader: &mut BufReader<Clocked>) -> Result<(), Reply> {
        let doc = self.find(id)?;
        if flag(query, "stdin") {
            return Err(message(501, STDIN_REFUSED));
        }
        let wants = wanted(query)?;
        let (stream, mut out) = hijacked(reader, tty(&doc))?;
        if out.start().is_err() {
            return Ok(());
        }
        let name = name_of(&doc).to_string();
        let st = state(&doc);
        let mut doc = doc;
        let from = if st.status == "created" {
            let started = starts(&doc);
            // ponytail: a client that left while it waits shows only by this ceiling (nothing is
            // written to it); a probe frame would end it sooner.
            let until = Instant::now() + START_WAIT;
            loop {
                if broken(reader) || Instant::now() > until {
                    return Ok(());
                }
                match self.find(&name) {
                    // (The started container is another resource: a Job made of the Workload that was created.)
                    Ok(now) if starts(&now) > started => {
                        doc = now;
                        break;
                    }
                    Err(gone) if gone.status == 404 => {
                        let _ = stream.shutdown(Shutdown::Both);
                        return Ok(());
                    }
                    _ => std::thread::sleep(START_POLL),
                }
            }
            Some(LogFrom::Start)
        } else if st.running {
            Some(if flag(query, "logs") {
                LogFrom::Start
            } else {
                LogFrom::Tail(0)
            })
        } else {
            flag(query, "logs").then_some(LogFrom::Start)
        };
        if let Some(from) = from {
            let mut tap = self.tap(&doc, wants, from);
            self.follow(&name, &mut tap, true, &mut out, reader, true);
        }
        let _ = stream.shutdown(Shutdown::Both);
        Ok(())
    }

    /// `POST /containers/{id}/wait?condition=next-exit`: the container's code at its next exit, which
    /// is the one it is running toward, or, when it is not running, the one after it is started.
    /// The head is sent first: the client waits for it before it starts the container.
    pub(super) fn wait_next(&self, id: &str, reader: &mut BufReader<Clocked>) -> Result<(), Reply> {
        let doc = self.find(id)?;
        let name = name_of(&doc).to_string();
        let after = (!state(&doc).running).then(|| starts(&doc));
        let mut stream = reader
            .get_ref()
            .stream
            .try_clone()
            .map_err(|e| message(500, e.to_string()))?;
        if stream.write_all(&json_head()).and_then(|()| stream.flush()).is_err() {
            return Ok(());
        }
        let mut gone = || hung_up(reader);
        // (An Err is the client hanging up, or the store failing: there is no one to say it to, or no head to say it in.)
        if let Ok(code) = self.exit_of(&name, after, &mut gone) {
            let _ = stream.write_all(wait_json(code).as_bytes());
        }
        let _ = stream.shutdown(Shutdown::Both);
        Ok(())
    }

    /// `POST /containers/{id}/exec`: a command to run in the container, which has to be running.
    pub(super) fn exec_create(&self, id: &str, body: &[u8]) -> Out {
        let doc = self.find(id)?;
        let name = name_of(&doc).to_string();
        let config: Value = if body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(body).map_err(|e| message(400, format!("kith: the exec body is not JSON: {e}")))?
        };
        if ["Env", "WorkingDir", "User", "Privileged"]
            .iter()
            .any(|f| set(&config[*f]))
        {
            return Err(message(
                501,
                "kith: exec runs the command as the container does: --env, --workdir, --user and --privileged are not supported",
            ));
        }
        let command = string_list(&config["Cmd"], "Cmd")?;
        if command.is_empty() {
            return Err(message(400, "No exec command specified"));
        }
        if !state(&doc).running {
            return Err(message(409, format!("Container {name} is not running")));
        }
        // The unit kithd runs: a Workload's first copy, or a Job's first run.
        let pod = if doc["kind"] == "Job" {
            format!("{name}-j0")
        } else {
            format!("{name}-0")
        };
        let exec_id = sha256_hex(&[
            name.as_bytes(),
            b"\0exec\0",
            &self.made.fetch_add(1, Ordering::SeqCst).to_be_bytes(),
            &now_nanos().to_be_bytes(),
        ]);
        let exec = Exec {
            container: name,
            pod,
            command,
            tty: config["Tty"].as_bool() == Some(true),
            stdin: config["AttachStdin"].as_bool() == Some(true),
            started: false,
            exit: None,
            size: None,
            input: None,
        };
        let mut execs = self.execs();
        if execs.len() >= MAX_EXECS {
            // The ones that ended go first.
            let done = execs.iter().find(|(_, e)| e.exit.is_some()).map(|(k, _)| k.clone());
            match done {
                Some(done) => {
                    execs.remove(&done);
                }
                None => return Err(message(503, "kith: too many execs are running")),
            }
        }
        execs.insert(exec_id.clone(), exec);
        Ok(json_reply(201, json!({"Id": exec_id}).to_string()))
    }

    /// `POST /exec/{id}/resize?h=&w=`: the terminal's size, now or when the command has started.
    pub(super) fn exec_resize(&self, id: &str, query: &str) -> Out {
        let size = |k| param(query, k).and_then(|v| v.parse::<u16>().ok());
        let (Some(height), Some(width)) = (size("h"), size("w")) else {
            return Err(message(400, "kith: h and w must be numbers"));
        };
        let mut execs = self.execs();
        let Some(exec) = execs.get_mut(id) else {
            return Err(message(404, format!("No such exec instance: {id}")));
        };
        match &exec.input {
            Some(input) => {
                let _ = input.send(Input::Resize(width, height));
            }
            None => exec.size = Some((width, height)),
        }
        Ok(empty(200))
    }

    /// `GET /exec/{id}/json`: whether it runs, and the code it ended with.
    pub(super) fn exec_inspect(&self, id: &str) -> Out {
        let execs = self.execs();
        let Some(exec) = execs.get(id) else {
            return Err(message(404, format!("No such exec instance: {id}")));
        };
        let words = &exec.command;
        Ok(json_reply(
            200,
            json!({
                "ID": id,
                "Running": exec.started && exec.exit.is_none(),
                "ExitCode": exec.exit.unwrap_or(0),
                "ProcessConfig": {
                    "tty": exec.tty,
                    "entrypoint": words[0],
                    "arguments": &words[1..],
                    "privileged": false,
                    "user": "",
                },
                "OpenStdin": exec.stdin,
                "OpenStderr": !exec.tty,
                "OpenStdout": true,
                "CanRemove": false,
                "ContainerID": container_id(NAMESPACE, &exec.container),
                "DetachKeys": "",
                "Pid": 0,
            })
            .to_string(),
        ))
    }

    /// `POST /exec/{id}/start`: runs the command, and the connection is its terminal: its output
    /// goes out, what the client sends goes in. The code is kept before the connection closes, so
    /// the `inspect` that follows it finds it.
    pub(super) fn exec_start(&self, id: &str, body: &[u8], reader: &mut BufReader<Clocked>) -> Result<(), Reply> {
        let config: Value = if body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(body).map_err(|e| message(400, format!("kith: the exec body is not JSON: {e}")))?
        };
        if config["Detach"].as_bool() == Some(true) {
            return Err(message(
                501,
                "kith: docker exec -d is not supported: the command's output has nowhere to go",
            ));
        }
        let (pod, command, tty, stdin, size) = {
            let mut execs = self.execs();
            let Some(exec) = execs.get_mut(id) else {
                return Err(message(404, format!("No such exec instance: {id}")));
            };
            if exec.started {
                return Err(message(409, format!("Exec command {id} already started")));
            }
            exec.started = true;
            (exec.pod.clone(), exec.command.clone(), exec.tty, exec.stdin, exec.size)
        };
        let undo = |e: Reply| {
            if let Some(exec) = self.execs().get_mut(id) {
                exec.started = false;
            }
            e
        };
        let session = self
            .store
            .exec(&pod, &command, tty, stdin)
            .map_err(|e| undo(message(500, e)))?;
        let Session { events, input } = session;
        let (stream, mut out) = hijacked(reader, tty)
            .inspect_err(|_| {
                let _ = input.send(Input::Close);
            })
            .map_err(undo)?;
        if let Some((width, height)) = size {
            let _ = input.send(Input::Resize(width, height));
        }
        if let Some(exec) = self.execs().get_mut(id) {
            exec.input = Some(input.clone());
        }
        let mut code = 1;
        if out.start().is_ok() {
            reader.get_mut().until = Instant::now() + super::super::NEVER;
            std::thread::scope(|scope| {
                // What the client sends is the command's input. Its end is the end of the command's
                // input (a client half-closes and goes on reading); with no stdin wanted, the end is
                // no hang-up either (`docker exec` without -i half-closes at once): the command ends
                // on its own, or when a write to the gone client fails, or on a read error.
                scope.spawn(|| {
                    let mut buf = [0u8; 8192];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) => {
                                if stdin {
                                    let _ = input.send(Input::End);
                                }
                                break;
                            }
                            Ok(n) if stdin => {
                                if input.send(Input::Data(buf[..n].to_vec())).is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => {
                                let _ = input.send(Input::Close);
                                break;
                            }
                        }
                    }
                });
                for event in events.iter() {
                    match event {
                        Event::Out(data) => {
                            if out.put(Kind::Stdout, &data).is_err() {
                                break;
                            }
                        }
                        Event::Err(data) => {
                            if out.put(Kind::Stderr, &data).is_err() {
                                break;
                            }
                        }
                        Event::Done(done) => {
                            code = done;
                            break;
                        }
                        Event::Failed(why) => {
                            let _ = out.put(Kind::Stderr, format!("{why}\r\n").as_bytes());
                            code = 126;
                            break;
                        }
                    }
                }
                self.exec_ended(id, code);
                let _ = input.send(Input::Close);
                // (This is what ends the reader above: its read returns.)
                let _ = stream.shutdown(Shutdown::Both);
            });
        } else {
            self.exec_ended(id, code);
            let _ = input.send(Input::Close);
        }
        Ok(())
    }

    /// The command ended with `code`: kept for `inspect`, and nothing is sent to it any more.
    fn exec_ended(&self, id: &str, code: i64) {
        if let Some(exec) = self.execs().get_mut(id) {
            exec.exit = Some(code);
            exec.input = None;
        }
    }
}

fn now_nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos())
}
