//! The audit log: who changed what, when, and who was refused. One JSON object a line
//! in the node's state directory, written by the node that was asked:
//! `{"at": seconds, "who": "alice", "verb": "apply", "what": ["Workload/web/site"], "ok": true}`
//! and `"error"` with the reason when `ok` is false.
//
// ponytail: each node keeps its own file, of what was asked of it. One log for the
// cluster means writing it through the store (every write twice); ship the files instead.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

/// At this size the file is moved aside (`audit.log.1`; the numbered ones before it move up).
const CAP: u64 = 4 << 20;
/// How many moved-aside files are kept: `audit.log.1` (the newest) to `audit.log.4`.
const KEPT: u32 = 4;
/// Most lines one read gives.
pub const MOST: u64 = 1000;

/// Most of each thing named in an entry: a path is as long as its sender likes.
const LONGEST: usize = 200;
/// Most refusals written in a minute. More are counted, and the count written with the
/// next entry: whoever is refused in a loop does not push what others did out of the log.
const REFUSALS: u32 = 60;

struct Log {
    path: PathBuf,
    /// The minute (of the clock) refusals are being counted in, how many were written
    /// in it, and how many were not written since the last entry.
    minute: u64,
    refused: u32,
    unwritten: u64,
}

pub struct Audit(Mutex<Log>);

impl Audit {
    pub fn new(path: PathBuf) -> Audit {
        Audit(Mutex::new(Log {
            path,
            minute: 0,
            refused: 0,
            unwritten: 0,
        }))
    }

    /// Write down that `who` did `verb` to `what`, or why not.
    // A log that cannot be written is said on stderr and the request goes on: a full disk
    // must not be what keeps an admin from making room.
    pub fn record(&self, who: &impl std::fmt::Display, verb: &str, what: Vec<String>, outcome: Result<(), String>) {
        let at = kith_api::store::now();
        let mut log = self.0.lock().expect("nothing panics holding the audit log");
        if outcome.is_err() {
            if log.minute != at / 60 {
                (log.minute, log.refused) = (at / 60, 0);
            }
            log.refused += 1;
            if log.refused > REFUSALS {
                log.unwritten += 1;
                return;
            }
        }
        let short = |text: &String| match text.char_indices().nth(LONGEST) {
            Some((cut, _)) => format!("{}…", &text[..cut]),
            None => text.clone(),
        };
        let what: Vec<String> = what.iter().map(short).collect();
        let mut line = serde_json::json!({
            "at": at, "who": who.to_string(), "verb": verb, "what": what, "ok": outcome.is_ok(),
        });
        if let Err(why) = outcome {
            line["error"] = short(&why).into();
        }
        if log.unwritten > 0 {
            line["refusalsNotWritten"] = std::mem::take(&mut log.unwritten).into();
        }
        let path = &log.path;
        if std::fs::metadata(path).is_ok_and(|file| file.len() >= CAP) {
            rotate(path);
        }
        let mut options = std::fs::OpenOptions::new();
        let file = options.append(true).create(true).mode(0o600).open(path);
        if let Err(e) = file.and_then(|mut file| file.write_all(format!("{line}\n").as_bytes())) {
            eprintln!(
                "kithd: writing the audit log {}: {e} (the entry: {line})",
                path.display()
            );
        }
    }

    /// The last `lines` entries (at most [`MOST`]), oldest first: from the file moved
    /// aside too, when the one being written is short of them.
    pub fn tail(&self, lines: u64) -> std::io::Result<Vec<serde_json::Value>> {
        let log = self.0.lock().expect("nothing panics holding the audit log");
        let lines = lines.min(MOST);
        let read = |path: &std::path::Path, lines: u64| -> std::io::Result<Vec<serde_json::Value>> {
            let (text, _) = crate::api::log_chunk(path, None, Some(lines))?;
            Ok(text
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect())
        };
        let mut entries = read(&log.path, lines)?;
        for n in 1..=KEPT {
            let missing = lines.saturating_sub(entries.len() as u64);
            if missing == 0 {
                break;
            }
            let mut older = read(&numbered(&log.path, n), missing)?;
            older.append(&mut entries);
            entries = older;
        }
        Ok(entries)
    }
}

/// The moved-aside file `n` back from `path`: `audit.log.1`, `audit.log.2`…
fn numbered(path: &std::path::Path, n: u32) -> PathBuf {
    path.with_extension(format!("log.{n}"))
}

/// Moves the full file aside: each numbered file one further back, the oldest dropped.
fn rotate(path: &std::path::Path) {
    let _ = std::fs::remove_file(numbered(path, KEPT));
    for n in (1..KEPT).rev() {
        let _ = std::fs::rename(numbered(path, n), numbered(path, n + 1));
    }
    let _ = std::fs::rename(path, numbered(path, 1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::Caller;

    #[test]
    fn audit_entries_are_kept_in_order() {
        let path = std::env::temp_dir().join(format!("kith-audit-{}.log", std::process::id()));
        let audit = Audit::new(path.clone());
        assert!(audit.tail(10).unwrap().is_empty());
        audit.record(&Caller::Admin, "apply", vec!["Workload/default/a".into()], Ok(()));
        let refused = Err("alice may not delete Node".to_string());
        audit.record(
            &Caller::Identity("alice".into()),
            "delete",
            vec!["Node/n1".into()],
            refused,
        );
        let entries = audit.tail(10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["who"], "local socket");
        assert_eq!(
            (&entries[1]["who"], &entries[1]["ok"]),
            (&"alice".into(), &false.into())
        );
        assert_eq!(entries[1]["error"], "alice may not delete Node");
        assert_eq!(audit.tail(1).unwrap()[0]["verb"], "delete");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        // Refused in a loop: sixty a minute are written, the rest counted with the next entry.
        // (The two above were in this minute or the one before: either way most of 100 are not written.)
        let long = "x".repeat(5000);
        for _ in 0..100 {
            audit.record(
                &Caller::Identity("mallory".into()),
                "GET",
                vec![long.clone()],
                Err("no".into()),
            );
        }
        audit.record(&Caller::Admin, "apply", vec!["Workload/default/b".into()], Ok(()));
        let entries = audit.tail(1000).unwrap();
        assert!(entries.len() <= 2 + 60 + 1, "{}", entries.len());
        let last = entries.last().unwrap();
        assert_eq!(last["what"][0], "Workload/default/b");
        assert!(last["refusalsNotWritten"].as_u64().unwrap() >= 39);
        assert!(entries[2]["what"][0].as_str().unwrap().chars().count() <= 201);

        // What was moved aside is still read.
        std::fs::rename(&path, path.with_extension("log.1")).unwrap();
        audit.record(&Caller::Admin, "delete", vec!["Workload/default/b".into()], Ok(()));
        let entries = audit.tail(3).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            (&entries[1]["verb"], &entries[2]["verb"]),
            (&"apply".into(), &"delete".into())
        );
        std::fs::remove_file(path.with_extension("log.1")).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn audit_files_are_numbered_and_read_back() {
        let path = std::env::temp_dir().join(format!("kith-audit-numbered-{}.log", std::process::id()));
        let audit = Audit::new(path.clone());
        // Each round fills the file past the cap with a line that is no entry, then writes
        // two entries after it (the reader looks at the last megabyte only), then records a
        // third: that one starts the next file, and the full one moves aside.
        let write = |text: String| {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&path)
                .unwrap();
            file.write_all(text.as_bytes()).unwrap();
        };
        let entry = |verb: &str| {
            format!(
                "{}\n",
                serde_json::json!({"at": 1, "who": "local socket", "verb": verb, "what": [], "ok": true})
            )
        };
        for round in 1..=6 {
            write(format!("{}\n", " ".repeat(CAP as usize)));
            write(entry(&format!("a{round}")));
            write(entry(&format!("b{round}")));
            audit.record(&Caller::Admin, &format!("t{round}"), vec![], Ok(()));
        }

        // Four moved-aside files are kept (the newest is `.1`); the fifth back is gone.
        let holds = |n: u32, verb: &str| {
            let text = std::fs::read_to_string(numbered(&path, n)).unwrap_or_default();
            text.contains(&format!("\"verb\":\"{verb}\""))
        };
        assert!(holds(1, "a6") && holds(1, "b6") && holds(2, "a5") && holds(3, "a4") && holds(4, "a3"));
        assert!(!holds(4, "a2") && !numbered(&path, 5).exists());
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"verb\":\"t6\""));

        // Read back across the moved-aside files, oldest first.
        for (n, verb) in [(3, "old"), (2, "mid"), (1, "new")] {
            std::fs::write(numbered(&path, n), entry(verb)).unwrap();
        }
        std::fs::write(&path, entry("now")).unwrap();
        let verbs: Vec<String> = audit
            .tail(10)
            .unwrap()
            .iter()
            .map(|e| e["verb"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(verbs, ["old", "mid", "new", "now"]);

        std::fs::remove_file(&path).unwrap();
        for n in 1..=4 {
            let _ = std::fs::remove_file(numbered(&path, n));
        }
    }
}
