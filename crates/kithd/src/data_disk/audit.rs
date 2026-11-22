//! What the audit log (`audit.rs`) is told of the disk verbs: each add and remove, done or refused,
//! with who asked, the serial the owner typed and the disk's id once it has one. Never a key, and
//! never a byte of a disk: the log names what was asked and what came of it.
use super::Id;
use crate::audit::Audit;

fn add_verb((wipe, quick): (bool, bool)) -> String {
    let mut verb = String::from("disk add");
    if wipe {
        verb.push_str(" --wipe");
    }
    if quick {
        verb.push_str(" --quick");
    }
    verb
}

/// An add of the disk with `serial` as `who`, with `--wipe` and `--quick` as they were given.
pub fn add(audit: &Audit, who: &impl std::fmt::Display, serial: &str, flags: (bool, bool), done: Result<Id, String>) {
    let mut what = vec![format!("Serial/{serial}")];
    if let Ok(id) = &done {
        what.push(format!("Disk/{}", crate::pki::hex(id)));
    }
    audit.record(who, &add_verb(flags), what, done.map(drop));
}

/// An add that begins: written before the work, which overwrites a disk and takes hours, so a log
/// read while it runs (or after a crash in it) shows who began what.
pub fn adding(audit: &Audit, who: &impl std::fmt::Display, serial: &str, flags: (bool, bool)) {
    let verb = format!("{} started", add_verb(flags));
    audit.record(who, &verb, vec![format!("Serial/{serial}")], Ok(()));
}

fn remove_what(id: &str, serial: Option<&str>) -> Vec<String> {
    let mut what = vec![format!("Disk/{id}")];
    what.extend(serial.map(|serial| format!("Serial/{serial}")));
    what
}

/// A remove of the disk `id` (as typed: a refusal of one that is no id is written too), with the
/// serial the node kept for it when it has one.
pub fn remove(audit: &Audit, who: &impl std::fmt::Display, id: &str, serial: Option<&str>, done: Result<(), String>) {
    audit.record(who, "disk remove", remove_what(id, serial), done);
}

/// A remove that begins (as [`adding`]).
pub fn removing(audit: &Audit, who: &impl std::fmt::Display, id: &str, serial: Option<&str>) {
    audit.record(who, "disk remove started", remove_what(id, serial), Ok(()));
}

/// A disk verb sent to the wrong node: refused, and written.
pub fn misdirected(audit: &Audit, who: &impl std::fmt::Display, verb: &str, node: &str, why: String) {
    audit.record(who, verb, vec![format!("Node/{node}")], Err(why));
}

#[cfg(test)]
mod tests {
    use super::super::support::*;
    use super::*;
    use serde_json::json;

    /// An audit log in a directory of its own (kept alive with the `Dir`).
    fn log(tag: &str) -> (Dir, Audit) {
        let (dir, _, _) = rig(tag);
        let audit = Audit::new(dir.path().join("audit.log"));
        (dir, audit)
    }

    #[test]
    fn an_add_is_written_with_who_the_serial_and_the_id() {
        let (_dir, audit) = log("audit-add");
        add(&audit, &"local socket", "S1", (false, false), Ok(ID));
        let entry = audit.tail(1).unwrap().remove(0);
        assert_eq!(entry["verb"], "disk add");
        assert_eq!(entry["who"], "local socket");
        assert_eq!(entry["ok"], true);
        assert_eq!(
            entry["what"],
            json!(["Serial/S1", format!("Disk/{}", crate::pki::hex(&ID))])
        );
    }

    #[test]
    fn a_refused_add_is_written_with_its_flags_and_why() {
        let (_dir, audit) = log("audit-add-refused");
        add(&audit, &"alice", "S1", (true, true), Err("it holds a GPT".into()));
        let entry = audit.tail(1).unwrap().remove(0);
        assert_eq!(entry["verb"], "disk add --wipe --quick");
        assert_eq!(entry["ok"], false);
        assert_eq!(entry["error"], "it holds a GPT");
        // (No id: the disk was not made one.)
        assert_eq!(entry["what"], json!(["Serial/S1"]));
    }

    #[test]
    fn a_remove_is_written_done_or_refused() {
        let (_dir, audit) = log("audit-remove");
        let id = crate::pki::hex(&ID);
        remove(&audit, &"local socket", &id, None, Ok(()));
        remove(
            &audit,
            &"local socket",
            "nonsense",
            None,
            Err("an id is 32 hex digits".into()),
        );
        let entries = audit.tail(2).unwrap();
        assert_eq!(entries[0]["verb"], "disk remove");
        assert_eq!(
            (entries[0]["ok"].clone(), entries[0]["what"].clone()),
            (json!(true), json!([format!("Disk/{id}")]))
        );
        assert_eq!(
            (entries[1]["ok"].clone(), entries[1]["error"].clone()),
            (json!(false), json!("an id is 32 hex digits"))
        );
        assert_eq!(entries[1]["what"], json!(["Disk/nonsense"]));
    }

    #[test]
    fn a_remove_names_the_serial_when_the_node_has_it() {
        let (_dir, audit) = log("audit-remove-serial");
        remove(&audit, &"alice", "ab", Some("S1"), Err("in use".into()));
        let entry = audit.tail(1).unwrap().remove(0);
        assert_eq!(entry["what"], json!(["Disk/ab", "Serial/S1"]));
    }

    /// The first entry is written when the work begins, the second when it ends.
    #[test]
    fn a_verb_that_begins_is_written_before_it_ends() {
        let (_dir, audit) = log("audit-started");
        adding(&audit, &"alice", "S1", (true, false));
        removing(&audit, &"alice", "ab", Some("S1"));
        let entries = audit.tail(2).unwrap();
        assert_eq!(entries[0]["verb"], "disk add --wipe started");
        assert_eq!(entries[0]["what"], json!(["Serial/S1"]));
        assert_eq!(entries[1]["verb"], "disk remove started");
        assert_eq!(entries[1]["what"], json!(["Disk/ab", "Serial/S1"]));
        assert!(entries.iter().all(|entry| entry["ok"] == true));
    }

    #[test]
    fn a_verb_for_another_node_is_written_refused() {
        let (_dir, audit) = log("audit-misdirected");
        misdirected(&audit, &"alice", "disk list", "n2", "ask n2".into());
        let entry = audit.tail(1).unwrap().remove(0);
        assert_eq!(
            (entry["verb"].clone(), entry["ok"].clone(), entry["what"].clone()),
            (json!("disk list"), json!(false), json!(["Node/n2"]))
        );
    }
}
