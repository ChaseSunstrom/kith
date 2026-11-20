//! What the audit log (`audit.rs`) is told of the disk verbs: each add and remove, done or refused,
//! with who asked, the serial the owner typed and the disk's id once it has one. Never a key, and
//! never a byte of a disk: the log names what was asked and what came of it.
use super::Id;
use crate::audit::Audit;

/// An add of the disk with `serial` as `who`, with `--wipe` and `--quick` as they were given.
pub fn add(
    audit: &Audit,
    who: &impl std::fmt::Display,
    serial: &str,
    (wipe, quick): (bool, bool),
    done: Result<Id, String>,
) {
    let mut verb = String::from("disk add");
    if wipe {
        verb.push_str(" --wipe");
    }
    if quick {
        verb.push_str(" --quick");
    }
    let mut what = vec![format!("Serial/{serial}")];
    if let Ok(id) = &done {
        what.push(format!("Disk/{}", crate::pki::hex(id)));
    }
    audit.record(who, &verb, what, done.map(drop));
}

/// A remove of the disk `id` (as typed: a refusal of one that is no id is written too).
pub fn remove(audit: &Audit, who: &impl std::fmt::Display, id: &str, done: Result<(), String>) {
    audit.record(who, "disk remove", vec![format!("Disk/{id}")], done);
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
        remove(&audit, &"local socket", &id, Ok(()));
        remove(
            &audit,
            &"local socket",
            "nonsense",
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
}
