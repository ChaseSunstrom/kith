//! Contexts (T-0031): a name for a remote kithd and the identity directory that calls it,
//! kept in `~/.config/kith/contexts.yaml` (`$XDG_CONFIG_HOME/kith/` when that is set):
//!
//! ```yaml
//! current-context: lab
//! contexts:
//!   lab: { server: "10.0.0.5:7443", identity: /srv/kith/alice }
//! ```
//!
//! `kith --context lab` (or `KITH_CONTEXT`, or the `current-context` line) means `--server`
//! and `--identity` from that entry; a flag given as well wins. Every error names the file.

use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Default)]
struct File {
    current: Option<String>,
    contexts: BTreeMap<String, Entry>,
}

#[derive(Clone)]
pub struct Entry {
    pub server: String,
    pub identity: PathBuf,
}

/// The file's text as it holds: a map of `current-context` and `contexts`, and nothing else
/// (read through a plain value, not a derived type: kith's size budget counts each one).
fn shape(text: &str) -> Result<File, String> {
    let value: Value = kith_yaml::from_str(text).map_err(|e| e.to_string())?;
    let mut held = File::default();
    for (key, value) in value.as_object().ok_or("it is not a map")? {
        match (key.as_str(), value) {
            ("current-context", Value::String(name)) => held.current = Some(name.clone()),
            ("contexts", Value::Object(all)) => {
                for (name, entry) in all {
                    let text = |field: &str| entry.get(field).and_then(Value::as_str);
                    let (Some(server), Some(identity), true) = (
                        text("server"),
                        text("identity"),
                        entry.as_object().is_some_and(|m| m.len() == 2),
                    ) else {
                        return Err(format!("{name}: it takes a server and an identity, and nothing else"));
                    };
                    let entry = Entry {
                        server: server.into(),
                        identity: identity.into(),
                    };
                    held.contexts.insert(name.clone(), entry);
                }
            }
            _ => return Err(format!("{key}: not a current-context name or a map of contexts")),
        }
    }
    Ok(held)
}

/// Where the file is: under `$XDG_CONFIG_HOME`, else `$HOME/.config`.
pub fn file() -> Result<PathBuf, String> {
    let env = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let config = env("XDG_CONFIG_HOME")
        .or_else(|| env("HOME").map(|home| home.join(".config")))
        .ok_or("error: no HOME to keep contexts in: set HOME or XDG_CONFIG_HOME")?;
    Ok(config.join("kith/contexts.yaml"))
}

/// What the file holds; a file that is not there holds nothing.
fn load(file: &Path) -> Result<File, String> {
    let text = match std::fs::read_to_string(file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(File::default()),
        Err(e) => return Err(format!("error: {}: {e}", file.display())),
    };
    if text.trim().is_empty() {
        return Ok(File::default());
    }
    shape(&text).map_err(|e| format!("error: {}: {e}", file.display()))
}

/// The entry for `named`, or for the file's `current-context` when none is named: none at
/// all when neither is there. An entry is only returned if its identity directory is.
pub fn pick(file: &Path, named: Option<&str>) -> Result<Option<Entry>, String> {
    let held = load(file)?;
    let Some(name) = named.or(held.current.as_deref()) else {
        return Ok(None);
    };
    let Some(entry) = held.contexts.get(name) else {
        let known: Vec<&str> = held.contexts.keys().map(String::as_str).collect();
        let known = if known.is_empty() {
            "none".into()
        } else {
            known.join(", ")
        };
        return Err(format!(
            "error: no context {name:?} in {} (it has: {known})",
            file.display()
        ));
    };
    if !entry.identity.is_dir() {
        return Err(format!(
            "error: context {name:?} in {}: its identity directory {} is not there",
            file.display(),
            entry.identity.display()
        ));
    }
    Ok(Some(entry.clone()))
}

/// Keep `held` as the file: its directory 0700, itself 0600, put in place whole.
fn save(file: &Path, held: &File) -> Result<(), String> {
    let wrong = |e: std::io::Error| format!("error: {}: {e}", file.display());
    let dir = file.parent().unwrap_or(Path::new("."));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(wrong)?;
    // (A directory that was there is kith's own, and holds a certificate's way in.)
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(wrong)?;
    let mut top = Map::new();
    top.extend(
        held.current
            .iter()
            .map(|name| ("current-context".into(), name.as_str().into())),
    );
    let each = |(name, e): (&String, &Entry)| {
        let entry = serde_json::json!({ "server": e.server, "identity": e.identity.to_string_lossy() });
        (name.clone(), entry)
    };
    top.insert(
        "contexts".into(),
        Value::Object(held.contexts.iter().map(each).collect()),
    );
    let text = kith_yaml::to_string(&Value::Object(top));
    let mut draft = file.to_path_buf().into_os_string();
    draft.push(format!(".{}", std::process::id()));
    let draft = PathBuf::from(draft);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&draft)
        .and_then(|mut f| {
            std::io::Write::write_all(&mut f, text.as_bytes())?;
            // (A draft a crash left from an earlier process of this number keeps its mode.)
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
        })
        .and_then(|()| std::fs::rename(&draft, file));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&draft);
        wrong(e)
    })
}

fn known<'a>(held: &'a mut File, file: &Path, name: &str) -> Result<&'a mut File, String> {
    if held.contexts.contains_key(name) {
        return Ok(held);
    }
    Err(format!("error: no context {name:?} in {}", file.display()))
}

/// Hold the file's lock (a sibling file) until the returned handle drops: two `context` verbs
/// at once each read and write the whole file.
fn locked(file: &Path) -> Result<std::fs::File, String> {
    let wrong = |e: std::io::Error| format!("error: {}: {e}", file.display());
    let dir = file.parent().unwrap_or(Path::new("."));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(wrong)?;
    let mut name = file.as_os_str().to_os_string();
    name.push(".lock");
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(PathBuf::from(name))
        .map_err(wrong)?;
    lock.lock().map_err(wrong)?;
    Ok(lock)
}

/// `kith context add`: a second add of a name replaces it.
pub fn add(file: &Path, name: &str, server: &str, identity: &Path) -> Result<(), String> {
    let plain = !name.is_empty() && !name.starts_with(['-', '.']);
    if !plain || !name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        return Err(format!(
            "error: context name {name:?}: use letters, digits, . _ and -, not starting with - or ."
        ));
    }
    if !server
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
    {
        return Err(format!("error: --server {server:?}: write HOST:PORT"));
    }
    // Kept as a full path: the context is used from wherever kith runs next.
    let identity = identity
        .canonicalize()
        .ok()
        .filter(|path| path.is_dir())
        .ok_or_else(|| format!("error: --identity {}: not a directory", identity.display()))?;
    let _lock = locked(file)?;
    let mut held = load(file)?;
    held.contexts.insert(
        name.into(),
        Entry {
            server: server.into(),
            identity,
        },
    );
    save(file, &held)
}

/// `kith context use`.
pub fn use_(file: &Path, name: &str) -> Result<(), String> {
    let _lock = locked(file)?;
    let mut held = load(file)?;
    known(&mut held, file, name)?.current = Some(name.into());
    save(file, &held)
}

/// `kith context rm`: the current one stops being so.
pub fn rm(file: &Path, name: &str) -> Result<(), String> {
    let _lock = locked(file)?;
    let mut held = load(file)?;
    known(&mut held, file, name)?.contexts.remove(name);
    if held.current.as_deref() == Some(name) {
        held.current = None;
    }
    save(file, &held)
}

/// `kith context ls`: one line each, the current one starred.
pub fn ls(file: &Path) -> Result<String, String> {
    let held = load(file)?;
    let mut out = String::new();
    for (name, entry) in &held.contexts {
        let star = if held.current.as_deref() == Some(name) {
            '*'
        } else {
            ' '
        };
        out += &format!("{star} {name}\t{}\t{}\n", entry.server, entry.identity.display());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder of this test's own, with a contexts file path in a directory not made yet.
    fn home(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("kith-context-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("alice")).unwrap();
        (dir.join("config/kith/contexts.yaml"), dir.join("alice"))
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn context_resolves_named_then_current_and_names_the_file_when_it_cannot() {
        let (file, alice) = home("resolve");
        // No file: no context, and a named one is an error that names the file.
        assert!(pick(&file, None).unwrap().is_none());
        let wrong = pick(&file, Some("lab")).err().unwrap();
        assert!(
            wrong.contains("no context") && wrong.contains(&*file.display().to_string()),
            "{wrong}"
        );

        add(&file, "lab", "10.0.0.5:7443", &alice).unwrap();
        add(&file, "home", "[::1]:7443", &alice).unwrap();
        // Added is not current.
        assert!(pick(&file, None).unwrap().is_none());
        use_(&file, "lab").unwrap();
        assert_eq!(pick(&file, None).unwrap().unwrap().server, "10.0.0.5:7443");
        // A name wins over the current one.
        let home = pick(&file, Some("home")).unwrap().unwrap();
        assert_eq!(
            (home.server.as_str(), &home.identity),
            ("[::1]:7443", &alice.canonicalize().unwrap())
        );
        // An unknown name lists what there is.
        let wrong = pick(&file, Some("nope")).err().unwrap();
        assert!(
            wrong.contains("home, lab") && wrong.contains(&*file.display().to_string()),
            "{wrong}"
        );

        // An identity directory that went away.
        std::fs::remove_dir_all(&alice).unwrap();
        let wrong = pick(&file, None).err().unwrap();
        assert!(
            wrong.contains("identity directory") && wrong.contains(&*file.display().to_string()),
            "{wrong}"
        );
    }

    #[test]
    fn context_file_that_is_not_ours_is_an_error_naming_it() {
        let (file, alice) = home("broken");
        add(&file, "lab", "10.0.0.5:7443", &alice).unwrap();
        for text in [
            "contexts: [1, 2]\n",
            "contexts:\n  lab: { server: x }\n",
            "other: 1\n",
            "a: [\n",
        ] {
            std::fs::write(&file, text).unwrap();
            let wrong = pick(&file, None).err().unwrap_or_default() + &ls(&file).err().unwrap_or_default();
            assert!(wrong.contains("contexts.yaml"), "{text:?}: {wrong}");
        }
        // Nothing was written over it by a failed add.
        assert!(add(&file, "two", "h:1", &alice).is_err());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "a: [\n");
    }

    #[test]
    fn context_verbs_write_0600_in_0700_and_a_second_add_replaces() {
        let (file, alice) = home("verbs");
        let bob = alice.with_file_name("bob");
        std::fs::create_dir(&bob).unwrap();
        // The directory kith keeps it in is there already, and open to others.
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::set_permissions(file.parent().unwrap(), std::fs::Permissions::from_mode(0o755)).unwrap();

        add(&file, "lab", "10.0.0.5:7443", &alice).unwrap();
        assert_eq!((mode(&file), mode(file.parent().unwrap())), (0o600, 0o700));
        add(&file, "lab", "10.0.0.6:7443", &bob).unwrap();
        let entry = pick(&file, Some("lab")).unwrap().unwrap();
        assert_eq!(
            (entry.server.as_str(), entry.identity),
            ("10.0.0.6:7443", bob.canonicalize().unwrap())
        );
        assert_eq!(ls(&file).unwrap().lines().count(), 1);

        add(&file, "zed", "z.example:1", &alice).unwrap();
        use_(&file, "zed").unwrap();
        assert_eq!(mode(&file), 0o600);
        let listed = ls(&file).unwrap();
        assert!(
            listed.starts_with("  lab\t") && listed.contains("\n* zed\tz.example:1\t"),
            "{listed}"
        );

        // Removing the current one leaves none current; an unknown name is an error.
        rm(&file, "zed").unwrap();
        assert!(pick(&file, None).unwrap().is_none());
        assert!(rm(&file, "zed").err().unwrap().contains("no context"));
        assert!(use_(&file, "zed").err().unwrap().contains("no context"));
        assert_eq!(ls(&file).unwrap().lines().count(), 1);
        // Names and addresses a file could not hold, or kith could not call.
        assert!(add(&file, "a b", "h:1", &alice).is_err());
        assert!(add(&file, "x", "no-port", &alice).is_err());
        assert!(add(&file, "x", "h:1", &alice.join("nope")).is_err());
        assert!(add(&file, "-x", "h:1", &alice).is_err());
        assert!(add(&file, "..", "h:1", &alice).is_err());
        // No draft is left beside it (only its lock).
        assert_eq!(std::fs::read_dir(file.parent().unwrap()).unwrap().count(), 2);
    }
}
