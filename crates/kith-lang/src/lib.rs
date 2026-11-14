//! kith's own configuration language: files named `*.kith` that give the resources a YAML
//! file would. Values, `let`, functions, `if`, records and lists that spread, strings with
//! `${…}`, and imports of other files of the same directory; a kind's name before a record
//! (`Workload { … }`) makes it a resource of that kind.
//!
//! What a file gives is handed to kith-api as the very tree kith-yaml would have parsed,
//! each part with the place in the `.kith` file where it was said: so a resource is
//! checked by the code that checks YAML, and a wrong field is refused at its line and
//! column. README.md ("kith's own language") has the grammar.

mod eval;
mod parse;

pub use eval::BUILTINS;
pub use parse::WORDS;

use eval::{Machine, V};
use kith_api::Resource;
use kith_yaml::{Node, Pos, Value as Yaml};

/// How a file is read: its path from the directory the first file is in (`lib/web.kith`).
pub type Load<'a> = &'a (dyn Fn(&str) -> Result<String, String> + Sync);

/// A place in a file that was read.
#[derive(Clone, Copy)]
struct At {
    file: u8,
    /// In bytes from the file's start.
    off: u32,
}

impl At {
    /// Of a value that no file said: one handed in, like a package's `values`.
    const NOWHERE: At = At { file: u8::MAX, off: 0 };
}

struct Fail {
    at: At,
    msg: String,
    /// A field or an item that is not there: what `??` answers for.
    missing: bool,
}

type Result<T, E = Box<Fail>> = std::result::Result<T, E>;

/// What is wrong, and where it was said. Written out, it is the message after
/// `file:line:column:` with the line under it, the way a YAML file's errors are shown.
#[derive(Debug)]
pub struct Error {
    /// The file (by the path it was read with), the line and the column, from 1; none
    /// for what no file said.
    pub at: Option<(String, usize, usize)>,
    pub msg: String,
    shown: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.shown)
    }
}

/// An error, at a place in a file (its name and its text) when a file said it.
fn wrong(msg: String, at: Option<(&str, &str, Pos)>) -> Error {
    let Some((name, text, pos)) = at else {
        return Error {
            at: None,
            shown: msg.clone(),
            msg,
        };
    };
    let shown = kith_yaml::Error {
        msg: msg.clone(),
        pos: Some(pos),
    }
    .render(name, text);
    Error {
        at: Some((name.to_string(), pos.line, pos.col)),
        msg,
        shown,
    }
}

/// Evaluation calls itself as deep as the file nests, so it gets a stack of its own
/// size whoever asks. (Only what is touched of it is ever memory.)
const STACK: usize = 64 << 20;

/// What a file gave: its documents, as kith-yaml would have parsed them.
pub struct Output {
    pub docs: Vec<Node>,
    files: Vec<(String, String)>,
}

/// The file and the position an encoded position (see `Machine::pos`) is of.
fn place(pos: Pos) -> (usize, Pos) {
    (
        pos.line >> 24,
        Pos {
            line: pos.line & 0xff_ffff,
            col: pos.col,
        },
    )
}

/// The path of the first part of a document that was said at `pos`: `.spec.replicas`.
fn path(node: &Node, pos: Pos, at: &mut String) -> bool {
    let step = |name: String, key: Option<Pos>, value: &Node, at: &mut String| {
        let len = at.len();
        at.push_str(&name);
        let found = key == Some(pos) || value.pos == pos || path(value, pos, at);
        if !found {
            at.truncate(len);
        }
        found
    };
    match &node.value {
        Yaml::Map(fields) => fields
            .iter()
            .any(|(key, value)| step(format!(".{}", key.name), Some(key.pos), value, at)),
        Yaml::Seq(items) => items
            .iter()
            .enumerate()
            .any(|(n, item)| step(format!("[{n}]"), None, item, at)),
        Yaml::Scalar { .. } => false,
    }
}

impl Output {
    /// What kith-api said of one of the documents, with the path into it:
    /// `Workload.spec.replicas: invalid type…`, at the place the value was said.
    pub fn said(&self, doc: &Node, error: &kith_yaml::Error) -> Error {
        let Some(pos) = error.pos else {
            return wrong(error.msg.clone(), None);
        };
        let mut at = match doc.get("kind").map(|kind| &kind.value) {
            Some(Yaml::Scalar { text, .. }) => text.clone(),
            _ => String::new(),
        };
        // (What is said of the resource as a whole, like its kind, has no path.)
        let msg = match doc.pos != pos && path(doc, pos, &mut at) {
            true => format!("{at}: {}", error.msg),
            false => error.msg.clone(),
        };
        let (file, pos) = place(pos);
        let (name, text) = &self.files[file];
        wrong(msg, Some((name, text, pos)))
    }
}

/// Evaluate the file `entry`. `globals` are names every file can use besides its own (a
/// package gives `values`, `release`, …).
pub fn eval(entry: &str, load: Load, globals: &[(&str, serde_json::Value)]) -> Result<Output, Error> {
    run(entry, load, globals, false)
}

/// `eval`; with `library`, a file that gives something other than resources (a record of
/// functions for other files to import, say) gives no documents instead of an error.
fn run(entry: &str, load: Load, globals: &[(&str, serde_json::Value)], library: bool) -> Result<Output, Error> {
    let run = || {
        let mut machine = Machine::new(load, globals);
        let shown = |machine: &Machine, fail: Box<Fail>| match fail.at.file == At::NOWHERE.file {
            true => wrong(fail.msg, None),
            false => {
                let (file, pos) = place(machine.pos(fail.at));
                let (name, text, _) = &machine.files[file];
                wrong(fail.msg, Some((name, text, pos)))
            }
        };
        let value = machine.file(entry, At::NOWHERE).map_err(|fail| shown(&machine, fail))?;
        // One resource, a list of them (lists inside it too), or nothing.
        // (A record that says any of a resource's own fields is meant as one, `kind` misspelt or not.)
        let own = |key: &str| ["kind", "apiVersion", "metadata"].contains(&key);
        let resource = |value: &V| matches!(value, V::Rec(fields) if fields.iter().any(|field| own(&field.key)));
        if library && !matches!(value, V::Null | V::List(_)) && !resource(&value) {
            return Ok(Output {
                docs: Vec::new(),
                files: Vec::new(),
            });
        }
        let (mut found, mut docs, mut size) = (vec![(value, machine.gave)], Vec::new(), 0);
        while let Some((value, at)) = found.pop() {
            match &value {
                V::Null => {}
                V::List(items) => found.extend(items.iter().rev().cloned()),
                V::Rec(_) => {
                    let top = Pos { line: 1, col: 1 };
                    docs.push(
                        machine
                            .node(&value, at, top, &mut size)
                            .map_err(|fail| shown(&machine, fail))?,
                    );
                }
                _ => {
                    let fail = Fail {
                        at,
                        msg: "a file gives a resource, a list of them or null".into(),
                        missing: false,
                    };
                    return Err(shown(&machine, Box::new(fail)));
                }
            }
        }
        let files = machine.files.into_iter().map(|(name, text, _)| (name, text)).collect();
        Ok(Output { docs, files })
    };
    std::thread::scope(|scope| {
        let thread = std::thread::Builder::new().stack_size(STACK).spawn_scoped(scope, run);
        let thread = thread.map_err(|e| wrong(format!("kith's language could not start: {e}"), None))?;
        let stopped = |_| {
            Err(wrong(
                "kith's language stopped where it should not have: a bug in kith".into(),
                None,
            ))
        };
        thread.join().unwrap_or_else(stopped)
    })
}

/// All that is wrong with a file, for an editor: as `resources` finds it, but a file
/// that is there to be imported is no mistake.
pub fn check(entry: &str, load: Load, globals: &[(&str, serde_json::Value)]) -> Vec<Error> {
    match run(entry, load, globals, true) {
        Ok(output) => output
            .docs
            .iter()
            .filter_map(|doc| Some(output.said(doc, &Resource::from_node(doc).err()?)))
            .collect(),
        Err(error) => vec![error],
    }
}

/// The resources a file gives, checked as a YAML file's are. All that is wrong with them
/// is said at once.
pub fn resources(entry: &str, load: Load, globals: &[(&str, serde_json::Value)]) -> Result<Vec<Resource>, Vec<Error>> {
    checked(entry, load, globals, false)
}

/// `resources` for a file that was not asked for by name (one of a directory): one that
/// is there to be imported gives none, and is no mistake.
pub fn resources_if_any(
    entry: &str,
    load: Load,
    globals: &[(&str, serde_json::Value)],
) -> Result<Vec<Resource>, Vec<Error>> {
    checked(entry, load, globals, true)
}

fn checked(
    entry: &str,
    load: Load,
    globals: &[(&str, serde_json::Value)],
    library: bool,
) -> Result<Vec<Resource>, Vec<Error>> {
    let output = run(entry, load, globals, library).map_err(|error| vec![error])?;
    let (mut resources, mut wrong) = (Vec::new(), Vec::new());
    for doc in &output.docs {
        match Resource::from_node(doc) {
            Ok(resource) => resources.push(resource),
            Err(error) => wrong.push(output.said(doc, &error)),
        }
    }
    match wrong.is_empty() {
        true => Ok(resources),
        false => Err(wrong),
    }
}

/// Files read from a directory, for `eval`: nothing outside it, nothing through a link,
/// and nothing that is not a file (a pipe would be read for ever).
pub fn dir(root: &std::path::Path) -> impl Fn(&str) -> Result<String, String> + Sync + '_ {
    move |name| {
        let (mut path, mut file) = (root.to_path_buf(), false);
        for part in name.split('/') {
            path.push(part);
            let is = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if is.file_type().is_symlink() {
                return Err("is a link: an import is a file of this directory".into());
            }
            file = is.is_file();
        }
        if !file {
            return Err("is not a file".into());
        }
        std::fs::read_to_string(&path).map_err(|e| e.to_string())
    }
}
