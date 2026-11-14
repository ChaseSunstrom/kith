//! A language server for kith's own language (`*.kith` files): what is wrong with a file
//! as it is typed, the kinds and their fields offered from kith's own schemas, and what a
//! field or a builtin is when it is pointed at. It speaks the Language Server Protocol on
//! stdin and stdout, so an editor starts it; nothing else of kith needs it.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// The largest message taken: a file being edited, whole, with room to spare.
const LARGEST: usize = 8 << 20;

fn main() {
    let (stdin, stdout) = (std::io::stdin(), std::io::stdout());
    if let Err(e) = serve(&mut stdin.lock(), &mut stdout.lock()) {
        eprintln!("kith-lsp: {e}");
        std::process::exit(1);
    }
}

/// One message: headers, an empty line, and as many bytes as `Content-Length` said.
fn read(input: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = None;
    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        match line.trim_end().split_once(':') {
            Some((name, value)) if name.eq_ignore_ascii_case("content-length") => length = value.trim().parse().ok(),
            Some(_) => {}
            None if line.trim_end().is_empty() => break,
            None => return Err(std::io::Error::other(format!("not a header: {}", line.trim_end()))),
        }
    }
    let length = length.filter(|length| *length <= LARGEST);
    let length =
        length.ok_or_else(|| std::io::Error::other(format!("a message says no length up to {LARGEST} bytes")))?;
    let mut body = vec![0; length];
    input.read_exact(&mut body)?;
    Ok(Some(body))
}

fn send(output: &mut impl Write, message: &Value) -> std::io::Result<()> {
    let body = message.to_string();
    write!(output, "Content-Length: {}\r\n\r\n{body}", body.len())?;
    output.flush()
}

fn serve(input: &mut impl BufRead, output: &mut impl Write) -> std::io::Result<()> {
    // The files the editor has open, as it has them (not as the disk does), each with the
    // name the editor calls it by; and every file something wrong was last said of.
    let mut open: BTreeMap<PathBuf, (String, String)> = BTreeMap::new();
    let mut told: BTreeSet<String> = BTreeSet::new();
    while let Some(body) = read(input)? {
        let Ok(message) = serde_json::from_slice::<Value>(&body) else {
            send(
                output,
                &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "not JSON" } }),
            )?;
            continue;
        };
        let (id, params) = (message.get("id"), &message["params"]);
        let uri = params["textDocument"]["uri"].as_str().unwrap_or_default();
        let path = path_of(uri);
        // Where a request points: the file's text and how many bytes into it.
        let pointed = || {
            let (_, text) = open.get(path.as_ref()?)?;
            let (line, character) = (
                params["position"]["line"].as_u64()?,
                params["position"]["character"].as_u64()?,
            );
            Some((text.as_str(), offset(text, line as usize, character as usize)))
        };
        let result = match message["method"].as_str() {
            Some("initialize") => json!({
                "capabilities": {
                    // 1: the whole text with every change.
                    "textDocumentSync": 1,
                    "completionProvider": {},
                    "hoverProvider": true,
                },
                "serverInfo": { "name": "kith-lsp", "version": env!("CARGO_PKG_VERSION") },
            }),
            Some("shutdown") => Value::Null,
            Some("exit") => break,
            Some(method @ ("textDocument/didOpen" | "textDocument/didChange" | "textDocument/didClose")) => {
                let text = match method {
                    "textDocument/didOpen" => params["textDocument"]["text"].as_str(),
                    "textDocument/didChange" => params["contentChanges"]
                        .as_array()
                        .and_then(|changes| changes.last()?["text"].as_str()),
                    _ => None,
                };
                let Some(path) = path else { continue };
                match text {
                    Some(text) => open.insert(path, (uri.to_string(), text.to_string())),
                    None => open.remove(&path),
                };
                // A change in one file is a change in every file that imports it: all again.
                let mut wrong = diagnostics(&open);
                for uri in std::mem::take(&mut told) {
                    wrong.entry(uri).or_default();
                }
                for (uri, diagnostics) in wrong {
                    if !diagnostics.is_empty() {
                        told.insert(uri.clone());
                    }
                    let params = json!({ "uri": uri, "diagnostics": diagnostics });
                    send(
                        output,
                        &json!({ "jsonrpc": "2.0", "method": "textDocument/publishDiagnostics", "params": params }),
                    )?;
                }
                continue;
            }
            Some("textDocument/completion") => pointed().map_or(json!([]), |(text, offset)| completion(text, offset)),
            Some("textDocument/hover") => pointed()
                .and_then(|(text, offset)| hover(text, offset))
                .unwrap_or(Value::Null),
            // A request this does not answer is told so; anything else is not for it.
            Some(method) if id.is_some() => {
                let error = json!({ "code": -32601, "message": format!("kith-lsp does not answer {method}") });
                send(output, &json!({ "jsonrpc": "2.0", "id": id, "error": error }))?;
                continue;
            }
            _ => continue,
        };
        if let Some(id) = id {
            send(output, &json!({ "jsonrpc": "2.0", "id": id, "result": result }))?;
        }
    }
    Ok(())
}

/// The file a `file://` name is of.
fn path_of(uri: &str) -> Option<PathBuf> {
    let (rest, mut bytes) = (uri.strip_prefix("file://")?.as_bytes(), Vec::new());
    let mut at = 0;
    while at < rest.len() {
        let hex = rest
            .get(at + 1..at + 3)
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());
        match (rest[at], hex) {
            (b'%', Some(byte)) => {
                bytes.push(byte);
                at += 3;
            }
            (byte, _) => {
                bytes.push(byte);
                at += 1;
            }
        }
    }
    Some(PathBuf::from(String::from_utf8(bytes).ok()?))
}

/// The name an editor knows a file by.
fn uri_of(path: &Path) -> String {
    let mut uri = String::from("file://");
    for byte in path.to_string_lossy().bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => uri.push(char::from(byte)),
            _ => uri.push_str(&format!("%{byte:02X}")),
        }
    }
    uri
}

/// How many bytes into `text` a line and a character of it are, as an editor counts
/// them: both from 0, a character being a UTF-16 unit.
fn offset(text: &str, line: usize, character: usize) -> usize {
    let start: usize = text.split_inclusive('\n').take(line).map(str::len).sum();
    let mut units = 0;
    for (at, c) in text[start..].char_indices() {
        if units >= character || c == '\n' {
            return start + at;
        }
        units += c.len_utf16();
    }
    text.len()
}

/// Where an editor underlines for something said of `line` and `col` (both from 1, the
/// column in characters): the word there, or one character.
fn range(text: &str, line: usize, col: usize) -> Value {
    let said = text.lines().nth(line.saturating_sub(1)).unwrap_or_default();
    let units = |chars: usize| said.chars().take(chars).map(char::len_utf16).sum::<usize>();
    let word = said
        .chars()
        .skip(col.saturating_sub(1))
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .count();
    let (from, to) = (units(col.saturating_sub(1)), units(col.saturating_sub(1) + word.max(1)));
    json!({ "start": { "line": line.saturating_sub(1), "character": from }, "end": { "line": line.saturating_sub(1), "character": to } })
}

/// The names a file in a package's `templates/` has (README: In a package): the values
/// are the package's own `values.yaml`, and the release is made up, as none is there yet.
// ponytail: only files right in `templates/`; one in a directory below it is read as a
// plain file. Look upward for package.yaml when packages keep templates that deep.
fn names(root: &Path) -> Vec<(&'static str, Value)> {
    let package = root
        .parent()
        .filter(|package| root.ends_with("templates") && package.join("package.yaml").is_file());
    let Some(package) = package else {
        return Vec::new();
    };
    let values = std::fs::read_to_string(package.join("values.yaml")).ok();
    let values = values.and_then(|text| kith_yaml::from_str::<Value>(&text).ok());
    vec![
        ("values", values.filter(Value::is_object).unwrap_or(json!({}))),
        ("release", json!({ "name": "release", "namespace": "default" })),
        ("package", json!({ "name": "package", "version": "0.0.0" })),
        ("name", json!("release-package")),
        ("labels", json!({})),
    ]
}

/// What is wrong with every open file, by the file it is in (an open file with nothing
/// wrong has an empty list, so that what was said of it before is taken back).
fn diagnostics(open: &BTreeMap<PathBuf, (String, String)>) -> BTreeMap<String, Vec<Value>> {
    let mut found: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (path, (uri, _)) in open {
        found.entry(uri.clone()).or_default();
        let (Some(root), Some(entry)) = (path.parent(), path.file_name().and_then(|name| name.to_str())) else {
            continue;
        };
        let load = |name: &str| match open.get(&root.join(name)) {
            Some((_, text)) => Ok(text.clone()),
            None => kith_lang::dir(root)(name),
        };
        let names = names(root);
        let names: Vec<(&str, Value)> = names.iter().map(|(name, value)| (*name, value.clone())).collect();
        for error in kith_lang::check(entry, &load, &names) {
            let (uri, range) = match &error.at {
                Some((file, line, col)) => {
                    let named = open.get(&root.join(file)).map(|(uri, _)| uri.clone());
                    let uri = named.unwrap_or_else(|| uri_of(&root.join(file)));
                    (uri, range(&load(file).unwrap_or_default(), *line, *col))
                }
                None => (uri.clone(), range("", 1, 1)),
            };
            let diagnostic = json!({ "range": range, "severity": 1, "source": "kith", "message": error.msg });
            // (Two open files that import a third both find what is wrong in it.)
            let list = found.entry(uri).or_default();
            if !list.contains(&diagnostic) {
                list.push(diagnostic);
            }
        }
    }
    found
}

/// A step into a resource: a field of a record, or any item of a list.
#[derive(Debug, PartialEq)]
enum Step {
    Field(String),
    Item,
}

/// Where in a file's records a place is.
#[derive(Debug, Default, PartialEq)]
struct Place {
    /// The kind whose record (`Workload { … }`) it is inside, and the steps down to it;
    /// none where that cannot be told (inside a function's values, say).
    inside: Option<(String, Vec<Step>)>,
    /// The field whose value is being said there; none where a field's name comes next.
    value_of: Option<String>,
    /// Inside a record at all.
    record: bool,
}

/// Read `text` up to `end` only as far as brackets, strings and `name:` go, which is as
/// much as a file that is half typed has to say.
// ponytail: a `"` inside `${…}` inside a string ends the string for this reading; the
// rest of that line is then misread until the next quote. kith-lang's own lexer if it grows a
// way to read a file that does not parse.
fn place(text: &str, end: usize) -> Place {
    struct Frame {
        open: u8,
        kind: Option<String>,
        /// The field this bracket is the value of.
        key: Option<String>,
        /// The field whose value is being said in it now.
        now: Option<String>,
    }
    let (bytes, mut frames, mut word, mut at) = (text.as_bytes(), Vec::<Frame>::new(), None::<&str>, 0);
    let end = end.min(bytes.len());
    while at < end {
        let byte = bytes[at];
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' => at += 1,
            b'/' if bytes.get(at + 1) == Some(&b'/') => at = text[at..].find('\n').map_or(end, |n| at + n),
            b'"' => {
                let fence = if text[at..].starts_with("\"\"\"") {
                    "\"\"\""
                } else {
                    "\""
                };
                let mut close = at + fence.len();
                // (By bytes: a step may end inside a letter of more than one.)
                while close < end && !bytes[close..].starts_with(fence.as_bytes()) {
                    close += 1 + usize::from(bytes[close] == b'\\');
                }
                word = text.get(at + fence.len()..close);
                at = close + fence.len();
            }
            _ if byte.is_ascii_alphabetic() || byte == b'_' => {
                let len = text[at..]
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(text.len() - at);
                // (A word the place is in the middle of is the one being typed there.)
                word = (at + len < end).then(|| &text[at..at + len]);
                at += len;
            }
            b'{' | b'[' | b'(' => {
                let key = frames.last().and_then(|frame| frame.now.clone());
                let kind = word.filter(|word| byte == b'{' && word.starts_with(|c: char| c.is_ascii_uppercase()));
                frames.push(Frame {
                    open: byte,
                    kind: kind.map(str::to_string),
                    key,
                    now: None,
                });
                (word, at) = (None, at + 1);
            }
            b'}' | b']' | b')' => {
                frames.pop();
                (word, at) = (None, at + 1);
            }
            b':' | b',' => {
                if let Some(frame) = frames.last_mut().filter(|frame| frame.open == b'{') {
                    frame.now = if byte == b':' {
                        frame.now.take().or(word.map(str::to_string))
                    } else {
                        None
                    };
                }
                (word, at) = (None, at + 1);
            }
            _ => (word, at) = (None, at + 1),
        }
    }
    let Some(last) = frames.last() else {
        return Place::default();
    };
    let record = last.open == b'{';
    // From the nearest kind's record down: every bracket on the way is the value of a
    // field, or an item of a list.
    let inside = frames.iter().rposition(|frame| frame.kind.is_some()).and_then(|top| {
        let steps = frames
            .windows(2)
            .skip(top)
            .map(|pair| match (pair[0].open, &pair[1].key) {
                (b'[', _) => Some(Step::Item),
                (b'{', Some(key)) => Some(Step::Field(key.clone())),
                _ => None,
            });
        Some((frames[top].kind.clone()?, steps.collect::<Option<Vec<Step>>>()?))
    });
    Place {
        inside: inside.filter(|_| record),
        value_of: last.now.clone(),
        record,
    }
}

/// What a part of a schema says once what it points to is followed: `$ref`, and the one
/// of `anyOf` that is not null.
fn resolved<'a>(root: &'a Value, mut schema: &'a Value) -> &'a Value {
    // (Bounded: a schema that points at itself is followed no further.)
    for _ in 0..16 {
        let named = schema["$ref"]
            .as_str()
            .and_then(|name| root["$defs"].get(name.rsplit('/').next()?));
        let chosen = schema["anyOf"]
            .as_array()
            .and_then(|any| any.iter().find(|one| one["type"] != "null"));
        match named.or(chosen) {
            Some(next) => schema = next,
            None => break,
        }
    }
    schema
}

/// The schema of what is `steps` down a kind's resource.
fn schema_at(kind: &str, steps: &[Step]) -> Option<(Value, Value)> {
    let root = kith_api::KINDS.iter().find(|info| info.kind == kind)?.schema();
    let mut schema = &root;
    for step in steps {
        let of = resolved(&root, schema);
        schema = match step {
            // (A map of names to values has one schema for all of them.)
            Step::Field(name) => of["properties"]
                .get(name)
                .or(of.get("additionalProperties").filter(|any| any.is_object()))?,
            Step::Item => of.get("items")?,
        };
    }
    let found = schema.clone();
    Some((root, found))
}

/// A schema's type in a few words: `integer`, `Template`, `list of Container`.
fn type_of(root: &Value, schema: &Value) -> String {
    let named = |schema: &Value| {
        schema["$ref"]
            .as_str()
            .and_then(|name| name.rsplit('/').next())
            .map(str::to_string)
    };
    let any = schema["anyOf"].as_array().and_then(|any| any.iter().find_map(named));
    if let Some(name) = named(schema).or(any) {
        return name;
    }
    let schema = resolved(root, schema);
    match &schema["type"] {
        Value::String(one) if one == "array" => format!("list of {}", type_of(root, &schema["items"])),
        Value::String(one) => one.clone(),
        Value::Array(some) => some
            .iter()
            .filter_map(Value::as_str)
            .find(|one| *one != "null")
            .unwrap_or("any")
            .to_string(),
        _ => "any".to_string(),
    }
}

/// The values a schema names, where it names them (`Always`, `IfNotPresent`, …).
fn choices(root: &Value, schema: &Value) -> Vec<String> {
    let schema = resolved(root, schema);
    let own = |schema: &Value| -> Vec<String> {
        let listed = schema["enum"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(schema.get("const"));
        listed.filter_map(Value::as_str).map(str::to_string).collect()
    };
    let nested = ["oneOf", "anyOf"]
        .iter()
        .filter_map(|key| schema[key].as_array())
        .flatten()
        .flat_map(own);
    own(schema).into_iter().chain(nested).collect()
}

/// What can be typed at `end`: a field of the kind's record it is inside, or the words
/// of the language, the builtins, the kinds and the names the file gives.
fn completion(text: &str, end: usize) -> Value {
    // 5 a field, 20 one of a named few, 14 a keyword, 3 a function, 7 a kind, 6 a name.
    let item = |label: &str, kind: u8, detail: &str| json!({ "label": label, "kind": kind, "detail": detail });
    let place = place(text, end);
    let at = place
        .inside
        .as_ref()
        .and_then(|(kind, steps)| Some((schema_at(kind, steps)?, steps.is_empty())));
    let mut items = Vec::new();
    match (&at, &place.value_of) {
        // A field's name comes next, and the schema knows which there are.
        (Some(((root, schema), top)), None) => {
            let fields = resolved(root, schema)["properties"].as_object().into_iter().flatten();
            // (`Workload {` has said the kind.)
            for (name, field) in fields.filter(|(name, _)| !(*top && *name == "kind")) {
                let about = field["description"]
                    .as_str()
                    .or(resolved(root, field)["description"].as_str());
                let mut found = item(name, 5, &type_of(root, field));
                found["documentation"] = about.into();
                items.push(found);
            }
            if !items.is_empty() {
                return items.into();
            }
        }
        (Some(((root, schema), _)), Some(field)) => {
            let of = resolved(root, schema)["properties"].get(field);
            let named = of.map(|of| choices(root, of)).unwrap_or_default();
            items.extend(named.iter().map(|choice| item(&format!("\"{choice}\""), 20, field)));
        }
        _ => {}
    }
    // Where a field's name comes next in a record nothing is known of, nothing is offered.
    if place.record && place.value_of.is_none() {
        return items.into();
    }
    items.extend(kith_lang::WORDS.iter().map(|word| item(word, 14, "")));
    items.extend(kith_lang::BUILTINS.iter().map(|(name, usage)| item(name, 3, usage)));
    items.extend(kith_api::KINDS.iter().map(|kind| item(kind.kind, 7, kind.about)));
    let mut words = text
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|word| !word.is_empty());
    let mut names = BTreeSet::new();
    while let Some(word) = words.next() {
        if matches!(word, "let" | "fn") {
            names.extend(words.next());
        }
    }
    items.extend(names.iter().map(|name| item(name, 6, "")));
    items.into()
}

/// What the word at `at` is: a builtin, a kind, or a field of the kind's record it is in.
fn hover(text: &str, at: usize) -> Option<Value> {
    let part = |c: char| c.is_alphanumeric() || c == '_';
    let start = text[..at].rfind(|c| !part(c)).map_or(0, |before| before + 1);
    let len = text[start..].find(|c| !part(c)).unwrap_or(text.len() - start);
    let word = text.get(start..start + len).filter(|word| !word.is_empty())?;
    let builtin = kith_lang::BUILTINS
        .iter()
        .find(|(name, _)| *name == word)
        .map(|(_, usage)| usage.to_string());
    let kind = kith_api::KINDS
        .iter()
        .find(|kind| kind.kind == word)
        .map(|kind| format!("{}: {}", kind.kind, kind.about));
    let field = || {
        let place = place(text, start);
        let (kind, steps) = place.inside.filter(|_| place.value_of.is_none())?;
        let (root, schema) = schema_at(&kind, &steps)?;
        let field = resolved(&root, &schema)["properties"].get(word)?;
        let about = field["description"]
            .as_str()
            .or(resolved(&root, field)["description"].as_str());
        let path: String = steps
            .iter()
            .map(|step| match step {
                Step::Field(name) => format!(".{name}"),
                Step::Item => "[]".to_string(),
            })
            .collect();
        Some(
            format!(
                "{kind}{path}.{word}: {}\n\n{}",
                type_of(&root, field),
                about.unwrap_or_default()
            )
            .trim_end()
            .to_string(),
        )
    };
    let said = builtin.or(kind).or_else(field)?;
    Some(json!({ "contents": { "kind": "plaintext", "value": said } }))
}
