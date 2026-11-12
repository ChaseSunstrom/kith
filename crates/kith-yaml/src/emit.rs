//! Block-style YAML output that [`crate::parse`] reads back to the same value.

use crate::{Plain, resolve};
use serde_json::Value;

pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Object(m) if !m.is_empty() => block(&mut out, value, 0),
        Value::Array(a) if !a.is_empty() => block(&mut out, value, 0),
        _ => {
            out.push_str(&scalar(value, 0));
            out.push('\n');
        }
    }
    out
}

fn is_block(v: &Value) -> bool {
    match v {
        Value::Object(m) => !m.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => false,
    }
}

/// Emit a non-empty map or list, every line indented by `indent`.
fn block(out: &mut String, value: &Value, indent: usize) {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(map) => {
            for (key, v) in map {
                out.push_str(&pad);
                out.push_str(&if plain_safe(key) { key.clone() } else { quoted(key) });
                out.push(':');
                if is_block(v) {
                    out.push('\n');
                    block(out, v, indent + 2);
                } else {
                    out.push(' ');
                    out.push_str(&scalar(v, indent));
                    out.push('\n');
                }
            }
        }
        Value::Array(items) => {
            for v in items {
                out.push_str(&pad);
                out.push_str("- ");
                if is_block(v) {
                    // Emit the child two columns in, then let its first line share ours.
                    let mut child = String::new();
                    block(&mut child, v, indent + 2);
                    out.push_str(&child[indent + 2..]);
                } else {
                    out.push_str(&scalar(v, indent));
                    out.push('\n');
                }
            }
        }
        _ => unreachable!("block() is only called on non-empty collections"),
    }
}

fn scalar(value: &Value, indent: usize) -> String {
    match value {
        Value::String(s) => string(s, indent),
        Value::Object(_) => "{}".into(),
        Value::Array(_) => "[]".into(),
        other => other.to_string(),
    }
}

fn string(s: &str, indent: usize) -> String {
    if plain_safe(s) {
        return s.to_string();
    }
    if let Some(block) = literal(s, indent) {
        return block;
    }
    quoted(s)
}

/// A JSON string is a valid YAML double-quoted scalar.
fn quoted(s: &str) -> String {
    serde_json::to_string(s).expect("strings always serialize")
}

/// True if `s` reads back as the same string unquoted, here and in other YAML parsers.
fn plain_safe(s: &str) -> bool {
    let Some(first) = s.chars().next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == '/' || first == '_') || s.ends_with([' ', ':']) {
        return false;
    }
    let ok_chars = s.chars().all(|c| c.is_ascii_alphanumeric() || " _-./@+=:,".contains(c));
    if !ok_chars || s.contains(": ") || resolve(s) != Plain::Str(s) {
        return false;
    }
    // Words YAML 1.1 parsers read as booleans or null.
    let lower = s.to_ascii_lowercase();
    if ["y", "n", "yes", "no", "on", "off", "true", "false", "null"].contains(&lower.as_str()) {
        return false;
    }
    // Things other parsers read as numbers: 0x1f, 0o7, 1_000, 1:30, 012, 1e3.
    if first.is_ascii_digit() {
        let version_like = s.matches('.').count() >= 2 && s.chars().all(|c| c.is_ascii_digit() || c == '.');
        let numeric_chars = s.chars().all(|c| c.is_ascii_digit() || "_.:eE+-".contains(c));
        let radix = ["0x", "0o", "0b", "0X", "0O", "0B"].iter().any(|p| s.starts_with(p));
        return version_like || !(numeric_chars || radix);
    }
    true
}

/// A `|` literal block for multi-line text, when it can represent `s` exactly.
fn literal(s: &str, indent: usize) -> Option<String> {
    let body = s.strip_suffix('\n').unwrap_or(s);
    let representable = s.contains('\n')
        && !body.is_empty()
        && !body.ends_with('\n')
        && !body.starts_with([' ', '\n'])
        && body
            .chars()
            .all(|c| c == '\n' || !(c.is_control() || c == '\u{2028}' || c == '\u{2029}'))
        && body.lines().all(|l| !l.ends_with(' ') && !l.contains('\u{feff}'));
    if !representable {
        return None;
    }
    let pad = " ".repeat(indent + 2);
    let mut out = String::from(if s.ends_with('\n') { "|" } else { "|-" });
    for line in body.split('\n') {
        out.push('\n');
        if !line.is_empty() {
            out.push_str(&pad);
            out.push_str(line);
        }
    }
    Some(out)
}
