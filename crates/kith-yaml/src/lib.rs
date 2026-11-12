//! Strict YAML for kith (PLAN.md §4.2).
//!
//! The accepted subset, compared with YAML 1.2:
//! - duplicate mapping keys are an error;
//! - anchors, aliases and tags are errors (stricter than the plan's "no anchors
//!   across documents"; relax to same-document aliases if anyone misses them);
//! - mapping keys must be scalars;
//! - plain scalars resolve only as `null`/`~`/empty, `true`/`false`, decimal
//!   integers and decimal floats. `no`, `on`, `Yes`, `0x10`, `012` are strings;
//! - when the target type wants a string, the raw text is used, so
//!   `version: 1.0` stays `"1.0"`; a number or bool field never accepts a string.
//!
//! JSON is accepted as-is: it parses as YAML flow syntax. One gap: a character
//! written as a `\uD83D\uDE00` surrogate pair is rejected by the scanner; write
//! the character itself (JSON allows that, and most tools emit it).
//! Every error carries the line and column it came from.

mod de;
mod emit;
mod parse;

pub use de::{from_node, from_str};
pub use emit::to_string;
pub use parse::{Key, Node, Value, parse};

/// 1-based line and column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pos {
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Error {
    pub msg: String,
    pub pos: Option<Pos>,
}

impl Error {
    pub(crate) fn at(pos: Pos, msg: impl Into<String>) -> Self {
        Error {
            msg: msg.into(),
            pos: Some(pos),
        }
    }

    /// `file:line:col: message`, plus the offending source line with a caret.
    pub fn render(&self, file: &str, src: &str) -> String {
        let Some(Pos { line, col }) = self.pos else {
            return format!("{file}: {}", self.msg);
        };
        let mut out = format!("{file}:{line}:{col}: {}", self.msg);
        if let Some(text) = src.lines().nth(line - 1) {
            let pad: String = text
                .chars()
                .take(col - 1)
                .map(|c| if c == '\t' { '\t' } else { ' ' })
                .collect();
            out.push_str(&format!("\n  | {text}\n  | {pad}^"));
        }
        out
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pos {
            Some(p) => write!(f, "line {}, column {}: {}", p.line, p.col, self.msg),
            None => f.write_str(&self.msg),
        }
    }
}

impl std::error::Error for Error {}

/// What a plain (unquoted) scalar means when nothing says what type is wanted.
#[derive(Debug, PartialEq)]
pub(crate) enum Plain<'a> {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(&'a str),
}

pub(crate) fn resolve(text: &str) -> Plain<'_> {
    match text {
        "" | "~" | "null" => return Plain::Null,
        "true" => return Plain::Bool(true),
        "false" => return Plain::Bool(false),
        _ => {}
    }
    match number_shape(text) {
        Some(true) => {
            if let Ok(i) = text.parse() {
                return Plain::Int(i);
            }
            if let Ok(u) = text.parse() {
                return Plain::UInt(u);
            }
            text.parse().map_or(Plain::Str(text), Plain::Float)
        }
        Some(false) => match text.parse::<f64>() {
            Ok(f) if f.is_finite() => Plain::Float(f),
            _ => Plain::Str(text),
        },
        None => Plain::Str(text),
    }
}

/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?`; `Some(true)` for an integer.
fn number_shape(s: &str) -> Option<bool> {
    let digits = |b: &[u8]| b.iter().take_while(|c| c.is_ascii_digit()).count();
    let b = s.strip_prefix('-').unwrap_or(s).as_bytes();
    let n = digits(b);
    if n == 0 || (n > 1 && b[0] == b'0') {
        return None;
    }
    let mut rest = &b[n..];
    let mut int = true;
    if let [b'.', tail @ ..] = rest {
        let m = digits(tail);
        if m == 0 {
            return None;
        }
        rest = &tail[m..];
        int = false;
    }
    if let [b'e' | b'E', tail @ ..] = rest {
        let tail = match tail {
            [b'+' | b'-', t @ ..] => t,
            t => t,
        };
        let m = digits(tail);
        if m == 0 {
            return None;
        }
        rest = &tail[m..];
        int = false;
    }
    rest.is_empty().then_some(int)
}

#[cfg(test)]
mod tests;
