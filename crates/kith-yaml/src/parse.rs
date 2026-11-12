use crate::{Error, Plain, Pos, resolve};
use saphyr_parser::{Event, Parser, ScalarStyle, Span, StrInput, Tag};
use std::borrow::Cow;
use std::collections::HashSet;

/// Nesting deeper than this is an error rather than a stack overflow.
const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub pos: Pos,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `plain` is false for quoted and block scalars, which are always strings.
    Scalar {
        text: String,
        plain: bool,
    },
    Seq(Vec<Node>),
    Map(Vec<(Key, Node)>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Key {
    pub name: String,
    pub pos: Pos,
}

impl Node {
    /// Look up a key in a mapping.
    pub fn get(&self, key: &str) -> Option<&Node> {
        match &self.value {
            Value::Map(entries) => entries.iter().find(|(k, _)| k.name == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            Value::Scalar { text, .. } => Some(text),
            _ => None,
        }
    }

    fn is_null(&self) -> bool {
        matches!(&self.value, Value::Scalar { text, plain: true } if resolve(text) == Plain::Null)
    }
}

/// Parse every document in `src`. Empty documents are skipped.
pub fn parse(src: &str) -> Result<Vec<Node>, Error> {
    let mut events = Events(Parser::new_from_str(src), src);
    let mut docs = Vec::new();
    loop {
        match events.next()? {
            (Event::StreamEnd, _) => return Ok(docs),
            (Event::DocumentStart(_), _) => {
                let (ev, span) = events.next()?;
                let node = build(&mut events, ev, span, 0)?;
                if !node.is_null() {
                    docs.push(node);
                }
            }
            _ => {}
        }
    }
}

struct Events<'a>(Parser<'a, StrInput<'a>>, &'a str);

impl<'a> Events<'a> {
    fn next(&mut self) -> Result<(Event<'a>, Span), Error> {
        match self.0.next() {
            Some(Ok(ev)) => Ok(ev),
            Some(Err(e)) => {
                let mut at = pos(e.marker().line(), e.marker().col());
                // The scanner reports a tab at the start of the scalar it was reading;
                // point at the first tab-indented line from there instead.
                if e.info().contains("found a tab") {
                    let indent_tab = |l: &str| l.find('\t').filter(|&i| l[..i].trim().is_empty());
                    let mut lines = self.1.lines().enumerate().skip(at.line - 1);
                    if let Some((n, col)) = lines.find_map(|(n, l)| indent_tab(l).map(|i| (n, i))) {
                        at = pos(n + 1, col);
                    }
                }
                Err(Error::at(at, e.info()))
            }
            None => Err(Error {
                msg: "unexpected end of input".into(),
                pos: None,
            }),
        }
    }
}

fn pos(line: usize, col0: usize) -> Pos {
    Pos { line, col: col0 + 1 }
}

fn plain_only(at: Pos, anchor: usize, tag: &Option<Cow<'_, Tag>>) -> Result<(), Error> {
    if anchor != 0 {
        return Err(Error::at(at, "anchors (&name) are not supported in kith YAML"));
    }
    if let Some(tag) = tag {
        return Err(Error::at(
            at,
            format!("tags ({}{}) are not supported in kith YAML", tag.handle, tag.suffix),
        ));
    }
    Ok(())
}

fn build<'a>(events: &mut Events<'a>, ev: Event<'a>, span: Span, depth: usize) -> Result<Node, Error> {
    let at = pos(span.start.line(), span.start.col());
    if depth > MAX_DEPTH {
        return Err(Error::at(at, format!("nested more than {MAX_DEPTH} levels deep")));
    }
    let value = match ev {
        Event::Alias(_) => return Err(Error::at(at, "aliases (*name) are not supported in kith YAML")),
        Event::Scalar(text, style, anchor, tag) => {
            plain_only(at, anchor, &tag)?;
            Value::Scalar {
                text: text.into_owned(),
                plain: style == ScalarStyle::Plain,
            }
        }
        Event::SequenceStart(anchor, tag) => {
            plain_only(at, anchor, &tag)?;
            let mut items = Vec::new();
            loop {
                match events.next()? {
                    (Event::SequenceEnd, _) => break,
                    (ev, span) => items.push(build(events, ev, span, depth + 1)?),
                }
            }
            Value::Seq(items)
        }
        Event::MappingStart(anchor, tag) => {
            plain_only(at, anchor, &tag)?;
            let mut entries = Vec::new();
            let mut seen = HashSet::new();
            loop {
                let (ev, span) = events.next()?;
                let key_at = pos(span.start.line(), span.start.col());
                let name = match ev {
                    Event::MappingEnd => break,
                    Event::Scalar(text, _, anchor, tag) => {
                        plain_only(key_at, anchor, &tag)?;
                        text.into_owned()
                    }
                    Event::Alias(_) => return Err(Error::at(key_at, "aliases (*name) are not supported in kith YAML")),
                    _ => return Err(Error::at(key_at, "mapping keys must be scalars")),
                };
                if !seen.insert(name.clone()) {
                    return Err(Error::at(key_at, format!("duplicate key `{name}`")));
                }
                let (ev, span) = events.next()?;
                entries.push((Key { name, pos: key_at }, build(events, ev, span, depth + 1)?));
            }
            Value::Map(entries)
        }
        other => return Err(Error::at(at, format!("unexpected YAML event {other:?}"))),
    };
    Ok(Node { pos: at, value })
}
