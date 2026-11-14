//! Text to tree, by hand and in one pass. A token is read when the grammar asks for one, so
//! a string can hold `${…}` with any expression in it. The grammar is in README.md
//! ("kith's own language") and each rule's function here is named after it.

use crate::{At, Fail, Result};
use std::rc::Rc;

/// How deep `(`, `[`, `{` and `${` may nest, and how long a chain of operators, calls or
/// fields may be: a tree is walked (and dropped) by functions that call themselves.
const NESTING: u32 = 64;
const CHAIN: u32 = 500;

pub(crate) struct Expr {
    /// Where it starts in its file, in bytes.
    pub at: u32,
    pub is: Is,
}

pub(crate) enum Is {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Vec<Part>),
    Var(Rc<str>),
    List(Vec<Item>),
    Rec(Vec<Field>),
    /// `let` and `fn` statements, then the value.
    Block(Vec<(Rc<str>, Bind)>, Box<Expr>),
    If(Box<[Expr; 3]>),
    Fn(Rc<Lambda>),
    Call(Box<Expr>, Vec<Expr>),
    Field(Box<Expr>, String),
    Index(Box<[Expr; 2]>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Op(&'static str, Box<[Expr; 2]>),
    Import(String),
    /// `Workload { … }`: the record, as a resource of that kind.
    Kind(String, Box<Expr>),
}

pub(crate) enum Part {
    Text(String),
    Expr(Expr),
}

pub(crate) enum Item {
    One(Expr),
    Spread(Expr),
    For {
        name: Rc<str>,
        of: Expr,
        when: Option<Expr>,
        give: Expr,
    },
}

pub(crate) enum Field {
    Pair { key: Key, at: u32, value: Expr },
    Spread(Expr),
}

pub(crate) enum Key {
    Name(String),
    Expr(Expr),
}

pub(crate) enum Bind {
    Let(Expr),
    Fn(Rc<Lambda>),
}

pub(crate) struct Lambda {
    /// For messages: `web`, or "the function" when it has no name.
    pub name: String,
    pub params: Vec<(Rc<str>, Option<Expr>)>,
    pub body: Expr,
}

#[derive(Clone, PartialEq)]
enum Tok {
    Name(String),
    Int(i64),
    Float(f64),
    /// The `"` a string starts with: the rest of it is read by `string`.
    Quote,
    Sym(&'static str),
    End,
}

/// (The longer first: `..` before `.`.)
const SYMS: [&str; 28] = [
    "..", "==", "!=", "<=", ">=", "&&", "||", "??", "(", ")", "[", "]", "{", "}", ",", ";", ":", ".", "=", "<", ">",
    "+", "-", "*", "/", "%", "!", "|",
];

/// Operators between two values, and how tightly each binds.
const OPS: [(&str, u8); 14] = [
    ("??", 1),
    ("||", 2),
    ("&&", 3),
    ("==", 4),
    ("!=", 4),
    ("<", 5),
    ("<=", 5),
    (">", 5),
    (">=", 5),
    ("+", 6),
    ("-", 6),
    ("*", 7),
    ("/", 7),
    ("%", 7),
];

/// Words the grammar keeps: none of them can name a value (any can name a field).
pub const WORDS: [&str; 11] = [
    "let", "fn", "if", "then", "else", "for", "in", "import", "true", "false", "null",
];

fn fail(at: usize, msg: impl Into<String>) -> Box<Fail> {
    Box::new(Fail {
        at: At {
            file: 0,
            off: at as u32,
        },
        msg: msg.into(),
        missing: false,
    })
}

fn show(tok: &Tok) -> String {
    match tok {
        Tok::Name(name) => format!("`{name}`"),
        Tok::Int(n) => format!("`{n}`"),
        Tok::Float(n) => format!("`{n}`"),
        Tok::Quote => "a string".into(),
        Tok::Sym(sym) => format!("`{sym}`"),
        Tok::End => "the end of the file".into(),
    }
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    /// The token after `pos`, once it has been asked for: itself, its start and its end.
    ahead: Option<(Tok, usize, usize)>,
    depth: u32,
}

/// A whole file: statements, then the value the file gives.
pub(crate) fn file(src: &str) -> Result<Expr> {
    let mut p = Parser {
        src,
        pos: 0,
        ahead: None,
        depth: 0,
    };
    let tree = p.body()?;
    match p.next()? {
        (Tok::End, _) => Ok(tree),
        (tok, at) => Err(fail(
            at,
            format!("expected an operator or the end of the file, not {}", show(&tok)),
        )),
    }
}

impl Parser<'_> {
    fn peek(&mut self) -> Result<&Tok> {
        if self.ahead.is_none() {
            let mut at = self.pos;
            loop {
                let rest = &self.src[at..];
                let text = rest.trim_start();
                at += rest.len() - text.len();
                match text.starts_with("//") {
                    true => at += text.find('\n').unwrap_or(text.len()),
                    false => break,
                }
            }
            let rest = &self.src[at..];
            let digits = |s: &str| s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
            let (tok, len) = match rest.chars().next() {
                None => (Tok::End, 0),
                Some('"') => (Tok::Quote, 1),
                Some(c) if c.is_ascii_digit() => {
                    let whole = digits(rest);
                    let part = match rest[whole..].strip_prefix('.').map(digits) {
                        Some(part) if part > 0 => part + 1,
                        _ => 0,
                    };
                    let text = &rest[..whole + part];
                    let tok = match part {
                        0 => text.parse().map(Tok::Int).ok(),
                        _ => text.parse().map(Tok::Float).ok(),
                    };
                    (tok.ok_or_else(|| fail(at, "too large a number"))?, text.len())
                }
                Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                    let len = rest
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .unwrap_or(rest.len());
                    (Tok::Name(rest[..len].into()), len)
                }
                Some(c) => match SYMS.iter().find(|sym| rest.starts_with(**sym)) {
                    Some(sym) => (Tok::Sym(sym), sym.len()),
                    None => return Err(fail(at, format!("`{c}` means nothing here"))),
                },
            };
            self.ahead = Some((tok, at, at + len));
        }
        Ok(&self.ahead.as_ref().expect("just read").0)
    }

    /// The next token and where it starts; it is behind us after this.
    fn next(&mut self) -> Result<(Tok, usize)> {
        self.peek()?;
        let (tok, start, end) = self.ahead.take().expect("just read");
        self.pos = end;
        Ok((tok, start))
    }

    /// Where the next token starts.
    fn at(&mut self) -> Result<usize> {
        self.peek()?;
        Ok(self.ahead.as_ref().expect("just read").1)
    }

    fn sym(&mut self) -> Result<Option<&'static str>> {
        Ok(match self.peek()? {
            Tok::Sym(sym) => Some(sym),
            _ => None,
        })
    }

    fn eat(&mut self, sym: &str) -> Result<bool> {
        let there = self.sym()? == Some(sym);
        if there {
            self.next()?;
        }
        Ok(there)
    }

    fn expect(&mut self, sym: &str) -> Result<()> {
        match self.eat(sym)? {
            true => Ok(()),
            false => {
                let (tok, at) = self.next()?;
                Err(fail(at, format!("expected `{sym}`, not {}", show(&tok))))
            }
        }
    }

    /// The word, if it is next.
    fn word(&mut self, word: &str) -> Result<bool> {
        let there = matches!(self.peek()?, Tok::Name(name) if name == word);
        if there {
            self.next()?;
        }
        Ok(there)
    }

    fn keyword(&mut self, word: &str) -> Result<()> {
        match self.word(word)? {
            true => Ok(()),
            false => {
                let (tok, at) = self.next()?;
                Err(fail(at, format!("expected `{word}`, not {}", show(&tok))))
            }
        }
    }

    /// A name that is being given to something.
    fn name(&mut self) -> Result<Rc<str>> {
        match self.next()? {
            (Tok::Name(name), _) if !WORDS.contains(&name.as_str()) => Ok(name.into()),
            (tok, at) => Err(fail(at, format!("expected a name, not {}", show(&tok)))),
        }
    }

    fn link(&mut self, links: &mut u32, at: usize) -> Result<()> {
        *links += 1;
        match *links > CHAIN {
            true => Err(fail(at, format!("more than {CHAIN} in a row: put some in a `let`"))),
            false => Ok(()),
        }
    }

    /// body = { "let" NAME "=" expr ";" | "fn" NAME "(" params ")" "=" expr ";" } expr
    fn body(&mut self) -> Result<Expr> {
        let at = self.at()?;
        let mut binds = Vec::new();
        loop {
            if self.word("let")? {
                let name = self.name()?;
                self.expect("=")?;
                binds.push((name, Bind::Let(self.expr()?)));
            } else if self.word("fn")? {
                let name = self.name()?;
                self.expect("(")?;
                let params = self.params(")")?;
                self.expect("=")?;
                let lambda = Lambda {
                    name: format!("`{name}`"),
                    params,
                    body: self.expr()?,
                };
                binds.push((name, Bind::Fn(Rc::new(lambda))));
            } else {
                break;
            }
            self.expect(";")?;
        }
        if matches!(self.peek()?, Tok::End | Tok::Sym("}")) {
            return Err(fail(
                self.at()?,
                "expected the value this gives (after its `let`s and `fn`s)",
            ));
        }
        let tail = self.expr()?;
        Ok(match binds.is_empty() {
            true => tail,
            false => Expr {
                at: at as u32,
                is: Is::Block(binds, Box::new(tail)),
            },
        })
    }

    /// params = [ NAME [ "=" expr ] { "," NAME [ "=" expr ] } [ "," ] ], up to `close`
    fn params(&mut self, close: &str) -> Result<Vec<(Rc<str>, Option<Expr>)>> {
        let mut params = Vec::new();
        while !self.eat(close)? {
            let name = self.name()?;
            let default = match self.eat("=")? {
                true => Some(self.binary(0)?),
                false => None,
            };
            params.push((name, default));
            if !self.eat(",")? {
                self.expect(close)?;
                break;
            }
        }
        Ok(params)
    }

    /// expr = "if" expr "then" expr "else" expr | "|" params "|" expr | binary
    fn expr(&mut self) -> Result<Expr> {
        let at = self.at()?;
        self.depth += 1;
        if self.depth > NESTING {
            return Err(fail(at, format!("nested more than {NESTING} deep")));
        }
        let tree = if self.word("if")? {
            let when = self.expr()?;
            self.keyword("then")?;
            let then = self.expr()?;
            self.keyword("else")?;
            Expr {
                at: at as u32,
                is: Is::If(Box::new([when, then, self.expr()?])),
            }
        } else if matches!(self.sym()?, Some("|" | "||")) {
            let params = match self.next()?.0 {
                Tok::Sym("||") => Vec::new(),
                _ => self.params("|")?,
            };
            let lambda = Lambda {
                name: "the function".into(),
                params,
                body: self.expr()?,
            };
            Expr {
                at: at as u32,
                is: Is::Fn(Rc::new(lambda)),
            }
        } else {
            self.binary(0)?
        };
        self.depth -= 1;
        Ok(tree)
    }

    /// binary = unary { OP unary }, the tighter operators first
    fn binary(&mut self, least: u8) -> Result<Expr> {
        let mut left = self.unary()?;
        let mut links = 0;
        loop {
            let op = self
                .sym()?
                .and_then(|sym| OPS.iter().find(|(op, bind)| *op == sym && *bind >= least));
            let Some((op, bind)) = op else { return Ok(left) };
            let at = self.next()?.1;
            self.link(&mut links, at)?;
            let right = self.binary(bind + 1)?;
            left = Expr {
                at: at as u32,
                is: Is::Op(op, Box::new([left, right])),
            };
        }
    }

    /// unary = { "!" | "-" } postfix
    fn unary(&mut self) -> Result<Expr> {
        let mut ops = Vec::new();
        while let Some(op @ ("!" | "-")) = self.sym()? {
            let at = self.next()?.1;
            ops.push((op, at));
            self.link(&mut (ops.len() as u32 - 1), at)?;
        }
        let mut tree = self.postfix()?;
        for (op, at) in ops.into_iter().rev() {
            let of = Box::new(tree);
            tree = Expr {
                at: at as u32,
                is: if op == "!" { Is::Not(of) } else { Is::Neg(of) },
            };
        }
        Ok(tree)
    }

    /// postfix = primary { "." (NAME | STRING) | "[" expr "]" | "(" [ expr { "," expr } [ "," ] ] ")" }
    fn postfix(&mut self) -> Result<Expr> {
        let mut tree = self.primary()?;
        let mut links = 0;
        loop {
            let at = self.at()?;
            let is = match self.sym()? {
                Some(".") => {
                    self.next()?;
                    let name = match self.next()? {
                        (Tok::Name(name), _) => name,
                        (Tok::Quote, at) => self.text(at)?,
                        (tok, at) => return Err(fail(at, format!("expected a field's name, not {}", show(&tok)))),
                    };
                    Is::Field(Box::new(tree), name)
                }
                Some("[") => {
                    self.next()?;
                    let index = self.expr()?;
                    self.expect("]")?;
                    Is::Index(Box::new([tree, index]))
                }
                Some("(") => {
                    self.next()?;
                    let mut args = Vec::new();
                    while !self.eat(")")? {
                        args.push(self.expr()?);
                        if !self.eat(",")? {
                            self.expect(")")?;
                            break;
                        }
                    }
                    Is::Call(Box::new(tree), args)
                }
                _ => return Ok(tree),
            };
            self.link(&mut links, at)?;
            tree = Expr { at: at as u32, is };
        }
    }

    /// primary = NUMBER | STRING | "true" | "false" | "null" | NAME | KIND record
    ///         | "import" STRING | "(" expr ")" | list | record | "{" body "}"
    fn primary(&mut self) -> Result<Expr> {
        let (tok, at) = self.next()?;
        let is = match tok {
            Tok::Int(n) => Is::Int(n),
            Tok::Float(n) => Is::Float(n),
            Tok::Quote => Is::Str(self.string(at)?),
            Tok::Name(name) => match name.as_str() {
                "null" => Is::Null,
                "true" => Is::Bool(true),
                "false" => Is::Bool(false),
                "import" => match self.next()? {
                    (Tok::Quote, at) => Is::Import(self.text(at)?),
                    (tok, at) => {
                        return Err(fail(
                            at,
                            format!("expected a file's name in quotes, not {}", show(&tok)),
                        ));
                    }
                },
                word if WORDS.contains(&word) => {
                    return Err(fail(
                        at,
                        format!("`{word}` cannot stand here (an `if` inside a value goes in brackets)"),
                    ));
                }
                _ if name.starts_with(|c: char| c.is_ascii_uppercase()) && self.sym()? == Some("{") => {
                    let at = self.next()?.1;
                    Is::Kind(name, Box::new(self.record(at)?))
                }
                _ => Is::Var(name.into()),
            },
            Tok::Sym("(") => {
                let inside = self.expr()?;
                self.expect(")")?;
                return Ok(inside);
            }
            Tok::Sym("[") => Is::List(self.list()?),
            Tok::Sym("{") => {
                // A block when it starts with a statement: `{ let: 1 }` is still a record.
                let (pos, ahead) = (self.pos, self.ahead.clone());
                let block = (self.word("let")? || self.word("fn")?) && !matches!(self.sym()?, Some(":" | "," | "}"));
                (self.pos, self.ahead) = (pos, ahead);
                if !block {
                    return self.record(at);
                }
                let body = self.body()?;
                self.expect("}")?;
                return Ok(body);
            }
            tok => return Err(fail(at, format!("expected a value, not {}", show(&tok)))),
        };
        Ok(Expr { at: at as u32, is })
    }

    /// list = "[" [ item { "," item } [ "," ] ] "]"
    /// item = expr | ".." expr | "for" NAME "in" expr [ "if" expr ] ":" expr
    fn list(&mut self) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        while !self.eat("]")? {
            items.push(if self.eat("..")? {
                Item::Spread(self.expr()?)
            } else if self.word("for")? {
                let name = self.name()?;
                self.keyword("in")?;
                let of = self.binary(0)?;
                let when = match self.word("if")? {
                    true => Some(self.binary(0)?),
                    false => None,
                };
                self.expect(":")?;
                Item::For {
                    name,
                    of,
                    when,
                    give: self.expr()?,
                }
            } else {
                Item::One(self.expr()?)
            });
            if !self.eat(",")? {
                self.expect("]")?;
                break;
            }
        }
        Ok(items)
    }

    /// record = "{" [ field { "," field } [ "," ] ] "}"
    /// field  = (NAME | STRING | "[" expr "]") ":" expr | NAME | ".." expr
    fn record(&mut self, at: usize) -> Result<Expr> {
        let mut fields = Vec::new();
        while !self.eat("}")? {
            let (tok, at) = self.next()?;
            let key = match tok {
                Tok::Sym("..") => {
                    fields.push(Field::Spread(self.expr()?));
                    None
                }
                Tok::Sym("[") => {
                    let key = self.expr()?;
                    self.expect("]")?;
                    Some(Key::Expr(key))
                }
                Tok::Quote => Some(Key::Expr(Expr {
                    at: at as u32,
                    is: Is::Str(self.string(at)?),
                })),
                // `{ name }` is `{ name: name }`.
                Tok::Name(name) if self.sym()? != Some(":") && !WORDS.contains(&name.as_str()) => {
                    let value = Expr {
                        at: at as u32,
                        is: Is::Var(name.as_str().into()),
                    };
                    fields.push(Field::Pair {
                        key: Key::Name(name),
                        at: at as u32,
                        value,
                    });
                    None
                }
                Tok::Name(name) => Some(Key::Name(name)),
                tok => return Err(fail(at, format!("expected a field's name, not {}", show(&tok)))),
            };
            if let Some(key) = key {
                self.expect(":")?;
                fields.push(Field::Pair {
                    key,
                    at: at as u32,
                    value: self.expr()?,
                });
            }
            if !self.eat(",")? {
                self.expect("}")?;
                break;
            }
        }
        Ok(Expr {
            at: at as u32,
            is: Is::Rec(fields),
        })
    }

    /// The rest of a string whose first `"` (at `at`) is behind us: text, `\` escapes and
    /// `${expr}`. Three quotes open a block, which ends at the next three and loses the
    /// indentation its closing quotes have.
    fn string(&mut self, at: usize) -> Result<Vec<Part>> {
        let block = self.src[self.pos..].starts_with("\"\"");
        self.pos += if block { 2 } else { 0 };
        let (mut parts, mut text) = (Vec::new(), String::new());
        loop {
            let rest = &self.src[self.pos..];
            let Some(c) = rest.chars().next() else {
                return Err(fail(at, "this string does not end"));
            };
            self.pos += c.len_utf8();
            match c {
                '"' if !block => break,
                '"' if rest.starts_with("\"\"\"") => {
                    self.pos += 2;
                    break;
                }
                '\\' => {
                    let escaped = rest[1..].chars().next();
                    text.push(match escaped {
                        Some('n') => '\n',
                        Some('t') => '\t',
                        Some('r') => '\r',
                        Some(c @ ('"' | '\\' | '$')) => c,
                        _ => return Err(fail(self.pos, "after `\\` comes n, t, r, \", \\ or $")),
                    });
                    self.pos += escaped.map_or(0, char::len_utf8);
                }
                '$' if rest[1..].starts_with('{') => {
                    self.pos += 1;
                    if !text.is_empty() {
                        parts.push(Part::Text(std::mem::take(&mut text)));
                    }
                    parts.push(Part::Expr(self.expr()?));
                    self.expect("}")?;
                }
                c => text.push(c),
            }
        }
        if !text.is_empty() {
            parts.push(Part::Text(text));
        }
        if block {
            dedent(&mut parts);
        }
        Ok(parts)
    }

    /// A string that is only text: a file's name, a field's.
    fn text(&mut self, at: usize) -> Result<String> {
        match self.string(at)?.as_mut_slice() {
            [] => Ok(String::new()),
            [Part::Text(text)] => Ok(std::mem::take(text)),
            _ => Err(fail(at, "`${…}` cannot be used in this string")),
        }
    }
}

/// A block's lines without the indentation of the line its closing quotes are on, and
/// without the line break after its opening ones.
fn dedent(parts: &mut [Part]) {
    let Some(Part::Text(last)) = parts.last() else { return };
    let indent = match last.rfind('\n') {
        Some(at) if last[at + 1..].chars().all(|c| c == ' ' || c == '\t') => format!("\n{}", &last[at + 1..]),
        _ => return,
    };
    for (n, part) in parts.iter_mut().enumerate() {
        if let Part::Text(text) = part {
            *text = text.replace(&indent, "\n");
            if n == 0 && text.starts_with('\n') {
                text.remove(0);
            }
        }
    }
}
