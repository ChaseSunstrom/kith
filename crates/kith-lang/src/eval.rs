//! The tree to values. Strict and in order: nothing is put off, nothing is changed once
//! made, and the only thing read from outside is another file of the same directory.

use crate::parse::{self, Bind, Expr, Field, Is, Item, Key, Lambda, Part};
use crate::{At, Fail, Load, Result};
use kith_yaml::{Node, Pos, Value as Yaml};
use std::cmp::Ordering;
use std::rc::Rc;

/// What one evaluation may spend, as the Jinja templates have their fuel: a step for each
/// thing it works out and each item it makes, and for anything that takes longer the more
/// it is given (a long string searched, a field found among many), steps by its size.
const STEPS: u64 = 500_000;
/// How deep values may be worked out inside one another (a function calling itself goes
/// three deeper each time), and how deep a value is followed into itself.
const DEPTH: u32 = 3000;
/// What one evaluation may give, and how large a file it reads, in bytes.
pub(crate) const SIZE: usize = 1 << 20;
/// How many files one evaluation may read: a position's file is kept in a byte.
const FILES: usize = 255;

#[derive(Clone)]
pub(crate) enum V {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    /// Each item with where it was said.
    List(Rc<Vec<(V, At)>>),
    Rec(Rc<Vec<Entry>>),
    Fn(Rc<Closure>),
    Builtin(&'static str),
}

#[derive(Clone)]
pub(crate) struct Entry {
    pub key: Rc<str>,
    key_at: At,
    value: V,
    at: At,
}

pub(crate) struct Closure {
    lambda: Rc<Lambda>,
    env: Env,
    file: u8,
}

/// What is in reach of an expression: the nearest name first.
type Env = Option<Rc<Scope>>;

struct Scope {
    name: Rc<str>,
    bound: Bound,
    up: Env,
}

enum Bound {
    Value(V),
    /// A `fn`: made into a closure over this very scope when it is looked up, so it can
    /// call itself and nothing holds itself alive.
    Fn(Rc<Lambda>, u8),
}

fn bind(env: &Env, name: &Rc<str>, value: V) -> Env {
    Some(Rc::new(Scope {
        name: name.clone(),
        bound: Bound::Value(value),
        up: env.clone(),
    }))
}

/// What a name is bound to, and how many names were passed on the way to it.
/// What a name is bound to, and how many names were passed looking (whether it was
/// found or not: the looking is work either way).
fn lookup(env: &Env, name: &str) -> (Option<V>, usize) {
    let (mut here, mut passed) = (env, 0);
    while let Some(scope) = here {
        if &*scope.name == name {
            let value = match &scope.bound {
                Bound::Value(value) => value.clone(),
                Bound::Fn(lambda, file) => V::Fn(Rc::new(Closure {
                    lambda: lambda.clone(),
                    env: here.clone(),
                    file: *file,
                })),
            };
            return (Some(value), passed);
        }
        (here, passed) = (&scope.up, passed + 1);
    }
    (None, passed)
}

// A file can hang a hundred thousand names one from another, and nest a value as deep, in
// fewer steps than it may spend: what lets go of them does so in a loop, not one inside
// the other, which would take stack by the depth.
impl Drop for Scope {
    fn drop(&mut self) {
        let mut up = self.up.take();
        while let Some(mut scope) = up.and_then(Rc::into_inner) {
            up = scope.up.take();
        }
    }
}

impl Drop for V {
    fn drop(&mut self) {
        fn inside(value: &mut V, more: &mut Vec<V>) {
            match value {
                V::List(items) => more.extend(
                    Rc::get_mut(items)
                        .into_iter()
                        .flat_map(|items| items.drain(..))
                        .map(|(item, _)| item),
                ),
                V::Rec(fields) => more.extend(
                    Rc::get_mut(fields)
                        .into_iter()
                        .flat_map(|fields| fields.drain(..))
                        .map(|field| field.value),
                ),
                _ => {}
            }
        }
        let mut more = Vec::new();
        inside(self, &mut more);
        while let Some(mut value) = more.pop() {
            inside(&mut value, &mut more);
        }
    }
}

/// The functions every file has, each with the line that says how it is called.
pub const BUILTINS: [(&str, &str); 20] = [
    (
        "len",
        "len(x): how many items a list, fields a record or characters a string has",
    ),
    ("map", "map(list, f): a list of f(item) for each item"),
    ("filter", "filter(list, f): the items f(item) is true of"),
    (
        "range",
        "range(n) or range(from, to): the whole numbers from 0 (or `from`) up to, not including, the last",
    ),
    (
        "sort",
        "sort(list): a list of strings or a list of numbers, the smallest first",
    ),
    ("keys", "keys(record): its fields' names, in order"),
    ("values", "values(record): its fields' values, in order"),
    (
        "entries",
        "entries(record): a list of { key, value }, one for each field",
    ),
    ("record", "record(list): a record from a list of { key, value }"),
    (
        "has",
        "has(x, y): whether a record has the field y, a list the item y or a string the text y",
    ),
    (
        "merge",
        "merge(a, b): record a with b's fields over it, records inside merged the same way",
    ),
    ("join", "join(list, between): its items as one string"),
    ("split", "split(string, at): the pieces of a string between each `at`"),
    (
        "replace",
        "replace(string, from, to): the string with every `from` made `to`",
    ),
    ("string", "string(x): a number, true or false as text"),
    (
        "int",
        "int(x): a whole number from a string or from a number with a fraction (which is cut off)",
    ),
    ("json", "json(x): a value written out as JSON"),
    ("yaml", "yaml(x): a value written out as YAML"),
    ("b64", "b64(string): its bytes in base64"),
    ("error", "error(message): stops here with that message"),
];

impl V {
    fn kind(&self) -> &'static str {
        match self {
            V::Null => "null",
            V::Bool(_) => "true or false",
            V::Int(_) | V::Float(_) => "a number",
            V::Str(_) => "a string",
            V::List(_) => "a list",
            V::Rec(_) => "a record",
            V::Fn(_) | V::Builtin(_) => "a function",
        }
    }

    fn number(&self) -> Option<f64> {
        match self {
            V::Int(n) => Some(*n as f64),
            V::Float(n) => Some(*n),
            _ => None,
        }
    }
}

fn fail(at: At, msg: impl Into<String>) -> Box<Fail> {
    Box::new(Fail {
        at,
        msg: msg.into(),
        missing: false,
    })
}

/// What `??` takes for an answer: a field or an item that is not there.
fn missing(at: At, msg: String) -> Box<Fail> {
    Box::new(Fail { at, msg, missing: true })
}

/// A field put into a record: over the one of that name, or at the end.
fn put(fields: &mut Vec<Entry>, entry: Entry) {
    match fields.iter_mut().find(|field| field.key == entry.key) {
        Some(field) => *field = entry,
        None => fields.push(entry),
    }
}

fn b64(bytes: &[u8]) -> String {
    const LETTERS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let bits = chunk.iter().fold(0u32, |bits, byte| bits << 8 | u32::from(*byte)) << (8 * (3 - chunk.len()));
        for n in 0..4 {
            out.push(match n <= chunk.len() {
                true => char::from(LETTERS[(bits >> (18 - 6 * n)) as usize & 63]),
                false => '=',
            });
        }
    }
    out
}

/// The file an import names, from the file it is written in: inside the directory the
/// first file is in, or refused.
fn resolve(from: &str, path: &str) -> std::result::Result<String, String> {
    if path.starts_with('/') || path.contains('\\') || !path.ends_with(".kith") {
        return Err(format!(
            "an import names a .kith file from the file it is in (\"./lib.kith\"), not \"{path}\""
        ));
    }
    let mut parts: Vec<&str> = from.split('/').collect();
    parts.pop();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.pop().is_none() => {
                return Err(format!("\"{path}\" is outside the directory the first file is in"));
            }
            ".." => {}
            part => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

pub(crate) struct Machine<'a> {
    load: Load<'a>,
    /// Each file read: its name, its text, and where each of its lines starts.
    pub files: Vec<(String, String, Vec<u32>)>,
    /// Each file imported, and what it gave once it has.
    imported: Vec<(String, Option<V>)>,
    /// Where the first file says the value it gives.
    pub gave: At,
    globals: Env,
    steps: u64,
    depth: u32,
}

impl<'a> Machine<'a> {
    pub fn new(load: Load<'a>, globals: &[(&str, serde_json::Value)]) -> Self {
        let mut env = None;
        for (name, value) in globals {
            env = bind(&env, &Rc::from(*name), given(value));
        }
        Machine {
            load,
            files: Vec::new(),
            imported: Vec::new(),
            gave: At { file: 0, off: 0 },
            globals: env,
            steps: 0,
            depth: 0,
        }
    }

    fn spend(&mut self, steps: usize, at: At) -> Result<()> {
        self.steps += steps as u64;
        match self.steps > STEPS {
            true => Err(fail(at, format!("did not end in {STEPS} steps"))),
            false => Ok(()),
        }
    }

    /// A file's value: read, parsed and worked out, once.
    pub fn file(&mut self, name: &str, at: At) -> Result<V> {
        if let Some((_, known)) = self.imported.iter().find(|(known, _)| known == name) {
            return known.clone().ok_or_else(|| fail(at, format!("{name} imports itself")));
        }
        let text = (self.load)(name).map_err(|why| fail(at, format!("{name}: {why}")))?;
        if text.len() > SIZE || self.files.len() == FILES {
            return Err(fail(
                at,
                format!("{name}: more than {SIZE} bytes, or more than {FILES} files"),
            ));
        }
        let file = self.files.len() as u8;
        let lines = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(at, _)| at as u32 + 1))
            .collect();
        self.files.push((name.into(), text, lines));
        self.imported.push((name.into(), None));
        let tree = parse::file(&self.files[usize::from(file)].1).map_err(|mut fail| {
            fail.at.file = file;
            fail
        })?;
        if file == 0 {
            self.gave.off = match &tree.is {
                Is::Block(_, tail) => tail.at,
                _ => tree.at,
            };
        }
        let value = self.eval(&tree, &self.globals.clone(), file)?;
        self.imported[usize::from(file)].1 = Some(value.clone());
        Ok(value)
    }

    /// One level down, into what is being worked out or into a value.
    fn deeper<T>(&mut self, at: At, inside: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.depth == DEPTH {
            let why = "a function that calls itself and never stops, or a value nested that far";
            return Err(fail(at, format!("more than {DEPTH} deep: {why}")));
        }
        self.depth += 1;
        let out = inside(self);
        self.depth -= 1;
        out
    }

    fn eval(&mut self, tree: &Expr, env: &Env, file: u8) -> Result<V> {
        let at = At { file, off: tree.at };
        self.spend(1, at)?;
        self.deeper(at, |machine| machine.eval_at(tree, env, file, at))
    }

    /// Whether two values are the same. A value can hold another twice over at every
    /// level, and so be far larger than what it took to make: a step for each part.
    fn same(&mut self, a: &V, b: &V, at: At) -> Result<bool> {
        self.spend(1, at)?;
        Ok(match (a, b) {
            (V::Null, V::Null) => true,
            (V::Bool(a), V::Bool(b)) => a == b,
            (V::Int(a), V::Int(b)) => a == b,
            (V::Str(a), V::Str(b)) => a.len() == b.len() && self.spend(a.len() / 64, at).map(|()| a == b)?,
            (V::List(a), V::List(b)) if a.len() == b.len() => self.deeper(at, |machine| {
                for (a, b) in a.iter().zip(b.iter()) {
                    if !machine.same(&a.0, &b.0, at)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            })?,
            (V::Rec(a), V::Rec(b)) if a.len() == b.len() => self.deeper(at, |machine| {
                for field in a.iter() {
                    machine.spend(b.len() / 64, at)?;
                    match b.iter().find(|other| other.key == field.key) {
                        Some(other) if machine.same(&field.value, &other.value, at)? => {}
                        _ => return Ok(false),
                    }
                }
                Ok(true)
            })?,
            (V::List(_), V::List(_)) | (V::Rec(_), V::Rec(_)) => false,
            // (A function is the same as nothing, itself included.)
            _ => matches!((a.number(), b.number()), (Some(a), Some(b)) if a == b),
        })
    }

    /// `under` with `over`'s fields over it, records in both merged the same way.
    fn merge(&mut self, under: &[Entry], over: &[Entry], at: At) -> Result<V> {
        self.spend(under.len() + over.len() * (1 + (under.len() + over.len()) / 32), at)?;
        let mut fields = under.to_vec();
        for entry in over {
            let both = match (
                fields
                    .iter()
                    .find(|field| field.key == entry.key)
                    .map(|field| &field.value),
                &entry.value,
            ) {
                (Some(V::Rec(under)), V::Rec(over)) => {
                    Some(self.deeper(at, |machine| machine.merge(&under.clone(), over, at))?)
                }
                _ => None,
            };
            put(
                &mut fields,
                Entry {
                    value: both.unwrap_or_else(|| entry.value.clone()),
                    ..entry.clone()
                },
            );
        }
        Ok(V::Rec(Rc::new(fields)))
    }

    fn truth(&mut self, tree: &Expr, env: &Env, file: u8) -> Result<bool> {
        match self.eval(tree, env, file)? {
            V::Bool(truth) => Ok(truth),
            other => Err(fail(
                At { file, off: tree.at },
                format!("expected true or false, not {}", other.kind()),
            )),
        }
    }

    fn eval_at(&mut self, tree: &Expr, env: &Env, file: u8, at: At) -> Result<V> {
        let place = |tree: &Expr| At { file, off: tree.at };
        Ok(match &tree.is {
            Is::Null => V::Null,
            Is::Bool(b) => V::Bool(*b),
            Is::Int(n) => V::Int(*n),
            Is::Float(n) => V::Float(*n),
            Is::Str(parts) => {
                let mut text = String::new();
                for part in parts {
                    match part {
                        Part::Text(part) => text.push_str(part),
                        Part::Expr(part) => {
                            let value = self.eval(part, env, file)?;
                            let part = self.text(&value, place(part))?;
                            self.spend(part.len() / 16, at)?;
                            text.push_str(&part);
                        }
                    }
                }
                V::Str(text.into())
            }
            Is::Var(name) => {
                let (value, passed) = lookup(env, name);
                self.spend(passed / 64, at)?;
                match (value, BUILTINS.iter().find(|(builtin, _)| *builtin == &**name)) {
                    (Some(value), _) => value,
                    (None, Some((builtin, _))) => V::Builtin(builtin),
                    (None, None) => return Err(fail(at, format!("nothing here is named `{name}`"))),
                }
            }
            Is::List(items) => {
                let mut list = Vec::new();
                for item in items {
                    match item {
                        Item::One(item) => list.push((self.eval(item, env, file)?, place(item))),
                        Item::Spread(more) => match &self.eval(more, env, file)? {
                            V::List(more) => {
                                self.spend(more.len(), at)?;
                                list.extend(more.iter().cloned());
                            }
                            V::Null => {}
                            other => {
                                return Err(fail(
                                    place(more),
                                    format!("`..` in a list takes a list, not {}", other.kind()),
                                ));
                            }
                        },
                        Item::For { name, of, when, give } => {
                            let each = self.eval(of, env, file)?;
                            let V::List(each) = &each else {
                                return Err(fail(
                                    place(of),
                                    "`for` goes through a list (entries(record) makes one of a record)",
                                ));
                            };
                            for (item, _) in each.iter() {
                                let env = bind(env, name, item.clone());
                                if match when {
                                    Some(when) => self.truth(when, &env, file)?,
                                    None => true,
                                } {
                                    list.push((self.eval(give, &env, file)?, place(give)));
                                }
                            }
                        }
                    }
                }
                V::List(Rc::new(list))
            }
            Is::Rec(fields) => {
                let (mut record, mut said) = (Vec::new(), Vec::new());
                for field in fields {
                    match field {
                        Field::Spread(more) => match &self.eval(more, env, file)? {
                            V::Rec(more) => {
                                // (Each field is looked for among those there are.)
                                self.spend(more.len() * (1 + (record.len() + more.len()) / 64), at)?;
                                more.iter().for_each(|entry| put(&mut record, entry.clone()));
                            }
                            V::Null => {}
                            other => {
                                return Err(fail(
                                    place(more),
                                    format!("`..` in a record takes a record, not {}", other.kind()),
                                ));
                            }
                        },
                        Field::Pair { key, at: key_at, value } => {
                            let key_at = At { file, off: *key_at };
                            let key: Rc<str> = match key {
                                Key::Name(name) => name.as_str().into(),
                                Key::Expr(name) => match &self.eval(name, env, file)? {
                                    V::Str(name) => name.clone(),
                                    other => {
                                        return Err(fail(
                                            key_at,
                                            format!("a field's name is a string, not {}", other.kind()),
                                        ));
                                    }
                                },
                            };
                            self.spend(record.len() / 32, key_at)?;
                            if said.contains(&key) {
                                return Err(fail(key_at, format!("`{key}` is given twice")));
                            }
                            said.push(key.clone());
                            let entry = Entry {
                                key,
                                key_at,
                                value: self.eval(value, env, file)?,
                                at: place(value),
                            };
                            put(&mut record, entry);
                        }
                    }
                }
                V::Rec(Rc::new(record))
            }
            Is::Block(binds, tail) => {
                let mut env = env.clone();
                for (name, bound) in binds {
                    let bound = match bound {
                        Bind::Let(value) => Bound::Value(self.eval(value, &env, file)?),
                        Bind::Fn(lambda) => Bound::Fn(lambda.clone(), file),
                    };
                    env = Some(Rc::new(Scope {
                        name: name.clone(),
                        bound,
                        up: env,
                    }));
                }
                self.eval(tail, &env, file)?
            }
            Is::If(parts) => {
                let [when, then, otherwise] = &**parts;
                match self.truth(when, env, file)? {
                    true => self.eval(then, env, file)?,
                    false => self.eval(otherwise, env, file)?,
                }
            }
            Is::Fn(lambda) => V::Fn(Rc::new(Closure {
                lambda: lambda.clone(),
                env: env.clone(),
                file,
            })),
            Is::Call(function, args) => {
                let function = self.eval(function, env, file)?;
                let mut given = Vec::with_capacity(args.len());
                for arg in args {
                    given.push(self.eval(arg, env, file)?);
                }
                // (What is missing inside a function is the function's business, not a `??` outside it.)
                self.call(&function, given, at).map_err(|mut fail| {
                    fail.missing = false;
                    fail
                })?
            }
            Is::Field(of, name) => {
                let of = self.eval(of, env, file)?;
                self.field(&of, name, at)?
            }
            Is::Index(parts) => {
                let (of, index) = (self.eval(&parts[0], env, file)?, self.eval(&parts[1], env, file)?);
                match (&of, &index) {
                    (V::List(list), V::Int(n)) => match usize::try_from(*n).ok().and_then(|n| list.get(n)) {
                        Some((item, _)) => item.clone(),
                        None => return Err(missing(at, format!("no item {n}: the list has {}", list.len()))),
                    },
                    (V::Rec(_) | V::Null, V::Str(name)) => self.field(&of, name, at)?,
                    _ => return Err(fail(at, format!("{} has no item named by {}", of.kind(), index.kind()))),
                }
            }
            Is::Not(of) => V::Bool(!self.truth(of, env, file)?),
            Is::Neg(of) => match self.eval(of, env, file)? {
                V::Int(n) => V::Int(n.checked_neg().ok_or_else(|| fail(at, "too large a number"))?),
                V::Float(n) => V::Float(-n),
                other => return Err(fail(at, format!("`-` takes a number, not {}", other.kind()))),
            },
            Is::Op("??", parts) => match self.eval(&parts[0], env, file) {
                Ok(V::Null) => self.eval(&parts[1], env, file)?,
                Err(fail) if fail.missing => self.eval(&parts[1], env, file)?,
                other => other?,
            },
            Is::Op("&&", parts) => V::Bool(self.truth(&parts[0], env, file)? && self.truth(&parts[1], env, file)?),
            Is::Op("||", parts) => V::Bool(self.truth(&parts[0], env, file)? || self.truth(&parts[1], env, file)?),
            Is::Op(op, parts) => {
                let (a, b) = (self.eval(&parts[0], env, file)?, self.eval(&parts[1], env, file)?);
                self.op(op, &a, &b, at)?
            }
            Is::Import(path) => {
                let name = resolve(&self.files[usize::from(file)].0, path).map_err(|why| fail(at, why))?;
                self.file(&name, at)?
            }
            Is::Kind(kind, record) => {
                let record = self.eval(record, env, file)?;
                let V::Rec(record) = &record else {
                    unreachable!("the grammar puts a record here")
                };
                self.spend(record.len(), at)?;
                let field = |key: &str, value: &str| Entry {
                    key: key.into(),
                    key_at: at,
                    value: V::Str(value.into()),
                    at,
                };
                // (A kind of the cluster's own says its apiVersion itself.)
                let ours = !record.iter().any(|entry| &*entry.key == "apiVersion");
                let mut fields: Vec<Entry> = ours
                    .then(|| field("apiVersion", kith_api::API_VERSION))
                    .into_iter()
                    .collect();
                fields.push(field("kind", kind));
                if let Some(entry) = record.iter().find(|entry| &*entry.key == "kind") {
                    return Err(fail(entry.key_at, format!("`{kind} {{` says the kind already")));
                }
                fields.extend(record.iter().cloned());
                V::Rec(Rc::new(fields))
            }
        })
    }

    fn field(&mut self, of: &V, name: &str, at: At) -> Result<V> {
        match of {
            V::Rec(fields) => match self
                .spend(fields.len() / 64, at)
                .map(|()| fields.iter().find(|field| &*field.key == name))?
            {
                Some(field) => Ok(field.value.clone()),
                None => {
                    let there: Vec<&str> = fields.iter().map(|field| &*field.key).collect();
                    Err(missing(
                        at,
                        format!("no field `{name}` (there is: {})", there.join(", ")),
                    ))
                }
            },
            V::Null => Err(missing(at, format!("no field `{name}`: this is null"))),
            other => Err(fail(at, format!("{} has no field `{name}`", other.kind()))),
        }
    }

    fn call(&mut self, function: &V, args: Vec<V>, at: At) -> Result<V> {
        match function {
            V::Fn(closure) => {
                let (name, params) = (&closure.lambda.name, &closure.lambda.params);
                if args.len() > params.len() {
                    return Err(fail(
                        at,
                        format!("{name} takes {} values, not {}", params.len(), args.len()),
                    ));
                }
                let (mut env, mut args) = (closure.env.clone(), args.into_iter());
                for (param, default) in params {
                    let value = match (args.next(), default) {
                        (Some(value), _) => value,
                        (None, Some(default)) => self.eval(default, &env, closure.file)?,
                        (None, None) => return Err(fail(at, format!("{name} is not given its `{param}`"))),
                    };
                    env = bind(&env, param, value);
                }
                self.eval(&closure.lambda.body, &env, closure.file)
            }
            V::Builtin(name) => self.builtin(name, &args, at),
            other => Err(fail(at, format!("{} cannot be called", other.kind()))),
        }
    }

    fn op(&mut self, op: &str, a: &V, b: &V, at: At) -> Result<V> {
        let wrong = || fail(at, format!("`{op}` does not take {} and {}", a.kind(), b.kind()));
        if let "==" | "!=" = op {
            return Ok(V::Bool(self.same(a, b, at)? == (op == "==")));
        }
        if let "<" | "<=" | ">" | ">=" = op {
            let order = match (a, b) {
                (V::Int(a), V::Int(b)) => a.cmp(b),
                (V::Str(a), V::Str(b)) => self.spend(a.len().min(b.len()) / 64, at).map(|()| a.cmp(b))?,
                _ => a
                    .number()
                    .zip(b.number())
                    .and_then(|(a, b)| a.partial_cmp(&b))
                    .ok_or_else(wrong)?,
            };
            return Ok(V::Bool(match op {
                "<" => order == Ordering::Less,
                "<=" => order != Ordering::Greater,
                ">" => order == Ordering::Greater,
                _ => order != Ordering::Less,
            }));
        }
        Ok(match (op, a, b) {
            ("+", V::Str(a), V::Str(b)) => {
                self.spend((a.len() + b.len()) / 16, at)?;
                V::Str(format!("{a}{b}").into())
            }
            ("+", V::List(a), V::List(b)) => {
                self.spend(a.len() + b.len(), at)?;
                V::List(Rc::new(a.iter().chain(b.iter()).cloned().collect()))
            }
            (_, V::Int(a), V::Int(b)) => {
                let (a, b) = (*a, *b);
                let n = match op {
                    "+" => a.checked_add(b),
                    "-" => a.checked_sub(b),
                    "*" => a.checked_mul(b),
                    _ if b == 0 => return Err(fail(at, "divided by 0")),
                    "/" => a.checked_div(b),
                    _ => a.checked_rem(b),
                };
                V::Int(n.ok_or_else(|| fail(at, "too large a number"))?)
            }
            _ => {
                let (a, b) = a.number().zip(b.number()).ok_or_else(wrong)?;
                let n = match op {
                    "+" => a + b,
                    "-" => a - b,
                    "*" => a * b,
                    _ if b == 0.0 => return Err(fail(at, "divided by 0")),
                    "/" => a / b,
                    _ => a % b,
                };
                // (What is no number is refused here, where it was worked out.)
                if !n.is_finite() {
                    return Err(fail(at, "too large a number"));
                }
                V::Float(n)
            }
        })
    }

    /// A value as the text it is in a string: text, a number, true or false.
    fn text(&mut self, value: &V, at: At) -> Result<String> {
        Ok(match value {
            V::Str(text) => text.to_string(),
            V::Int(n) => n.to_string(),
            V::Float(n) => n.to_string(),
            V::Bool(b) => b.to_string(),
            other => {
                return Err(fail(
                    at,
                    format!("{} is not text (json(x) writes any value out)", other.kind()),
                ));
            }
        })
    }

    fn builtin(&mut self, name: &'static str, args: &[V], at: At) -> Result<V> {
        let list = |items: Vec<V>| V::List(Rc::new(items.into_iter().map(|item| (item, at)).collect()));
        let string = |text: &str| V::Str(text.into());
        // What it is given is gone through at least once.
        let size = |value: &V| match value {
            V::Str(text) => text.len() / 64,
            V::List(items) => items.len(),
            V::Rec(fields) => fields.len(),
            _ => 0,
        };
        self.spend(args.iter().map(size).sum(), at)?;
        Ok(match (name, args) {
            ("len", [V::List(items)]) => V::Int(items.len() as i64),
            ("len", [V::Rec(fields)]) => V::Int(fields.len() as i64),
            ("len", [V::Str(text)]) => V::Int(text.chars().count() as i64),
            ("map", [V::List(items), function]) => {
                let mut out = Vec::with_capacity(items.len());
                for (item, _) in items.iter() {
                    out.push((self.call(function, vec![item.clone()], at)?, at));
                }
                V::List(Rc::new(out))
            }
            ("filter", [V::List(items), function]) => {
                let mut out = Vec::new();
                for item in items.iter() {
                    match self.call(function, vec![item.0.clone()], at)? {
                        V::Bool(true) => out.push(item.clone()),
                        V::Bool(false) => {}
                        other => {
                            return Err(fail(
                                at,
                                format!("filter's function gives true or false, not {}", other.kind()),
                            ));
                        }
                    }
                }
                V::List(Rc::new(out))
            }
            ("range", [V::Int(to)]) | ("range", [V::Int(_), V::Int(to)]) => {
                let from = match args {
                    [V::Int(from), _] => *from,
                    _ => 0,
                };
                self.spend(usize::try_from(to.saturating_sub(from)).unwrap_or(0), at)?;
                list((from..*to).map(V::Int).collect())
            }
            ("sort", [V::List(items)]) => {
                // (What `<` puts in order: strings among strings, numbers among numbers.)
                let strings = items.iter().all(|(item, _)| matches!(item, V::Str(_)));
                if !strings && !items.iter().all(|(item, _)| item.number().is_some()) {
                    return Err(fail(at, "sort takes a list of strings or a list of numbers"));
                }
                // (Every item is held against about log2 of them others, a string by its bytes.)
                let long: usize = items
                    .iter()
                    .map(|(item, _)| if let V::Str(text) = item { text.len() / 64 } else { 0 })
                    .sum();
                self.spend((items.len() + long) * items.len().max(2).ilog2() as usize, at)?;
                // (One order for the whole list, or sorting may panic: whole numbers as they
                // are when all of it is whole numbers, and every one as a fraction otherwise.)
                let whole = items.iter().all(|(item, _)| matches!(item, V::Int(_)));
                let mut sorted = items.to_vec();
                sorted.sort_by(|(a, _), (b, _)| match (a, b) {
                    (V::Str(a), V::Str(b)) => a.cmp(b),
                    (V::Int(a), V::Int(b)) if whole => a.cmp(b),
                    _ => a.number().unwrap_or(0.0).total_cmp(&b.number().unwrap_or(0.0)),
                });
                V::List(Rc::new(sorted))
            }
            ("keys", [V::Rec(fields)]) => list(fields.iter().map(|field| V::Str(field.key.clone())).collect()),
            ("values", [V::Rec(fields)]) => V::List(Rc::new(
                fields.iter().map(|field| (field.value.clone(), field.at)).collect(),
            )),
            ("entries", [V::Rec(fields)]) => list(
                fields
                    .iter()
                    .map(|field| {
                        let key = Entry {
                            key: "key".into(),
                            key_at: field.key_at,
                            value: V::Str(field.key.clone()),
                            at: field.key_at,
                        };
                        V::Rec(Rc::new(vec![
                            key,
                            Entry {
                                key: "value".into(),
                                ..field.clone()
                            },
                        ]))
                    })
                    .collect(),
            ),
            ("record", [V::List(items)]) => {
                let mut fields = Vec::new();
                for (item, item_at) in items.iter() {
                    match (&self.field(item, "key", at), &self.field(item, "value", at)) {
                        (Ok(V::Str(key)), Ok(value)) => {
                            self.spend(fields.len() / 64, at)?;
                            put(
                                &mut fields,
                                Entry {
                                    key: key.clone(),
                                    key_at: *item_at,
                                    value: value.clone(),
                                    at: *item_at,
                                },
                            )
                        }
                        _ => return Err(fail(at, "record takes a list of { key, value }, each key a string")),
                    }
                }
                V::Rec(Rc::new(fields))
            }
            ("has", [V::Rec(fields), V::Str(name)]) => V::Bool(fields.iter().any(|field| field.key == *name)),
            ("has", [V::List(items), item]) => {
                let mut found = false;
                for (other, _) in items.iter() {
                    found = found || self.same(other, item, at)?;
                }
                V::Bool(found)
            }
            ("has", [V::Str(text), V::Str(part)]) => V::Bool(text.contains(&**part)),
            ("merge", [V::Rec(under), V::Rec(over)]) => self.merge(under, over, at)?,
            ("join", [V::List(items), V::Str(between)]) => {
                let mut joined = String::new();
                for (n, (item, _)) in items.iter().enumerate() {
                    let part = self.text(item, at)?;
                    self.spend((part.len() + between.len()) / 16, at)?;
                    joined.push_str(if n == 0 { "" } else { between });
                    joined.push_str(&part);
                }
                V::Str(joined.into())
            }
            ("split", [V::Str(whole), V::Str(between)]) if !between.is_empty() => {
                self.spend(whole.len() / 16 + whole.matches(&**between).count(), at)?;
                list(whole.split(&**between).map(string).collect())
            }
            ("replace", [V::Str(whole), V::Str(from), V::Str(to)]) if !from.is_empty() => {
                self.spend((whole.len() + whole.matches(&**from).count() * to.len()) / 16, at)?;
                V::Str(whole.replace(&**from, to).into())
            }
            ("string", [value]) => V::Str(self.text(value, at)?.into()),
            ("int", [V::Int(n)]) => V::Int(*n),
            ("int", [V::Float(n)]) if n.is_finite() && n.abs() < 9e18 => V::Int(*n as i64),
            ("int", [V::Str(digits)]) => V::Int(
                digits
                    .trim()
                    .parse()
                    .map_err(|_| fail(at, format!("\"{digits}\" is not a whole number")))?,
            ),
            ("json" | "yaml", [value]) => {
                let json = kith_yaml::from_node::<serde_json::Value>(&self.node(
                    value,
                    at,
                    Pos { line: 1, col: 1 },
                    &mut 0,
                )?);
                let json = json.map_err(|e| fail(at, e.msg))?;
                let written = if name == "json" {
                    json.to_string()
                } else {
                    kith_yaml::to_string(&json)
                };
                self.spend(written.len() / 16, at)?;
                V::Str(written.into())
            }
            ("b64", [V::Str(plain)]) => self
                .spend(plain.len() / 8, at)
                .map(|()| V::Str(b64(plain.as_bytes()).into()))?,
            ("error", [V::Str(message)]) => return Err(fail(at, message.to_string())),
            _ => {
                let given: Vec<&str> = args.iter().map(V::kind).collect();
                let usage = BUILTINS
                    .iter()
                    .find(|(builtin, _)| *builtin == name)
                    .map_or("", |(_, usage)| usage);
                return Err(fail(at, format!("{name} is not given ({}): {usage}", given.join(", "))));
            }
        })
    }

    /// A position as kith-yaml has them: line and column, with the file in the line's
    /// high bits (`crate::place` takes them apart again).
    pub fn pos(&self, at: At) -> Pos {
        let (_, text, lines) = &self.files[usize::from(at.file)];
        let line = lines.partition_point(|start| *start <= at.off) - 1;
        // (A place inside a letter of more than one byte is that letter's: never a panic.)
        let off = (0..=at.off as usize)
            .rev()
            .find(|off| text.is_char_boundary(*off))
            .unwrap_or(0);
        let col = text[lines[line] as usize..off.max(lines[line] as usize)]
            .chars()
            .count()
            + 1;
        Pos {
            line: usize::from(at.file) << 24 | (line + 1),
            col,
        }
    }

    /// A value as the document kith-yaml would have parsed, each part with the place it
    /// was said. What is null is left out of records and lists; `size` counts what is written.
    pub fn node(&mut self, value: &V, at: At, parent: Pos, size: &mut usize) -> Result<Node> {
        self.deeper(at, |machine| machine.node_at(value, at, parent, size))
    }

    fn node_at(&mut self, value: &V, at: At, parent: Pos, size: &mut usize) -> Result<Node> {
        let pos = if at.file == At::NOWHERE.file {
            parent
        } else {
            self.pos(at)
        };
        let scalar = |text: String, plain: bool| Yaml::Scalar { text, plain };
        let value = match value {
            V::Null => scalar("null".into(), true),
            V::Bool(b) => scalar(b.to_string(), true),
            V::Int(n) => scalar(n.to_string(), true),
            V::Float(n) if n.is_finite() => scalar(format!("{n:?}"), true),
            V::Float(_) => return Err(fail(at, "not a number any more (divided by 0?)")),
            V::Str(text) => scalar(text.to_string(), false),
            V::List(items) => {
                let mut nodes = Vec::with_capacity(items.len());
                for (item, at) in items.iter().filter(|(item, _)| !matches!(item, V::Null)) {
                    nodes.push(self.node(item, *at, pos, size)?);
                }
                Yaml::Seq(nodes)
            }
            V::Rec(fields) => {
                let mut nodes = Vec::with_capacity(fields.len());
                for field in fields.iter().filter(|field| !matches!(field.value, V::Null)) {
                    *size += field.key.len();
                    let key_pos = if field.key_at.file == At::NOWHERE.file {
                        pos
                    } else {
                        self.pos(field.key_at)
                    };
                    nodes.push((
                        kith_yaml::Key {
                            name: field.key.to_string(),
                            pos: key_pos,
                        },
                        self.node(&field.value, field.at, pos, size)?,
                    ));
                }
                Yaml::Map(nodes)
            }
            V::Fn(_) | V::Builtin(_) => return Err(fail(at, "a function cannot be written out: call it")),
        };
        *size += match &value {
            Yaml::Scalar { text, .. } => text.len() + 4,
            _ => 4,
        };
        match *size > SIZE {
            true => Err(fail(at, format!("gives more than {SIZE} bytes"))),
            false => Ok(Node { pos, value }),
        }
    }
}

/// A value handed in from outside (a package's `values`): said nowhere in a file.
fn given(value: &serde_json::Value) -> V {
    use serde_json::Value as Json;
    match value {
        Json::Null => V::Null,
        Json::Bool(b) => V::Bool(*b),
        Json::Number(n) => n.as_i64().map(V::Int).or(n.as_f64().map(V::Float)).unwrap_or(V::Null),
        Json::String(text) => V::Str(text.as_str().into()),
        Json::Array(items) => V::List(Rc::new(items.iter().map(|item| (given(item), At::NOWHERE)).collect())),
        Json::Object(fields) => V::Rec(Rc::new(
            fields
                .iter()
                .map(|(key, value)| Entry {
                    key: key.as_str().into(),
                    key_at: At::NOWHERE,
                    value: given(value),
                    at: At::NOWHERE,
                })
                .collect(),
        )),
    }
}
