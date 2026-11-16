//! A serde `Deserializer` over a parsed [`Node`]. The target type decides how a
//! scalar is read, so nothing is coerced behind the schema's back, and every
//! error is stamped with the position of the node it was raised on.

use crate::parse::{Key, Node, Value, parse};
use crate::{Error, Plain, Pos, resolve};
use serde::de::{self, DeserializeOwned, DeserializeSeed, IntoDeserializer, Unexpected, Visitor};

impl de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error {
            msg: msg.to_string(),
            pos: None,
        }
    }
}

pub fn from_node<T: DeserializeOwned>(node: &Node) -> Result<T, Error> {
    T::deserialize(De(node, false))
}

/// Read JSON by the same code as YAML (one `Deserialize` per type in the binary, not one for
/// each format), with JSON's types: a number, a bool or a null is no string nor a variant's
/// name, as serde_json has it. The errors have no position.
pub fn from_json<T: DeserializeOwned>(json: &serde_json::Value) -> Result<T, Error> {
    use serde_json::Value as Json;
    fn node(json: &Json) -> Node {
        let scalar = |text: String, plain| Value::Scalar { text, plain };
        let value = match json {
            Json::Null => scalar("null".into(), true),
            Json::Bool(b) => scalar(b.to_string(), true),
            Json::Number(n) => scalar(n.to_string(), true),
            Json::String(s) => scalar(s.clone(), false),
            Json::Array(items) => Value::Seq(items.iter().map(node).collect()),
            Json::Object(fields) => Value::Map(
                fields
                    .iter()
                    .map(|(name, value)| {
                        (
                            Key {
                                name: name.clone(),
                                pos: Pos::default(),
                            },
                            node(value),
                        )
                    })
                    .collect(),
            ),
        };
        Node {
            pos: Pos::default(),
            value,
        }
    }
    T::deserialize(De(&node(json), true)).map_err(|e| Error { msg: e.msg, pos: None })
}

/// Parse a source holding exactly one document.
pub fn from_str<T: DeserializeOwned>(src: &str) -> Result<T, Error> {
    match parse(src)?.as_slice() {
        [doc] => from_node(doc),
        docs => Err(Error {
            msg: format!("expected one document, found {}", docs.len()),
            pos: None,
        }),
    }
}

/// Stamp an error with `pos` unless a deeper node already did.
fn at<T>(pos: Pos, result: Result<T, Error>) -> Result<T, Error> {
    result.map_err(|mut e| {
        e.pos.get_or_insert(pos);
        e
    })
}

/// A node, and whether it came from JSON (`true`): then a plain scalar is a number, a bool or
/// a null, and only that.
struct De<'a>(&'a Node, bool);

impl<'a> De<'a> {
    fn is_null(&self) -> bool {
        matches!(&self.0.value, Value::Scalar { text, plain: true } if resolve(text) == Plain::Null)
    }

    /// What JSON's reader says of this node where `wanted` is wanted.
    fn json_refuses(&self, wanted: &str) -> Error {
        let unexpected = match &self.0.value {
            Value::Scalar { text, plain: false } => Unexpected::Str(text),
            Value::Scalar { text, plain: true } => match resolve(text) {
                Plain::Null => Unexpected::Other("null"),
                Plain::Bool(b) => Unexpected::Bool(b),
                Plain::Int(i) => Unexpected::Signed(i),
                Plain::UInt(u) => Unexpected::Unsigned(u),
                Plain::Float(f) => Unexpected::Float(f),
                Plain::Str(s) => Unexpected::Str(s),
            },
            Value::Seq(_) => Unexpected::Seq,
            Value::Map(_) => Unexpected::Map,
        };
        de::Error::invalid_type(unexpected, &wanted)
    }

    /// A null where something else is wanted, as YAML's reader says it or as serde_json does.
    fn null(&self, wanted: &dyn de::Expected) -> Error {
        let null = if self.1 {
            Unexpected::Other("null")
        } else {
            Unexpected::Unit
        };
        de::Error::invalid_type(null, wanted)
    }
}

/// What reads as anything (`deserialize_any`), but a null from JSON is refused as serde_json
/// refuses it. (From YAML a null is read as `()` and refused by what wanted something else.)
macro_rules! not_null {
    ($($name:ident($($arg:ident: $ty:ty),*))*) => {$(
        fn $name<V: Visitor<'de>>(self, $($arg: $ty,)* v: V) -> Result<V::Value, Error> {
            if self.1 && self.is_null() {
                return at(self.0.pos, Err(self.null(&v)));
            }
            self.deserialize_any(v)
        }
    )*};
}

impl<'de> de::Deserializer<'de> for De<'_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        let result = match &self.0.value {
            Value::Scalar { text, plain: false } => v.visit_str(text),
            Value::Scalar { text, plain: true } => match resolve(text) {
                Plain::Null => v.visit_unit(),
                Plain::Bool(b) => v.visit_bool(b),
                Plain::Int(i) => v.visit_i64(i),
                Plain::UInt(u) => v.visit_u64(u),
                Plain::Float(f) => v.visit_f64(f),
                Plain::Str(s) => v.visit_str(s),
            },
            Value::Seq(items) => v.visit_seq(Seq(items.iter(), self.1)),
            Value::Map(entries) => v.visit_map(Map {
                iter: entries.iter(),
                value: None,
                json: self.1,
            }),
        };
        at(self.0.pos, result)
    }

    /// A string field takes any scalar's raw text: `1.0`, `no` and `true` stay strings.
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        match &self.0.value {
            Value::Scalar { .. } if self.is_null() => at(self.0.pos, Err(self.null(&v))),
            Value::Scalar { plain: true, .. } if self.1 => self.deserialize_any(v),
            Value::Scalar { text, .. } => at(self.0.pos, v.visit_str(text)),
            _ => self.deserialize_any(v),
        }
    }

    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        self.deserialize_str(v)
    }

    fn deserialize_char<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        self.deserialize_str(v)
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        self.deserialize_str(v)
    }

    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        if self.is_null() {
            v.visit_none()
        } else {
            v.visit_some(self)
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _: &'static str, v: V) -> Result<V::Value, Error> {
        v.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, Error> {
        let result = match &self.0.value {
            // (As serde_json says it.)
            Value::Scalar { plain: true, .. } if self.1 => Err(self.json_refuses("string or map")),
            Value::Scalar { text, .. } => v.visit_enum(text.as_str().into_deserializer()),
            Value::Map(entries) if entries.len() == 1 => v.visit_enum(Variant(&entries[0].0, &entries[0].1, self.1)),
            _ => Err(de::Error::custom("expected a variant name or a map with a single key")),
        };
        at(self.0.pos, result)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_unit()
    }

    not_null! {
        deserialize_bool() deserialize_i8() deserialize_i16() deserialize_i32() deserialize_i64()
        deserialize_i128() deserialize_u8() deserialize_u16() deserialize_u32() deserialize_u64()
        deserialize_u128() deserialize_f32() deserialize_f64() deserialize_bytes() deserialize_byte_buf()
        deserialize_seq() deserialize_map() deserialize_tuple(_len: usize)
        deserialize_tuple_struct(_name: &'static str, _len: usize)
        deserialize_struct(_name: &'static str, _fields: &'static [&'static str])
    }

    serde::forward_to_deserialize_any! { unit unit_struct }
}

struct Seq<'a>(std::slice::Iter<'a, Node>, bool);

impl<'de> de::SeqAccess<'de> for Seq<'_> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, Error> {
        self.0
            .next()
            .map(|node| at(node.pos, seed.deserialize(De(node, self.1))))
            .transpose()
    }
}

struct Map<'a> {
    iter: std::slice::Iter<'a, (Key, Node)>,
    value: Option<&'a Node>,
    json: bool,
}

impl<'de> de::MapAccess<'de> for Map<'_> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, Error> {
        let Some((key, value)) = self.iter.next() else {
            return Ok(None);
        };
        self.value = Some(value);
        at(key.pos, seed.deserialize(key.name.as_str().into_deserializer())).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let node = self.value.take().expect("next_value before next_key");
        at(node.pos, seed.deserialize(De(node, self.json)))
    }
}

struct Variant<'a>(&'a Key, &'a Node, bool);

impl<'de, 'a> de::EnumAccess<'de> for Variant<'a> {
    type Error = Error;
    type Variant = De<'a>;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, De<'a>), Error> {
        let name = at(self.0.pos, seed.deserialize(self.0.name.as_str().into_deserializer()))?;
        Ok((name, De(self.1, self.2)))
    }
}

impl<'de> de::VariantAccess<'de> for De<'_> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(self)
    }

    fn tuple_variant<V: Visitor<'de>>(self, _: usize, v: V) -> Result<V::Value, Error> {
        if self.1 && !matches!(self.0.value, Value::Seq(_)) {
            return at(self.0.pos, Err(self.json_refuses("tuple variant")));
        }
        de::Deserializer::deserialize_any(self, v)
    }

    fn struct_variant<V: Visitor<'de>>(self, _: &'static [&'static str], v: V) -> Result<V::Value, Error> {
        if self.1 && !matches!(self.0.value, Value::Map(_)) {
            return at(self.0.pos, Err(self.json_refuses("struct variant")));
        }
        de::Deserializer::deserialize_any(self, v)
    }
}
