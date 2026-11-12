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
    T::deserialize(De(node))
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

struct De<'a>(&'a Node);

impl<'a> De<'a> {
    fn is_null(&self) -> bool {
        matches!(&self.0.value, Value::Scalar { text, plain: true } if resolve(text) == Plain::Null)
    }
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
            Value::Seq(items) => v.visit_seq(Seq(items.iter())),
            Value::Map(entries) => v.visit_map(Map {
                iter: entries.iter(),
                value: None,
            }),
        };
        at(self.0.pos, result)
    }

    /// A string field takes any scalar's raw text: `1.0`, `no` and `true` stay strings.
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        match &self.0.value {
            Value::Scalar { .. } if self.is_null() => {
                at(self.0.pos, Err(de::Error::invalid_type(Unexpected::Unit, &v)))
            }
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
            Value::Scalar { text, .. } => v.visit_enum(text.as_str().into_deserializer()),
            Value::Map(entries) if entries.len() == 1 => v.visit_enum(Variant(&entries[0].0, &entries[0].1)),
            _ => Err(de::Error::custom("expected a variant name or a map with a single key")),
        };
        at(self.0.pos, result)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, Error> {
        v.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 bytes byte_buf
        unit unit_struct seq tuple tuple_struct map struct
    }
}

struct Seq<'a>(std::slice::Iter<'a, Node>);

impl<'de> de::SeqAccess<'de> for Seq<'_> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, Error> {
        self.0
            .next()
            .map(|node| at(node.pos, seed.deserialize(De(node))))
            .transpose()
    }
}

struct Map<'a> {
    iter: std::slice::Iter<'a, (Key, Node)>,
    value: Option<&'a Node>,
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
        at(node.pos, seed.deserialize(De(node)))
    }
}

struct Variant<'a>(&'a Key, &'a Node);

impl<'de, 'a> de::EnumAccess<'de> for Variant<'a> {
    type Error = Error;
    type Variant = De<'a>;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, De<'a>), Error> {
        let name = at(self.0.pos, seed.deserialize(self.0.name.as_str().into_deserializer()))?;
        Ok((name, De(self.1)))
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
        de::Deserializer::deserialize_any(self, v)
    }

    fn struct_variant<V: Visitor<'de>>(self, _: &'static [&'static str], v: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_any(self, v)
    }
}
