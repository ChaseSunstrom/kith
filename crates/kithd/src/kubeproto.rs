//! Kubernetes's binary encoding, read as the JSON the same object would have been:
//! `kubectl create` and Helm send the kinds Kubernetes has built in as protobuf, whatever
//! the server says it takes. What each numbered field is called and holds is in
//! `kubeproto.txt`, which `ci/kube_proto.py` makes from Kubernetes's own types.

use base64::Engine;
use kith_api::store::rfc3339;
use serde_json::{Map, Value};
use std::cell::Cell;

const TABLE: &str = include_str!("kubeproto.txt");
/// What every such body begins with.
pub const MAGIC: &[u8] = b"k8s\0";
/// No message of the table is this deep in another.
const DEPTH: u8 = 24;
/// The fields that are read of one body. (An object has hundreds; a body made of nothing
/// but empty fields would have millions, each a row of the table to look for.)
const FIELDS: u32 = 50_000;

/// One more field read, of those a body may have.
fn spend(left: &Cell<u32>) -> Result<(), String> {
    let now = left.get().checked_sub(1).ok_or(format!("more than {FIELDS} fields"))?;
    left.set(now);
    Ok(())
}

enum Wire<'a> {
    Number(u64),
    Bytes(&'a [u8]),
}

fn number(at: &mut &[u8]) -> Result<u64, String> {
    let mut value = 0;
    for shift in (0..64).step_by(7) {
        let (byte, rest) = at.split_first().ok_or("it ends in the middle of a number")?;
        *at = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("a number of more than ten bytes".into())
}

/// The next field of a message: its number and what it holds.
fn field<'a>(at: &mut &'a [u8]) -> Result<(u64, Wire<'a>), String> {
    let tag = number(at)?;
    let cut = |at: &mut &'a [u8], len: u64| {
        let len = usize::try_from(len).ok().filter(|len| *len <= at.len());
        let (bytes, rest) = at.split_at(len.ok_or("a field is longer than what is left")?);
        *at = rest;
        Ok::<_, String>(bytes)
    };
    let wire = match tag & 7 {
        0 => Wire::Number(number(at)?),
        1 => Wire::Bytes(cut(at, 8)?),
        2 => {
            let len = number(at)?;
            Wire::Bytes(cut(at, len)?)
        }
        5 => Wire::Bytes(cut(at, 4)?),
        other => return Err(format!("wire type {other} is not one protobuf has now")),
    };
    Ok((tag >> 3, wire))
}

/// The fields of the message `bytes` are, each with its number.
fn fields(mut bytes: &[u8]) -> impl Iterator<Item = Result<(u64, Wire<'_>), String>> {
    std::iter::from_fn(move || (!bytes.is_empty()).then(|| field(&mut bytes)))
}

fn text(bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| "text that is not UTF-8".to_string())
}

/// What a field of type `kind` (as the table writes one) holds.
fn value(kind: &str, wire: Wire, depth: u8, left: &Cell<u32>) -> Result<Value, String> {
    Ok(match (kind, wire) {
        ("s", Wire::Bytes(bytes)) => text(bytes)?.into(),
        ("y", Wire::Bytes(bytes)) => base64::engine::general_purpose::STANDARD.encode(bytes).into(),
        // (A negative number is its sixty-four bits.)
        ("i", Wire::Number(n)) => (n as i64).into(),
        ("b", Wire::Number(n)) => (n != 0).into(),
        ("s" | "y" | "i" | "b", _) | (_, Wire::Number(_)) => {
            return Err(format!("a {kind} that is not written as one"));
        }
        (name, Wire::Bytes(bytes)) => message(name, bytes, depth, left)?,
    })
}

/// The message `name` that `bytes` are, as JSON has it. A field the table does not have
/// is passed over: a newer client's, or one of those left out of it.
fn message(name: &str, bytes: &[u8], depth: u8, left: &Cell<u32>) -> Result<Value, String> {
    let depth = depth.checked_sub(1).ok_or("messages nested too deep")?;
    let mut read = Vec::new();
    for field in fields(bytes) {
        spend(left)?;
        read.push(field?);
    }
    let whole = |number: u64| read.iter().find(|(n, _)| *n == number).map(|(_, wire)| wire);
    let int = |number| match whole(number) {
        Some(Wire::Number(n)) => *n as i64,
        _ => 0,
    };
    let bytes_of = |number| match whole(number) {
        Some(Wire::Bytes(bytes)) => *bytes,
        _ => &[],
    };
    // Those Kubernetes writes in JSON by a rule of their own.
    match name {
        // (A time that was never set is written as an empty message.)
        "Time" if read.is_empty() => return Ok(Value::Null),
        "Time" => return Ok(rfc3339(u64::try_from(int(1)).unwrap_or(0)).into()),
        "Duration" => return Ok(format!("{}s", int(1) / 1_000_000_000).into()),
        "Quantity" => return Ok(text(bytes_of(1))?.into()),
        "IntOrString" if int(1) == 0 => return Ok(int(2).into()),
        "IntOrString" => return Ok(text(bytes_of(3))?.into()),
        "RawExtension" => return serde_json::from_slice(bytes_of(1)).or(Ok(Value::Null)),
        _ => {}
    }
    let table = TABLE.split('=').find(|table| table.lines().next() == Some(name));
    let table = table.ok_or(format!("{name} is not a message that is read here"))?;
    let mut out = Map::new();
    for (number, wire) in read {
        let row = table.lines().skip(1).find_map(|line| {
            let mut row = line.split(' ');
            (row.next()?.parse() == Ok(number)).then_some((row.next()?, row.next()?))
        });
        let Some((field, kind)) = row else { continue };
        if let Some(of) = kind.strip_prefix('*') {
            let Some(list) = out
                .entry(field)
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
            else {
                continue;
            };
            match wire {
                // (Numbers packed into one field.)
                Wire::Bytes(mut packed) if matches!(of, "i" | "b") => {
                    while !packed.is_empty() {
                        spend(left)?;
                        list.push(value(of, Wire::Number(self::number(&mut packed)?), depth, left)?);
                    }
                }
                wire => list.push(value(of, wire, depth, left)?),
            }
        } else if let Some(of) = kind.strip_prefix('{') {
            // An entry of a mapping is a message: 1 is what it is under, 2 what it is.
            let (Wire::Bytes(entry), mut key, mut held) = (wire, String::new(), Value::Null) else {
                return Err(format!("{name}.{field}: an entry that is not a message"));
            };
            for part in fields(entry) {
                spend(left)?;
                match part? {
                    (1, Wire::Bytes(bytes)) => key = text(bytes)?,
                    (2, wire) => held = value(of, wire, depth, left)?,
                    _ => {}
                }
            }
            if let Some(map) = out
                .entry(field)
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
            {
                map.insert(key, held);
            }
        } else {
            let (kind, left_out) = kind.strip_suffix('!').map_or((kind, false), |kind| (kind, true));
            let held = value(kind, wire, depth, left).map_err(|e| format!("{name}.{field}: {e}"))?;
            // What Go writes whether it was set or not, and JSON leaves out when it was not.
            let empty = held.is_null() || (left_out && (held == "" || held == 0 || held == false));
            match (field, held) {
                _ if empty => {}
                // (Fields that are the parent's own in JSON.)
                (".", Value::Object(inner)) => out.extend(inner),
                (_, held) => drop(out.insert(field.into(), held)),
            }
        }
    }
    Ok(out.into())
}

/// The object a body in Kubernetes's binary encoding is: after [`MAGIC`], what kind it is
/// and the message of that kind.
pub fn object(body: &[u8]) -> Result<Value, String> {
    let body = body.strip_prefix(MAGIC).ok_or("not Kubernetes's binary encoding")?;
    let (mut version, mut kind, mut raw) = (String::new(), String::new(), &[][..]);
    for part in fields(body) {
        match part? {
            (1, Wire::Bytes(meta)) => {
                for part in fields(meta) {
                    match part? {
                        (1, Wire::Bytes(bytes)) => version = text(bytes)?,
                        (2, Wire::Bytes(bytes)) => kind = text(bytes)?,
                        _ => {}
                    }
                }
            }
            (2, Wire::Bytes(bytes)) => raw = bytes,
            _ => {}
        }
    }
    let mut object = message(&kind, raw, DEPTH, &Cell::new(FIELDS))
        .map_err(|e| format!("a {kind} in Kubernetes's binary encoding: {e}"))?;
    if let Some(object) = object.as_object_mut() {
        object.insert("apiVersion".into(), version.into());
        object.insert("kind".into(), kind.into());
    }
    Ok(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A field as protobuf writes one (lengths under 128, which is all these need).
    fn bytes(number: u8, bytes: &[u8]) -> Vec<u8> {
        [&[number << 3 | 2, bytes.len() as u8], bytes].concat()
    }

    #[test]
    fn a_secret_in_protobuf_is_the_secret_in_json() {
        let entry = [bytes(1, b"password"), bytes(2, b"hunter2")].concat();
        let labels = [bytes(1, b"owner"), bytes(2, b"helm")].concat();
        // name, an empty generateName (Go writes it; JSON does not), a time never set, a label.
        let meta = [
            bytes(1, b"sh.helm.release.v1.site.v1"),
            bytes(2, b""),
            bytes(8, b""),
            bytes(11, &labels),
        ]
        .concat();
        let secret = [bytes(1, &meta), bytes(2, &entry), bytes(3, b"helm.sh/release.v1")].concat();
        let kind = [bytes(1, b"v1"), bytes(2, b"Secret")].concat();
        let body = [MAGIC, &bytes(1, &kind), &bytes(2, &secret)].concat();
        let want = serde_json::json!({
            "apiVersion": "v1", "kind": "Secret", "type": "helm.sh/release.v1",
            "metadata": { "name": "sh.helm.release.v1.site.v1", "labels": { "owner": "helm" } },
            "data": { "password": "aHVudGVyMg==" }, // pragma: allowlist secret
        });
        assert_eq!(object(&body).unwrap(), want);
        // What is cut short, or is not what it says, is an error and not a panic.
        for cut in 0..body.len() {
            let _ = object(&body[..cut]);
        }
        assert!(object(b"{}").is_err());
        // A body of nothing but empty entries is not read to its end.
        let many = [&[0x0a, 0xc0, 0xa9, 0x07][..], &bytes(2, b"").repeat(60_000)].concat();
        let body = [MAGIC, &bytes(1, &kind), &[0x12, 0xc4, 0xa9, 0x07], &many].concat();
        assert!(object(&body).unwrap_err().contains("more than 50000 fields"));
        assert!(
            object(&[MAGIC, &bytes(1, &bytes(2, b"Pod"))].concat())
                .unwrap_err()
                .contains("Pod")
        );
    }

    #[test]
    fn the_table_names_only_messages_it_has() {
        let names: Vec<&str> = TABLE.split('=').filter_map(|table| table.lines().next()).collect();
        let rule = [
            "s",
            "y",
            "i",
            "b",
            "Time",
            "Duration",
            "Quantity",
            "IntOrString",
            "RawExtension",
        ];
        for row in TABLE.lines().filter(|line| !line.starts_with('=')) {
            let kind = row
                .split(' ')
                .nth(2)
                .unwrap_or_else(|| panic!("{row}: not NUMBER name TYPE"));
            let kind = kind.trim_start_matches(['*', '{']).trim_end_matches('!');
            assert!(
                rule.contains(&kind) || names.contains(&kind),
                "{row}: no message {kind}"
            );
        }
    }
}
