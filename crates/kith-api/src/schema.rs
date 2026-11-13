//! The subset of JSON Schema kith checks values against: a package's values and the
//! spec of a kind a `KindDefinition` makes.

use serde_json::Value;

/// The schema keywords [`check`] knows; the last few say nothing about a value.
const KEYWORDS: [&str; 18] = [
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "$schema",
    "$id",
    "title",
    "description",
    "default",
    "examples",
];

/// The keywords in `schema` that [`check`] would pass over without a word.
pub fn unknown_keywords(schema: &Value, at: &str, found: &mut Vec<String>) {
    let Value::Object(schema) = schema else { return };
    for (keyword, inside) in schema {
        if !KEYWORDS.contains(&keyword.as_str()) {
            found.push(format!("{at}: `{keyword}` is not a keyword kith checks"));
        }
        // (A keyword of the wrong shape would be passed over just the same.)
        let shaped = match keyword.as_str() {
            "required" | "enum" => inside.is_array(),
            "properties" => inside.is_object(),
            "type" => inside.is_string() || inside.is_array(),
            "minimum" | "maximum" | "minLength" | "maxLength" | "minItems" | "maxItems" => inside.is_number(),
            _ => true,
        };
        if !shaped {
            found.push(format!("{at}: `{keyword}` cannot be {inside}"));
        }
        match (keyword.as_str(), inside) {
            ("properties", Value::Object(properties)) => {
                for (name, property) in properties {
                    unknown_keywords(property, &format!("{at}.{name}"), found);
                }
            }
            ("items" | "additionalProperties", inside) => unknown_keywords(inside, &format!("{at}[]"), found),
            _ => {}
        }
    }
}

fn is(kind: &str, value: &Value) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "integer" => value.as_f64().is_some_and(|number| number.fract() == 0.0),
        _ => false,
    }
}

/// Check `value` (called `at` in what is said) against `schema`: everything wrong with it.
pub fn check(schema: &Value, value: &Value, at: &str, wrong: &mut Vec<String>) {
    let Value::Object(schema) = schema else { return };
    let kinds = match schema.get("type") {
        Some(Value::String(kind)) => vec![kind.as_str()],
        Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    if !kinds.is_empty() && !kinds.iter().any(|kind| is(kind, value)) {
        // (Nothing more to say about a value of the wrong kind.)
        return wrong.push(format!("{at}: must be {}, not {value}", kinds.join(" or ")));
    }
    if let Some(Value::Array(allowed)) = schema.get("enum")
        && !allowed.contains(value)
    {
        wrong.push(format!(
            "{at}: must be one of {}, not {value}",
            Value::Array(allowed.clone())
        ));
    }
    let limit = |keyword: &str| schema.get(keyword).and_then(Value::as_f64);
    let mut within = |size: f64, least: &str, most: &str, what: &str| {
        if limit(least).is_some_and(|least| size < least) {
            wrong.push(format!("{at}: {what} must be at least {}", schema[least]));
        }
        if limit(most).is_some_and(|most| size > most) {
            wrong.push(format!("{at}: {what} must be at most {}", schema[most]));
        }
    };
    #[allow(clippy::cast_precision_loss)]
    match value {
        Value::Number(number) => within(number.as_f64().unwrap_or(0.0), "minimum", "maximum", "it"),
        Value::String(text) => within(text.chars().count() as f64, "minLength", "maxLength", "its length"),
        Value::Array(items) => within(items.len() as f64, "minItems", "maxItems", "the number of items"),
        _ => {}
    }
    match value {
        Value::Object(fields) => {
            for name in schema.get("required").and_then(Value::as_array).into_iter().flatten() {
                if let Some(name) = name.as_str().filter(|name| !fields.contains_key(*name)) {
                    wrong.push(format!("{at}.{name}: is required"));
                }
            }
            let properties = schema.get("properties").and_then(Value::as_object);
            for (name, field) in fields {
                let at = format!("{at}.{name}");
                match (
                    properties.and_then(|properties| properties.get(name)),
                    schema.get("additionalProperties"),
                ) {
                    (Some(property), _) => check(property, field, &at, wrong),
                    (None, Some(Value::Bool(false))) => wrong.push(format!("{at}: is not a field the schema has")),
                    (None, Some(others)) => check(others, field, &at, wrong),
                    (None, None) => {}
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if let Some(schema) = schema.get("items") {
                    check(schema, item, &format!("{at}[{index}]"), wrong);
                }
            }
        }
        _ => {}
    }
}
