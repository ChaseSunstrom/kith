//! `kith.dev/v1` is stable: a file a build took as v1 is taken by every later build.
//!
//! `v1.schema.json` is every kind's JSON Schema as it was last written down. The test
//! here compares the code with it. Taking more (a new optional field, a new kind, a new
//! value) passes once the file is written again (`KITH_BLESS=1`); refusing anything the
//! file took (a field or a kind gone, a type changed, a field newly required, a new
//! limit) is named and fails, with or without it.
//
// ponytail: the comparison errs on the side of "breaking": a limit that was loosened
// (a lower minimum, a wider pattern) or a type that was only renamed in the code is
// named too, and then the file is changed by hand in a commit that says why. Teach it
// each keyword's direction if that happens more than once a year. What a field *means*
// (its default, what a controller does with it) is not in a schema: people review that.

use crate::KINDS;
use serde_json::{Map, Value, json};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/v1.schema.json");

/// Every kind's schema, the definitions they share written once.
fn schemas() -> Value {
    let (mut kinds, mut defs) = (Map::new(), Map::new());
    for kind in KINDS {
        let mut schema = kind.schema();
        if let Some(Value::Object(own)) = schema.as_object_mut().and_then(|schema| schema.remove("$defs")) {
            for (name, def) in own {
                // One name is one type, whichever kind uses it: that is what lets them be shared.
                if let Some(other) = defs.insert(name.clone(), def.clone()) {
                    assert_eq!(other, def, "two different definitions are named {name}");
                }
            }
        }
        kinds.insert(kind.kind.into(), schema);
    }
    defs.sort_keys();
    json!({ "kinds": kinds, "$defs": defs })
}

/// Says nothing about which files are taken.
const NOTES: &[&str] = &[
    "description",
    "title",
    "default",
    "examples",
    "deprecated",
    "$schema",
    "$comment",
];

fn list(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(values)) => values.clone(),
        Some(one) => vec![one.clone()],
        None => Vec::new(),
    }
}

/// What `old` took and `new` does not, into `out`: each with where in the schema it is.
fn breaks(old: &Value, new: &Value, at: &str, out: &mut Vec<String>) {
    let (Value::Object(old), Value::Object(new)) = (old, new) else {
        if old != new {
            out.push(format!("{at}: was {old}, is {new}"));
        }
        return;
    };
    let keys = old.keys().chain(new.keys().filter(|key| !old.contains_key(*key)));
    for key in keys.filter(|key| !NOTES.contains(&key.as_str())) {
        let (was, now) = (old.get(key), new.get(key));
        let at = format!("{at}/{key}");
        match (key.as_str(), was, now) {
            // Named things: each that was there is still there, and takes what it took.
            // (A struct with no field left has no `properties` at all: that is every one gone.)
            ("kinds" | "properties" | "$defs", _, _) => {
                let none = Map::new();
                let was = was.and_then(Value::as_object).unwrap_or(&none);
                let now = now.and_then(Value::as_object).unwrap_or(&none);
                for (name, was) in was {
                    match now.get(name) {
                        Some(now) => breaks(was, now, &format!("{at}/{name}"), out),
                        None => out.push(format!("{at}/{name}: gone")),
                    }
                }
                // Where any name was taken (a map of labels beside a field or two), a new
                // field takes that name away from the map.
                let open = key == "properties" && old.get("additionalProperties") != Some(&Value::Bool(false));
                for name in now.keys().filter(|name| open && !was.contains_key(*name)) {
                    out.push(format!("{at}/{name}: a new field where any name was taken"));
                }
            }
            ("required", _, _) => {
                let was = list(was);
                for name in list(now).into_iter().filter(|name| !was.contains(name)) {
                    out.push(format!("{at}: {name} is newly required"));
                }
            }
            // A limit that is gone limits nothing; a list of what is taken with nothing gone takes it all.
            (_, Some(_), None) => {}
            ("enum" | "type", Some(_), Some(_)) => {
                let now = list(now);
                for value in list(was).into_iter().filter(|value| !now.contains(value)) {
                    out.push(format!("{at}: {value} is no longer taken"));
                }
            }
            ("anyOf" | "oneOf", Some(_), Some(_)) => {
                let now = list(now);
                let taken = |was: &Value| {
                    now.iter().any(|now| {
                        let mut inner = Vec::new();
                        breaks(was, now, "", &mut inner);
                        inner.is_empty()
                    })
                };
                for was in list(was).iter().filter(|was| !taken(was)) {
                    out.push(format!("{at}: a form is no longer taken: {was}"));
                }
            }
            // (Fields that were refused and are taken now.)
            ("additionalProperties", Some(Value::Bool(false)), Some(_)) => {}
            (_, Some(was), Some(now)) if was.is_object() && now.is_object() => breaks(was, now, &at, out),
            (_, Some(was), Some(now)) if was == now => {}
            (_, Some(was), Some(now)) => out.push(format!("{at}: was {was}, is {now}")),
            (_, None, Some(Value::Bool(true))) => {}
            (_, None, Some(now)) => out.push(format!("{at}: a new limit: {now}")),
            (_, None, None) => {}
        }
    }
}

fn broken(old: Value, new: Value) -> Vec<String> {
    let mut out = Vec::new();
    breaks(&old, &new, "", &mut out);
    out
}

#[test]
fn stable_v1_takes_every_file_it_took() {
    let now = schemas();
    let text = serde_json::to_string_pretty(&now).unwrap() + "\n";
    let golden = std::fs::read_to_string(GOLDEN).unwrap_or_default();
    if golden == text {
        return;
    }
    let old = if golden.is_empty() {
        json!({})
    } else {
        serde_json::from_str(&golden).unwrap()
    };
    let broken = broken(old, now);
    assert!(
        broken.is_empty(),
        "kith.dev/v1 is stable, and this build refuses what it took:\n  {}\n(If every v1 file still means what it \
         meant, change crates/kith-api/v1.schema.json by hand, in a commit that says why.)",
        broken.join("\n  ")
    );
    if std::env::var_os("KITH_BLESS").is_some() {
        std::fs::write(GOLDEN, text).unwrap();
        return;
    }
    panic!(
        "the kinds take more than crates/kith-api/v1.schema.json says, and nothing it took is refused: run this test \
         once with KITH_BLESS=1 to write it down"
    );
}

#[test]
fn stable_names_each_way_of_refusing_what_was_taken() {
    let object = |properties: Value, required: Value| json!({ "type": "object", "additionalProperties": false, "properties": properties, "required": required });
    let text = json!({ "type": "string" });
    let old = || {
        object(
            json!({ "name": text, "size": { "type": ["integer", "null"], "minimum": 0 } }),
            json!(["name"]),
        )
    };
    let same = |new: Value| assert_eq!(broken(old(), new), Vec::<String>::new());
    let breaks = |new: Value, what: &str| {
        let said = broken(old(), new).join("; ");
        assert!(
            said.contains(what) && said.split("; ").count() == what.split("; ").count(),
            "{what}: {said}"
        );
    };
    let size = || json!({ "type": ["integer", "null"], "minimum": 0 });

    // Taking more: a field nobody has to give, a type more, a limit gone, words about it.
    same(object(
        json!({ "name": text, "size": size(), "more": text }),
        json!(["name"]),
    ));
    same(object(
        json!({ "name": { "type": ["string", "null"], "description": "x" }, "size": { "type": ["integer", "null"] } }),
        json!([]),
    ));
    same(json!({ "type": "object", "properties": old()["properties"], "required": ["name"] }));

    // Refusing what was taken, each way.
    breaks(
        object(json!({ "name": text }), json!(["name"])),
        "/properties/size: gone",
    );
    breaks(
        object(
            json!({ "name": text, "size": size(), "more": text }),
            json!(["name", "more"]),
        ),
        "\"more\" is newly required",
    );
    breaks(
        object(
            json!({ "name": { "type": "integer" }, "size": size() }),
            json!(["name"]),
        ),
        "/properties/name/type: \"string\" is no longer taken",
    );
    breaks(
        object(
            json!({ "name": text, "size": { "type": ["integer"], "minimum": 0 } }),
            json!(["name"]),
        ),
        "\"null\" is no longer taken",
    );
    breaks(
        object(
            json!({ "name": text, "size": { "type": ["integer", "null"], "minimum": 1 } }),
            json!(["name"]),
        ),
        "/minimum: was 0, is 1",
    );
    breaks(
        object(
            json!({ "name": { "type": "string", "maxLength": 9 }, "size": size() }),
            json!(["name"]),
        ),
        "/maxLength: a new limit",
    );
    breaks(
        object(
            json!({ "name": { "$ref": "#/$defs/Name" }, "size": size() }),
            json!(["name"]),
        ),
        "/$ref: a new limit",
    );

    // A struct that loses its only field has no `properties` left; a field added beside a
    // map of any names takes a name the map had.
    let only = json!({ "type": "object", "additionalProperties": false });
    breaks(only.clone(), "/properties/name: gone; /properties/size: gone");
    let labels =
        |properties: Value| json!({ "type": "object", "additionalProperties": text, "properties": properties });
    let said = broken(
        labels(json!({ "weight": size() })),
        labels(json!({ "weight": size(), "zone": size() })),
    );
    assert_eq!(said, ["/properties/zone: a new field where any name was taken"]);
    assert_eq!(
        broken(json!({}), json!({ "kinds": { "Job": old() }, "$defs": {} })),
        Vec::<String>::new()
    );

    // Values, forms, definitions and whole kinds.
    let pair = |old: Value, new: Value| broken(old, new).join("; ");
    let policy = |values: Value| json!({ "enum": values });
    assert_eq!(pair(policy(json!(["a", "b"])), policy(json!(["a", "b", "c"]))), "");
    assert!(pair(policy(json!(["a", "b"])), policy(json!(["a"]))).contains("/enum: \"b\" is no longer taken"));
    let forms = |forms: Value| json!({ "anyOf": forms });
    let reference = json!({ "$ref": "#/$defs/Spec" });
    assert_eq!(
        pair(
            forms(json!([reference, { "type": "null" }])),
            forms(json!([{ "type": "null" }, reference, text]))
        ),
        ""
    );
    assert!(
        pair(forms(json!([reference, { "type": "null" }])), forms(json!([reference])))
            .contains("a form is no longer taken")
    );
    assert!(pair(json!({ "$ref": "#/$defs/A" }), json!({ "$ref": "#/$defs/B" })).contains("/$ref: was"));
    assert!(
        pair(
            json!({ "additionalProperties": true }),
            json!({ "additionalProperties": false })
        )
        .contains("was true, is false")
    );
    assert!(pair(json!({}), json!({ "additionalProperties": false })).contains("a new limit"));
    let whole = |kinds: Value, defs: Value| json!({ "kinds": kinds, "$defs": defs });
    let was = whole(json!({ "Job": old() }), json!({ "Spec": old() }));
    assert_eq!(
        pair(
            was.clone(),
            whole(
                json!({ "Job": old(), "Task": old() }),
                json!({ "Spec": old(), "Other": text })
            )
        ),
        ""
    );
    assert_eq!(
        pair(was.clone(), whole(json!({ "Task": old() }), json!({ "Spec": old() }))),
        "/kinds/Job: gone"
    );
    let less = whole(
        json!({ "Job": old() }),
        json!({ "Spec": object(json!({ "name": text }), json!(["name"])) }),
    );
    assert_eq!(pair(was, less), "/$defs/Spec/properties/size: gone");
}
