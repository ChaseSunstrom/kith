//! The web UI (PLAN.md 4.12): a page kithd serves at `/ui/`, and the three questions it
//! asks that the CLI answers for itself: which kinds there are and their schemas
//! (`GET /v1/schemas`), YAML to JSON and back (`POST /v1/convert`), and what an apply would
//! change, as a diff (`POST /v1/diff`). None of them writes: what the page changes it
//! changes with the calls `kith` makes (`/v1/apply`, `DELETE /v1/resources/…`,
//! `/v1/rollback/…`), as the caller it is, in the audit log like anyone.
//!
//! The page's files are in the binary and are the same for everyone, so they are served
//! to whoever asks, certificate or not; everything they then ask for is not.

use crate::Shared;
use crate::access::{Caller, Grants};
use crate::api::{ApiError, Reply};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use kith_api::kinds::Verb;
use kith_api::store::{Action, Error, Store};
use kith_api::{KINDS, Resource};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// The page: name under `/ui/`, content type, content.
const FILES: [(&str, &str, &[u8]); 5] = [
    ("", "text/html; charset=utf-8", include_bytes!("../ui/index.html")),
    ("app.css", "text/css; charset=utf-8", include_bytes!("../ui/app.css")),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/app.js"),
    ),
    (
        "forms.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/forms.js"),
    ),
    // The page's face (Overpass, SIL OFL: its copyright and licence are in the file's own
    // name table and in docs/fonts/OFL.txt). The website's copy: there is one in the tree.
    (
        "overpass.woff2",
        "font/woff2",
        include_bytes!("../../../docs/fonts/overpass.woff2"),
    ),
];

/// The page may run its own script and style, show its own face and talk to where it came
/// from: nothing inline, nothing from elsewhere, nobody's frame. (What it shows is other people's text:
/// names, messages, logs.)
const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                      img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; \
                      frame-ancestors 'none'";

/// The page's files, for anyone.
pub fn pages() -> Router {
    // (Relative: the page works under whatever path a forwarder puts in front of it.)
    let slash = || async { (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, "ui/")]) };
    Router::new()
        .route("/ui", get(slash))
        .route("/ui/", get(|| page(Path(String::new()))))
        .route("/ui/{file}", get(page))
}

async fn page(Path(file): Path<String>) -> Response {
    let Some((_, kind, content)) = FILES.iter().find(|(name, ..)| *name == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let headers = [
        (header::CONTENT_TYPE, *kind),
        (header::CONTENT_SECURITY_POLICY, POLICY),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        // (Small, and a new kithd has a new page: asked for again each time.)
        (header::CACHE_CONTROL, "no-cache"),
    ];
    (headers, *content).into_response()
}

/// What the page asks that is not a resource; part of the API, behind who is asking.
pub fn router() -> Router<Arc<Shared>> {
    Router::new()
        .route("/v1/schemas", get(schemas))
        // A page's text, not a package: 1 MB is far past any manifest typed into a form.
        .route("/v1/convert", post(convert).layer(DefaultBodyLimit::max(1 << 20)))
        .route("/v1/diff", post(diff))
}

const VERBS: [Verb; 6] = [
    Verb::Get,
    Verb::List,
    Verb::Watch,
    Verb::Apply,
    Verb::Delete,
    Verb::Exec,
];

/// Every kind `grants` lets its holder do anything with: kith's own, then the cluster's,
/// each with the schema of a whole resource of it and what may be done (somewhere).
fn kinds(store: &Store, grants: &Grants) -> Vec<Value> {
    let own = KINDS.iter().map(|kind| {
        json!({
            "kind": kind.kind, "apiVersion": kith_api::API_VERSION, "namespaced": kind.namespaced,
            "about": kind.about, "schema": kind.schema(), "columns": [],
        })
    });
    let defined = store.list(Some("KindDefinition")).map(|definition| {
        let spec = &definition.spec;
        let version = format!(
            "{}/{}",
            spec["group"].as_str().unwrap_or_default(),
            spec["version"].as_str().unwrap_or_default()
        );
        // A resource of it is shaped like any other, around the spec its definition describes.
        let mut schema = kith_api::kind("ConfigMap").expect("kith has ConfigMaps").schema();
        schema["title"] = spec["kind"].clone();
        schema["description"] = version.clone().into();
        schema["properties"]["kind"] = json!({ "const": spec["kind"] });
        schema["properties"]["apiVersion"] = json!({ "const": version });
        schema["properties"]["spec"] = match &spec["schema"] {
            Value::Null => json!({ "type": "object" }),
            schema => schema.clone(),
        };
        json!({
            "kind": spec["kind"], "apiVersion": version, "namespaced": spec["namespaced"] != false,
            "about": version, "schema": schema, "columns": spec["columns"].as_array().cloned().unwrap_or_default(),
            "definition": definition.key(),
        })
    });
    let mut kinds: Vec<Value> = own.chain(defined).collect();
    kinds.retain_mut(|kind| {
        let name = kind["kind"].as_str().unwrap_or_default().to_string();
        let may: Vec<&Verb> = VERBS.iter().filter(|verb| grants.anywhere(verb, Some(&name))).collect();
        kind["may"] = json!(may);
        !may.is_empty()
    });
    kinds
}

async fn schemas(State(shared): State<Arc<Shared>>, Extension(caller): Extension<Caller>) -> Json<Value> {
    let state = shared.store.lock().expect("a handler panicked holding the store");
    let kinds = kinds(&state.store, &Grants::of(&caller, &state.store));
    Json(json!({ "caller": caller.to_string(), "kinds": kinds }))
}

#[derive(Deserialize)]
struct Convert {
    /// YAML, to be read: the documents in it come back as `resources`.
    yaml: Option<String>,
    /// Or JSON values, to be written: they come back as `yaml`, one document each.
    #[serde(default)]
    resources: Vec<Value>,
}

/// YAML read as kith reads it (strictly), or written as kith writes it. Nothing is
/// checked beyond that, and nothing of the cluster is said.
async fn convert(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Json(asked): Json<Convert>,
) -> Reply<Value> {
    // (For those the cluster knows: an Identity bound to nothing has nothing to write here.)
    let known = {
        let state = shared.store.lock().expect("a handler panicked holding the store");
        let grants = Grants::of(&caller, &state.store);
        [Verb::Get, Verb::List, Verb::Apply]
            .iter()
            .any(|verb| grants.anywhere(verb, None))
    };
    if !known {
        return Err(ApiError::Refused(format!(
            "{caller} may not use this: no Role is bound to it"
        )));
    }
    converted(asked)
}

fn converted(asked: Convert) -> Reply<Value> {
    let Some(yaml) = asked.yaml else {
        let documents: Vec<String> = asked.resources.iter().map(kith_yaml::to_string).collect();
        return Ok(Json(json!({ "yaml": documents.join("---\n") })));
    };
    let invalid = |e: kith_yaml::Error| ApiError::Store(Error::Invalid(e.render("yaml", &yaml)));
    let nodes = kith_yaml::parse(&yaml).map_err(invalid)?;
    let resources: Result<Vec<Value>, _> = nodes.iter().map(kith_yaml::from_node).collect();
    Ok(Json(json!({ "resources": resources.map_err(invalid)? })))
}

/// What applying `resources` would do, one entry each: `{ key, action, diff }`. A dry
/// run in every way (who may, admission, the kinds' checks), said as `kith diff` says it.
async fn diff(
    State(shared): State<Arc<Shared>>,
    Extension(caller): Extension<Caller>,
    Json(resources): Json<Vec<Resource>>,
) -> Reply<Vec<Value>> {
    let changes = crate::api::plan(&shared, &caller, resources).await?;
    let said = changes.iter().map(|change| {
        let action = match change.action {
            Action::Created => "created",
            Action::Updated => "updated",
            Action::Unchanged => "unchanged",
        };
        json!({ "key": change.after.key(), "action": action, "diff": change.diff() })
    });
    Ok(Json(said.collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAME: &str = "apiVersion: kith.dev/v1\nkind: KindDefinition\nmetadata: { name: gameserver }\nspec:\n  \
        group: games.example.com\n  version: v1\n  kind: GameServer\n  schema:\n    type: object\n    required: [map]\n    \
        properties:\n      map: { type: string }\n      players: { type: integer, maximum: 64 }\n      \
        mode: { enum: [duel, team] }\n      tags: { type: array, items: { type: string } }\n      \
        env: { type: object, additionalProperties: { type: string } }\n  columns:\n    - { name: Map, path: spec.map }\n";

    fn store(yaml: &str) -> Store {
        let mut store = Store::default();
        for resource in Resource::from_source(yaml).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        store
    }

    #[test]
    fn ui_schemas_are_the_kinds_one_may_touch() {
        let rules = "---\napiVersion: kith.dev/v1\nkind: Identity\nmetadata: { name: alice }\nspec: {}\n---\n\
            apiVersion: kith.dev/v1\nkind: Role\nmetadata: { name: games }\nspec:\n  rules:\n    \
            - { kinds: [GameServer], verbs: [get, list, apply] }\n    - { kinds: [ConfigMap], verbs: [get] }\n---\n\
            apiVersion: kith.dev/v1\nkind: RoleBinding\nmetadata: { name: games }\nspec: { role: games, subjects: [alice] }\n";
        let store = store(&format!("{GAME}{rules}"));
        // Everything, for the node's own administrator; a defined kind after kith's, with its columns.
        let all = kinds(&store, &Grants::of(&Caller::Admin, &store));
        assert_eq!(all.len(), KINDS.len() + 1);
        let game = all.last().unwrap();
        assert_eq!(game["apiVersion"], "games.example.com/v1");
        assert_eq!(game["columns"][0]["path"], "spec.map");
        assert_eq!(game["schema"]["properties"]["spec"]["required"][0], "map");
        assert_eq!(game["schema"]["properties"]["kind"]["const"], "GameServer");
        assert!(game["schema"]["$defs"]["Metadata"].is_object());
        assert_eq!(game["may"].as_array().unwrap().len(), VERBS.len());
        // For an Identity: the kinds a Role of its names, with what it may do with each.
        let hers = kinds(&store, &Grants::of(&Caller::Identity("alice".into()), &store));
        let names: Vec<&str> = hers.iter().filter_map(|kind| kind["kind"].as_str()).collect();
        assert_eq!(names, ["ConfigMap", "GameServer"]);
        assert_eq!(hers[0]["may"], json!(["get"]));
        assert_eq!(hers[1]["may"], json!(["get", "list", "apply"]));
        // For one with no Role: nothing.
        assert!(kinds(&store, &Grants::of(&Caller::Identity("mallory".into()), &store)).is_empty());
    }

    /// The page's own functions, run by node over the real schemas (`ui/test.mjs`).
    /// Skipped, with a line saying so, where there is no node.
    #[test]
    fn ui_forms_are_drawn_from_every_schema() {
        let store = store(GAME);
        let kinds = kinds(&store, &Grants::of(&Caller::Admin, &store));
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
        let file = std::env::temp_dir().join(format!("kith-ui-kinds-{}.json", std::process::id()));
        std::fs::write(&file, serde_json::to_vec(&kinds).unwrap()).unwrap();
        let run = std::process::Command::new("node")
            .arg(dir.join("test.mjs"))
            .arg(&file)
            .output();
        let Ok(run) = run else {
            eprintln!("skipped: no node to run crates/kithd/ui/test.mjs with");
            return;
        };
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(run.status.success(), "{said}");
        // Every script the page loads is one node could read.
        for script in ["app.js", "forms.js"] {
            let check = std::process::Command::new("node")
                .arg("--check")
                .arg(dir.join(script))
                .output()
                .unwrap();
            assert!(
                check.status.success(),
                "{script}: {}",
                String::from_utf8_lossy(&check.stderr)
            );
        }
    }

    #[tokio::test]
    async fn ui_pages_are_served_locked_down() {
        for (name, kind, content) in FILES {
            let served = page(Path(name.to_string())).await;
            assert_eq!(served.status(), StatusCode::OK);
            assert_eq!(served.headers()[header::CONTENT_TYPE], kind);
            assert_eq!(served.headers()[header::CONTENT_SECURITY_POLICY], POLICY);
            // (The face is not text: there is nothing in it to read for these.)
            let Ok(content) = std::str::from_utf8(content) else {
                continue;
            };
            // Nothing inline, nothing from elsewhere: the policy would stop it, and the page would be broken.
            for banned in [
                "style=",
                "onclick=",
                "<style",
                "http://",
                "https://",
                "innerHTML",
                "eval(",
            ] {
                let found = content
                    .lines()
                    .find(|line| line.contains(banned) && !line.contains("www.w3.org"));
                assert_eq!(found, None, "{name} has {banned}");
            }
        }
        assert_eq!(page(Path("../Cargo.toml".into())).await.status(), StatusCode::NOT_FOUND);
        // What the style sheet loads is a file of the page, and the policy lets it: a face
        // the policy stops is a page in whatever the browser has.
        let css = std::str::from_utf8(FILES[1].2).unwrap();
        let loaded: Vec<&str> = css
            .split("url(")
            .skip(1)
            .filter_map(|rest| rest.split(')').next())
            .collect();
        assert_eq!(loaded, ["overpass.woff2"]);
        assert!(
            FILES
                .iter()
                .any(|(name, kind, _)| *name == "overpass.woff2" && *kind == "font/woff2")
        );
        assert!(POLICY.contains("font-src 'self'"));
    }

    #[test]
    fn ui_yaml_goes_to_json_and_back() {
        let ask = |asked: Value| converted(serde_json::from_value(asked).unwrap());
        let Ok(Json(read)) = ask(json!({ "yaml": "a: 1\nb: [x, 'no']\n---\nc: ~\n" })) else {
            panic!("it is YAML");
        };
        assert_eq!(read["resources"], json!([{ "a": 1, "b": ["x", "no"] }, { "c": null }]));
        let Ok(Json(written)) = ask(json!({ "resources": read["resources"] })) else {
            panic!("it is JSON");
        };
        let Ok(Json(again)) = ask(json!({ "yaml": written["yaml"] })) else {
            panic!("what kith writes, kith reads: {written}");
        };
        assert_eq!(again, read);
        // What is wrong is said with where.
        let Err(ApiError::Store(Error::Invalid(said))) = ask(json!({ "yaml": "a: 1\n b: 2\n" })) else {
            panic!("it is not YAML");
        };
        assert!(said.contains("yaml:2"), "{said}");
    }
}
