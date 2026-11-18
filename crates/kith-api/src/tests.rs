use crate::store::{Action, FileStore, HISTORY_LIMIT, Store, rfc3339};
use crate::*;
use serde_json::json;

const JELLYFIN: &str = include_str!("../../../examples/jellyfin.yaml");
const WORKSTATION: &str = include_str!("../../../examples/workstation.yaml");

fn load(src: &str) -> Vec<Resource> {
    Resource::from_source(src)
        .unwrap()
        .into_iter()
        .map(|r| r.unwrap())
        .collect()
}

fn one(src: &str) -> Resource {
    load(src).pop().unwrap()
}

#[test]
fn passed_on_is_one_list_for_the_nodes_and_the_cli() {
    // Reads a node passes on to the node that has the thing.
    assert!(passed_on("GET", "/v1/logs/Workload/default/web?replica=0"));
    assert!(passed_on("GET", "/v1/volumes/default/data/files"));
    // Changes a control node that is not the leader passes on as they came.
    assert!(passed_on("POST", "/v1/apply"));
    assert!(passed_on("DELETE", "/v1/resources/ConfigMap/default/gone"));
    assert!(passed_on("POST", "/v1/rollback/ConfigMap/default/gone?to=1"));
    // Not these: a node's own reads, and the same routes by another method.
    assert!(!passed_on("GET", "/v1/cluster"));
    assert!(!passed_on("GET", "/v1/resources?namespace=default"));
    assert!(!passed_on("GET", "/v1/apply"));
    assert!(!passed_on("GET", "/v1/resources/ConfigMap/default/gone"));
    assert!(!passed_on("DELETE", "/v1/rollback/ConfigMap/default/gone?to=1"));
}

/// The (line, column, message) of the first error in `src`.
fn err(src: &str) -> (usize, usize, String) {
    let e = match Resource::from_source(src) {
        Err(e) => e,
        Ok(docs) => docs.into_iter().find_map(Result::err).expect("an error"),
    };
    let p = e.pos.expect("a position");
    (p.line, p.col, e.msg)
}

fn workload(extra: &str) -> String {
    format!(
        "apiVersion: kith.dev/v1\nkind: Workload\nmetadata:\n  name: web\nspec:\n  template:\n    containers:\n      - name: web\n        image: nginx:1.27\n{extra}"
    )
}

#[test]
fn plan_examples_validate_and_normalise() {
    let docs = load(JELLYFIN);
    assert_eq!(
        docs.iter().map(Resource::key).collect::<Vec<_>>(),
        ["Namespace/media", "Workload/media/jellyfin", "Service/media/jellyfin"]
    );
    assert_eq!(docs[0].spec, json!({}));
    assert_eq!(
        docs[1].spec,
        json!({
            "replicas": 1,
            "template": {"containers": [{
                "name": "jellyfin",
                "image": "docker.io/jellyfin/jellyfin:10",
                "resources": {"cpu": "2", "memory": "2Gi"},
                "ports": [{"name": "http", "port": 8096}],
                "volumeMounts": [{"volume": "media", "path": "/media"}],
            }]},
            "placement": {"require": {"node.labels.disks": "hdd"}, "prefer": [{"weight": 50, "node.labels.room": "closet"}]},
        })
    );
    assert_eq!(docs[2].spec["ports"][0]["targetPort"], json!("http"));
    let release = one(WORKSTATION);
    assert_eq!(release.spec["values"]["apps"], json!(["firefox", "code", "steam"]));
    assert_eq!(release.spec["package"]["version"], json!("^1.2"));
}

#[test]
fn strings_are_never_coerced() {
    let r = one(&workload(
        "        args: [no, 1.0, true, 0x10]\n        resources: { cpu: 2, memory: 512Mi }\n  placement:\n    require: { rack: 12, ssd: yes }\n    prefer: [{ weight: 5, zone: 1.0 }]\n",
    ));
    let c = &r.spec["template"]["containers"][0];
    assert_eq!(c["args"], json!(["no", "1.0", "true", "0x10"]));
    assert_eq!(c["resources"]["cpu"], json!("2"));
    assert_eq!(
        r.spec["placement"],
        json!({"require": {"rack": "12", "ssd": "yes"}, "prefer": [{"weight": 5, "zone": "1.0"}]})
    );
    // And a number field does not take a string.
    let (line, _, msg) = err(&workload("  replicas: '2'\n"));
    assert_eq!(line, 10, "{msg}");
}

#[test]
fn errors_point_at_the_mistake() {
    // Unknown field, three levels down.
    let (l, c, m) = err(&workload("        imagePullPolicy: Always\n"));
    assert_eq!((l, c), (10, 9), "{m}");
    assert!(m.contains("unknown field `imagePullPolicy`"), "{m}");
    // A bad quantity points at the value.
    let (l, c, m) = err(&workload("        resources:\n          memory: 2 gigs\n"));
    assert_eq!((l, c), (11, 19), "{m}");
    assert!(m.contains("invalid quantity `2 gigs`"), "{m}");
    // Kinds.
    assert_eq!(
        err("apiVersion: kith.dev/v1\nkind: workload\nmetadata: {name: a}\n"),
        (2, 7, "unknown kind `workload`, did you mean `Workload`?".into())
    );
    assert_eq!(
        err("apiVersion: kith.dev/v1\nkind: Deployment\nmetadata: {name: a}\n").0,
        2
    );
    assert_eq!(
        err("apiVersion: kith.dev/v1\nmetadata: {name: a}\n"),
        (1, 1, "missing field `kind`".into())
    );
    // Envelope rules.
    assert_eq!(err("apiVersion: apps/v1\nkind: Namespace\nmetadata: {name: a}\n").0, 1);
    let (l, c, m) = err("apiVersion: kith.dev/v1\nkind: Namespace\nmetadata:\n  name: Media_1\n");
    assert_eq!((l, c), (4, 9), "{m}");
    let (l, _, m) = err("apiVersion: kith.dev/v1\nkind: Node\nmetadata:\n  name: a\n  namespace: x\n");
    assert_eq!(l, 5, "{m}");
    assert!(m.contains("cluster-scoped"), "{m}");
    // A kind with required fields needs its spec.
    assert!(
        err("apiVersion: kith.dev/v1\nkind: Workload\nmetadata: {name: a}\n")
            .2
            .contains("missing field `template`")
    );
    // Rules beyond the shape.
    let (l, _, m) = err(&workload(
        "        env:\n          - name: A\n            value: x\n            secret: {name: s, key: k}\n",
    ));
    assert_eq!(l, 6, "points into the spec: {m}");
    assert_eq!(
        m,
        "template, unit `web`, env `A`: set exactly one of `value`, `secret`, `configMap`, `field`"
    );
    assert!(
        err(&workload("      - name: web\n        image: other\n"))
            .2
            .contains("two units are named `web`")
    );
    assert!(
        err("apiVersion: kith.dev/v1\nkind: Job\nmetadata: {name: a}\nspec: {template: {}}\n")
            .2
            .contains("at least one")
    );
    // Enums list what is allowed.
    let (l, _, m) = err(&workload("  strategy: canary\n"));
    assert_eq!(l, 10);
    assert!(m.contains("`rolling`") && m.contains("`blueGreen`"), "{m}");
    // A later document's error still has its own line.
    assert_eq!(
        err(&format!("{JELLYFIN}---\napiVersion: kith.dev/v1\nkind: Nope\n")).0,
        JELLYFIN.lines().count() + 3
    );
}

#[test]
fn every_kind_has_a_schema_and_a_minimal_resource() {
    // (PLAN.md's 28, NodeKey and Blob. `Backup` is one of the 28. Then AccessLevel and
    // RemotePeer, docs/adr-people.md's.)
    assert_eq!(KINDS.len(), 38);
    for info in KINDS {
        let schema = info.schema();
        assert_eq!(schema["properties"]["kind"]["const"], json!(info.kind));
        assert_eq!(
            schema["required"],
            json!(["apiVersion", "kind", "metadata"]),
            "{}",
            info.kind
        );
        assert!(schema["properties"]["spec"].is_object(), "{}", info.kind);
        assert_eq!(kind(&info.kind.to_lowercase()).unwrap().kind, info.kind);
    }
    let workload = kind("Workload").unwrap().schema();
    let text = workload.to_string();
    assert!(text.contains("\"required\":[\"template\"]"), "{text}");
    assert!(text.contains("Ki|Mi|Gi|Ti"), "the quantity pattern is in the schema");
    assert!(text.contains("blueGreen"));
}

#[test]
fn yaml_output_reads_back_identically() {
    for r in load(JELLYFIN).into_iter().chain(load(WORKSTATION)) {
        assert_eq!(one(&r.to_yaml()), r, "{}", r.to_yaml());
    }
}

#[test]
fn apply_diff_and_revisions() {
    let mut store = Store::default();
    let v1 = one(&workload(""));

    let created = store.apply(v1.clone()).unwrap();
    assert_eq!(
        (created.action, created.after.metadata.revision),
        (Action::Created, Some(1))
    );
    assert!(
        created
            .diff()
            .starts_with("--- /dev/null\n+++ Workload/default/web (new)\n"),
        "{}",
        created.diff()
    );

    // Applying the same thing again changes nothing and records nothing.
    let again = store.apply(v1.clone()).unwrap();
    assert_eq!((again.action, again.diff().as_str()), (Action::Unchanged, ""));
    assert_eq!(store.history("Workload/default/web").unwrap().len(), 1);

    let v2 = one(&workload("  replicas: 3\n"));
    let planned = store.plan(v2.clone()).unwrap();
    assert_eq!(
        store.get("Workload/default/web").unwrap().metadata.revision,
        Some(1),
        "plan does not write"
    );
    let updated = store.apply(v2).unwrap();
    assert_eq!(planned, updated);
    assert_eq!(
        (updated.action, updated.after.metadata.revision),
        (Action::Updated, Some(2))
    );
    let diff = updated.diff();
    assert!(
        diff.contains("--- Workload/default/web (live)\n+++ Workload/default/web (desired)\n"),
        "{diff}"
    );
    assert!(diff.contains("\n+  replicas: 3\n"), "{diff}");
    assert!(!diff.contains("revision"), "{diff}");

    // Rolling back re-applies old content as a new revision.
    let back = store.rollback("Workload/default/web", 1).unwrap();
    assert_eq!((back.action, back.after.metadata.revision), (Action::Updated, Some(3)));
    assert_eq!(back.after.spec, v1.spec);
    assert!(back.diff().contains("\n-  replicas: 3\n"));
    assert!(matches!(
        store.rollback("Workload/default/web", 9),
        Err(store::Error::NotFound(_))
    ));
    let revisions: Vec<_> = store
        .history("Workload/default/web")
        .unwrap()
        .iter()
        .map(|r| r.resource.metadata.revision)
        .collect();
    assert_eq!(revisions, [Some(1), Some(2), Some(3)]);

    // The store survives a round trip through JSON.
    let saved: Store = serde_json::from_str(&serde_json::to_string(&store).unwrap()).unwrap();
    assert_eq!(saved, store);

    assert_eq!(store.list(Some("Workload")).count(), 1);
    assert_eq!(store.list(Some("Service")).count(), 0);
    assert_eq!(store.delete("Workload/default/web").unwrap().metadata.revision, Some(3));
    assert!(store.get("Workload/default/web").is_none());
    assert!(store.delete("Workload/default/web").is_err());
}

#[test]
fn apply_keeps_status_and_validates() {
    let mut store = Store::default();
    let mut sneaky = one(&workload(""));
    sneaky.status = Some(json!({"ready": 99}));
    assert_eq!(
        store.apply(sneaky).unwrap().after.status,
        None,
        "apply never writes status"
    );
    store
        .set_status("Workload/default/web", Some(json!({"ready": 1})))
        .unwrap();
    assert_eq!(
        store.history("Workload/default/web").unwrap().len(),
        1,
        "status is not versioned"
    );
    let change = store.apply(one(&workload("  replicas: 2\n"))).unwrap();
    assert_eq!(change.after.status, Some(json!({"ready": 1})));

    // `kith get -o yaml`, edit, apply: fine while the revision is still live, refused once it is stale.
    let mut edited = one(&store.get("Workload/default/web").unwrap().to_yaml());
    assert_eq!(edited.metadata.revision, Some(2));
    edited.spec["replicas"] = json!(5);
    assert_eq!(store.apply(edited.clone()).unwrap().after.metadata.revision, Some(3));
    edited.spec["replicas"] = json!(6);
    assert!(matches!(store.apply(edited), Err(store::Error::Conflict(m)) if m.contains("is at revision 3")));

    // Resources built in code go through the same validation as files.
    let mut bad = one(&workload(""));
    bad.spec["template"]["containers"][0]["image"] = json!(5);
    assert!(matches!(store.plan(bad), Err(store::Error::Invalid(m)) if m.contains("expected a string")));
    let mut bad = one(&workload(""));
    bad.kind = "Gadget".into();
    assert!(store.apply(bad).is_err());
}

#[test]
fn a_view_keeps_a_resource_as_it_was_sent() {
    let mut theirs = Store::default();
    for n in 1..=3 {
        theirs.apply(one(&workload(&format!("  replicas: {n}\n")))).unwrap();
    }
    let key = "Workload/default/web";
    theirs.set_status(key, Some(json!({ "ready": 3 }))).unwrap();
    let sent = theirs.get(key).unwrap().clone();
    // Its revision and status as they were, one revision of it and no history.
    let mut view = Store::default();
    view.put(sent.clone());
    view.put(sent.clone());
    assert_eq!(view.get(key), Some(&sent));
    assert_eq!(view.history(key).unwrap().len(), 1);
    assert!(view.remove(key) && !view.remove(key) && view.get(key).is_none());
}

#[test]
fn history_is_bounded() {
    let mut store = Store::default();
    for n in 0..HISTORY_LIMIT + 5 {
        store.apply(one(&workload(&format!("  replicas: {n}\n")))).unwrap();
    }
    let history = store.history("Workload/default/web").unwrap();
    assert_eq!(history.len(), HISTORY_LIMIT);
    assert_eq!(
        history.last().unwrap().resource.metadata.revision,
        Some(HISTORY_LIMIT as u64 + 5)
    );
}

/// When a resource was first made is kept once the store is marked: set by the change
/// that makes it, the same after its history is trimmed, gone with it, new when it is made
/// again; and a batch that is refused leaves no mark of what it would have made.
#[test]
fn born_is_set_once_and_outlives_the_history() {
    let key = "Workload/default/web";
    let web = |n: usize| one(&workload(&format!("  replicas: {n}\n")));
    let mut store = Store::default();
    store.at(Some(100));
    store.apply(web(0)).unwrap();
    assert!(!store.marked() && store.born(key).is_none());
    let unmarked = serde_json::to_string(&store).unwrap();
    assert!(!unmarked.contains("born"), "{unmarked}");
    // What was there when it is marked: the time of the oldest revision kept, of entry 0.
    store.mark();
    assert_eq!(store.born(key), Some((0, 100)));
    store.at(Some(200));
    for n in 1..HISTORY_LIMIT + 50 {
        store.entry(n as u64);
        store.apply(web(n)).unwrap();
    }
    assert_eq!(store.history(key).unwrap().first().unwrap().at, 200);
    assert_eq!(store.born(key), Some((0, 100)));
    store.mark();
    assert_eq!(store.born(key), Some((0, 100)));
    // It is read back as it was written.
    let read: Store = serde_json::from_str(&serde_json::to_string(&store).unwrap()).unwrap();
    assert_eq!(read.born(key), Some((0, 100)));
    // Deleted and made again: new, of the entry that made it.
    store.delete(key).unwrap();
    assert_eq!(store.born(key), None);
    store.entry(900);
    store.at(Some(300));
    store.apply(web(0)).unwrap();
    assert_eq!(store.born(key), Some((900, 300)));
    store.entry(901);
    store.rollback(key, 1).unwrap();
    assert_eq!(store.born(key), Some((900, 300)));
    // A batch that is refused, and one only tried, make nothing.
    let other = || one(&workload("  replicas: 1\n").replace("name: web", "name: other"));
    // (Based on a revision it is not at.)
    let mut refused = one(&workload("  replicas: 1\n").replace("name: web", "name: third"));
    refused.metadata.revision = Some(7);
    assert!(store.apply_all(vec![other(), refused]).is_err());
    store.dry_run(vec![other()]).unwrap();
    assert_eq!(store.born("Workload/default/other"), None);
    store.apply_all(vec![other()]).unwrap();
    assert_eq!(store.born("Workload/default/other"), Some((901, 300)));
    assert!(store.remove("Workload/default/other") && store.born("Workload/default/other").is_none());
}

#[test]
fn package_history() {
    let package = |n: usize| {
        one(&format!(
            "apiVersion: kith.dev/v1\nkind: Package\nmetadata:\n  name: web\nspec:\n  version: 1.0.0\n  files:\n    package.yaml: \"n{n}\"\n"
        ))
    };
    let mut store = Store::default();
    for n in 0..10 {
        store.apply(package(n)).unwrap();
    }
    let history = store.history("Package/web").unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].resource.metadata.revision, Some(8));

    // Rolling back within what is kept works; further back is refused.
    assert!(store.rollback("Package/web", 7).is_err());
    store.rollback("Package/web", 8).unwrap();
    let live = store.get("Package/web").unwrap();
    assert_eq!(live.metadata.revision, Some(11));
    assert_eq!(live.spec["files"]["package.yaml"], json!("n7"));

    // Other kinds keep the full limit.
    for n in 0..HISTORY_LIMIT + 5 {
        store.apply(one(&workload(&format!("  replicas: {n}\n")))).unwrap();
    }
    assert_eq!(store.history("Workload/default/web").unwrap().len(), HISTORY_LIMIT);
}

/// A NodeKey keeps its live revision only: a key the cluster forgot is in no earlier one.
#[test]
fn node_key_history() {
    let key = |wrapped: &str| {
        let id = "ab".repeat(32);
        one(&format!(
            "apiVersion: kith.dev/v1\nkind: NodeKey\nmetadata:\n  name: n1\nspec:\n  id: \"{id}\"\n  wrapped: \"{wrapped}\"\n"
        ))
    };
    let wrapped = "c0ffee".repeat(10); // pragma: allowlist secret
    let mut store = Store::default();
    store.apply(key(&wrapped)).unwrap();
    store.apply(key("")).unwrap();
    let history = store.history("NodeKey/n1").unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].resource.metadata.revision, Some(2));
    assert!(!serde_json::to_string(&store).unwrap().contains(&wrapped));

    // A batch that is refused puts back what was there, its one revision.
    let mut bad = one(&workload(""));
    bad.metadata.name = "Not Valid".into();
    assert!(store.apply_all(vec![key(&wrapped), bad.clone()]).is_err());
    assert_eq!(store.history("NodeKey/n1").unwrap().len(), 1);
    assert!(!serde_json::to_string(&store).unwrap().contains(&wrapped));
    store.apply(key(&wrapped)).unwrap();
    assert!(store.apply_all(vec![key(""), bad]).is_err());
    let history = store.history("NodeKey/n1").unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].resource.spec["wrapped"], json!(wrapped));

    // Other kinds keep theirs.
    for n in 0..5 {
        store.apply(one(&workload(&format!("  replicas: {n}\n")))).unwrap();
    }
    assert_eq!(store.history("Workload/default/web").unwrap().len(), 5);
}

#[test]
fn node_key_history_from_before_is_cut() {
    let key = |wrapped: &str| {
        let id = "ab".repeat(32);
        one(&format!(
            "apiVersion: kith.dev/v1\nkind: NodeKey\nmetadata:\n  name: n1\nspec:\n  id: \"{id}\"\n  wrapped: \"{wrapped}\"\n"
        ))
    };
    let wrapped = "c0ffee".repeat(10); // pragma: allowlist secret
    let mut store = Store::default();
    store.apply(key(&wrapped)).unwrap();
    let first = serde_json::to_value(&store.history("NodeKey/n1").unwrap()[0]).unwrap();
    store.apply(key("")).unwrap();
    for n in 0..5 {
        store.apply(one(&workload(&format!("  replicas: {n}\n")))).unwrap();
    }
    // As a store from before the one-revision limit has it: the key in an earlier revision.
    let mut old = serde_json::to_value(&store).unwrap();
    old["resources"]["NodeKey/n1"].as_array_mut().unwrap().insert(0, first);
    let mut store: Store = serde_json::from_value(old).unwrap();
    assert!(serde_json::to_string(&store).unwrap().contains(&wrapped));

    assert!(store.cut_node_key_histories());
    let history = store.history("NodeKey/n1").unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].resource.metadata.revision, Some(2));
    assert!(!serde_json::to_string(&store).unwrap().contains(&wrapped));
    assert_eq!(store.history("Workload/default/web").unwrap().len(), 5);
    // Nothing left to cut.
    assert!(!store.cut_node_key_histories());
}

#[test]
fn timestamps() {
    assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(rfc3339(1_794_476_096), "2026-11-12T09:34:56Z");
}

#[test]
fn file_store() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("kith-file-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("nested/store");

    // Reading a store that does not exist gives an empty one and creates nothing.
    assert_eq!(FileStore::read(&path).unwrap().store, Store::default());
    assert!(!dir.exists());

    let mut fs = FileStore::open(&path).unwrap();
    fs.store.apply(one(&workload(""))).unwrap();
    fs.save().unwrap();
    fs.save().unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600,
        "secrets live here"
    );
    assert!(!dir.join("nested/store.tmp").exists());
    assert_eq!(FileStore::read(&path).unwrap().store, fs.store);
    drop(fs);

    // Damaged stores are errors, not panics and not silent resets.
    std::fs::write(&path, &std::fs::read(&path).unwrap()[..40]).unwrap();
    assert!(matches!(FileStore::open(&path), Err(store::Error::Io(m)) if m.contains("is not a kith store")));
    std::fs::write(&path, r#"{"resources":{"Workload/default/web":[]}}"#).unwrap();
    let mut fs = FileStore::open(&path).unwrap();
    assert!(fs.store.get("Workload/default/web").is_none());
    assert_eq!(fs.store.list(None).count(), 0);
    assert!(fs.store.delete("Workload/default/web").is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn apply_all_is_all_or_nothing() {
    let mut store = Store::default();
    let mut bad = one(&workload(""));
    bad.metadata.name = "Not Valid".into();
    assert!(store.apply_all(vec![one(&workload("")), bad]).is_err());
    assert_eq!(store.list(None).count(), 0, "the good one was not applied either");
    let changes = store.apply_all(load(JELLYFIN)).unwrap();
    assert_eq!(changes.len(), 3);
    assert_eq!(store.list(None).count(), 3);
    // Changes travel over the API as JSON.
    let wire: Vec<store::Change> = serde_json::from_str(&serde_json::to_string(&changes).unwrap()).unwrap();
    assert_eq!(wire, changes);
}

#[test]
fn quantities_have_values() {
    let q = |s: &str| kinds::Quantity::try_from(s.to_string()).unwrap().value();
    assert_eq!(
        (q("2"), q("500m"), q("1.5"), q("64Mi"), q("2Gi"), q("1G")),
        (2.0, 0.5, 1.5, 67108864.0, 2147483648.0, 1e9)
    );
}

#[test]
fn expose_host_is_a_domain_name() {
    let service = |host: &str| {
        let spec =
            format!("selector: {{ app: web }}\n  ports: [{{ port: 80 }}]\n  expose: {{ host: '{host}', via: edge }}");
        let yaml = format!("apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: web }}\nspec:\n  {spec}\n");
        Resource::from_source(&yaml)
            .map_err(|e| e.msg)?
            .into_iter()
            .try_for_each(|doc| doc.map(drop).map_err(|e| e.msg))
    };
    assert_eq!(service("shop.example.org"), Ok(()));
    for bad in [
        "",
        "https://shop.example.org",
        "shop.example.org:443",
        "shop example",
        "*.example.org",
        "a..b",
        ".a",
    ] {
        let said = service(bad).unwrap_err();
        assert!(
            said.contains("expose.host") && said.contains("not a domain name"),
            "{bad}: {said}"
        );
    }
    let long = vec!["a".repeat(60); 5].join(".");
    assert!(service(&long).unwrap_err().contains("expose.host"));
}

#[test]
fn expose_host_is_one_a_certificate_authority_issues_for() {
    for bad in [
        "203.0.113.7",
        "2130706433",
        "shop.example.123",
        "-shop.example.org",
        "shop-.example.org",
        "shop.-a.org",
        "my_shop.example.org",
    ] {
        let spec =
            format!("selector: {{ app: web }}\n  ports: [{{ port: 80 }}]\n  expose: {{ host: '{bad}', via: edge }}");
        let yaml = format!("apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: web }}\nspec:\n  {spec}\n");
        let said = Resource::from_source(&yaml).unwrap().remove(0).unwrap_err().msg;
        assert!(said.contains("expose.host") && said.contains(bad), "{bad}: {said}");
    }
    assert_eq!(crate::kinds::expose_host_refused("shop.example.org"), None);
    assert_eq!(crate::kinds::expose_host_refused("a-b.c1.org"), None);
}

#[test]
fn expose_asks_for_the_proxy_protocol() {
    let service = |expose: &str| {
        let yaml = format!(
            "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: web }}\nspec:\n  \
             selector: {{ app: web }}\n  ports: [{{ port: 80 }}]\n  expose: {expose}\n"
        );
        let resource = Resource::from_source(&yaml).unwrap().remove(0).map_err(|e| e.msg)?;
        serde_json::from_value::<kinds::ServiceSpec>(resource.spec).map_err(|e| e.to_string())
    };
    let on = service("{ host: a.example.org, via: edge, proxyProtocol: true }").unwrap();
    assert_eq!(on.expose.unwrap().proxy_protocol, Some(true));
    let off = service("{ host: a.example.org, via: edge }").unwrap();
    assert_eq!(off.expose.unwrap().proxy_protocol, None);
    assert!(service("{ host: a.example.org, via: edge, proxyProtocol: yes please }").is_err());
}

#[test]
fn expose_paths_and_headers_are_checked_naming_the_field() {
    let service = |expose: &str| {
        let yaml = format!(
            "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: web }}\nspec:\n  \
             selector: {{ app: web }}\n  ports: [{{ port: 80 }}]\n  expose: {expose}\n"
        );
        let resource = Resource::from_source(&yaml).unwrap().remove(0).map_err(|e| e.msg)?;
        serde_json::from_value::<kinds::ServiceSpec>(resource.spec).map_err(|e| e.to_string())
    };
    let host = "host: a.example.org, via: edge";
    let fine = service(&format!(
        "{{ {host}, paths: [{{ path: /, service: web, port: 80 }}, {{ path: /api/, exact: true, service: api, port: \
         8080 }}], headers: {{ X-Env: 'prod; a=b' }} }}"
    ))
    .unwrap()
    .expose
    .unwrap();
    assert_eq!(fine.paths.len(), 2);
    assert_eq!(fine.paths[1].exact, Some(true));
    assert_eq!(fine.headers["X-Env"], "prod; a=b");
    // A host without either reads as before, and writes as before.
    let plain = service(&format!("{{ {host} }}")).unwrap().expose.unwrap();
    assert!(plain.paths.is_empty() && plain.headers.is_empty());
    assert_eq!(
        serde_json::to_value(&plain).unwrap(),
        serde_json::json!({"host": "a.example.org", "via": "edge"})
    );

    let refused = |expose: &str, field: &str| {
        let said = service(&format!("{{ {host}, {expose} }}")).unwrap_err();
        assert!(said.contains(field), "{expose}: {said}");
    };
    let path = |p: &str| format!("paths: [{{ path: '{p}', service: web, port: 80 }}]");
    for bad in ["app", "/a b", "/a?x=1", "/a#top", "/caf\u{e9}", "/a\tb", ""] {
        refused(&path(bad), "expose.paths[0].path");
    }
    refused(&path(&format!("/{}", "a".repeat(1100))), "expose.paths[0].path");
    refused(
        "paths: [{ path: /a, service: web, port: 80 }, { path: /a/, service: api, port: 80 }]",
        "expose.paths[1].path: `/a/` is there twice",
    );
    refused(
        "paths: [{ path: /a, service: Web_1, port: 80 }]",
        "expose.paths[0].service",
    );
    refused(
        "paths: [{ path: /a, service: ../x, port: 80 }]",
        "expose.paths[0].service",
    );
    refused("paths: [{ path: /a, service: web, port: 0 }]", "expose.paths[0].port");
    refused(
        "paths: [{ path: /a, service: web, port: 80, namespace: other }]",
        "namespace",
    );
    refused("proxyProtocol: true, headers: { X-A: b }", "expose.proxyProtocol");
    for name in [
        "Connection",
        "transfer-encoding",
        "Upgrade",
        "Host",
        "Content-Length",
        "TE",
        "Trailer",
        "Keep-Alive",
        "Proxy-Authorization",
        "X-Forwarded-For",
        "x-forwarded-proto",
        "X-Forwarded-Host",
        "Forwarded",
        "X A",
        "X:A",
        "",
    ] {
        refused(
            &format!("headers: {{ '{name}': v }}"),
            &format!("expose.headers[{name}]"),
        );
    }
    for value in ["a\\r\\nX-Evil: 1", "a\\nb", "a\\rb", "a\\u0000b", "\\u00e9t\\u00e9"] {
        refused(&format!("headers: {{ X-A: \"{value}\" }}"), "expose.headers[X-A]");
    }
    refused("headers: { X-A: a, x-a: b }", "named twice");
}

#[test]
fn dns_block_list_is_checked() {
    let list = |spec: &str| {
        let yaml = format!("apiVersion: kith.dev/v1\nkind: DNSBlockList\nmetadata: {{ name: ads }}\nspec: {spec}\n");
        let docs = Resource::from_source(&yaml).map_err(|e| e.msg)?;
        docs.into_iter().try_for_each(|doc| doc.map(drop).map_err(|e| e.msg))
    };
    let sha = "a".repeat(64);
    for ok in [
        "{ url: 'https://lists.example/hosts.txt' }".to_string(),
        format!("{{ url: 'https://lists.example:8443/h?x=1', sha256: {sha}, interval: 6h, answer: unspecified }}"),
        "{ configMap: { name: ads, key: hosts }, clients: [192.168.0.0/16, 'fd00::/8'] }".to_string(),
        "{ configMap: { name: ads, key: hosts }, answer: nxdomain }".to_string(),
    ] {
        assert_eq!(list(&ok), Ok(()), "{ok}");
    }
    for (bad, why) in [
        ("{}", "exactly one"),
        (
            "{ url: 'https://a.example/x', configMap: { name: a, key: b } }",
            "exactly one",
        ),
        ("{ url: 'http://a.example/x' }", "not an https://"),
        ("{ url: 'ftp://a.example/x' }", "not an https://"),
        ("{ url: 'https://' }", "needs a host"),
        ("{ url: 'https://user:pw@a.example/x' }", "no user or password"),
        ("{ url: 'https://a.example/a b' }", "space or control"),
        ("{ url: 'https://a.example/x', sha256: abc }", "64 hexadecimal"),
        ("{ url: 'https://a.example/x', interval: 1m }", "at least 5m"),
        ("{ url: 'https://a.example/x', interval: soon }", "not like"),
        ("{ configMap: { name: a, key: b }, interval: 1h }", "for a `url` list"),
        ("{ configMap: { name: '', key: b } }", "name and a key"),
        // (Read from kith-system only: there is no namespace to say.)
        ("{ configMap: { namespace: dns, name: a, key: b } }", "namespace"),
        ("{ url: 'https://a.example/x', clients: [lan] }", "not a network"),
        ("{ url: 'https://a.example/x', answer: redirect }", "unknown variant"),
        ("{ url: 'https://a.example/x', extra: 1 }", "extra"),
    ] {
        let said = list(bad).unwrap_err();
        assert!(said.contains(why), "{bad}: {said}");
    }
}

#[test]
fn dns_kinds_are_checked() {
    let zone = |spec: &str| format!("apiVersion: kith.dev/v1\nkind: DNSZone\nmetadata: {{ name: z }}\nspec: {spec}\n");
    let record =
        |spec: &str| format!("apiVersion: kith.dev/v1\nkind: DNSRecord\nmetadata: {{ name: r }}\nspec: {spec}\n");
    let good = |yaml: String| {
        let docs = Resource::from_source(&yaml).map_err(|e| e.msg)?;
        docs.into_iter().try_for_each(|doc| doc.map(drop).map_err(|e| e.msg))
    };
    let said = |yaml: String| good(yaml).unwrap_err();

    assert_eq!(
        good(zone(
            "{ domain: home.example, clients: [192.168.0.0/16, 'fd00::/8', 10.0.0.1] }"
        )),
        Ok(())
    );
    assert!(said(zone("{ domain: 'home example' }")).contains("not a domain name"));
    assert!(said(zone("{ domain: Node.Kith }")).contains("the cluster's own"));
    assert!(
        said(zone(&format!(
            "{{ domain: {}.example }}",
            vec!["a".repeat(60); 4].join(".")
        )))
        .contains("longer than 240")
    );
    assert!(said(zone("{ domain: a.b, clients: [10.0.0.0/33] }")).contains("prefix length"));
    assert!(said(zone("{ domain: a.b, clients: [lan] }")).contains("not a network"));

    for ok in [
        "{ zone: z, name: nas, type: A, values: [192.168.1.20, 192.168.1.21] }",
        "{ zone: z, name: '@', type: AAAA, values: ['fd00::1'], ttl: 60 }",
        "{ zone: z, name: '*.apps', type: CNAME, values: [nas.home.example.] }",
        "{ zone: z, name: _http._tcp, type: SRV, values: ['0 5 8080 nas.home.example'] }",
        "{ zone: z, name: '@', type: TXT, values: ['v=spf1 -all'] }",
    ] {
        assert_eq!(good(record(ok)), Ok(()), "{ok}");
    }
    for (bad, why) in [
        (
            "{ zone: z, name: nas, type: A, values: ['fd00::1'] }",
            "not an IPv4 address",
        ),
        ("{ zone: z, name: nas, type: A, values: [] }", "1 to 100 values"),
        (
            "{ zone: z, name: 'a b', type: A, values: [1.2.3.4] }",
            "not a name like",
        ),
        (
            "{ zone: z, name: nas, type: CNAME, values: [a.b, c.d] }",
            "a CNAME has one value",
        ),
        (
            "{ zone: z, name: nas, type: SRV, values: ['0 5 nas'] }",
            "priority weight port target",
        ),
        ("{ zone: z, name: nas, type: MX, values: [a.b] }", "MX"),
    ] {
        let said = said(record(bad));
        assert!(said.contains(why), "{bad}: {said}");
    }
}

const GAME: &str = "
apiVersion: kith.dev/v1
kind: KindDefinition
metadata: { name: gameserver }
spec:
  group: games.example.com
  version: v1
  kind: GameServer
  schema:
    type: object
    required: [map]
    additionalProperties: false
    properties:
      map: { type: string }
      players: { type: integer, minimum: 1, maximum: 64 }
  columns:
    - { name: Map, path: spec.map }
";

#[test]
fn custom_kinds_are_checked_by_the_store() {
    let mut store = Store::default();
    let server =
        |rest: &str| format!("apiVersion: games.example.com/v1\nkind: GameServer\nmetadata: {{ name: one }}\n{rest}");
    let refused = |store: &mut Store, src: &str| store.apply(one(src)).unwrap_err().to_string();

    // No definition, no kind; and kith's own apiVersion is for kith's own kinds.
    assert!(refused(&mut store, &server("spec: { map: dust }")).contains("no KindDefinition makes it"));
    assert!(
        err("apiVersion: kith.dev/v1\nkind: GameServer\nmetadata: { name: one }\n")
            .2
            .contains("unknown kind")
    );

    store.apply(one(GAME)).unwrap();
    let made = store
        .apply(one(&server("spec: { map: dust, players: 8 }")))
        .unwrap()
        .after;
    assert_eq!(
        (made.key().as_str(), made.api_version.as_str()),
        ("GameServer/default/one", "games.example.com/v1")
    );
    // One of kith's own kinds in other capitals is no kind of anyone's.
    let shouted = server("spec: {}").replace("GameServer", "WORKLOAD");
    assert!(err(&shouted).2.contains("did you mean `Workload`"));
    let mut forged = made.clone();
    (forged.kind, forged.metadata.revision) = ("SOURCE".into(), None);
    assert!(
        store
            .apply(forged)
            .unwrap_err()
            .to_string()
            .contains("did you mean `Source`")
    );
    assert_eq!(one(&made.to_yaml()), made);

    // What the schema says, with the path; the apiVersion; a spec that is no mapping.
    let wrong = refused(&mut store, &server("spec: { players: 99, cheats: true }"));
    for said in [
        "spec.map: is required",
        "spec.players: it must be at most 64",
        "spec.cheats: is not a field the schema has",
    ] {
        assert!(wrong.contains(said), "{wrong}");
    }
    let other = server("spec: { map: dust }").replace("example.com/v1", "example.com/v2");
    assert!(refused(&mut store, &other).contains("GameServer is `games.example.com/v1`"));
    assert!(err(&server("spec: [1]")).2.contains("spec"));
    assert!(
        err(&server("").replace("GameServer", "gameServer"))
            .2
            .contains("invalid kind")
    );

    // One definition for a kind; its kind and scope stay, and it stays, while it is used.
    let again = GAME.replace("name: gameserver", "name: again");
    let lower = again.replace("kind: GameServer", "kind: Gameserver");
    assert!(refused(&mut store, &lower).contains("already defines `GameServer`"));
    let second = refused(&mut store, &again);
    assert!(
        second.contains("KindDefinition/gameserver already defines `GameServer`"),
        "{second}"
    );
    let cluster = GAME.replace("version: v1\n", "version: v1\n  namespaced: false\n");
    assert!(refused(&mut store, &cluster).contains("1 `GameServer` resources exist"));
    assert!(
        store
            .delete("KindDefinition/gameserver")
            .unwrap_err()
            .to_string()
            .contains("delete them first")
    );
    store.delete("GameServer/default/one").unwrap();
    store.apply(one(&cluster)).unwrap();
    assert_eq!(
        store.apply(one(&server("spec: { map: dust }"))).unwrap().after.key(),
        "GameServer/one"
    );
    let placed = server("spec: { map: dust }").replace("name: one", "name: one, namespace: shop");
    assert!(refused(&mut store, &placed).contains("cluster-scoped"));
    store.delete("GameServer/one").unwrap();
    store.delete("KindDefinition/gameserver").unwrap();
}

#[test]
fn custom_kind_definitions_are_checked() {
    let wrong = |from: &str, to: &str| err(&GAME.replace(from, to)).2;
    assert!(wrong("kind: GameServer", "kind: Workload").contains("one of kith's own kinds"));
    assert!(wrong("kind: GameServer", "kind: game_server").contains("invalid kind"));
    // `Audit` is the role resource that reads the audit log: no definition takes it, in any case.
    assert!(wrong("kind: GameServer", "kind: Audit").contains("reserved"));
    assert!(wrong("kind: GameServer", "kind: AUDIT").contains("reserved"));
    assert!(wrong("games.example.com", "kith.dev").contains("not kith.dev"));
    assert!(wrong("games.example.com", "games").contains("domain name"));
    assert!(wrong("version: v1", "version: one").contains("like v1 or v1beta1"));
    assert!(wrong("type: object", "oneOf: []").contains("`oneOf` is not a keyword kith checks"));
    assert!(wrong("path: spec.map", "path: 'spec..map'").contains("dotted path"));
}

/// A batch is all or nothing and a dry run changes nothing, without a copy of the store:
/// what they put back is the histories they touched.
#[test]
fn batches_and_dry_runs_leave_the_store_as_it_was() {
    let cm = |name: &str, value: &str| {
        one(&format!(
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: {{ name: {name} }}\nspec: {{ data: {{ k: {value} }} }}"
        ))
    };
    let mut store = Store::default();
    store.apply_all(vec![cm("a", "1"), cm("b", "1")]).unwrap();
    let before = store.clone();
    // A dry run says what would happen (a later one sees an earlier) and changes nothing.
    let said = store
        .dry_run(vec![cm("a", "2"), cm("a", "3"), cm("c", "1"), cm("b", "1")])
        .unwrap();
    let actions: Vec<_> = said.iter().map(|c| (c.after.metadata.revision, c.action)).collect();
    let (updated, created, unchanged) = (Action::Updated, Action::Created, Action::Unchanged);
    assert_eq!(
        actions,
        [
            (Some(2), updated),
            (Some(3), updated),
            (Some(1), created),
            (Some(1), unchanged)
        ]
    );
    assert_eq!(store, before);
    // A refused one takes back the ones before it: an update, a new key.
    let mut refused = one("apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: d }");
    refused.metadata.revision = Some(7);
    assert!(store.apply_all(vec![cm("a", "2"), cm("e", "1"), refused]).is_err());
    assert_eq!(store, before);
    // And a good one is kept.
    store.apply_all(vec![cm("a", "2"), cm("e", "1")]).unwrap();
    assert_eq!(store.get("ConfigMap/default/a").unwrap().metadata.revision, Some(2));
    assert!(store.get("ConfigMap/default/e").is_some());
}

#[test]
fn an_image_kind_names_a_volume_and_a_tag_a_registry_can_serve() {
    let image = |spec: &str| {
        let text = format!("apiVersion: kith.dev/v1\nkind: Image\nmetadata: {{ name: hello }}\nspec: {spec}\n");
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    image("{ volume: out }").unwrap();
    image("{ volume: out, tag: v1.2_rc-3, job: build, entrypoint: [/bin/hello], env: ['A=b=c', 'EMPTY='], workingDir: /srv }").unwrap();
    assert!(image("{ tag: '1' }").unwrap_err().contains("volume"));
    for bad in ["a/b", "a:b", "-a", ".a", "é", "'a b'", "''"] {
        assert!(
            image(&format!("{{ volume: out, tag: {bad} }}"))
                .unwrap_err()
                .contains("tag:"),
            "{bad}"
        );
    }
    assert!(
        image("{ volume: out, env: [NOPE] }")
            .unwrap_err()
            .contains("NAME=value")
    );
    assert!(
        image("{ volume: out, env: ['=x'] }")
            .unwrap_err()
            .contains("NAME=value")
    );
    assert!(
        image("{ volume: out, workingDir: srv }")
            .unwrap_err()
            .contains("workingDir")
    );
}

#[test]
fn a_backup_says_how_often_and_sends_keys_over_tls_only() {
    use crate::kinds::every;
    assert_eq!(
        (every("90s"), every("30m"), every("24h"), every("7d")),
        (Some(90), Some(1800), Some(86400), Some(604_800))
    );
    for bad in ["", "h", "0h", "-1h", "1.5h", "24", "24 h", "1w", "5é", "é", "+5h"] {
        assert_eq!(every(bad), None, "{bad}");
    }
    let backup = |spec: &str| {
        let text = format!("apiVersion: kith.dev/v1\nkind: Backup\nmetadata: {{ name: nightly }}\nspec: {spec}\n");
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    backup("{ volume: data, every: 24h }").unwrap();
    assert!(backup("{ volume: data, every: daily }").unwrap_err().contains("every:"));
    let s3 = |endpoint: &str, bucket: &str| {
        backup(&format!(
            "{{ volume: data, every: 1h, s3: {{ endpoint: '{endpoint}', bucket: '{bucket}', secret: keys }} }}"
        ))
    };
    s3("https://s3.example.org", "backups").unwrap();
    assert!(s3("http://127.0.0.1:9000", "backups").unwrap_err().contains("https://"));
    assert!(s3("http://s3.example.org", "backups").unwrap_err().contains("https://"));
    assert!(
        s3("http://127.0.0.1.example.org", "backups")
            .unwrap_err()
            .contains("https://")
    );
    assert!(s3("https://s3.example.org", "a/../b").unwrap_err().contains("bucket"));
}

#[test]
fn a_volumes_replicas_are_at_least_itself_and_synced_no_more_often_than_every_ten_seconds() {
    let volume = |spec: &str| {
        let text = format!("apiVersion: kith.dev/v1\nkind: Volume\nmetadata: {{ name: data }}\nspec: {spec}\n");
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    volume("{ node: a, path: d, replicas: 2, sync: 10s }").unwrap();
    assert!(
        volume("{ node: a, path: d, replicas: 0 }")
            .unwrap_err()
            .contains("replicas:")
    );
    assert!(
        volume("{ node: a, path: d, replicas: 2, sync: 9s }")
            .unwrap_err()
            .contains("under 10s")
    );
    assert!(
        volume("{ node: a, path: d, replicas: 2, sync: often }")
            .unwrap_err()
            .contains("sync:")
    );
}

#[test]
fn a_share_names_who_may_use_it_and_no_range_wider_than_a_slash_eight() {
    let share = |spec: &str| {
        let text = format!("apiVersion: kith.dev/v1\nkind: Share\nmetadata: {{ name: films }}\nspec: {spec}\n");
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    share("{ volume: media, nfs: { clients: [192.168.1.20, 192.168.1.0/24] }, readOnly: true }").unwrap();
    share("{ volume: media, users: [ada], uid: 1000, gid: 1000 }").unwrap();
    for bad in ["a:b", "@wheel", "+staff", "a b", ""] {
        let refused = share(&format!("{{ volume: media, users: ['{bad}'] }}"));
        assert!(refused.unwrap_err().contains("not an Identity's name"), "{bad}");
    }
    // (Given to nobody yet: its status says so.)
    share("{ volume: media }").unwrap();
    for bad in ["0.0.0.0/0", "10.0.0.0/7"] {
        let refused = share(&format!("{{ volume: media, nfs: {{ clients: [{bad}] }} }}"));
        assert!(refused.unwrap_err().contains("wider than a /8"), "{bad}");
    }
    for bad in ["lan", "fd00::1", "10.0.0.1/33", "10.0.0.1/+8", "10.0.0/24"] {
        let refused = share(&format!("{{ volume: media, nfs: {{ clients: ['{bad}'] }} }}"));
        assert!(refused.unwrap_err().contains("not an IPv4 address or range"), "{bad}");
    }
}

#[test]
fn a_vm_unit_names_what_it_starts_by_absolute_paths_and_its_memory() {
    let job = |vm: &str| {
        let text = format!(
            "apiVersion: kith.dev/v1\nkind: Job\nmetadata: {{ name: boot }}\nspec:\n  template:\n    vms:\n      - {vm}\n"
        );
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    job("{ name: vm, kernel: /boot/vmlinuz, cmdline: 'console=ttyS0', memory: 256Mi }").unwrap();
    job("{ name: vm, hypervisor: cloudHypervisor, disks: [{ path: /var/lib/vm/disk.raw, readOnly: true }], cpus: 4, memory: 2Gi }").unwrap();
    for (bad, why) in [
        ("{ name: vm, memory: 256Mi }", "nothing to start"),
        (
            "{ name: vm, disks: [{ path: /d.raw }], cmdline: quiet, memory: 256Mi }",
            "are a `kernel`'s",
        ),
        ("{ name: vm, kernel: vmlinuz, memory: 256Mi }", "absolute path"),
        ("{ name: vm, kernel: '/boot/a,b', memory: 256Mi }", "no comma"),
        (
            "{ name: vm, disks: [{ path: '/d.raw,format=qcow2' }], memory: 256Mi }",
            "no comma",
        ),
        (
            "{ name: vm, kernel: /k, cmdline: \"a\\nb\", memory: 256Mi }",
            "one line",
        ),
        ("{ name: vm, kernel: /k, cpus: 0, memory: 256Mi }", "cpus:"),
        ("{ name: vm, kernel: /k, memory: 8Mi }", "at least 16Mi"),
        (
            "{ name: vm, kernel: /k, hypervisor: xen, memory: 256Mi }",
            "unknown variant `xen`",
        ),
    ] {
        let refused = job(bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
    // A VM's name is a unit's name, like a container's.
    let twice = "{ name: vm, kernel: /k, memory: 256Mi }\n      - { name: vm, kernel: /k, memory: 256Mi }";
    assert!(job(twice).unwrap_err().contains("two units are named `vm`"));
}

/// A release may hand its key over to others: what it says is checked for its shape when
/// it is applied (whether it is signed, by the node that would take it).
#[test]
fn handover_names_keys_and_carries_two_signatures() {
    let release = |handover: &str| {
        let text = format!(
            "apiVersion: kith.dev/v1\nkind: OSRelease\nmetadata: {{ name: r }}\nspec: {{ version: '2', image: 'http://h/u', {handover} }}\n"
        );
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    let (key, signature) = ("ab".repeat(32), "cd".repeat(64));
    release("publicKey: aa").unwrap();
    release(&format!(
        "handover: {{ keys: [{key}, {}], signature: {signature}, proof: {signature} }}",
        key.to_uppercase()
    ))
    .unwrap();
    // (A key of digits and one `e` is a number to most YAML readers: here it is the text it is.)
    let number = format!("1e{}", "7".repeat(62));
    release(&format!(
        "handover: {{ keys: [{number}], signature: {signature}, proof: {signature} }}"
    ))
    .unwrap();
    let nine = [key.as_str(); 9].join(", ");
    for (wrong, said) in [
        (
            format!("handover: {{ keys: [], signature: {signature}, proof: {signature} }}"),
            "1 to 8 keys",
        ),
        (
            format!("handover: {{ keys: [{nine}], signature: {signature}, proof: {signature} }}"),
            "1 to 8 keys",
        ),
        (
            format!("handover: {{ keys: [{key}zz], signature: {signature}, proof: {signature} }}"),
            "64 hex digits",
        ),
        (
            format!("handover: {{ keys: [{key}], signature: {key}, proof: {signature} }}"),
            "`signature`",
        ),
        (
            format!("handover: {{ keys: [{key}], signature: {signature}, proof: later }}"),
            "`proof`",
        ),
        (
            format!("handover: {{ keys: [{key}], signature: {signature} }}"),
            "proof",
        ),
        (
            format!("handover: {{ keys: [{key}], signature: {signature}, proof: {signature}, to: all }}"),
            "to",
        ),
    ] {
        let e = release(&wrong).expect_err(&wrong);
        assert!(e.contains(said), "{wrong}: {e}");
    }
}

/// A Cluster's fields that nothing reads are named, each one that is set; `images`, which
/// is read, is not, and no other kind is named for anything.
#[test]
fn cluster_fields_nothing_reads_are_named() {
    let read = |text: &str| Resource::from_source(text).unwrap().remove(0).unwrap();
    let cluster = |spec: &str| {
        read(&format!(
            "apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec: {spec}\n"
        ))
    };
    let all = "{ domain: example.org, voters: [a], updatePolicy: { windows: [Sat 02:00-05:00] }, \
               mesh: { port: 51820 }, values: { a: 1 }, images: [] }";
    let named = ["domain", "voters", "updatePolicy", "mesh", "values"];
    assert_eq!(cluster(all).not_acted_on(), named);
    assert_eq!(cluster("{ voters: [a] }").not_acted_on(), ["voters"]);
    for none in ["{}", "{ images: [] }", "{ voters: [] }"] {
        assert!(cluster(none).not_acted_on().is_empty(), "{none}");
    }
    let other = "apiVersion: kith.dev/v1\nkind: Namespace\nmetadata: { name: values }\n";
    assert!(read(other).not_acted_on().is_empty());
}

/// An identity among a rule's signers (signed without a kept key): its issuer, its subject,
/// its authority's certificates and its log's key, each checked for its shape when the
/// Cluster is applied; and what is neither a key nor an identity refused.
#[test]
fn keyless_identities_in_image_rules_are_checked_when_a_cluster_is_applied() {
    let cluster = |images: &str| {
        let text =
            format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec:\n  images: {images}\n");
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    let p256 = format!("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE{}==", "A".repeat(86));
    let cert = "\"-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\\n\"";
    let identity = |issuer: &str, subject: &str, authority: &str, log: &str| {
        format!(
            "[{{ prefix: ghcr.io, signedBy: [{{ issuer: \"{issuer}\", subject: \"{subject}\", authority: {authority}, log: {log} }}] }}]"
        )
    };
    let issuer = "https://token.actions.githubusercontent.com";
    let subject = "https://github.com/acme/tool/.github/workflows/release.yml@refs/heads/main";
    let good = identity(issuer, subject, &format!("[{cert}]"), &p256);
    cluster(&good).unwrap_or_else(|e| panic!("{good}: {e}"));
    // A key and an identity, side by side.
    let both = good.replace("signedBy: [", &format!("signedBy: [{p256}, "));
    cluster(&both).unwrap_or_else(|e| panic!("{both}: {e}"));
    for (bad, why) in [
        (
            identity("", subject, &format!("[{cert}]"), &p256),
            "names its issuer and its subject",
        ),
        (
            identity(issuer, "", &format!("[{cert}]"), &p256),
            "names its issuer and its subject",
        ),
        (identity(issuer, subject, "[]", &p256), "1 to 4 PEM certificates"),
        (
            identity(issuer, subject, &format!("[{}]", [cert; 5].join(", ")), &p256),
            "1 to 4 PEM certificates",
        ),
        (
            identity(issuer, subject, "[cosign.pub]", &p256),
            "1 to 4 PEM certificates",
        ),
        (
            identity(issuer, subject, &format!("[{cert}]"), "rekor.pub"),
            "log is not an ECDSA P-256 public key",
        ),
        // (An identity with a field it does not know, or without one, is neither.)
        (good.replace("log:", "logs:"), "signedBy"),
        (
            "[{ prefix: ghcr.io, signedBy: [{ issuer: x, subject: y }] }]".to_string(),
            "signedBy",
        ),
    ] {
        let said = cluster(&bad).err().unwrap_or_default();
        assert!(said.contains(why), "{bad}: expected `{why}`, got `{said}`");
    }
}

/// The Cluster's rules for whose signatures images are taken by: a prefix that is a registry
/// or a registry and a path, keys of the shape a template's are, and no more than 32 rules.
#[test]
fn image_rules_are_checked_when_a_cluster_is_applied() {
    let cluster = |images: &str| {
        let text =
            format!("apiVersion: kith.dev/v1\nkind: Cluster\nmetadata: {{ name: home }}\nspec:\n  images: {images}\n");
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    let p256 = format!("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE{}==", "A".repeat(86));
    let ed = format!("MCowBQYDK2VwAyEA{}=", "A".repeat(43));
    let rule = |prefix: &str| format!("{{ prefix: \"{prefix}\", signedBy: [{ed}] }}");
    for good in [
        "[]".to_string(),
        format!("[{}]", rule("")),
        format!("[{{ signedBy: [{p256}, {ed}] }}]"),
        format!(
            "[{}, {}, {}]",
            rule("ghcr.io"),
            rule("ghcr.io/acme"),
            rule("ghcr.io/acme/tools")
        ),
        format!("[{}, {}]", rule("registry.example:5000/team"), rule("localhost:5000")),
    ] {
        cluster(&good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    let many: Vec<String> = (0..33).map(|n| rule(&format!("r{n}.example"))).collect();
    for (bad, why) in [
        ("[{ prefix: ghcr.io, signedBy: [] }]".to_string(), "names no key"),
        ("[{ prefix: ghcr.io }]".to_string(), "signedBy"),
        (
            "[{ prefix: ghcr.io, signedBy: [cosign.pub] }]".to_string(),
            "is not a public key kith can check",
        ),
        (
            format!("[{{ prefix: ghcr.io, signedBy: [{}] }}]", [ed.as_str(); 17].join(", ")),
            "at most 16 keys",
        ),
        (format!("[{}]", many.join(", ")), "at most 32 rules"),
        (format!("[{}, {}]", rule("ghcr.io/acme"), rule("ghcr.io/acme")), "twice"),
        // (A path alone is under no registry: `library/nginx` is `docker.io/library/nginx`.)
        (format!("[{}]", rule("library")), "starts with a registry"),
        (format!("[{}]", rule("acme/tools")), "starts with a registry"),
        (
            format!("[{}]", rule("ghcr.io/")),
            "is not a registry or a registry and a path",
        ),
        (
            format!("[{}]", rule("/ghcr.io")),
            "is not a registry or a registry and a path",
        ),
        (
            format!("[{}]", rule("ghcr.io//acme")),
            "is not a registry or a registry and a path",
        ),
        (
            format!("[{}]", rule("GHCR.io/acme")),
            "is not a registry or a registry and a path",
        ),
        (
            format!("[{}]", rule("ghcr.io/acme:1")),
            "is not a registry or a registry and a path",
        ),
        (
            format!("[{}]", rule("ghcr.io/acme@sha256")),
            "is not a registry or a registry and a path",
        ),
        (
            format!("[{}]", rule("ghcr.io/ac*")),
            "is not a registry or a registry and a path",
        ),
    ] {
        let refused = cluster(&bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
}

/// A container's user and what its filter lets through: said by the template, and checked
/// when it is applied.
#[test]
fn hardened_containers_say_who_they_are_and_what_they_call() {
    let job = |container: &str| {
        let text = format!(
            "apiVersion: kith.dev/v1\nkind: Job\nmetadata: {{ name: j }}\nspec:\n  template:\n    containers: [{{ name: c, image: i, {container} }}]\n"
        );
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    // (The shape of a key: what a P-256 and an Ed25519 public key file start with, and how long each is.)
    let p256 = format!("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE{}==", "A".repeat(86));
    let ed = format!("MCowBQYDK2VwAyEA{}=", "A".repeat(43));
    let pem = format!(
        "\"-----BEGIN PUBLIC KEY-----\\n{}\\n{}\\n-----END PUBLIC KEY-----\\n\"",
        &p256[..64],
        &p256[64..]
    );
    for good in [
        format!("signedBy: [{p256}, {ed}]"),
        format!("signedBy: [{pem}]"),
        "signedBy: []".to_string(),
    ] {
        job(&good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for (bad, why) in [
        (
            format!("signedBy: [{}]", &p256[..100]),
            "is not a public key kith can check",
        ),
        (
            "signedBy: [cosign.pub]".to_string(),
            "`cosign.pub` is not a public key kith can check",
        ),
        (
            format!("signedBy: [{}]", [ed.as_str(); 17].join(", ")),
            "at most 16 keys",
        ),
        (format!("signedBy: {ed}"), "expected a sequence"),
    ] {
        let refused = job(&bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
    for good in [
        "runAsUser: 0",
        "runAsUser: 1000",
        "seccomp: { unconfined: true }",
        "seccomp: { allow: [unshare, clone, clone3] }",
        "seccomp: {}",
    ] {
        job(good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for (bad, why) in [
        ("runAsUser: 4294967295", "is no user"),
        ("runAsUser: -1", "expected u32"),
        ("runAsUser: nobody", "expected u32"),
        (
            "seccomp: { allow: [read] }",
            "`read` is not a call the filter refuses (it refuses: mount, umount2,",
        ),
        (
            "seccomp: { allow: [Mount] }",
            "`Mount` is not a call the filter refuses",
        ),
        ("seccomp: unconfined", "expected struct Seccomp"),
        ("seccomp: { deny: [read] }", "deny"),
    ] {
        let refused = job(bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
}

/// What a pod of Kubernetes has that a 1.0 template had not: containers that run first,
/// ConfigMaps and Secrets as files, a directory of the replica's own, every key of a map
/// as a variable, something of the replica itself as one, capabilities dropped, and not
/// root. Each is checked when applied, and a path never climbs out of what is mounted.
#[test]
fn a_template_says_what_a_pod_says() {
    let job = |template: &str, container: &str| {
        let text = format!(
            "apiVersion: kith.dev/v1\nkind: Job\nmetadata: {{ name: j }}\nspec:\n  template:\n    {template}\n    containers: [{{ name: c, image: i, {container} }}]\n"
        );
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map_err(|e| e.msg)
    };
    let mount = |mount: &str| job("restartPolicy: never", &format!("volumeMounts: [{{ {mount} }}]"));
    for good in [
        "volume: data, path: /data",
        "volume: data, path: /data, readOnly: true",
        "configMap: site, path: /etc/site",
        "configMap: site, path: /etc/site, items: { index: conf.d/index.html }, mode: 0440",
        "secret: tls, path: /etc/tls/key.pem, subPath: tls.key, mode: 400",
        "scratch: cache, path: /cache",
        "scratch: cache, path: /cache, memory: true",
        "volume: data, path: /var/lib/postgresql/data, subPath: pg/15",
        "scratch: cache, path: /cache, subPath: a",
    ] {
        mount(good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for (bad, why) in [
        (
            "path: /data",
            "set exactly one of `volume`, `configMap`, `secret`, `scratch`",
        ),
        ("volume: a, secret: b, path: /data", "set exactly one of"),
        (
            "volume: data, path: /d, items: { a: b }",
            "`items` and `mode` are a `configMap`'s or a `secret`'s",
        ),
        ("scratch: s, path: /d, mode: 0400", "`items` and `mode` are"),
        ("volume: data, path: /d, memory: true", "`memory` is a `scratch`'s"),
        (
            "configMap: c, path: /d, items: { a: ../b }",
            "items: `../b` is not a path inside it",
        ),
        (
            "configMap: c, path: /d, items: { a: /etc/passwd }",
            "items: `/etc/passwd` is not a path inside it",
        ),
        ("configMap: c, path: /d, items: { a: 'b/' }", "is not a path inside it"),
        (
            "secret: s, path: /d, subPath: a/../../b",
            "subPath: `a/../../b` is not a path inside it",
        ),
        (
            "secret: v, path: /d, subPath: ''",
            "subPath: `` is not a path inside it",
        ),
        (
            "configMap: c, path: /d, items: { a: ..data }",
            "items: `..data` is not a path inside it",
        ),
        (
            "volume: v, path: /d, subPath: pg/../../etc",
            "subPath: `pg/../../etc` is not a path inside it",
        ),
        (
            "scratch: s, path: /d, subPath: /etc",
            "subPath: `/etc` is not a path inside it",
        ),
        (
            "secret: s, path: /d, items: { a: f, b: f }",
            "items: `f` is named twice",
        ),
        (
            "secret: s, path: /d, items: { a: f, b: f/g }",
            "items: `f` is named twice, or is a file with files under it",
        ),
        ("scratch: a/b, path: /d", "scratch: `a/b` is not a name"),
        ("scratch: .., path: /d", "scratch: `..` is not a name"),
        (
            "secret: s, path: /d, mode: 0888",
            "mode: `0888` is not a file's mode in octal",
        ),
        ("secret: s, path: /d, mode: 04000", "is not a file's mode in octal"),
        ("secret: s, path: /d, mode: rw", "is not a file's mode in octal"),
    ] {
        let refused = mount(bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
        assert!(refused.contains("container `c`, mount at `/d"), "{bad}: {refused}");
    }

    for good in [
        "envFrom: [{ configMap: site }, { secret: keys, prefix: KEY_ }]",
        "env: [{ name: ME, field: name }, { name: AT, field: address }, { name: ON, field: node }, { name: NS, field: namespace }]",
        "dropCapabilities: [all]",
        "dropCapabilities: [NET_RAW, MKNOD]",
        "runAsNonRoot: true",
        "runAsNonRoot: true, runAsUser: 1000",
    ] {
        job("restartPolicy: never", good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for (bad, why) in [
        (
            "envFrom: [{ prefix: A_ }]",
            "envFrom: set exactly one of `configMap`, `secret`",
        ),
        ("envFrom: [{ configMap: a, secret: b }]", "envFrom: set exactly one of"),
        ("env: [{ name: ME, field: uid }]", "unknown variant `uid`"),
        (
            "env: [{ name: ME, field: name, value: x }]",
            "set exactly one of `value`, `secret`, `configMap`, `field`",
        ),
        (
            "dropCapabilities: [NET_RWA]",
            "`NET_RWA` is not a capability: `all`, or one of CHOWN,",
        ),
        ("dropCapabilities: [ALL]", "`ALL` is not a capability"),
        ("dropCapabilities: [CAP_NET_RAW]", "`CAP_NET_RAW` is not a capability"),
        (
            "runAsNonRoot: true, runAsUser: 0",
            "runAsNonRoot, and runAsUser: 0 is root",
        ),
    ] {
        let refused = job("restartPolicy: never", bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }

    // Containers that run first: each a container as any other, checked as one.
    let first = "initContainers: [{ name: first, image: i, volumeMounts: [{ scratch: s, path: /s }] }]";
    let read = job(first, "volumeMounts: [{ scratch: s, path: /s }]").unwrap();
    assert_eq!(read[0].spec["template"]["initContainers"][0]["name"], "first");
    for (bad, why) in [
        ("initContainers: [{ name: c, image: i }]", "two units are named `c`"),
        (
            "initContainers: [{ name: first, image: i, readiness: { tcp: { port: 1 } } }]",
            "container `first`: an init container runs to its end, and has no probes",
        ),
        (
            "initContainers: [{ name: first, image: i, volumeMounts: [{ secret: s, path: /d, subPath: .. }] }]",
            "container `first`, mount at `/d`: subPath: `..` is not a path inside it",
        ),
        (
            "initContainers: [{ name: first, image: i, dropCapabilities: [x] }]",
            "container `first`: dropCapabilities",
        ),
    ] {
        let refused = job(bad, "command: [a]").unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
    let alone = "apiVersion: kith.dev/v1\nkind: Job\nmetadata: { name: j }\nspec:\n  template:\n    initContainers: [{ name: first, image: i }]\n    exec: [{ name: e, command: [a] }]\n";
    let refused = Resource::from_source(alone).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
    assert!(
        refused
            .unwrap_err()
            .msg
            .contains("initContainers run before `containers`, and there are none")
    );

    // A 1.0 file reads as it did, and is written back as it was: nothing new in it.
    let old = job("restartPolicy: never", "volumeMounts: [{ volume: data, path: /data }]").unwrap();
    let container = &old[0].spec["template"]["containers"][0];
    assert_eq!(
        container["volumeMounts"],
        serde_json::json!([{ "volume": "data", "path": "/data" }])
    );
    assert_eq!(container.as_object().unwrap().len(), 3);
}

/// `encrypted: true` on a Volume and `confidential: true` on a template: what each needs,
/// and what neither can be yet.
#[test]
fn an_encrypted_volume_and_a_confidential_template_are_checked() {
    let read = |text: String| {
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map(drop).map_err(|e| e.msg)
    };
    let volume = |spec: &str| {
        read(format!(
            "apiVersion: kith.dev/v1\nkind: Volume\nmetadata: {{ name: vault }}\nspec: {spec}\n"
        ))
    };
    volume("{ node: a, path: data, size: 1Gi, encrypted: true }").unwrap();
    volume("{ node: a, path: data, size: 8Mi, encrypted: true }").unwrap();
    volume("{ node: a, path: data, encrypted: false, shared: true }").unwrap();
    for (bad, why) in [
        ("{ node: a, path: data, encrypted: true }", "needs a `size`"),
        ("{ node: a, path: data, size: 4Mi, encrypted: true }", "at least 8Mi"),
        (
            "{ node: a, path: data, size: 1Gi, encrypted: true, shared: true }",
            "cannot be encrypted yet",
        ),
        (
            "{ node: a, path: data, size: 1Gi, encrypted: true, replicas: 2 }",
            "cannot be encrypted yet",
        ),
    ] {
        let refused = volume(bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }

    let job = |template: &str| {
        read(format!(
            "apiVersion: kith.dev/v1\nkind: Job\nmetadata: {{ name: sealed }}\nspec:\n  template: {template}\n"
        ))
    };
    let vm = "{ name: vm, firmware: /usr/share/ovmf/OVMF.fd, disks: [{ path: /var/d.raw }], memory: 1Gi }";
    job(&format!("{{ confidential: true, vms: [{vm}] }}")).unwrap();
    for (bad, why) in [
        (format!("{{ confidential: true, vms: [{vm}], containers: [{{ name: c, image: i }}] }}"), "only `vms`"),
        (format!("{{ confidential: true, vms: [{vm}], exec: [{{ name: e, command: [/bin/true] }}] }}"), "only `vms`"),
        ("{ confidential: true, vms: [{ name: vm, kernel: /k, memory: 1Gi }] }".to_string(), "needs a `firmware`"),
        (
            "{ confidential: true, vms: [{ name: vm, firmware: /f, disks: [{ path: /d }], hypervisor: cloudHypervisor, memory: 1Gi }] }".to_string(),
            "QEMU as its hypervisor",
        ),
    ] {
        let refused = job(&bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
}

/// `resources.storage` on a container: how much its pod may write outside its Volumes, a
/// whole number of bytes, checked when applied. An exec unit and a VM have no root of their
/// own to count, and are refused one.
#[test]
fn storage_limit_is_bytes_a_container_may_write() {
    let job = |template: &str| {
        let text =
            format!("apiVersion: kith.dev/v1\nkind: Job\nmetadata: {{ name: j }}\nspec:\n  template: {template}\n");
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map_err(|e| e.msg)
    };
    let read = job("{ containers: [{ name: c, image: i, resources: { storage: 1Gi } }] }").unwrap();
    assert_eq!(
        read[0].spec["template"]["containers"][0]["resources"],
        json!({ "storage": "1Gi" })
    );
    for good in [
        "{ containers: [{ name: c, image: i, resources: { storage: 500M, memory: 1Gi } }] }",
        "{ initContainers: [{ name: f, image: i, resources: { storage: 1Gi } }], containers: [{ name: c, image: i }] }",
    ] {
        job(good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for (bad, why) in [
        (
            "{ containers: [{ name: c, image: i, resources: { storage: 500m } }] }",
            "container `c`: resources.storage: `500m` is not a whole number of bytes",
        ),
        (
            "{ containers: [{ name: c, image: i, resources: { storage: 0 } }] }",
            "`0` is not a whole number of bytes from 1 to 2^53 - 1",
        ),
        (
            "{ containers: [{ name: c, image: i, resources: { storage: 9007199254740992 } }] }",
            "from 1 to 2^53 - 1",
        ),
        // (Less than the directories kithd makes a pod's containers would hold by themselves.)
        (
            "{ containers: [{ name: c, image: i, resources: { storage: 4Ki } }] }",
            "container `c`: resources.storage: `4Ki` is less than 64Ki",
        ),
        (
            "{ containers: [{ name: c, image: i, resources: { storage: lots } }] }",
            "invalid quantity `lots`",
        ),
        (
            "{ exec: [{ name: e, command: [a], resources: { storage: 1Gi } }] }",
            "exec `e`: resources.storage: an exec unit has no root of its own to count",
        ),
        (
            "{ vms: [{ name: v, kernel: /k, memory: 1Gi, resources: { storage: 1Gi } }] }",
            "vm `v`: resources.storage: a VM writes to its disks, not to a root of its own",
        ),
    ] {
        let refused = job(bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
    // Resources is shared with what a node keeps back, a namespace's quota and a seat's
    // reserve: none of them reads storage, so none takes it.
    let read = |kind: &str, spec: &str| {
        let text = format!("apiVersion: kith.dev/v1\nkind: {kind}\nmetadata: {{ name: n }}\nspec: {spec}\n");
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map_err(|e| e.msg)
    };
    for (kind, spec, field) in [
        ("Node", "{ reserved: { storage: 1Gi } }", "reserved"),
        ("Namespace", "{ quota: { storage: 1Gi } }", "quota"),
        ("Seat", "{ node: a, reserve: { storage: 1Gi } }", "reserve"),
    ] {
        let refused = read(kind, spec).unwrap_err();
        assert!(
            refused.contains(&format!("{field}.storage: is not read here")),
            "{kind}: {refused}"
        );
        let without = spec.replace("storage", "memory");
        read(kind, &without).unwrap_or_else(|e| panic!("{kind} {without}: {e}"));
    }
}

/// An Exit names its node, its Secret and the namespaces that may use it; a pod leaves by
/// one only as a Workload's pod of containers, and only a pod publishes a port, from 1024.
/// A build that knows no `exit` refuses a template that names one (unknown fields are
/// errors), so no older node runs such a pod with the node's own way out.
#[test]
fn an_exit_and_a_published_port_are_checked() {
    let read = |kind: &str, spec: &str| {
        let text = format!("apiVersion: kith.dev/v1\nkind: {kind}\nmetadata: {{ name: n }}\nspec: {spec}\n");
        let read = Resource::from_source(&text).and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>());
        read.map_err(|e| e.msg)
    };
    let exit = "{ node: n1, secret: vpn, namespaces: [media], dns: [10.2.0.1] }";
    read("Exit", exit).unwrap();
    assert!(!kind("Exit").unwrap().namespaced);
    for (bad, why) in [
        ("{ node: n1, secret: vpn, namespaces: [] }", "namespaces: at least one"),
        (
            "{ node: n1, secret: vpn, namespaces: [Media] }",
            "namespaces: invalid name",
        ),
        (
            "{ node: n1, secret: vpn, namespaces: [m], dns: [fd00::1] }",
            "dns: `fd00::1` is not an IPv4",
        ),
        ("{ node: n1, namespaces: [m] }", "secret"),
        (
            "{ node: n1, secret: vpn, namespaces: [m], key: x }",
            "unknown field `key`",
        ),
    ] {
        let refused = read("Exit", bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
    let template = |extra: &str, ports: &str| {
        format!("{{ template: {{ {extra} containers: [{{ name: c, image: i, ports: [{ports}] }}] }} }}")
    };
    read(
        "Workload",
        &template("pod: true, exit: vpn,", "{ port: 8080, publish: true }"),
    )
    .unwrap();
    let both = "{ port: 6881, publish: true }, { port: 6881, protocol: udp, publish: true }";
    read("Workload", &template("pod: true,", both)).unwrap();
    read("NodeWorkload", &template("pod: true,", "{ port: 8080, publish: true }")).unwrap();
    for (kind, bad, why) in [
        ("Workload", template("exit: vpn,", ""), "exit: only a `pod`"),
        ("Workload", template("pod: true, exit: Vpn,", ""), "exit: invalid name"),
        (
            "Workload",
            "{ template: { pod: true, exit: vpn, exec: [{ name: e, command: [x] }] } }".into(),
            "exit: only containers",
        ),
        (
            "NodeWorkload",
            template("pod: true, exit: vpn,", ""),
            "a NodeWorkload cannot leave by an Exit",
        ),
        (
            "Job",
            template("pod: true, exit: vpn,", ""),
            "only a Workload leaves by an Exit",
        ),
        (
            "Workload",
            template("", "{ port: 8080, publish: true }"),
            "publish: only a `pod`",
        ),
        (
            "Workload",
            template("pod: true,", "{ port: 80, publish: true }"),
            "only ports from 1024",
        ),
        (
            "Workload",
            template("pod: true,", "{ port: 7443, publish: true }"),
            "port 7443 is kithd's own (its API",
        ),
        (
            "Workload",
            template("pod: true,", "{ port: 51820, protocol: udp, publish: true }"),
            "port 51820 is kithd's own (its mesh",
        ),
        (
            "Workload",
            template("pod: true,", "{ port: 5000, publish: true }"),
            "port 5000 is kithd's own (its registry",
        ),
        (
            "Workload",
            template(
                "pod: true,",
                "{ port: 8080, publish: true }, { port: 8080, publish: true }",
            ),
            "published twice",
        ),
        (
            "Workload",
            template(
                "pod: true,",
                &(8080..8089)
                    .map(|port| format!("{{ port: {port}, publish: true }}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            "at most 8 ports",
        ),
        (
            "Workload",
            template("pod: true, exitt: vpn,", ""),
            "unknown field `exitt`",
        ),
    ] {
        let refused = read(kind, &bad).unwrap_err();
        assert!(refused.contains(why), "{kind} {bad}: {refused}");
    }
}

/// An AccessLevel says what its peers reach: ranges, Services, a resolver, and the internet by
/// this home's own connection or by one Exit, not both. Documentation addresses only.
#[test]
fn an_access_level_is_checked() {
    let read = |spec: &str| {
        let text = format!("apiVersion: kith.dev/v1\nkind: AccessLevel\nmetadata: {{ name: family }}\nspec: {spec}\n");
        Resource::from_source(&text)
            .and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>())
            .map_err(|e| e.msg)
    };
    assert!(!kind("AccessLevel").unwrap().namespaced);
    for ok in [
        "{ networks: [192.0.2.0/24, 198.51.100.0/24], services: ['*'], api: true, dns: 192.0.2.53, internet: true }",
        "{ networks: [192.0.2.0/24, 'fd00::/8'], services: [media/films, home/photos], dns: 'fd00::53', exit: nl-1 }",
        "{ services: [media/films], dns: 192.0.2.53, internet: true }",
        "{ dns: 192.0.2.53, exit: nl-1, internet: false }",
        "{}",
    ] {
        read(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for (bad, why) in [
        ("{ networks: [192.0.2.0] }", "networks: `192.0.2.0` is not a range"),
        (
            "{ networks: [192.0.2.0/33] }",
            "networks: `192.0.2.0/33` is not a range",
        ),
        (
            "{ networks: [example.org/24] }",
            "networks: `example.org/24` is not a range",
        ),
        (
            "{ networks: ['192.0.2.5/24'] }",
            "networks: `192.0.2.5/24` is not a range",
        ),
        ("{ networks: ['fd00::1/8'] }", "networks: `fd00::1/8` is not a range"),
        (
            "{ networks: ['0.0.0.0/0'] }",
            "networks: `0.0.0.0/0` is the whole internet",
        ),
        ("{ networks: ['::/0'] }", "networks: `::/0` is the whole internet"),
        (
            "{ services: [Media/films] }",
            "services: `Media/films` is not namespace/name",
        ),
        ("{ services: [films] }", "services: `films` is not namespace/name"),
        ("{ services: ['media/*'] }", "services: `media/*` is not namespace/name"),
        ("{ dns: example.org }", "dns: `example.org` is not an IP address"),
        ("{ dns: '192.0.2.0/24' }", "dns: `192.0.2.0/24` is not an IP address"),
        (
            "{ dns: 192.0.2.53, internet: true, exit: nl-1 }",
            "internet and exit: not both",
        ),
        ("{ internet: true }", "internet: needs `dns`"),
        ("{ exit: nl-1 }", "exit: needs `dns`"),
        ("{ dns: 192.0.2.53, exit: Nl-1 }", "exit: invalid name"),
        ("{ dns: 192.0.2.53, internet: true, extra: 1 }", "unknown field `extra`"),
    ] {
        let refused = read(bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
}

/// A RemotePeer names its node, its level and its WireGuard public key: 32 bytes in base64,
/// 44 characters with one `=` at the end whose last data character has no bits set past the
/// 256th. Its private key is never given to kith.
#[test]
fn a_remote_peer_is_checked() {
    let read = |spec: &str| {
        let text = format!("apiVersion: kith.dev/v1\nkind: RemotePeer\nmetadata: {{ name: phone-1 }}\nspec: {spec}\n");
        Resource::from_source(&text)
            .and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>())
            .map_err(|e| e.msg)
    };
    assert!(!kind("RemotePeer").unwrap().namespaced);
    let zeros = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let peer = |key: &str| format!("{{ node: n1, level: family, publicKey: '{key}' }}");
    for key in [zeros, "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="] {
        read(&peer(key)).unwrap_or_else(|e| panic!("{key}: {e}"));
    }
    let stars = format!("{}*=", "A".repeat(42));
    let bits = format!("{}B=", "A".repeat(42));
    for (bad, why) in [
        (
            "{ node: N1, level: family, publicKey: 'AAAA' }".to_string(),
            "node: invalid name",
        ),
        (
            "{ node: n1, level: Family, publicKey: 'AAAA' }".to_string(),
            "level: invalid name",
        ),
        ("{ node: n1, level: family }".to_string(), "publicKey"),
        (peer(&"A".repeat(43)), "not 32 bytes of base64"),
        (peer(&format!("{}=", "A".repeat(44))), "not 32 bytes of base64"),
        (peer(&"A".repeat(44)), "not 32 bytes of base64"),
        (peer(&format!("{}==", "A".repeat(42))), "not 32 bytes of base64"),
        (peer(&stars), "a character that is not in base64"),
        (peer(&bits), "a bit set past the 32nd byte"),
        (
            "{ node: n1, level: family, publicKey: 'AAAA', key: x }".to_string(),
            "unknown field `key`",
        ),
    ] {
        let refused = read(&bad).unwrap_err();
        assert!(refused.contains(why), "{bad}: {refused}");
    }
}

/// An Identity says which Workloads may run as it (`workloads`: a namespace, and maybe
/// names), and a Workload which Identity it runs as (`identity`): both names are checked,
/// and an Identity bound to a key of its own runs as no Workload.
#[test]
fn an_identity_names_the_workloads_that_run_as_it() {
    let read = |text: String| {
        Resource::from_source(&text)
            .and_then(|docs| docs.into_iter().collect::<Result<Vec<_>, _>>())
            .map_err(|e| e.msg)
    };
    let identity = |spec: &str| {
        read(format!(
            "apiVersion: kith.dev/v1\nkind: Identity\nmetadata: {{ name: gateway }}\nspec: {spec}\n"
        ))
    };
    let read_back = identity("{ workloads: [{ namespace: edge }, { namespace: web, names: [proxy, api] }] }").unwrap();
    let spec = &read_back[0].spec;
    assert_eq!(spec["workloads"][1]["names"][1], "api", "{spec}");
    for bad in [
        "{ workloads: [{ namespace: Edge }] }",
        "{ workloads: [{ namespace: web, names: ['a b'] }] }",
    ] {
        assert!(identity(bad).unwrap_err().contains("invalid name"), "{bad}");
    }
    let keyed = identity("{ publicKey: abc, workloads: [{ namespace: edge }] }").unwrap_err();
    assert!(keyed.contains("workloads") && keyed.contains("publicKey"), "{keyed}");

    let workload = |identity: &str| {
        read(format!(
            "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: {{ name: proxy, namespace: web }}\n\
             spec: {{ identity: {identity}, template: {{ containers: [{{ name: c, image: i }}] }} }}\n"
        ))
    };
    assert_eq!(workload("gateway").unwrap()[0].spec["identity"], "gateway");
    assert!(workload("'Gate way'").unwrap_err().contains("identity"));
    assert!(workload("gate.way").unwrap_err().contains("no `.`"));
    // Only containers are given the certificate: a template with anything else is refused.
    let exec = read(
        "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: proxy }\n\
         spec: { identity: gateway, template: { exec: [{ name: e, command: [sh] }] } }\n"
            .into(),
    );
    assert!(exec.unwrap_err().contains("only containers"));
}
