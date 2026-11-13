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
        "template, unit `web`, env `A`: set exactly one of `value`, `secret`, `configMap`"
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
    assert_eq!(KINDS.len(), 28);
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
    assert!(wrong("games.example.com", "kith.dev").contains("not kith.dev"));
    assert!(wrong("games.example.com", "games").contains("domain name"));
    assert!(wrong("version: v1", "version: one").contains("like v1 or v1beta1"));
    assert!(wrong("type: object", "oneOf: []").contains("`oneOf` is not a keyword kith checks"));
    assert!(wrong("path: spec.map", "path: 'spec..map'").contains("dotted path"));
}
