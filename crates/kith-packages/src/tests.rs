use super::*;

fn example() -> Package {
    Package::load(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages/web"))).unwrap()
}

const SHOP: Release<'static> = Release {
    name: "shop",
    namespace: "store",
};

#[test]
fn a_package_renders_to_resources() {
    let package = example();
    assert_eq!(
        (package.meta.name.as_str(), package.meta.version.as_str()),
        ("web", "0.1.0")
    );
    assert_eq!(package.lint(), Vec::<String>::new());

    // The defaults: a Workload, a Service and the page, named for the release, in its
    // namespace, labelled as its own.
    let rendered = package.render(SHOP, &[]).unwrap();
    let keys: Vec<String> = rendered.resources.iter().map(Resource::key).collect();
    assert_eq!(
        keys,
        [
            "Service/store/shop-web",
            "ConfigMap/store/shop-web-page",
            "Workload/store/shop-web"
        ]
    );
    let workload = &rendered.resources[2];
    assert_eq!(workload.metadata.labels[LABEL_RELEASE], "shop");
    assert_eq!(workload.metadata.labels[LABEL_PACKAGE], "web");
    assert_eq!(workload.metadata.labels["app"], "shop-web");
    assert_eq!(workload.spec["replicas"], 1);
    assert_eq!(
        workload.spec["template"]["containers"][0]["image"],
        "docker.io/library/nginx:1.27-alpine"
    );
    assert!(rendered.resources[0].spec.get("expose").is_none());
    assert!(rendered.notes.unwrap().contains("curl http://shop-web.store.kith/"));

    // Values in layers: the later one wins, key by key; what they turn off is not rendered.
    let layers = [
        json!({ "replicas": 3, "expose": { "host": "shop.example.org" }, "env": { "MODE": "a: b" } }),
        json!({ "replicas": 2, "page": "" }),
    ];
    let rendered = package.render(Release { name: "web", ..SHOP }, &layers).unwrap();
    let keys: Vec<String> = rendered.resources.iter().map(Resource::key).collect();
    assert_eq!(keys, ["Service/store/web", "Workload/store/web"]);
    assert_eq!(rendered.resources[0].spec["expose"]["host"], "shop.example.org");
    assert_eq!(rendered.resources[1].spec["replicas"], 2);
    let env = &rendered.resources[1].spec["template"]["containers"][0]["env"][0];
    assert_eq!(
        (env["name"].as_str(), env["value"].as_str()),
        (Some("MODE"), Some("a: b"))
    );
    assert!(rendered.notes.unwrap().contains("2 copies"));
}

#[test]
fn what_is_wrong_is_said_with_its_place() {
    let package = example();
    // Values the schema does not allow: all of them, by name.
    let wrong = package
        .render(SHOP, &[json!({ "replicas": "many", "port": 0, "colour": "red" })])
        .unwrap_err();
    assert!(
        wrong.contains("values.replicas: must be integer, not \"many\""),
        "{wrong}"
    );
    assert!(wrong.contains("values.port: it must be at least 1"), "{wrong}");
    assert!(
        wrong.contains("values.colour: is not a field the schema has"),
        "{wrong}"
    );

    let with = |path: &str, source: &str| {
        let mut package = example();
        package.schema = None;
        package.templates.insert(path.into(), source.into());
        package
    };
    // A template that does not parse, one that uses what is not there, one that asks for
    // a value, one that never ends: the file (and line) each time.
    let broken = with("templates/bad.yaml", "a: 1\n{% if %}\n")
        .render(SHOP, &[])
        .unwrap_err();
    assert!(broken.contains("templates/bad.yaml:2"), "{broken}");
    let missing = with("templates/bad.yaml", "a: 1\nb: {{ values.nothing.here }}\n")
        .render(SHOP, &[])
        .unwrap_err();
    assert!(missing.contains("templates/bad.yaml:2"), "{missing}");
    let asked = with(
        "templates/bad.yaml",
        "a: {{ required(values.expose.token | default(none), 'expose.token is needed') }}\n",
    );
    assert!(asked.render(SHOP, &[]).unwrap_err().contains("expose.token is needed"));
    let endless = with(
        "templates/bad.yaml",
        "{% for a in range(100000) %}{% for b in range(100000) %}{% endfor %}{% endfor %}",
    );
    assert!(endless.render(SHOP, &[]).unwrap_err().contains("fuel"));
    // What renders to something that is no resource: the rendered text's line.
    let odd = with(
        "templates/bad.yaml",
        "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: {{ name }}-x }\nspec: { replicas: lots }\n",
    );
    let odd = odd.render(SHOP, &[]).unwrap_err();
    assert!(odd.contains("templates/bad.yaml:4"), "{odd}");
    // The same resource twice.
    let twice = with("templates/again.yaml", "{% include 'templates/workload.yaml' %}")
        .render(SHOP, &[])
        .unwrap_err();
    assert!(twice.contains("Workload/store/shop-web is rendered twice"), "{twice}");
    // A template cannot read outside its package.
    let outside = with("templates/bad.yaml", "{% include '/etc/hostname' %}")
        .render(SHOP, &[])
        .unwrap_err();
    assert!(outside.contains("/etc/hostname"), "{outside}");

    // Lint: the version, the name, schema keywords that would be passed over.
    let mut package = example();
    package.meta.version = "one".into();
    package.meta.name = "Web Server".into();
    package.schema = Some(json!({ "type": "object", "properties": { "image": { "pattern": "^a" } } }));
    let lint = package.lint().join("\n");
    assert!(lint.contains("version `one` is not like 1.2.3"), "{lint}");
    assert!(lint.contains("invalid name `Web Server`"), "{lint}");
    assert!(
        lint.contains("values.schema.json.image: `pattern` is not a keyword kith checks"),
        "{lint}"
    );

    let no_meta = Package::from_files(BTreeMap::new()).unwrap_err();
    assert_eq!(no_meta, "no package.yaml");
    let files = BTreeMap::from([(
        "package.yaml".to_string(),
        "name: a\nversion: 1.0.0\nlicence: x\n".to_string(),
    )]);
    assert!(Package::from_files(files).unwrap_err().contains("package.yaml:3"));
}

#[test]
fn values_merge_and_toyaml() {
    let mut base = json!({ "a": { "b": 1, "c": [1, 2] }, "d": 1 });
    merge(&mut base, &json!({ "a": { "c": [3], "e": null }, "d": { "f": 1 } }));
    assert_eq!(base, json!({ "a": { "b": 1, "c": [3], "e": null }, "d": { "f": 1 } }));
    assert_eq!(full_name("shop", "web"), "shop-web");
    assert_eq!(full_name("my-web", "web"), "my-web");
    assert_eq!(full_name(&"a".repeat(62), "web").len(), 62);

    let files = BTreeMap::from([
        ("package.yaml".to_string(), "name: maps\nversion: 1.0.0\n".to_string()),
        ("values.yaml".to_string(), "data: { a: 'x: y', b: \"2\" }\n".to_string()),
        (
            "templates/map.yaml".to_string(),
            "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata:\n  name: {{ name }}\n  labels:\n    {{ labels | toYaml | indent(4) }}\nspec:\n  data:\n    {{ values.data | toYaml | indent(4) }}\n".to_string(),
        ),
    ]);
    let rendered = Package::from_files(files).unwrap().render(SHOP, &[]).unwrap();
    assert_eq!(rendered.resources[0].spec["data"], json!({ "a": "x: y", "b": "2" }));
    assert_eq!(rendered.notes, None);
}

#[test]
fn the_schema_check_by_keyword() {
    let said = |schema: Value, value: Value| {
        let mut wrong = Vec::new();
        check(&schema, &value, "v", &mut wrong);
        wrong
    };
    let fine = |schema: Value, value: Value| said(schema, value).is_empty();
    assert!(fine(json!({ "type": ["string", "null"] }), json!(null)));
    assert!(fine(json!({ "type": "number" }), json!(1.5)) && !fine(json!({ "type": "integer" }), json!(1.5)));
    assert!(fine(json!({ "type": "integer" }), json!(2.0)) && !fine(json!({ "type": "boolean" }), json!("true")));
    assert!(fine(json!({ "enum": ["a", 1] }), json!(1)) && !fine(json!({ "enum": ["a", 1] }), json!("b")));
    assert!(!fine(json!({ "maxLength": 2 }), json!("äöü")) && fine(json!({ "maxLength": 3 }), json!("äöü")));
    let list =
        json!({ "type": "array", "minItems": 1, "maxItems": 2, "items": { "type": "object", "required": ["port"] } });
    assert_eq!(
        said(list.clone(), json!([])),
        ["v: the number of items must be at least 1"]
    );
    assert_eq!(
        said(list.clone(), json!([{ "port": 1 }, {}])),
        ["v[1].port: is required"]
    );
    assert_eq!(said(list, json!([{}, {}, {}])).len(), 4);
    let open = json!({ "properties": { "a": { "type": "string" } }, "additionalProperties": { "type": "integer" } });
    assert_eq!(said(open, json!({ "a": 1, "b": "x", "c": 2 })).len(), 2);
    // A schema that is no object, or says nothing, allows everything.
    assert!(fine(json!(true), json!(1)) && fine(json!({}), json!({ "a": [1] })));
    let mut found = Vec::new();
    unknown_keywords(
        &json!({ "items": { "oneOf": [] }, "properties": { "a": { "format": "x" } } }),
        "s",
        &mut found,
    );
    assert_eq!(
        found,
        [
            "s[]: `oneOf` is not a keyword kith checks",
            "s.a: `format` is not a keyword kith checks"
        ]
    );
}

#[test]
fn a_package_stays_in_bounds() {
    // Names are names: nothing that could say more in the YAML they are written into.
    let package = example();
    for name in ["x\n  namespace: kith-system", "Shop", "", &"é".repeat(32)] {
        let wrong = package.render(Release { name, ..SHOP }, &[]).unwrap_err();
        assert!(wrong.starts_with("the release's name"), "{wrong}");
    }
    assert!(
        package
            .render(
                Release {
                    namespace: "a b",
                    ..SHOP
                },
                &[]
            )
            .is_err()
    );
    // A value that tries to be more than a value is still one.
    let image = "nginx\n  command: [sh]";
    let rendered = package.render(SHOP, &[json!({ "image": image })]).unwrap();
    let container = &rendered.resources[2].spec["template"]["containers"][0];
    assert!(container["image"] == image && container.get("command").is_none());

    // A template that writes without end; a package of too many files.
    let mut big = example();
    let line = format!("{{% for a in range(300000) %}}{}{{% endfor %}}", "a".repeat(100));
    big.templates.insert("templates/big.yaml".into(), line);
    assert!(big.render(SHOP, &[]).is_err());
    let files: BTreeMap<String, String> = (0..300)
        .map(|n| (format!("templates/{n}.yaml"), String::new()))
        .collect();
    assert!(Package::from_files(files).unwrap_err().contains("more than 200 files"));

    // A link in a package's directory is not followed.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/linked");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("templates")).unwrap();
    std::fs::write(dir.join("package.yaml"), "name: linked\nversion: 1.0.0\n").unwrap();
    std::os::unix::fs::symlink("/etc/hostname", dir.join("NOTES")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", dir.join("templates/host.yaml")).unwrap();
    let linked = Package::load(&dir).unwrap();
    assert!(linked.notes.is_none() && linked.templates.is_empty());

    let mut found = Vec::new();
    unknown_keywords(&json!({ "required": "image", "minimum": "1" }), "s", &mut found);
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn deep_values_do_not_end_the_process() {
    let with = |source: String| {
        let mut deep = example();
        deep.templates.insert("templates/deep.yaml".into(), source);
        deep.render(SHOP, &[])
    };
    // Nothing a loop could nest a value in itself with; nor is one written out by hand.
    let nest = "{% set ns = namespace(a=[]) %}{% for i in range(50000) %}{% set ns.a = [ns.a] %}{% endfor %}a: {{ ns.a | toYaml }}";
    assert!(with(nest.into()).unwrap_err().contains("namespace"));
    assert!(
        with(format!(
            "a: {{{{ {}{} | toYaml }}}}",
            "[".repeat(50000),
            "]".repeat(50000)
        ))
        .is_err()
    );
    assert!(with("{% macro m(a) %}{{ m([a]) }}{% endmacro %}a: {{ m([]) }}".into()).is_err());
}

#[test]
fn desktop_packages_lint_and_render() {
    let load = |name: &str| {
        let dir = format!("{}/../../packages/{name}", env!("CARGO_MANIFEST_DIR"));
        Package::load(Path::new(&dir)).unwrap()
    };
    let office = Release {
        name: "office",
        namespace: "desktop",
    };
    for name in ["hyprland", "gnome", "kiosk"] {
        let package = load(name);
        assert_eq!(package.lint(), Vec::<String>::new(), "{name}");
        // No seat named: it asks for `seat0`, and waits until there is one; an empty name is refused.
        assert_eq!(package.render(office, &[]).unwrap().resources[0].spec["seat"], "seat0");
        assert!(package.render(office, &[json!({ "seat": "" })]).is_err(), "{name}");
        let values = json!({ "seat": "office-pc-seat0", "env": { "LANG": "en_GB.UTF-8" } });
        let rendered = package.render(office, &[values]).unwrap();
        let keys: Vec<String> = rendered.resources.iter().map(Resource::key).collect();
        let full = format!("office-{name}");
        assert_eq!(
            keys,
            [
                format!("DeviceClaim/desktop/{full}"),
                format!("Workload/desktop/{full}")
            ]
        );
        assert_eq!(rendered.resources[0].spec["seat"], "office-pc-seat0");
        let template = &rendered.resources[1].spec["template"];
        assert_eq!(template["deviceClaims"][0], full.as_str());
        assert_eq!(template["containers"][0]["resources"]["memory"], "4Gi");
        assert!(rendered.notes.unwrap().contains("office-pc-seat0"));
    }
    let kiosk = load("kiosk").render(office, &[json!({ "seat": "s", "command": ["foot"] })]);
    assert_eq!(
        kiosk.unwrap().resources[1].spec["template"]["containers"][0]["command"][0],
        "foot"
    );
    let panel = load("kith-panel");
    assert_eq!(panel.lint(), Vec::<String>::new());
    let rendered = panel
        .render(office, &[json!({ "require": { "desk": "office" } })])
        .unwrap();
    assert_eq!(rendered.resources[0].spec["placement"]["require"]["desk"], "office");
}
