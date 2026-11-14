//! The language, from outside: files in, documents (or one message) out.

use serde_json::{Value, json};

/// Files by name, for `eval`.
fn files<'a>(files: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Result<String, String> + Sync + 'a {
    move |name| match files.iter().find(|(file, _)| *file == name) {
        Some((_, text)) => Ok(text.to_string()),
        None => Err("no such file".into()),
    }
}

/// What `app.kith` with this text gives, each document as JSON.
fn gives(src: &str) -> Result<Vec<Value>, String> {
    let output = kith_lang::eval("app.kith", &files(&[("app.kith", src)]), &[]).map_err(|e| e.to_string())?;
    Ok(output
        .docs
        .iter()
        .map(|doc| kith_yaml::from_node(doc).expect("a document is JSON"))
        .collect())
}

/// The one document a file gives.
fn one(src: &str) -> Value {
    match gives(src) {
        Ok(docs) if docs.len() == 1 => docs.into_iter().next().expect("one"),
        other => panic!("{src}\ngave {other:?}"),
    }
}

/// The message a file is refused with.
fn refused(src: &str) -> String {
    gives(src).expect_err(src)
}

#[test]
fn values_and_operators() {
    let out = one(r#"{
        sum: 1 + 2 * 3, text: "x" + "y", list: [1, 2] + [3], whole: 7 / 2, rest: 7 % 4, half: 1.5 * 2,
        logic: !true || 1 < 2 && "a" < "b", minus: -3 - -1, same: 1 == 1.0 && [1, { a: "b" }] == [1, { a: "b" }],
        other: 1 != 2, order: [1 <= 1, 2 >= 3, 2 > 1.5], brackets: (1 + 2) * 3, nothing: null,
    }"#);
    assert_eq!(
        out,
        json!({ "sum": 7, "text": "xy", "list": [1, 2, 3], "whole": 3, "rest": 3, "half": 3.0, "logic": true,
            "minus": -2, "same": true, "other": true, "order": [true, false, true], "brackets": 9 })
    );
    assert!(refused("{ a: 1 + \"x\" }").starts_with("app.kith:1:8: `+` does not take a number and a string"));
    assert!(refused("{ a: 1 / 0 }").contains("divided by 0"));
    assert!(refused("{ a: 9223372036854775807 + 1 }").contains("too large a number"));
    assert!(refused("{ a: if 1 then 2 else 3 }").contains("app.kith:1:9: expected true or false, not a number"));
}

#[test]
fn let_and_functions() {
    let out = one(r#"
        // A name for a value, and for a function; a function's last values may have defaults.
        let app = "web";
        fn port(number, name = "http") = { name, port: number };
        fn times(n) = |x| x * n;
        fn factorial(n) = if n < 2 then 1 else n * factorial(n - 1);
        fn area(w, h) = { let both = w * h; let twice = both * 2; twice / 2 };
        let triple = times(3);
        {
            app,
            ports: [port(80), port(9090, "metrics")],
            nine: triple(3),
            big: factorial(10),
            area: area(3, 4),
            none: (|| 1)(),
            called: map([1, 2], triple),
        }
    "#);
    assert_eq!(
        out,
        json!({ "app": "web", "ports": [{ "name": "http", "port": 80 }, { "name": "metrics", "port": 9090 }],
            "nine": 9, "big": 3628800, "area": 12, "none": 1, "called": [3, 6] })
    );
    assert!(refused("fn f(a) = a; { x: f() }").contains("app.kith:1:20: `f` is not given its `a`"));
    assert!(refused("fn f(a) = a; { x: f(1, 2) }").contains("`f` takes 1 values, not 2"));
    assert!(refused("{ x: y }").contains("app.kith:1:6: nothing here is named `y`"));
    assert!(refused("let x = 1; { x: x(2) }").contains("a number cannot be called"));
    assert!(refused("let if = 1; { }").contains("expected a name, not `if`"));
    assert!(refused("let x = 1;").contains("expected the value this gives"));
}

#[test]
fn records_and_lists() {
    let out = one(r#"
        let base = { a: 1, b: { c: 2 }, "quoted key": true };
        let key = "made";
        let xs = [1, 2, 3, 4];
        {
            over: { ..base, a: 5, d: 6 },
            under: { a: 5, ..base },
            computed: { [key + "-up"]: 1, "${key}": 2 },
            words: { let: 1, if: 2, fn: 3 },
            field: base.b.c + base["a"] + xs[3],
            quoted: base."quoted key",
            more: [0, ..xs, ..null, 5],
            even: [for x in xs if x % 2 == 0: x * 10],
            pairs: [for e in entries({ a: 1, b: 2 }): "${e.key}=${e.value}"],
            when: if len(xs) > 3 then "long" else "short",
            left_out: null,
            holes: [1, null, 2, if false then 3 else null],
            optional: { ..if true then { on: true } else null },
        }
    "#);
    assert_eq!(
        out,
        json!({ "over": { "a": 5, "b": { "c": 2 }, "quoted key": true, "d": 6 },
            "under": { "a": 1, "b": { "c": 2 }, "quoted key": true },
            "computed": { "made-up": 1, "made": 2 }, "words": { "let": 1, "if": 2, "fn": 3 },
            "field": 7, "quoted": true, "more": [0, 1, 2, 3, 4, 5], "even": [20, 40], "pairs": ["a=1", "b=2"],
            "when": "long", "holes": [1, 2], "optional": { "on": true } })
    );
    assert!(refused("{ a: 1, a: 2 }").contains("app.kith:1:9: `a` is given twice"));
    assert!(refused("{ a: [..1] }").contains("`..` in a list takes a list, not a number"));
    assert!(refused("{ a: [for x in { b: 1 }: x] }").contains("`for` goes through a list"));
    assert!(refused("{ a: { b: 1 }.c }").contains("app.kith:1:14: no field `c` (there is: b)"));
    assert!(refused("[1]").contains("a file gives a resource, a list of them or null"));
}

#[test]
fn strings() {
    let out = one(r#"
        let name = "web";
        {
            plain: "a \"b\" \\ \$ \n",
            put_in: "${name}-${1 + 1}-${true}-${"in" + "side"}",
            block: """
                server {
                  listen ${80 + 8000};
                }
                """,
        }
    "#);
    assert_eq!(
        out,
        json!({ "plain": "a \"b\" \\ $ \n", "put_in": "web-2-true-inside", "block": "server {\n  listen 8080;\n}\n" })
    );
    assert!(refused("{ a: \"${[1]}\" }").contains("a list is not text (json(x) writes any value out)"));
    assert!(refused("{ a: \"never").contains("app.kith:1:6: this string does not end"));
    assert!(refused("{ a: \"\\q\" }").contains("after `\\` comes"));
}

#[test]
fn defaults_for_what_is_not_there() {
    let out = one(r#"
        let values = { image: "nginx", limits: null };
        fn inner(r) = r.absent;
        {
            there: values.image ?? "busybox",
            absent: values.replicas ?? 2,
            null_too: values.limits ?? "none",
            deeper: values.limits.memory ?? "64Mi",
            past_the_end: [1][3] ?? 0,
            by_name: values["tag"] ?? "latest",
            chain: values.a ?? values.b ?? "c",
        }
    "#);
    assert_eq!(
        out,
        json!({ "there": "nginx", "absent": 2, "null_too": "none", "deeper": "64Mi", "past_the_end": 0, "by_name": "latest", "chain": "c" })
    );
    // What a function did not find inside itself is its mistake, not a default's to cover.
    assert!(refused("fn inner(r) = r.absent; { a: inner({}) ?? 1 }").contains("no field `absent`"));
    assert!(refused("{ a: 1.b ?? 2 }").contains("a number has no field `b`"));
    assert!(refused("{ a: {}.b ?? error(\"b is needed\") }").contains("app.kith:1:19: b is needed"));
}

#[test]
fn builtins() {
    let out = one(r#"{
        len: [len([1, 2]), len({ a: 1 }), len("héllo")],
        map: map([1, 2], |x| x + 1),
        filter: filter([1, 2, 3], |x| x != 2),
        range: [range(3), range(2, 5), range(0)],
        keys: keys({ b: 1, a: 2 }),
        sort: [sort(["b", "a", "B"]), sort([3, 1.5, -2]), sort([])],
        values: values({ b: 1, a: 2 }),
        record: record([{ key: "a", value: 1 }, { key: "b", value: [2] }]),
        has: [has({ a: 1 }, "a"), has({ a: 1 }, "b"), has([1, 2], 2), has("kith", "it"), has("kith", "x")],
        merge: merge({ a: { b: 1, c: 2 }, d: 1 }, { a: { c: 3 }, e: 4 }),
        join: join(["a", 1, true], "-"),
        split: split("a,b,c", ","),
        replace: replace("a.b.c", ".", "/"),
        string: string(42) + string(1.5),
        int: [int("42"), int(3.9), int(7)],
        json: json({ a: [1, "b", null], c: 1.5 }),
        yaml: yaml({ a: [1, "b"] }),
        b64: [b64(""), b64("a"), b64("ab"), b64("abc"), b64("kith!")],
    }"#);
    assert_eq!(
        out,
        json!({ "len": [2, 1, 5], "map": [2, 3], "filter": [1, 3], "range": [[0, 1, 2], [2, 3, 4], []],
            "keys": ["b", "a"], "sort": [["B", "a", "b"], [-2, 1.5, 3], []], "values": [1, 2], "record": { "a": 1, "b": [2] },
            "has": [true, false, true, true, false], "merge": { "a": { "b": 1, "c": 3 }, "d": 1, "e": 4 },
            "join": "a-1-true", "split": ["a", "b", "c"], "replace": "a/b/c", "string": "421.5", "int": [42, 3, 7],
            "json": "{\"a\":[1,\"b\"],\"c\":1.5}", "yaml": "a:\n  - 1\n  - b\n",
            "b64": ["", "YQ==", "YWI=", "YWJj", "a2l0aCE="] })
    );
    let said = refused("{ a: len(1) }");
    assert!(
        said.contains("app.kith:1:9: len is not given (a number): len(x): how many"),
        "{said}"
    );
    assert!(refused("{ a: int(\"x\") }").contains("\"x\" is not a whole number"));
    assert!(refused("{ a: json(|x| x) }").contains("a function cannot be written out"));
    // (Every one of them is told of in its usage line, which is what an editor shows.)
    assert!(
        kith_lang::BUILTINS
            .iter()
            .all(|(name, usage)| usage.starts_with(&format!("{name}(")))
    );
}

#[test]
fn imports_of_files_beside_it() {
    let lib = r#"
        fn web(name, replicas = 1) = { name, replicas, from: values.from };
        { web, port: 80 }
    "#;
    let tree = [
        (
            "app.kith",
            r#"let lib = import "./lib/web.kith"; [lib.web("a", 2), { port: (import "lib/web.kith").port }, import "./other.kith"]"#,
        ),
        ("lib/web.kith", lib),
        ("other.kith", r#"{ up: (import "./lib/up.kith").port }"#),
        ("lib/up.kith", r#"import "../lib/web.kith""#),
    ];
    let globals = [("values", json!({ "from": "outside" }))];
    let output = kith_lang::eval("app.kith", &files(&tree), &globals).expect("imports");
    let docs: Vec<Value> = output
        .docs
        .iter()
        .map(|doc| kith_yaml::from_node(doc).expect("JSON"))
        .collect();
    assert_eq!(
        docs,
        [
            json!({ "name": "a", "replicas": 2, "from": "outside" }),
            json!({ "port": 80 }),
            json!({ "up": 80 })
        ]
    );

    let refused = |tree: &[(&str, &str)]| {
        kith_lang::eval("app.kith", &files(tree), &[])
            .err()
            .expect("refused")
            .to_string()
    };
    let said = refused(&[
        ("app.kith", r#"import "./b.kith""#),
        ("b.kith", r#"{ a: import "./app.kith" }"#),
    ]);
    assert!(said.starts_with("b.kith:1:6: app.kith imports itself"), "{said}");
    for (path, why) in [
        ("../secret.kith", "is outside the directory the first file is in"),
        (
            "/etc/passwd.kith",
            "an import names a .kith file from the file it is in",
        ),
        ("./values.yaml", "an import names a .kith file"),
        ("./gone.kith", "gone.kith: no such file"),
    ] {
        let said = refused(&[("app.kith", &format!("import \"{path}\""))]);
        assert!(
            said.starts_with("app.kith:1:1: ") && said.contains(why),
            "{path}: {said}"
        );
    }
    // A mistake in an imported file is shown in that file.
    let said = refused(&[("app.kith", "import \"./b.kith\""), ("b.kith", "\n{ a: 1 +\n}")]);
    assert!(said.starts_with("b.kith:3:1: expected a value, not `}`"), "{said}");
}

#[cfg(unix)]
#[test]
fn imports_from_a_directory_follow_no_link() {
    let dir = std::env::temp_dir().join(format!("kith-lang-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("lib")).expect("a directory");
    std::fs::write(dir.join("app.kith"), "import \"./lib/a.kith\"").expect("write");
    std::fs::write(dir.join("lib/a.kith"), "{ a: 1 }").expect("write");
    std::fs::write(dir.join("real.kith"), "{ b: 2 }").expect("write");
    std::os::unix::fs::symlink(dir.join("real.kith"), dir.join("lib/link.kith")).expect("a link");
    let read = kith_lang::dir(&dir);
    assert_eq!(kith_lang::eval("app.kith", &read, &[]).expect("read").docs.len(), 1);
    std::fs::write(dir.join("app.kith"), "import \"./lib/link.kith\"").expect("write");
    let said = kith_lang::eval("app.kith", &read, &[])
        .err()
        .expect("a link is refused")
        .to_string();
    assert!(said.contains("lib/link.kith: is a link"), "{said}");
    // What is not a file is not read: a pipe nobody writes to would be read for ever.
    let made = std::process::Command::new("mkfifo")
        .arg(dir.join("lib/pipe.kith"))
        .status();
    assert!(made.expect("mkfifo").success());
    std::fs::write(dir.join("app.kith"), "import \"./lib/pipe.kith\"").expect("write");
    let said = kith_lang::eval("app.kith", &read, &[])
        .err()
        .expect("a pipe is refused")
        .to_string();
    assert!(said.contains("lib/pipe.kith: is not a file"), "{said}");
    std::fs::remove_dir_all(&dir).expect("removed");
}

#[test]
fn limits_hold_what_never_ends() {
    // A function that calls itself for ever; a list with no end in sight; a string that doubles.
    assert!(refused("fn f(n) = f(n + 1); { a: f(0) }").contains("more than 3000 deep"));
    assert!(refused("{ a: [for x in range(100000000): x] }").contains("did not end in 500000 steps"));
    assert!(
        refused("fn f(n) = if n == 0 then 0 else f(n - 1) * 0; { a: [for x in range(100000): f(50)] }")
            .contains("did not end in")
    );
    assert!(
        refused("fn grow(s, n) = if n == 0 then s else grow(s + s, n - 1); { a: grow(\"x\", 60) }")
            .contains("did not end in")
    );
    // Little work, much to write: the same large string many times over.
    let said = refused(
        "fn grow(s, n) = if n == 0 then s else grow(s + s, n - 1); let big = grow(\"x\", 17); { a: [for x in range(20): big] }",
    );
    assert!(said.contains("gives more than 1048576 bytes"), "{said}");
    // Text that nests or runs on past what the parser will follow.
    assert!(refused(&format!("{{ a: {}1{} }}", "(".repeat(100), ")".repeat(100))).contains("nested more than 64 deep"));
    assert!(refused(&format!("{{ a: 1{} }}", " + 1".repeat(600))).contains("more than 500 in a row"));
    assert!(refused(&format!("{{ a: {}true }}", "!".repeat(600))).contains("more than 500 in a row"));
    assert!(refused(&format!("{{ a: x{} }}", ".y".repeat(600))).contains("more than 500 in a row"));
    let large = format!("{{ a: \"{}\" }}", "x".repeat(1 << 20));
    assert!(refused(&large).contains("more than 1048576 bytes"));
}

const WEB_YAML: &str = "
apiVersion: kith.dev/v1
kind: Workload
metadata: { name: web, labels: { app: web } }
spec:
  replicas: 3
  template:
    containers:
      - name: web
        image: docker.io/library/nginx:1.27-alpine
        ports: [{ name: http, port: 80 }]
        env: [{ name: MODE, value: production }]
---
apiVersion: kith.dev/v1
kind: Service
metadata: { name: web }
spec:
  selector: { app: web }
  ports: [{ port: 80, targetPort: http }]
";

const WEB_KITH: &str = r#"
let app = "web";
fn container(image, port, env = {}) = {
    name: app,
    image,
    ports: [{ name: "http", port }],
    env: [for e in entries(env): { name: e.key, value: e.value }],
};
[
    Workload {
        metadata: { name: app, labels: { app } },
        spec: {
            replicas: values.replicas,
            template: { containers: [container("docker.io/library/nginx:1.27-alpine", 80, { MODE: "production" })] },
        },
    },
    Service { metadata: { name: app }, spec: { selector: { app }, ports: [{ port: 80, targetPort: "http" }] } },
]
"#;

/// The resources `app.kith` gives, or all that is wrong with them.
fn resources(src: &str, values: Value) -> Result<Vec<Value>, String> {
    let found = kith_lang::resources("app.kith", &files(&[("app.kith", src)]), &[("values", values)])
        .map_err(|wrong| wrong.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"))?;
    Ok(found
        .iter()
        .map(|resource| serde_json::to_value(resource).expect("JSON"))
        .collect())
}

#[test]
fn typed_the_same_resources_as_yaml() {
    let yaml: Vec<Value> = kith_api::Resource::from_source(WEB_YAML)
        .expect("YAML")
        .into_iter()
        .map(|resource| serde_json::to_value(resource.expect("valid")).expect("JSON"))
        .collect();
    assert_eq!(resources(WEB_KITH, json!({ "replicas": 3 })).expect("valid"), yaml);
}

#[test]
fn typed_a_wrong_field_is_refused_where_it_was_said() {
    // A value of the wrong type, said in the file: the place of the value, and its path.
    let said = resources(
        &WEB_KITH.replace("port: 80,", "port: \"80\","),
        json!({ "replicas": 3 }),
    )
    .expect_err("refused");
    assert!(
        said.starts_with("app.kith:17:83: Service.spec.ports[0].port: invalid type: string \"80\""),
        "{said}"
    );
    // One handed in from outside: the place it was put into the resource.
    let said = resources(WEB_KITH, json!({ "replicas": "three" })).expect_err("refused");
    assert!(
        said.starts_with("app.kith:13:29: Workload.spec.replicas: invalid type: string \"three\""),
        "{said}"
    );
    assert!(
        said.contains("\n  |             replicas: values.replicas,\n  |                             ^"),
        "{said}"
    );
    // A field the kind does not have, made inside a function: the field's own name.
    let said = resources(
        &WEB_KITH.replace("    image,", "    imagee: image,"),
        json!({ "replicas": 3 }),
    )
    .expect_err("refused");
    assert!(
        said.starts_with("app.kith:5:5: Workload.spec.template.containers[0].imagee: unknown field `imagee`"),
        "{said}"
    );
    // What the kind's own check refuses, and a kind there is none of; both are said.
    let said = resources(
        "[Workload { metadata: { name: \"Not A Name\" } }, Wrkload { metadata: { name: \"x\" } }]",
        json!({}),
    )
    .expect_err("refused");
    assert!(
        said.contains("app.kith:1:31: Workload.metadata.name: invalid name `Not A Name`"),
        "{said}"
    );
    assert!(
        said.contains("app.kith:1:49: unknown kind `Wrkload` (`kith schema` lists the kinds)"),
        "{said}"
    );
    assert!(
        resources("Workload { kind: \"Job\" }", json!({}))
            .expect_err("refused")
            .contains("`Workload {` says the kind already")
    );
    // A kind the cluster defines is a record that says its own apiVersion.
    let custom = resources(
        "Tunnel { apiVersion: \"example.com/v1\", metadata: { name: \"a\" }, spec: { to: \"b\" } }",
        json!({}),
    );
    assert_eq!(custom.expect("valid")[0]["apiVersion"], "example.com/v1");
}

#[test]
fn check_takes_a_file_made_to_be_imported() {
    let check = |src: &str| kith_lang::check("app.kith", &files(&[("app.kith", src)]), &[]);
    assert!(check("fn web(name) = Workload { metadata: { name } }; { web, port: 80 }").is_empty());
    assert!(check("|x| x").is_empty());
    let wrong = check(
        "[Workload { metadata: { name: \"a\" }, spec: { replicas: \"x\" } }, Service { metadata: { name: 1.5 } }]",
    );
    let at: Vec<_> = wrong.iter().map(|e| e.at.clone().expect("a place")).collect();
    assert_eq!(at[0], ("app.kith".to_string(), 1, 56));
    assert!(
        wrong[0].msg.starts_with("Workload.spec.replicas: invalid type"),
        "{}",
        wrong[0]
    );
    assert_eq!(wrong.len(), 2, "{wrong:?}");
    assert_eq!(check("{ a: }")[0].at, Some(("app.kith".to_string(), 1, 6)));
    // A resource with its `kind` misspelt is a mistake, not a file made to be imported.
    assert_eq!(
        check("{ apiVersion: \"kith.dev/v1\", kidn: \"ConfigMap\", metadata: { name: \"a\" } }").len(),
        1
    );
}

/// kithd evaluates a stranger's package, and a panic there ends kithd: nothing a file
/// says may be one.
#[test]
fn limits_hold_what_would_stop_the_program() {
    // After `\`, a letter of more than one byte: the place said is that letter's.
    assert!(
        refused("{ a: \"\\é\" }").contains("app.kith:1:8: after `\\` comes"),
        "{}",
        refused("{ a: \"\\é\" }")
    );
    assert!(refused("{ a: \"é\\𝄞\" }").contains("app.kith:1:9: after `\\` comes"));
    // A number that is none is refused where it was worked out, so nothing ever sorts one.
    for none in ["0.0 / 0.0", "1.5 % 0.0", "1 / 0.0", "sort([3, 0.0 / 0.0, 1])"] {
        let said = refused(&format!("{{ a: {none} }}"));
        assert!(
            said.contains("divided by 0") || said.contains("too large a number"),
            "{none}: {said}"
        );
    }
    let grown = refused("fn grow(x, n) = if n == 0 then x else grow(x * 1000000.0, n - 1); { a: grow(1.0, 60) }");
    assert!(grown.contains("too large a number"), "{grown}");
    // Whole numbers too large to be told apart as fractions, among fractions: one order all the same.
    let large = "9007199254740993, 0.5, 9007199254740992, 9007199254740994, -1";
    let sorted = one(&format!("{{ a: sort([{}]) }}", [large; 8].join(", ")));
    assert_eq!(sorted["a"].as_array().map(Vec::len), Some(40));
    assert_eq!(sorted["a"][0], -1);
    assert_eq!(
        one("{ a: sort([3, 9007199254740993, 9007199254740992]) }")["a"][2],
        9007199254740993i64
    );
}

#[test]
fn limits_hold_what_is_small_to_write_and_large_to_do() {
    let begun = std::time::Instant::now();
    let twice = "fn g(x, n) = if n == 0 then x else g([x, x], n - 1);";
    let big = "let big = join(map(range(60000), |x| \"aaaaaaaa\"), \"\");";
    let names: String = (0..60000).map(|n| format!("let a{n} = 1;")).collect();
    let nested = format!("let a = [1];{}", "let a = [a];".repeat(60000));
    let wide: Vec<String> = (0..30000).map(|n| format!("k{n}: 1")).collect();
    let steps = "did not end in 500000 steps";
    for (src, said) in [
        // A value that holds itself twice at every level is 2^40 parts to compare or to look through.
        (format!("{twice} {{ a: g(1, 40) == g(1, 40) }}"), steps),
        (format!("{twice} {{ a: has([g(1, 40)], g(1, 40)) }}"), steps),
        ("fn g(x, n) = if n == 0 then x else g({ a: x, b: x }, n - 1); { a: merge(g(1, 30), g(1, 30)) }".to_string(), steps),
        // A value nested deeper than there is stack to follow it: let go of, written, compared.
        (format!("{nested} {{ b: 1 }}"), ""),
        (format!("{nested} {{ a }}"), "more than 3000 deep"),
        (format!("{nested} {{ a: a == a }}"), "more than 3000 deep"),
        (format!("{nested} {{ a: json(a) }}"), "more than 3000 deep"),
        ("fn f(n) = map([n], |x| f(x + 1))[0]; { a: f(0) }".to_string(), "more than 3000 deep"),
        // Much to go through for each step: many names, many fields, long strings.
        (format!("{names} {{ a: [for x in range(100000): a0] }}"), steps),
        // (A builtin's name is looked for through every one of them, and found in none.)
        (format!("{names} {{ a: [for x in range(100000): len(\"\")] }}"), steps),
        (format!("{{ {} }}", wide.join(", ")), steps),
        ("let r = record(map(range(4000), |n| { key: \"k${n}\", value: n })); { a: [for x in range(100000): r.k3999] }".to_string(), steps),
        ("let xs = range(100000); { a: len([..xs, ..xs, ..xs, ..xs, ..xs, ..xs]) }".to_string(), steps),
        (format!("{big} {{ a: len(join(map(range(1000), |x| big), \"\")) }}"), steps),
        (format!("{big} {{ a: len(replace(big, \"a\", big)) }}"), steps),
        (format!("{big} {{ a: len(split(big + big + big, \"a\")) }}"), steps),
        (format!("{big} {{ a: [for x in range(100000): len(big)] }}"), steps),
        (format!("{big} {{ a: len(sort([for x in range(10000): big])) }}"), steps),
        (format!("{big} let other = big + \"b\"; {{ a: [for x in range(100000): big < other || big == other] }}"), steps),
        (format!("{big} {{ a: len(\"{}\") }}", "${big}".repeat(100)), steps),
    ] {
        match gives(&src) {
            Ok(_) => assert_eq!(said, "", "{}", &src[..src.len().min(200)]),
            Err(why) => assert!(!said.is_empty() && why.contains(said), "{}: {}", &src[..src.len().min(200)], &why[..why.len().min(300)]),
        }
    }
    // What is in reach: five hundred resources from one function, a record of a thousand fields.
    let many = "fn web(n) = Workload { metadata: { name: \"web-${n}\" }, spec: { template: { containers: [{ name: \"c\", image: \"busybox\" }] } } }; [for n in range(500): web(n)]";
    assert_eq!(gives(many).expect("in reach").len(), 500);
    assert!(gives(&format!("{{ {} }}", wide[..1000].join(", "))).is_ok());
    assert!(
        begun.elapsed() < std::time::Duration::from_secs(30),
        "{:?}",
        begun.elapsed()
    );
}

/// A file taken apart at random is refused or gives something: it never stops the
/// program (a panic is said as "a bug in kith", and in kithd it would end kithd).
#[test]
fn limits_hold_a_file_taken_apart_at_random() {
    const MORE: &str = r#"
let t = """a ${"b" + string(1.5)} \$ é𝄞""";
fn f(x, y = [..[1, 2], x]) = { ..{ a: x }, "k${x}": y, n: -x % 3 };
{ a: [for i in range(3): if i > 0 then f(i) else null], b: sort(keys(f(1))), c: (|q| q ?? t)(null), d: len(json(f(2))), e: split(t, " ")[0] }
"#;
    let pieces = [
        "\"", "\\", "é", "𝄞", "${", "}", "{", "(", ")", "[", "]", "..", "|", "\"\"\"", ":", ",", ";", "0", ".", "-",
        "//", "\n", " ", "/", "%", "len", "sort", "values", "Workload", "if", "for", "in", "import", "null",
    ];
    gives(MORE).expect("whole, it is a file");
    // (An LCG: the same files every run.)
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = |below: usize| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (seed >> 33) as usize % below
    };
    for round in 0..3000 {
        let mut src: Vec<char> = [WEB_KITH, MORE][round % 2].chars().collect();
        for _ in 0..1 + next(4) {
            let at = next(src.len().max(1));
            match next(3) {
                0 if at < src.len() => drop(src.remove(at)),
                0 | 1 => src
                    .splice(at.min(src.len())..at.min(src.len()), pieces[next(pieces.len())].chars())
                    .for_each(drop),
                _ => src.truncate(at.max(1)),
            }
        }
        let src: String = src.into_iter().collect();
        if let Err(said) = resources(&src, json!({ "replicas": 2 })) {
            assert!(!said.contains("a bug in kith"), "{src}");
        }
    }
}
