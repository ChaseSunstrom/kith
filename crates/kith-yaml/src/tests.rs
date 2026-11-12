use crate::*;
use serde::Deserialize;
use serde_json::{Value as Json, json};

fn err(src: &str) -> (usize, usize, String) {
    let e = parse(src)
        .and_then(|docs| docs.iter().try_for_each(|d| from_node::<Json>(d).map(drop)))
        .unwrap_err();
    let p = e.pos.expect("error has a position");
    (p.line, p.col, e.msg)
}

#[test]
fn plain_scalars_resolve_strictly() {
    let v: Json = from_str(
        "a: no\nb: on\nc: Yes\nd: 1.0\ne: 012\nf: 0x10\ng: true\nh: ~\ni:\nj: -3\nk: 1e3\nl: '1'\nm: \"true\"\nn: 18446744073709551615\no: True\np: .5\n",
    )
    .unwrap();
    assert_eq!(
        v,
        json!({"a": "no", "b": "on", "c": "Yes", "d": 1.0, "e": "012", "f": "0x10", "g": true, "h": null, "i": null,
               "j": -3, "k": 1000.0, "l": "1", "m": "true", "n": 18446744073709551615u64, "o": "True", "p": ".5"})
    );
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Typed {
    name: String,
    version: String,
    enabled: bool,
    count: Option<u32>,
    mode: Mode,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Mode {
    Rolling,
    Recreate,
    Custom { step: u8 },
}

#[test]
fn string_fields_keep_raw_text() {
    let t: Typed = from_str("name: no\nversion: 1.0\nenabled: true\nmode: rolling\ntags: [1, on, 0x1]\n").unwrap();
    assert_eq!(
        t,
        Typed {
            name: "no".into(),
            version: "1.0".into(),
            enabled: true,
            count: None,
            mode: Mode::Rolling,
            tags: vec!["1".into(), "on".into(), "0x1".into()]
        }
    );
    let t: Typed = from_str("name: a\nversion: v\nenabled: false\ncount: 3\nmode: { custom: { step: 2 } }\n").unwrap();
    assert_eq!((t.count, t.mode), (Some(3), Mode::Custom { step: 2 }));
}

fn typed_err(src: &str) -> (usize, usize, String) {
    let e = from_str::<Typed>(src).unwrap_err();
    let p = e.pos.expect("error has a position");
    (p.line, p.col, e.msg)
}

#[test]
fn typed_errors_point_at_the_offending_node() {
    let base = "name: a\nversion: v\nmode: rolling\n";
    // `no` is not a boolean, and a quoted number is not a number.
    let (l, c, m) = typed_err(&format!("{base}enabled: no\n"));
    assert_eq!((l, c), (4, 10), "{m}");
    assert!(m.contains("expected a boolean"), "{m}");
    let (l, c, m) = typed_err(&format!("{base}enabled: true\ncount: '3'\n"));
    assert_eq!((l, c), (5, 8), "{m}");
    // Unknown field: the key. Missing field: the map. Bad variant: the value.
    let (l, c, m) = typed_err(&format!("{base}enabled: true\n  \nreplicass: 1\n"));
    assert_eq!((l, c), (6, 1), "{m}");
    assert!(m.contains("unknown field `replicass`"), "{m}");
    let (l, c, m) = typed_err("name: a\nversion: v\nmode: rolling\n");
    assert_eq!((l, c), (1, 1), "{m}");
    assert!(m.contains("missing field `enabled`"), "{m}");
    let (l, c, m) = typed_err(&format!("{base}enabled: true\ntags:\n  - ok\n  - [nested]\n"));
    assert_eq!((l, c), (7, 5), "{m}");
    assert_eq!(typed_err("name: a\nversion: v\nenabled: true\nmode: sideways\n").0, 4);
    // A string field does not accept null.
    assert_eq!(typed_err("name:\nversion: v\nenabled: true\nmode: rolling\n").0, 1);
}

#[test]
fn strictness_errors() {
    let (l, c, m) = err("a: 1\nb: 2\na: 3\n");
    assert_eq!((l, c, m.as_str()), (3, 1, "duplicate key `a`"));
    assert_eq!(
        err("x:\n  k: {p: 1, q: 2, p: 3}\n"),
        (2, 19, "duplicate key `p`".into())
    );
    assert!(err("a: &x 1\nb: *x\n").2.contains("anchors"));
    assert!(err("a: 1\nb: *x\n").0 == 2);
    assert!(err("a: !!str 1\n").2.contains("tags"));
    assert!(err("? [a, b]\n: 1\n").2.contains("keys must be scalars"));
    let deep = "[".repeat(200) + &"]".repeat(200);
    assert!(err(&deep).2.contains("levels deep"));
}

#[test]
fn syntax_errors_have_positions() {
    assert_eq!(err("a: 1\nb: [1, 2\nc: 3\n").0, 3);
    assert_eq!(err("a:\n  b: 1\n c: 2\n").0, 3);
    // The scanner reports a tab where the scalar before it began; we point at the tab.
    assert_eq!(
        err("a: 1\n\tb: 2\n"),
        (2, 1, "while scanning a plain scalar, found a tab".into())
    );
    assert_eq!(err("a:\n  b: 1\n  \tc: 2\n").0, 3);
    assert!(err("a: 'unterminated\nb: 2\n").0 >= 1);
}

#[test]
fn documents_and_json() {
    let docs = parse("---\na: 1\n---\n---\n# only a comment\n---\n{\"b\": [true, null, \"x\"]}\n").unwrap();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[1].pos.line, 7);
    assert_eq!(from_node::<Json>(&docs[1]).unwrap(), json!({"b": [true, null, "x"]}));
    assert!(parse("").unwrap().is_empty());
    assert!(from_str::<Json>("a: 1\n---\nb: 2\n").is_err());
}

#[test]
fn render_shows_file_line_and_caret() {
    let src = "a: 1\nb:\n  c: 1\n  c: 2\n";
    let e = parse(src).unwrap_err();
    assert_eq!(
        e.render("x.yaml", src),
        "x.yaml:4:3: duplicate key `c`\n  |   c: 2\n  |   ^"
    );
    assert_eq!(e.to_string(), "line 4, column 3: duplicate key `c`");
}

#[test]
fn emit_is_readable() {
    let v = json!({
        "apiVersion": "kith.dev/v1",
        "metadata": {"name": "web", "labels": {}},
        "spec": {
            "image": "docker.io/library/nginx:1.27",
            "version": "1.0",
            "answer": "no",
            "ip": "10.0.0.1",
            "args": ["-c", "echo hi"],
            "ports": [{"name": "http", "port": 80}, {"name": "https", "port": 443}],
            "script": "#!/bin/sh\necho hi\n\nexit 0\n",
            "empty": [],
            "nothing": null
        }
    });
    let expected = "apiVersion: kith.dev/v1
metadata:
  name: web
  labels: {}
spec:
  image: docker.io/library/nginx:1.27
  version: \"1.0\"
  answer: \"no\"
  ip: 10.0.0.1
  args:
    - \"-c\"
    - echo hi
  ports:
    - name: http
      port: 80
    - name: https
      port: 443
  script: |
    #!/bin/sh
    echo hi

    exit 0
  empty: []
  nothing: null
";
    assert_eq!(to_string(&v), expected);
    assert_eq!(from_str::<Json>(expected).unwrap(), v);
}

/// Property: whatever we emit parses back to the same value.
#[test]
fn emit_round_trips_random_values() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }
    }
    const WORDS: &[&str] = &[
        "",
        " ",
        "a",
        "no",
        "Yes",
        "~",
        "null",
        "true",
        "1",
        "1.0",
        "-1",
        "0x1f",
        "1e3",
        "012",
        "1:30",
        "1.2.3",
        "a: b",
        "a #b",
        "#c",
        "- x",
        "-",
        "?",
        "x:",
        ":x",
        "é",
        "日本",
        "a\nb",
        "a\nb\n",
        "a\n\nb\n",
        "\n",
        "a\n\n",
        " lead\nx",
        "trail \nx",
        "tab\there",
        "\u{2028}x\ny",
        "{a}",
        "[a]",
        "a,b",
        "'q'",
        "\"dq\"",
        "back\\slash",
        "*star",
        "&amp",
        "!bang",
        "%pct",
        "@at",
        "a b",
        "http://x/y?z=1",
        "2Gi",
        "\r\n",
        "x\ry\n",
        "key with spaces",
        "\u{feff}bom\nx",
        "a\n b\n",
        "a\n\tb",
        "end:",
        "\u{85}nel\nx",
    ];
    fn value(rng: &mut Rng, depth: usize) -> Json {
        match rng.next(if depth > 3 { 6 } else { 9 }) {
            0 => Json::Null,
            1 => Json::Bool(rng.next(2) == 0),
            2 => json!(rng.next(1000) as i64 - 500),
            3 => json!(rng.next(1000) as f64 / 8.0),
            4 | 5 => json!(WORDS[rng.next(WORDS.len())]),
            6 | 7 => {
                let n = rng.next(4);
                Json::Object(
                    (0..n)
                        .map(|_| (WORDS[rng.next(WORDS.len())].to_string(), value(rng, depth + 1)))
                        .collect(),
                )
            }
            _ => {
                let n = rng.next(4);
                Json::Array((0..n).map(|_| value(rng, depth + 1)).collect())
            }
        }
    }
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..5000 {
        let v = value(&mut rng, 0);
        if v.is_null() {
            continue; // an empty document, skipped by parse()
        }
        let text = to_string(&v);
        let back: Json =
            from_str(&text).unwrap_or_else(|e| panic!("{e}\n--- emitted ---\n{text}\n--- from ---\n{v:?}"));
        assert_eq!(back, v, "emitted:\n{text}");
    }
}
