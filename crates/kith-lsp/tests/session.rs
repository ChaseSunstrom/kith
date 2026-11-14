//! kith-lsp as an editor has it: started, written to and read from.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// Something wrong, as it is told: its line, from where to where on it, and what.
type Wrong = (u64, u64, u64, String);

struct Session {
    server: Child,
    to: ChildStdin,
    from: BufReader<ChildStdout>,
    id: u64,
}

impl Session {
    fn start() -> Session {
        let piped = [Stdio::piped(), Stdio::piped()];
        let [stdin, stdout] = piped;
        let mut server = Command::new(env!("CARGO_BIN_EXE_kith-lsp"))
            .stdin(stdin)
            .stdout(stdout)
            .spawn()
            .expect("kith-lsp starts");
        let (to, from) = (
            server.stdin.take().expect("stdin"),
            BufReader::new(server.stdout.take().expect("stdout")),
        );
        Session {
            server,
            to,
            from,
            id: 0,
        }
    }

    fn write(&mut self, body: &str) {
        write!(self.to, "Content-Length: {}\r\n\r\n{body}", body.len()).expect("written");
        self.to.flush().expect("sent");
    }

    fn read(&mut self) -> Value {
        let mut length = 0;
        loop {
            let mut line = String::new();
            assert!(
                self.from.read_line(&mut line).expect("a header") > 0,
                "kith-lsp said no more"
            );
            match line.trim_end().split_once(": ") {
                Some(("Content-Length", value)) => length = value.parse().expect("a length"),
                _ if line.trim_end().is_empty() => break,
                _ => panic!("not a header: {line}"),
            }
        }
        let mut body = vec![0; length];
        self.from.read_exact(&mut body).expect("a body");
        serde_json::from_slice(&body).expect("JSON")
    }

    fn tell(&mut self, method: &str, params: Value) {
        self.write(&json!({ "jsonrpc": "2.0", "method": method, "params": params }).to_string());
    }

    fn ask(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        self.write(&json!({ "jsonrpc": "2.0", "id": self.id, "method": method, "params": params }).to_string());
        let answer = self.read();
        assert_eq!(answer["id"], self.id, "{answer}");
        answer
    }

    /// What is wrong, as it is told after a change: by file, each as (line, from, to, message).
    fn wrong(&mut self, files: usize) -> Vec<(String, Vec<Wrong>)> {
        let mut told = Vec::new();
        for _ in 0..files {
            let message = self.read();
            assert_eq!(message["method"], "textDocument/publishDiagnostics", "{message}");
            let list = message["params"]["diagnostics"].as_array().expect("a list").iter();
            let list = list.map(|one| {
                let (start, end) = (&one["range"]["start"], &one["range"]["end"]);
                assert_eq!(
                    (&one["severity"], &one["source"], &start["line"]),
                    (&json!(1), &json!("kith"), &end["line"])
                );
                let number = |value: &Value| value.as_u64().expect("a number");
                (
                    number(&start["line"]),
                    number(&start["character"]),
                    number(&end["character"]),
                    one["message"].as_str().expect("text").to_string(),
                )
            });
            let name = message["params"]["uri"]
                .as_str()
                .expect("a name")
                .rsplit('/')
                .next()
                .expect("a file")
                .to_string();
            told.push((name, list.collect()));
        }
        told
    }
}

/// The place of `mark` in `text`, as an editor says it, and the text without it.
fn pointed(text: &str, uri: &str) -> (String, Value) {
    let at = text.find('|').expect("a mark");
    let line = text[..at].matches('\n').count();
    let character = text[..at].rsplit('\n').next().expect("a line").encode_utf16().count();
    let position = json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": character } });
    (text.replacen('|', "", 1), position)
}

#[test]
fn a_session() {
    let dir = std::env::temp_dir().join(format!("kith lsp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    std::fs::write(dir.join("lib.kith"), "fn web(name) = Workload { metadata: { name }, spec: { template: { containers: [{ name, image: \"busybox\" }] } } };\n{ web }\n").expect("written");
    // (A space in the directory's name: the editor writes it %20, and so does kith-lsp.)
    let uri = |name: &str| format!("file://{}/{name}", dir.display().to_string().replace(' ', "%20"));
    let app = uri("app.kith");
    let mut session = Session::start();

    let hello = session.ask(
        "initialize",
        json!({ "processId": null, "rootUri": null, "capabilities": {} }),
    );
    let able = &hello["result"]["capabilities"];
    assert_eq!(
        (&able["textDocumentSync"], &able["hoverProvider"]),
        (&json!(1), &json!(true)),
        "{hello}"
    );
    assert!(able["completionProvider"].is_object(), "{hello}");
    session.tell("initialized", json!({}));

    // What is wrong, under the word that said it (the editor counts 𝄞 as two).
    let text = "let lib = import \"./lib.kith\";\n[\n  lib.web(\"a\"),\n  Workload { metadata: { name: \"𝄞\" }, spec: { replicas: many, template: { containers: [{ name: \"c\", image: \"busybox\" }] } } },\n]\n";
    session.tell(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": app, "languageId": "kith", "version": 1, "text": text } }),
    );
    let told = session.wrong(1);
    assert_eq!(told[0].0, "app.kith");
    let [(line, from, to, message)] = &told[0].1[..] else {
        panic!("{told:?}")
    };
    assert_eq!((*line, *from, *to), (3, 57, 61), "{told:?}");
    assert_eq!(message, "nothing here is named `many`");

    // What the editor has is what is read, and a mistake is told of with the file it is in.
    let change = |uri: &str, text: &str| json!({ "textDocument": { "uri": uri, "version": 2 }, "contentChanges": [{ "text": text }] });
    session.tell(
        "textDocument/didChange",
        change(&app, &text.replace("many", "\"many\"")),
    );
    let told = session.wrong(1);
    assert!(
        told[0].1[0]
            .3
            .starts_with("Workload.spec.replicas: invalid type: string \"many\""),
        "{told:?}"
    );
    assert_eq!(told[0].1[0].0, 3);
    session.tell("textDocument/didChange", change(&app, &text.replace("many", "2")));
    let told = session.wrong(1);
    assert!(
        told[0].1[0].3.starts_with("Workload.metadata.name: invalid name"),
        "{told:?}"
    );
    let fine = text.replace("many", "2").replace('𝄞', "b");
    session.tell("textDocument/didChange", change(&app, &fine));
    assert_eq!(session.wrong(1), [("app.kith".to_string(), vec![])]);

    // The file it imports, opened and broken: said of that file, and taken back when mended.
    let lib = std::fs::read_to_string(dir.join("lib.kith")).expect("read");
    session.tell(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri("lib.kith"), "text": lib.replace("{ name }", "{ name: }") } }),
    );
    let told = session.wrong(2);
    assert_eq!(told[0], ("app.kith".to_string(), vec![]));
    assert_eq!(
        told[1],
        (
            "lib.kith".to_string(),
            vec![(0, 44, 45, "expected a value, not `}`".to_string())]
        )
    );
    session.tell("textDocument/didChange", change(&uri("lib.kith"), &lib));
    assert_eq!(
        session.wrong(2),
        [("app.kith".to_string(), vec![]), ("lib.kith".to_string(), vec![])]
    );
    session.tell(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": uri("lib.kith") } }),
    );
    assert_eq!(session.wrong(1), [("app.kith".to_string(), vec![])]);

    // Fields are offered from the kind's schema, down through records and lists.
    let labels = |session: &mut Session, text: &str| -> Vec<(String, String)> {
        let (text, position) = pointed(text, &app);
        session.tell("textDocument/didChange", change(&app, &text));
        // (Half-typed text is wrong somewhere; what is said of it is not this test's.)
        session.read();
        let answer = session.ask("textDocument/completion", position);
        let items = answer["result"].as_array().expect("a list").iter();
        items
            .map(|item| {
                (
                    item["label"].as_str().expect("a label").to_string(),
                    item["detail"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    };
    let has = |found: &[(String, String)], label: &str| found.iter().any(|(name, _)| name == label);
    let found = labels(&mut session, "Workload { | }");
    assert!(
        has(&found, "metadata") && has(&found, "spec") && !has(&found, "kind") && !has(&found, "len"),
        "{found:?}"
    );
    let found = labels(&mut session, "Workload { metadata: { name: \"a\" }, spec: { rep| } }");
    assert!(
        found.contains(&("replicas".to_string(), "integer".to_string())),
        "{found:?}"
    );
    assert!(
        found.contains(&("template".to_string(), "Template".to_string())),
        "{found:?}"
    );
    let found = labels(
        &mut session,
        "[Workload { spec: { template: { containers: [{ name: \"a\" }, { im| }] } } }]",
    );
    assert!(
        has(&found, "image") && has(&found, "ports") && !has(&found, "replicas"),
        "{found:?}"
    );
    let found = labels(
        &mut session,
        "Workload { spec: { template: { containers: [for c in cs: { name: c, pullPolicy: | }] } } }",
    );
    assert!(
        has(&found, "\"always\"") && has(&found, "len") && has(&found, "if"),
        "{found:?}"
    );
    // (Letters of more than one byte in a string before the place.)
    let found = labels(
        &mut session,
        "Workload { metadata: { name: \"café ☕\" }, spec: { | } }",
    );
    assert!(has(&found, "replicas"), "{found:?}");
    // Anywhere else: the language's words, the builtins, the kinds and the file's own names.
    let found = labels(&mut session, "let app = \"web\";\nfn port(n) = { port: n };\n|");
    for label in ["let", "import", "len", "merge", "Workload", "Service", "app", "port"] {
        assert!(has(&found, label), "{label}: {found:?}");
    }
    assert!(
        found
            .iter()
            .any(|(name, detail)| name == "len" && detail.starts_with("len(x)")),
        "{found:?}"
    );
    // In a record nothing is known of (a function's own), no guesses.
    assert_eq!(labels(&mut session, "fn port(n) = { | };\n{}"), []);

    // Pointing at a field, a builtin, a kind; and at nothing.
    let said = |session: &mut Session, text: &str| -> Value {
        let (text, position) = pointed(text, &app);
        session.tell("textDocument/didChange", change(&app, &text));
        session.read();
        session.ask("textDocument/hover", position)["result"]["contents"]["value"].clone()
    };
    let text = said(
        &mut session,
        "Workload { metadata: { name: \"a\" }, spec: { rep|licas: len([1]) } }",
    );
    assert_eq!(text, "Workload.spec.replicas: integer\n\nDefaults to 1.");
    let text = said(
        &mut session,
        "Workload { metadata: { name: \"a\" }, spec: { replicas: le|n([1]) } }",
    );
    assert!(text.as_str().is_some_and(|text| text.starts_with("len(x)")), "{text}");
    let text = said(&mut session, "Work|load { metadata: { name: \"a\" } }");
    assert!(
        text.as_str().is_some_and(|text| text.starts_with("Workload: ")),
        "{text}"
    );
    assert_eq!(
        said(&mut session, "Workload { metadata: { name: \"a\" } |}"),
        Value::Null
    );

    // A package's template has the names a template has, and the package's own values.
    let package = dir.join("pkg");
    std::fs::create_dir_all(package.join("templates")).expect("a directory");
    std::fs::write(package.join("package.yaml"), "name: pkg\nversion: 1.0.0\n").expect("written");
    std::fs::write(package.join("values.yaml"), "replicas: 2\n").expect("written");
    let template = uri("pkg/templates/web.kith");
    let text = "Workload { metadata: { name, labels }, spec: { replicas: values.replicas, template: { containers: [{ name: release.name, image: \"busybox:${package.version}\" }] } } }\n";
    session.tell(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": template, "text": text } }),
    );
    let of = |told: Vec<(String, Vec<Wrong>)>| {
        told.into_iter()
            .find(|(name, _)| name == "web.kith")
            .expect("told of it")
            .1
    };
    assert_eq!(of(session.wrong(2)), vec![]);
    session.tell(
        "textDocument/didChange",
        change(&template, &text.replace("values.replicas", "values.copies")),
    );
    let told = of(session.wrong(2));
    assert!(told.len() == 1 && told[0].3.contains("copies"), "{told:?}");
    session.tell("textDocument/didClose", json!({ "textDocument": { "uri": template } }));
    // (What was said of the closed file is taken back.)
    assert_eq!(of(session.wrong(2)), vec![]);

    // What is not the protocol is answered as the protocol says, and the session goes on.
    session.write("{ not json");
    assert_eq!(session.read()["error"]["code"], -32700);
    assert_eq!(
        session.ask("textDocument/definition", json!({}))["error"]["code"],
        -32601
    );
    session.tell("$/setTrace", json!({ "value": "off" }));
    session.tell(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": "untitled:Untitled-1", "text": "{" } }),
    );
    assert_eq!(
        session.ask(
            "textDocument/hover",
            json!({ "textDocument": { "uri": "untitled:Untitled-1" } })
        )["result"],
        Value::Null
    );
    assert_eq!(session.ask("shutdown", Value::Null)["result"], Value::Null);
    session.tell("exit", Value::Null);
    assert!(session.server.wait().expect("ended").success());
    std::fs::remove_dir_all(&dir).expect("removed");
}
