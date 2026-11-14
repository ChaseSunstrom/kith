//! kith's own language where YAML is taken: every example written both ways gives the
//! same resources, and `kith apply`, `lint`, `diff` and `eval` take a `.kith` file.

use std::path::{Path, PathBuf};
use std::process::Command;

use kith_api::Resource;

fn sandbox(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `kith` in `dir`; returns (exit code, stdout, stderr).
fn kith(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_kith"))
        .args(args)
        .current_dir(dir)
        .env("KITH_STORE", dir.join("store/store.json"))
        .env_remove("KITH_SOCKET")
        .output()
        .unwrap();
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
    (out.status.code().unwrap(), text(out.stdout), text(out.stderr))
}

fn resources(source: &str) -> serde_json::Value {
    let found: Vec<Resource> = Resource::from_source(source)
        .unwrap()
        .into_iter()
        .map(|resource| resource.map_err(|e| e.render("it", source)).unwrap())
        .collect();
    serde_json::to_value(found).unwrap()
}

#[test]
fn examples_written_both_ways_are_the_same_resources() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let dir = sandbox("lang-examples");
    let mut seen = 0;
    for entry in std::fs::read_dir(&examples).unwrap() {
        let yaml = entry.unwrap().path();
        if yaml.extension().is_none_or(|extension| extension != "yaml") {
            continue;
        }
        let twin = examples
            .join("kith")
            .join(yaml.with_extension("kith").file_name().unwrap());
        let (code, out, err) = kith(&dir, &["eval", twin.to_str().unwrap()]);
        assert_eq!(code, 0, "{}: {err}", twin.display());
        let said = std::fs::read_to_string(&yaml).unwrap();
        assert_eq!(resources(&out), resources(&said), "{}", twin.display());
        seen += 1;
    }
    assert!(seen >= 5, "examples/ has lost its YAML files");
}

const APP: &str = r#"let lib = import "./lib.kith";
[lib.web("web", 3), lib.web("api", REPLICAS)]
"#;

const LIB: &str = r#"fn web(name, replicas) = Workload {
    metadata: { name, labels: { app: name } },
    spec: {
        replicas,
        template: { containers: [{ name: "main", image: "example.org/${name}:1" }] },
    },
};
{ web }
"#;

#[test]
fn apply_lint_and_diff_take_a_kith_file() {
    let dir = sandbox("lang-apply");
    std::fs::write(dir.join("app.kith"), APP.replace("REPLICAS", "1")).unwrap();
    std::fs::write(dir.join("lib.kith"), LIB).unwrap();

    let (code, out, err) = kith(&dir, &["lint", "-f", "app.kith"]);
    assert_eq!((code, out.as_str()), (0, "2 resources ok\n"), "{err}");

    // (`kith diff` exits 1 when there is something to change.)
    let (code, out, err) = kith(&dir, &["diff", "-f", "app.kith"]);
    assert_eq!(code, 1, "{err}");
    assert!(
        out.contains("Workload/default/web") && out.contains("replicas: 3"),
        "{out}"
    );

    let (code, out, err) = kith(&dir, &["apply", "-f", "app.kith"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("Workload/default/web created") && out.contains("Workload/default/api created"),
        "{out}"
    );

    // A directory: its YAML and its `.kith` files, and a file that is only there to be
    // imported (it gives functions, not resources) is no mistake in it.
    std::fs::write(
        dir.join("more.yaml"),
        "apiVersion: kith.dev/v1\nkind: ConfigMap\nmetadata: { name: more }\nspec: { data: { a: b } }\n",
    )
    .unwrap();
    let (code, out, err) = kith(&dir, &["lint", "-f", "."]);
    assert_eq!((code, out.as_str()), (0, "3 resources ok\n"), "{err}");

    // What it gives, as YAML that `kith apply` takes as well.
    let (code, out, err) = kith(&dir, &["eval", "app.kith"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.starts_with("apiVersion: kith.dev/v1\nkind: Workload\n") && out.contains("\n---\n"),
        "{out}"
    );
    assert_eq!(resources(&out).as_array().map(Vec::len), Some(2));
}

#[test]
fn a_mistake_in_a_kith_file_is_refused_where_it_was_said() {
    let dir = sandbox("lang-wrong");
    // (The value comes from another file's call: the place is where the field is said.)
    std::fs::write(dir.join("app.kith"), APP.replace("REPLICAS", "\"one\"")).unwrap();
    std::fs::write(dir.join("lib.kith"), LIB).unwrap();
    let (code, out, err) = kith(&dir, &["lint", "-f", "app.kith"]);
    assert_eq!((code, out.as_str()), (2, ""), "{err}");
    assert!(
        err.contains("lib.kith:4:9: Workload.spec.replicas: invalid type: string \"one\""),
        "{err}"
    );

    // Asked for by its path, a place is said by that path.
    let (code, _, err) = kith(&dir, &["apply", "-f", "./app.kith"]);
    assert_eq!(code, 2);
    assert!(err.contains("./lib.kith:4:9: "), "{err}");

    // The file that is named may be a link (as a YAML file may); what it imports may not.
    std::os::unix::fs::symlink(dir.join("lib.kith"), dir.join("link.kith")).unwrap();
    std::fs::write(dir.join("named.kith"), "(import \"./lib.kith\").web(\"a\", 1)\n").unwrap();
    std::os::unix::fs::symlink(dir.join("named.kith"), dir.join("as.kith")).unwrap();
    assert_eq!(kith(&dir, &["lint", "-f", "as.kith"]).1, "1 resource ok\n");
    std::fs::write(dir.join("through.kith"), "(import \"./link.kith\").web(\"a\", 1)\n").unwrap();
    let (code, _, err) = kith(&dir, &["lint", "-f", "through.kith"]);
    assert!(code == 2 && err.contains("link.kith: is a link"), "{err}");

    // Nothing outside the directory of the file that was given is read.
    std::fs::write(dir.join("out.kith"), "import \"../lib.kith\"\n").unwrap();
    let (code, _, err) = kith(&dir, &["lint", "-f", "out.kith"]);
    assert_eq!(code, 2);
    assert!(err.contains("out.kith:1:"), "{err}");
}
