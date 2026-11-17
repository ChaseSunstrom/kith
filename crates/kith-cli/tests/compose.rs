//! `kith import compose`: a docker-compose file as kith resources, and every key it
//! does not carry said by path.

use kith_api::Resource;
use kith_kube::{compose, documents};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURE: &str = include_str!("fixtures/media-stack.yml");

fn translate(doc: Value, namespace: Option<&str>) -> (Vec<Resource>, Vec<String>) {
    compose::translate(doc, namespace, Some("n1"))
}

fn fixture() -> Value {
    documents("media-stack.yml", FIXTURE).unwrap().remove(0)
}

fn spec<'a>(all: &'a [Resource], key: &str) -> &'a Value {
    // A resource with no namespace given is in `default`.
    let found = all.iter().find(|r| r.key().replacen("/default/", "/", 1) == key);
    &found
        .unwrap_or_else(|| panic!("no {key} in {:?}", all.iter().map(Resource::key).collect::<Vec<_>>()))
        .spec
}

fn said(report: &[String], at: &str, why: &str) {
    let found = report.iter().any(|line| line.contains(at) && line.contains(why));
    assert!(found, "no line with `{at}` and `{why}` in:\n{}", report.join("\n"));
}

#[test]
fn compose_fixture_is_a_pod_a_service_and_volumes() {
    let (all, _) = translate(fixture(), None);
    let mut keys: Vec<String> = all.iter().map(|r| r.key().replacen("/default/", "/", 1)).collect();
    keys.sort();
    let expect = "Service/gateway Service/indexer Service/films Service/media Service/mediaserver Service/requests \
        Service/shows Service/subtitles Service/vpn Volume/config-downloader Volume/config-films \
        Volume/config-indexer Volume/config-media Volume/config-requests Volume/config-shows \
        Volume/config-subtitles Volume/config-vpn Volume/downloads Volume/library Workload/films \
        Workload/indexer Workload/media Workload/requests Workload/shows Workload/subtitles Workload/vpn";
    let mut expect: Vec<&str> = expect.split_whitespace().collect();
    expect.sort_unstable();
    assert_eq!(keys, expect);

    // The downloader shares the VPN's network: one pod, two containers.
    let vpn = &spec(&all, "Workload/vpn")["template"];
    let names: Vec<&Value> = vpn["containers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| &c["name"])
        .collect();
    assert_eq!(names, ["vpn", "downloader"]);
    assert_eq!((&vpn["pod"], &vpn["restartPolicy"]), (&json!(true), &json!("always")));
    let [vpn_c, down_c] = &vpn["containers"].as_array().unwrap()[..] else {
        panic!()
    };
    assert_eq!(
        vpn_c["readiness"],
        json!({"http": {"path": "/ping", "port": 9696}, "intervalSeconds": 30, "timeoutSeconds": 5, "failureThreshold": 3})
    );
    assert_eq!(
        vpn_c["env"],
        json!([{"name": "TZ", "value": "Etc/UTC"}, {"name": "VPN_PROVIDER", "value": "example"}])
    );
    assert!(
        down_c["env"]
            .as_array()
            .unwrap()
            .contains(&json!({"name": "PUID", "value": "1000"}))
    );
    assert_eq!(
        vpn_c["volumeMounts"],
        json!([{"volume": "config-vpn", "path": "/config"}])
    );

    // A Service for the name and one for each alias, over the pod's container ports.
    let service = json!({"selector": {"app": "vpn"}, "ports": [{"port": 8080}, {"port": 9696}]});
    assert_eq!(spec(&all, "Service/vpn"), &service);
    assert_eq!(spec(&all, "Service/gateway"), &service);
    assert_eq!(spec(&all, "Service/mediaserver")["selector"], json!({"app": "media"}));
    assert_eq!(spec(&all, "Service/films")["ports"], json!([{"port": 7878}]));

    // A bind directory and a named volume are Volumes of the namespace; ro is carried.
    assert_eq!(
        spec(&all, "Volume/config-vpn"),
        &json!({"node": "n1", "path": "config/vpn"})
    );
    assert_eq!(spec(&all, "Volume/library"), &json!({"node": "n1", "path": "library"}));
    let shows = &spec(&all, "Workload/shows")["template"];
    let c = &shows["containers"][0];
    assert!(
        c["volumeMounts"]
            .as_array()
            .unwrap()
            .contains(&json!({"volume": "downloads", "path": "/downloads", "readOnly": true}))
    );
    assert_eq!(
        (&c["dropCapabilities"], &c["readOnlyRoot"], &c["pullPolicy"]),
        (&json!(["all"]), &json!(true), &json!("always"))
    );
    let films = &spec(&all, "Workload/films")["template"];
    let c = &films["containers"][0];
    assert_eq!(
        (&c["command"], &c["args"]),
        (&json!(["/init"]), &json!(["--data", "/config"]))
    );
    assert_eq!(
        (&c["workingDir"], &c["runAsUser"], &films["restartPolicy"]),
        (&json!("/config"), &json!(1000), &json!("onFailure"))
    );
    assert!(
        c["volumeMounts"]
            .as_array()
            .unwrap()
            .contains(&json!({"volume": "library", "path": "/library", "readOnly": true}))
    );
    assert_eq!(spec(&all, "Workload/media")["template"]["restartPolicy"], "never");
    // A test written as a line, `wget` this time, is an http probe as well.
    let c = &spec(&all, "Workload/requests")["template"]["containers"][0];
    assert_eq!(
        c["readiness"],
        json!({"http": {"path": "/api/status", "port": 5055}, "intervalSeconds": 60})
    );
}

#[test]
fn compose_refuses_by_path_what_kith_does_not_carry() {
    let (_, report) = translate(fixture(), None);
    for (at, why) in [
        ("services.vpn.cap_add[0]", "capabilit"),
        ("services.vpn.sysctls[0]", "kernel"),
        ("services.vpn.devices[0]", "DeviceClaim"),
        ("services.requests.privileged", "privilege"),
        ("services.requests.env_file", "environment"),
        ("services.vpn.ports[0]", "8080"),
        ("services.vpn.ports[2]", "UDP"),
        ("services.media.ports[1]", "UDP"),
        ("services.requests.ports[0]", "5055"),
        ("services.downloader.depends_on.vpn.condition", "service_healthy"),
        ("services.downloader.volumes[1]", "absolute"),
        ("services.media.volumes[2]", "absolute"),
        ("services.media.environment[1]", "PUID"),
        ("services.subtitles.environment.TZ", "variable"),
        ("services.subtitles.tmpfs[0]", "tmpfs"),
    ] {
        said(&report, at, why);
        // Refused, not hinted: the line is not a hint (which says it changes nothing).
        let line = report.iter().find(|l| l.contains(at) && l.contains(why)).unwrap();
        assert!(!line.contains("changes nothing"), "{line}");
    }
    for at in [
        "name",
        "networks.media",
        "services.indexer.hostname",
        "services.indexer.healthcheck",
        "services.vpn.healthcheck.start_period",
        "services.shows.depends_on[1]",
        "services.shows.depends_on[0]",
        "services.subtitles.labels",
        "services.subtitles.logging",
        "services.subtitles.platform",
        "services.requests.stdin_open",
        "services.indexer.user",
    ] {
        said(&report, at, "");
    }
}

/// One step into a document: a key, or an index.
#[derive(Clone)]
enum Step {
    Key(String),
    At(usize),
}

fn cuts(v: &Value, here: &mut Vec<Step>, all: &mut Vec<Vec<Step>>) {
    let children: Vec<(Step, &Value)> = match v {
        Value::Object(m) => m.iter().map(|(k, x)| (Step::Key(k.clone()), x)).collect(),
        Value::Array(a) => a.iter().enumerate().map(|(i, x)| (Step::At(i), x)).collect(),
        _ => return,
    };
    for (step, child) in children {
        here.push(step);
        all.push(here.clone());
        cuts(child, here, all);
        here.pop();
    }
}

fn cut(v: &mut Value, path: &[Step]) {
    let (last, parents) = path.split_last().unwrap();
    let mut at = v;
    for step in parents {
        at = match step {
            Step::Key(k) => &mut at[k.as_str()],
            Step::At(i) => &mut at[*i],
        };
    }
    match last {
        Step::Key(k) => drop(at.as_object_mut().unwrap().shift_remove(k)),
        Step::At(i) => drop(at.as_array_mut().unwrap().remove(*i)),
    }
}

fn render(path: &[Step]) -> String {
    let part = |s: &Step| match s {
        Step::Key(k) => format!(".{k}"),
        Step::At(i) => format!("[{i}]"),
    };
    path.iter().map(part).collect()
}

/// Nothing is dropped silently: take any one key or list item out of the fixture, at
/// any depth, and what comes out (the resources, or what is said) is not the same.
#[test]
fn compose_every_key_of_the_fixture_is_carried_hinted_or_refused() {
    let full = fixture();
    let (all, report) = translate(full.clone(), None);
    let whole: Vec<String> = all.iter().map(Resource::to_yaml).collect();
    let mut paths = Vec::new();
    cuts(&full, &mut Vec::new(), &mut paths);
    assert!(paths.len() > 150, "{} places", paths.len());
    for path in paths {
        let mut less = full.clone();
        cut(&mut less, &path);
        let (all, said) = translate(less, None);
        let yaml: Vec<String> = all.iter().map(Resource::to_yaml).collect();
        assert!(
            yaml != whole || said != report,
            "taking out {} changes nothing",
            render(&path)
        );
    }
}

#[test]
fn compose_the_system_namespace_takes_absolute_paths_and_others_relative_ones() {
    let src =
        "services:\n  app:\n    image: example/app:1\n    volumes:\n      - /srv/app:/data\n      - ./conf:/conf\n";
    let doc = || documents("c.yml", src).unwrap().remove(0);
    let (all, report) = translate(doc(), Some("kith-system"));
    assert_eq!(
        spec(&all, "Volume/kith-system/srv-app"),
        &json!({"node": "n1", "path": "/srv/app"})
    );
    said(&report, "services.app.volumes[1]", "absolute");
    let (all, report) = translate(doc(), Some("media"));
    assert_eq!(spec(&all, "Volume/media/conf"), &json!({"node": "n1", "path": "conf"}));
    said(&report, "services.app.volumes[0]", "absolute");
}

#[test]
fn compose_a_volume_needs_the_node_that_holds_it() {
    let src = "services:\n  app:\n    image: example/app:1\n    volumes:\n      - ./conf:/conf\n";
    let doc = documents("c.yml", src).unwrap().remove(0);
    let (all, report) = compose::translate(doc, None, None);
    assert!(all.iter().all(|r| r.kind != "Volume"));
    said(&report, "--node", "volume");
}

#[test]
fn compose_two_networks_are_refused_for_a_namespace_is_one() {
    let src = "services:\n  a:\n    image: x/a:1\n    networks: [front, back]\n  b:\n    image: x/b:1\n    networks: [back]\n";
    let (_, report) = translate(documents("c.yml", src).unwrap().remove(0), None);
    said(&report, "services.a.networks", "one network");
}

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox(dir)
    }

    fn kith(&self, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_kith"))
            .args(args)
            .current_dir(&self.0)
            .env("KITH_STORE", self.0.join("store/store.json"))
            .output()
            .unwrap();
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
        (out.status.code().unwrap(), text(out.stdout), text(out.stderr))
    }
}

#[test]
fn compose_import_prints_yaml_that_lints_and_exits_one_for_what_was_left_out() {
    let sb = Sandbox::new("compose-import");
    std::fs::write(sb.0.join("compose.yml"), FIXTURE).unwrap();
    let (code, out, err) = sb.kith(&[
        "import",
        "compose",
        "compose.yml",
        "--node",
        "n1",
        "--namespace",
        "media",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("not translated: compose: services.vpn.cap_add[0]"),
        "{err}"
    );
    assert!(err.contains("26 resources"), "{err}");
    std::fs::write(sb.0.join("out.yml"), &out).unwrap();
    let (code, out, err) = sb.kith(&["lint", "--file", "out.yml"]);
    assert_eq!((code, out.trim()), (0, "26 resources ok"), "{err}");

    // A compose file that translates whole exits 0.
    std::fs::write(
        sb.0.join("small.yml"),
        "services:\n  web:\n    image: example/web:1\n    expose: [80]\n",
    )
    .unwrap();
    let (code, out, _) = sb.kith(&["import", "compose", "small.yml"]);
    assert_eq!(code, 0);
    assert!(out.contains("kind: Workload") && out.contains("kind: Service"), "{out}");
}

#[test]
fn compose_anchors_must_be_written_out() {
    let sb = Sandbox::new("compose-anchors");
    std::fs::write(
        sb.0.join("compose.yml"),
        "x-common: &common\n  restart: always\nservices:\n  a:\n    <<: *common\n    image: x/a:1\n",
    )
    .unwrap();
    let (code, _, err) = sb.kith(&["import", "compose", "compose.yml"]);
    assert_eq!(code, 2);
    assert!(
        err.contains("written out") && err.contains("docker compose config"),
        "{err}"
    );
}

#[test]
fn compose_every_service_is_a_pod_with_a_network_of_its_own() {
    let (all, _) = translate(fixture(), None);
    for r in all.iter().filter(|r| r.kind == "Workload") {
        assert_eq!(r.spec["template"]["pod"], json!(true), "{}", r.key());
    }
}

#[test]
fn compose_two_volumes_that_make_one_name_are_not_one_volume_in_silence() {
    let src = "volumes:\n  a_b:\n  a.b:\n  data:\nservices:\n  app:\n    image: example/app:1\n    volumes:\n      - a_b:/one\n      - a.b:/two\n      - data:/three\n      - ./data:/four\n";
    let (all, report) = translate(documents("c.yml", src).unwrap().remove(0), None);
    said(&report, "volumes.a.b", "`a-b`");
    said(&report, "services.app.volumes[1]", "`a-b`");
    // A named volume and a directory of the same name are two things in compose.
    said(&report, "services.app.volumes[3]", "`data`");
    let mounts = spec(&all, "Workload/app")["template"]["containers"][0]["volumeMounts"].to_string();
    assert!(mounts.contains("/one") && mounts.contains("/three"), "{mounts}");
    assert!(!mounts.contains("/two") && !mounts.contains("/four"), "{mounts}");
}

#[test]
fn compose_the_nodes_own_directories_are_not_carried_even_in_the_system_namespace() {
    for path in ["/", "/proc", "/sys/fs", "/dev", "/var/run/docker.sock", "/srv/../etc"] {
        let src = format!("services:\n  app:\n    image: example/app:1\n    volumes:\n      - {path}:/host\n");
        let (all, report) = translate(documents("c.yml", &src).unwrap().remove(0), Some("kith-system"));
        said(&report, "services.app.volumes[0]", "node's own");
        assert!(all.iter().all(|r| r.kind != "Volume"), "{path}");
    }
}

#[test]
fn compose_a_variable_that_reads_as_a_secret_is_said() {
    let src = "services:\n  app:\n    image: example/app:1\n    environment:\n      DB_PASSWORD: example\n      API_TOKEN: \"\"\n      TZ: Etc/UTC\n";
    let (all, report) = translate(documents("c.yml", src).unwrap().remove(0), None);
    said(&report, "services.app.environment.DB_PASSWORD", "Secret");
    assert_eq!(report.len(), 1, "{report:?}");
    // It is still carried: the hint says what it is, the owner decides.
    assert!(spec(&all, "Workload/app").to_string().contains("DB_PASSWORD"));
}

/// What `sh ci/vm.sh --test compose` imports on the host and runs in a node: kith's own test
/// pod as four services, with nothing refused, so every one of them is a Workload and a
/// Service (and `frontend`, web's alias, another) the node can be asked for by name.
#[test]
fn compose_vm_stack_imports_clean() {
    let sb = Sandbox::new("compose-vm-stack");
    let stack = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ci/compose/stack.yml");
    let (code, out, err) = sb.kith(&["import", "compose", stack]);
    assert_eq!((code, err.trim()), (0, "9 resources, 0 things not translated"));
    let (all, _) = translate(
        documents("stack.yml", &std::fs::read_to_string(stack).unwrap())
            .unwrap()
            .remove(0),
        None,
    );
    let mut keys: Vec<String> = all.iter().map(|r| r.key().replacen("/default/", "/", 1)).collect();
    keys.sort();
    let expect = "Service/api Service/cache Service/db Service/frontend Service/web \
        Workload/api Workload/cache Workload/db Workload/web";
    assert_eq!(keys, expect.split_whitespace().collect::<Vec<_>>());
    for name in ["api", "cache", "db", "web"] {
        assert!(out.contains(&format!("name: {name}\n")), "{out}");
        let c = &spec(&all, &format!("Workload/{name}"))["template"]["containers"][0];
        assert_eq!(
            (&c["image"], &c["command"], &c["args"]),
            (&json!("kith.test/pod:1"), &json!(["/bin/pod"]), &json!(["serve"]))
        );
        assert_eq!(
            spec(&all, &format!("Service/{name}"))["ports"],
            json!([{"port": 80}]),
            "{name}"
        );
    }
    // web is ready by its healthcheck, an http probe of its own port.
    let web = &spec(&all, "Workload/web")["template"]["containers"][0];
    assert_eq!(web["readiness"]["http"], json!({"path": "/", "port": 80}));
    assert_eq!(spec(&all, "Service/frontend")["selector"], json!({"app": "web"}));
}

#[test]
fn compose_two_documents_are_not_one_stack() {
    let sb = Sandbox::new("compose-two");
    std::fs::write(
        sb.0.join("compose.yml"),
        "services:\n  a:\n    image: x/a:1\n---\nservices:\n  b:\n    image: x/b:1\n",
    )
    .unwrap();
    let (code, out, err) = sb.kith(&["import", "compose", "compose.yml"]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(err.contains("2 documents"), "{err}");
}
