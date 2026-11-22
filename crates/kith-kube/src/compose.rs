//! A docker-compose file as kith resources.
//!
//! Like the Kubernetes reader, each key is taken out of the input as it is carried over,
//! so what is left is what was not: it is said by path. Nothing is dropped silently.

use super::*;
use std::collections::BTreeSet;

/// Keys kith cannot do what they ask, with why: each item or entry is refused by path.
const REFUSED: &[(&str, &str)] = &[
    ("cap_add", "adds capabilities: kith only drops them"),
    ("sysctls", "sets kernel parameters"),
    ("devices", "hands in a device: a DeviceClaim does that"),
    ("privileged", "asks for every privilege"),
    ("env_file", "reads a file: write the variables under environment"),
    ("build", "builds an image"),
    ("security_opt", "sets security options"),
    ("tmpfs", "mounts a tmpfs"),
];

/// Keys that kith has no use for, and without which the same thing runs.
const SAID: &[&str] = &[
    "labels",
    "hostname",
    "logging",
    "stdin_open",
    "tty",
    "init",
    "platform",
    "stop_grace_period",
];

const NOTHING: &str = "changes nothing: kith has no use for it";

/// A shell would have to read these: a command with one is written as a list.
const SHELL: &[char] = &[
    '"', '\'', '\\', '|', '&', ';', '<', '>', '*', '?', '(', ')', '`', '{', '}', '#',
];

/// What the volumes of the file are made of, as they are met.
struct Env<'a> {
    ns: Option<&'a str>,
    node: Option<&'a str>,
    declared: Vec<String>,
    /// Volume name to its directory, and what in the file it is made for: a directory, or a
    /// named volume (two things that make one name must not become one Volume in silence).
    vols: BTreeMap<String, (String, String)>,
}

/// One service, as a container of a pod and what the pod gets from it.
struct Part {
    container: Value,
    ports: BTreeSet<u32>,
    names: Vec<String>,
    restart: Option<(String, &'static str)>,
}

/// A docker-compose file as kith resources, and what was left out, by path.
/// The volumes are made on `node`: without one they are said, not made.
pub fn translate(root: Value, namespace: Option<&str>, node: Option<&str>) -> (Vec<Resource>, Vec<String>) {
    let mut cx = Cx {
        who: "compose".into(),
        import: true,
        hints: Vec::new(),
        refused: Vec::new(),
    };
    let mut root = root;
    variables(&mut cx, &mut root, "");
    let Value::Object(mut root) = root else {
        cx.whole("is not a mapping");
        return (Vec::new(), cx.refused);
    };
    for key in ["name", "version"] {
        if root.remove(key).is_some_and(|v| !is_empty(&v)) {
            cx.hint(key, NOTHING);
        }
    }
    let mut env = Env {
        ns: namespace,
        node,
        declared: Vec::new(),
        vols: BTreeMap::new(),
    };
    for (name, v) in cx.map(&mut root, "volumes", "") {
        let at = join("volumes", &name);
        let mut one = Map::from_iter([(name.clone(), v)]);
        let mut m = cx.map(&mut one, &name, "volumes");
        // (`local` is what it is anyway.)
        if m.get("driver").is_some_and(|d| d == "local") {
            m.remove("driver");
        }
        cx.rest(m, &at);
        claim(&mut cx, &mut env, &at, &slug(&name), Some(&name));
        env.declared.push(name);
    }
    let mut list = Vec::new();
    for (name, v) in cx.map(&mut root, "services", "") {
        let mut one = Map::from_iter([(name.clone(), v)]);
        list.push((name.clone(), cx.map(&mut one, &name, "services")));
    }
    if list.is_empty() {
        cx.whole("has no services");
    }
    let used: BTreeSet<&str> = list.iter().flat_map(|(_, m)| network_names(m)).collect();
    let multi = used.len() > 1;
    for (n, v) in cx.map(&mut root, "networks", "") {
        let at = join("networks", &n);
        net(&mut cx, &at, multi);
        let mut one = Map::from_iter([(n.clone(), v)]);
        let m = cx.map(&mut one, &n, "networks");
        cx.rest(m, &at);
    }
    cx.rest(root, "");

    let names: Vec<String> = list.iter().map(|(n, _)| n.clone()).collect();
    // A service that shares another's network is a container of that one's pod.
    let own: Vec<bool> = list
        .iter()
        .map(|(_, m)| {
            !m.get("network_mode")
                .and_then(Value::as_str)
                .is_some_and(|s| s.starts_with("service:"))
        })
        .collect();
    let mut head_of = Vec::new();
    for (name, m) in &mut list {
        let at = join(&join("services", name), "network_mode");
        head_of.push(match m.remove("network_mode") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => match s.strip_prefix("service:") {
                Some(head) => {
                    let found = names.iter().position(|n| n == head).filter(|i| own[*i] && head != name);
                    if found.is_none() {
                        cx.note(&at, &format!("`{s}` is no service that has a network of its own"));
                    }
                    found
                }
                None if s == "bridge" || s == "default" => {
                    cx.hint(&at, NOTHING);
                    None
                }
                None => {
                    cx.note(
                        &at,
                        &format!("`{s}` not translated: a pod shares a network as `service:NAME`"),
                    );
                    None
                }
            },
            Some(_) => {
                cx.note(&at, "should be text");
                None
            }
        });
    }

    let mut maps: Vec<Option<Map>> = list.into_iter().map(|(_, m)| Some(m)).collect();
    let (mut made, mut seen) = (Vec::new(), BTreeSet::new());
    for i in (0..names.len()).filter(|i| head_of[*i].is_none()) {
        let head = &names[i];
        let members = (0..names.len()).filter(|j| head_of[*j] == Some(i));
        let (mut containers, mut ports, mut aliases, mut restart) =
            (Vec::new(), BTreeSet::new(), vec![head.clone()], None);
        for j in std::iter::once(i).chain(members) {
            let Some(part) = part(&mut cx, &mut env, &names[j], maps[j].take().unwrap_or_default(), multi) else {
                continue;
            };
            containers.push(part.container);
            ports.extend(part.ports);
            aliases.extend(part.names);
            // ponytail: a service with no `restart` takes kith's default, not compose's `no`.
            match (&restart, part.restart) {
                (None, one) => restart = one,
                (Some((_, word)), Some((at, other))) if *word != other => cx.note(
                    &at,
                    "differs from the pod's other containers: a pod has one restart policy",
                ),
                _ => {}
            }
        }
        if containers.is_empty() {
            continue;
        }
        let meta = |name: &str, labels: Strings| Metadata {
            name: name.into(),
            namespace: namespace.map(String::from),
            labels,
            annotations: Strings::new(),
            revision: None,
        };
        let template = obj([
            ("containers", Some(json!(containers))),
            ("restartPolicy", restart.map(|(_, word)| json!(word))),
            // A compose service has a network of its own, so each is a pod: without it a
            // container shares its node's network.
            ("pod", Some(json!(true))),
        ]);
        let app = Strings::from([("app".to_string(), head.clone())]);
        made.push(make("Workload", meta(head, app), json!({ "template": template })));
        for name in aliases {
            if !seen.insert(name.clone()) {
                let at = join("services", head);
                cx.note(&at, &format!("makes a second Service of the name `{name}`"));
            } else if !ports.is_empty() {
                let ports: Vec<Value> = ports.iter().map(|port| json!({ "port": port })).collect();
                made.push(make(
                    "Service",
                    meta(&name, Strings::new()),
                    json!({ "selector": { "app": head }, "ports": ports }),
                ));
            }
        }
    }
    match env.node {
        Some(node) => {
            for (name, (path, _)) in &env.vols {
                let meta = Metadata {
                    name: name.clone(),
                    namespace: namespace.map(String::from),
                    labels: Strings::new(),
                    annotations: Strings::new(),
                    revision: None,
                };
                made.push(make("Volume", meta, json!({ "node": node, "path": path })));
            }
        }
        None if !env.vols.is_empty() => {
            cx.whole("has volumes: give --node NODE to make them");
        }
        None => {}
    }
    let mut out = Vec::new();
    for resource in made {
        let key = resource.key();
        match resource.validated() {
            Ok(resource) => out.push(resource),
            Err(e) => cx.whole(&format!("{key} is not valid: {e}")),
        }
    }
    (out, [cx.refused, cx.hints].concat())
}

/// What `docker inspect` printed (an array of containers, or one) as a compose file, for
/// [`translate`] to refuse and carry by its own rules, so a container made with `docker run` is
/// read as a compose service of its name. Also each named volume mounted: its docker name and
/// the name kith gives the Volume.
/// ponytail: the fields compose has a key for; limits (Memory, NanoCpus, Ulimits), Dns, ExtraHosts
/// and the like are not read: add a key here, and the translator says it by path.
pub fn from_docker(inspected: Vec<Value>) -> Result<(Value, Vec<(String, String)>), String> {
    let (mut services, mut volumes, mut named) = (Map::new(), Map::new(), Vec::new());
    for c in inspected
        .iter()
        .flat_map(|v| v.as_array().map_or_else(|| vec![v], |a| a.iter().collect()))
    {
        let (cfg, host) = (&c["Config"], &c["HostConfig"]);
        let name = c["Name"].as_str().unwrap_or("").trim_start_matches('/');
        if name.is_empty() || !c.is_object() {
            return Err("a container of the input has no Name: is it `docker inspect` of containers?".into());
        }
        // What is there, and not the empty or false it stands for.
        let on = |v: &Value| (!is_empty(v) && *v != json!(false)).then(|| v.clone());
        let secs = |ns: &Value| {
            ns.as_u64()
                .filter(|n| *n > 0)
                .map(|n| json!(format!("{}s", n.div_ceil(1_000_000_000))))
        };
        let id = c["Id"].as_str().unwrap_or("");
        let h = &cfg["Healthcheck"];
        let restart = match (
            host["RestartPolicy"]["Name"].as_str().unwrap_or(""),
            &host["RestartPolicy"]["MaximumRetryCount"],
        ) {
            ("", _) => json!("no"),
            (r, n) if n.as_u64().unwrap_or(0) > 0 => json!(format!("{r}:{n}")),
            (r, _) => json!(r),
        };
        // `bridge` (`default`) is what a container has without a word; a network of its own
        // name is one network; the rest (host, none, container:ID) are said as they are.
        let (network_mode, networks) = match host["NetworkMode"].as_str().unwrap_or("") {
            "" | "default" | "bridge" => (None, None),
            m if m == "host" || m == "none" || m.starts_with("container:") => (Some(json!(m)), None),
            m => (None, Some(json!([m]))),
        };
        let devices: Vec<Value> = host["Devices"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|d| {
                json!(format!(
                    "{}:{}",
                    d["PathOnHost"].as_str().unwrap_or(""),
                    d["PathInContainer"].as_str().unwrap_or("")
                ))
            })
            .collect();
        let mut ports = Vec::new();
        for (key, _) in cfg["ExposedPorts"].as_object().into_iter().flatten() {
            let (port, proto) = key.split_once('/').unwrap_or((key, "tcp"));
            match host["PortBindings"][key.as_str()].as_array().filter(|b| !b.is_empty()) {
                Some(bound) => ports.extend(bound.iter().map(|b| {
                    json!(format!("{}:{port}/{proto}", b["HostPort"].as_str().unwrap_or(""))) // (the address a port is bound to is not carried)
                })),
                None => ports.push(json!(key)),
            }
        }
        let mut vols = Vec::new();
        let mut tmpfs = Vec::new();
        for m in c["Mounts"].as_array().into_iter().flatten() {
            let (dest, read_only) = (&m["Destination"], m["RW"] == json!(false));
            match m["Type"].as_str() {
                Some("volume") => {
                    let docker = m["Name"].as_str().unwrap_or("");
                    volumes.insert(docker.to_string(), json!({}));
                    if !named.iter().any(|(d, _)| d == docker) {
                        named.push((docker.to_string(), slug(docker)));
                    }
                    vols.push(json!({"type": "volume", "source": docker, "target": dest, "read_only": read_only}));
                }
                Some("tmpfs") => tmpfs.push(dest.clone()),
                // A bind (and a type nobody knows of) is refused by compose's own rule for it.
                _ => {
                    vols.push(json!({"type": m["Type"], "source": m["Source"], "target": dest, "read_only": read_only}))
                }
            }
        }
        let logging = host["LogConfig"]["Type"]
            .as_str()
            .filter(|t| !["", "json-file", "local"].contains(t));
        let service = obj([
            ("image", on(&cfg["Image"])),
            ("environment", on(&cfg["Env"])),
            ("command", on(&cfg["Cmd"])),
            ("entrypoint", on(&cfg["Entrypoint"])),
            ("working_dir", on(&cfg["WorkingDir"])),
            ("user", on(&cfg["User"])),
            ("labels", on(&cfg["Labels"])),
            // (A container's hostname is its id's start unless it was given one.)
            (
                "hostname",
                cfg["Hostname"]
                    .as_str()
                    .filter(|h| !h.is_empty() && !id.starts_with(h))
                    .map(|h| json!(h)),
            ),
            ("tty", on(&cfg["Tty"])),
            ("stdin_open", on(&cfg["OpenStdin"])),
            (
                "stop_grace_period",
                cfg["StopTimeout"]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .map(|n| json!(format!("{n}s"))),
            ),
            ("ports", nonempty(json!(ports))),
            (
                "healthcheck",
                on(h).map(|h| {
                    obj([
                        ("test", on(&h["Test"])),
                        ("interval", secs(&h["Interval"])),
                        ("timeout", secs(&h["Timeout"])),
                        ("retries", on(&h["Retries"])),
                        ("start_period", secs(&h["StartPeriod"])),
                        ("start_interval", secs(&h["StartInterval"])),
                    ])
                }),
            ),
            ("restart", Some(restart)),
            ("network_mode", network_mode),
            ("networks", networks),
            ("privileged", on(&host["Privileged"])),
            ("cap_add", on(&host["CapAdd"])),
            ("cap_drop", on(&host["CapDrop"])),
            ("security_opt", on(&host["SecurityOpt"])),
            ("sysctls", on(&host["Sysctls"])),
            ("devices", nonempty(json!(devices))),
            ("read_only", on(&host["ReadonlyRootfs"])),
            ("init", on(&host["Init"])),
            ("logging", logging.map(|driver| json!({ "driver": driver }))),
            ("tmpfs", nonempty(json!(tmpfs))),
            ("volumes", nonempty(json!(vols))),
        ]);
        if services.insert(name.to_string(), service).is_some() {
            return Err(format!("two containers of the name `{name}`: a name is one service"));
        }
    }
    if services.is_empty() {
        return Err("no containers in the input".into());
    }
    let doc = obj([
        ("services", Some(Value::Object(services))),
        ("volumes", nonempty(Value::Object(volumes))),
    ]);
    Ok((doc, named))
}

/// A value that asks the shell compose runs in is not one kith can read: said where it is,
/// and left out (a null), so that what reads the key does not say it twice.
fn variables(cx: &mut Cx, v: &mut Value, at: &str) {
    match v {
        Value::String(s) if s.contains('$') => {
            let why = "uses a variable: write its value in (`docker compose config` does)";
            cx.note(at, why);
            *v = Value::Null;
        }
        Value::Array(a) => a
            .iter_mut()
            .enumerate()
            .for_each(|(i, x)| variables(cx, x, &format!("{at}[{i}]"))),
        Value::Object(o) => o.iter_mut().for_each(|(k, x)| variables(cx, x, &join(at, k))),
        _ => {}
    }
}

fn network_names(service: &Map) -> Vec<&str> {
    match service.get("networks") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        Some(Value::Object(o)) => o.keys().map(String::as_str).collect(),
        _ => Vec::new(),
    }
}

/// A namespace is one network: a file that names two cannot be one namespace.
fn net(cx: &mut Cx, at: &str, multi: bool) {
    if multi {
        cx.note(
            at,
            "is one of several: a namespace is one network, write a file for each",
        );
    } else {
        cx.hint(at, "changes nothing: a namespace is one network");
    }
}

/// Has the key at `at` been said already?
fn said(cx: &Cx, at: &str) -> bool {
    let line = format!(": {at} ");
    cx.refused.iter().any(|l| l.contains(&line))
}

/// One service, taken apart: whatever is not carried is said.
fn part(cx: &mut Cx, env: &mut Env, name: &str, mut m: Map, multi: bool) -> Option<Part> {
    let at = join("services", name);
    let image = cx.text(&mut m, "image", &at);
    let mut names = Vec::new();
    names.extend(cx.text(&mut m, "container_name", &at).filter(|c| c != name));
    let vars = environment(cx, &mut m, &at);
    let mut ports = BTreeSet::new();
    for key in ["ports", "expose"] {
        container_ports(cx, &mut m, key, &at, &mut ports);
    }
    let mounts = mounts(cx, env, &mut m, &at);
    depends_on(cx, &mut m, &at);
    let readiness = healthcheck(cx, &mut m, &at);
    let args = argv(cx, &mut m, "command", &at);
    let command = argv(cx, &mut m, "entrypoint", &at);
    let working_dir = cx.text(&mut m, "working_dir", &at);
    let user = user(cx, &mut m, &at);
    let read_only = cx.flag(&mut m, "read_only", &at).filter(|r| *r);
    let dropped: Vec<String> = cx
        .strs(&mut m, "cap_drop", &at)
        .into_iter()
        .map(|c| if c == "ALL" { "all".into() } else { c })
        .collect();
    let pull = cx.text(&mut m, "pull_policy", &at);
    let pull = cx.pick(
        &join(&at, "pull_policy"),
        pull,
        &[
            ("always", "always"),
            ("never", "never"),
            ("missing", "ifNotPresent"),
            ("if_not_present", "ifNotPresent"),
        ],
    );
    let restart = restart(cx, &mut m, &at);
    networks(cx, &mut m, &at, multi, &mut names);
    for (key, why) in REFUSED {
        refuse(cx, &mut m, key, why, &at);
    }
    for key in SAID {
        if m.remove(*key).is_some_and(|v| !is_empty(&v)) {
            cx.hint(&join(&at, key), NOTHING);
        }
    }
    cx.rest(m, &at);
    let Some(image) = image else {
        cx.note(&at, "has no image");
        return None;
    };
    let listed: Vec<Value> = ports.iter().map(|port| json!({ "port": port })).collect();
    let container = obj([
        ("name", Some(json!(name))),
        ("image", Some(json!(image))),
        ("pullPolicy", pull),
        ("command", nonempty(json!(command))),
        ("args", nonempty(json!(args))),
        ("env", nonempty(json!(vars))),
        ("workingDir", some(working_dir)),
        ("ports", nonempty(json!(listed))),
        ("volumeMounts", nonempty(json!(mounts))),
        ("readiness", readiness),
        ("readOnlyRoot", some(read_only)),
        ("runAsUser", some(user)),
        ("dropCapabilities", nonempty(json!(dropped))),
    ]);
    Some(Part {
        container,
        ports,
        names,
        restart,
    })
}

/// A key kith cannot do: each item (or entry) is refused by path, a lone value once.
fn refuse(cx: &mut Cx, m: &mut Map, key: &str, why: &str, at: &str) {
    let at = join(at, key);
    match m.remove(key) {
        None | Some(Value::Null | Value::Bool(false)) => {}
        Some(Value::Array(a)) => {
            for (i, _) in a.iter().enumerate().filter(|(_, item)| !item.is_null()) {
                cx.note(&format!("{at}[{i}]"), why);
            }
        }
        Some(Value::Object(o)) => o.keys().for_each(|k| cx.note(&join(&at, k), why)),
        Some(v) if is_empty(&v) => {}
        Some(_) => cx.note(&at, why),
    }
}

fn environment(cx: &mut Cx, m: &mut Map, at: &str) -> Vec<Value> {
    let at = join(at, "environment");
    let mut out = Vec::new();
    let mut var = |cx: &mut Cx, at: &str, name: &str, value: Option<String>| match value {
        Some(value) => {
            let upper = name.to_ascii_uppercase();
            if !value.is_empty()
                && ["PASS", "SECRET", "TOKEN", "KEY"]
                    .iter()
                    .any(|word| upper.contains(word))
            {
                cx.hint(
                    at,
                    "reads as a secret and is carried as plain `env`: a Secret and `envFrom` keep it out of the Workload",
                );
            }
            out.push(json!({ "name": name, "value": value }));
        }
        None if said(cx, at) => {}
        None => cx.note(at, &format!("`{name}` has no value: write `{name}=value`")),
    };
    match m.remove("environment") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for (i, item) in items.into_iter().enumerate() {
                let at = format!("{at}[{i}]");
                match item {
                    Value::String(s) => match s.split_once('=') {
                        Some((name, value)) => var(cx, &at, name, Some(value.into())),
                        None => var(cx, &at, &s, None),
                    },
                    Value::Null if said(cx, &at) => {}
                    _ => cx.note(&at, "should be NAME=value text"),
                }
            }
        }
        Some(Value::Object(map)) => {
            for (name, v) in map {
                let at = join(&at, &name);
                match v {
                    Value::String(s) => var(cx, &at, &name, Some(s)),
                    v @ (Value::Number(_) | Value::Bool(_)) => var(cx, &at, &name, Some(v.to_string())),
                    Value::Null => var(cx, &at, &name, None),
                    _ => cx.note(&at, "should be text"),
                }
            }
        }
        Some(_) => cx.note(&at, "should be a list or a mapping"),
    }
    out
}

/// The container ports of `ports` or `expose`; a port published on the node is refused.
fn container_ports(cx: &mut Cx, m: &mut Map, key: &str, at: &str, out: &mut BTreeSet<u32>) {
    for (i, item) in cx.list(m, key, at).into_iter().enumerate() {
        let at = format!("{}[{i}]", join(at, key));
        let (target, published, protocol);
        match item {
            Value::String(_) | Value::Number(_) => {
                let text = item.as_str().map_or_else(|| item.to_string(), String::from);
                let (addr, proto) = text
                    .split_once('/')
                    .map_or((&text[..], None), |(a, p)| (a, Some(p.to_string())));
                let parts: Vec<&str> = addr.split(':').collect();
                // `port`, `host:port` or `address:host:port`.
                if parts.len() > 3 {
                    cx.note(&at, "is not a port");
                    continue;
                }
                target = parts.last().map(|p| p.to_string());
                published = (parts.len() > 1).then(|| parts[parts.len() - 2].to_string());
                protocol = proto;
            }
            Value::Object(mut o) => {
                target = cx.text(&mut o, "target", &at);
                published = cx.text(&mut o, "published", &at);
                protocol = cx.text(&mut o, "protocol", &at);
                cx.rest(o, &at);
            }
            _ => {
                cx.note(&at, "should be a port");
                continue;
            }
        }
        let Some(port) = target.as_deref().and_then(|t| t.parse::<u16>().ok()).filter(|p| *p > 0) else {
            let seen = target.unwrap_or_default();
            cx.note(&at, &format!("`{seen}` is not one port"));
            continue;
        };
        if let Some(proto) = protocol.filter(|p| !p.eq_ignore_ascii_case("tcp")) {
            let proto = proto.to_uppercase();
            cx.note(&at, &format!("is {proto}: kith's Service carries TCP only"));
            continue;
        }
        if let Some(on_node) = published {
            let on_node = if on_node.is_empty() { "a port" } else { &on_node };
            let why = format!("publishes {on_node} on the node: kith does not, only port {port} in the namespace");
            cx.note(&at, &why);
        }
        out.insert(u32::from(port));
    }
}

/// `volumes`: a bind of a directory, or a named volume, each a Volume of the namespace.
fn mounts(cx: &mut Cx, env: &mut Env, m: &mut Map, at: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (i, item) in cx.list(m, "volumes", at).into_iter().enumerate() {
        let at = format!("{}[{i}]", join(at, "volumes"));
        let (bind, src, dst, read_only) = match item {
            Value::String(s) => {
                let parts: Vec<&str> = s.split(':').collect();
                let read_only = match parts[..] {
                    [_] => {
                        cx.note(&at, "is an anonymous volume: name a directory or a volume to mount");
                        continue;
                    }
                    [_, _] | [_, _, "rw"] => false,
                    [_, _, "ro"] => true,
                    _ => {
                        cx.note(&at, "has an option other than ro or rw");
                        continue;
                    }
                };
                (
                    parts[0].starts_with(['/', '.', '~']),
                    parts[0].to_string(),
                    parts[1].to_string(),
                    read_only,
                )
            }
            Value::Object(mut o) => {
                let kind = cx.text(&mut o, "type", &at);
                let (src, dst) = (cx.text(&mut o, "source", &at), cx.text(&mut o, "target", &at));
                let read_only = cx.flag(&mut o, "read_only", &at).unwrap_or(false);
                cx.rest(o, &at);
                let bind = match kind.as_deref() {
                    Some("bind") => true,
                    Some("volume") => false,
                    _ => {
                        cx.note(&at, "needs a `type` of bind or volume");
                        continue;
                    }
                };
                let (Some(src), Some(dst)) = (src, dst) else {
                    cx.note(&at, "needs a `source` and a `target`");
                    continue;
                };
                (bind, src, dst, read_only)
            }
            _ => {
                cx.note(&at, "should be text or a mapping");
                continue;
            }
        };
        if !dst.starts_with('/') {
            cx.note(&at, "has a target that is not an absolute path");
            continue;
        }
        let volume = if bind && src.starts_with('~') {
            cx.note(&at, "starts with ~: write the path out");
            None
        } else if bind {
            claim(cx, env, &at, &src, None)
        } else if env.declared.contains(&src) {
            claim(cx, env, &at, &slug(&src), Some(&src))
        } else {
            cx.note(&at, "names a volume the file does not declare");
            None
        };
        let Some(volume) = volume else { continue };
        out.push(obj([
            ("volume", Some(json!(volume))),
            ("path", Some(json!(dst))),
            ("readOnly", read_only.then(|| json!(true))),
        ]));
    }
    out
}

/// A name kith takes, of whatever is written.
fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let c = if c.is_ascii_alphanumeric() {
            c.to_ascii_lowercase()
        } else {
            '-'
        };
        if c != '-' || !out.ends_with('-') {
            out.push(c);
        }
    }
    out.trim_matches('-').to_string()
}

/// The Volume of a directory: its name, or none, the reason said at `at`.
/// A volume of `kith-system` is an absolute host path, of any other namespace a
/// directory inside its own.
/// `named` is the file's own name of a named volume, whose directory is `path`.
fn claim(cx: &mut Cx, env: &mut Env, at: &str, path: &str, named: Option<&str>) -> Option<String> {
    let path = match (!path.starts_with('/'), env.ns == Some("kith-system")) {
        (false, true) => {
            // The node's own insides are no container's to hold, whoever applies it.
            let own = |p: &str| path == p || path.strip_prefix(p).is_some_and(|rest| rest.starts_with('/'));
            if path.trim_end_matches('/').is_empty()
                || ["/proc", "/sys", "/dev"].into_iter().any(own)
                || path.ends_with("docker.sock")
                || path.split('/').any(|part| part == "..")
            {
                cx.note(
                    at,
                    "is the node's own (/, /proc, /sys, /dev, a docker socket) or climbs with `..`: not carried",
                );
                return None;
            }
            path.to_string()
        }
        (true, true) => {
            cx.note(at, "is relative: a volume in kith-system takes an absolute path");
            return None;
        }
        (false, false) => {
            cx.note(
                at,
                "is an absolute host path: write it relative (./data), or apply in kith-system",
            );
            return None;
        }
        (true, false) => {
            let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
            if parts.contains(&"..") || parts.is_empty() {
                cx.note(at, "is not a directory inside its namespace");
                return None;
            }
            parts.join("/")
        }
    };
    let name = slug(&path);
    if name.is_empty() {
        cx.note(at, "has a path that makes no name");
        return None;
    }
    let of = named.map_or_else(|| path.clone(), |named| format!("the volume `{named}`"));
    if env.vols.get(&name).is_some_and(|(_, other)| *other != of) {
        cx.note(
            at,
            &format!("makes the name `{name}`, which another volume or path of the file makes too"),
        );
        return None;
    }
    env.vols.insert(name.clone(), (path, of));
    Some(name)
}

fn depends_on(cx: &mut Cx, m: &mut Map, at: &str) {
    let at = join(at, "depends_on");
    let said = NOTHING;
    match m.remove("depends_on") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => (0..a.len()).for_each(|i| cx.hint(&format!("{at}[{i}]"), said)),
        Some(Value::Object(o)) => {
            for (name, v) in o {
                let at = join(&at, &name);
                cx.hint(&at, said);
                let mut one = Map::from_iter([(name.clone(), v)]);
                let mut inner = cx.map(&mut one, &name, "");
                if let Some(c) = inner.remove("condition").filter(|c| c != "service_started") {
                    let c = c.as_str().unwrap_or("?");
                    cx.note(
                        &join(&at, "condition"),
                        &format!("`{c}` not translated: kith waits for nothing"),
                    );
                }
                cx.rest(inner, &at);
            }
        }
        Some(_) => cx.note(&at, "should be a list or a mapping"),
    }
}

/// `1m30s` as seconds.
fn duration(s: &str) -> Option<u32> {
    let (mut total, mut digits) = (0u32, String::new());
    for c in s.chars() {
        match c {
            '0'..='9' => digits.push(c),
            'h' | 'm' | 's' if !digits.is_empty() => {
                let unit = match c {
                    'h' => 3600,
                    'm' => 60,
                    _ => 1,
                };
                total = total.checked_add(digits.parse::<u32>().ok()?.checked_mul(unit)?)?;
                digits.clear();
            }
            _ => return None,
        }
    }
    (digits.is_empty() && total > 0).then_some(total)
}

fn seconds(cx: &mut Cx, h: &mut Map, key: &str, at: &str) -> Option<u32> {
    let s = cx.text(h, key, at)?;
    let found = duration(&s);
    if found.is_none() {
        cx.note(&join(at, key), "is not a duration such as 30s or 1m");
    }
    found
}

/// The request in a test of `curl` or `wget` that asks the container itself for a page:
/// only that is one kith's probe does. Anything it does not know of stops it, for a flag
/// it left out may be what made the test pass or fail.
fn http(words: &[String]) -> Option<(String, u32)> {
    let (program, args) = words.split_first()?;
    let at = args.iter().position(|a| ["||", "&&", ";", "|"].contains(&a.as_str()));
    let (args, tail) = args.split_at(at.unwrap_or(args.len()));
    if !(tail.is_empty() || tail == ["||", "exit", "1"]) {
        return None;
    }
    let curl = program == "curl";
    if !curl && program != "wget" {
        return None;
    }
    // (`wget` fails on an error status as it is: `curl` only with `-f`.)
    let (mut url, mut fails) = (None, !curl);
    for a in args {
        if let Some(rest) = a.strip_prefix("http://") {
            // (two URLs are not one request.)
            if url.replace(rest).is_some() {
                return None;
            }
        } else if curl
            && a.starts_with('-')
            && !a.starts_with("--")
            && a.len() > 1
            && a[1..].chars().all(|c| "fsS".contains(c))
        {
            fails |= a.contains('f');
        } else if curl && ["--fail", "--silent", "--show-error"].contains(&a.as_str()) {
            fails |= a == "--fail";
        } else if !curl && ["-q", "-qO-", "-O-", "--spider", "--quiet", "-nv", "--no-verbose"].contains(&a.as_str()) {
        } else {
            return None;
        }
    }
    let url: &str = url?;
    if !fails {
        return None;
    }
    let (host, path) = url.find('/').map_or((url, "/"), |i| url.split_at(i));
    let (host, port) = match host.split_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok().filter(|p| *p > 0)?),
        None => (host, 80),
    };
    ["localhost", "127.0.0.1", "0.0.0.0"]
        .contains(&host)
        .then(|| (path.to_string(), u32::from(port)))
}

/// A `healthcheck` is a readiness probe where its test is one kith runs; else it is said.
fn healthcheck(cx: &mut Cx, m: &mut Map, at: &str) -> Option<Value> {
    let mut h = cx.map(m, "healthcheck", at);
    let at = join(at, "healthcheck");
    let test = h.remove("test");
    let (interval, timeout) = (
        seconds(cx, &mut h, "interval", &at),
        seconds(cx, &mut h, "timeout", &at),
    );
    let retries = cx.num(&mut h, "retries", &at);
    for key in ["start_period", "start_interval"] {
        if h.remove(key).is_some_and(|v| !is_empty(&v)) {
            cx.hint(&join(&at, key), NOTHING);
        }
    }
    cx.rest(h, &at);
    let at = join(&at, "test");
    let words: Vec<String> = match test {
        None | Some(Value::Null) => {
            if interval.or(timeout).or(retries).is_some() {
                cx.hint(&at, "has no test: the image's is not run");
            }
            return None;
        }
        Some(Value::String(s)) => s.split_whitespace().map(String::from).collect(),
        Some(Value::Array(a)) => {
            let mut words = Vec::new();
            for x in &a {
                match x {
                    Value::String(s) => words.push(s.clone()),
                    Value::Number(_) | Value::Bool(_) => words.push(x.to_string()),
                    _ => {
                        cx.note(&at, "should be text");
                        return None;
                    }
                }
            }
            match words.split_first() {
                Some((first, rest)) if first == "CMD" => rest.to_vec(),
                Some((first, rest)) if first == "CMD-SHELL" => {
                    rest.join(" ").split_whitespace().map(String::from).collect()
                }
                Some((first, _)) if first == "NONE" => {
                    cx.hint(&at, "turns the image's test off");
                    return None;
                }
                _ => {
                    cx.note(&at, "should begin with CMD, CMD-SHELL or NONE");
                    return None;
                }
            }
        }
        Some(_) => {
            cx.note(&at, "should be text or a list");
            return None;
        }
    };
    let Some((path, port)) = http(&words) else {
        let line = words.join(" ");
        cx.hint(
            &at,
            &format!("`{line}` is not an http request kith can probe: it changes nothing"),
        );
        return None;
    };
    Some(obj([
        ("http", Some(json!({ "path": path, "port": port }))),
        ("intervalSeconds", some(interval)),
        ("timeoutSeconds", some(timeout)),
        ("failureThreshold", some(retries)),
    ]))
}

/// `command` or `entrypoint`: a list, or a line of plain words.
fn argv(cx: &mut Cx, m: &mut Map, key: &str, at: &str) -> Option<Vec<String>> {
    if let Some(Value::String(line)) = m.get(key) {
        let line = line.clone();
        m.remove(key);
        if line.contains(SHELL) {
            cx.note(&join(at, key), "needs a shell to read it: write it as a list");
            return None;
        }
        return Some(line.split_whitespace().map(String::from).collect());
    }
    Some(cx.strs(m, key, at)).filter(|words| !words.is_empty())
}

/// `user`: a number is `runAsUser`; a name needs the image to say what it is.
fn user(cx: &mut Cx, m: &mut Map, at: &str) -> Option<u32> {
    let text = cx.text(m, "user", at)?;
    let at = join(at, "user");
    let (uid, group) = text.split_once(':').unwrap_or((&text, ""));
    if !group.is_empty() {
        cx.hint(&at, "has a group: kith runs as the user only");
    }
    let uid = uid.parse().ok();
    if uid.is_none() {
        cx.note(&at, "is a name: kith takes the number");
    }
    uid
}

fn restart(cx: &mut Cx, m: &mut Map, at: &str) -> Option<(String, &'static str)> {
    let value = cx.text(m, "restart", at)?;
    let at = join(at, "restart");
    let word = match value.as_str() {
        "always" | "unless-stopped" => "always",
        "on-failure" => "onFailure",
        "no" | "false" => "never",
        _ => {
            cx.note(&at, &format!("`{value}` not translated"));
            return None;
        }
    };
    Some((at, word))
}

/// `networks`: each is said, and the aliases are names of the Service too.
fn networks(cx: &mut Cx, m: &mut Map, at: &str, multi: bool, names: &mut Vec<String>) {
    let at = join(at, "networks");
    match m.remove("networks") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => (0..a.len()).for_each(|i| net(cx, &format!("{at}[{i}]"), multi)),
        Some(Value::Object(o)) => {
            for (name, v) in o {
                let at_net = join(&at, &name);
                net(cx, &at_net, multi);
                let mut one = Map::from_iter([(name.clone(), v)]);
                let mut inner = cx.map(&mut one, &name, &at);
                names.extend(cx.strs(&mut inner, "aliases", &at_net));
                cx.rest(inner, &at_net);
            }
        }
        Some(_) => cx.note(&at, "should be a list or a mapping"),
    }
}
