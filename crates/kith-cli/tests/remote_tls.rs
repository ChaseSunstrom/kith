//! `kith --server HOST:PORT --identity DIR` over mutual TLS to a kithd's `--listen` port (T-0404).
//! The kithd here is an in-process TLS server with certificates from a test CA, on 127.0.0.1
//! only, so these need no kithd on the machine. Built only with `--features remote`.
#![cfg(feature = "remote")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

/// A cluster CA, as kithd's pki.rs makes one: it signs, and nothing else.
struct Ca {
    common: String,
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn ca_params(common: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, common);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    params
}

fn ca(common: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let cert = ca_params(common).self_signed(&key).unwrap();
    Ca {
        common: common.into(),
        cert,
        key,
    }
}

/// A certificate for `names` signed by `ca`, with the usages kithd gives it (pki.rs `sign`).
fn leaf(ca: &Ca, names: &[&str], usages: Vec<ExtendedKeyUsagePurpose>) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    let mut params = CertificateParams::new(names).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = usages;
    params.use_authority_key_identifier_extension = true;
    let issuer = Issuer::new(ca_params(&ca.common), &ca.key);
    (params.signed_by(&key, &issuer).unwrap(), key)
}

/// A node's certificate as kithd gives it: the name it is known by, and the server name `kith` checks.
fn node_cert(ca: &Ca, names: &[&str]) -> (rcgen::Certificate, KeyPair) {
    leaf(
        ca,
        names,
        vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
    )
}

/// An identity directory as `kith identity` leaves it: the CA, then NAME.crt and its 0600 NAME.key.
fn identity_dir(tag: &str, cluster: &Ca) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("remote-tls-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = leaf(
        cluster,
        &["laptop.user.kith"],
        vec![ExtendedKeyUsagePurpose::ClientAuth],
    );
    std::fs::write(dir.join("ca.crt"), cluster.cert.pem()).unwrap();
    std::fs::write(dir.join("laptop.crt"), cert.pem()).unwrap();
    std::fs::write(dir.join("laptop.key"), key.serialize_pem()).unwrap();
    std::fs::set_permissions(dir.join("laptop.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    dir
}

type Log = Arc<Mutex<Vec<String>>>;

/// What the fake kithd answers: a JSON body, a 101 that starts a tunnel (it echoes `hello`
/// and keeps what the client sends), or nothing at all, and no more connections.
enum Reply {
    Json(&'static str),
    Tunnel,
    Stop,
}

/// Reads one request: its request line and its body (Content-Length bytes). None if the
/// handshake or the read failed, which is a refused connection and not a request.
fn read_request(tls: &mut impl Read) -> Option<(String, String)> {
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tls.read(&mut one).ok()? == 0 {
            return None;
        }
        head.push(one[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    tls.read_exact(&mut body).ok()?;
    Some((
        head.lines().next()?.to_string(),
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

/// A kithd on 127.0.0.1 with `node` as its certificate. It asks clients for theirs, as kithd
/// does (`allow_unauthenticated`), and checks it against `cluster`. One connection at a time.
fn start(
    cluster: &Ca,
    node: &(rcgen::Certificate, KeyPair),
    mut answer: impl FnMut(&str, &str) -> Reply + Send + 'static,
) -> (SocketAddr, Log) {
    let mut roots = RootCertStore::empty();
    roots.add(cluster.cert.der().clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(node.1.serialize_der()));
    let config = Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![node.0.der().clone()], key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let log = Log::default();
    let seen = log.clone();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            let mut tls = StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), tcp);
            let Some((line, body)) = read_request(&mut tls) else {
                continue;
            };
            let who = tls.conn.peer_certificates().is_some();
            seen.lock().unwrap().push(format!("{line} cert={who} body={body}"));
            match answer(&line, &body) {
                Reply::Json(json) => {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        json.len()
                    );
                    let _ = tls.write_all(format!("{head}{json}").as_bytes());
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
                Reply::Tunnel => {
                    let _ = tls.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: kith-run\r\n\r\n",
                    );
                    let _ = tls.write_all(b"hello\n");
                    let _ = tls.flush();
                    let mut through = Vec::new();
                    let _ = tls.read_to_end(&mut through);
                    seen.lock()
                        .unwrap()
                        .push(format!("through {}", String::from_utf8_lossy(&through)));
                }
                Reply::Stop => break,
            }
        }
    });
    (addr, log)
}

/// `kith` pointed at `server` with the identity in `identity`, in this test's environment.
fn kith(identity: &Path, server: SocketAddr, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kith"))
        .env_remove("KITH_STORE")
        .env_remove("KITH_SOCKET")
        .arg("--server")
        .arg(server.to_string())
        .arg("--identity")
        .arg(identity)
        .args(["--timeout", "5"])
        .args(args)
        .output()
        .unwrap()
}

/// Writes a file the way cli.rs does: the text goes to a draft that is never run, and `cp`
/// (which forks nothing) copies it, so no other test's fork keeps the file open (ETXTBSY).
fn write_executable(path: &Path, text: &str) {
    let mut draft = path.to_path_buf().into_os_string();
    draft.push(".draft");
    std::fs::write(&draft, text).unwrap();
    let copied = Command::new("cp").arg(&draft).arg(path).status().unwrap();
    assert!(copied.success(), "cp of {}: {copied}", path.display());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// What `waypipe client` is here: answers the line it is sent, in capitals, after its tag.
const STAND_IN: &str = r#"#!/usr/bin/env python3
import socket, sys
args, tag = sys.argv[1:], b""
if args[0] == "--secctx":
    tag, args = args[1].encode() + b" ", args[2:]
if args[0] != "--socket" or args[2:] != ["client"]:
    sys.exit(3)
s = socket.socket(socket.AF_UNIX)
s.bind(args[1])
s.listen(1)
c, _ = s.accept()
c.sendall(tag + c.makefile("rb").readline().upper())
"#;

/// The stderr of a refused run, which must have printed nothing to stdout either.
fn refused(out: &Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "kith ran on a refused node: {err}");
    assert!(out.stdout.is_empty(), "{}", String::from_utf8_lossy(&out.stdout));
    err
}

#[test]
fn remote_tls_get_lists_over_the_node_certificate() {
    let cluster = ca("kith test cluster");
    let node = node_cert(&cluster, &["kith", "node1.node.kith"]);
    let (server, log) = start(&cluster, &node, |_, _| Reply::Json("[]"));
    let identity = identity_dir("get", &cluster);
    let out = kith(&identity, server, &["get"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "KIND  NAMESPACE  NAME  REVISION  STATUS\n"
    );
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|l| l.starts_with("GET /v1/resources") && l.contains("cert=true")),
        "{seen:?}"
    );
}

#[test]
fn remote_tls_apply_posts_the_resources() {
    let cluster = ca("kith test cluster");
    let node = node_cert(&cluster, &["kith", "node1.node.kith"]);
    let (server, log) = start(&cluster, &node, |_, _| Reply::Json("[]"));
    let identity = identity_dir("apply", &cluster);
    let file = identity.join("web.yaml");
    std::fs::write(
        &file,
        "apiVersion: kith.dev/v1\nkind: Workload\nmetadata: { name: web-config }\nspec:\n  template:\n    containers: [{ name: web, image: example/web }]\n",
    )
    .unwrap();
    let out = kith(&identity, server, &["apply", "-f", file.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|l| l.starts_with("POST /v1/apply ") && l.contains("web-config")),
        "{seen:?}"
    );
}

#[test]
fn remote_tls_logs_follow_reads_until_the_unit_is_done() {
    let cluster = ca("kith test cluster");
    let node = node_cert(&cluster, &["kith", "node1.node.kith"]);
    let (server, log) = start(&cluster, &node, |line, _| {
        if line.contains("offset=4") {
            Reply::Json(r#"{"data":"","next":4,"more":false}"#)
        } else {
            Reply::Json(r#"{"data":"one\n","next":4,"more":true}"#)
        }
    });
    let identity = identity_dir("logs", &cluster);
    let out = kith(&identity, server, &["logs", "Workload/web", "-f"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "one\n");
    assert_eq!(log.lock().unwrap().len(), 2);
}

#[test]
fn remote_tls_watch_says_when_kithd_stops() {
    let cluster = ca("kith test cluster");
    let node = node_cert(&cluster, &["kith", "node1.node.kith"]);
    let mut polls = 0;
    let (server, _log) = start(&cluster, &node, move |_, _| {
        polls += 1;
        match polls {
            1 | 2 => Reply::Json(r#"{"generation":1,"resources":[]}"#),
            _ => Reply::Stop,
        }
    });
    let identity = identity_dir("watch", &cluster);
    let out = kith(&identity, server, &["get", "--watch"]);
    // Every error kith reports exits 2; the stop is one of them.
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "KIND  NAMESPACE  NAME  REVISION  STATUS\n"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("kithd stopped"));
}

#[test]
fn remote_tls_run_joins_the_local_client_to_the_tunnel() {
    let cluster = ca("kith test cluster");
    let node = node_cert(&cluster, &["kith", "node1.node.kith"]);
    let (server, log) = start(&cluster, &node, |_, _| Reply::Tunnel);
    let identity = identity_dir("run", &cluster);
    let via = identity.join("standin");
    write_executable(&via, STAND_IN);
    let out = kith(
        &identity,
        server,
        &[
            "run",
            "--on",
            "role=display",
            "--via",
            via.to_str().unwrap(),
            "--",
            "true",
        ],
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|l| l.starts_with("POST /v1/run ") && l.contains("cert=true")),
        "{seen:?}"
    );
    // "hello" went through the tunnel to the client, which answered in capitals.
    assert!(seen.iter().any(|l| l == "through dev.kith.run HELLO\n"), "{seen:?}");
}

#[test]
fn remote_tls_ui_carries_a_101_tunnel() {
    let cluster = ca("kith test cluster");
    let node = node_cert(&cluster, &["kith", "node1.node.kith"]);
    let (server, log) = start(&cluster, &node, |_, _| Reply::Tunnel);
    let identity = identity_dir("ui", &cluster);
    let mut ui: Child = Command::new(env!("CARGO_BIN_EXE_kith"))
        .env_remove("KITH_STORE")
        .env_remove("KITH_SOCKET")
        .arg("--server")
        .arg(server.to_string())
        .arg("--identity")
        .arg(&identity)
        .args(["--timeout", "5", "ui"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The address to open is the one line on stdout: http://127.0.0.1:PORT/SECRET/ui/
    let mut first = String::new();
    let mut stdout = ui.stdout.take().unwrap();
    let mut byte = [0u8; 1];
    while !first.ends_with('\n') && stdout.read(&mut byte).unwrap() == 1 {
        first.push(byte[0] as char);
    }
    let rest = first
        .trim()
        .strip_prefix("http://127.0.0.1:")
        .unwrap_or_else(|| panic!("no address: {first}"));
    let mut parts = rest.split('/');
    let port: u16 = parts.next().unwrap().parse().unwrap();
    let secret = parts.next().unwrap().to_string();

    let mut browser = TcpStream::connect(("127.0.0.1", port)).unwrap();
    browser.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        browser,
        "POST /{secret}/v1/run HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: Upgrade\r\nUpgrade: kith-run\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
    )
    .unwrap();
    let mut reply = Vec::new();
    let mut buf = [0u8; 256];
    while !reply.ends_with(b"hello\n") {
        let n = browser.read(&mut buf).unwrap();
        assert!(
            n > 0,
            "the tunnel ended before hello: {}",
            String::from_utf8_lossy(&reply)
        );
        reply.extend_from_slice(&buf[..n]);
    }
    let reply = String::from_utf8_lossy(&reply).into_owned();
    ui.kill().unwrap();
    ui.wait().unwrap();

    assert!(reply.starts_with("HTTP/1.1 101 "), "{reply}");
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|l| l.starts_with("POST /v1/run ") && l.contains("cert=true")),
        "{seen:?}"
    );
}

#[test]
fn remote_tls_refuses_a_node_cert_from_another_ca() {
    let cluster = ca("kith test cluster");
    let other = ca("some other cluster");
    let node = node_cert(&other, &["kith", "node1.node.kith"]);
    let (server, log) = start(&cluster, &node, |_, _| Reply::Json("[]"));
    let identity = identity_dir("other-ca", &cluster);
    let err = refused(&kith(&identity, server, &["get"]));
    assert!(err.contains("certificate"), "{err}");
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn remote_tls_refuses_a_node_cert_for_another_name() {
    let cluster = ca("kith test cluster");
    let node = node_cert(&cluster, &["node1.node.kith"]);
    let (server, log) = start(&cluster, &node, |_, _| Reply::Json("[]"));
    let identity = identity_dir("other-name", &cluster);
    let err = refused(&kith(&identity, server, &["get"]));
    assert!(err.contains("certificate"), "{err}");
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn remote_tls_refuses_a_key_readable_by_others() {
    let cluster = ca("kith test cluster");
    let node = node_cert(&cluster, &["kith", "node1.node.kith"]);
    let (server, log) = start(&cluster, &node, |_, _| Reply::Json("[]"));
    let identity = identity_dir("readable", &cluster);
    std::fs::set_permissions(identity.join("laptop.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = refused(&kith(&identity, server, &["get"]));
    assert!(
        err.contains("readable by others") && err.contains("laptop.key"),
        "{err}"
    );
    assert!(log.lock().unwrap().is_empty());
}
