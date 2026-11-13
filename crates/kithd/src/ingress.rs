//! The way in from outside (`--ingress`, for edge nodes): HTTPS on port 443 for every
//! Service with `expose`, by the name the client asks for, passed on to the Service's
//! address on the mesh; and port 80, which answers ACME challenges and sends everything
//! else to HTTPS.
//!
//! A host's certificate and key are the Secret `tls-<host>` next to its Service
//! (`tls.crt`, `tls.key`). With `--acme`, a node that finds none (or one that runs out
//! soon) orders one and puts it there. Every node with `--ingress` answers the
//! challenge: the answer takes only the account's key, which is the Secret
//! `kith-system/acme-account`.
//
// ponytail: TLS ends here and the bytes go on as they are: no HTTP is read on 443, so the
// backend is not told who the client is (no X-Forwarded-For), and to a NetworkPolicy the
// connection comes from this node. Two nodes can order for one host at the same moment
// (both then get one; the later Secret stays). A connection is cut after a time with no
// byte either way, but one that trickles a byte inside that time keeps its place in the
// room (port 80 has no limit on how slowly a request may come, only on how many).
// Read HTTP here when a backend needs the client's address.

use crate::{Shared, acme};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use kith_api::Resource;
use kith_api::kinds::{Protocol, SecretSpec, ServiceSpec};
use kith_api::store::{Store, now};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::time::{Instant, Sleep};
use tokio_rustls::TlsAcceptor;

const ACCOUNT: &str = "Secret/kith-system/acme-account";
/// A host is asked a certificate for once in this many seconds at most, so that a setup
/// that cannot work does not use up what the authority allows.
const BETWEEN_ORDERS: u64 = 3600;
/// How many connections from outside at a time on each port; one over it is hung up on.
const CONNECTIONS: usize = 1024;
/// A connection on port 443 with no byte either way for this long is closed.
const IDLE: Duration = Duration::from_secs(300);
/// On port 80, where a request is small, this is all the time a connection gets,
/// bytes or no bytes: one that drips a byte now and then does not keep its place.
const IDLE_PLAIN: Duration = Duration::from_secs(30);

/// A host that is exposed: its Service, and where on the mesh that answers.
#[derive(Debug, Clone, PartialEq)]
pub struct Exposed {
    service: String,
    namespace: String,
    to: SocketAddr,
}

/// The exposed hosts, and the Services refused one: Service key to why. (Two Services
/// with one host: the first by key has it, the others are refused.)
pub fn exposed(store: &Store, prefix: Ipv6Addr) -> (BTreeMap<String, Exposed>, BTreeMap<String, String>) {
    let mut hosts: BTreeMap<String, Exposed> = BTreeMap::new();
    let mut refused = BTreeMap::new();
    for service in store.list(Some("Service")) {
        let Ok(spec) = serde_json::from_value::<ServiceSpec>(service.spec.clone()) else {
            continue;
        };
        let port = spec.ports.iter().find(|port| port.protocol != Some(Protocol::Udp));
        let (Some(expose), Some(port)) = (spec.expose, port) else {
            continue;
        };
        let key = service.key();
        let namespace = key.split('/').nth(1).unwrap_or_default();
        let address = kith_mesh::service_address(prefix, namespace, &service.metadata.name);
        let host = expose.host.to_ascii_lowercase();
        if let Some(first) = hosts.get(&host) {
            let message = format!("the host {host} is already exposed by {}", first.service);
            refused.insert(key, message);
            continue;
        }
        let to = SocketAddr::new(address.into(), port.port);
        let namespace = namespace.to_string();
        hosts.insert(
            host,
            Exposed {
                namespace,
                service: key,
                to,
            },
        );
    }
    (hosts, refused)
}

fn secret(store: &Store, key: &str) -> BTreeMap<String, String> {
    let spec = store.get(key).map(|secret| secret.spec.clone());
    let spec = spec.and_then(|spec| serde_json::from_value::<SecretSpec>(spec).ok());
    spec.map(|spec| spec.data).unwrap_or_default()
}

fn tls_secret(host: &str, exposed: &Exposed) -> String {
    format!("Secret/{}/tls-{host}", exposed.namespace)
}

/// One DER element at the start of `der`: its tag, what is in it, and what follows it.
fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let mut length = usize::from(first);
    if first >= 0x80 {
        let (bytes, after) = rest.split_at_checked(usize::from(first & 0x7f).min(5))?;
        length = bytes.iter().try_fold(0usize, |length, byte| {
            Some(length.checked_mul(256)? + usize::from(*byte))
        })?;
        rest = after;
    }
    let (inside, after) = rest.split_at_checked(length)?;
    Some((tag, inside, after))
}

/// A time in a certificate (`YYMMDDHHMMSSZ`, or with four digits of year) in seconds
/// since 1970.
fn time(tag: u8, text: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(text).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 => {
            let year: u64 = text.get(..2)?.parse().ok()?;
            (year + if year < 50 { 2000 } else { 1900 }, text.get(2..)?)
        }
        0x18 => (text.get(..4)?.parse().ok()?, text.get(4..)?),
        _ => return None,
    };
    let two = |at: usize| rest.get(at..at + 2)?.parse::<u64>().ok();
    let (month, day, hour, minute, second) = (two(0)?, two(2)?, two(4)?, two(6)?, two(8)?);
    if rest.len() != 10 || !(1..=12).contains(&month) || day == 0 {
        return None;
    }
    // (Days since 1970, with the year starting in March so the leap day comes last.)
    let year = if month <= 2 { year.checked_sub(1)? } else { year };
    let of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = year * 365 + year / 4 - year / 100 + year / 400 + of_year;
    Some(days.checked_sub(719_468)? * 86400 + hour * 3600 + minute * 60 + second)
}

/// From when until when the certificate `der` is good.
fn validity(der: &[u8]) -> Option<(u64, u64)> {
    let (_, certificate, _) = element(der)?;
    let (_, mut signed, _) = element(certificate)?;
    // The version (if it says), the serial number, the algorithm, the issuer: then it.
    let (tag, _, after) = element(signed)?;
    if tag == 0xa0 {
        signed = after;
    }
    for _ in 0..3 {
        signed = element(signed)?.2;
    }
    let (_, validity, _) = element(signed)?;
    let (tag, from, rest) = element(validity)?;
    let from = time(tag, from)?;
    let (tag, until, _) = element(rest)?;
    Some((from, time(tag, until)?))
}

/// Is a certificate good from `from` until `until` due for another one at `at`? Not
/// good yet, or in the last third of its time.
fn due(from: u64, until: u64, at: u64) -> bool {
    at < from || at >= until.saturating_sub(until.saturating_sub(from) / 3)
}

/// The certificates by host, for whoever says hello.
#[derive(Debug, Default)]
struct Certificates(Mutex<BTreeMap<String, Arc<CertifiedKey>>>);

impl ResolvesServerCert for Certificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name()?.to_ascii_lowercase();
        self.0.lock().ok()?.get(&host).cloned()
    }
}

#[derive(Default)]
struct Web {
    hosts: Mutex<BTreeMap<String, Exposed>>,
    thumbprint: Mutex<Option<String>>,
    certificates: Arc<Certificates>,
}

/// Port 80: the answer to an ACME challenge, or the way to HTTPS for a host we have.
async fn plain(State(web): State<Arc<Web>>, headers: HeaderMap, uri: Uri) -> Response {
    if let Some(token) = uri.path().strip_prefix("/.well-known/acme-challenge/") {
        let thumbprint = web.thumbprint.lock().expect("nothing panics holding it").clone();
        return match thumbprint.filter(|_| acme::token_like(token)) {
            Some(thumbprint) => acme::answer(token, &thumbprint).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let host = headers.get(header::HOST).and_then(|host| host.to_str().ok());
    let host = host.map(|host| host.split(':').next().unwrap_or(host).to_ascii_lowercase());
    let ours = |host: &String| web.hosts.lock().expect("nothing panics holding it").contains_key(host);
    match host.filter(ours) {
        Some(host) => {
            let path = uri.path_and_query().map_or("/", |path| path.as_str());
            let to = format!("https://{host}{path}");
            (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, to)]).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Connections that came in here and are a Service's: port 443 or 80 of a Service's own
/// address on the mesh. (Listening on a port of every address, as this does, leaves no
/// room for another listener on that port of one address.) The Service proxy takes them.
pub type Strays = mpsc::UnboundedSender<TcpStream>;

/// A connection that is closed once `idle` goes by with no byte read or written, and
/// that keeps its place in the room (if it has one) while it lasts.
struct Idle<T> {
    inner: T,
    timer: Pin<Box<Sleep>>,
    idle: Duration,
    /// Do bytes moved start the time over?
    renews: bool,
    _room: Option<OwnedSemaphorePermit>,
}

impl<T> Idle<T> {
    fn new(inner: T, idle: Duration, room: Option<OwnedSemaphorePermit>) -> Self {
        let timer = Box::pin(tokio::time::sleep(idle));
        Idle {
            inner,
            timer,
            idle,
            renews: true,
            _room: room,
        }
    }

    /// The same, but `life` is all it gets, idle or not.
    fn lasting(inner: T, life: Duration, room: Option<OwnedSemaphorePermit>) -> Self {
        Idle {
            renews: false,
            ..Idle::new(inner, life, room)
        }
    }

    /// Bytes moved start the time over; a poll that has to wait asks the time.
    fn watch<R>(&mut self, cx: &mut Context<'_>, polled: Poll<std::io::Result<R>>) -> Poll<std::io::Result<R>> {
        match polled {
            Poll::Ready(_) if self.renews => self.timer.as_mut().reset(Instant::now() + self.idle),
            Poll::Ready(_) => {}
            Poll::Pending if self.timer.as_mut().poll(cx).is_ready() => {
                return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
            }
            Poll::Pending => {}
        }
        polled
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Idle<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.watch(cx, polled)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Idle<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.watch(cx, polled)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A port open to everyone, less what is a Service's.
struct Door {
    listener: TcpListener,
    prefix: Ipv6Addr,
    me: Ipv6Addr,
    strays: Strays,
}

impl Door {
    async fn accept(&mut self) -> (TcpStream, SocketAddr) {
        loop {
            let Ok((stream, from)) = self.listener.accept().await else {
                // (Out of file descriptors, say: not in a tight loop.)
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            match stream.local_addr() {
                Ok(SocketAddr::V6(at)) if kith_mesh::in_mesh(self.prefix, *at.ip()) && *at.ip() != self.me => {
                    let _ = self.strays.send(stream);
                }
                _ => return (stream, from),
            }
        }
    }
}

/// Port 80 for axum: at most `CONNECTIONS` at a time, each cut when idle. (Past that, a
/// client is hung up on, as on port 443.)
struct Capped(Door, Arc<Semaphore>);

impl axum::serve::Listener for Capped {
    type Io = Idle<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Idle<TcpStream>, SocketAddr) {
        loop {
            let (stream, from) = self.0.accept().await;
            if let Ok(turn) = self.1.clone().try_acquire_owned() {
                return (Idle::lasting(stream, IDLE_PLAIN, Some(turn)), from);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.listener.local_addr()
    }
}

/// Port 443: TLS for the host asked for, then the bytes go to its Service and back.
async fn secure(mut door: Door, tls: TlsAcceptor, web: Arc<Web>) {
    let room = Arc::new(Semaphore::new(CONNECTIONS));
    loop {
        // (Accepting goes on when the room is full, for what is a Service's; a client
        // there is no room for is hung up on.)
        let (stream, _) = door.accept().await;
        let Ok(turn) = room.clone().try_acquire_owned() else {
            continue;
        };
        let (tls, web) = (tls.clone(), web.clone());
        tokio::spawn(async move {
            let _turn = turn;
            let stream = Idle::new(stream, IDLE, None);
            let hello = tokio::time::timeout(Duration::from_secs(10), tls.accept(stream));
            let Ok(Ok(mut client)) = hello.await else {
                return;
            };
            let host = client.get_ref().1.server_name().map(str::to_ascii_lowercase);
            let to = host.and_then(|host| Some(web.hosts.lock().ok()?.get(&host)?.to));
            let Some(to) = to else { return };
            let reached = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(to));
            if let Ok(Ok(service)) = reached.await {
                // (A Service that stops taking bytes does not hold the place either.)
                let mut service = Idle::new(service, IDLE, None);
                let _ = tokio::io::copy_bidirectional(&mut client, &mut service).await;
            }
        });
    }
}

/// What the store says now: the hosts, their certificates (and which are due for
/// another), and the account key if there is one.
fn look(store: &Store, prefix: Ipv6Addr, web: &Web) -> (Vec<(String, Exposed)>, Option<acme::Account>) {
    let hosts = exposed(store, prefix).0;
    let mut certificates = BTreeMap::new();
    let mut wanting = Vec::new();
    let at = now();
    for (host, exposed) in &hosts {
        let held = secret(store, &tls_secret(host, exposed));
        let read = held.get("tls.crt").zip(held.get("tls.key"));
        let read = read.and_then(|(chain, key)| crate::pki::certified(chain, key).ok());
        let good = read.as_ref().and_then(|read| validity(read.cert.first()?));
        if good.is_none_or(|(from, until)| due(from, until, at)) {
            wanting.push((host.clone(), exposed.clone()));
        }
        // (One that has run out is still shown: the client then says what is wrong.)
        if let Some(read) = read {
            certificates.insert(host.clone(), Arc::new(read));
        }
    }
    let key = secret(store, ACCOUNT).remove("key");
    let key = key.and_then(|key| BASE64.decode(key).ok());
    let account = key.and_then(|key| acme::Account::from_pkcs8(&key).ok());
    *web.hosts.lock().expect("nothing panics holding it") = hosts;
    *web.certificates.0.lock().expect("nothing panics holding it") = certificates;
    *web.thumbprint.lock().expect("nothing panics holding it") = account.as_ref().map(acme::Account::thumbprint);
    (wanting, account)
}

fn a_secret(key: &str, data: Value) -> Result<Resource, String> {
    let mut parts = key.split('/').skip(1);
    let (namespace, name) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    let secret = json!({
        "apiVersion": "kith.dev/v1", "kind": "Secret",
        "metadata": { "name": name, "namespace": namespace }, "spec": { "data": data },
    });
    let secret: Resource = serde_json::from_value(secret).map_err(|e| e.to_string())?;
    secret.validated()
}

async fn put(shared: &Shared, key: &str, data: Value) -> Result<(), String> {
    let command = kith_store::Command::Apply {
        resources: vec![a_secret(key, data)?],
        at: now(),
    };
    shared.submit(command).await.map(drop).map_err(|e| e.to_string())
}

/// Say in the Service's status how its certificate is coming along.
async fn say(shared: &Shared, service: &str, tls: Value) -> bool {
    let mut fields = serde_json::Map::new();
    fields.insert("tls".into(), tls);
    let statuses = vec![(service.to_string(), fields)];
    let said = shared.submit(kith_store::Command::Patch { statuses }).await;
    if let Err(e) = &said {
        eprintln!("kithd: ingress: writing the status of {service}: {e}");
    }
    said.is_ok()
}

/// Order a certificate for `host`, unless one was asked for within the hour.
async fn order(
    shared: &Shared,
    client: &reqwest::Client,
    directory: &str,
    account: &acme::Account,
    host: &str,
    of: &Exposed,
    tried: &mut BTreeMap<String, u64>,
) {
    let me = shared.members.me();
    // (Whatever the store says or cannot be told: this node asks once an hour at most.)
    if tried
        .get(host)
        .is_some_and(|tried| now().saturating_sub(*tried) < BETWEEN_ORDERS)
    {
        return;
    }
    let asked = {
        let state = shared.store.lock().expect("nothing panics holding the store");
        let status = state.store.get(&of.service).and_then(|service| service.status.clone());
        status.and_then(|status| status["tls"]["at"].as_u64())
    };
    if asked.is_some_and(|asked| now().saturating_sub(asked) < BETWEEN_ORDERS) {
        return;
    }
    tried.insert(host.to_string(), now());
    // A certificate there would be nowhere to keep is not asked for.
    if let Err(e) = a_secret(&tls_secret(host, of), json!({})) {
        let message = format!("the host's Secret cannot be named: {e}");
        say(
            shared,
            &of.service,
            json!({ "state": "error", "message": message, "by": me, "at": now() }),
        )
        .await;
        return;
    }
    // Nor one that the store cannot be told was asked for: the next try would not know.
    if !say(
        shared,
        &of.service,
        json!({ "state": "ordering", "by": me, "at": now() }),
    )
    .await
    {
        return;
    }
    eprintln!("kithd: ingress: asking {directory} for a certificate for {host}");
    let ordered = match acme::order(client, directory, account, host).await {
        Ok((chain, key)) => {
            let secret = tls_secret(host, of);
            put(shared, &secret, json!({ "tls.crt": chain, "tls.key": key })).await
        }
        Err(e) => Err(e),
    };
    let tls = match ordered {
        Ok(()) => json!({ "state": "ready", "by": me, "at": now() }),
        Err(e) => {
            eprintln!("kithd: ingress: no certificate for {host}: {e}");
            json!({ "state": "error", "message": e, "by": me, "at": now() })
        }
    };
    say(shared, &of.service, tls).await;
}

/// Serve ports 443 and 80 until told to stop; with `acme` (a directory URL), order the
/// certificates that are missing.
pub async fn run(shared: Arc<Shared>, acme: Option<String>, strays: Strays, mut stopping: watch::Receiver<bool>) {
    let Some(cluster) = &shared.cluster else { return };
    let prefix = crate::mesh::prefix(&cluster.me.ca);
    let web = Arc::new(Web::default());
    let any = |port: u16| SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port);
    let (https, http) = match (TcpListener::bind(any(443)).await, TcpListener::bind(any(80)).await) {
        (Ok(https), Ok(http)) => (https, http),
        (Err(e), _) | (_, Err(e)) => {
            return eprintln!("kithd: no ingress: ports 443 and 80: {e} (binding them takes CAP_NET_BIND_SERVICE)");
        }
    };
    let tls = match crate::pki::ingress_config(web.certificates.clone()) {
        Ok(tls) => TlsAcceptor::from(tls),
        Err(e) => return eprintln!("kithd: no ingress: {e}"),
    };
    let me = kith_mesh::node_address(prefix, shared.members.me());
    let door = |listener| Door {
        listener,
        prefix,
        me,
        strays: strays.clone(),
    };
    let (https, http) = (door(https), door(http));
    let secure = tokio::spawn(secure(https, tls, web.clone()));
    let router = axum::Router::new().fallback(plain).with_state(web.clone());
    let http = Capped(http, Arc::new(Semaphore::new(CONNECTIONS)));
    let plain = tokio::spawn(async move {
        let _ = axum::serve(http, router).await;
    });
    eprintln!("kithd: ingress on ports 443 and 80");

    // (reqwest's TLS wants to be told once which crypto to use.)
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(30)).build() {
        Ok(client) => client,
        Err(e) => return eprintln!("kithd: no ingress: {e}"),
    };
    let mut generation = shared.generation.subscribe();
    let mut tried = BTreeMap::new();
    loop {
        let (wanting, account) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            look(&state.store, prefix, &web)
        };
        if let Some(directory) = acme.as_deref().filter(|_| !wanting.is_empty()) {
            let orders = async {
                match account {
                    // (Made now, used from the next look on: by then every node has it,
                    // or another node's, if two made one at once.)
                    None => {
                        let made = acme::Account::generate().map(|key| json!({ "key": BASE64.encode(key) }));
                        let put = match made {
                            Ok(data) => put(&shared, ACCOUNT, data).await,
                            Err(e) => Err(e),
                        };
                        if let Err(e) = put {
                            eprintln!("kithd: ingress: keeping an ACME account key: {e}");
                        }
                    }
                    Some(account) => {
                        for (host, of) in &wanting {
                            order(&shared, &client, directory, &account, host, of, &mut tried).await;
                        }
                    }
                }
            };
            tokio::select! {
                () = orders => {}
                _ = stopping.changed() => break,
            }
        }
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = stopping.changed() => break,
        }
    }
    secure.abort();
    plain.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_certificate_times() {
        let mut store = Store::default();
        let source = "apiVersion: kith.dev/v1\nkind: Service\nmetadata: { name: web, namespace: shop }\nspec:\n  \
                      selector: { app: web }\n  ports: [{ port: 53, protocol: udp }, { port: 8080 }]\n  \
                      expose: { host: Shop.Example.org, via: edge }\n---\n\
                      apiVersion: kith.dev/v1\nkind: Service\nmetadata: { name: inner }\nspec:\n  \
                      selector: { app: inner }\n  ports: [{ port: 80 }]\n";
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let prefix = kith_mesh::prefix(b"ca");
        let (hosts, refused) = exposed(&store, prefix);
        assert!(refused.is_empty());
        let to = SocketAddr::new(kith_mesh::service_address(prefix, "shop", "web").into(), 8080);
        assert_eq!(hosts.len(), 1);
        let shop = &hosts["shop.example.org"];
        assert_eq!((shop.service.as_str(), shop.to), ("Service/shop/web", to));
        assert_eq!(tls_secret("shop.example.org", shop), "Secret/shop/tls-shop.example.org");
        assert!(a_secret("Secret/shop/tls-shop.example.org", json!({ "tls.crt": "c" })).is_ok());

        // A certificate says from when until when; another is due in its last third.
        let mut params = rcgen::CertificateParams::new(vec!["shop.example.org".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 3, 1);
        params.not_after = rcgen::date_time_ymd(2026, 5, 30);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let (from, until) = validity(certificate.der()).unwrap();
        // (1 March 2026 and 30 May 2026, 90 days on.)
        assert_eq!((from, until), (1_772_323_200, 1_772_323_200 + 90 * 86400));
        assert!(due(from, until, from - 1) && !due(from, until, from + 59 * 86400));
        assert!(due(from, until, from + 60 * 86400) && due(from, until, until + 1));
        let read = crate::pki::certified(&certificate.pem(), &key.serialize_pem()).unwrap();
        assert_eq!(validity(&read.cert[0]), Some((from, until)));
        assert!(
            crate::pki::certified(&certificate.pem(), &rcgen::KeyPair::generate().unwrap().serialize_pem()).is_err()
        );

        // Port 80: a challenge's answer once there is an account, HTTPS for a host we
        // have, nothing for anyone else.
        let web = Arc::new(Web::default());
        *web.hosts.lock().unwrap() = hosts;
        let ask = |host: &'static str, path: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, host.parse().unwrap());
            let reply = plain(State(web.clone()), headers, path.parse().unwrap());
            let reply = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(reply);
            let to = reply
                .headers()
                .get(header::LOCATION)
                .map(|to| to.to_str().unwrap().to_string());
            (reply.status().as_u16(), to)
        };
        let moved = ask("Shop.Example.org:80", "/a?b=1");
        assert_eq!(moved, (308, Some("https://shop.example.org/a?b=1".into())));
        assert_eq!(ask("evil.example", "/a"), (404, None));
        let challenge = "/.well-known/acme-challenge/tok";
        assert_eq!(ask("shop.example.org", challenge).0, 404);
        *web.thumbprint.lock().unwrap() = Some("print".into());
        assert_eq!(ask("anything", challenge).0, 200);
        assert_eq!(ask("anything", "/.well-known/acme-challenge/a%3Cb").0, 404);

        assert_eq!(time(0x17, b"700101000001Z"), Some(1));
        assert_eq!(time(0x18, b"20000229120000Z"), Some(951_825_600));
        assert_eq!(time(0x17, b"491231235959Z"), Some(2_524_607_999));
        assert_eq!(time(0x17, b"7001010000Z"), None);
        assert_eq!(validity(b"\x30\x03\x30\x01"), None);
        assert_eq!(validity(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), None);
    }

    #[test]
    fn a_second_service_on_one_host_is_refused() {
        let mut store = Store::default();
        let service = |name: &str, host: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: {name} }}\nspec:\n  \
                 selector: {{ app: {name} }}\n  ports: [{{ port: 80 }}]\n  expose: {{ host: {host}, via: edge }}\n---\n"
            )
        };
        // (Applied last to first: the key decides, not the order.)
        let source = [
            service("b", "Shop.example.org"),
            service("c", "other.example.org"),
            service("a", "shop.example.org"),
        ];
        for resource in Resource::from_source(&source.concat()).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let (hosts, refused) = exposed(&store, kith_mesh::prefix(b"ca"));
        assert_eq!(hosts["shop.example.org"].service, "Service/default/a");
        assert_eq!(hosts["other.example.org"].service, "Service/default/c");
        let said = "the host shop.example.org is already exposed by Service/default/a";
        assert_eq!(
            refused,
            BTreeMap::from([("Service/default/b".to_string(), said.to_string())])
        );
    }

    #[tokio::test]
    async fn an_idle_connection_is_cut_and_one_that_moves_bytes_is_not() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (ours, mut theirs) = tokio::io::duplex(64);
        let (mut read, mut write) = tokio::io::split(Idle::new(ours, Duration::from_secs(2), None));
        let reader = tokio::spawn(async move { read.read_u8().await });
        // Bytes written to the client keep it open past the idle time...
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            write.write_all(b"x").await.unwrap();
            assert!(!reader.is_finished());
        }
        // ...and then nothing for the time cuts it.
        let cut = tokio::time::timeout(Duration::from_secs(10), reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cut.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(theirs.read_u8().await.unwrap(), b'x');

        // On port 80 bytes buy no time.
        let (ours, _theirs) = tokio::io::duplex(64);
        let (mut read, mut write) = tokio::io::split(Idle::lasting(ours, Duration::from_millis(300), None));
        let reader = tokio::spawn(async move { read.read_u8().await });
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = write.write_all(b"x").await;
        }
        assert_eq!(reader.await.unwrap().unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn port_80_takes_so_many_connections_at_a_time() {
        use axum::serve::Listener;
        use tokio::io::AsyncReadExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let (strays, _kept) = mpsc::unbounded_channel();
        let me = Ipv6Addr::LOCALHOST;
        let door = Door {
            listener,
            prefix: kith_mesh::prefix(b"ca"),
            me,
            strays,
        };
        let mut capped = Capped(door, Arc::new(Semaphore::new(1)));
        let first = TcpStream::connect(at).await.unwrap();
        let (held, _) = capped.accept().await;
        // With the room full, the next client is hung up on, and the one after it, with
        // the room free again, is taken.
        let mut second = TcpStream::connect(at).await.unwrap();
        let next = tokio::spawn(async move {
            let taken = capped.accept().await;
            (capped, taken)
        });
        let hung_up = tokio::time::timeout(Duration::from_secs(5), second.read_u8())
            .await
            .unwrap();
        assert!(hung_up.is_err());
        drop(held);
        let _third = TcpStream::connect(at).await.unwrap();
        let (_, (taken, _)) = tokio::time::timeout(Duration::from_secs(5), next)
            .await
            .unwrap()
            .unwrap();
        drop((taken, first));
    }
}
