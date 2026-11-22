//! The way in from outside (`--ingress`, for edge nodes): HTTPS on port 443 for every
//! Service with `expose`, by the name the client asks for, passed on to the Service's
//! address on the mesh; and port 80, which answers ACME challenges and sends everything
//! else to HTTPS.
//!
//! A host's certificate and key are the Secret `tls-<host>` next to its Service
//! (`tls.crt`, `tls.key`). With `--acme`, a control node that finds none (or one that runs
//! out soon) orders one and puts it there: one that serves ingress itself, and the leader
//! while a worker does. Every node with `--ingress` answers the challenge, with the
//! thumbprint of the account (whose key is the Secret `kith-system/acme-account`, which
//! only control nodes hold); a worker reads it from the ConfigMap `kith-system/acme`, in
//! the view it is sent with the `tls-` Secrets of the exposed hosts.
//
// ponytail: TLS ends here and, for a host without `paths` or `headers`, the bytes go on
// as they are: no HTTP is read, so there is no X-Forwarded-For; a Service that asks
// (`expose.proxyProtocol`) gets the client's address in a PROXY v1 line instead. A host
// with either is read request by request with hyper (its parser, its framing, its
// limits) and each request is sent on by hyper's client, so a backend only ever sees
// requests framed by kith. Either way, to a NetworkPolicy the connection comes from this
// node, to a Service's address, as any other: the Service's proxy decides. Two nodes can order for one host at the same moment
// (both then get one; the later Secret stays). A connection is cut after a time with no
// byte either way, but one that trickles a byte inside that time keeps its place in the
// room (port 80 has no limit on how slowly a request may come, only on how many). A source
// (an IPv4 address, an IPv6 /64) holds at most `PER_SOURCE` of a port's places: many
// clients behind one NAT share that.

use crate::{Shared, acme};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri, Version, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::{TokioIo, TokioTimer};
use kith_api::Resource;
use kith_api::kinds::{NamespaceSpec, Protocol, SecretSpec, ServiceSpec};
use kith_api::store::{Store, now};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::time::{Instant, Sleep};
use tokio_rustls::TlsAcceptor;

pub(crate) const ACCOUNT: &str = "Secret/kith-system/acme-account";
/// The ConfigMap (namespace and name) with the account's thumbprint, which a challenge is
/// answered with: what a worker that serves ingress has of the account.
pub(crate) const THUMBPRINT: &str = "kith-system/acme";
/// A host is asked a certificate for once in this many seconds at most, so that a setup
/// that cannot work does not use up what the authority allows.
const BETWEEN_ORDERS: u64 = 3600;
/// How long the leader waits on an ingress worker that does not say its view holds the account's
/// thumbprint (one that hangs, or was taken, never says it) before it orders anyway.
const WAIT_AT_MOST: u64 = 600;
/// How long a leader waits for its linearizable read before a term's first order: past it the round
/// orders nothing, and the read is tried again at the next look.
const READ_AT_MOST: Duration = Duration::from_secs(30);

/// The seconds between two orders for a host: shorter where the last was asked while a worker
/// had not said it holds the thumbprint, so that worker's 404 holds the host up less (four
/// tries an hour: an authority allows about five failed ones for a host, Let's Encrypt five).
fn between(hurried: bool) -> u64 {
    if hurried { 900 } else { BETWEEN_ORDERS }
}

/// Whether a host was asked for within `between` seconds at `now`: by this process (`tried_at`), or
/// as the store says (`store_at`, the Service's status `tls.at`, written before the ACME call, so it
/// holds across a leader change, where `tried` starts empty).
fn asked_lately(tried_at: Option<u64>, store_at: Option<u64>, now: u64, between: u64) -> bool {
    [tried_at, store_at]
        .into_iter()
        .flatten()
        .any(|at| now.saturating_sub(at) < between)
}

/// Whether orders still wait on `waits`, the ingress workers that have not said their view holds
/// the thumbprint, at `now`: up to [`WAIT_AT_MOST`] from when this wait began (`since`).
fn holds_up(since: &mut Option<u64>, waits: &[String], now: u64) -> bool {
    if waits.is_empty() {
        *since = None;
        return false;
    }
    now.saturating_sub(*since.get_or_insert(now)) < WAIT_AT_MOST
}
/// How many connections from outside at a time on each port; one over it is hung up on.
const CONNECTIONS: usize = 1024;
/// How many of them one source may hold at a time on a port (a source: an IPv4 address,
/// or the /64 of an IPv6 one).
const PER_SOURCE: usize = 64;
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
    /// Does the backend want the PROXY protocol line (`expose.proxyProtocol`)?
    proxy: bool,
    /// Requests by their path (`expose.paths`), each to a Service of `namespace`.
    routes: Vec<Route>,
    /// Set on each request (`expose.headers`).
    headers: Vec<(HeaderName, HeaderValue)>,
}

/// Where requests under one path go.
#[derive(Debug, Clone, PartialEq)]
struct Route {
    /// For a prefix, without its last `/` (so `/` is ``).
    path: String,
    exact: bool,
    to: SocketAddr,
}

impl Exposed {
    /// Is HTTP read on this host's connections, or are their bytes carried as they are?
    fn reads_http(&self) -> bool {
        !self.routes.is_empty() || !self.headers.is_empty()
    }

    /// Where a request for `path` goes, if anywhere. The path is matched as the client
    /// sent it, byte for byte: nothing decoded, no `..` or `//` folded, so no way of
    /// writing one path reaches another's Service. (`/app` fits `/app` and `/app/x`, not
    /// `/application`; of those that fit the longest wins, and an exact one over a
    /// prefix as long.)
    fn route(&self, path: &str) -> Option<SocketAddr> {
        if !path.starts_with('/') {
            return None;
        }
        if self.routes.is_empty() {
            return Some(self.to);
        }
        let fits = |route: &&Route| match route.exact {
            true => path == route.path,
            false => path
                .strip_prefix(route.path.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/')),
        };
        let best = self
            .routes
            .iter()
            .filter(fits)
            .max_by_key(|route| (route.path.len(), route.exact));
        best.map(|route| route.to)
    }
}

/// The exposed hosts, and the Services refused one: Service key to why. (Two Services
/// with one host: the older has it, the others are refused; one name for a host no
/// certificate authority issues for is refused too; and so is a host some Namespace
/// keeps for itself, or one a Namespace that keeps any does not name.)
//
// ponytail: two Namespaces that keep the same host both expose it (the older Service
// has it): the people who write Namespaces are the cluster's own. Refuse the second
// Namespace when it is applied if that is ever not so.
// "Older" is by when the store says a Service was first made (`Store::born`: the log's
// entry, so every node agrees and no clock says it), whatever is edited or trimmed after.
// In a store not marked yet (a member's kithd is from before), and for a Service there was
// before the mark, it is the time of the oldest revision kept, as it was: one edited more
// than `HISTORY_LIMIT` times before the mark looked as new as its oldest kept edit then.
pub fn exposed(store: &Store, prefix: Ipv6Addr) -> (BTreeMap<String, Exposed>, BTreeMap<String, String>) {
    exposed_in(store, prefix, false)
}

/// [`exposed`], of a worker's view (`view`) or of the store.
fn exposed_in(store: &Store, prefix: Ipv6Addr, view: bool) -> (BTreeMap<String, Exposed>, BTreeMap<String, String>) {
    let mut hosts: BTreeMap<String, Exposed> = BTreeMap::new();
    let mut refused = BTreeMap::new();
    let born = |service: &Resource| {
        let key = service.key();
        let oldest = || {
            let kept = store.history(&key).ok();
            (0, kept.and_then(|kept| kept.first()).map_or(u64::MAX, |first| first.at))
        };
        store.born(&key).unwrap_or_else(oldest)
    };
    let kept = store.list(Some("Namespace")).filter_map(|namespace| {
        let spec = serde_json::from_value::<NamespaceSpec>(namespace.spec.clone()).ok()?;
        (!spec.hosts.is_empty()).then_some((namespace.metadata.name.as_str(), spec))
    });
    let kept: BTreeMap<&str, NamespaceSpec> = kept.collect();
    let mut services: Vec<&Resource> = store.list(Some("Service")).collect();
    // (Stable: of the same age, by key.)
    services.sort_by_key(|service| born(service));
    if view {
        // A view keeps no history (a Service in it is as old as its last change), so there the
        // store's own word goes first: a Service the leader's status says was refused is last.
        let said_refused = |service: &&Resource| {
            let status = service.status.as_ref();
            status.is_some_and(|status| status["expose"]["state"] == "refused")
        };
        services.sort_by_key(said_refused);
        // And one it has not reported on yet (no `address`) is not served where another
        // claims its host: which came first is the leader's word, not this view's.
        let host = |service: &Resource| service.spec["expose"]["host"].as_str().map(str::to_ascii_lowercase);
        let mut claims: BTreeMap<String, usize> = BTreeMap::new();
        for claimed in services.iter().filter_map(|service| host(service)) {
            *claims.entry(claimed).or_default() += 1;
        }
        let unreported = |service: &Resource| service.status.as_ref().is_none_or(|status| status["address"].is_null());
        services.retain(|service| !unreported(service) || host(service).is_none_or(|claimed| claims[&claimed] < 2));
    }
    for service in services {
        let Ok(spec) = serde_json::from_value::<ServiceSpec>(service.spec.clone()) else {
            continue;
        };
        let port = spec.ports.iter().find(|port| port.protocol != Some(Protocol::Udp));
        let (Some(expose), Some(port)) = (spec.expose, port) else {
            continue;
        };
        let key = service.key();
        // (A headless Service has no address to send a host to: its name answers its replicas.
        // Refused at apply; one a store kept from before that check is refused here too.)
        if crate::services::headless(service) {
            refused.insert(
                key,
                "a headless Service has no address to expose: its name answers its replicas".to_string(),
            );
            continue;
        }
        let namespace = key.split('/').nth(1).unwrap_or_default();
        let address = kith_mesh::service_address(prefix, namespace, &service.metadata.name);
        let host = expose.host.to_ascii_lowercase();
        if let Some(message) = kith_api::kinds::expose_host_refused(&host) {
            refused.insert(key, message);
            continue;
        }
        let kept_for = match kept.get(namespace) {
            Some(own) if own.keeps(&host) => None,
            Some(own) => Some(format!(
                "the namespace {namespace} exposes only its Namespace's hosts ({}), and {host} is not one",
                own.hosts.join(", ").to_ascii_lowercase()
            )),
            None => kept
                .iter()
                .find(|(_, other)| other.keeps(&host))
                .map(|(other, _)| format!("the host {host} is kept for the namespace {other} (its Namespace's hosts)")),
        };
        if let Some(message) = kept_for {
            refused.insert(key, message);
            continue;
        }
        if let Some(first) = hosts.get(&host) {
            let message = format!("the host {host} is already exposed by {}", first.service);
            refused.insert(key, message);
            continue;
        }
        let to = SocketAddr::new(address.into(), port.port);
        let proxy = expose.proxy_protocol == Some(true);
        // (Only ever a Service of the exposing one's namespace: the name is all a path says.)
        let routes: Vec<Route> = expose
            .paths
            .iter()
            .map(|route| {
                let exact = route.exact == Some(true);
                Route {
                    path: kith_api::kinds::exposed_prefix(&route.path, exact).to_string(),
                    exact,
                    to: SocketAddr::new(
                        kith_mesh::service_address(prefix, namespace, &route.service).into(),
                        route.port,
                    ),
                }
            })
            .collect();
        // (Checked when applied: one that is not a header is not there.)
        let headers = expose.headers.iter().filter_map(|(name, value)| {
            Some((
                HeaderName::try_from(name.as_str()).ok()?,
                HeaderValue::try_from(value.as_str()).ok()?,
            ))
        });
        let namespace = namespace.to_string();
        hosts.insert(
            host,
            Exposed {
                namespace,
                service: key,
                to,
                proxy,
                routes,
                headers: headers.collect(),
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

pub(crate) fn tls_secret(host: &str, exposed: &Exposed) -> String {
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

/// Is what an authority gave worth keeping at `at`: `host`'s, with its key, and not due
/// for another at once (one that has run out, or is not good yet, would be served instead
/// of the one held).
fn fresh(chain: &str, key: &str, host: &str, at: u64) -> bool {
    let read = crate::pki::certified(chain, key, host).ok();
    let good = read.and_then(|read| validity(read.cert.first()?));
    good.is_some_and(|(from, until)| !due(from, until, at))
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

/// How many connections are held at a time, in all and by each source.
#[derive(Clone)]
pub struct Limits {
    pub(crate) room: Arc<Semaphore>,
    pub(crate) sources: Arc<Mutex<BTreeMap<IpAddr, usize>>>,
    per_source: usize,
    /// How much of an IPv6 address is one source.
    bits: u32,
}

/// One connection's place under the `Limits`; given back when dropped.
pub struct Place {
    _room: OwnedSemaphorePermit,
    source: IpAddr,
    sources: Arc<Mutex<BTreeMap<IpAddr, usize>>>,
}

impl Limits {
    pub fn new(connections: usize, per_source: usize) -> Self {
        Limits {
            room: Arc::new(Semaphore::new(connections)),
            sources: Arc::default(),
            per_source,
            bits: 64,
        }
    }

    /// For callers on the mesh: a source is a node, which has a /80 of it.
    pub fn per_node(self) -> Self {
        Limits { bits: 80, ..self }
    }

    /// For the people: a source is one address, whole (a peer has an address of its own, and
    /// the peers of one /64 are not one).
    pub fn per_address(self) -> Self {
        Limits { bits: 128, ..self }
    }

    /// A place for a connection from `from`, unless it or its source has none left.
    pub fn take(&self, from: IpAddr) -> Option<Place> {
        // (A client of IPv6 has a /64 to itself: its addresses are one source. A v4
        // client of the dual-stack socket shows as a mapped address.)
        let source = match from.to_canonical() {
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (u128::MAX << (128 - self.bits)))),
            ip => ip,
        };
        let mut sources = self.sources.lock().expect("nothing panics holding the sources");
        let held = sources.entry(source).or_default();
        if *held >= self.per_source {
            return None;
        }
        // (Not until the source is known to be under its limit, nor left counted if the
        // room is full: the count only holds what is held, so the map is no bigger than
        // the room.)
        let Ok(room) = self.room.clone().try_acquire_owned() else {
            if *held == 0 {
                sources.remove(&source);
            }
            return None;
        };
        *held += 1;
        Some(Place {
            _room: room,
            source,
            sources: self.sources.clone(),
        })
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut sources = self.sources.lock().expect("nothing panics holding the sources");
        if let Some(held) = sources.get_mut(&self.source) {
            *held -= 1;
            if *held == 0 {
                sources.remove(&self.source);
            }
        }
    }
}

/// A connection that is closed once `idle` goes by with no byte read or written, and
/// that keeps its place in the room (if it has one) while it lasts.
pub struct Idle<T> {
    inner: T,
    timer: Pin<Box<Sleep>>,
    idle: Duration,
    /// Do bytes moved start the time over?
    renews: bool,
    _room: Option<Place>,
}

impl<T> Idle<T> {
    pub fn new(inner: T, idle: Duration, room: Option<Place>) -> Self {
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
    fn lasting(inner: T, life: Duration, room: Option<Place>) -> Self {
        Idle {
            renews: false,
            ..Idle::new(inner, life, room)
        }
    }

    /// Starts the time over, as if a byte had moved now.
    pub fn renew(&mut self) {
        self.timer.as_mut().reset(Instant::now() + self.idle);
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
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        self.watch(cx, polled)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.watch(cx, polled)
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

/// Port 80 for axum: at most `CONNECTIONS` at a time (`PER_SOURCE` from one source),
/// each cut when idle. (Past that, a client is hung up on, as on port 443.)
struct Capped(Door, Limits);

impl axum::serve::Listener for Capped {
    type Io = Idle<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Idle<TcpStream>, SocketAddr) {
        loop {
            let (stream, from) = self.0.accept().await;
            if let Some(turn) = self.1.take(from.ip()) {
                return (Idle::lasting(stream, IDLE_PLAIN, Some(turn)), from);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.listener.local_addr()
    }
}

/// The PROXY protocol v1 line for a client `from` that reached us at `to`. (A client
/// of one address family at an address of the other is `UNKNOWN`, which the protocol
/// allows: the backend then takes the connection as it is.)
fn proxy_line(from: SocketAddr, to: SocketAddr) -> String {
    match (from.ip().to_canonical(), to.ip().to_canonical()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => format!("PROXY TCP4 {src} {dst} {} {}\r\n", from.port(), to.port()),
        (IpAddr::V6(src), IpAddr::V6(dst)) => format!("PROXY TCP6 {src} {dst} {} {}\r\n", from.port(), to.port()),
        _ => "PROXY UNKNOWN\r\n".to_string(),
    }
}

/// Bytes both ways between the client and the Service; with a `line`, the Service gets
/// it first, before any byte of the client's.
async fn carry<C, S>(client: &mut C, service: &mut S, line: Option<String>)
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(line) = line
        && service.write_all(line.as_bytes()).await.is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(client, service).await;
}

/// A connection to a Service's address, cut when nothing moves on it for `IDLE`. (The
/// Service's proxy on this node takes it, and its NetworkPolicy decides, as for any other.)
async fn reach(to: SocketAddr) -> Option<Idle<TcpStream>> {
    let reached = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(to)).await;
    Some(Idle::new(reached.ok()?.ok()?, IDLE, None))
}

/// The connection on to a Service a client's connection keeps between its requests, and
/// where it goes.
type Kept = Mutex<Option<(SocketAddr, SendRequest<Body>)>>;

/// Headers that are a connection's own, not the message's: never passed on.
const HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Is `name` (lower case, as hyper has it) a header a client does not say for itself: where
/// a request is from, or what a backend may read as that? One with `_` in it too, as nginx
/// drops them: CGI, WSGI and Rack read `X_Forwarded_For` and `X-Forwarded-For` as one name.
fn forged(name: &str) -> bool {
    const FROM: [&str; 5] = [
        "forwarded",
        "x-real-ip",
        "x-client-ip",
        "x-original-url",
        "x-rewrite-url",
    ];
    name.contains('_') || name.starts_with("x-forwarded-") || FROM.contains(&name)
}

/// Takes out of `headers` what is the connection's: those always, and what `Connection`
/// names. (`Expect` too: hyper has answered it already.)
fn unhop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::try_from(name.trim()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP {
        headers.remove(name);
    }
    headers.remove(header::EXPECT);
}

/// A host read as HTTP, its client's requests one by one. hyper reads them: a request it
/// cannot frame one way only (`Content-Length` twice and different, a folded or NUL
/// header, `Transfer-Encoding` that does not end in chunked) is answered 400 and goes
/// nowhere. One with both `Content-Length` and chunked is read as chunked and the
/// connection closed after it (RFC 9112 6.3): what follows it is never read as a request.
async fn serve<C>(client: C, from: SocketAddr, host: String, of: Exposed, turn: Place)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let of = Arc::new((of, host, Kept::default(), turn));
    let service = hyper::service::service_fn(move |request| {
        let of = of.clone();
        async move { Ok::<_, std::convert::Infallible>(pass(request, from, of).await) }
    });
    // ponytail: hyper's limits: 100 headers (431 past that), a request's head within about
    // 64 KiB (`max_buf_size`, looked at between reads; 431 past it) and within 30 seconds
    // of starting to read it (from the connection's start or the end of the last answer);
    // the connection's own idle time (`IDLE`, under TLS) ends one that says nothing between.
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .max_buf_size(64 * 1024);
    let _ = http
        .serve_connection(TokioIo::new(client), service)
        .with_upgrades()
        .await;
}

/// One request: to the Service its path names, as the client sent its path, with the
/// headers kith sets in place of any the client sent by those names; the answer back.
/// A body goes on as it comes, both ways; after a 101, so do the bytes. `connection`: the
/// host, where its last request went, and the client's place under the `Limits`.
async fn pass(
    mut request: Request<Incoming>,
    from: SocketAddr,
    connection: Arc<(Exposed, String, Kept, Place)>,
) -> Response {
    let (of, host, kept, _) = &*connection;
    let to = (request.method() != Method::CONNECT)
        .then(|| of.route(request.uri().path()))
        .flatten();
    let Some(to) = to else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // (A WebSocket only: any other protocol a backend switched to, h2c for one, would be
    // requests kith no longer reads, past the paths and the headers.)
    let upgrade = request.headers().get(header::UPGRADE);
    let upgrade = upgrade
        .filter(|to| to.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .cloned();
    let client = upgrade.is_some().then(|| hyper::upgrade::on(&mut request));
    let (mut parts, body) = request.into_parts();
    // (Origin form, whatever the client wrote: a host in the target is not ours to follow.)
    let target = parts.uri.path_and_query().cloned();
    let Some(target) = target else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    parts.uri = Uri::from(target);
    parts.version = Version::HTTP_11;
    let headers = &mut parts.headers;
    unhop(headers);
    let theirs: Vec<HeaderName> = headers.keys().filter(|name| forged(name.as_str())).cloned().collect();
    for name in theirs {
        headers.remove(name);
    }
    let said = |text: &str| HeaderValue::try_from(text).ok();
    let ours = [
        (header::HOST, said(host)),
        (
            HeaderName::from_static("x-forwarded-for"),
            said(&from.ip().to_canonical().to_string()),
        ),
        (HeaderName::from_static("x-forwarded-proto"), said("https")),
        (HeaderName::from_static("x-forwarded-host"), said(host)),
    ];
    for (name, value) in ours {
        // (In place of what the client said: `insert`, not `append`.)
        headers.remove(&name);
        if let Some(value) = value {
            headers.insert(name, value);
        }
    }
    for (name, value) in &of.headers {
        headers.insert(name, value.clone());
    }
    if let Some(upgrade) = upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, upgrade);
    }
    let mut request = Request::from_parts(parts, Body::new(body));

    // The connection kept from the last request if it goes to the same place and is open,
    // else a new one. One kept may have been closed by the Service between: a request it
    // did not take goes once more, on a new connection.
    let reused = kept.lock().ok().and_then(|mut kept| kept.take());
    let mut sender = reused
        .filter(|(at, sender)| *at == to && !sender.is_closed())
        .map(|(_, sender)| sender);
    let (sender, mut response) = loop {
        let (fresh, mut sender) = match sender.take() {
            Some(sender) => (false, sender),
            None => match open(to).await {
                Some(sender) => (true, sender),
                None => return StatusCode::BAD_GATEWAY.into_response(),
            },
        };
        if sender.ready().await.is_err() {
            match fresh {
                true => return StatusCode::BAD_GATEWAY.into_response(),
                false => continue,
            }
        }
        match sender.try_send_request(request).await {
            Ok(response) => break (sender, response),
            Err(mut error) => match error.take_message() {
                Some(again) if !fresh => request = again,
                _ => return StatusCode::BAD_GATEWAY.into_response(),
            },
        }
    };
    let upgrade = response.headers().get(header::UPGRADE).cloned();
    unhop(response.headers_mut());
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        if let Ok(mut kept) = kept.lock() {
            *kept = Some((to, sender));
        }
        return response.map(Body::new);
    }
    // (A Service that switches when not asked to is not answering this request.)
    let (Some(client), Some(upgrade)) = (client, upgrade) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let service = hyper::upgrade::on(&mut response);
    // (hyper is done with the connection once it is upgraded; its place goes with the bytes.)
    let held = connection.clone();
    tokio::spawn(async move {
        let _held = held;
        if let (Ok(client), Ok(service)) = tokio::join!(client, service) {
            let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut TokioIo::new(service)).await;
        }
    });
    let headers = response.headers_mut();
    headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(header::UPGRADE, upgrade);
    response.map(Body::new)
}

/// A new connection to the Service at `to`, HTTP/1.1 on it.
async fn open(to: SocketAddr) -> Option<SendRequest<Body>> {
    let service = reach(to).await?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(service))
        .await
        .ok()?;
    tokio::spawn(connection.with_upgrades());
    Some(sender)
}

/// Port 443: TLS for the host asked for, then the bytes go to its Service and back.
async fn secure(mut door: Door, tls: TlsAcceptor, web: Arc<Web>, limits: Limits) {
    loop {
        // (Accepting goes on when the room is full, for what is a Service's; a client
        // there is no room for, or that holds its share already, is hung up on.)
        let (stream, from) = door.accept().await;
        let Some(turn) = limits.take(from.ip()) else {
            continue;
        };
        let (tls, web) = (tls.clone(), web.clone());
        tokio::spawn(async move {
            // (Where the client reached us: the line's destination.)
            let at = stream.local_addr();
            let stream = Idle::new(stream, IDLE, None);
            let hello = tokio::time::timeout(Duration::from_secs(10), tls.accept(stream));
            let Ok(Ok(mut client)) = hello.await else {
                return;
            };
            let Some(host) = client.get_ref().1.server_name().map(str::to_ascii_lowercase) else {
                return;
            };
            let of = web.hosts.lock().ok().and_then(|hosts| hosts.get(&host).cloned());
            let Some(of) = of else { return };
            if of.reads_http() {
                return serve(client, from, host, of, turn).await;
            }
            let _turn = turn;
            let line = of
                .proxy
                .then(|| at.map_or_else(|_| "PROXY UNKNOWN\r\n".into(), |at| proxy_line(from, at)));
            // (A Service that stops taking bytes does not hold the place either.)
            if let Some(mut service) = reach(of.to).await {
                carry(&mut client, &mut service, line).await;
            }
        });
    }
}

/// The thumbprint a control node wrote for workers that serve ingress (in [`THUMBPRINT`]).
fn thumbprint_of(store: &Store) -> Option<String> {
    let map = store.get(&format!("ConfigMap/{THUMBPRINT}"))?;
    map.spec["data"]["thumbprint"].as_str().map(str::to_string)
}

/// What the store (or a worker's view of it: `view`) says now: the hosts, their certificates
/// (and which are due for another), the account key if there is one, and the Services whose
/// status does not yet name the Secret of the certificate that serves them (service key and
/// what to say). Challenges are answered with the account's thumbprint, or where the account
/// key is not there (a worker's view) with the one a control node wrote down.
/// Whether a wake's `look` is used at all: by a node that serves ingress (its listeners take the
/// certificates) or by the control node that leads (it orders for the workers and keeps the
/// thumbprint written). Any other node with `--acme` would read and parse every exposed
/// host's certificate and key at each change of the store, and throw the result away.
fn looks(serves: bool, worker: bool, leading: bool) -> bool {
    serves || (!worker && leading)
}

#[allow(clippy::type_complexity)]
fn look(
    store: &Store,
    prefix: Ipv6Addr,
    web: &Web,
    view: bool,
) -> (Vec<(String, Exposed)>, Option<acme::Account>, Vec<(String, Value)>) {
    let hosts = exposed_in(store, prefix, view).0;
    let mut certificates = BTreeMap::new();
    let mut wanting = Vec::new();
    let mut naming = Vec::new();
    let at = now();
    for (host, exposed) in &hosts {
        let key = tls_secret(host, exposed);
        let held = secret(store, &key);
        let read = held.get("tls.crt").zip(held.get("tls.key"));
        let read = read.and_then(|(chain, key)| crate::pki::certified(chain, key, host).ok());
        let good = read.as_ref().and_then(|read| validity(read.cert.first()?));
        if good.is_none_or(|(from, until)| due(from, until, at)) {
            wanting.push((host.clone(), exposed.clone()));
        } else {
            // One that is good was applied by hand or ordered earlier: either way the
            // status says which Secret it is, once.
            let status = store.get(&exposed.service).and_then(|service| service.status.as_ref());
            // (Not while a node's order is under way: that node says so itself, as `acme`,
            // and two answers would race.)
            let ordering = status.is_some_and(|status| {
                let asked = status["tls"]["at"].as_u64();
                status["tls"]["state"] == "ordering"
                    && asked.is_some_and(|asked| at.saturating_sub(asked) < BETWEEN_ORDERS)
            });
            if !ordering && status.is_none_or(|status| status["tls"]["secret"] != key.as_str()) {
                let said = json!({ "state": "ready", "secret": key, "source": "applied" });
                naming.push((exposed.service.clone(), said));
            }
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
    let thumbprint = account.as_ref().map(acme::Account::thumbprint);
    *web.thumbprint.lock().expect("nothing panics holding it") = thumbprint.or_else(|| thumbprint_of(store));
    (wanting, account, naming)
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
    // (The ACME account's and the certificates' Secrets: this node's own writes, signed by its key.)
    shared.submit_node(command).await.map(drop).map_err(|e| e.to_string())
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

/// Order a certificate for `host`, unless one was asked for within `between` seconds.
async fn order(
    shared: &Shared,
    directory: &str,
    account: &acme::Account,
    host: &str,
    of: &Exposed,
    tried: &mut BTreeMap<String, u64>,
    between: u64,
) {
    let me = shared.members.me();
    let asked = {
        let state = shared.store.lock().expect("nothing panics holding the store");
        let status = state.store.get(&of.service).and_then(|service| service.status.clone());
        status.and_then(|status| status["tls"]["at"].as_u64())
    };
    // (Whatever the store says or cannot be told: this node asks once in that time at most.)
    if asked_lately(tried.get(host).copied(), asked, now(), between) {
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
    // (An order has ten minutes: an authority that never finishes holds up no other host's.)
    let whole = tokio::time::timeout(Duration::from_secs(600), acme::order(directory, account, host)).await;
    let ordered = match whole.unwrap_or(Err("the authority did not finish in ten minutes".into())) {
        Ok((chain, key)) if fresh(&chain, &key, host, now()) => {
            let secret = tls_secret(host, of);
            put(shared, &secret, json!({ "tls.crt": chain, "tls.key": key })).await
        }
        Ok(_) => Err("the authority's certificate is not good now".into()),
        Err(e) => Err(e),
    };
    let tls = match ordered {
        Ok(()) => json!({ "state": "ready", "secret": tls_secret(host, of), "source": "acme", "by": me, "at": now() }),
        Err(e) => {
            // (What the authority said is in it: the status keeps a few lines of it, no more.)
            let e: String = e.chars().take(500).collect();
            eprintln!("kithd: ingress: no certificate for {host}: {e}");
            json!({ "state": "error", "message": e, "by": me, "at": now() })
        }
    };
    say(shared, &of.service, tls).await;
}

/// Write down the account's thumbprint for the workers that serve ingress (they answer the
/// authority's challenges with it, and have nothing else of the account), unless the store
/// has it already.
async fn tell_thumbprint(shared: &Shared, account: &acme::Account) {
    let thumbprint = account.thumbprint();
    let kept = thumbprint_of(&shared.store.lock().expect("nothing panics holding the store").store);
    if kept.as_deref() == Some(thumbprint.as_str()) {
        return;
    }
    let (namespace, name) = THUMBPRINT.split_once('/').expect("namespace/name");
    let map = json!({
        "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
        "metadata": { "name": name, "namespace": namespace }, "spec": { "data": { "thumbprint": thumbprint } },
    });
    let map = serde_json::from_value::<Resource>(map).map_err(|e| e.to_string());
    let command = map
        .and_then(|map| map.validated())
        .map(|map| kith_store::Command::Apply {
            resources: vec![map],
            at: now(),
        });
    let told = match command {
        Ok(command) => shared.submit(command).await.map(drop).map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    if let Err(e) = told {
        eprintln!("kithd: ingress: writing down the ACME account's thumbprint: {e}");
    }
}

/// The reachable workers that serve ingress from a view whose Node does not say their view holds
/// `thumbprint` (`status.thumbprint`). The authority asks any node that serves ingress, so an
/// order waits on these: asked first, one would answer the challenge 404 and the order fail.
fn unanswered(store: &Store, thumbprint: &str) -> Vec<String> {
    let waits = |status: &Value| {
        status["view"] == true
            && status["serves"]["ingress"] == true
            && status["state"] != "unreachable"
            && status["thumbprint"] != thumbprint
    };
    store
        .list(Some("Node"))
        .filter(|node| node.status.as_ref().is_some_and(waits))
        .map(|node| node.metadata.name.clone())
        .collect()
}

/// What this worker (`me`) is to say its view holds, the thumbprint it answers challenges with
/// (`holds`), where its own Node does not say it yet.
fn to_say(store: &Store, me: &str, holds: Option<&str>) -> Option<String> {
    let own = store.get(&format!("Node/{me}"))?;
    let says = own.status.as_ref().and_then(|status| status["thumbprint"].as_str());
    holds.filter(|holds| says != Some(*holds)).map(str::to_string)
}

/// Until told to stop: with `strays` (`--ingress`), serve ports 443 and 80 from what the store
/// (or this worker's view of it) holds; on a control node with `acme` (a directory URL), order
/// the certificates that are missing, where it serves ingress itself or, as the leader, while
/// any node does. A worker orders nothing: its writes would be refused, and it is never sent
/// the account key.
pub async fn run(
    shared: Arc<Shared>,
    acme: Option<String>,
    strays: Option<Strays>,
    mut stopping: watch::Receiver<bool>,
) {
    let Some(cluster) = &shared.cluster else { return };
    let prefix = crate::mesh::prefix(&cluster.me.ca);
    let web = Arc::new(Web::default());
    let served = match strays {
        Some(strays) => match listen(&shared, prefix, &web, strays).await {
            Some(tasks) => Some(tasks),
            None => return,
        },
        None => None,
    };
    let me = shared.members.me().to_string();
    // (reqwest's TLS wants to be told once which crypto to use.)
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut generation = shared.generation.subscribe();
    let mut tried = BTreeMap::new();
    // (The term whose first order followed a linearizable read: a new leader's store may lag the old leader's.)
    let mut read_term: Option<u64> = None;
    // (Since when orders wait on a worker; the hosts last ordered without waiting on one.)
    let (mut since, mut hurried) = (None, std::collections::BTreeSet::<String>::new());
    let mut said = false;
    // (What this worker last said its view holds, and when; the workers the last order waited on.)
    let mut saying: Option<(String, Instant)> = None;
    let mut waited = Vec::new();
    loop {
        let (leading, term) = {
            let metrics = shared.raft.metrics().borrow().clone();
            (metrics.current_leader == Some(metrics.id), metrics.current_term)
        };
        let (worker, wanted, (wanting, account, naming)) = {
            let state = shared.store.lock().expect("nothing panics holding the store");
            let worker = crate::access::is_worker(&state.store, &me);
            let mut nodes = state.store.list(Some("Node"));
            let wanted = nodes.any(|node| node.status.as_ref().is_some_and(|s| s["serves"]["ingress"] == true));
            let looked = match looks(served.is_some(), worker, leading) {
                true => look(&state.store, prefix, &web, worker),
                false => Default::default(),
            };
            (worker, wanted, looked)
        };
        let leads = !worker && leading;
        if worker && acme.is_some() && !said {
            said = true;
            eprintln!(
                "kithd: ingress: --acme does nothing on a worker: the leading control node orders its certificates \
                 (give the control nodes --acme)"
            );
        }
        // Who orders: a control node that serves ingress, and the leader for the workers that do.
        let orders = !worker && (served.is_some() || (leads && wanted));
        if orders {
            for (service, tls) in naming {
                say(&shared, &service, tls).await;
            }
        }
        // The leader keeps the thumbprint written whether or not anything is ordered now, so
        // a worker has it before a renewal asks; and whoever orders writes it first.
        if let Some(account) = account.as_ref().filter(|_| acme.is_some() && (leads || orders)) {
            tell_thumbprint(&shared, account).await;
        }
        // A worker that serves ingress says when its view holds the thumbprint it answers
        // challenges with: the leader orders once each one has it. (The same word again only
        // after a while: one refused, or a view not caught up yet, is not sent at every change.)
        if worker && served.is_some() {
            let holds = web.thumbprint.lock().expect("nothing panics holding it").clone();
            let says = to_say(
                &shared.store.lock().expect("nothing panics holding the store").store,
                &me,
                holds.as_deref(),
            );
            let again =
                |(was, at): &(String, Instant)| Some(was) != says.as_ref() || at.elapsed() > Duration::from_secs(10);
            if let Some(print) = says.clone().filter(|_| saying.as_ref().is_none_or(again)) {
                saying = Some((print.clone(), Instant::now()));
                let fields = serde_json::Map::from_iter([("thumbprint".to_string(), Value::from(print))]);
                let statuses = vec![(format!("Node/{me}"), fields)];
                if let Err(e) = shared.submit(kith_store::Command::Patch { statuses }).await {
                    eprintln!("kithd: ingress: saying this node's view holds the ACME account's thumbprint: {e}");
                }
            }
        }
        if let Some(directory) = acme.as_deref().filter(|_| orders && !wanting.is_empty()) {
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
                        // A worker answers a challenge with the thumbprint its view holds: none is
                        // asked for until each that serves ingress says it has it (its view may be
                        // any while behind). The store's change when one says it wakes this again.
                        let print = account.thumbprint();
                        let waits = unanswered(
                            &shared.store.lock().expect("nothing panics holding the store").store,
                            &print,
                        );
                        if holds_up(&mut since, &waits, now()) {
                            if waits != waited {
                                eprintln!(
                                    "kithd: ingress: no certificate is asked for until each ingress worker's view holds the ACME account's thumbprint (ten minutes at most); waiting on: {}",
                                    waits.join(", ")
                                );
                            }
                            waited = waits;
                            return;
                        }
                        // Waited long enough on one that never said: asked anyway, and a host that
                        // fails so is asked again in fifteen minutes, not an hour.
                        let past = !waits.is_empty();
                        if past && waits != waited {
                            eprintln!(
                                "kithd: ingress: certificates are asked for without waiting longer on {}, whose view has not said it holds the ACME account's thumbprint for ten minutes (a challenge there may fail)",
                                waits.join(", ")
                            );
                        }
                        waited = waits;
                        // The leader's first order of a term follows a linearizable read: the store has then
                        // applied what the old leader committed, its `tls.at` for each Service, which an empty
                        // `tried` cannot tell. A read that fails or is late orders nothing this round.
                        if leading && read_term != Some(term) {
                            let read = tokio::time::timeout(READ_AT_MOST, shared.raft.ensure_linearizable());
                            match read.await {
                                Ok(Ok(_)) => read_term = Some(term),
                                Ok(Err(e)) => {
                                    eprintln!(
                                        "kithd: ingress: no certificate is asked for yet, the store is not read: {e}"
                                    );
                                    return;
                                }
                                Err(_) => {
                                    eprintln!(
                                        "kithd: ingress: no certificate is asked for yet, the store is not read in time"
                                    );
                                    return;
                                }
                            }
                        }
                        for (host, of) in &wanting {
                            let before = tried.get(host).copied();
                            let pause = between(hurried.contains(host));
                            order(&shared, directory, &account, host, of, &mut tried, pause).await;
                            // (What the pause after an order is: set by how that order was asked.)
                            if tried.get(host).copied() != before {
                                if past {
                                    hurried.insert(host.clone());
                                } else {
                                    hurried.remove(host);
                                }
                            }
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
    if let Some((secure, plain)) = served {
        secure.abort();
        plain.abort();
    }
}

/// Listen on ports 443 and 80 and serve them from `web`; the two tasks that do, or nothing
/// (said why) where the ports cannot be had.
async fn listen(
    shared: &Shared,
    prefix: Ipv6Addr,
    web: &Arc<Web>,
    strays: Strays,
) -> Option<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    let any = |port: u16| SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port);
    let (https, http) = match (TcpListener::bind(any(443)).await, TcpListener::bind(any(80)).await) {
        (Ok(https), Ok(http)) => (https, http),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("kithd: no ingress: ports 443 and 80: {e} (binding them takes CAP_NET_BIND_SERVICE)");
            return None;
        }
    };
    let tls = match crate::pki::ingress_config(web.certificates.clone()) {
        Ok(tls) => TlsAcceptor::from(tls),
        Err(e) => {
            eprintln!("kithd: no ingress: {e}");
            return None;
        }
    };
    let me = kith_mesh::node_address(prefix, shared.members.me());
    let door = |listener| Door {
        listener,
        prefix,
        me,
        strays: strays.clone(),
    };
    let (https, http) = (door(https), door(http));
    let secure = tokio::spawn(secure(https, tls, web.clone(), Limits::new(CONNECTIONS, PER_SOURCE)));
    let router = axum::Router::new().fallback(plain).with_state(web.clone());
    let http = Capped(http, Limits::new(CONNECTIONS, PER_SOURCE));
    let plain = tokio::spawn(async move {
        let _ = axum::serve(http, router).await;
    });
    eprintln!("kithd: ingress on ports 443 and 80");
    Some((secure, plain))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A worker that never says its view holds the thumbprint holds orders up for
    /// [`WAIT_AT_MOST`], not for ever; one that answers ends the wait, and a new one starts
    /// its own. Ordered past such a worker, a host is asked again sooner than an hour.
    #[test]
    fn a_worker_that_never_answers_holds_orders_up_for_a_while_only() {
        let silent = vec!["edge".to_string()];
        let mut since = None;
        assert!(holds_up(&mut since, &silent, 1000));
        assert!(holds_up(&mut since, &silent, 1000 + WAIT_AT_MOST - 1));
        assert!(!holds_up(&mut since, &silent, 1000 + WAIT_AT_MOST));
        assert!(!holds_up(&mut since, &silent, 1000 + 10 * WAIT_AT_MOST));
        // It answered: nothing waits, and the next wait is counted from its own start.
        assert!(!holds_up(&mut since, &[], 5000));
        assert!(holds_up(&mut since, &silent, 6000));
        assert!(!holds_up(&mut since, &silent, 6000 + WAIT_AT_MOST));
        // (Four tries an hour: an authority allows about five failed ones for a host.)
        assert_eq!((between(true), between(false)), (900, BETWEEN_ORDERS));
    }

    /// A new leader's `tried` is empty: the store's `tls.at`, which the old leader wrote before its
    /// ACME call, is what keeps it from ordering a host the old one asked for within `between`.
    /// One asked long ago, or never, is due; this process's own ask counts the same way.
    #[test]
    fn asked_lately_a_new_leader_orders_no_host_the_old_one_asked_for() {
        let (now, between) = (1_000_000, BETWEEN_ORDERS);
        let ago = |secs: u64| now - secs;
        assert!(asked_lately(None, Some(ago(60)), now, between));
        assert!(!asked_lately(None, Some(ago(2 * between)), now, between));
        assert!(!asked_lately(None, None, now, between));
        assert!(asked_lately(Some(ago(60)), None, now, between));
        let long_ago = ago(2 * between);
        assert!(!asked_lately(Some(long_ago), Some(long_ago), now, between));
        // (Exactly `between` seconds ago is due again; one second less is not.)
        assert!(!asked_lately(None, Some(ago(between)), now, between));
        assert!(asked_lately(None, Some(ago(between - 1)), now, between));
    }

    /// A new leader's `tried` is empty: `order()` must hold a host off by its Service's `tls.at`
    /// alone, asked a minute ago by the old leader. It returns before any ACME call. The directory
    /// is a closed port on 127.0.0.1, so a call would fail and write an error into the status; the
    /// status must keep the old `tls.at`, and nothing is tried or written for the account.
    #[tokio::test]
    async fn asked_lately_order_holds_a_host_off_by_the_stores_tls_at() {
        use crate::cluster::{Cluster, pinned_peer};
        let ca = crate::pki::Ca::create().unwrap();
        let control = Cluster::new(pinned_peer::node(&ca, "a"), Some(ca)).unwrap();
        let shared = pinned_peer::shared_of("asked-lately-order", control, &[]).await;
        let id = shared.raft.metrics().borrow().id;
        let leads = shared.raft.wait(Some(Duration::from_secs(30)));
        leads.current_leader(id, "leads").await.unwrap();
        let source = "\
apiVersion: kith.dev/v1
kind: Service
metadata: { name: web, namespace: shop }
spec: { selector: { app: web }, ports: [{ port: 80 }] }
";
        let resources = Resource::from_source(source).unwrap().into_iter().map(Result::unwrap);
        let apply = kith_store::Command::Apply {
            resources: resources.collect(),
            at: now(),
        };
        shared.submit(apply).await.unwrap();
        let asked = now() - 60;
        let fields = serde_json::Map::from_iter([(
            "tls".to_string(),
            json!({ "state": "ordering", "by": "a", "at": asked }),
        )]);
        let patch = kith_store::Command::Patch {
            statuses: vec![("Service/shop/web".to_string(), fields)],
        };
        shared.submit(patch).await.unwrap();

        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let directory = format!("http://127.0.0.1:{closed}/directory");
        let account = acme::Account::from_pkcs8(&acme::Account::generate().unwrap()).unwrap();
        let of = routed(at(9), Vec::new(), &[]);
        let mut tried = BTreeMap::new();
        order(
            &shared,
            &directory,
            &account,
            "shop.example.org",
            &of,
            &mut tried,
            BETWEEN_ORDERS,
        )
        .await;

        assert!(tried.is_empty(), "a host the store says was asked lately is not tried");
        let status = shared
            .store
            .lock()
            .unwrap()
            .store
            .get("Service/shop/web")
            .unwrap()
            .status
            .clone()
            .unwrap();
        assert_eq!(
            (status["tls"]["state"].as_str(), status["tls"]["at"].as_u64()),
            (Some("ordering"), Some(asked))
        );
        assert!(shared.store.lock().unwrap().store.get(ACCOUNT).is_none());
    }

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
        let read = crate::pki::certified(&certificate.pem(), &key.serialize_pem(), "shop.example.org").unwrap();
        assert_eq!(validity(&read.cert[0]), Some((from, until)));
        // What an authority gives is kept while it is good, not once it has run out,
        // before it starts, or for another host.
        let fresh = |host, at| fresh(&certificate.pem(), &key.serialize_pem(), host, at);
        assert!(fresh("shop.example.org", from + 86400));
        assert!(!fresh("shop.example.org", until + 1) && !fresh("shop.example.org", from - 1));
        assert!(!fresh("other.example.org", from + 86400));
        assert!(
            crate::pki::certified(
                &certificate.pem(),
                &rcgen::KeyPair::generate().unwrap().serialize_pem(),
                "shop.example.org"
            )
            .is_err()
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

    /// In a worker's view (which keeps no history to say which came first) a host two Services
    /// claim goes by what the leader wrote in their status: one it has not reported on yet is
    /// not served, so the worker never serves the one the leader then refuses.
    #[test]
    fn in_a_view_a_host_two_services_claim_goes_by_the_leaders_word() {
        let mut store = Store::default();
        let service = |name: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: {name} }}\nspec:\n  \
                 selector: {{ app: {name} }}\n  ports: [{{ port: 80 }}]\n  expose: {{ host: shop.example.org, via: edge }}\n---\n"
            )
        };
        for resource in Resource::from_source(&(service("a") + &service("b"))).unwrap() {
            store.put(resource.unwrap());
        }
        let prefix = kith_mesh::prefix(b"ca");
        let served = |store: &Store| {
            exposed_in(store, prefix, true)
                .0
                .get("shop.example.org")
                .map(|of| of.service.clone())
        };
        // Neither reported on yet: neither is served.
        assert_eq!(served(&store), None);
        // The leader reported on b, and refused a (b came first): b, though a sorts first.
        let mut b = store.get("Service/default/b").unwrap().clone();
        b.status = Some(json!({ "address": "fd00::1", "expose": null }));
        store.put(b);
        assert_eq!(served(&store).as_deref(), Some("Service/default/b"));
        let mut a = store.get("Service/default/a").unwrap().clone();
        let refused = "the host shop.example.org is already exposed by Service/default/b";
        a.status = Some(json!({ "address": "fd00::2", "expose": { "state": "refused", "message": refused } }));
        store.put(a);
        assert_eq!(served(&store).as_deref(), Some("Service/default/b"));
        // One Service alone on its host is served before the leader says anything of it.
        store.delete("Service/default/b").unwrap();
        let mut a = store.get("Service/default/a").unwrap().clone();
        a.status = None;
        store.put(a);
        assert_eq!(served(&store).as_deref(), Some("Service/default/a"));
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

    #[test]
    fn only_a_node_that_serves_or_leads_looks() {
        // (serves, worker, leading)
        assert!(looks(true, false, false) && looks(true, true, false) && looks(false, false, true));
        // A control node that follows and serves nothing, and a worker that serves nothing
        // (a worker never leads; a view that says it does is no reason to look).
        assert!(!looks(false, false, false) && !looks(false, true, false) && !looks(false, true, true));
    }

    #[test]
    fn a_certificate_applied_by_hand_is_named_in_the_status() {
        let mut params = rcgen::CertificateParams::new(vec!["shop.example.org".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2999, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let data = json!({ "tls.crt": certificate.pem(), "tls.key": key.serialize_pem() });
        let secret = json!({ "apiVersion": "kith.dev/v1", "kind": "Secret",
                             "metadata": { "name": "tls-shop.example.org", "namespace": "shop" }, "spec": { "data": data } });
        let service = "apiVersion: kith.dev/v1\nkind: Service\nmetadata: { name: web, namespace: shop }\nspec:\n  \
                       selector: { app: web }\n  ports: [{ port: 8080 }]\n  \
                       expose: { host: shop.example.org, via: edge, proxyProtocol: true }\n";
        let mut store = Store::default();
        store
            .apply(Resource::from_source(service).unwrap().remove(0).unwrap())
            .unwrap();
        let prefix = kith_mesh::prefix(b"ca");
        let web = Web::default();
        // No certificate: it is wanted, and nothing is named.
        let (wanting, _, naming) = look(&store, prefix, &web, false);
        assert_eq!((wanting.len(), naming.len()), (1, 0));
        assert!(wanting[0].1.proxy);
        // (Only a Service that asks gets the line.)
        let quiet = Resource::from_source(&service.replace("proxyProtocol: true", "proxyProtocol: false"));
        let mut other = store.clone();
        other.apply(quiet.unwrap().remove(0).unwrap()).unwrap();
        assert!(!look(&other, prefix, &web, false).0[0].1.proxy);
        // One applied by hand: not wanted, and the status is to name its Secret.
        store.apply(serde_json::from_value(secret).unwrap()).unwrap();
        let (wanting, _, naming) = look(&store, prefix, &web, false);
        assert!(wanting.is_empty());
        assert_eq!(naming.len(), 1);
        let (to, said) = &naming[0];
        assert_eq!(to, "Service/shop/web");
        assert_eq!(said["secret"], "Secret/shop/tls-shop.example.org");
        assert_eq!(said["state"], "ready");
        // Once the status says so, it is not said again.
        store.set_status(to, Some(json!({ "tls": said }))).unwrap();
        assert!(look(&store, prefix, &web, false).2.is_empty());
    }

    #[test]
    fn proxy_protocol_lines() {
        let at = |text: &str| text.parse::<SocketAddr>().unwrap();
        let line = proxy_line(at("203.0.113.7:51000"), at("192.0.2.1:443"));
        assert_eq!(line, "PROXY TCP4 203.0.113.7 192.0.2.1 51000 443\r\n");
        let line = proxy_line(at("[2001:db8::7]:51000"), at("[2001:db8::1]:443"));
        assert_eq!(line, "PROXY TCP6 2001:db8::7 2001:db8::1 51000 443\r\n");
        // (A v4 client of the dual-stack socket shows as a mapped address.)
        let line = proxy_line(at("[::ffff:203.0.113.7]:51000"), at("[::ffff:192.0.2.1]:443"));
        assert_eq!(line, "PROXY TCP4 203.0.113.7 192.0.2.1 51000 443\r\n");
        let line = proxy_line(at("203.0.113.7:51000"), at("[2001:db8::1]:443"));
        assert_eq!(line, "PROXY UNKNOWN\r\n");
    }

    #[tokio::test]
    async fn proxy_protocol_line_comes_before_the_clients_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The backend, over loopback, reads all it is sent; the client sends "GET /".
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let to = backend.local_addr().unwrap();
        for line in [Some("PROXY TCP4 203.0.113.7 192.0.2.1 51000 443\r\n".to_string()), None] {
            let (mut client, theirs) = tokio::io::duplex(64);
            let mut service = TcpStream::connect(to).await.unwrap();
            let (mut seen, _) = backend.accept().await.unwrap();
            let wanted = line.clone().unwrap_or_default() + "GET /";
            let carried = {
                let mut theirs = theirs;
                tokio::spawn(async move { carry(&mut theirs, &mut service, line).await })
            };
            client.write_all(b"GET /").await.unwrap();
            client.shutdown().await.unwrap();
            let mut got = String::new();
            seen.read_to_string(&mut got).await.unwrap();
            assert_eq!(got, wanted);
            drop(seen);
            let _ = carried.await;
        }
    }

    /// A client that is not a bare TCP stream (the TLS stream of port 443, whose bytes are not
    /// the socket's) is carried by the copy, never by splice.
    #[tokio::test]
    async fn splice_is_not_reached_by_a_tls_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut client, mut theirs) = tokio::io::duplex(64);
        let mut service = TcpStream::connect(backend.local_addr().unwrap()).await.unwrap();
        let (mut seen, _) = backend.accept().await.unwrap();
        let carried = tokio::spawn(async move { carry(&mut theirs, &mut service, None).await });
        client.write_all(b"GET /").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = String::new();
        seen.read_to_string(&mut got).await.unwrap();
        assert_eq!(got, "GET /");
        drop(seen);
        let _ = carried.await;
        assert_eq!(crate::services::SPLICED.get(), 0);
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
        let mut capped = Capped(door, Limits::new(1, 100));
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

    /// Port 443 on loopback with `limits`; the task that serves it.
    async fn open_443(limits: Limits) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let (at, serving, _) = open_443_with(limits).await;
        (at, serving)
    }

    /// The same, and what it serves.
    async fn open_443_with(limits: Limits) -> (SocketAddr, tokio::task::JoinHandle<()>, Arc<Web>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let (strays, _kept) = mpsc::unbounded_channel();
        let door = Door {
            listener,
            prefix: kith_mesh::prefix(b"ca"),
            me: Ipv6Addr::LOCALHOST,
            strays,
        };
        let web = Arc::new(Web::default());
        let tls = TlsAcceptor::from(crate::pki::ingress_config(web.certificates.clone()).unwrap());
        (at, tokio::spawn(secure(door, tls, web.clone(), limits)), web)
    }

    /// Is the connection hung up on (not held open) within a moment?
    async fn hung_up(client: &mut TcpStream) -> bool {
        use tokio::io::AsyncReadExt;
        let read = tokio::time::timeout(Duration::from_millis(400), client.read_u8()).await;
        read.is_ok()
    }

    #[tokio::test]
    async fn port_443_takes_so_many_connections_at_a_time() {
        let (at, task) = open_443(Limits::new(1, 100)).await;
        let first = TcpStream::connect(at).await.unwrap();
        // With the room full, the next client is hung up on...
        let mut second = TcpStream::connect(at).await.unwrap();
        assert!(hung_up(&mut second).await);
        // ...and once the room is free again, one is taken (and held, silent as it is,
        // until the hello time runs out).
        drop(first);
        let mut taken = false;
        for _ in 0..30 {
            let mut client = TcpStream::connect(at).await.unwrap();
            if !hung_up(&mut client).await {
                taken = true;
                break;
            }
        }
        assert!(taken);
        task.abort();
    }

    #[tokio::test]
    async fn port_443_takes_so_many_connections_from_one_source() {
        // Everyone here is 127.0.0.1: two at a time, however much room there is.
        let (at, task) = open_443(Limits::new(100, 2)).await;
        let held = [
            TcpStream::connect(at).await.unwrap(),
            TcpStream::connect(at).await.unwrap(),
        ];
        let mut third = TcpStream::connect(at).await.unwrap();
        assert!(hung_up(&mut third).await);
        drop(held);
        let mut taken = false;
        for _ in 0..30 {
            let mut client = TcpStream::connect(at).await.unwrap();
            if !hung_up(&mut client).await {
                taken = true;
                break;
            }
        }
        assert!(taken);
        task.abort();
    }

    #[test]
    fn a_source_over_its_limit_is_refused_while_others_connect() {
        let at = |text: &str| text.parse::<SocketAddr>().unwrap();
        let limits = Limits::new(10, 2);
        let (a1, a2) = (
            limits.take(at("203.0.113.7:1000").ip()),
            limits.take(at("203.0.113.7:1001").ip()),
        );
        assert!(a1.is_some() && a2.is_some());
        // The same address (v4 on a dual-stack socket too) is over; another is not.
        assert!(limits.take(at("203.0.113.7:1002").ip()).is_none());
        assert!(limits.take(at("[::ffff:203.0.113.7]:1003").ip()).is_none());
        let other = limits.take(at("203.0.113.8:1000").ip());
        assert!(other.is_some());
        // A v6 client has a /64 to itself, so its other addresses are the same source.
        let (b1, b2) = (
            limits.take(at("[2001:db8:0:1::1]:1").ip()),
            limits.take(at("[2001:db8:0:1::2]:1").ip()),
        );
        assert!(b1.is_some() && b2.is_some());
        assert!(limits.take(at("[2001:db8:0:1::3]:1").ip()).is_none());
        assert!(limits.take(at("[2001:db8:0:2::1]:1").ip()).is_some());
        // One that goes frees its place, and the room is still counted too.
        drop(a1);
        assert!(limits.take(at("203.0.113.7:1004").ip()).is_some());
        // On the mesh a source is a node's /80: two nodes in one /64 are two sources.
        let nodes = Limits::new(10, 1).per_node();
        let n1 = nodes.take(at("[fd00:0:0:1:aaaa::1]:1").ip());
        assert!(n1.is_some() && nodes.take(at("[fd00:0:0:1:aaaa::2]:1").ip()).is_none());
        assert!(nodes.take(at("[fd00:0:0:1:bbbb::1]:1").ip()).is_some());
        let full = Limits::new(1, 5);
        let _one = full.take(at("203.0.113.7:1").ip());
        assert!(full.take(at("203.0.113.9:1").ip()).is_none());
        // (And a refusal for want of room does not keep a count against its source.)
        drop(_one);
        assert!(full.take(at("203.0.113.9:1").ip()).is_some());
    }

    /// Limits for the people: a peer is its own address (never its /64), and what is counted
    /// is no bigger than the room, so a flood of new sources cannot grow it.
    #[test]
    fn people_serving_limits_count_each_address_and_bound_their_table() {
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        let limits = Limits::new(100, 2).per_address();
        let held: Vec<_> = ["fd00:0:0:1::1", "fd00:0:0:1::1", "fd00:0:0:1::2", "fd00:0:0:1::2"]
            .into_iter()
            .map(|from| limits.take(ip(from)))
            .collect();
        assert!(held.iter().all(Option::is_some), "two peers of one /64 count apart");
        assert!(limits.take(ip("fd00:0:0:1::1")).is_none() && limits.take(ip("fd00:0:0:1::2")).is_none());
        assert!(limits.take(ip("fd00:0:0:1::3")).is_some());
        // A flood of new sources: the table never holds more than the room.
        let small = Limits::new(4, 1).per_address();
        let places: Vec<_> = (0..200u32)
            .filter_map(|n| small.take(ip(&format!("fd00:0:0:1::{n:x}"))))
            .collect();
        assert_eq!(places.len(), 4);
        assert!(small.sources.lock().unwrap().len() <= 4);
        drop(places);
        assert!(small.sources.lock().unwrap().is_empty());
    }

    #[test]
    fn the_older_service_keeps_a_host_two_claim() {
        let service = |name: &str, port: u16, host: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: {name} }}\nspec:\n  \
                 selector: {{ app: {name} }}\n  ports: [{{ port: {port} }}]\n  expose: {{ host: {host}, via: edge }}\n"
            )
        };
        let mut store = Store::default();
        let mut apply = |at: u64, source: String| {
            store.at(Some(at));
            store
                .apply(Resource::from_source(&source).unwrap().remove(0).unwrap())
                .unwrap();
        };
        // "z" is the older one, though "a" comes first by key; an edit to "z" later does not make it newer.
        apply(100, service("z", 80, "shop.example.org"));
        apply(200, service("a", 80, "Shop.example.org"));
        apply(300, service("z", 81, "shop.example.org"));
        let (hosts, refused) = exposed(&store, kith_mesh::prefix(b"ca"));
        assert_eq!(hosts["shop.example.org"].service, "Service/default/z");
        let said = "the host shop.example.org is already exposed by Service/default/z";
        assert_eq!(
            refused,
            BTreeMap::from([("Service/default/a".to_string(), said.to_string())])
        );
    }

    /// The Service made first has a host two name, however often it is edited after and
    /// whatever of its history is trimmed: the store says when each was first made.
    #[test]
    fn exposed_host_stays_with_the_service_made_first_after_150_edits_and_a_restart() {
        use kith_store::Command;
        let host = "shop.example.org";
        let service = |name: &str, port: u16| {
            let source = format!(
                "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: {name} }}\nspec:\n  \
                 selector: {{ app: {name} }}\n  ports: [{{ port: {port} }}]\n  expose: {{ host: {host}, via: edge }}\n"
            );
            Resource::from_source(&source).unwrap().remove(0).unwrap()
        };
        // The log: "z" is made, then "a" names its host, then "z" is edited 150 times.
        let written = |marked: bool| {
            let mut store = Store::default();
            let mut index = 0;
            let mut run = |store: &mut Store, command: Command| {
                index += 1;
                store.entry(index);
                kith_store::run(store, command).unwrap();
            };
            let apply = |service: Resource, at: u64| Command::Apply {
                resources: vec![service],
                at,
            };
            if marked {
                run(&mut store, Command::Mark);
            }
            run(&mut store, apply(service("z", 80), 100));
            run(&mut store, apply(service("a", 80), 200));
            for edit in 1..=150 {
                run(&mut store, apply(service("z", 80 + edit), 300 + u64::from(edit)));
            }
            store
        };
        let holder = |store: &Store| {
            let (hosts, refused) = exposed(store, kith_mesh::prefix(b"ca"));
            (hosts[host].service.clone(), refused)
        };
        let refused = |loser: &str, holder: &str| {
            let said = format!("the host {host} is already exposed by Service/default/{holder}");
            BTreeMap::from([(format!("Service/default/{loser}"), said)])
        };
        let store = written(true);
        // (All the store keeps of "z" is newer than "a" by now.)
        assert!(store.history("Service/default/z").unwrap()[0].at > 200);
        assert_eq!(holder(&store), ("Service/default/z".to_string(), refused("a", "z")));
        // Every node started again reads the store from its snapshot: the same.
        let read: Store = serde_json::from_slice(&serde_json::to_vec(&store).unwrap()).unwrap();
        assert_eq!(holder(&read), ("Service/default/z".to_string(), refused("a", "z")));
        // Deleted, "z" gives the host up, and made again it is the newer one.
        let mut gone = read.clone();
        gone.delete("Service/default/z").unwrap();
        gone.entry(1000);
        gone.at(Some(50));
        gone.apply(service("z", 80)).unwrap();
        assert_eq!(holder(&gone), ("Service/default/a".to_string(), refused("z", "a")));

        // A store not marked (a member's kithd is from before) orders as it did: by the
        // oldest revision kept, so there "a" has the host after those edits. Marked then,
        // what there was keeps that order: SECURITY.md says to keep such a host by its Namespace.
        let mut before = written(false);
        assert_eq!(holder(&before), ("Service/default/a".to_string(), refused("z", "a")));
        kith_store::run(&mut before, Command::Mark).unwrap();
        assert_eq!(holder(&before), ("Service/default/a".to_string(), refused("z", "a")));
    }

    /// Whoever may write a Service in one namespace could otherwise take a host another
    /// namespace means to serve, by being there first: a Namespace names the hosts that
    /// are its own, and then exposes only those.
    #[test]
    fn reserved_hosts_are_exposed_by_their_namespace_alone() {
        let mut store = Store::default();
        let apply = |store: &mut Store, at: u64, source: String| {
            store.at(Some(at));
            let resource = Resource::from_source(&source).unwrap().remove(0);
            resource
                .map_err(|e| e.msg)
                .and_then(|resource| store.apply(resource).map_err(|e| e.to_string()))
        };
        let namespace = |name: &str, hosts: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: Namespace\nmetadata: {{ name: {name} }}\nspec: {{ hosts: {hosts} }}\n"
            )
        };
        let service = |namespace: &str, name: &str, host: &str| {
            format!(
                "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: {name}, namespace: {namespace} }}\nspec:\n  \
                 selector: {{ app: {name} }}\n  ports: [{{ port: 80 }}]\n  expose: {{ host: {host}, via: edge }}\n"
            )
        };
        // The one who was there first, and the namespace the host is kept for.
        apply(&mut store, 100, service("other", "squat", "shop.example.org")).unwrap();
        apply(&mut store, 200, namespace("shop", "['*.Example.org', example.org]")).unwrap();
        apply(&mut store, 300, service("shop", "web", "Shop.example.org")).unwrap();
        apply(&mut store, 300, service("shop", "apex", "example.org")).unwrap();
        apply(&mut store, 300, service("shop", "stray", "stray.example.net")).unwrap();
        // A namespace that names none exposes what nobody keeps.
        apply(&mut store, 300, namespace("other", "[]")).unwrap();
        apply(&mut store, 300, service("other", "free", "free.example.net")).unwrap();
        apply(&mut store, 300, service("other", "near", "badexample.org")).unwrap();
        apply(&mut store, 300, service("nowhere", "deep", "a.b.example.org")).unwrap();

        let (hosts, refused) = exposed(&store, kith_mesh::prefix(b"ca"));
        let served: BTreeMap<&str, &str> = hosts
            .iter()
            .map(|(host, to)| (host.as_str(), to.service.as_str()))
            .collect();
        assert_eq!(
            served,
            BTreeMap::from([
                ("badexample.org", "Service/other/near"),
                ("example.org", "Service/shop/apex"),
                ("free.example.net", "Service/other/free"),
                ("shop.example.org", "Service/shop/web"),
            ])
        );
        let said = |service: &str| refused[service].as_str();
        assert_eq!(
            said("Service/other/squat"),
            "the host shop.example.org is kept for the namespace shop (its Namespace's hosts)"
        );
        assert_eq!(
            said("Service/nowhere/deep"),
            "the host a.b.example.org is kept for the namespace shop (its Namespace's hosts)"
        );
        assert_eq!(
            said("Service/shop/stray"),
            "the namespace shop exposes only its Namespace's hosts (*.example.org, example.org), and stray.example.net \
             is not one"
        );
        assert_eq!(refused.len(), 3);

        // What is no host, or a pattern of some other kind, is refused when applied.
        for hosts in [
            "['*']",
            "['*.*.example.org']",
            "['shop.*.org']",
            "['203.0.113.7']",
            "['a b']",
            "['']",
        ] {
            let said = apply(&mut store, 400, namespace("bad", hosts)).unwrap_err();
            assert!(said.contains("hosts"), "{hosts}: {said}");
        }
    }

    #[test]
    fn a_host_acme_would_refuse_is_refused() {
        let hosts = [
            ("ip", "203.0.113.7"),
            ("num", "2130706433"),
            ("dash", "-shop.example.org"),
            ("dashed", "shop-.example.org"),
            ("ok", "shop.example.org"),
        ];
        let service = |name: &str, host: &str| {
            let source = format!(
                "apiVersion: kith.dev/v1\nkind: Service\nmetadata: {{ name: {name} }}\nspec:\n  \
                 selector: {{ app: {name} }}\n  ports: [{{ port: 80 }}]\n  expose: {{ host: '{host}', via: edge }}\n"
            );
            Resource::from_source(&source).unwrap().remove(0)
        };
        // Applying one is refused...
        let mut store = Store::default();
        for (name, host) in hosts {
            let said = service(name, host).map_err(|e| e.msg).err();
            let said = said.or_else(|| store.apply(service(name, host).unwrap()).err().map(|e| e.to_string()));
            assert_eq!(said.is_some(), name != "ok", "{name}: {said:?}");
            assert!(said.is_none_or(|said| said.contains("expose.host")));
        }
        // ...and one stored before that was (here: the same names, the hosts put in after) is
        // not ordered for, and says why.
        let mut store = Store::default();
        for (name, _) in hosts {
            store.apply(service(name, "shop.example.org").unwrap()).unwrap();
        }
        let mut stored = serde_json::to_value(&store).unwrap();
        for (name, host) in hosts {
            let key = format!("Service/default/{name}");
            stored["resources"][&key][0]["resource"]["spec"]["expose"]["host"] = host.into();
        }
        let store: Store = serde_json::from_value(stored).unwrap();
        let (hosts, refused) = exposed(&store, kith_mesh::prefix(b"ca"));
        assert_eq!(hosts.keys().collect::<Vec<_>>(), ["shop.example.org"]);
        for name in ["ip", "num", "dash", "dashed"] {
            let said = &refused[&format!("Service/default/{name}")];
            assert!(said.contains("expose.host"), "{name}: {said}");
        }
        assert_eq!(refused.len(), 4);
    }

    fn at(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn prefix(path: &str, to: SocketAddr) -> Route {
        let (path, exact) = (path.to_string(), false);
        Route { path, exact, to }
    }

    /// A host read as HTTP, its Service at `to`.
    fn routed(to: SocketAddr, routes: Vec<Route>, headers: &[(&'static str, &'static str)]) -> Exposed {
        let headers = headers
            .iter()
            .map(|(name, value)| (HeaderName::from_static(name), HeaderValue::from_static(value)));
        let (service, namespace) = ("Service/shop/web".to_string(), "shop".to_string());
        let (proxy, headers) = (false, headers.collect());
        Exposed {
            service,
            namespace,
            to,
            proxy,
            routes,
            headers,
        }
    }

    #[test]
    fn paths_are_matched_as_they_are_sent() {
        let exact = |path: &str, to| Route {
            exact: true,
            ..prefix(path, to)
        };
        let (api, admin, login, same, web) = (at(1), at(2), at(3), at(4), at(5));
        let routes = vec![
            prefix("/api", api),
            prefix("/api/admin", admin),
            exact("/login", login),
            exact("/api", same),
        ];
        let of = routed(web, routes, &[]);
        let cases = [
            ("/api/", Some(api)),
            ("/api/x", Some(api)),
            ("/api/admin/x", Some(admin)),
            ("/api/admin", Some(admin)),
            ("/api/administrator", Some(api)),
            // An exact path over a prefix as long.
            ("/api", Some(same)),
            ("/login", Some(login)),
            ("/login/", None),
            ("/apiary", None),
            ("/application", None),
            ("/", None),
            // Nothing decoded or folded: what is written another way is another path.
            ("//api", None),
            ("/%2fapi", None),
            ("/%2Fapi/x", None),
            ("/api%2fadmin", None),
            ("/API", None),
            ("/x/../api", None),
            ("/api/../login", Some(api)),
            ("/api/%2e%2e/login", Some(api)),
            ("/api/admin/../x", Some(admin)),
            ("*", None),
            ("", None),
        ];
        for (path, to) in cases {
            assert_eq!(of.route(path), to, "{path}");
        }
        // `/` is every path; with no paths at all, so is the Service of the host.
        let of = routed(web, vec![prefix("", web), prefix("/api", api)], &[]);
        assert_eq!(
            (of.route("/x"), of.route("/api/x"), of.route("*")),
            (Some(web), Some(api), None)
        );
        let plain = routed(web, Vec::new(), &[]);
        assert_eq!((plain.route("/anything"), plain.reads_http()), (Some(web), false));
        assert!(of.reads_http() && routed(web, Vec::new(), &[("x-env", "prod")]).reads_http());
    }

    #[test]
    fn a_hosts_paths_reach_services_of_its_namespace() {
        let mut store = Store::default();
        let source = "apiVersion: kith.dev/v1\nkind: Service\nmetadata: { name: web, namespace: shop }\nspec:\n  \
                      selector: { app: web }\n  ports: [{ port: 8080 }]\n  \
                      expose:\n    host: shop.example.org\n    via: edge\n    \
                      paths: [{ path: /api/, service: api, port: 9000 }, { path: /, service: web, port: 8080 }, \
                      { path: /health, exact: true, service: api, port: 9001 }]\n    \
                      headers: { X-Env: prod }\n";
        for resource in Resource::from_source(source).unwrap() {
            store.apply(resource.unwrap()).unwrap();
        }
        let prefix = kith_mesh::prefix(b"ca");
        let (hosts, refused) = exposed(&store, prefix);
        assert!(refused.is_empty());
        let to = |name, port| SocketAddr::new(kith_mesh::service_address(prefix, "shop", name).into(), port);
        let shop = &hosts["shop.example.org"];
        let routes = [
            Route {
                path: "/api".into(),
                exact: false,
                to: to("api", 9000),
            },
            Route {
                path: String::new(),
                exact: false,
                to: to("web", 8080),
            },
            Route {
                path: "/health".into(),
                exact: true,
                to: to("api", 9001),
            },
        ];
        assert_eq!(shop.routes, routes);
        let env = (HeaderName::from_static("x-env"), HeaderValue::from_static("prod"));
        assert_eq!(shop.headers, [env]);
        assert_eq!(shop.route("/api"), Some(to("api", 9000)));
    }

    /// What a test's Service was sent, byte for byte, as it reads it.
    struct Seen<T>(T, Arc<Mutex<Vec<u8>>>);

    impl<T: AsyncRead + Unpin> AsyncRead for Seen<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            let polled = Pin::new(&mut self.0).poll_read(cx, buf);
            self.1.lock().unwrap().extend_from_slice(&buf.filled()[before..]);
            polled
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for Seen<T> {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    /// A Service on loopback: what it was sent, and how many connections it took.
    struct Backend {
        at: SocketAddr,
        seen: Arc<Mutex<Vec<u8>>>,
        connections: Arc<std::sync::atomic::AtomicUsize>,
    }

    /// A Service named `name` that answers with what it was asked: the target, the headers
    /// kith sets (and two a client might), the size of the body. An upgrade to `echo` it
    /// takes, and sends back the four bytes it is sent after.
    async fn backend(name: &'static str) -> Backend {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = Backend {
            at: listener.local_addr().unwrap(),
            seen: Arc::default(),
            connections: Arc::default(),
        };
        let (seen, connections) = (backend.seen.clone(), backend.connections.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                connections.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let service = hyper::service::service_fn(move |mut request: Request<Incoming>| async move {
                    if request.headers().contains_key(header::UPGRADE) {
                        let upgraded = hyper::upgrade::on(&mut request);
                        tokio::spawn(async move {
                            let mut upgraded = TokioIo::new(upgraded.await.unwrap());
                            let mut four = [0; 4];
                            upgraded.read_exact(&mut four).await.unwrap();
                            upgraded.write_all(&four).await.unwrap();
                        });
                        let switching = axum::http::Response::builder()
                            .status(101)
                            .header(header::CONNECTION, "upgrade");
                        let switching = switching.header(header::UPGRADE, "websocket").body(Body::empty());
                        return Ok::<_, std::convert::Infallible>(switching.unwrap());
                    }
                    let said = |name: &str| {
                        let all = request.headers().get_all(name).iter();
                        let all: Vec<_> = all.map(|value| String::from_utf8_lossy(value.as_bytes())).collect();
                        if all.is_empty() { "-".to_string() } else { all.join("|") }
                    };
                    let names = [
                        "x-forwarded-for",
                        "x-forwarded-proto",
                        "x-forwarded-host",
                        "host",
                        "x-env",
                        "x-secret",
                        "x-real-ip",
                        "x_forwarded_for",
                    ];
                    let said: Vec<String> = names.iter().map(|name| said(name)).collect();
                    let text = format!("{name} {} {}", request.uri(), said.join(" "));
                    let body = axum::body::to_bytes(Body::new(request.into_body()), usize::MAX).await;
                    let size = body.map_or(0, |body| body.len());
                    Ok(Response::new(Body::from(format!("{text} body={size}"))))
                });
                let stream = TokioIo::new(Seen(stream, seen.clone()));
                let http = hyper::server::conn::http1::Builder::new();
                tokio::spawn(http.serve_connection(stream, service).with_upgrades());
            }
        });
        backend
    }

    /// `of` served as shop.example.org on loopback, under a certificate of a CA of the
    /// test's own; a client of it.
    async fn shop(
        of: Exposed,
    ) -> (
        impl AsyncFnMut() -> tokio_rustls::client::TlsStream<TcpStream>,
        Arc<Web>,
    ) {
        shop_with(of, Limits::new(100, 100)).await
    }

    async fn shop_with(
        of: Exposed,
        limits: Limits,
    ) -> (
        impl AsyncFnMut() -> tokio_rustls::client::TlsStream<TcpStream>,
        Arc<Web>,
    ) {
        let (at, _serving, web) = open_443_with(limits).await;
        let ca = crate::pki::Ca::create().unwrap();
        let (cert, key) = ca.issue("n1").unwrap();
        let certified = Arc::new(crate::pki::certified(&cert, &key, "kith").unwrap());
        web.certificates
            .0
            .lock()
            .unwrap()
            .insert("shop.example.org".into(), certified);
        web.hosts.lock().unwrap().insert("shop.example.org".into(), of);
        let tls = tokio_rustls::TlsConnector::from(Arc::new(crate::pki::client_config(&ca.cert, None, None).unwrap()));
        let connect = move || {
            let tls = tls.clone();
            async move {
                let name = rustls::pki_types::ServerName::try_from("shop.example.org").unwrap();
                tls.connect(name, TcpStream::connect(at).await.unwrap()).await.unwrap()
            }
        };
        (connect, web)
    }

    /// `request` sent on `stream`, and the answer's status and body (of its
    /// Content-Length), or None when the connection is closed first.
    async fn ask<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, request: &[u8]) -> Option<(u16, String)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let answer = async {
            stream.write_all(request).await.ok()?;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.ok()?);
            }
            let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
            let status = head[9..12].parse().unwrap();
            let length = head.lines().find_map(|line| line.strip_prefix("content-length:"));
            let mut body = vec![0; length.map_or(0, |length| length.trim().parse().unwrap())];
            stream.read_exact(&mut body).await.ok()?;
            Some((status, String::from_utf8(body).unwrap()))
        };
        tokio::time::timeout(Duration::from_secs(10), answer).await.unwrap()
    }

    #[tokio::test]
    async fn requests_go_by_their_path_with_the_headers_kith_sets() {
        let (api, web) = (backend("api").await, backend("web").await);
        let routes = vec![prefix("/api", api.at), prefix("/web", web.at)];
        let (mut connect, _web) = shop(routed(web.at, routes, &[("x-env", "prod")])).await;
        let mut client = connect().await;
        // What a client says of where it is from, and the headers kith sets, are replaced;
        // one its Connection header names goes no further.
        let request = b"GET /api/items?to=/web HTTP/1.1\r\nHost: shop.example.org\r\nX-Forwarded-For: 192.0.2.66\r\n\
                        X-Forwarded-Host: other.example\r\nX-Forwarded-Proto: http\r\nX-Env: mine\r\n\
                        X-Real-IP: 192.0.2.66\r\nX_Forwarded_For: 192.0.2.66\r\n\
                        Connection: keep-alive, X-Secret\r\nX-Secret: s\r\n\r\n";
        let said = "api /api/items?to=/web 127.0.0.1 https shop.example.org shop.example.org prod - - - body=0";
        assert_eq!(ask(&mut client, request).await, Some((200, said.into())));
        // The next request on the connection goes by its own path, and so on.
        let said = "web /web/ 127.0.0.1 https shop.example.org shop.example.org prod - - - body=0";
        let request = b"GET /web/ HTTP/1.1\r\nHost: other.example\r\n\r\n";
        assert_eq!(ask(&mut client, request).await, Some((200, said.into())));
        for _ in 0..2 {
            let answer = ask(
                &mut client,
                b"GET /api/%2e%2e/web HTTP/1.1\r\nHost: shop.example.org\r\n\r\n",
            )
            .await;
            assert!(answer.unwrap().1.starts_with("api /api/%2e%2e/web "));
        }
        // (A connection on to a Service is kept while requests go to it.)
        assert_eq!(api.connections.load(std::sync::atomic::Ordering::SeqCst), 2);
        for path in ["/application", "//api", "/%2fapi", "/", "*"] {
            let request = format!("GET {path} HTTP/1.1\r\nHost: shop.example.org\r\n\r\n");
            assert_eq!(
                ask(&mut client, request.as_bytes()).await,
                Some((404, String::new())),
                "{path}"
            );
        }
        // A body goes on as it comes, one larger than any buffer of kith's included.
        let body = vec![b'x'; 3 << 20];
        let request = [
            format!(
                "POST /web/up HTTP/1.1\r\nHost: s\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
            &body,
        ]
        .concat();
        let (status, said) = ask(&mut client, &request).await.unwrap();
        assert!(status == 200 && said.ends_with(&format!(" body={}", 3 << 20)), "{said}");
        let request =
            b"POST /web/up HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert!(ask(&mut client, request).await.unwrap().1.ends_with(" body=5"));
        // A target in absolute form goes by its path, to the host kith serves.
        let request = b"GET http://other.example/api/x HTTP/1.1\r\nHost: other.example\r\n\r\n";
        let said = "api /api/x 127.0.0.1 https shop.example.org shop.example.org prod - - - body=0";
        assert_eq!(ask(&mut client, request).await, Some((200, said.into())));
    }

    #[tokio::test]
    async fn a_request_hyper_cannot_frame_one_way_reaches_no_service() {
        let api = backend("api").await;
        let (mut connect, _web) = shop(routed(api.at, vec![prefix("/api", api.at)], &[])).await;
        let many: String = (0..120).map(|n| format!("X-{n}: 1\r\n")).collect();
        // (hyper looks at the size between reads: a head a little over 64 KiB may pass.)
        let long = format!("X-Long: {}\r\n", "a".repeat(200_000));
        let refused = [
            (
                "folded",
                "GET /api/smuggled HTTP/1.1\r\nHost: s\r\nX-A: 1\r\n  folded\r\n\r\n".to_string(),
            ),
            (
                "two lengths",
                "POST /api/smuggled HTTP/1.1\r\nHost: s\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab".into(),
            ),
            (
                "NUL",
                "GET /api/smuggled HTTP/1.1\r\nHost: s\r\nX-A: a\0b\r\n\r\n".into(),
            ),
            (
                "not chunked",
                "POST /api/smuggled HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: gzip\r\n\r\nab".into(),
            ),
            (
                "1.0 chunked",
                "POST /api/smuggled HTTP/1.0\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".into(),
            ),
            (
                "space before colon",
                "GET /api/smuggled HTTP/1.1\r\nHost: s\r\nContent-Length : 3\r\n\r\nabc".into(),
            ),
            (
                "too many",
                format!("GET /api/smuggled HTTP/1.1\r\nHost: s\r\n{many}\r\n"),
            ),
            (
                "too long",
                format!("GET /api/smuggled HTTP/1.1\r\nHost: s\r\n{long}\r\n"),
            ),
        ];
        for (what, request) in refused {
            let mut client = connect().await;
            let answer = ask(&mut client, request.as_bytes()).await;
            assert!(matches!(answer, None | Some((400 | 431, _))), "{what}: {answer:?}");
        }
        // Both a length and chunked: read as chunked (RFC 9112 6.3), and the connection
        // closed after, so what follows is never read as a request of its own.
        let mut client = connect().await;
        let request = b"POST /api/a HTTP/1.1\r\nHost: s\r\nContent-Length: 40\r\nTransfer-Encoding: chunked\r\n\r\n\
                        0\r\n\r\nGET /api/smuggled HTTP/1.1\r\nHost: s\r\n\r\n";
        let answer = ask(&mut client, request).await.unwrap();
        assert!(answer.0 == 200 && answer.1.starts_with("api /api/a ") && answer.1.ends_with(" body=0"));
        assert_eq!(ask(&mut client, b"GET /api/b HTTP/1.1\r\nHost: s\r\n\r\n").await, None);
        // A bare line feed: refused, or the request goes on as kith writes it.
        let mut client = connect().await;
        let answer = ask(&mut client, b"GET /api/lf HTTP/1.1\nHost: s\n\n").await;
        assert!(matches!(answer, None | Some((200 | 400, _))), "{answer:?}");

        let seen = String::from_utf8(api.seen.lock().unwrap().clone()).unwrap();
        assert!(!seen.contains("smuggled") && !seen.contains("folded"), "{seen}");
        assert!(!seen.replace("\r\n", "").contains('\n'), "{seen}");
    }

    #[test]
    fn a_client_does_not_say_where_it_is_from() {
        for name in [
            "x-forwarded-for",
            "x-forwarded-port",
            "x-forwarded-server",
            "x-forwarded-prefix",
            "forwarded",
            "x-real-ip",
            "x-client-ip",
            "x-original-url",
            "x-rewrite-url",
            "x_forwarded_for",
            "x_real_ip",
            "any_header",
        ] {
            assert!(forged(name), "{name}");
        }
        for name in ["x-env", "forwarded-for-fun", "cookie", "x-request-id", "authorization"] {
            assert!(!forged(name), "{name}");
        }
    }

    #[tokio::test]
    async fn an_upgrade_carries_bytes_after_the_101() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let api = backend("api").await;
        let limits = Limits::new(100, 100);
        let (mut connect, _web) = shop_with(routed(api.at, vec![prefix("/ws", api.at)], &[]), limits.clone()).await;
        let mut client = connect().await;
        // Only a WebSocket is switched to: a backend asked for h2c would then be sent requests
        // kith does not read. The request goes on as one with no upgrade in it.
        let request = b"GET /ws HTTP/1.1\r\nHost: s\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\
                        HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n";
        let (status, said) = ask(&mut client, request).await.unwrap();
        assert!(status == 200 && said.starts_with("api /ws "), "{status} {said}");
        let request = b"GET /ws HTTP/1.1\r\nHost: s\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\n\r\n";
        assert_eq!(ask(&mut client, request).await, Some((101, String::new())));
        client.write_all(b"ping").await.unwrap();
        let mut four = [0; 4];
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut four))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&four, b"ping");
        // The connection holds its place under the limits while it carries bytes, and gives
        // it back once it ends: one upgraded is no way past them.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(limits.room.available_permits(), 99);
        drop(client);
        let mut waited = 0;
        while limits.room.available_permits() != 100 && waited < 100 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 1;
        }
        assert_eq!(limits.room.available_permits(), 100);
    }

    #[tokio::test]
    async fn a_host_without_paths_or_headers_carries_bytes_as_they_are() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut connect, _web) = shop(routed(listener.local_addr().unwrap(), Vec::new(), &[])).await;
        let mut client = connect().await;
        client.write_all(b"GET /x HTTP/1.1\nX: a\0b\n\n").await.unwrap();
        client.shutdown().await.unwrap();
        let (mut service, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        service.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"GET /x HTTP/1.1\nX: a\0b\n\n");
    }

    /// The leading control node orders the certificate of a host only a worker serves, from
    /// an authority on 127.0.0.1; the worker's view has the certificate and the thumbprint
    /// (and no account key), it answers the challenge from them and serves the certificate
    /// once its view has it; and the worker, given `--acme`, asks the authority nothing and
    /// writes nothing.
    #[tokio::test]
    async fn orders_for_a_worker_that_serves_ingress_from_the_control_node() {
        use crate::cluster::{Cluster, pinned_peer};
        let host = "shop.example.org";
        let ca = crate::pki::Ca::create().unwrap();
        let edge = pinned_peer::node(&ca, "edge");
        let control = Cluster::new(pinned_peer::node(&ca, "a"), Some(ca)).unwrap();
        let shared = pinned_peer::shared_of("orders-for-a-worker", control, &[]).await;
        let id = shared.raft.metrics().borrow().id;
        let leads = shared.raft.wait(Some(Duration::from_secs(30)));
        leads.current_leader(id, "leads").await.unwrap();
        let source = format!(
            "\
apiVersion: kith.dev/v1
kind: Node
metadata: {{ name: edge }}
spec: {{ trust: worker, ingress: true }}
---
apiVersion: kith.dev/v1
kind: Service
metadata: {{ name: web, namespace: shop }}
spec: {{ selector: {{ app: web }}, ports: [{{ port: 80 }}], expose: {{ host: {host}, via: edge }} }}
"
        );
        let resources = Resource::from_source(&source).unwrap().into_iter().map(Result::unwrap);
        let command = kith_store::Command::Apply {
            resources: resources.collect(),
            at: now(),
        };
        shared.submit(command).await.unwrap();
        let say_of_edge = |field: &str, said: Value| {
            let fields = serde_json::Map::from_iter([(field.to_string(), said)]);
            kith_store::Command::Patch {
                statuses: vec![("Node/edge".to_string(), fields)],
            }
        };
        shared
            .submit(say_of_edge("serves", json!({ "ingress": true })))
            .await
            .unwrap();
        // (It runs from a view, as the control node that let it join wrote.)
        shared.submit(say_of_edge("view", true.into())).await.unwrap();

        let (base, asked) = crate::acme::tests::authority(host, |_, answer| answer.clone()).await;
        let directory = format!("{base}/directory");
        let (stop, stopping) = watch::channel(false);
        let ordering = tokio::spawn(run(shared.clone(), Some(directory.clone()), None, stopping));
        let key = format!("Secret/shop/tls-{host}");
        // (What a control node sends the worker first: its whole view.)
        let view_of = |shared: &Shared| {
            let state = shared.store.lock().unwrap();
            let Some(crate::view::Sent::Whole { resources, .. }) = crate::view::round(&state, "edge", &mut None) else {
                panic!("a first round sends the whole view");
            };
            let mut view = Store::default();
            resources.into_iter().for_each(|resource| view.put(resource));
            view
        };
        // (Before the certificate: the worker's view, which has the host and no certificate.)
        let before = view_of(&shared);
        let deadline = Instant::now() + Duration::from_secs(60);
        // (When the thumbprint was written, and when the worker said its view holds it.)
        let (mut printed, mut reported) = (None, None);
        while shared.store.lock().unwrap().store.get(&key).is_none() {
            assert!(
                Instant::now() < deadline,
                "no certificate was ordered: {:?}",
                asked.lock().unwrap()
            );
            let print = thumbprint_of(&shared.store.lock().unwrap().store);
            let now = Instant::now();
            if print.is_some() {
                printed.get_or_insert(now);
            }
            // The worker's view is a while behind (longer than any fixed pause): until it says
            // it holds the thumbprint, the authority is asked nothing, as the worker would
            // answer its challenge 404 and the order fail.
            if reported.is_none() {
                assert!(
                    asked.lock().unwrap().is_empty(),
                    "the authority was asked before the worker had the thumbprint"
                );
            }
            if let Some(print) =
                print.filter(|_| reported.is_none() && printed.is_some_and(|at| now >= at + Duration::from_secs(7)))
            {
                shared.submit(say_of_edge("thumbprint", print.into())).await.unwrap();
                reported = Some(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            reported.is_some(),
            "a certificate was ordered before the worker said it had the thumbprint"
        );
        let _ = stop.send(true);
        ordering.await.unwrap();
        let status = shared
            .store
            .lock()
            .unwrap()
            .store
            .get("Service/shop/web")
            .unwrap()
            .status
            .clone();
        assert_eq!(status.unwrap()["tls"]["source"], "acme");

        // The worker's view: the certificate and the thumbprint, never the account key.
        let view = view_of(&shared);
        assert!(view.get(&key).is_some());
        assert!(view.get(ACCOUNT).is_none());
        let account = look(
            &shared.store.lock().unwrap().store,
            kith_mesh::prefix(b"ca"),
            &Web::default(),
            false,
        )
        .1;
        let thumbprint = account.unwrap().thumbprint();
        assert_eq!(thumbprint_of(&view).as_deref(), Some(thumbprint.as_str()));

        // It answers the authority's challenge with the thumbprint its view holds, and serves
        // the certificate from the next look at its view: nothing is started again.
        let web = Arc::new(Web::default());
        let prefix = kith_mesh::prefix(b"ca");
        let (wanting, account, naming) = look(&before, prefix, &web, true);
        assert_eq!((wanting.len(), account.is_none(), naming.len()), (1, true, 0));
        assert!(web.certificates.0.lock().unwrap().is_empty());
        let (wanting, account, _) = look(&view, prefix, &web, true);
        assert!(wanting.is_empty() && account.is_none());
        assert!(web.certificates.0.lock().unwrap().contains_key(host));
        let uri: Uri = "/.well-known/acme-challenge/a-token_1".parse().unwrap();
        let said = plain(State(web.clone()), HeaderMap::new(), uri).await;
        assert_eq!(said.status(), StatusCode::OK);
        let said = axum::body::to_bytes(said.into_body(), 4096).await.unwrap();
        assert_eq!(said, acme::answer("a-token_1", &thumbprint).as_bytes());

        // The worker, running from that view with --acme, asks the authority nothing: its
        // certificates are the control node's to order, and it has no account to order with.
        let worker = pinned_peer::shared_with("orders-for-a-worker-edge", edge, &[]).await;
        let mut held = view_of(&shared);
        held.remove(&key);
        worker.store.lock().unwrap().store = held.clone();
        worker.view.send_replace(Some(u64::MAX));
        let were = asked.lock().unwrap().len();
        let (stop, stopping) = watch::channel(false);
        let running = tokio::spawn(run(worker.clone(), Some(directory), None, stopping));
        tokio::time::sleep(Duration::from_secs(3)).await;
        let _ = stop.send(true);
        running.await.unwrap();
        assert_eq!(asked.lock().unwrap().len(), were, "the worker asked the authority");
        assert!(
            worker.store.lock().unwrap().store == held,
            "the worker wrote to its view"
        );
    }

    /// Orders wait on each reachable worker that serves ingress from a view until it says its
    /// view holds the thumbprint; a worker says it when its own Node does not.
    #[test]
    fn the_leader_orders_once_each_ingress_worker_holds_the_thumbprint() {
        let mut store = Store::default();
        let node = |name: &str| {
            format!("apiVersion: kith.dev/v1\nkind: Node\nmetadata: {{ name: {name} }}\nspec: {{}}\n---\n")
        };
        let source: String = ["a", "b", "c", "d", "e"].map(node).concat();
        for resource in Resource::from_source(&source).unwrap() {
            store.put(resource.unwrap());
        }
        let set = |store: &mut Store, name: &str, status: Value| {
            store.set_status(&format!("Node/{name}"), Some(status)).unwrap()
        };
        // a: a control node that serves ingress (it has the account); b: a viewed worker that
        // does not serve ingress; c and d: viewed ingress workers, d unreachable; e: one that
        // says it already.
        set(&mut store, "a", json!({ "serves": { "ingress": true } }));
        set(&mut store, "b", json!({ "view": true, "serves": { "dns": 53 } }));
        set(&mut store, "c", json!({ "view": true, "serves": { "ingress": true } }));
        set(
            &mut store,
            "d",
            json!({ "view": true, "serves": { "ingress": true }, "state": "unreachable" }),
        );
        set(
            &mut store,
            "e",
            json!({ "view": true, "serves": { "ingress": true }, "thumbprint": "print" }),
        );
        assert_eq!(unanswered(&store, "print"), ["c"]);
        assert_eq!(unanswered(&store, "another"), ["c", "e"]);

        assert_eq!(to_say(&store, "c", Some("print")).as_deref(), Some("print"));
        assert_eq!(to_say(&store, "e", Some("print")), None);
        assert_eq!(to_say(&store, "e", Some("another")).as_deref(), Some("another"));
        assert_eq!(to_say(&store, "c", None), None);
        assert_eq!(to_say(&store, "gone", Some("print")), None);
        set(
            &mut store,
            "c",
            json!({ "view": true, "serves": { "ingress": true }, "thumbprint": "print" }),
        );
        assert!(unanswered(&store, "print").is_empty());
    }
}
