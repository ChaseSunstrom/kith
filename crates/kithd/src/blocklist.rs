//! Block lists for the DNS server: each `DNSBlockList` is read from a ConfigMap key or fetched
//! from an https address, made into a `kith_dns::Block`, and handed to the server through a watch
//! channel (see `dns::run`). Nothing of a list is written to disk: a restart reads or fetches it again.
//!
//! - A fetched list is asked for again every `interval` (24h unless it says). A fetch that fails, a
//!   body over the size cap, one that does not match `sha256`, or a list over the per-node bound
//!   leaves the list in use as it was, and the status says why.
//! - Only https is fetched, from an address that is not this node or its networks (the check
//!   Sources have: `sources::vetted`, the address then held for the connection), no redirect is
//!   followed, and no more than `MAX_BYTES` is read.
//! - A ConfigMap list is a key of a ConfigMap in `kith-system`: whoever writes it decides names
//!   for every node's clients.
//! - The names of all lists together are bounded by `MAX_NAMES` (8 bytes each once held).
//! - Each list's status says its state, name count, when it was fetched and by which node.
//!
//! A URL list is fetched by every node that serves DNS: the host of the list sees each node's
//! address and when it asks (SECURITY.md, "A block list is trusted…").
//
// ponytail: every node writes the same status, so with several nodes the last writer's `node`,
// `fetched` and cache numbers are what is shown; per-node status once someone needs to tell them apart.

use crate::Shared;
use kith_api::kinds::{
    BLOCK_LIST_INTERVAL, BLOCK_LIST_MIN_INTERVAL, DnsBlockAnswer, DnsBlockListSpec, every, https_url,
};
use kith_api::store::{now as unix_now, rfc3339};
use kith_dns::{Block, Cache, Cidr, Names, parse_list};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

/// The most names all the lists of one node hold together: 8 MB of hashes.
pub const MAX_NAMES: usize = 1_000_000;
/// The most bytes of one fetched list. (A million names as a hosts file is about 30 MB.)
// ponytail: the body is held whole while it is read, so a fetch can take this much memory for a moment.
const MAX_BYTES: usize = 32 << 20;
/// How long a fetch may take in all, and to connect.
const FETCH: Duration = Duration::from_secs(60);
const CONNECT: Duration = Duration::from_secs(10);

/// A list the store holds, and where its text comes from.
pub struct Want {
    key: String,
    spec: DnsBlockListSpec,
    source: Source,
}

enum Source {
    /// A ConfigMap key: a hash of its text, and the text itself when `Lists::needs` asked for it.
    Text {
        hash: u64,
        text: Result<Option<String>, String>,
    },
    Url,
}

/// What a list was last read as.
struct Good {
    names: Arc<Names>,
    skipped: usize,
    at: u64,
}

#[derive(Default)]
struct Held {
    spec: Option<DnsBlockListSpec>,
    /// A hash of the ConfigMap text last read.
    seen: Option<u64>,
    good: Option<Good>,
    error: Option<String>,
    /// When a URL list is fetched next.
    next: Option<Instant>,
}

pub struct Lists {
    held: BTreeMap<String, Held>,
    /// The status last written for each list, so the same one is not written twice.
    written: BTreeMap<String, Value>,
    /// The cache's numbers as they were when a list was last read: a status is not written
    /// again only to say them.
    cache: Value,
    /// The lists last given to the server.
    published: Vec<Block>,
    max: usize,
}

impl Default for Lists {
    fn default() -> Lists {
        Lists {
            held: BTreeMap::new(),
            written: BTreeMap::new(),
            cache: Value::Null,
            published: Vec::new(),
            max: MAX_NAMES,
        }
    }
}

/// What one pass over the lists came to.
pub struct Round {
    /// The lists to serve, when they are not the ones served already.
    pub blocks: Option<Vec<Block>>,
    /// Statuses to write.
    pub statuses: Vec<(String, Option<Value>)>,
}

fn hash_of(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// The URL check: https only. (In tests a list is served from this machine over plain http.)
fn check_url(url: &str) -> Result<(), String> {
    #[cfg(test)]
    if url.starts_with("http://127.0.0.1:") {
        return Ok(());
    }
    https_url(url)
}

/// A list's text from `url`, at most `MAX_BYTES`, and as `sha256` says if it says.
async fn fetch_list(url: &str, sha256: Option<&str>) -> Result<String, String> {
    check_url(url)?;
    let failed = |e: reqwest::Error| format!("{url}: {e}");
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("{url}: {e}"))?;
    // kithd fetches as root from inside the cluster: not from this node or its networks, and
    // from the address that was looked at (not one a second lookup gives).
    let (host, _, addresses) = crate::sources::vetted(&parsed.origin().ascii_serialization())
        .await
        .map_err(|e| match e.contains("its own networks") {
            true => format!(
                "{url}: a list is not fetched from this node or its own networks (a list of your own goes in a \
                 ConfigMap in kith-system)"
            ),
            false => e,
        })?;
    // (No redirect is followed: the address is the one the spec names. Nor a proxy, which
    // would look the name up again itself.)
    let client = reqwest::Client::builder()
        .resolve_to_addrs(&host, &addresses)
        .no_proxy()
        .timeout(FETCH)
        .connect_timeout(CONNECT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(failed)?;
    let reply = client.get(parsed).send().await.map_err(failed)?;
    let status = reply.status();
    if status.is_redirection() {
        return Err(format!("{url}: {status}; a redirect is not followed"));
    }
    if !status.is_success() {
        return Err(format!("{url}: {status}"));
    }
    let body = crate::acme::capped(reply, url, MAX_BYTES).await?;
    if let Some(want) = sha256 {
        let got = crate::pki::hex(&Sha256::digest(&body));
        if !got.eq_ignore_ascii_case(want) {
            return Err(format!("{url}: its SHA-256 is {got}, not the {want} the list says"));
        }
    }
    Ok(String::from_utf8(body).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

impl Lists {
    /// Does `key` need its ConfigMap text, not only its hash: it is new, edited or changed?
    pub fn needs(&self, key: &str, spec: &DnsBlockListSpec, hash: u64) -> bool {
        self.held
            .get(key)
            .is_none_or(|held| held.spec.as_ref() != Some(spec) || held.seen != Some(hash))
    }

    /// When something is next to do on its own: a URL list's fetch.
    pub fn due(&self) -> Option<Instant> {
        self.held.values().filter_map(|held| held.next).min()
    }

    /// Forgets what was written for these keys, so the next pass writes them again.
    pub fn unwritten(&mut self) {
        self.written.clear();
    }

    /// One pass: reads or fetches what is due, and gives what changed. `wants` are all the lists in
    /// the store, in the order they win (by key).
    pub async fn round(&mut self, wants: Vec<(Want, Option<Value>)>, now: Instant, cache: &Cache, node: &str) -> Round {
        let live: BTreeMap<String, Option<Value>> =
            wants.iter().map(|(w, live)| (w.key.clone(), live.clone())).collect();
        self.held.retain(|key, _| live.contains_key(key));
        self.written.retain(|key, _| live.contains_key(key));
        let mut used = 0;
        let mut reloaded = false;
        for (want, _) in &wants {
            let held = self.held.entry(want.key.clone()).or_default();
            if held.spec.as_ref() != Some(&want.spec) {
                // New or edited: what was held is not what the spec names any more.
                *held = Held {
                    spec: Some(want.spec.clone()),
                    ..Held::default()
                };
                reloaded = true;
            }
            let room = self.max.saturating_sub(used);
            let before_names = held.good.as_ref().map(|g| Arc::as_ptr(&g.names));
            match &want.source {
                Source::Text { hash, text } => match text {
                    Ok(Some(text)) => {
                        held.seen = Some(*hash);
                        load(held, text, room, self.max);
                    }
                    Ok(None) => {}
                    Err(e) => held.error = Some(e.clone()),
                },
                Source::Url => {
                    if held.next.is_none_or(|next| next <= now) {
                        let url = want.spec.url.as_deref().unwrap_or_default();
                        let every = want
                            .spec
                            .interval
                            .as_deref()
                            .and_then(every)
                            .unwrap_or(BLOCK_LIST_INTERVAL);
                        match fetch_list(url, want.spec.sha256.as_deref()).await {
                            Ok(text) => {
                                load(held, &text, room, self.max);
                                held.next = Some(now + Duration::from_secs(every));
                            }
                            Err(e) => {
                                held.error = Some(e);
                                held.next = Some(now + Duration::from_secs(BLOCK_LIST_MIN_INTERVAL.min(every)));
                            }
                        }
                    }
                }
            }
            reloaded |= before_names != held.good.as_ref().map(|g| Arc::as_ptr(&g.names));
            used += held.good.as_ref().map_or(0, |g| g.names.len());
        }
        let after = self.blocks(&wants);
        let blocks = (!same(&self.published, &after)).then(|| {
            self.published = after.clone();
            after
        });

        if reloaded || self.cache.is_null() {
            let s = cache.stats();
            self.cache = json!({ "entries": s.entries, "bytes": s.bytes, "hits": s.hits, "misses": s.misses });
        }
        let mut statuses = Vec::new();
        for (want, _) in &wants {
            let status = self.status(&want.key, node);
            // Written when it is not what this node wrote last, or the resource has none.
            if self.written.get(&want.key) != Some(&status) || live[&want.key].is_none() {
                self.written.insert(want.key.clone(), status.clone());
                statuses.push((want.key.clone(), Some(status)));
            }
        }
        Round { blocks, statuses }
    }

    /// The lists as the server takes them: those that hold names and fit the bound, in order.
    fn blocks(&self, wants: &[(Want, Option<Value>)]) -> Vec<Block> {
        let mut used = 0;
        let mut blocks = Vec::new();
        for (want, _) in wants {
            let Some(good) = self.held.get(&want.key).and_then(|held| held.good.as_ref()) else {
                continue;
            };
            if used + good.names.len() > self.max {
                continue;
            }
            // A network this cannot read (an apply refuses one) would leave the list with fewer
            // clients than it names, or with none, which is everyone: such a list is not served.
            let Ok(nets) = want
                .spec
                .clients
                .iter()
                .map(|net| net.parse::<Cidr>())
                .collect::<Result<Vec<_>, _>>()
            else {
                continue;
            };
            used += good.names.len();
            blocks.push(Block {
                nets,
                names: good.names.clone(),
                null: want.spec.answer == Some(DnsBlockAnswer::Unspecified),
            });
        }
        blocks
    }

    fn status(&self, key: &str, node: &str) -> Value {
        let held = &self.held[key];
        // (See `blocks`: such a list is not served.)
        let clients = held.spec.iter().flat_map(|spec| &spec.clients);
        let unread = clients.clone().find(|net| net.parse::<Cidr>().is_err());
        if let Some(net) = unread {
            let message = format!("clients: `{net}` is not a network: the list is not served");
            return json!({ "state": "error", "node": node, "message": message });
        }
        let mut status = json!({ "state": if held.error.is_some() || held.good.is_none() { "error" } else { "loaded" }, "node": node });
        if let Some(good) = &held.good {
            status["names"] = good.names.len().into();
            status["skipped"] = good.skipped.into();
            status["fetched"] = rfc3339(good.at).into();
        }
        match (&held.error, &held.good) {
            (Some(why), Some(_)) => status["message"] = format!("{why}; the list in use is unchanged").into(),
            (Some(why), None) => status["message"] = why.clone().into(),
            (None, None) => status["message"] = "not read yet".into(),
            (None, Some(_)) => {}
        }
        status["cache"] = self.cache.clone();
        status
    }
}

/// Reads `text` as the list: it replaces the one held unless it is over the bound.
fn load(held: &mut Held, text: &str, room: usize, max: usize) {
    let parsed = parse_list(text, room);
    if parsed.over {
        held.error = Some(format!(
            "more names than this node holds in all its lists ({max}, {room} of them left for this one)"
        ));
    } else {
        held.error = None;
        held.good = Some(Good {
            names: Arc::new(parsed.names),
            skipped: parsed.skipped,
            at: unix_now(),
        });
    }
}

fn same(a: &[Block], b: &[Block]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(a, b)| Arc::ptr_eq(&a.names, &b.names) && a.null == b.null && a.nets == b.nets)
}

/// The `DNSBlockList`s in the store, with the ConfigMap text of those that have one when it is new.
fn wants(shared: &Shared, lists: &Lists) -> Vec<(Want, Option<Value>)> {
    let state = shared.store.lock().expect("nothing panics holding the store");
    let mut wants = Vec::new();
    for resource in state.store.list(Some("DNSBlockList")) {
        let Ok(spec) = serde_json::from_value::<DnsBlockListSpec>(resource.spec.clone()) else {
            continue;
        };
        let source = match &spec.config_map {
            Some(map) => {
                let key = format!("ConfigMap/kith-system/{}", map.name);
                let text = state.store.get(&key).and_then(|cm| cm.spec["data"][&map.key].as_str());
                match text {
                    None => Source::Text {
                        hash: 0,
                        text: Err(format!("there is no key `{}` in the ConfigMap `{key}`", map.key)),
                    },
                    Some(text) => {
                        let hash = hash_of(text);
                        let text = Ok(lists.needs(&resource.key(), &spec, hash).then(|| text.to_string()));
                        Source::Text { hash, text }
                    }
                }
            }
            None => Source::Url,
        };
        let key = resource.key();
        wants.push((Want { key, spec, source }, resource.status.clone()));
    }
    wants
}

/// Keeps the DNS server's lists as the store says, until kithd stops.
pub async fn run(shared: Arc<Shared>, cache: Arc<Cache>, out: watch::Sender<Arc<Vec<Block>>>) {
    // (reqwest's TLS wants to be told once which crypto to use.)
    let _ = rustls::crypto::ring::default_provider().install_default();
    let node = shared
        .cluster
        .as_ref()
        .map_or("local", |cluster| cluster.me.name.as_str());
    let mut generation = shared.generation.subscribe();
    let mut lists = Lists::default();
    loop {
        let wanted = wants(&shared, &lists);
        let round = lists.round(wanted, Instant::now(), &cache, node).await;
        if let Some(blocks) = round.blocks {
            out.send_replace(Arc::new(blocks));
        }
        if !round.statuses.is_empty()
            && let Err(e) = shared
                .submit(kith_store::Command::Status {
                    statuses: round.statuses,
                })
                .await
        {
            eprintln!("kithd: reporting on block lists: {e}");
            lists.unwritten();
        }
        let due = lists.due();
        tokio::select! {
            changed = generation.changed() => if changed.is_err() { return },
            () = async { match due { Some(at) => tokio::time::sleep_until(at).await, None => std::future::pending().await } } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serves `(status, body)` for every request, from this machine; the pair can be changed.
    async fn serve(reply: Arc<Mutex<(u16, String)>>) -> String {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // (This test's "outside" is this machine.)
        crate::sources::LOOPBACK_IS_OUTSIDE.set(true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let (code, body) = reply.lock().unwrap().clone();
                tokio::spawn(async move {
                    let mut request = [0u8; 2048];
                    let _ = socket.read(&mut request).await;
                    let head = format!(
                        "HTTP/1.1 {code} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(body.as_bytes()).await;
                });
            }
        });
        format!("http://127.0.0.1:{port}/list.txt")
    }

    fn spec() -> DnsBlockListSpec {
        DnsBlockListSpec {
            config_map: None,
            url: None,
            sha256: None,
            interval: None,
            answer: None,
            clients: vec![],
        }
    }

    fn url_list(key: &str, url: &str, edit: impl FnOnce(&mut DnsBlockListSpec)) -> (Want, Option<Value>) {
        let mut spec = DnsBlockListSpec {
            url: Some(url.into()),
            ..spec()
        };
        edit(&mut spec);
        let want = Want {
            key: format!("DNSBlockList/{key}"),
            spec,
            source: Source::Url,
        };
        (want, None)
    }

    fn text_list(key: &str, text: &str, edit: impl FnOnce(&mut DnsBlockListSpec)) -> (Want, Option<Value>) {
        let mut spec = DnsBlockListSpec {
            config_map: Some(kith_api::kinds::BlockListMap {
                name: "lists".into(),
                key: key.into(),
            }),
            ..spec()
        };
        edit(&mut spec);
        let source = Source::Text {
            hash: hash_of(text),
            text: Ok(Some(text.into())),
        };
        let want = Want {
            key: format!("DNSBlockList/{key}"),
            spec,
            source,
        };
        (want, None)
    }

    fn blocked(blocks: &[Block], name: &str) -> Option<bool> {
        let zones = kith_dns::Zones {
            blocks: blocks.to_vec(),
            ..Default::default()
        };
        zones.blocked("192.168.1.5".parse::<IpAddr>().unwrap(), name)
    }

    const LATER: Duration = Duration::from_secs(2 * 86_400);

    #[test]
    fn blocklist_only_https_is_fetched() {
        let said = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fetch_list("http://lists.example/hosts", None))
            .unwrap_err();
        assert!(said.contains("not an https://"), "{said}");
    }

    #[tokio::test]
    async fn blocklist_a_fetched_list_is_served_and_the_last_good_one_kept() {
        let reply = Arc::new(Mutex::new((
            200,
            "0.0.0.0 ads.example\n# note\ntracker.example\n".to_string(),
        )));
        let url = serve(reply.clone()).await;
        let (cache, mut lists, start) = (Cache::default(), Lists::default(), Instant::now());

        let round = lists
            .round(vec![url_list("ads", &url, |_| {})], start, &cache, "alpha")
            .await;
        let blocks = round.blocks.expect("a list came in");
        assert_eq!(blocked(&blocks, "x.ads.example"), Some(false));
        assert_eq!(blocked(&blocks, "good.example"), None);
        let (key, status) = &round.statuses[0];
        let status = status.as_ref().unwrap();
        assert_eq!(key, "DNSBlockList/ads");
        assert_eq!(
            (status["state"].as_str(), status["names"].as_u64()),
            (Some("loaded"), Some(2))
        );
        assert_eq!(status["node"], "alpha");
        assert!(status["fetched"].as_str().unwrap().ends_with('Z'));

        // Not due yet: nothing is fetched, nothing changes, nothing is written again (the store
        // now holds the status that was written).
        *reply.lock().unwrap() = (500, String::new());
        let mut stored = url_list("ads", &url, |_| {});
        stored.1 = Some(status.clone());
        let again = lists.round(vec![stored], start, &cache, "alpha").await;
        assert!(again.blocks.is_none() && again.statuses.is_empty());

        // Due, and the host fails: the list in use stays, and the status says why.
        let failed = lists
            .round(vec![url_list("ads", &url, |_| {})], start + LATER, &cache, "alpha")
            .await;
        assert!(failed.blocks.is_none());
        let status = failed.statuses[0].1.as_ref().unwrap();
        assert_eq!(
            (status["state"].as_str(), status["names"].as_u64()),
            (Some("error"), Some(2))
        );
        let message = status["message"].as_str().unwrap();
        assert!(
            message.contains("500") && message.contains("the list in use is unchanged"),
            "{message}"
        );

        // The host is back with another list.
        *reply.lock().unwrap() = (200, "other.example\n".to_string());
        let back = lists
            .round(vec![url_list("ads", &url, |_| {})], start + 2 * LATER, &cache, "alpha")
            .await;
        let blocks = back.blocks.unwrap();
        assert_eq!(
            (blocked(&blocks, "ads.example"), blocked(&blocks, "other.example")),
            (None, Some(false))
        );
    }

    #[tokio::test]
    async fn blocklist_a_list_that_does_not_match_its_sha256_is_refused() {
        let reply = Arc::new(Mutex::new((200, "ads.example\n".to_string())));
        let url = serve(reply).await;
        let right = crate::pki::hex(&Sha256::digest("ads.example\n"));
        let (cache, mut lists, now) = (Cache::default(), Lists::default(), Instant::now());

        let wrong = "0".repeat(64);
        let round = lists
            .round(
                vec![url_list("ads", &url, |s| s.sha256 = Some(wrong.clone()))],
                now,
                &cache,
                "alpha",
            )
            .await;
        assert!(round.blocks.is_none());
        let message = round.statuses[0].1.as_ref().unwrap()["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(message.contains("SHA-256") && message.contains(&right), "{message}");

        // Edited to the right one, it is read at once, not at the next interval.
        let round = lists
            .round(
                vec![url_list("ads", &url, |s| s.sha256 = Some(right.to_ascii_uppercase()))],
                now,
                &cache,
                "alpha",
            )
            .await;
        assert_eq!(blocked(&round.blocks.unwrap(), "ads.example"), Some(false));
    }

    #[tokio::test]
    async fn blocklist_a_list_is_not_fetched_from_this_node_or_its_networks() {
        // kithd fetches as root from inside the cluster: what answers there is not a list's to ask.
        for url in [
            "https://127.0.0.1:6443/list",
            "https://localhost/list",
            "https://[::1]:8080/list",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.1/list",
            "https://192.168.1.1:8443/hosts",
            "https://0x7f.1/list",
            "https://2130706433/list",
        ] {
            let said = fetch_list(url, None).await.unwrap_err();
            assert!(
                said.contains("its own networks") && said.contains("ConfigMap"),
                "{url}: {said}"
            );
        }
        // Nor an address written so that one reader takes another host from it.
        let said = fetch_list("https://lists.example@127.0.0.1/list", None)
            .await
            .unwrap_err();
        assert!(said.contains("no user or password"), "{said}");
        // Nor a second spelling of a name, which would be looked up again when connecting.
        let said = fetch_list("https://lists.example./list", None).await.unwrap_err();
        assert!(said.contains("no dot at its end"), "{said}");
    }

    #[tokio::test]
    async fn blocklist_a_list_whose_clients_cannot_be_read_is_not_served() {
        // (An apply refuses such a list; one that got in must not come to block everyone.)
        let (cache, mut lists, now) = (Cache::default(), Lists::default(), Instant::now());
        let want = text_list("hosts", "ads.example\n", |spec| {
            spec.clients = vec!["192.168.0.0/16".into(), "not a network".into()];
        });
        let round = lists.round(vec![want], now, &cache, "alpha").await;
        assert!(round.blocks.is_none_or(|blocks| blocks.is_empty()));
        let status = round.statuses[0].1.clone().unwrap();
        assert_eq!(status["state"], "error", "{status}");
        assert!(
            status["message"].as_str().unwrap().contains("not a network"),
            "{status}"
        );
    }

    #[tokio::test]
    async fn blocklist_a_redirect_is_not_followed() {
        let reply = Arc::new(Mutex::new((302, String::new())));
        let url = serve(reply).await;
        let said = fetch_list(&url, None).await.unwrap_err();
        assert!(said.contains("302") && said.contains("not followed"), "{said}");
    }

    #[tokio::test]
    async fn blocklist_config_map_lists_are_read_again_when_their_text_changes() {
        let (cache, mut lists, now) = (Cache::default(), Lists::default(), Instant::now());
        let first = text_list("hosts", "ads.example\n127.0.0.1 localhost\nnot a list line\n", |s| {
            s.answer = Some(DnsBlockAnswer::Unspecified);
            s.clients = vec!["192.168.0.0/16".into()];
        });
        let round = lists.round(vec![first], now, &cache, "alpha").await;
        let blocks = round.blocks.unwrap();
        // The unspecified answer, and only for the client network named.
        assert_eq!(blocked(&blocks, "ads.example"), Some(true));
        assert_eq!(blocks[0].nets.len(), 1);
        let status = round.statuses[0].1.as_ref().unwrap();
        assert_eq!(
            (status["names"].as_u64(), status["skipped"].as_u64()),
            (Some(1), Some(1))
        );

        // The same text: not asked for again, nothing changes.
        let spec = |s: &mut DnsBlockListSpec| {
            s.answer = Some(DnsBlockAnswer::Unspecified);
            s.clients = vec!["192.168.0.0/16".into()];
        };
        let (want, _) = text_list("hosts", "ads.example\n127.0.0.1 localhost\nnot a list line\n", spec);
        assert!(!lists.needs(
            &want.key,
            &want.spec,
            hash_of("ads.example\n127.0.0.1 localhost\nnot a list line\n")
        ));
        assert!(lists.needs(&want.key, &want.spec, hash_of("other.example\n")));

        let second = text_list("hosts", "other.example\n", spec);
        let round = lists.round(vec![second], now, &cache, "alpha").await;
        let blocks = round.blocks.unwrap();
        assert_eq!(
            (blocked(&blocks, "ads.example"), blocked(&blocks, "other.example")),
            (None, Some(true))
        );
        // A list that is deleted stops blocking.
        let gone = lists.round(vec![], now, &cache, "alpha").await;
        assert!(gone.blocks.unwrap().is_empty());
        assert!(lists.held.is_empty() && lists.due().is_none());
    }

    #[tokio::test]
    async fn blocklist_names_in_all_lists_together_are_bounded() {
        let (cache, now) = (Cache::default(), Instant::now());
        let mut lists = Lists {
            max: 3,
            ..Lists::default()
        };
        let round = lists
            .round(
                vec![
                    text_list("a", "one.example\ntwo.example\n", |_| {}),
                    text_list("b", "three.example\nfour.example\n", |_| {}),
                ],
                now,
                &cache,
                "alpha",
            )
            .await;
        let blocks = round.blocks.unwrap();
        // The second would take the node past its bound: it is refused, the first is served.
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            (blocked(&blocks, "two.example"), blocked(&blocks, "four.example")),
            (Some(false), None)
        );
        let status = round.statuses[1].1.as_ref().unwrap();
        assert_eq!(status["state"], "error");
        assert!(
            status["message"]
                .as_str()
                .unwrap()
                .contains("more names than this node holds")
        );
    }

    #[tokio::test]
    async fn blocklist_a_status_is_written_when_it_changes_or_is_missing() {
        let (cache, mut lists, now) = (Cache::default(), Lists::default(), Instant::now());
        let want = || text_list("hosts", "ads.example\n", |_| {});
        let round = lists.round(vec![want()], now, &cache, "alpha").await;
        assert_eq!(round.statuses.len(), 1);
        let said = round.statuses[0].1.clone();
        // Another node wrote its own status over it: this one does not write over that.
        let (w, _) = want();
        let elsewhere = lists
            .round(vec![(w, Some(json!({ "node": "beta" })))], now, &cache, "alpha")
            .await;
        assert!(elsewhere.statuses.is_empty());
        // The resource has no status (made again): written again.
        let (w, _) = want();
        let again = lists.round(vec![(w, None)], now, &cache, "alpha").await;
        assert_eq!(again.statuses[0].1, said);
        // The cache's numbers are in it.
        assert!(said.unwrap()["cache"]["entries"].is_u64());
    }
}
