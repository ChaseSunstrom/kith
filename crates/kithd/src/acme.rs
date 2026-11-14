//! An ACME client (RFC 8555): as much of one as it takes to get a certificate for one
//! name by the HTTP-01 challenge. Whoever serves port 80 for the name answers the
//! challenge with [`answer`]; that takes the account's [`Account::thumbprint`] and
//! nothing about the order, so every machine behind the name can answer.
//
// ponytail: one name per certificate, HTTP-01 only (so no wildcards), no contact address,
// no external account binding, no revocation. DNS-01 when wildcards are wanted.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use std::time::Duration;

type Fallible<T> = Result<T, String>;

/// How often an authorization or an order is asked whether it is done, a second apart.
const ASKS: usize = 90;

/// Most bytes an answer may be, and a certificate chain's most (the one large answer). Longer
/// is refused, not held: the authority is not trusted for a size.
const ANSWER: usize = 64 * 1024;
const CHAIN: usize = 256 * 1024;
/// Most bytes a nonce may be (a few dozen are what they are).
const NONCE: usize = 256;

/// The key a certificate authority knows us by.
pub struct Account(EcdsaKeyPair);

impl Account {
    /// A new key, as PKCS#8.
    pub fn generate() -> Fallible<Vec<u8>> {
        let made = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new());
        made.map(|key| key.as_ref().to_vec())
            .map_err(|e| format!("making an account key: {e}"))
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Fallible<Account> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &SystemRandom::new())
            .map(Account)
            .map_err(|e| format!("reading the account key: {e}"))
    }

    /// The public key as a JWK, its members in the order a thumbprint wants them.
    fn jwk(&self) -> String {
        // (An uncompressed point: 4, then x and y, 32 bytes each.)
        let point = &self.0.public_key().as_ref()[1..];
        let (x, y) = (BASE64.encode(&point[..32]), BASE64.encode(&point[32..]));
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
    }

    /// RFC 7638: what the account's key is called in a challenge's answer.
    pub fn thumbprint(&self) -> String {
        BASE64.encode(ring::digest::digest(&ring::digest::SHA256, self.jwk().as_bytes()))
    }

    fn sign(&self, text: &str) -> Fallible<String> {
        let signed = self.0.sign(&SystemRandom::new(), text.as_bytes());
        signed
            .map(|signature| BASE64.encode(signature))
            .map_err(|e| format!("signing: {e}"))
    }
}

/// Is `token` one a challenge could have (and safe to send back as it came)?
pub fn token_like(token: &str) -> bool {
    let fine = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    !token.is_empty() && token.len() <= 256 && token.bytes().all(fine)
}

/// What `/.well-known/acme-challenge/<token>` has to say.
pub fn answer(token: &str, thumbprint: &str) -> String {
    format!("{token}.{thumbprint}")
}

struct Session<'a> {
    client: &'a reqwest::Client,
    account: &'a Account,
    new_nonce: String,
    nonce: Option<String>,
    /// The account's URL, once it is known; until then requests carry the key itself.
    account_url: Option<String>,
}

impl Session<'_> {
    /// A signed POST: of `payload`, or of nothing (how ACME reads a resource). Gives the
    /// reply's `Location` and body, the body at most `cap` bytes.
    async fn post(&mut self, url: &str, payload: Option<&Value>, cap: usize) -> Fallible<(Option<String>, Vec<u8>)> {
        let failed = |e: reqwest::Error| format!("{url}: {e}");
        let header = |reply: &reqwest::Response, name: &str| {
            let value = reply.headers().get(name).and_then(|value| value.to_str().ok());
            value.map(str::to_string)
        };
        let mut again = true;
        loop {
            let nonce = match self.nonce.take() {
                Some(nonce) => nonce,
                None => {
                    let reply = self.client.head(&self.new_nonce).send().await.map_err(failed)?;
                    header(&reply, "replay-nonce")
                        .filter(|nonce| nonce.len() <= NONCE)
                        .ok_or(format!("{}: no nonce", self.new_nonce))?
                }
            };
            let mut protected = json!({ "alg": "ES256", "nonce": nonce, "url": url });
            match &self.account_url {
                Some(account) => protected["kid"] = json!(account),
                None => protected["jwk"] = serde_json::from_str(&self.account.jwk()).expect("a JWK"),
            }
            let protected = BASE64.encode(protected.to_string());
            let payload = payload.map_or(String::new(), |payload| BASE64.encode(payload.to_string()));
            let signature = self.account.sign(&format!("{protected}.{payload}"))?;
            let body = json!({ "protected": protected, "payload": payload, "signature": signature });
            let request = self.client.post(url).header("content-type", "application/jose+json");
            let reply = request.body(body.to_string()).send().await.map_err(failed)?;
            self.nonce = header(&reply, "replay-nonce").filter(|nonce| nonce.len() <= NONCE);
            let (status, location) = (reply.status(), header(&reply, "location"));
            let body = capped(reply, url, cap).await?;
            if status.is_success() {
                return Ok((location, body));
            }
            let problem: Value = serde_json::from_slice(&body).unwrap_or_default();
            // (A nonce can go stale on their side: once more with the fresh one.)
            let stale = problem["type"].as_str().is_some_and(|kind| kind.ends_with(":badNonce"));
            if !(stale && std::mem::take(&mut again)) {
                let detail = problem["detail"].as_str().unwrap_or("no reason given");
                return Err(format!("{url}: {status}: {detail}"));
            }
        }
    }

    async fn read(&mut self, url: &str) -> Fallible<Value> {
        let (_, body) = self.post(url, None, ANSWER).await?;
        serde_json::from_slice(&body).map_err(|e| format!("{url}: {e}"))
    }

    /// Ask for `url` (an authorization, an order) until it is `valid`.
    async fn valid(&mut self, url: &str) -> Fallible<Value> {
        for _ in 0..ASKS {
            let now = self.read(url).await?;
            match now["status"].as_str() {
                Some("valid") => return Ok(now),
                Some("pending" | "processing" | "ready") => tokio::time::sleep(Duration::from_secs(1)).await,
                _ => {
                    // (Why a challenge failed is in the challenge.)
                    let challenges = now["challenges"].as_array().into_iter().flatten();
                    let mut reasons = challenges.filter_map(|challenge| challenge["error"]["detail"].as_str());
                    let reason = reasons.next().or(now["error"]["detail"].as_str());
                    return Err(format!(
                        "{url}: {}: {}",
                        now["status"],
                        reason.unwrap_or("no reason given")
                    ));
                }
            }
        }
        Err(format!("{url}: not done after {ASKS} s"))
    }
}

fn text<'a>(from: &'a Value, field: &str, of: &str) -> Fallible<&'a str> {
    from[field].as_str().ok_or(format!("{of}: no `{field}`"))
}

/// A reply's body, if it is at most `cap` bytes.
async fn capped(mut reply: reqwest::Response, url: &str, cap: usize) -> Fallible<Vec<u8>> {
    let longer = || format!("{url}: longer than {cap} bytes");
    if reply.content_length().is_some_and(|length| length > cap as u64) {
        return Err(longer());
    }
    let mut body = Vec::new();
    while let Some(piece) = reply.chunk().await.map_err(|e| format!("{url}: {e}"))? {
        if body.len() + piece.len() > cap {
            return Err(longer());
        }
        body.extend_from_slice(&piece);
    }
    Ok(body)
}

/// Get a certificate for `host` from the authority whose directory is at `directory`:
/// the chain and a new private key, both PEM. `host`'s port 80 has to answer the
/// challenge meanwhile (see [`answer`]). Using an authority means agreeing to its terms.
pub async fn order(directory: &str, account: &Account, host: &str) -> Fallible<(String, String)> {
    let failed = |e: reqwest::Error| format!("{directory}: {e}");
    // (No redirect is followed: the URLs the directory gives are the ones asked, and a reply
    // that moves is an error.)
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(failed)?;
    let listed = client.get(directory).send().await.map_err(failed)?;
    if !listed.status().is_success() {
        return Err(format!("{directory}: {}", listed.status()));
    }
    let urls = capped(listed, directory, ANSWER).await?;
    let urls: Value = serde_json::from_slice(&urls).map_err(|e| format!("{directory}: {e}"))?;
    let mut session = Session {
        client: &client,
        account,
        new_nonce: text(&urls, "newNonce", directory)?.into(),
        nonce: None,
        account_url: None,
    };
    let agreed = json!({ "termsOfServiceAgreed": true });
    let (account_url, _) = session
        .post(text(&urls, "newAccount", directory)?, Some(&agreed), ANSWER)
        .await?;
    session.account_url = Some(account_url.ok_or("the account has no URL")?);

    let wanted = json!({ "identifiers": [{ "type": "dns", "value": host }] });
    let (order_url, order) = session
        .post(text(&urls, "newOrder", directory)?, Some(&wanted), ANSWER)
        .await?;
    let order_url = order_url.ok_or("the order has no URL")?;
    let order: Value = serde_json::from_slice(&order).map_err(|e| format!("{order_url}: {e}"))?;
    for authorization in order["authorizations"].as_array().into_iter().flatten() {
        let url = authorization.as_str().ok_or("an authorization that is no URL")?;
        let now = session.read(url).await?;
        if now["status"] == "valid" {
            continue;
        }
        let mut challenges = now["challenges"].as_array().into_iter().flatten();
        let challenge = challenges.find(|challenge| challenge["type"] == "http-01");
        let challenge = challenge.ok_or(format!("{url}: no http-01 challenge on offer"))?;
        session
            .post(text(challenge, "url", url)?, Some(&json!({})), ANSWER)
            .await?;
        session.valid(url).await?;
    }

    let made = |e: rcgen::Error| format!("making the certificate request: {e}");
    let key = rcgen::KeyPair::generate().map_err(made)?;
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).map_err(made)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let request = params.serialize_request(&key).map_err(made)?;
    let request = json!({ "csr": BASE64.encode(request.der()) });
    session
        .post(text(&order, "finalize", &order_url)?, Some(&request), ANSWER)
        .await?;
    let order = session.valid(&order_url).await?;
    let (_, chain) = session
        .post(text(&order, "certificate", &order_url)?, None, CHAIN)
        .await?;
    let chain = String::from_utf8(chain).map_err(|e| format!("the certificate: {e}"))?;
    let key = key.serialize_pem();
    // (Not handed out unless the chain's leaf names `host` and is for this key: the stored
    // certificate stays in use then.)
    crate::pki::certified(&chain, &key, host).map(drop)?;
    Ok((chain, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// What a test authority sends back: a status, its headers, its body.
    type Answer = (u16, Vec<String>, Vec<u8>);

    /// A request's head and body, the body read as far as its Content-Length says.
    async fn read_request(socket: &mut TcpStream) -> Option<(String, Vec<u8>)> {
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        let end = loop {
            if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let n = socket.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            data.extend_from_slice(&buf[..n]);
        };
        let head = String::from_utf8_lossy(&data[..end]).to_string();
        let length = head.lines().find_map(|line| {
            let line = line.to_ascii_lowercase();
            line.strip_prefix("content-length:")?.trim().parse::<usize>().ok()
        });
        let mut body = data[end..].to_vec();
        while body.len() < length.unwrap_or(0) {
            let n = socket.read(&mut buf).await.ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
        }
        Some((head, body))
    }

    /// What a certificate authority answers, as an ACME one does: a directory, an account,
    /// an order for one name whose authorization is valid already, and a certificate for
    /// the key of the request it is finalized with, for the name `names`.
    fn ca_answer(
        base: &str,
        names: &str,
        issuer: &rcgen::Issuer<'_, rcgen::KeyPair>,
        chain: &Mutex<String>,
        path: &str,
        body: &[u8],
    ) -> Answer {
        let reply = |status: u16, location: Option<String>, value: Value| -> Answer {
            let headers = location.map(|to| format!("location: {to}")).into_iter().collect();
            (status, headers, value.to_string().into_bytes())
        };
        let link = |path: &str| format!("{base}{path}");
        match path {
            "/nonce" => (200, vec!["replay-nonce: n".into()], vec![]),
            "/directory" => reply(
                200,
                None,
                json!({ "newNonce": link("/nonce"), "newAccount": link("/account"), "newOrder": link("/order") }),
            ),
            "/account" => reply(201, Some(link("/account/1")), json!({ "status": "valid" })),
            "/order" => reply(
                201,
                Some(link("/order/1")),
                json!({ "status": "pending", "authorizations": [link("/authz/1")], "finalize": link("/finalize/1") }),
            ),
            "/authz/1" => reply(200, None, json!({ "status": "valid", "challenges": [] })),
            "/finalize/1" => {
                let request: Value = serde_json::from_slice(body).unwrap();
                let payload = BASE64.decode(request["payload"].as_str().unwrap()).unwrap();
                let csr = serde_json::from_slice::<Value>(&payload).unwrap();
                let csr = BASE64.decode(csr["csr"].as_str().unwrap()).unwrap();
                let csr = rcgen::CertificateSigningRequestParams::from_der(&csr.into()).unwrap();
                let leaf = rcgen::CertificateParams::new(vec![names.to_string()]).unwrap();
                *chain.lock().unwrap() = leaf.signed_by(&csr.public_key, issuer).unwrap().pem();
                reply(200, None, json!({ "status": "processing" }))
            }
            "/order/1" => reply(200, None, json!({ "status": "valid", "certificate": link("/cert/1") })),
            "/cert/1" => (
                200,
                vec!["content-type: application/pem-certificate-chain".into()],
                chain.lock().unwrap().clone().into_bytes(),
            ),
            _ => (404, vec![], vec![]),
        }
    }

    /// A certificate authority on 127.0.0.1 (the only address these tests reach), whose
    /// certificates are for `names`. `change` sees each answer with its path and sends
    /// what it says instead. Gives the authority's address and the paths asked of it.
    async fn authority(
        names: &'static str,
        change: impl Fn(&str, &Answer) -> Answer + Send + Sync + 'static,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let issuer = Arc::new(rcgen::Issuer::new(
            rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap(),
            rcgen::KeyPair::generate().unwrap(),
        ));
        let chain = Arc::new(Mutex::new(String::new()));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (change, log, at) = (Arc::new(change), asked.clone(), base.clone());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (issuer, chain, change, log, at) =
                    (issuer.clone(), chain.clone(), change.clone(), log.clone(), at.clone());
                tokio::spawn(async move {
                    let Some((head, body)) = read_request(&mut socket).await else {
                        return;
                    };
                    let path = head.split(' ').nth(1).unwrap_or_default().to_string();
                    log.lock().unwrap().push(path.clone());
                    let normal = ca_answer(&at, names, &issuer, &chain, &path, &body);
                    let (status, headers, body) = change(&path, &normal);
                    // (`no-length` among the headers: the body's length is not said, and
                    // it ends where the connection does.)
                    let length = match headers.iter().any(|h| h == "no-length") {
                        true => String::new(),
                        false => format!("content-length: {}\r\n", body.len()),
                    };
                    let mut reply = format!("HTTP/1.1 {status} x\r\n{length}connection: close\r\n");
                    let said = headers.iter().filter(|h| *h != "no-length");
                    reply += &said.map(|h| format!("{h}\r\n")).collect::<String>();
                    reply += "\r\n";
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                });
            }
        });
        (base, asked)
    }

    /// An order from the authority at `directory`, through the client the code uses.
    async fn ordered(directory: &str, account: &Account, host: &str) -> Fallible<(String, String)> {
        // (As ingress::run does once: reqwest's TLS wants its crypto told.)
        let _ = rustls::crypto::ring::default_provider().install_default();
        order(directory, account, host).await
    }

    fn an_account() -> Account {
        Account::from_pkcs8(&Account::generate().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn acme_capped_answers_are_read_to_a_cap() {
        // Each kind of answer on its own, one byte past its cap: refused, not held, whether
        // its length was said before it or not.
        let account = an_account();
        for (path, cap, length) in [
            ("/directory", 64 * 1024, ""),
            ("/order", 64 * 1024, ""),
            ("/authz/1", 64 * 1024, ""),
            ("/cert/1", 256 * 1024, ""),
            ("/directory", 64 * 1024, "no-length"),
            ("/cert/1", 256 * 1024, "no-length"),
        ] {
            let (base, _) = authority("shop.example.org", move |asked, answer| match asked == path {
                true => (
                    200,
                    length.split_whitespace().map(str::to_string).collect(),
                    vec![b'x'; cap + 1],
                ),
                false => answer.clone(),
            })
            .await;
            let refused = ordered(&format!("{base}/directory"), &account, "shop.example.org").await;
            let refused = refused.unwrap_err();
            assert!(refused.contains("longer than"), "{path}: {refused}");
        }
        // A nonce is a header's value of a few dozen bytes, not a page of them.
        let (base, _) = authority("shop.example.org", |asked, answer| match asked {
            "/nonce" => (200, vec![format!("replay-nonce: {}", "n".repeat(300))], vec![]),
            _ => answer.clone(),
        })
        .await;
        assert!(
            ordered(&format!("{base}/directory"), &account, "shop.example.org")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn acme_no_redirect_is_followed() {
        // The authority a redirect would lead to signs whatever it is asked: it must not be asked.
        let account = an_account();
        for path in ["/directory", "/order"] {
            let (elsewhere, asked) = authority("shop.example.org", |_, answer| answer.clone()).await;
            let (base, _) = authority("shop.example.org", move |asked, answer| match asked == path {
                true => (307, vec![format!("location: {elsewhere}{path}")], vec![]),
                false => answer.clone(),
            })
            .await;
            let refused = ordered(&format!("{base}/directory"), &account, "shop.example.org").await;
            assert!(refused.is_err(), "{path}: a redirect was followed");
            let asked = asked.lock().unwrap().clone();
            assert!(asked.is_empty(), "{path}: the redirect's target was asked: {asked:?}");
        }
    }

    #[tokio::test]
    async fn acme_names_refuse_a_chain_for_another_host() {
        let account = an_account();
        let (base, _) = authority("other.example.org", |_, answer| answer.clone()).await;
        let refused = ordered(&format!("{base}/directory"), &account, "shop.example.org").await;
        let refused = refused.unwrap_err();
        assert!(refused.contains("shop.example.org"), "{refused}");
    }

    #[tokio::test]
    async fn acme_names_accept_a_chain_for_the_host() {
        // The same authority, for the host asked for: the chain comes back.
        let account = an_account();
        let (base, _) = authority("shop.example.org", |_, answer| answer.clone()).await;
        let (chain, key) = ordered(&format!("{base}/directory"), &account, "shop.example.org")
            .await
            .unwrap();
        assert!(chain.starts_with("-----BEGIN CERTIFICATE-----") && key.contains("PRIVATE KEY"));
    }

    #[test]
    fn an_account_signs_and_answers() {
        let account = Account::from_pkcs8(&Account::generate().unwrap()).unwrap();
        // What it signs, its public key checks.
        let signature = BASE64.decode(account.sign("a.b").unwrap()).unwrap();
        let public = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, account.0.public_key().as_ref());
        assert!(public.verify(b"a.b", &signature).is_ok());
        // The thumbprint: 32 bytes, the same each time, and of this key.
        let print = account.thumbprint();
        assert_eq!(BASE64.decode(&print).unwrap().len(), 32);
        assert_eq!(print, account.thumbprint());
        let other = Account::from_pkcs8(&Account::generate().unwrap()).unwrap();
        assert_ne!(print, other.thumbprint());
        assert_eq!(answer("tok", &print), format!("tok.{print}"));
        assert!(token_like("aZ0-_") && !token_like("") && !token_like("a/b") && !token_like("<script>"));
    }
}
