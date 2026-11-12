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
    /// reply's `Location` and body.
    async fn post(&mut self, url: &str, payload: Option<&Value>) -> Fallible<(Option<String>, Vec<u8>)> {
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
                    header(&reply, "replay-nonce").ok_or(format!("{}: no nonce", self.new_nonce))?
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
            self.nonce = header(&reply, "replay-nonce");
            let (status, location) = (reply.status(), header(&reply, "location"));
            let body = reply.bytes().await.map_err(failed)?.to_vec();
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
        let (_, body) = self.post(url, None).await?;
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

/// Get a certificate for `host` from the authority whose directory is at `directory`:
/// the chain and a new private key, both PEM. `host`'s port 80 has to answer the
/// challenge meanwhile (see [`answer`]). Using an authority means agreeing to its terms.
pub async fn order(
    client: &reqwest::Client,
    directory: &str,
    account: &Account,
    host: &str,
) -> Fallible<(String, String)> {
    let failed = |e: reqwest::Error| format!("{directory}: {e}");
    let listed = client.get(directory).send().await.map_err(failed)?;
    let urls: Value = listed.json().await.map_err(failed)?;
    let mut session = Session {
        client,
        account,
        new_nonce: text(&urls, "newNonce", directory)?.into(),
        nonce: None,
        account_url: None,
    };
    let agreed = json!({ "termsOfServiceAgreed": true });
    let (account_url, _) = session
        .post(text(&urls, "newAccount", directory)?, Some(&agreed))
        .await?;
    session.account_url = Some(account_url.ok_or("the account has no URL")?);

    let wanted = json!({ "identifiers": [{ "type": "dns", "value": host }] });
    let (order_url, order) = session.post(text(&urls, "newOrder", directory)?, Some(&wanted)).await?;
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
        session.post(text(challenge, "url", url)?, Some(&json!({}))).await?;
        session.valid(url).await?;
    }

    let made = |e: rcgen::Error| format!("making the certificate request: {e}");
    let key = rcgen::KeyPair::generate().map_err(made)?;
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).map_err(made)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let request = params.serialize_request(&key).map_err(made)?;
    let request = json!({ "csr": BASE64.encode(request.der()) });
    session
        .post(text(&order, "finalize", &order_url)?, Some(&request))
        .await?;
    let order = session.valid(&order_url).await?;
    let (_, chain) = session.post(text(&order, "certificate", &order_url)?, None).await?;
    let chain = String::from_utf8(chain).map_err(|e| format!("the certificate: {e}"))?;
    Ok((chain, key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

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
