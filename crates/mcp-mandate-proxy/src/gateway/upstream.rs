//! The gateway's side of each server: where it is, and the gateway's own
//! credential for it. The caller's token never leaves the gateway, and one
//! server's credential is never sent to another.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue};
use reqwest::{Method, RequestBuilder, Response, Url};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::config::{Auth, Secret, ServerConfig};
use crate::ProxyError;

pub const SESSION_HEADER: &str = "mcp-session-id";
pub const PROTOCOL_HEADER: &str = "mcp-protocol-version";
/// How long a fetched access token is taken to last when deciding how long
/// to send it: as its `expires_in` says, but at most a day, and five
/// minutes without one.
const MAX_TOKEN_SECONDS: u64 = 24 * 3600;
const DEFAULT_TOKEN_SECONDS: u64 = 300;
/// A token stays among the [credential strings](Upstream::credential_strings)
/// for as long as it may be valid, long after it's last sent: until its
/// `expires_in` (at most a year), or for a day without one...
const MAX_SECRET_SECONDS: u64 = 365 * 24 * 3600;
const UNKNOWN_SECRET_SECONDS: u64 = 24 * 3600;
/// ...and only the newest this many tokens do, so they don't pile up.
const MAX_LISTED_TOKENS: usize = 16;
/// A token is renewed this long before it expires, so it never expires
/// mid-request...
const RENEW_EARLY: Duration = Duration::from_secs(30);
/// ...but is used for at least this long, so a short `expires_in` doesn't
/// mean a token fetch for every request.
const MIN_TOKEN_USE: Duration = Duration::from_secs(10);
/// Largest reply accepted from the token endpoint.
const MAX_TOKEN_REPLY_BYTES: usize = 64 * 1024;

/// The HTTP client for servers: no redirects (a redirect could carry the
/// gateway's credential to another host), and a limit on waiting for a
/// connection or for data.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(300))
        .user_agent(concat!("mcp-mandate/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("the HTTP client's settings are valid")
}

pub struct Upstream {
    pub url: Url,
    http: reqwest::Client,
    credential: Credential,
}

enum Credential {
    None,
    Header(HeaderName, HeaderValue),
    ClientCredentials(Box<ClientCredentials>),
}

struct ClientCredentials {
    token_url: Url,
    client_id: String,
    client_secret: Secret,
    scope: Option<String>,
    resource: String,
    /// Never held across an await.
    tokens: Mutex<Tokens>,
    /// Held while a token is fetched, so only one fetch runs at a time.
    fetching: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Tokens {
    /// The token to send, and when to stop sending it.
    current: Option<(HeaderValue, Instant)>,
    /// The tokens handed out that may still be valid, oldest first, with
    /// until when each stays secret: a request or stream may be carrying
    /// any of them, and a server may echo one later.
    issued: Vec<(HeaderValue, Instant)>,
}

impl Tokens {
    /// Makes `token`, which the token endpoint says lasts `expires_in`
    /// seconds, the one to send, and lists it for as long as it may be
    /// valid.
    fn issue(&mut self, token: HeaderValue, expires_in: Option<u64>, now: Instant) {
        let (send_for, secret_for) = lifetimes(expires_in);
        self.current = Some((token.clone(), now + send_for));
        self.issued.retain(|(_, until)| now < *until);
        self.issued.push((token, now + secret_for.max(send_for)));
        let excess = self.issued.len().saturating_sub(MAX_LISTED_TOKENS);
        self.issued.drain(..excess);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("couldn't reach the token endpoint")]
    Fetch(#[source] reqwest::Error),
    #[error("the token endpoint answered with HTTP {0}")]
    Status(u16),
    #[error("the token endpoint's reply is larger than {MAX_TOKEN_REPLY_BYTES} bytes")]
    TooLarge,
    #[error("the token endpoint's reply isn't a JSON token reply")]
    Malformed,
    #[error("the token endpoint's reply has no usable bearer `access_token`")]
    Invalid,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: Option<String>,
    token_type: Option<String>,
    #[serde(default, deserialize_with = "seconds")]
    expires_in: Option<u64>,
}

/// A number of seconds, given as a number or (by some providers) as a
/// string of digits. Anything else counts as not given.
fn seconds<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    Ok(match Value::deserialize(deserializer)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    })
}

impl Upstream {
    pub fn new(server: &ServerConfig, http: reqwest::Client) -> Self {
        let credential = match &server.auth {
            Auth::None => Credential::None,
            Auth::Header { name, value } => {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .expect("header names are checked when the configuration loads");
                let mut value = HeaderValue::from_str(value.expose())
                    .expect("secrets are checked for control characters when they load");
                value.set_sensitive(true);
                Credential::Header(name, value)
            }
            Auth::ClientCredentials {
                token_url,
                client_id,
                client_secret,
                scope,
                resource,
            } => Credential::ClientCredentials(Box::new(ClientCredentials {
                token_url: token_url.clone(),
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                scope: scope.clone(),
                resource: resource.clone(),
                tokens: Mutex::default(),
                fetching: tokio::sync::Mutex::new(()),
            })),
        };
        Self {
            url: server.url.clone(),
            http,
            credential,
        }
    }

    /// A request to the server carrying the gateway's credential and only
    /// the headers MCP needs: nothing else from the caller is passed on.
    pub async fn request(
        &self,
        method: Method,
        accept: &'static str,
        session: Option<&str>,
        protocol: Option<&HeaderValue>,
    ) -> Result<RequestBuilder, CredentialError> {
        let mut request = self
            .http
            .request(method, self.url.clone())
            .header(ACCEPT, accept);
        if let Some(session) = session {
            request = request.header(SESSION_HEADER, session);
        }
        if let Some(protocol) = protocol {
            request = request.header(PROTOCOL_HEADER, protocol.clone());
        }
        Ok(match &self.credential {
            Credential::None => request,
            Credential::Header(name, value) => request.header(name.clone(), value.clone()),
            Credential::ClientCredentials(client) => {
                request.header(AUTHORIZATION, client.token(&self.http).await?)
            }
        })
    }

    /// Posts one JSON-RPC message.
    pub async fn post(
        &self,
        body: Vec<u8>,
        session: Option<&str>,
        protocol: Option<&HeaderValue>,
    ) -> Result<Response, ProxyError> {
        Ok(self
            .request(
                Method::POST,
                "application/json, text/event-stream",
                session,
                protocol,
            )
            .await?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?)
    }

    /// Ends a session on the server.
    pub async fn delete(&self, session: &str) -> Result<Response, ProxyError> {
        Ok(self
            .request(Method::DELETE, "application/json", Some(session), None)
            .await?
            .send()
            .await?)
    }

    /// Every form of the credential the gateway uses for this server right
    /// now (the header value, the token after its scheme, the client
    /// secret, every access token that may still be valid), so a server
    /// echoing it back can't hand it to a caller. A token is listed from
    /// before it's first sent until it expires, or for a day when the
    /// token endpoint didn't say; only the newest few are.
    pub fn credential_strings(&self) -> Vec<String> {
        match &self.credential {
            Credential::None => Vec::new(),
            Credential::Header(_, value) => credential_forms(value),
            Credential::ClientCredentials(client) => {
                let mut forms = vec![client.client_secret.expose().to_owned()];
                let now = Instant::now();
                let mut tokens = client.tokens();
                tokens.issued.retain(|(_, expires)| now < *expires);
                for (token, _) in &tokens.issued {
                    forms.extend(credential_forms(token));
                }
                forms
            }
        }
    }

    /// The URL without its query, which could hold a secret, for logs.
    pub fn display_url(&self) -> String {
        let mut url = self.url.clone();
        url.set_query(None);
        url.set_fragment(None);
        url.to_string()
    }
}

/// A credential header's value, and the token after its scheme (`Bearer`,
/// `token`, `SSWS`, in any case): a server may echo either. (Read as text
/// even if it isn't ASCII, rather than not at all.)
fn credential_forms(value: &HeaderValue) -> Vec<String> {
    let value = String::from_utf8_lossy(value.as_bytes());
    let value = value.as_ref();
    let mut forms = vec![value.to_owned()];
    if let Some((scheme, token)) = value.split_once(' ')
        && !scheme.is_empty()
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
        && !token.trim().is_empty()
    {
        forms.push(token.trim().to_owned());
    }
    forms
}

/// For a token the token endpoint says lasts `expires_in` seconds: how long
/// it's sent before it's renewed, and how long it may be valid.
fn lifetimes(expires_in: Option<u64>) -> (Duration, Duration) {
    let lifetime = expires_in
        .unwrap_or(DEFAULT_TOKEN_SECONDS)
        .min(MAX_TOKEN_SECONDS);
    let valid = expires_in
        .unwrap_or(UNKNOWN_SECRET_SECONDS)
        .min(MAX_SECRET_SECONDS);
    (
        use_for(Duration::from_secs(lifetime)),
        Duration::from_secs(valid),
    )
}

/// How long a token that lasts `lifetime` is sent before it's renewed.
fn use_for(lifetime: Duration) -> Duration {
    lifetime
        .saturating_sub(RENEW_EARLY)
        .max(lifetime / 2)
        .max(MIN_TOKEN_USE)
}

impl ClientCredentials {
    /// A current access token: the cached one, or a new one from the token
    /// endpoint (OAuth client credentials, for this server's URL as the
    /// resource, RFC 8707). A new token is listed among the
    /// [credential strings](Upstream::credential_strings) before it's
    /// returned.
    async fn token(&self, http: &reqwest::Client) -> Result<HeaderValue, CredentialError> {
        if let Some(token) = self.current() {
            return Ok(token);
        }
        // One fetch at a time: whoever waited here finds the new token.
        let _fetching = self.fetching.lock().await;
        if let Some(token) = self.current() {
            return Ok(token);
        }
        let (token, expires_in) = self.fetch(http).await?;
        self.tokens()
            .issue(token.clone(), expires_in, Instant::now());
        Ok(token)
    }

    /// The cached token, unless it's due for renewal.
    fn current(&self) -> Option<HeaderValue> {
        self.tokens()
            .current
            .as_ref()
            .filter(|(_, until)| Instant::now() < *until)
            .map(|(token, _)| token.clone())
    }

    fn tokens(&self) -> MutexGuard<'_, Tokens> {
        // Nothing panics while holding it; and if something did, the
        // tokens are still the ones to keep secret.
        self.tokens.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Fetches a new token: the `Authorization` value, and how many
    /// seconds the endpoint says it lasts, if it says.
    async fn fetch(
        &self,
        http: &reqwest::Client,
    ) -> Result<(HeaderValue, Option<u64>), CredentialError> {
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("resource", self.resource.as_str()),
        ];
        if let Some(scope) = &self.scope {
            form.push(("scope", scope));
        }
        let fetch_error = |error: reqwest::Error| CredentialError::Fetch(error.without_url());
        let mut response = http
            .post(self.token_url.clone())
            .basic_auth(&self.client_id, Some(self.client_secret.expose()))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .body(form_encode(&form))
            .send()
            .await
            .map_err(fetch_error)?;
        if !response.status().is_success() {
            return Err(CredentialError::Status(response.status().as_u16()));
        }
        // Read with a limit, rather than buffering whatever arrives.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(fetch_error)? {
            if body.len() + chunk.len() > MAX_TOKEN_REPLY_BYTES {
                return Err(CredentialError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let reply: TokenReply =
            serde_json::from_slice(&body).map_err(|_| CredentialError::Malformed)?;
        let bearer = reply
            .token_type
            .as_deref()
            .is_none_or(|kind| kind.eq_ignore_ascii_case("bearer"));
        let access_token = reply.access_token.unwrap_or_default();
        // ASCII, as a bearer token is: a server may read other bytes in a
        // header as some other text than this, and echo that.
        if !bearer || access_token.is_empty() || !access_token.is_ascii() {
            return Err(CredentialError::Invalid);
        }
        let mut token = HeaderValue::from_str(&format!("Bearer {access_token}"))
            .map_err(|_| CredentialError::Invalid)?;
        token.set_sensitive(true);
        Ok((token, reply.expires_in))
    }
}

/// `application/x-www-form-urlencoded`.
fn form_encode(pairs: &[(&str, &str)]) -> String {
    let encode = |text: &str| {
        let mut out = String::new();
        for byte in text.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(char::from(byte));
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    };
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn form_encoding_escapes_reserved_characters() {
        assert_eq!(
            form_encode(&[
                ("resource", "https://x.example/mcp?a=1&b"),
                ("scope", "a b")
            ]),
            "resource=https%3A%2F%2Fx.example%2Fmcp%3Fa%3D1%26b&scope=a+b"
        );
    }

    #[test]
    fn a_token_reply_may_give_its_lifetime_as_a_string() {
        let lifetime = |reply: &str| {
            serde_json::from_str::<TokenReply>(reply)
                .unwrap()
                .expires_in
        };
        assert_eq!(
            lifetime(r#"{"access_token": "a", "expires_in": 3599}"#),
            Some(3599)
        );
        assert_eq!(
            lifetime(r#"{"access_token": "a", "expires_in": "3599"}"#),
            Some(3599)
        );
        assert_eq!(
            lifetime(r#"{"access_token": "a", "expires_in": "soon"}"#),
            None
        );
        assert_eq!(lifetime(r#"{"access_token": "a"}"#), None);
    }

    #[test]
    fn a_short_lived_token_is_still_used_for_a_while() {
        assert_eq!(use_for(Duration::ZERO), MIN_TOKEN_USE);
        assert_eq!(use_for(Duration::from_secs(30)), Duration::from_secs(15));
        assert_eq!(
            use_for(Duration::from_secs(3600)),
            Duration::from_secs(3570)
        );
    }

    #[test]
    fn a_token_stays_secret_for_as_long_as_it_may_be_valid() {
        let hours = |hours: u64| Duration::from_secs(hours * 3600);
        assert_eq!(lifetimes(Some(3600)), (Duration::from_secs(3570), hours(1)));
        // Without `expires_in`, it's sent for five minutes, but may be
        // valid for much longer.
        assert_eq!(lifetimes(None), (Duration::from_secs(270), hours(24)));
        // Sent for a day at most, but valid for as long as it says.
        assert_eq!(
            lifetimes(Some(30 * 24 * 3600)),
            (hours(24) - RENEW_EARLY, hours(30 * 24))
        );
        assert_eq!(lifetimes(Some(u64::MAX)).1, hours(365 * 24));
    }

    #[test]
    fn tokens_renewed_often_are_kept_secret_but_only_the_newest() {
        let token = |n: usize| HeaderValue::from_str(&format!("Bearer opaque-{n}")).unwrap();
        let start = Instant::now();
        let mut tokens = Tokens::default();
        tokens.issue(token(0), None, start);
        // An hour on, it's long been renewed, but it's still secret.
        let later = start + Duration::from_secs(3600);
        tokens.issue(token(1), None, later);
        assert_eq!(tokens.current.as_ref().unwrap().0, token(1));
        assert!(
            tokens
                .issued
                .iter()
                .any(|(listed, until)| *listed == token(0) && later < *until)
        );
        for n in 2..40 {
            tokens.issue(token(n), Some(3600), later);
        }
        assert_eq!(tokens.issued.len(), MAX_LISTED_TOKENS);
        assert_eq!(tokens.issued.last().unwrap().0, token(39));
        assert!(!tokens.issued.iter().any(|(listed, _)| *listed == token(0)));
    }

    #[test]
    fn the_token_after_any_scheme_is_a_credential_too() {
        let forms = |value: &str| credential_forms(&HeaderValue::from_str(value).unwrap());
        assert_eq!(
            forms("SSWS opaque-1234"),
            ["SSWS opaque-1234", "opaque-1234"]
        );
        assert_eq!(
            forms("bearer opaque-1234"),
            ["bearer opaque-1234", "opaque-1234"]
        );
        assert_eq!(forms("opaque-1234"), ["opaque-1234"]);
        let not_ascii = HeaderValue::from_bytes("Token pässwort-1234".as_bytes()).unwrap();
        assert_eq!(
            credential_forms(&not_ascii),
            ["Token pässwort-1234", "pässwort-1234"]
        );
    }

    /// A token endpoint, slow to answer, handing out a new token each time.
    async fn token_endpoint(reply: &str) -> (Url, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let fetched = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&fetched);
        let reply = reply.to_owned();
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(move || {
                let count = Arc::clone(&count);
                let reply = reply.clone();
                async move {
                    let n = count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    reply.replace("{n}", &n.to_string())
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await });
        (Url::parse(&url).unwrap(), fetched)
    }

    fn client_credentials(token_url: Url) -> ClientCredentials {
        ClientCredentials {
            token_url,
            client_id: "id".to_owned(),
            client_secret: Secret::new("client-secret"),
            scope: None,
            resource: "https://mcp.example/mcp".to_owned(),
            tokens: Mutex::default(),
            fetching: tokio::sync::Mutex::new(()),
        }
    }

    #[tokio::test]
    async fn one_fetch_at_a_time_and_every_token_in_use_stays_secret() {
        let (url, fetched) =
            token_endpoint(r#"{"access_token": "opaque-token-{n}", "expires_in": 3600}"#).await;
        let upstream = Upstream {
            url: Url::parse("https://mcp.example/mcp").unwrap(),
            http: reqwest::Client::new(),
            credential: Credential::ClientCredentials(Box::new(client_credentials(url))),
        };
        let Credential::ClientCredentials(client) = &upstream.credential else {
            unreachable!()
        };
        let tokens: Vec<HeaderValue> =
            futures_util::future::join_all((0..8).map(|_| client.token(&upstream.http)))
                .await
                .into_iter()
                .map(Result::unwrap)
                .collect();
        assert_eq!(fetched.load(Ordering::SeqCst), 1, "fetched once");
        assert!(tokens.iter().all(|token| token == "Bearer opaque-token-0"));

        // Renewed while the first token may still be on its way.
        client.tokens().current = None;
        assert_eq!(
            client.token(&upstream.http).await.unwrap(),
            "Bearer opaque-token-1"
        );
        let secrets = upstream.credential_strings();
        for secret in ["client-secret", "opaque-token-0", "opaque-token-1"] {
            assert!(secrets.iter().any(|known| known == secret), "{secrets:?}");
        }

        // An expired token is no longer listed.
        client.tokens().issued[0].1 = Instant::now();
        let secrets = upstream.credential_strings();
        assert!(!secrets.iter().any(|known| known.contains("opaque-token-0")));
        assert!(secrets.iter().any(|known| known == "opaque-token-1"));
    }

    #[tokio::test]
    async fn a_bad_token_reply_says_what_was_wrong() {
        let http = reqwest::Client::new();
        let (url, _) = token_endpoint("not json").await;
        let error = client_credentials(url).token(&http).await.unwrap_err();
        assert!(matches!(error, CredentialError::Malformed), "{error}");
        let (url, _) = token_endpoint(r#"{"token_type": "Bearer"}"#).await;
        let error = client_credentials(url).token(&http).await.unwrap_err();
        assert!(matches!(error, CredentialError::Invalid), "{error}");
        let (url, _) = token_endpoint(r#"{"access_token": "pässwort-token-1"}"#).await;
        let error = client_credentials(url).token(&http).await.unwrap_err();
        assert!(matches!(error, CredentialError::Invalid), "{error}");
        let huge = format!(
            r#"{{"access_token": "{}"}}"#,
            "a".repeat(MAX_TOKEN_REPLY_BYTES)
        );
        let (url, _) = token_endpoint(&huge).await;
        let error = client_credentials(url).token(&http).await.unwrap_err();
        assert!(matches!(error, CredentialError::TooLarge), "{error}");
    }
}
