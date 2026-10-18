//! The gateway's side of each server: where it is, and the gateway's own
//! credential for it. The caller's token never leaves the gateway, and one
//! server's credential is never sent to another.

use std::time::{Duration, Instant};

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue};
use reqwest::{Method, RequestBuilder, Response, Url};
use serde::Deserialize;
use tokio::sync::Mutex;

use super::config::{Auth, Secret, ServerConfig};
use crate::ProxyError;

pub const SESSION_HEADER: &str = "mcp-session-id";
pub const PROTOCOL_HEADER: &str = "mcp-protocol-version";
/// Longest a fetched access token is used, whatever its `expires_in` says.
const MAX_TOKEN_SECONDS: u64 = 24 * 3600;

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
    /// The current token and when to stop using it.
    cached: Mutex<Option<(HeaderValue, Instant)>>,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("couldn't reach the token endpoint")]
    Fetch(#[source] reqwest::Error),
    #[error("the token endpoint answered with HTTP {0}")]
    Status(u16),
    #[error("the token endpoint's reply has no usable bearer `access_token`")]
    Invalid,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u64>,
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
                cached: Mutex::new(None),
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

    /// Every form of the credential the gateway uses for this server (the
    /// header value, the bare token, the client secret, the current access
    /// token), so a server echoing it back can't hand it to a caller.
    pub fn credential_strings(&self) -> Vec<String> {
        let with_bare = |value: &str| {
            let mut forms = vec![value.to_owned()];
            if let Some(bare) = value.strip_prefix("Bearer ") {
                forms.push(bare.to_owned());
            }
            forms
        };
        match &self.credential {
            Credential::None => Vec::new(),
            Credential::Header(_, value) => with_bare(value.to_str().unwrap_or_default()),
            Credential::ClientCredentials(client) => {
                let mut forms = vec![client.client_secret.expose().to_owned()];
                if let Ok(cached) = client.cached.try_lock()
                    && let Some((token, _)) = &*cached
                {
                    forms.extend(with_bare(token.to_str().unwrap_or_default()));
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

impl ClientCredentials {
    /// A current access token: the cached one, or a new one from the token
    /// endpoint (OAuth client credentials, for this server's URL as the
    /// resource, RFC 8707).
    async fn token(&self, http: &reqwest::Client) -> Result<HeaderValue, CredentialError> {
        if let Some((token, until)) = &*self.cached.lock().await
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        // Fetched without holding the lock, so a slow token endpoint doesn't
        // queue every request behind it (two may fetch at once; harmless).
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("resource", self.resource.as_str()),
        ];
        if let Some(scope) = &self.scope {
            form.push(("scope", scope));
        }
        let response = http
            .post(self.token_url.clone())
            .basic_auth(&self.client_id, Some(self.client_secret.expose()))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .body(form_encode(&form))
            .send()
            .await
            .map_err(|error| CredentialError::Fetch(error.without_url()))?;
        if !response.status().is_success() {
            return Err(CredentialError::Status(response.status().as_u16()));
        }
        let reply: TokenReply = response
            .json()
            .await
            .map_err(|_| CredentialError::Invalid)?;
        let bearer = reply
            .token_type
            .as_deref()
            .is_none_or(|kind| kind.eq_ignore_ascii_case("bearer"));
        if !bearer || reply.access_token.is_empty() {
            return Err(CredentialError::Invalid);
        }
        let mut token = HeaderValue::from_str(&format!("Bearer {}", reply.access_token))
            .map_err(|_| CredentialError::Invalid)?;
        token.set_sensitive(true);
        // Renew a little early, so a token never expires mid-request, and
        // at least daily whatever the endpoint claims.
        let lifetime = Duration::from_secs(reply.expires_in.unwrap_or(300).min(MAX_TOKEN_SECONDS));
        let until = Instant::now()
            .checked_add(lifetime.saturating_sub(Duration::from_secs(30)))
            .unwrap_or_else(Instant::now);
        *self.cached.lock().await = Some((token.clone(), until));
        Ok(token)
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
}
