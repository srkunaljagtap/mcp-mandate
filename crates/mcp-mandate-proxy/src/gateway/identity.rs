//! Who's calling: checks each caller's access token (a JWT from your OIDC
//! identity provider) against the provider's published signing keys.
//! No valid token, no entry.

use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, Validation, decode, decode_header};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::{info, warn};

use super::config::{IdentityConfig, is_loopback};

/// How long fetched signing keys are used before they're fetched again.
const KEYS_TTL: Duration = Duration::from_secs(3600);
/// Fewest seconds between fetches, however many unknown keys arrive, so
/// junk tokens can't make the gateway hammer the provider.
const REFETCH_EVERY: Duration = Duration::from_secs(60);
/// Clock difference tolerated between the provider and the gateway.
const LEEWAY_SECONDS: u64 = 60;
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
/// Oldest signing keys still used while they can't be refreshed.
const MAX_KEY_AGE: Duration = Duration::from_secs(24 * 3600);

pub struct Identity {
    config: IdentityConfig,
    jwks_uri: String,
    http: reqwest::Client,
    keys: RwLock<Keys>,
}

struct Keys {
    set: JwkSet,
    fetched: Instant,
    attempted: Instant,
}

impl Keys {
    /// After a failed refresh, keys fetched `age` ago: still used for a
    /// while, so a brief outage doesn't lock everyone out, but not forever,
    /// since a key the provider has withdrawn mustn't stay valid. Returns
    /// whether they were dropped.
    fn expire(&mut self, age: Duration) -> bool {
        if age <= MAX_KEY_AGE || self.set.keys.is_empty() {
            return false;
        }
        self.set = JwkSet { keys: Vec::new() };
        true
    }
}

/// A caller whose token checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The token's subject (`sub`).
    pub subject: String,
    /// The OAuth client it was issued to (`azp` or `client_id`).
    pub client: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("couldn't fetch {url}")]
    Fetch {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{url} answered with HTTP {status}")]
    Status { url: String, status: u16 },
    #[error("{url} isn't what OIDC expects: {problem}")]
    Invalid { url: String, problem: String },
}

/// Why a token was refused. The caller only hears "invalid token"; the
/// reason goes to the gateway's log.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("the token can't be read")]
    Malformed,
    #[error("the token is signed with {0:?}, which isn't accepted")]
    Algorithm(Algorithm),
    #[error("no signing key of the provider matches the token")]
    UnknownKey,
    #[error("{0}")]
    Rejected(jsonwebtoken::errors::Error),
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    azp: Option<String>,
    client_id: Option<String>,
}

impl Identity {
    /// Finds the provider's signing keys (by OIDC discovery unless
    /// `jwks_uri` is set) and fetches them. Fails if they can't be had: the
    /// gateway doesn't start without a way to check tokens.
    pub async fn connect(
        config: IdentityConfig,
        http: reqwest::Client,
    ) -> Result<Self, IdentityError> {
        let jwks_uri = match &config.jwks_uri {
            Some(uri) => uri.clone(),
            None => discover(&http, &config.issuer).await?,
        };
        let set = fetch_keys(&http, &jwks_uri).await?;
        info!(issuer = %config.issuer, keys = set.keys.len(), "loaded the identity provider's signing keys");
        let now = Instant::now();
        Ok(Self {
            config,
            jwks_uri,
            http,
            keys: RwLock::new(Keys {
                set,
                fetched: now,
                attempted: now,
            }),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Checks a bearer token presented for the server at `server_url`. The
    /// token must be signed by the provider with an accepted algorithm,
    /// come from the configured issuer, be for this gateway or this server,
    /// name a subject, and be within its validity period.
    pub async fn check(&self, token: &str, server_url: &str) -> Result<Caller, TokenError> {
        let header = decode_header(token).map_err(|_| TokenError::Malformed)?;
        let algorithm = header.alg;
        if !self.config.algorithms.contains(&algorithm) {
            return Err(TokenError::Algorithm(algorithm));
        }
        let key = self.key(header.kid.as_deref(), algorithm).await?;
        let mut validation = Validation::new(algorithm);
        validation.leeway = LEEWAY_SECONDS;
        validation.validate_nbf = true;
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[self.config.audience.as_str(), server_url]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let data = decode::<Claims>(token, &key, &validation).map_err(TokenError::Rejected)?;
        Ok(Caller {
            subject: data.claims.sub,
            client: data.claims.azp.or(data.claims.client_id),
        })
    }

    /// The provider's key for a token, fetching the keys again (at most
    /// once a minute) when it isn't known: providers rotate keys.
    async fn key(
        &self,
        kid: Option<&str>,
        algorithm: Algorithm,
    ) -> Result<DecodingKey, TokenError> {
        let refetch = {
            let keys = self.keys.read().await;
            if keys.fetched.elapsed() < KEYS_TTL
                && let Some(key) = pick(&keys.set, kid, algorithm)
            {
                return Ok(key);
            }
            keys.attempted.elapsed() >= REFETCH_EVERY
        };
        if refetch {
            self.refetch().await;
        }
        let keys = self.keys.read().await;
        pick(&keys.set, kid, algorithm).ok_or(TokenError::UnknownKey)
    }

    async fn refetch(&self) {
        {
            let mut keys = self.keys.write().await;
            if keys.attempted.elapsed() < REFETCH_EVERY {
                return; // another request just did
            }
            keys.attempted = Instant::now();
        }
        // Fetched without holding the lock: token checks go on meanwhile.
        let fetched = fetch_keys(&self.http, &self.jwks_uri).await;
        let mut keys = self.keys.write().await;
        match fetched {
            Ok(set) => {
                keys.set = set;
                keys.fetched = Instant::now();
            }
            Err(error) => {
                warn!(%error, "couldn't refresh the identity provider's signing keys");
                let age = keys.fetched.elapsed();
                if keys.expire(age) {
                    warn!(
                        "the identity provider's keys are over a day old and can't be refreshed: refusing tokens until they can"
                    );
                }
            }
        }
    }
}

/// The signing key for a token: the one named by `kid`, or with no `kid`
/// the only key of the token's kind. The key's type must match the
/// token's algorithm, so a token can't pass off an RSA public key as an
/// HMAC secret.
fn pick(set: &JwkSet, kid: Option<&str>, algorithm: Algorithm) -> Option<DecodingKey> {
    let family = family(algorithm)?;
    let mut candidates = set.keys.iter().filter(|jwk| {
        let signs = !matches!(
            jwk.common.public_key_use,
            Some(PublicKeyUse::Encryption | PublicKeyUse::Other(_))
        );
        let same_algorithm = jwk
            .common
            .key_algorithm
            .is_none_or(|declared| format!("{declared:?}") == format!("{algorithm:?}"));
        signs && same_algorithm && kid.is_none_or(|kid| jwk.common.key_id.as_deref() == Some(kid))
    });
    let jwk: &Jwk = candidates.next()?;
    if kid.is_none() && candidates.next().is_some() {
        return None; // ambiguous
    }
    let key = DecodingKey::from_jwk(jwk).ok()?;
    (key.family() == family).then_some(key)
}

fn family(algorithm: Algorithm) -> Option<AlgorithmFamily> {
    [
        AlgorithmFamily::Rsa,
        AlgorithmFamily::Ec,
        AlgorithmFamily::Ed,
    ]
    .into_iter()
    .find(|family| family.algorithms().contains(&algorithm))
}

/// OIDC discovery: the provider's configuration names its key set.
async fn discover(http: &reqwest::Client, issuer: &str) -> Result<String, IdentityError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let document = get_json(http, &url).await?;
    let invalid = |problem: &str| IdentityError::Invalid {
        url: url.clone(),
        problem: problem.to_owned(),
    };
    // A document for another issuer would let its tokens in.
    if document.get("issuer").and_then(Value::as_str) != Some(issuer) {
        return Err(invalid("its `issuer` isn't the configured issuer"));
    }
    let jwks_uri = document
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("it has no `jwks_uri`"))?;
    let parsed = Url::parse(jwks_uri).map_err(|_| invalid("its `jwks_uri` isn't a URL"))?;
    if parsed.scheme() != "https" && !is_loopback(&parsed) {
        return Err(invalid("its `jwks_uri` doesn't use https://"));
    }
    Ok(jwks_uri.to_owned())
}

/// Fetches a key set, keeping the keys this gateway can use and skipping
/// any it can't parse.
async fn fetch_keys(http: &reqwest::Client, url: &str) -> Result<JwkSet, IdentityError> {
    let document = get_json(http, url).await?;
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| IdentityError::Invalid {
            url: url.to_owned(),
            problem: "it has no `keys`".to_owned(),
        })?
        .iter()
        .filter_map(|key| serde_json::from_value::<Jwk>(key.clone()).ok())
        .collect();
    Ok(JwkSet { keys })
}

async fn get_json(http: &reqwest::Client, url: &str) -> Result<Value, IdentityError> {
    let fetch = |source| IdentityError::Fetch {
        url: url.to_owned(),
        source,
    };
    let mut response = http.get(url).send().await.map_err(fetch)?;
    if !response.status().is_success() {
        return Err(IdentityError::Status {
            url: url.to_owned(),
            status: response.status().as_u16(),
        });
    }
    let invalid = |problem: &str| IdentityError::Invalid {
        url: url.to_owned(),
        problem: problem.to_owned(),
    };
    // Read with a limit, rather than buffering whatever arrives first.
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(fetch)? {
        if bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid("it's too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid("it isn't JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        let set = serde_json::from_value(serde_json::json!({
            "keys": [{"kty": "RSA", "kid": "k1", "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw", "e": "AQAB"}]
        }))
        .unwrap();
        Keys {
            set,
            fetched: Instant::now(),
            attempted: Instant::now(),
        }
    }

    #[test]
    fn keys_that_cant_be_refreshed_stop_working_after_a_day() {
        let mut recent = keys();
        assert!(!recent.expire(Duration::from_secs(3600)));
        assert_eq!(recent.set.keys.len(), 1);
        let mut old = keys();
        assert!(old.expire(MAX_KEY_AGE + Duration::from_secs(1)));
        assert!(old.set.keys.is_empty());
    }
}
