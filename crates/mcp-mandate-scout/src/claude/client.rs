//! A small HTTP client for the Claude Messages API.
//!
//! There's no official Anthropic SDK for Rust, so this is the whole "SDK":
//! build the request, add three headers, POST it, decode the JSON.

use std::fmt;
use std::time::Duration;

use super::error::Error;
use super::types::{MessagesRequest, MessagesResponse};

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// The API contract version. It's a date and rarely changes; new features
/// arrive through `anthropic-beta` headers instead.
const API_VERSION: &str = "2023-06-01";
/// Beta header that enables `"fallbacks": "default"` on a request.
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
/// Non-streaming replies can take minutes on hard tasks; give up after 10.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

pub struct Client {
    http: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl Client {
    pub fn new(api_key: impl Into<String>) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.to_owned(),
        })
    }

    /// Reads the key from `ANTHROPIC_API_KEY`.
    pub fn from_env() -> Result<Self, Error> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .filter(|key| !key.trim().is_empty())
            .ok_or(Error::MissingApiKey)?;
        Self::new(api_key)
    }

    /// Points the client at a different server, such as a fake API in tests.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Sends one request and waits for the complete reply.
    pub async fn send(&self, request: &MessagesRequest) -> Result<MessagesResponse, Error> {
        let mut http_request = self
            .http
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .json(request);
        if request.fallbacks.is_some() {
            http_request = http_request.header("anthropic-beta", FALLBACK_BETA);
        }

        // Each `.await` is a point where this task pauses while the network
        // works, letting other tasks run on the same thread.
        let response = http_request.send().await?;
        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            return Err(Error::from_api_response(status.as_u16(), &body));
        }
        Ok(serde_json::from_str(&body)?)
    }
}

// Hand-written instead of #[derive(Debug)] so the key can never end up in a
// log line or a panic message.
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .field("api_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_api_key() {
        let client = Client::new("sk-ant-secret-value").unwrap();

        let printed = format!("{client:?}");

        assert!(!printed.contains("sk-ant-secret-value"));
        assert!(printed.contains("[redacted]"));
    }
}
