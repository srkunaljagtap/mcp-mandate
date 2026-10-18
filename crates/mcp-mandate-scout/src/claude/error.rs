//! Everything that can go wrong when talking to Claude, as one typed enum.
//!
//! A library returns a specific error type (built with `thiserror`) so callers
//! can `match` on what happened: retry a rate limit, fix a bad key, and so on.
//! The binary uses `anyhow` instead, because it only reports errors.

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ANTHROPIC_API_KEY is not set; add it to .env (see .env.example)")]
    MissingApiKey,

    /// Couldn't reach the API at all: DNS, TLS, timeout, connection reset.
    #[error("network error talking to the Claude API")]
    Http(#[from] reqwest::Error),

    /// The API answered with an error status, e.g. 401 or 429.
    #[error("Claude API returned {status} ({kind}): {message}")]
    Api {
        status: u16,
        /// The API's error type, e.g. `authentication_error`.
        kind: String,
        message: String,
    },

    /// The API said "success" but the body wasn't the JSON we expected.
    #[error("couldn't decode the Claude API response")]
    Decode(#[from] serde_json::Error),
}

impl Error {
    /// Builds an [`Error::Api`] from an error response body.
    ///
    /// The API's error bodies look like
    /// `{"type": "error", "error": {"type": "...", "message": "..."}}`.
    /// If the body isn't that (a proxy's HTML page, say), keep the raw text so
    /// the user still sees something useful.
    pub(crate) fn from_api_response(status: u16, body: &str) -> Self {
        #[derive(Deserialize)]
        struct Body {
            error: Detail,
        }
        #[derive(Deserialize)]
        struct Detail {
            #[serde(rename = "type")]
            kind: String,
            message: String,
        }

        match serde_json::from_str::<Body>(body) {
            Ok(Body { error }) => Self::Api {
                status,
                kind: error.kind,
                message: error.message,
            },
            Err(_) => Self::Api {
                status,
                kind: "unknown".to_owned(),
                message: body.chars().take(500).collect(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_api_error_body() {
        let body = r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"},"request_id":"req_1"}"#;

        let error = Error::from_api_response(401, body);

        assert!(matches!(
            error,
            Error::Api { status: 401, ref kind, ref message }
                if kind == "authentication_error" && message == "invalid x-api-key"
        ));
    }

    #[test]
    fn keeps_raw_text_when_body_is_not_json() {
        let error = Error::from_api_response(502, "<html>Bad Gateway</html>");

        assert!(matches!(
            error,
            Error::Api { status: 502, ref kind, ref message }
                if kind == "unknown" && message == "<html>Bad Gateway</html>"
        ));
    }
}
