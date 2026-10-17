//! JSON-RPC 2.0 framing for MCP's stdio transport: one message per line.
//!
//! Frames are forwarded exactly as received. They're parsed only to learn
//! what they are, so the proxy can never alter a message by re-encoding it.

use std::borrow::Cow;
use std::fmt;

use serde::Deserialize;
use serde::de::IgnoredAny;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Largest single message accepted, newline included. Tool results can carry
/// base64 images, so this is generous; anything bigger ends the session
/// instead of being buffered without limit.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("message is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Reads one newline-terminated frame into `buf`, newline included.
///
/// Returns `Ok(false)` at end of stream. A last frame without a trailing
/// newline is still returned.
pub async fn read_frame<R>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> Result<bool, FrameError>
where
    R: AsyncBufRead + Unpin,
{
    buf.clear();
    loop {
        let (used, complete) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(!buf.is_empty());
            }
            let (used, complete) = match available.iter().position(|&byte| byte == b'\n') {
                Some(newline) => (newline + 1, true),
                None => (available.len(), false),
            };
            if buf.len() + used > limit {
                return Err(FrameError::TooLarge { limit });
            }
            buf.extend_from_slice(&available[..used]);
            (used, complete)
        };
        reader.consume(used);
        if complete {
            return Ok(true);
        }
    }
}

/// What a frame is, as far as routing and logging are concerned.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// Expects a response with the same id.
    Request {
        id: serde_json::Value,
        method: String,
    },
    /// Fire-and-forget; no response.
    Notification { method: String },
    Response {
        id: serde_json::Value,
        is_error: bool,
    },
    /// Several messages in one JSON array (allowed by older MCP versions).
    Batch { len: usize },
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request { id, method } => write!(f, "request {method} (id {id})"),
            Self::Notification { method } => write!(f, "notification {method}"),
            Self::Response { id, is_error } => {
                let kind = if *is_error {
                    "error response"
                } else {
                    "response"
                };
                write!(f, "{kind} (id {id})")
            }
            Self::Batch { len } => write!(f, "batch of {len}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("empty line")]
    Empty,
    #[error("not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not a JSON-RPC 2.0 message: {0}")]
    NotJsonRpc(&'static str),
}

/// Works out what kind of JSON-RPC message a frame holds.
pub fn classify(frame: &[u8]) -> Result<Message, ParseError> {
    let body = frame.trim_ascii();
    match body.first() {
        None => Err(ParseError::Empty),
        Some(b'[') => {
            let items: Vec<Envelope<'_>> = serde_json::from_slice(body)?;
            if items.is_empty() {
                return Err(ParseError::NotJsonRpc("empty batch"));
            }
            for item in items.iter() {
                item.check_version()?;
            }
            Ok(Message::Batch { len: items.len() })
        }
        Some(_) => {
            let envelope: Envelope<'_> = serde_json::from_slice(body)?;
            envelope.into_message()
        }
    }
}

/// The parts of a message the proxy looks at. Everything else (`params`,
/// the body of `result`) is skipped by the parser without being copied.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow)]
    jsonrpc: Cow<'a, str>,
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default, borrow)]
    method: Option<Cow<'a, str>>,
    #[serde(default)]
    error: Option<IgnoredAny>,
}

impl Envelope<'_> {
    fn check_version(&self) -> Result<(), ParseError> {
        if self.jsonrpc == "2.0" {
            Ok(())
        } else {
            Err(ParseError::NotJsonRpc("`jsonrpc` must be \"2.0\""))
        }
    }

    fn into_message(self) -> Result<Message, ParseError> {
        self.check_version()?;
        let is_error = self.error.is_some();
        match (self.method, self.id) {
            (Some(method), Some(id)) => Ok(Message::Request {
                id,
                method: method.into_owned(),
            }),
            (Some(method), None) => Ok(Message::Notification {
                method: method.into_owned(),
            }),
            (None, Some(id)) => Ok(Message::Response { id, is_error }),
            // An error about a request that couldn't be read has a null id.
            (None, None) if is_error => Ok(Message::Response {
                id: serde_json::Value::Null,
                is_error,
            }),
            (None, None) => Err(ParseError::NotJsonRpc("no `method` and no `id`")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(text: &str) -> Message {
        classify(text.as_bytes()).unwrap()
    }

    #[test]
    fn classifies_requests_notifications_and_responses() {
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x"}}"#),
            Message::Request {
                id: json!(7),
                method: "tools/call".to_owned()
            }
        );
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Message::Notification {
                method: "notifications/initialized".to_owned()
            }
        );
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":"a","result":{"tools":[]}}"#),
            Message::Response {
                id: json!("a"),
                is_error: false
            }
        );
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}"#),
            Message::Response {
                id: serde_json::Value::Null,
                is_error: true
            }
        );
    }

    #[test]
    fn accepts_batches_and_a_trailing_crlf() {
        assert_eq!(
            parse(
                "[{\"jsonrpc\":\"2.0\",\"method\":\"a\"},{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"b\"}]\r\n"
            ),
            Message::Batch { len: 2 }
        );
    }

    #[test]
    fn rejects_what_is_not_json_rpc() {
        for text in [
            "",
            "   \r\n",
            "hello",
            r#"{"jsonrpc":"1.0","id":1,"method":"x"}"#,
            r#"{"id":1,"method":"x"}"#,
            r#"{"jsonrpc":"2.0"}"#,
            "[]",
            r#"[{"jsonrpc":"2.0","method":"a"},{"method":"b"}]"#,
        ] {
            assert!(classify(text.as_bytes()).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn displays_messages_for_logs() {
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#).to_string(),
            "request tools/list (id 3)"
        );
    }

    async fn frames(input: &[u8], limit: usize) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut reader = tokio::io::BufReader::with_capacity(4, input);
        let mut frame = Vec::new();
        let mut frames = Vec::new();
        while read_frame(&mut reader, &mut frame, limit).await? {
            frames.push(frame.clone());
        }
        Ok(frames)
    }

    #[tokio::test]
    async fn splits_lines_and_keeps_their_endings() {
        let frames = frames(b"{\"a\":1}\n{\"b\":2}\r\n{\"c\":3}", 1024)
            .await
            .unwrap();
        assert_eq!(
            frames,
            [&b"{\"a\":1}\n"[..], b"{\"b\":2}\r\n", b"{\"c\":3}"]
        );
    }

    #[tokio::test]
    async fn refuses_frames_over_the_limit() {
        let error = frames(b"0123456789\n", 8).await.unwrap_err();
        assert!(matches!(error, FrameError::TooLarge { limit: 8 }));
    }
}
