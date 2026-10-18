//! Classifying JSON-RPC 2.0 messages without copying their payloads, and
//! refusing the ones the gate couldn't check reliably.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// Longest string id accepted. MCP ids are short; a huge one would only
/// cost memory wherever the gate keeps it.
const MAX_ID_BYTES: usize = 128;

/// What a message is, as far as routing and checking are concerned.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// Expects a response with the same id.
    Request {
        id: Value,
        method: String,
    },
    /// Fire-and-forget; no response.
    Notification {
        method: String,
    },
    Response {
        id: Value,
        is_error: bool,
    },
    /// Several messages in one JSON array (allowed by older MCP versions).
    Batch {
        len: usize,
    },
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

/// Works out what kind of JSON-RPC message a frame holds. Refuses, besides
/// anything that isn't JSON-RPC 2.0:
///
/// - any object with a repeated key, at any depth: parsers disagree about
///   which copy wins, so the message the gate checked could differ from the
///   one the other side reads;
/// - a request whose id is null, or isn't a short string or an integer;
/// - a notification not named `notifications/…`: a request sent without an
///   id would otherwise skip every check, and some servers run it anyway.
pub fn classify(frame: &[u8]) -> Result<Message, ParseError> {
    let body = frame.trim_ascii();
    if body.is_empty() {
        return Err(ParseError::Empty);
    }
    serde_json::from_slice::<NoDuplicates>(body)?;
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

/// The parts of a message classification looks at. Everything else
/// (`params`, the body of `result`) is skipped without being copied.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow)]
    jsonrpc: Cow<'a, str>,
    /// `None` when there's no `id` member; `Some(Value::Null)` for `"id": null`.
    #[serde(default, deserialize_with = "present")]
    id: Option<Value>,
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
            (Some(_), Some(Value::Null)) => {
                Err(ParseError::NotJsonRpc("a request's id can't be null"))
            }
            (Some(method), Some(id)) => Ok(Message::Request {
                id: valid_id(id)?,
                method: method.into_owned(),
            }),
            (Some(method), None) if method.starts_with("notifications/") => {
                Ok(Message::Notification {
                    method: method.into_owned(),
                })
            }
            (Some(_), None) => Err(ParseError::NotJsonRpc(
                "a message without an id must be a notification (`notifications/…`)",
            )),
            // An error about a request that couldn't be read has a null id.
            (None, Some(Value::Null) | None) if is_error => Ok(Message::Response {
                id: Value::Null,
                is_error,
            }),
            (None, Some(id)) => Ok(Message::Response {
                id: valid_id(id)?,
                is_error,
            }),
            (None, None) => Err(ParseError::NotJsonRpc("no `method` and no `id`")),
        }
    }
}

/// An id must be a short string or an integer.
fn valid_id(id: Value) -> Result<Value, ParseError> {
    let valid = match &id {
        Value::String(text) => text.len() <= MAX_ID_BYTES,
        Value::Number(number) => number.is_i64() || number.is_u64(),
        _ => false,
    };
    if valid {
        Ok(id)
    } else {
        Err(ParseError::NotJsonRpc(
            "an id must be a string of at most 128 bytes or an integer",
        ))
    }
}

/// Keeps `"id": null` apart from no `id` at all.
fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// A whole JSON document read only to fail on an object with a repeated
/// key (compared after unescaping, so `"name"` repeats `"name"`).
struct NoDuplicates;

impl<'de> Deserialize<'de> for NoDuplicates {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicatesVisitor)
    }
}

struct NoDuplicatesVisitor;

impl<'de> Visitor<'de> for NoDuplicatesVisitor {
    type Value = NoDuplicates;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }

    fn visit_i64<E>(self, _: i64) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }

    fn visit_u64<E>(self, _: u64) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }

    fn visit_f64<E>(self, _: f64) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }

    fn visit_str<E>(self, _: &str) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }

    fn visit_unit<E>(self) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NoDuplicates, A::Error> {
        while seq.next_element::<NoDuplicates>()?.is_some() {}
        Ok(NoDuplicates)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NoDuplicates, A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("an object repeats a key"));
            }
            map.next_value::<NoDuplicates>()?;
        }
        Ok(NoDuplicates)
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
                id: Value::Null,
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
    fn refuses_what_could_skip_the_checks() {
        for text in [
            // A request with a null id is a request in JSON-RPC, not a notification.
            r#"{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{}}"#,
            // A request sent without an id.
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}"#,
            r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":{}}"#,
            // Ids that are huge, fractional, or not scalars.
            format!(
                r#"{{"jsonrpc":"2.0","id":"{}","method":"ping"}}"#,
                "x".repeat(200)
            )
            .as_str(),
            r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":true,"result":{}}"#,
        ] {
            assert!(classify(text.as_bytes()).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn refuses_repeated_keys_at_any_depth() {
        for text in [
            r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo","name":"echo"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"a","description":"b"}]}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{"name":"a","name":"b"}}"#,
        ] {
            assert!(classify(text.as_bytes()).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn displays_messages_for_logs() {
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#).to_string(),
            "request tools/list (id 3)"
        );
    }
}
