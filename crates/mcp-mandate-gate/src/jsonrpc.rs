//! Classifying JSON-RPC 2.0 messages without copying their payloads, and
//! refusing the ones the gate couldn't check reliably.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// Longest string id accepted. MCP ids are short; a huge one would only
/// cost memory wherever the gate keeps it.
const MAX_ID_BYTES: usize = 128;

/// Longest method name accepted. MCP's are short, and the gate keeps the
/// method of every request waiting for an answer.
const MAX_METHOD_BYTES: usize = 256;

/// Most values (object keys included) one message may hold. The gate reads
/// a message in full to check it, where each value takes far more memory
/// than in the message's text, so a message of tiny values (`[0,0,0,…]`)
/// would cost many times its size. Real messages hold far fewer: a long
/// text or a base64 image is one value.
const MAX_VALUES: usize = 1_000_000;

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
    #[error("too large to check: more than {max} values", max = MAX_VALUES)]
    TooManyValues,
}

/// Works out what kind of JSON-RPC message a frame holds. Refuses, besides
/// anything that isn't JSON-RPC 2.0:
///
/// - any object with a repeated key, at any depth: parsers disagree about
///   which copy wins, so the message the gate checked could differ from the
///   one the other side reads;
/// - a message that is both a request and a response (`method` with
///   `result` or `error`), or both a success and an error, or whose `error`
///   isn't an object: clients disagree about which part counts;
/// - a request whose id is null, or isn't a short string or an integer;
/// - a notification not named `notifications/…`: a request sent without an
///   id would otherwise skip every check, and some servers run it anyway;
/// - a method name over 256 bytes, or more than 1,000,000 values in all.
pub fn classify(frame: &[u8]) -> Result<Message, ParseError> {
    let body = trim_json_whitespace(frame);
    if body.is_empty() {
        return Err(ParseError::Empty);
    }
    check_values(body)?;
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

/// `frame` without the whitespace JSON allows around a value. Only that:
/// anything else (a form feed, say) makes a full parse of the message fail,
/// so classifying it must fail too.
fn trim_json_whitespace(mut frame: &[u8]) -> &[u8] {
    while let [b' ' | b'\t' | b'\n' | b'\r', rest @ ..] = frame {
        frame = rest;
    }
    while let [rest @ .., b' ' | b'\t' | b'\n' | b'\r'] = frame {
        frame = rest;
    }
    frame
}

/// Reads the whole message, refusing a repeated key or too many values.
fn check_values(body: &[u8]) -> Result<(), ParseError> {
    let count = Cell::new(0);
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let checked = NoDuplicates { count: &count }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end());
    match checked {
        Ok(()) => Ok(()),
        Err(_) if count.get() > MAX_VALUES => Err(ParseError::TooManyValues),
        Err(error) => Err(error.into()),
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
    /// Whether there's a `result` member, `"result": null` included.
    #[serde(default, deserialize_with = "present")]
    result: Option<IgnoredAny>,
    /// Whether there's an `error` member; one that isn't an object (`null`
    /// included) fails to parse.
    #[serde(default, deserialize_with = "present")]
    error: Option<ErrorObject>,
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
        let answers = is_error || self.result.is_some();
        if is_error && self.result.is_some() {
            return Err(ParseError::NotJsonRpc(
                "a response can't have both `result` and `error`",
            ));
        }
        if answers && self.method.is_some() {
            return Err(ParseError::NotJsonRpc(
                "a message can't have both `method` and `result` or `error`",
            ));
        }
        if self
            .method
            .as_ref()
            .is_some_and(|method| method.len() > MAX_METHOD_BYTES)
        {
            return Err(ParseError::NotJsonRpc(
                "a method name must be at most 256 bytes",
            ));
        }
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

/// Keeps a member set to `null` apart from no member at all (`"id": null`,
/// say).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// An `error` member, which must be an object. What it holds is skipped
/// without being copied.
struct ErrorObject;

impl<'de> Deserialize<'de> for ErrorObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ErrorObject)
    }
}

impl<'de> Visitor<'de> for ErrorObject {
    type Value = ErrorObject;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an error object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ErrorObject, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(ErrorObject)
    }
}

/// Reads a whole JSON document only to fail on an object with a repeated
/// key (compared after unescaping, so `"name"` repeats `"name"`), or on
/// more than [`MAX_VALUES`] values and keys in all.
#[derive(Clone, Copy)]
struct NoDuplicates<'a> {
    /// Values and keys read so far, in the whole document.
    count: &'a Cell<usize>,
}

impl NoDuplicates<'_> {
    /// Counts one more value or key.
    fn tally<E: de::Error>(self) -> Result<(), E> {
        let count = self.count.get() + 1;
        self.count.set(count);
        if count > MAX_VALUES {
            Err(E::custom("too many values"))
        } else {
            Ok(())
        }
    }
}

impl<'de> DeserializeSeed<'de> for NoDuplicates<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.tally()?;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NoDuplicates<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(self)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.tally()?;
            if !seen.insert(key) {
                return Err(de::Error::custom("an object repeats a key"));
            }
            map.next_value_seed(self)?;
        }
        Ok(())
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
    fn refuses_messages_that_are_both_a_request_and_a_response() {
        for text in [
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","result":{"tools":[]}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","error":{"code":1,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/message","result":null}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":{}},"error":null}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":"failed"}"#,
            r#"{"jsonrpc":"2.0","id":null,"error":null}"#,
        ] {
            assert!(classify(text.as_bytes()).is_err(), "accepted {text}");
        }
        // A null result is still a result.
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            Message::Response {
                id: json!(1),
                is_error: false
            }
        );
    }

    #[test]
    fn trims_only_what_json_counts_as_whitespace() {
        assert!(matches!(
            parse(" \t{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n"),
            Message::Request { .. }
        ));
        for text in [
            "\x0c{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\x0c\n",
            "\x0b{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
        ] {
            assert!(classify(text.as_bytes()).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn refuses_long_method_names() {
        let named = |method: &str| format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
        assert!(classify(named(&"x".repeat(256)).as_bytes()).is_ok());
        assert!(classify(named(&"x".repeat(257)).as_bytes()).is_err());
    }

    #[test]
    fn refuses_more_values_than_any_real_message_holds() {
        // 13 values and keys, plus the arguments' items.
        let call = |items: usize| {
            let mut text = String::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":["#,
            );
            text.push_str(&vec!["0"; items].join(","));
            text.push_str("]}}");
            text
        };
        assert!(classify(call(MAX_VALUES - 13).as_bytes()).is_ok());
        assert!(matches!(
            classify(call(MAX_VALUES - 12).as_bytes()),
            Err(ParseError::TooManyValues)
        ));
        // Long text is one value.
        let text = format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/message","params":{{"data":"{}"}}}}"#,
            "a".repeat(4 * 1024 * 1024)
        );
        assert!(classify(text.as_bytes()).is_ok());
    }

    #[test]
    fn displays_messages_for_logs() {
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#).to_string(),
            "request tools/list (id 3)"
        );
    }
}
