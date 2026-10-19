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

/// What reading a message in full costs in memory, beyond its text, as
/// serde_json lays it out. Every value and key takes a 32-byte slot (twice
/// that, counting the room a growing array keeps), and a non-empty string,
/// array or object takes an allocation of its own besides: an object's is
/// a tree node with room for eleven members, so `[{"":0},…]` costs about
/// a hundred times its size.
const VALUE_COST: usize = 64;
const STRING_COST: usize = 32;
const ARRAY_COST: usize = 128;
const OBJECT_COST: usize = 640;

/// The most a message may cost: about 64 MB, as much as [`MAX_VALUES`]
/// numbers do.
const MAX_COST: usize = MAX_VALUES * VALUE_COST;

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
    #[error(
        "too large to check: reading it would take more memory than {max} values do",
        max = MAX_VALUES
    )]
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
/// - a method name over 256 bytes;
/// - a message that would take more memory to read in full than 1,000,000
///   values do (fewer when they are small objects, arrays or strings,
///   which take more each).
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

/// What a message says it is, read from its top-level members alone and
/// checked as [`classify`] checks them, without reading the rest (`params`,
/// the body of `result`) into memory, and without the limit on what the
/// whole message may cost. Only for answering a message too large to check
/// (a request gets an error rather than no answer): it doesn't look for
/// repeated keys below the top level. `None` for a batch, or when even
/// that can't be read.
pub fn head(frame: &[u8]) -> Option<Message> {
    let body = trim_json_whitespace(frame);
    if body.first() == Some(&b'[') {
        return None;
    }
    let envelope: Envelope<'_> = serde_json::from_slice(body).ok()?;
    envelope.into_message().ok()
}

/// What each message in a batch says it is, read as [`head`] reads a
/// single message (`None` for one that doesn't say), handed to `each` as
/// it's read: a batch of any size takes no more memory than one message's
/// head. If a message can't even be told apart from the next, whatever is
/// left of the batch is handed on as one more `None`. Returns false, having
/// handed nothing, when `frame` isn't a batch.
pub fn batch_heads(frame: &[u8], mut each: impl FnMut(Option<Message>)) -> bool {
    let body = trim_json_whitespace(frame);
    if body.first() != Some(&b'[') {
        return false;
    }
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let read = Heads(&mut each)
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end());
    if read.is_err() {
        each(None);
    }
    true
}

/// Whether `frame` names `sampling/createMessage` as its method, or one of
/// its messages does if it's a batch, read as leniently as a client might:
/// in any copy of a repeated `method` member, whatever its id and its other
/// members say. For a message whose head can't be read ([`head`]), which
/// such a client could still take for a sampling request.
///
/// Where serde_json refuses something a client's parser may take (`1e999`,
/// read as infinity; a lone surrogate or a byte that isn't UTF-8, read as
/// U+FFFD; another message after this one), what comes after it can't be
/// read here, and could be another copy of `method`: then the name
/// anywhere in the text, escapes written out, counts.
pub fn names_sampling(frame: &[u8]) -> bool {
    let found = Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_slice(trim_json_whitespace(frame));
    let read = Sampling {
        found: &found,
        batch: true,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end());
    found.get() || (read.is_err() && unescaped(frame).contains("sampling/createMessage"))
}

/// Whether reading `frame` in full would take no more memory than
/// [`classify`] allows. Unlike classifying, it reads on past a repeated
/// key, so every copy counts and a message with one can still be read in
/// full safely. `Ok` says whether some object in it repeats a key (a parser
/// keeps only one copy); an error when it would take more
/// ([`ParseError::TooManyValues`]), or isn't JSON.
pub fn within_cost(frame: &[u8]) -> Result<bool, ParseError> {
    let repeated = Cell::new(false);
    read_values(trim_json_whitespace(frame), Some(&repeated))?;
    Ok(repeated.get())
}

/// `frame` as text, with each escape in its strings (`\n`, `\"`, `A`,
/// …) written as the character it stands for, so a search finds what a
/// parser reads in them, keys included. Borrowed when there's nothing to
/// write out; bytes that aren't UTF-8 read as U+FFFD.
pub fn unescaped(frame: &[u8]) -> Cow<'_, str> {
    let text = String::from_utf8_lossy(frame);
    if !text.contains('\\') {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_ref();
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let mut chars = rest[at + 1..].chars();
        let Some(kind) = chars.next() else {
            out.push('\\');
            return Cow::Owned(out);
        };
        rest = chars.as_str();
        match kind {
            'u' => match unicode_escape(rest) {
                Some((character, used)) => {
                    out.push(character);
                    rest = &rest[used..];
                }
                None => out.push('u'),
            },
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            // `\"`, `\\` and `\/`, and any JSON doesn't allow.
            other => out.push(other),
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// The character a `\u` escape stands for, given what follows the `\u`,
/// and how many bytes of that it takes: a surrogate pair takes the next
/// `\u` escape too. One half of a pair alone stands for U+FFFD.
fn unicode_escape(after: &str) -> Option<(char, usize)> {
    let unit = |text: &str| {
        let hex = text.get(..4)?;
        if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(hex, 16).ok()
    };
    let first = unit(after)?;
    let second = after
        .get(4..)
        .and_then(|rest| rest.strip_prefix("\\u"))
        .and_then(unit);
    if let Some(second) = second
        && (0xD800..0xDC00).contains(&first)
        && (0xDC00..0xE000).contains(&second)
        && let Some(Ok(character)) = char::decode_utf16([first, second]).next()
    {
        return Some((character, 10));
    }
    let character = char::from_u32(u32::from(first)).unwrap_or(char::REPLACEMENT_CHARACTER);
    Some((character, 4))
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

/// Reads the whole message, refusing a repeated key or one that would cost
/// too much to read in full.
fn check_values(body: &[u8]) -> Result<(), ParseError> {
    read_values(body, None)
}

/// Reads the whole message, refusing one that would cost too much to read
/// in full, and a repeated key unless `repeated` is given, where it's
/// noted instead.
fn read_values(body: &[u8], repeated: Option<&Cell<bool>>) -> Result<(), ParseError> {
    let cost = Cell::new(0);
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let checked = NoDuplicates {
        cost: &cost,
        repeated,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end());
    match checked {
        Ok(()) => Ok(()),
        Err(_) if cost.get() > MAX_COST => Err(ParseError::TooManyValues),
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
    /// An array or object (never a valid id) fails to parse rather than
    /// being read into memory.
    #[serde(default, deserialize_with = "scalar")]
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

/// Like [`present`], for a member that must be a string, a number, a
/// boolean or `null`.
fn scalar<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    deserializer.deserialize_any(Scalar).map(Some)
}

struct Scalar;

impl Visitor<'_> for Scalar {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string, a number, a boolean or null")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
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
/// key (compared after unescaping, so `"name"` repeats `"name"`), unless
/// told to note one instead, or on one that would cost more than
/// [`MAX_COST`] to read in full.
#[derive(Clone, Copy)]
struct NoDuplicates<'a> {
    /// What the document read so far would cost.
    cost: &'a Cell<usize>,
    /// Where a repeated key is noted, to read on past it and add up the
    /// whole document's cost; `None` to fail on one.
    repeated: Option<&'a Cell<bool>>,
}

impl NoDuplicates<'_> {
    /// Adds `cost` to the document's.
    fn charge<E: de::Error>(self, cost: usize) -> Result<(), E> {
        let total = self.cost.get().saturating_add(cost);
        self.cost.set(total);
        if total > MAX_COST {
            Err(E::custom("too large to check"))
        } else {
            Ok(())
        }
    }
}

impl<'de> DeserializeSeed<'de> for NoDuplicates<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.charge(VALUE_COST)?;
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

    fn visit_str<E: de::Error>(self, text: &str) -> Result<(), E> {
        if text.is_empty() {
            Ok(())
        } else {
            self.charge(STRING_COST)
        }
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        if seq.next_element_seed(self)?.is_some() {
            self.charge(ARRAY_COST)?;
            while seq.next_element_seed(self)?.is_some() {}
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            let mut cost = VALUE_COST;
            if !key.is_empty() {
                cost += STRING_COST;
            }
            if seen.is_empty() {
                cost += OBJECT_COST;
            }
            self.charge(cost)?;
            if !seen.insert(key) {
                match self.repeated {
                    Some(repeated) => repeated.set(true),
                    None => return Err(de::Error::custom("an object repeats a key")),
                }
            }
            map.next_value_seed(self)?;
        }
        Ok(())
    }
}

/// Hands each message of a batch, as [`head`] reads it, to the function it
/// holds.
struct Heads<F>(F);

impl<'de, F: FnMut(Option<Message>)> DeserializeSeed<'de> for Heads<F> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, F: FnMut(Option<Message>)> Visitor<'de> for Heads<F> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a batch of JSON-RPC messages")
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
        while let Some(item) = seq.next_element::<Envelope<'de>>()? {
            (self.0)(item.into_message().ok());
        }
        Ok(())
    }
}

/// Looks through a message, or each message of a batch, for a `method`
/// member naming `sampling/createMessage`, skipping everything else unread.
#[derive(Clone, Copy)]
struct Sampling<'a> {
    found: &'a Cell<bool>,
    /// Whether this may be a batch, rather than a message in one.
    batch: bool,
}

impl<'de> DeserializeSeed<'de> for Sampling<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Sampling<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON-RPC message or batch")
    }

    // Anything but an object (or, at the top, an array) names no method.
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
        if self.batch {
            let message = Sampling {
                batch: false,
                ..self
            };
            while seq.next_element_seed(message)?.is_some() {}
        } else {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "method" {
                if map.next_value_seed(SamplingMethod)? {
                    self.found.set(true);
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

/// Whether a value is the string `sampling/createMessage`. Anything else is
/// skipped unread.
struct SamplingMethod;

impl<'de> DeserializeSeed<'de> for SamplingMethod {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for SamplingMethod {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a method name")
    }

    fn visit_str<E>(self, method: &str) -> Result<bool, E> {
        Ok(method == "sampling/createMessage")
    }

    fn visit_bool<E>(self, _: bool) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_i64<E>(self, _: i64) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_u64<E>(self, _: u64) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_f64<E>(self, _: f64) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_unit<E>(self) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(false)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(false)
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

    /// A tool call whose arguments are `items` copies of `item`.
    fn call_with(item: &str, items: usize) -> String {
        let mut text = String::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":["#,
        );
        text.push_str(&vec![item; items].join(","));
        text.push_str("]}}");
        text
    }

    #[test]
    fn refuses_more_values_than_any_real_message_holds() {
        // The envelope, with its objects, keys and strings, costs as much
        // as 39.5 numbers.
        assert!(classify(call_with("0", MAX_VALUES - 40).as_bytes()).is_ok());
        assert!(matches!(
            classify(call_with("0", MAX_VALUES - 39).as_bytes()),
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
    fn counts_small_objects_by_the_memory_they_take() {
        // 13 values and keys in the envelope, three in each object: a
        // million in all, but each object takes a whole tree node once
        // read, so this 2.3 MB message would take over 200 MB.
        let objects = (MAX_VALUES - 13) / 3;
        assert!(matches!(
            classify(call_with(r#"{"":0}"#, objects).as_bytes()),
            Err(ParseError::TooManyValues)
        ));
        // A large result with many small objects still passes.
        let rows = vec![r#"{"id":1,"name":"x"}"#; 40_000].join(",");
        let result = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"structuredContent":{{"rows":[{rows}]}}}}}}"#
        );
        assert!(classify(result.as_bytes()).is_ok());
    }

    #[test]
    fn the_head_of_a_message_too_large_to_check_can_still_be_read() {
        let call = call_with("0", MAX_VALUES);
        assert!(matches!(
            classify(call.as_bytes()),
            Err(ParseError::TooManyValues)
        ));
        assert_eq!(
            head(call.as_bytes()),
            Some(Message::Request {
                id: json!(1),
                method: "tools/call".to_owned()
            })
        );
        // Never by reading a large id into memory, and never for a
        // message classifying would refuse anyway.
        let values = vec!["0"; MAX_VALUES].join(",");
        for text in [
            format!(r#"{{"jsonrpc":"2.0","id":[{values}],"method":"ping"}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":1,"id":2,"result":[{values}]}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping","result":[{values}]}}"#),
            format!(r#"[{{"jsonrpc":"2.0","id":1,"result":[{values}]}}]"#),
        ] {
            assert_eq!(head(text.as_bytes()), None, "{}", &text[..40]);
        }
    }

    /// The heads [`batch_heads`] hands on, in order; `None` when `frame`
    /// isn't a batch.
    fn heads(frame: &[u8]) -> Option<Vec<Option<Message>>> {
        let mut heads = Vec::new();
        batch_heads(frame, |head| heads.push(head)).then_some(heads)
    }

    #[test]
    fn the_messages_of_a_batch_can_be_read_one_by_one() {
        let answer = |id: i32| {
            Some(Message::Response {
                id: json!(id),
                is_error: false,
            })
        };
        let batch = br#"[{"jsonrpc":"2.0","id":7,"result":{}},{"jsonrpc":"2.0","id":8,"method":"ping","result":{}},{"jsonrpc":"2.0","method":"notifications/x"}]"#;
        assert_eq!(
            heads(batch),
            Some(vec![
                answer(7),
                // Both a request and a response.
                None,
                Some(Message::Notification {
                    method: "notifications/x".to_owned()
                }),
            ])
        );
        assert_eq!(heads(br#"{"jsonrpc":"2.0","id":7,"result":{}}"#), None);
        // Each is handed on as it's read: those before a message that can't
        // be told apart from the next, then one `None` for the rest.
        for text in [
            r#"[{"jsonrpc":"2.0","id":7,"result":{}},1,{"jsonrpc":"2.0","id":8,"result":{}}]"#,
            r#"[{"jsonrpc":"2.0","id":7,"result":{}},{"jsonrpc":"2.0","id":8,"id":8,"result":{}}]"#,
            r#"[{"jsonrpc":"2.0","id":7,"result":{}}] trailing"#,
        ] {
            assert_eq!(
                heads(text.as_bytes()),
                Some(vec![answer(7), None]),
                "{text}"
            );
        }
        // One too large to check is read one message at a time all the
        // same.
        let mut batch = String::from("[");
        batch.push_str(&vec![r#"{"jsonrpc":""}"#; 80_000].join(","));
        batch.push_str(r#",{"jsonrpc":"2.0","id":7,"result":{}}]"#);
        assert!(matches!(
            classify(batch.as_bytes()),
            Err(ParseError::TooManyValues)
        ));
        let mut count = 0;
        let mut last = None;
        assert!(batch_heads(batch.as_bytes(), |head| {
            count += 1;
            last = head;
        }));
        assert_eq!((count, last), (80_001, answer(7)));
    }

    #[test]
    fn finds_a_sampling_request_a_lenient_client_would_read() {
        for text in [
            // Repeated top-level members, whichever copy a client keeps.
            r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":6,"method":"sampling/createMessage","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":6,"method":"ping","method":"sampling/createMessage"}"#,
            r#"{"jsonrpc":"2.0","id":6,"method":"sampling/createMessage","method":"ping"}"#,
            // Ids classifying refuses, which some clients accept.
            r#"{"jsonrpc":"2.0","id":5.0,"method":"sampling/createMessage","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":18446744073709551616,"method":"sampling/createMessage"}"#,
            // Written with escapes.
            r#"{"jsonrpc":"2.0","id":5.0,"method":"sampling\/createMessage"}"#,
            // In a batch, after messages that can't be read at all.
            r#"[1,{"method":[0]},{"jsonrpc":"2.0","id":5.0,"method":"sampling/createMessage"}]"#,
            // After something serde_json refuses but a client may read on
            // past, which hides what follows from a reading here.
            r#"{"jsonrpc":"2.0","id":6,"method":1e999,"method":"sampling/createMessage"}"#,
            r#"{"jsonrpc":"2.0","id":6,"method":"\ud800","method":"sampling/createMessage"}"#,
            r#"{"jsonrpc":"2.0","\ud800":0,"id":6,"method":"sampling/createMessage"}"#,
            r#"[{"jsonrpc":"2.0","id":6,"method":1e999,"method":"sampling/createMessage"}]"#,
            r#"[1e999,{"jsonrpc":"2.0","id":6,"method":"sampling/createMessage"}]"#,
            r#"["\ud800",{"jsonrpc":"2.0","id":6,"method":"sampling\/createMessage"}]"#,
            r#"{"jsonrpc":"2.0","id":6,"method":"ping"} {"jsonrpc":"2.0","id":7,"method":"sampling/createMessage"}"#,
            // Anywhere in what isn't JSON at all.
            "not json, sampling/createMessage",
        ] {
            assert!(names_sampling(text.as_bytes()), "{text}");
            assert_eq!(head(text.as_bytes()), None, "{text}");
        }
        // A byte that isn't UTF-8, in the first copy of `method` or before
        // the message in a batch.
        for frame in [
            &b"{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"\xff\",\"method\":\"sampling/createMessage\"}"[..],
            b"[{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"\xff\",\"method\":\"sampling/createMessage\"}]",
            b"[\"\xff\",{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"sampling/createMessage\"}]",
        ] {
            let text = String::from_utf8_lossy(frame);
            assert!(names_sampling(frame), "{text}");
            assert_eq!(head(frame), None, "{text}");
        }
        let long_id = format!(
            r#"{{"jsonrpc":"2.0","id":"{}","method":"sampling/createMessage"}}"#,
            "x".repeat(200)
        );
        assert!(names_sampling(long_id.as_bytes()));
        for text in [
            r#"{"jsonrpc":"2.0","id":6,"id":6,"method":"ping"}"#,
            // Named only in what the message carries.
            r#"{"jsonrpc":"2.0","id":6,"id":6,"result":{"method":"sampling/createMessage"}}"#,
            r#"{"jsonrpc":"2.0","id":6,"id":6,"method":["sampling/createMessage"]}"#,
            r#"[[{"jsonrpc":"2.0","id":6,"method":"sampling/createMessage"}]]"#,
            // Not named at all, in what can't be read.
            r#"{"jsonrpc":"2.0","id":6,"method":1e999,"method":"ping"}"#,
            "not json",
        ] {
            assert!(!names_sampling(text.as_bytes()), "{text}");
        }
    }

    #[test]
    fn adds_up_the_cost_of_a_message_past_a_repeated_key() {
        assert_eq!(within_cost(br#"{"a":1,"b":{"a":2}}"#).ok(), Some(false));
        assert_eq!(
            within_cost(br#"{"a":1,"b":{"c":2,"c":3}}"#).ok(),
            Some(true)
        );
        assert!(within_cost(b"not json").is_err());
        // Classifying stops at the repeated key, before the cost adds up.
        let values = vec!["0"; MAX_VALUES].join(",");
        let costly =
            format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"x":0,"x":0,"rows":[{values}]}}}}"#);
        assert!(matches!(
            classify(costly.as_bytes()),
            Err(ParseError::Json(_))
        ));
        assert!(matches!(
            within_cost(costly.as_bytes()),
            Err(ParseError::TooManyValues)
        ));
        // Every copy counts.
        let copies = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{{}}}}}"#,
            vec![r#""x":0"#; MAX_VALUES / 2].join(",")
        );
        assert!(matches!(
            within_cost(copies.as_bytes()),
            Err(ParseError::TooManyValues)
        ));
    }

    #[test]
    fn writes_out_what_escapes_stand_for() {
        assert!(matches!(unescaped(br#"{"a":"plain"}"#), Cow::Borrowed(_)));
        for (text, expected) in [
            (r#""token-\"1\"\/2\\3\n""#, "\"token-\"1\"/2\\3\n\""),
            (r#""😀 \ud83d é""#, "\"😀 \u{fffd} é\""),
            (r#""\uZZZZ \u12""#, "\"uZZZZ u12\""),
            ("\"end\\", "\"end\\"),
        ] {
            assert_eq!(unescaped(text.as_bytes()), expected, "{text}");
        }
    }

    #[test]
    fn an_array_or_object_id_is_refused_at_its_first_byte() {
        // Each is cut off before it ends, so reading it through would run
        // out of input: a type error, raised where it starts, shows it was
        // refused unread.
        let values = vec!["0"; 10_000].join(",");
        for text in [
            "[".to_owned(),
            "{".to_owned(),
            format!("[{values}"),
            format!(r#"{{"a":[{values}"#),
        ] {
            let error = scalar(&mut serde_json::Deserializer::from_str(&text)).unwrap_err();
            assert_eq!(
                error.classify(),
                serde_json::error::Category::Data,
                "{error}"
            );
            assert!(error.column() < 10, "{error}");
        }
        // The same within a message, as `classify` and `head` read it.
        let text = format!(r#"{{"jsonrpc":"2.0","method":"ping","id":[{values}"#);
        let error = serde_json::from_str::<Envelope<'_>>(&text)
            .err()
            .expect("an array id is refused");
        assert_eq!(
            error.classify(),
            serde_json::error::Category::Data,
            "{error}"
        );
        assert!(error.column() < 50, "{error}");
    }

    #[test]
    fn displays_messages_for_logs() {
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#).to_string(),
            "request tools/list (id 3)"
        );
    }
}
