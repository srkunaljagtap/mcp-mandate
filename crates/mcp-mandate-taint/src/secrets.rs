//! Spotting secrets in text and in JSON messages.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::{
    STANDARD, STANDARD_PAD_INDIFFERENT, URL_SAFE_PAD_INDIFFERENT,
};
use regex::Regex;
use serde_json::Value;

/// A kind of secret and the pattern that finds it.
#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub name: String,
    pub regex: Regex,
}

impl SecretPattern {
    pub fn new(name: impl Into<String>, regex: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            name: name.into(),
            regex: Regex::new(regex)?,
        })
    }
}

/// Built-in patterns: shapes specific enough to rarely match anything
/// else. Order matters: more specific patterns run first, so an Anthropic
/// key is reported as one rather than as a generic `sk-` key.
const BUILT_IN: &[(&str, &str)] = &[
    (
        // To its END line, or to the end of the text when it was cut short.
        "private-key",
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|[\s\S]*)",
    ),
    ("anthropic-api-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    (
        "openai-api-key",
        r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}",
    ),
    ("aws-access-key-id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    (
        "github-token",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b",
    ),
    ("github-token", r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    ("slack-token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    (
        "stripe-key",
        r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b",
    ),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    (
        // `DB_PASSWORD=…`, `aws_secret_access_key = …`, `"apiKey": "…"`:
        // a name that says secret, anywhere in a longer name, then a value.
        // Quotes may be escaped (JSON inside text), and a quoted value runs
        // to its closing quote, spaces and all.
        "secret-assignment",
        r#"(?i)[A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|(?:auth|access|refresh|session|bearer)[_-]?token|credentials?)[A-Za-z0-9_.-]*\\?["']?\s*[:=]\s*(?:\\?"[^"\n]{8,}|'[^'\n]{8,}|[^\s"',;\[\]]{8,})"#,
    ),
];

/// A JSON field whose name says it holds a secret; its string value is
/// treated as one.
static SECRET_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^[A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|(?:auth|access|refresh|session|bearer)[_-]?token|credentials?)[A-Za-z0-9_.-]*$",
    )
    .expect("the field pattern is valid")
});

/// Shortest value of a secret field, or exact secret, worth flagging.
const MIN_SECRET_CHARS: usize = 8;
/// A decoded blob that isn't text is checked this many bytes at a time, so
/// its lossy text copy stays small...
const BLOB_WINDOW: usize = 1024 * 1024;
/// ...with windows overlapping by this much, so a secret no longer than
/// this always falls wholly inside one.
const BLOB_OVERLAP: usize = 64 * 1024;
/// What replaces the value of a field named like a secret.
const SECRET_FIELD_MARKER: &str = "[REDACTED: secret-field]";

static BUILT_IN_PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    BUILT_IN
        .iter()
        .map(|(name, regex)| SecretPattern::new(*name, regex).expect("built-in patterns are valid"))
        .collect()
});

/// Finds and redacts secrets using the built-in patterns plus any custom
/// ones.
#[derive(Debug, Clone)]
pub struct SecretDetector {
    patterns: Vec<SecretPattern>,
    /// How many of `patterns`, at the end, are exact strings.
    literals: usize,
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl SecretDetector {
    /// The built-in patterns, then `custom` ones.
    pub fn new(custom: Vec<SecretPattern>) -> Self {
        let mut patterns = BUILT_IN_PATTERNS.clone();
        patterns.extend(custom);
        Self {
            patterns,
            literals: 0,
        }
    }

    /// The kind of the first secret found in `text`.
    pub fn find(&self, text: &str) -> Option<&str> {
        self.patterns
            .iter()
            .find(|pattern| pattern.regex.is_match(text))
            .map(|pattern| pattern.name.as_str())
    }

    /// Adds an exact string to treat as a secret, reported as `name`.
    /// Strings shorter than 8 characters, and ones already known, are
    /// skipped.
    pub fn add_literal(&mut self, name: &str, literal: &str) {
        let escaped = regex::escape(literal);
        if literal.chars().count() < MIN_SECRET_CHARS
            || self
                .patterns
                .iter()
                .any(|pattern| pattern.regex.as_str() == escaped)
        {
            return;
        }
        if let Ok(pattern) = SecretPattern::new(name, &escaped) {
            self.patterns.push(pattern);
            self.literals += 1;
        }
    }

    /// Replaces every exact string added or set before with `literals`,
    /// reported as `name`: for a secret that changes, such as a renewed
    /// token, so the old ones don't pile up. Short strings are skipped, as
    /// [`add_literal`](Self::add_literal) skips them. They're found with one
    /// pattern, so each text is searched once however many there are; where
    /// two start at the same place, the longer is redacted whole. Nothing is
    /// rebuilt when the strings are the ones already set, so this is cheap
    /// to call before every message.
    pub fn set_literals(&mut self, name: &str, literals: &[String]) {
        let mut wanted: Vec<String> = Vec::new();
        for literal in literals {
            let escaped = regex::escape(literal);
            if literal.chars().count() >= MIN_SECRET_CHARS && !wanted.contains(&escaped) {
                wanted.push(escaped);
            }
        }
        // The longest first: of the alternatives that match at one place,
        // the first listed is taken.
        wanted.sort_by_key(|escaped| std::cmp::Reverse(escaped.len()));
        let combined = wanted.join("|");
        let kept = self.patterns.len() - self.literals;
        let current = &self.patterns[kept..];
        let sources: Vec<&str> = current
            .iter()
            .map(|pattern| pattern.regex.as_str())
            .collect();
        // Set already, as one pattern or (if that was too large) one each.
        let unchanged = current.iter().all(|pattern| pattern.name == name)
            && (sources == [combined.as_str()] || sources.iter().eq(wanted.iter()));
        if unchanged {
            return;
        }
        self.patterns.truncate(kept);
        self.literals = 0;
        if wanted.is_empty() {
            return;
        }
        if let Ok(pattern) = SecretPattern::new(name, &combined) {
            self.patterns.push(pattern);
            self.literals = 1;
            return;
        }
        // Too large to compile as one: one pattern each.
        for escaped in wanted {
            if let Ok(pattern) = SecretPattern::new(name, &escaped) {
                self.patterns.push(pattern);
                self.literals += 1;
            }
        }
    }

    /// The kind of the first secret anywhere in `value`: in any string, any
    /// object key, or a field named like a secret. Nothing is skipped: use
    /// this on what a client sends.
    pub fn find_in_json(&self, value: &Value) -> Option<String> {
        let mut found = None;
        self.scan(value, false, &mut found);
        found
    }

    /// Like [`find_in_json`](Self::find_in_json), but leaving binary payloads
    /// where MCP puts them as [`redact_json`](Self::redact_json) does: use
    /// this on what a server sends.
    pub fn find_in_response(&self, value: &Value) -> Option<String> {
        let mut found = None;
        self.scan(value, true, &mut found);
        found
    }

    fn scan(&self, value: &Value, skip_binary: bool, found: &mut Option<String>) {
        if found.is_some() {
            return;
        }
        match value {
            Value::String(text) => *found = self.find(text).map(str::to_owned),
            Value::Array(items) => items
                .iter()
                .for_each(|item| self.scan(item, skip_binary, found)),
            Value::Object(map) => {
                let binary = binary_field(map);
                for (key, item) in map {
                    if found.is_some() {
                        return;
                    }
                    if let Some(kind) = self.find(key) {
                        *found = Some(kind.to_owned());
                    } else if secret_field(key, item) {
                        *found = Some("secret-field".to_owned());
                    } else if skip_binary && binary == Some(key.as_str()) {
                        *found = self.blob_secret(key, item);
                    } else {
                        self.scan(item, skip_binary, found);
                    }
                }
            }
            _ => {}
        }
    }

    /// Replaces each secret in `text` with `[REDACTED: kind]`. Returns
    /// `None` when there was nothing to redact.
    pub fn redact_text(&self, text: &str) -> Option<(String, Vec<String>)> {
        let mut current: Cow<'_, str> = Cow::Borrowed(text);
        let mut kinds = Vec::new();
        for pattern in &self.patterns {
            if pattern.regex.is_match(&current) {
                let marker = format!("[REDACTED: {}]", pattern.name);
                let replaced = pattern
                    .regex
                    .replace_all(&current, regex::NoExpand(&marker))
                    .into_owned();
                current = Cow::Owned(replaced);
                kinds.push(pattern.name.clone());
            }
        }
        match current {
            Cow::Borrowed(_) => None,
            Cow::Owned(text) => Some((text, kinds)),
        }
    }

    /// Redacts secrets everywhere in what a server sends: every string, every
    /// object key, and the value of every field named like a secret (each
    /// string, if it's a list). Binary payloads are left alone only where MCP
    /// puts them (the base64 `data` of an image or audio block); a resource's
    /// base64 `blob` is decoded and checked, and replaced if it holds a
    /// secret. Returns the kinds redacted.
    pub fn redact_json(&self, value: &mut Value) -> Vec<String> {
        let mut kinds = Vec::new();
        self.redact_value(value, &mut kinds);
        kinds
    }

    fn redact_value(&self, value: &mut Value, kinds: &mut Vec<String>) {
        match value {
            Value::String(text) => {
                if let Some((redacted, found)) = self.redact_text(text) {
                    *text = redacted;
                    kinds.extend(found);
                }
            }
            Value::Array(items) => items
                .iter_mut()
                .for_each(|item| self.redact_value(item, kinds)),
            Value::Object(map) => {
                let binary = binary_field(map);
                // The next number to try for each key that's taken, so
                // numbering many keys that redact alike stays quick.
                let mut next_number: HashMap<String, u64> = HashMap::new();
                // Keys can't be changed in place, so the map is rebuilt.
                for (mut key, mut item) in std::mem::take(map) {
                    if secret_field(&key, &item) {
                        self.redact_field(&mut item, kinds);
                        kinds.push("secret-field".to_owned());
                    } else if binary == Some(key.as_str()) {
                        if let Some(kind) = self.blob_secret(&key, &item) {
                            item = Value::String(redacted_blob(&kind));
                            kinds.push(kind);
                        }
                    } else {
                        self.redact_value(&mut item, kinds);
                    }
                    if let Some((redacted, found)) = self.redact_text(&key) {
                        key = redacted;
                        kinds.extend(found);
                    }
                    // Two keys can redact to the same text: number the later
                    // ones rather than lose them.
                    if map.contains_key(&key) {
                        let next = next_number.entry(key.clone()).or_insert(2);
                        let (n, numbered) = (*next..)
                            .map(|n| (n, format!("{key} #{n}")))
                            .find(|(_, numbered)| !map.contains_key(numbered))
                            .expect("some number is free");
                        *next = n + 1;
                        key = numbered;
                    }
                    map.insert(key, item);
                }
            }
            _ => {}
        }
    }

    /// Replaces the value of a field named like a secret, or each secret in
    /// it if it's a list (anything else in the list is redacted as usual).
    fn redact_field(&self, value: &mut Value, kinds: &mut Vec<String>) {
        match value {
            Value::Array(items) => {
                for item in items {
                    if secret_value(item) {
                        *item = Value::String(SECRET_FIELD_MARKER.to_owned());
                    } else {
                        self.redact_value(item, kinds);
                    }
                }
            }
            _ => *value = Value::String(SECRET_FIELD_MARKER.to_owned()),
        }
    }

    /// A secret inside a binary field: a resource blob is decoded and its
    /// content checked; image and audio data aren't, as long as it is
    /// base64. Anything that isn't canonical base64 is judged as text, and a
    /// blob is also decoded the way lenient clients do it.
    fn blob_secret(&self, key: &str, value: &Value) -> Option<String> {
        let text = value.as_str()?;
        let blob = key == "blob";
        let found = match STANDARD.decode(text.trim()) {
            Ok(bytes) if blob => self.find_in_bytes(&bytes),
            Ok(_) => None,
            Err(_) if blob => self
                .find(text)
                .or_else(|| decode_leniently(text).and_then(|bytes| self.find_in_bytes(&bytes))),
            Err(_) => self.find(text),
        };
        found.map(str::to_owned)
    }

    /// The kind of the first secret in decoded bytes. Text is checked whole;
    /// anything else a window at a time.
    fn find_in_bytes(&self, bytes: &[u8]) -> Option<&str> {
        if let Ok(text) = std::str::from_utf8(bytes) {
            return self.find(text);
        }
        let mut start = 0;
        loop {
            let end = bytes.len().min(start + BLOB_WINDOW);
            if let Some(kind) = self.find(&String::from_utf8_lossy(&bytes[start..end])) {
                return Some(kind);
            }
            if end == bytes.len() {
                return None;
            }
            start = end - BLOB_OVERLAP;
        }
    }
}

/// `text` decoded as base64 the way lenient decoders read it: ignoring line
/// breaks and other whitespace, with or without padding, in the standard or
/// the URL-safe alphabet.
fn decode_leniently(text: &str) -> Option<Vec<u8>> {
    let compact: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    STANDARD_PAD_INDIFFERENT
        .decode(&compact)
        .or_else(|_| URL_SAFE_PAD_INDIFFERENT.decode(&compact))
        .ok()
}

/// What replaces a blob that held a secret: still valid base64.
fn redacted_blob(kind: &str) -> String {
    STANDARD.encode(format!("[REDACTED: {kind}]"))
}

/// The binary field of `map`, if it's where MCP puts binary data: `data`
/// in an image or audio content block, `blob` in a resource's contents.
fn binary_field(map: &serde_json::Map<String, Value>) -> Option<&'static str> {
    let media = matches!(
        map.get("type").and_then(Value::as_str),
        Some("image" | "audio")
    ) && map.get("data").is_some_and(Value::is_string);
    let resource = map.get("uri").is_some_and(Value::is_string)
        && map.get("blob").is_some_and(Value::is_string);
    if media {
        Some("data")
    } else if resource {
        Some("blob")
    } else {
        None
    }
}

/// Whether `key` names a secret and `value` holds one: a string long enough
/// to be one, or a list with such a string in it.
fn secret_field(key: &str, value: &Value) -> bool {
    let holds_one = match value {
        Value::Array(items) => items.iter().any(secret_value),
        value => secret_value(value),
    };
    holds_one && SECRET_FIELD.is_match(key)
}

/// Whether `value`, found under a name that says secret, is one: a string
/// long enough, and not just what redaction left there.
fn secret_value(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| text.chars().count() >= MIN_SECRET_CHARS && !is_redaction(text))
}

/// Whether `text` is exactly a redaction marker, `[REDACTED: kind]`, with
/// nothing before or after it.
fn is_redaction(text: &str) -> bool {
    text.strip_prefix("[REDACTED: ")
        .and_then(|rest| rest.strip_suffix(']'))
        .is_some_and(|kind| {
            !kind.is_empty() && !kind.contains(']') && !kind.contains(char::is_control)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// One example of each built-in kind. Fake values, shaped like the real ones.
    const SAMPLES: &[(&str, &str)] = &[
        (
            "private-key",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
        ),
        (
            "anthropic-api-key",
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123",
        ),
        (
            "openai-api-key",
            "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789AB",
        ),
        ("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
        ("github-token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        (
            "github-token",
            "github_pat_11ABCDEFG0123456789_abcdefghijklmnop",
        ),
        ("slack-token", "xoxb-1234567890-abcdefghij"),
        // Built from pieces, so secret scanners reading this file don't
        // take these fake keys for real ones.
        (
            "google-api-key",
            concat!("AIza", "SyA-abcdefghijklmnopqrstuvwxyz01234"),
        ),
        (
            "stripe-key",
            concat!("sk_", "live_abcdefghijklmnopqrstuvwx"),
        ),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
        ),
        ("secret-assignment", "password = \"correct-horse-battery\""),
    ];

    #[test]
    fn finds_each_built_in_kind() {
        let detector = SecretDetector::default();
        for (kind, sample) in SAMPLES {
            let text = format!("config: {sample} (end)");
            assert_eq!(detector.find(&text), Some(*kind), "for {sample:?}");
        }
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        let detector = SecretDetector::default();
        for text in [
            "The quick brown fox jumps over the lazy dog.",
            "See https://example.com/docs?page=2 for the AKIA prefix explanation.",
            "sk-short is not a key",
            "password: hunter2",
            "Echo: hello",
        ] {
            assert_eq!(detector.find(text), None, "flagged {text:?}");
            assert!(detector.redact_text(text).is_none());
        }
    }

    #[test]
    fn redacts_inside_messages_but_not_binary_data() {
        let detector = SecretDetector::default();
        // A value that would be redacted if it were text.
        let image_data = "AKIAIOSFODNN7EXAMPLE".to_owned();
        let mut message = json!({"content": [
            {"type": "text", "text": "Your key is AKIAIOSFODNN7EXAMPLE, keep it safe."},
            {"type": "image", "data": image_data, "mimeType": "image/png"},
            {"type": "resource", "resource": {"uri": "file:///k", "blob": image_data}}
        ]});

        let kinds = detector.redact_json(&mut message);

        assert_eq!(kinds, ["aws-access-key-id"]);
        assert_eq!(
            message["content"][0]["text"],
            "Your key is [REDACTED: aws-access-key-id], keep it safe."
        );
        assert_eq!(message["content"][1]["data"], image_data);
        assert_eq!(message["content"][2]["resource"]["blob"], image_data);
    }

    #[test]
    fn finds_secrets_in_the_shapes_they_usually_take() {
        let detector = SecretDetector::default();
        for text in [
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "DB_PASSWORD=correct-horse-battery",
            r#"{"password": "correct-horse-battery"}"#,
            r#"apiKey: "abcd1234efgh5678""#,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----",
            // JSON inside text, as `aws secretsmanager` prints it.
            r#"{"SecretString": "{\"username\":\"admin\",\"password\":\"hunter2hunter2\"}"}"#,
            r#"DB_PASSWORD="correct horse battery staple""#,
        ] {
            assert!(detector.find(text).is_some(), "missed {text:?}");
        }
    }

    #[test]
    fn redacts_a_quoted_value_up_to_its_closing_quote() {
        let detector = SecretDetector::default();
        for (text, secret) in [
            (r#"PASSWORD="hunter22 x y""#, "x y"),
            (r#"DB_PASSWORD="correct horse battery staple""#, "staple"),
            ("db_password: 'correct horse battery'", "battery"),
            (
                r#"{"SecretString": "{\"username\":\"admin\",\"password\":\"hunter2hunter2\"}"}"#,
                "hunter2",
            ),
        ] {
            let (redacted, _) = detector
                .redact_text(text)
                .unwrap_or_else(|| panic!("missed {text:?}"));
            assert!(!redacted.contains(secret), "{redacted}");
        }
        // An empty value doesn't take the next field with it.
        let empty = r#"{"password": "", "username": "bob-the-builder"}"#;
        assert_eq!(detector.find(empty), None);
    }

    #[test]
    fn checks_resource_blobs_of_any_size() {
        let detector = SecretDetector::default();
        let mut text = "x".repeat(2 * BLOB_WINDOW);
        text.push_str("\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
        let mut resource =
            json!({"contents": [{"uri": "file:///app.log", "blob": STANDARD.encode(&text)}]});
        assert_eq!(detector.redact_json(&mut resource), ["aws-access-key-id"]);
        let blob = resource["contents"][0]["blob"].as_str().unwrap();
        assert_eq!(
            STANDARD.decode(blob).unwrap(),
            b"[REDACTED: aws-access-key-id]"
        );

        // Binary content, with a key across the end of the first window.
        let mut bytes = vec![0xff];
        bytes.extend(std::iter::repeat_n(b'.', BLOB_WINDOW - 10));
        bytes.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE");
        bytes.extend(std::iter::repeat_n(b'.', BLOB_WINDOW));
        let binary = json!({"uri": "file:///core", "blob": STANDARD.encode(&bytes)});
        assert_eq!(
            detector.find_in_response(&binary),
            Some("aws-access-key-id".to_owned())
        );
    }

    #[test]
    fn decodes_blobs_the_way_lenient_clients_do() {
        let detector = SecretDetector::default();
        let env = "# written by the deploy script ???\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
        // Broken into lines as MIME encoders write it, without padding.
        let encoded = STANDARD.encode(env);
        let wrapped = encoded
            .trim_end_matches('=')
            .as_bytes()
            .chunks(76)
            .map(|line| format!("{}\r\n", std::str::from_utf8(line).unwrap()))
            .collect::<String>();
        let url_safe = URL_SAFE_PAD_INDIFFERENT.encode(env);
        assert!(url_safe.contains(['-', '_']), "{url_safe}");
        for blob in [wrapped, url_safe] {
            assert!(STANDARD.decode(blob.trim()).is_err(), "{blob}");
            let resource = json!({"uri": "file:///.env", "blob": blob});
            assert_eq!(
                detector.find_in_response(&resource),
                Some("aws-access-key-id".to_owned()),
                "{blob}"
            );
        }
    }

    #[test]
    fn treats_lists_named_like_secrets_as_secrets() {
        let detector = SecretDetector::default();
        let mut message = json!({
            "api_keys": ["k1-opaque-0042", "k2-opaque-0043", 7, "short"],
            "password": "[REDACTED] sk9f8q7w6e5r4t"
        });
        assert_eq!(
            detector.find_in_json(&json!({"secrets": ["k1-opaque-0042"]})),
            Some("secret-field".to_owned())
        );
        detector.redact_json(&mut message);
        assert_eq!(
            message,
            json!({
                "api_keys": ["[REDACTED: secret-field]", "[REDACTED: secret-field]", 7, "short"],
                "password": "[REDACTED: secret-field]"
            })
        );
        // What redaction left isn't taken for a secret again.
        assert_eq!(detector.find_in_json(&message), None);
    }

    #[test]
    fn keeps_every_key_when_two_redact_alike() {
        let detector = SecretDetector::default();
        let mut message = json!({
            "AKIAIOSFODNN7EXAMPLE": {"user": "a"},
            "AKIAI44QH8DHBEXAMPLE": {"user": "b"}
        });
        detector.redact_json(&mut message);
        let keys: Vec<&String> = message.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "[REDACTED: aws-access-key-id]",
                "[REDACTED: aws-access-key-id] #2"
            ],
            "{message}"
        );
    }

    #[test]
    fn numbers_many_keys_that_redact_alike_quickly() {
        let detector = SecretDetector::default();
        let count = 20_000;
        let mut message = Value::Object(
            (0..count)
                .map(|n| (format!("AKIA{n:016}"), json!(n)))
                .collect(),
        );
        let started = std::time::Instant::now();
        detector.redact_json(&mut message);
        let took = started.elapsed();
        let keys = message.as_object().unwrap();
        assert_eq!(keys.len(), count);
        assert!(keys.contains_key(&format!("[REDACTED: aws-access-key-id] #{count}")));
        assert!(took < std::time::Duration::from_secs(10), "took {took:?}");
    }

    #[test]
    fn numbering_skips_numbers_already_taken() {
        let detector = SecretDetector::default();
        let token = |c: &str| format!("ghp_{}", c.repeat(36));
        let mut message = json!({
            "[REDACTED: github-token] #2": 0,
            token("a"): 1,
            token("b"): 2,
            token("c"): 3
        });
        detector.redact_json(&mut message);
        assert_eq!(
            message,
            json!({
                "[REDACTED: github-token]": 1,
                "[REDACTED: github-token] #2": 0,
                "[REDACTED: github-token] #3": 2,
                "[REDACTED: github-token] #4": 3
            })
        );
    }

    #[test]
    fn takes_quoted_text_after_a_secret_name_as_a_secret() {
        let detector = SecretDetector::default();
        // A quoted value is taken whole, so a passphrase with spaces is
        // caught, and so is prose in quotes after such a name.
        assert_eq!(
            detector.find(r#"const PASSWORD_PROMPT = "Enter your password";"#),
            Some("secret-assignment")
        );
        // An unquoted value stops at the first space.
        assert_eq!(detector.find("Password: must be 12 characters"), None);
    }

    #[test]
    fn treats_fields_named_like_secrets_as_secrets() {
        let detector = SecretDetector::default();
        let mut message = json!({"config": {"db_password": "correct-horse", "apiKey": "zq8f3kq9z2m1", "name": "production"}});
        assert_eq!(
            detector.find_in_json(&message),
            Some("secret-field".to_owned())
        );
        detector.redact_json(&mut message);
        assert_eq!(message["config"]["db_password"], "[REDACTED: secret-field]");
        assert_eq!(message["config"]["apiKey"], "[REDACTED: secret-field]");
        assert_eq!(message["config"]["name"], "production");
    }

    #[test]
    fn binary_exemptions_apply_only_where_mcp_puts_binary_data() {
        let detector = SecretDetector::default();
        // From a client, nothing is exempt.
        assert!(
            detector
                .find_in_json(&json!({"body": {"blob": "AKIAIOSFODNN7EXAMPLE"}}))
                .is_some()
        );
        assert!(
            detector
                .find_in_json(&json!({"type": "image", "mimeType": "image/png", "data": "x AKIAIOSFODNN7EXAMPLE"}))
                .is_some()
        );
        // From a server, a `blob` outside resource contents is ordinary text.
        let mut stray = json!({"structuredContent": {"blob": "key AKIAIOSFODNN7EXAMPLE"}});
        assert_eq!(detector.redact_json(&mut stray), ["aws-access-key-id"]);
        // Image data that isn't base64 is judged as text.
        let mut smuggled =
            json!({"type": "image", "mimeType": "image/png", "data": "key AKIAIOSFODNN7EXAMPLE"});
        assert_eq!(detector.redact_json(&mut smuggled), ["aws-access-key-id"]);
        assert!(STANDARD.decode(smuggled["data"].as_str().unwrap()).is_ok());
        // A resource blob holding a secret is decoded, found and replaced.
        let encoded = STANDARD.encode("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
        let mut resource = json!({"contents": [{"uri": "file:///.env", "blob": encoded}]});
        assert_eq!(
            detector.find_in_response(&resource),
            Some("aws-access-key-id".to_owned())
        );
        detector.redact_json(&mut resource);
        let blob = resource["contents"][0]["blob"].as_str().unwrap();
        assert_eq!(
            STANDARD.decode(blob).unwrap(),
            b"[REDACTED: aws-access-key-id]"
        );
    }

    #[test]
    fn exact_strings_can_be_secrets_too() {
        let mut detector = SecretDetector::default();
        detector.add_literal("gateway-credential", "opaque-token-1234567");
        detector.add_literal("gateway-credential", "short");
        assert_eq!(
            detector.find("echo: Bearer opaque-token-1234567"),
            Some("gateway-credential")
        );
        assert_eq!(detector.find("short"), None);
    }

    #[test]
    fn exact_strings_that_change_replace_the_old_ones() {
        let mut detector = SecretDetector::default();
        let built_in = detector.patterns.len();
        detector.add_literal("gateway-credential", "client-secret-0");
        for renewal in 0..100 {
            let token = format!("opaque-token-{renewal}");
            let set = [token.clone(), format!("Bearer {token}"), "tiny".to_owned()];
            detector.set_literals("gateway-credential", &set);
            detector.set_literals("gateway-credential", &set);
        }
        assert_eq!(
            detector.patterns.len(),
            built_in + 1,
            "the latest token's two forms, in one pattern, and nothing else"
        );
        assert_eq!(
            detector.find("echo: opaque-token-99"),
            Some("gateway-credential")
        );
        assert_eq!(detector.find("echo: opaque-token-98"), None);
        assert_eq!(detector.find("echo: client-secret-0"), None);
        let (text, _) = detector.redact_text("Bearer opaque-token-99").unwrap();
        assert!(!text.contains("opaque-token-99"), "{text}");
        detector.set_literals("gateway-credential", &[]);
        assert_eq!(detector.patterns.len(), built_in);
    }

    #[test]
    fn many_exact_strings_are_searched_for_at_once() {
        let mut detector = SecretDetector::default();
        let built_in = detector.patterns.len();
        let mut set = vec!["client-secret".to_owned()];
        for n in 0..16 {
            set.push(format!("Bearer opaque-token-{n}"));
            set.push(format!("opaque-token-{n}"));
        }
        // Starts where another does, and goes on past it.
        set.push("client-secret-and-more".to_owned());
        detector.set_literals("gateway-credential", &set);
        assert_eq!(detector.patterns.len(), built_in + 1, "one pattern");
        for literal in &set {
            let text = format!("echo: {literal}.");
            assert_eq!(
                detector.find(&text),
                Some("gateway-credential"),
                "{literal}"
            );
            let (redacted, _) = detector.redact_text(&text).unwrap();
            assert_eq!(redacted, "echo: [REDACTED: gateway-credential].");
        }
    }

    #[test]
    fn reports_an_anthropic_key_as_such() {
        let detector = SecretDetector::default();
        let (text, kinds) = detector
            .redact_text("key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789")
            .unwrap();
        assert_eq!(text, "key [REDACTED: anthropic-api-key]");
        assert_eq!(kinds, ["anthropic-api-key"]);
    }

    #[test]
    fn supports_custom_patterns() {
        let custom = SecretPattern::new("internal-token", r"itk_[a-z0-9]{16}").unwrap();
        let detector = SecretDetector::new(vec![custom]);
        assert_eq!(
            detector.find_in_json(&json!({"args": ["x", "itk_0123456789abcdef"]})),
            Some("internal-token".to_owned())
        );
    }

    #[test]
    fn finds_and_redacts_secrets_in_object_keys() {
        let detector = SecretDetector::new(Vec::new());
        let mut message = json!({"result": {"AKIAIOSFODNN7EXAMPLE": {"note": "ok"}}});
        assert_eq!(
            detector.find_in_json(&message),
            Some("aws-access-key-id".to_owned())
        );
        assert_eq!(detector.redact_json(&mut message), ["aws-access-key-id"]);
        assert_eq!(
            message,
            json!({"result": {"[REDACTED: aws-access-key-id]": {"note": "ok"}}})
        );
    }
}
