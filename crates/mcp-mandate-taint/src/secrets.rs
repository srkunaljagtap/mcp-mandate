//! Spotting secrets in text and in JSON messages.

use std::borrow::Cow;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
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
        "secret-assignment",
        r#"(?i)[A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|(?:auth|access|refresh|session|bearer)[_-]?token|credentials?)[A-Za-z0-9_.-]*["']?\s*[:=]\s*["']?[^\s"',;\[\]]{8,}"#,
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
/// Largest resource blob decoded to look for secrets inside it.
const MAX_BLOB_BYTES: usize = 1024 * 1024;

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
        Self { patterns }
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
    /// object key, and the value of every field named like a secret. Binary
    /// payloads are left alone only where MCP puts them (the base64 `data`
    /// of an image or audio block); a resource's base64 `blob` is decoded and
    /// checked, and replaced if it holds a secret. Returns the kinds
    /// redacted.
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
                // Keys can't be changed in place, so the map is rebuilt.
                for (mut key, mut item) in std::mem::take(map) {
                    if secret_field(&key, &item) {
                        item = Value::String("[REDACTED: secret-field]".to_owned());
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
                    map.insert(key, item);
                }
            }
            _ => {}
        }
    }

    /// A secret inside a binary field: a resource blob is decoded (up to a
    /// size limit) and its text checked; image and audio data aren't, as
    /// long as it is base64. Anything that isn't is judged as text.
    fn blob_secret(&self, key: &str, value: &Value) -> Option<String> {
        let text = value.as_str()?;
        match STANDARD.decode(text.trim()) {
            Ok(_) if key != "blob" => None,
            Ok(bytes) if bytes.len() <= MAX_BLOB_BYTES => self
                .find(&String::from_utf8_lossy(&bytes))
                .map(str::to_owned),
            // Too large to check, or not base64 at all: judged as text.
            _ => self.find(text).map(str::to_owned),
        }
    }
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

/// Whether `key` names a secret and `value` is a string long enough to be
/// one.
fn secret_field(key: &str, value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.chars().count() >= MIN_SECRET_CHARS && !text.starts_with("[REDACTED")
    }) && SECRET_FIELD.is_match(key)
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
        ("google-api-key", "AIzaSyA-abcdefghijklmnopqrstuvwxyz01234"),
        ("stripe-key", "sk_live_abcdefghijklmnopqrstuvwx"),
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
        ] {
            assert!(detector.find(text).is_some(), "missed {text:?}");
        }
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
