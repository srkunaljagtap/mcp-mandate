//! Spotting secrets in text and in JSON messages.

use std::borrow::Cow;
use std::sync::LazyLock;

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
        "private-key",
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
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
        "password-assignment",
        r#"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']?[^\s"',;]{12,}"#,
    ),
];

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

    /// The kind of the first secret found in any string inside `value`.
    pub fn find_in_json(&self, value: &Value) -> Option<String> {
        let mut found = None;
        walk(value, &mut |text| {
            if found.is_none() {
                found = self.find(text).map(str::to_owned);
            }
        });
        found
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

    /// Redacts every string inside `value` except binary payloads (image
    /// and audio data, resource blobs). Returns the kinds redacted.
    pub fn redact_json(&self, value: &mut Value) -> Vec<String> {
        let mut kinds = Vec::new();
        walk_mut(value, &mut |text| {
            if let Some((redacted, found)) = self.redact_text(text) {
                *text = redacted;
                kinds.extend(found);
            }
        });
        kinds
    }
}

/// Whether `map` is an image or audio content block, whose `data` is
/// base64 and must not be touched.
fn is_binary_block(map: &serde_json::Map<String, Value>) -> bool {
    matches!(
        map.get("type").and_then(Value::as_str),
        Some("image" | "audio")
    )
}

fn skip(key: &str, binary: bool) -> bool {
    key == "blob" || (binary && key == "data")
}

fn walk(value: &Value, visit: &mut impl FnMut(&str)) {
    match value {
        Value::String(text) => visit(text),
        Value::Array(items) => items.iter().for_each(|item| walk(item, visit)),
        Value::Object(map) => {
            let binary = is_binary_block(map);
            for (key, item) in map {
                if !skip(key, binary) {
                    walk(item, visit);
                }
            }
        }
        _ => {}
    }
}

fn walk_mut(value: &mut Value, visit: &mut impl FnMut(&mut String)) {
    match value {
        Value::String(text) => visit(text),
        Value::Array(items) => items.iter_mut().for_each(|item| walk_mut(item, visit)),
        Value::Object(map) => {
            let binary = is_binary_block(map);
            for (key, item) in map.iter_mut() {
                if !skip(key, binary) {
                    walk_mut(item, visit);
                }
            }
        }
        _ => {}
    }
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
        (
            "password-assignment",
            "password = \"correct-horse-battery\"",
        ),
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
}
