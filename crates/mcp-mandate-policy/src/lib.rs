//! The policy file: what a session may do, written by people.
//!
//! ```toml
//! mode = "enforce"               # the default, "observe", only logs what would be blocked
//! pins = "everything.pins.toml"  # relative to this file
//!
//! [defaults]
//! tools = "deny"                 # tools no rule matches
//!
//! [[tools]]
//! match = "echo"                 # glob on the tool name
//! action = "allow"
//! no_shell_metacharacters = ["message"]
//!
//! [[tools]]
//! match = "send_*"
//! sends_out = true               # held once the session is tainted
//!
//! [server_requests]
//! sampling = "deny"
//!
//! [secrets]
//! redact_responses = true
//! block_in_arguments = true
//!
//! [audit]
//! path = "logs/server.audit.jsonl"  # default: policy.toml → policy.audit.jsonl
//! ```
//!
//! When several rules match a tool, the most restrictive action wins
//! (deny over hold over allow), so rule order never matters.
//!
//! A rule's `match` is a glob on the whole tool name (`*`, `?`, `[abc]`,
//! `{a,b}`), case-sensitive. It means the same on every platform: `\` makes
//! the next character literal (`run\*` matches only `run*`), and `/` and `\`
//! in a name are ordinary characters. A `**` right before or after a `\`
//! is refused: globset would read that `\` as a path separator on Windows.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use globset::GlobBuilder;
use serde::Deserialize;
use serde_json::Value;

/// Default cap on a tool call's arguments, as JSON.
pub const DEFAULT_MAX_ARGUMENT_BYTES: usize = 64 * 1024;

/// The shortest text, in bytes, a custom secret pattern must need to match.
/// No real secret is shorter, and a pattern that matches less (`token|`,
/// `[a-z]*`, `[A-Za-z0-9]` without its count) would match ordinary text
/// everywhere: every call blocked, every message filled with markers.
const MIN_SECRET_PATTERN_BYTES: usize = 5;

/// Characters that let a string run extra shell commands.
const SHELL_METACHARACTERS: &[char] = &[
    ';', '&', '|', '$', '`', '<', '>', '(', ')', '{', '}', '\n', '\r', '\0',
];

/// What happens to a call. Ordered from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    /// Needs a person's approval. Approvals aren't supported yet, so a held
    /// call is blocked with a reason saying so.
    Hold,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Block what the policy doesn't allow.
    Enforce,
    /// Log what would be blocked, but let everything through. The default:
    /// a policy blocks only once it says `mode = "enforce"`.
    #[default]
    Observe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Defaults {
    /// For tools no rule gives an action.
    pub tools: Action,
    pub max_argument_bytes: usize,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            tools: Action::Deny,
            max_argument_bytes: DEFAULT_MAX_ARGUMENT_BYTES,
        }
    }
}

/// Requests a server sends to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerRequests {
    /// `sampling/createMessage`: the server asks the client's model to write.
    pub sampling: Action,
    /// `elicitation/create`: the server asks you a question.
    pub elicitation: Action,
    /// `roots/list`: the server asks which folders it may work in.
    pub roots: Action,
}

impl Default for ServerRequests {
    fn default() -> Self {
        Self {
            sampling: Action::Deny,
            elicitation: Action::Deny,
            roots: Action::Allow,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    mode: Mode,
    pins: Option<PathBuf>,
    #[serde(default)]
    defaults: Defaults,
    #[serde(default)]
    tools: Vec<ToolRuleFile>,
    #[serde(default)]
    server_requests: ServerRequests,
    /// Requests mcp-mandate doesn't know how to check.
    #[serde(default = "deny")]
    unknown_requests: Action,
    #[serde(default)]
    secrets: SecretsFile,
    #[serde(default)]
    taint: Taint,
    #[serde(default)]
    audit: AuditFile,
}

fn deny() -> Action {
    Action::Deny
}

/// Combines two optional answers, keeping whichever is set when only one is.
fn either(
    current: Option<bool>,
    rule: Option<bool>,
    combine: fn(bool, bool) -> bool,
) -> Option<bool> {
    match (current, rule) {
        (Some(current), Some(rule)) => Some(combine(current, rule)),
        (current, None) => current,
        (None, rule) => rule,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct SecretsFile {
    redact_responses: bool,
    block_in_arguments: bool,
    patterns: Vec<SecretPatternFile>,
}

impl Default for SecretsFile {
    fn default() -> Self {
        Self {
            redact_responses: true,
            block_in_arguments: true,
            patterns: Vec::new(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretPatternFile {
    name: String,
    regex: String,
}

/// How secrets (API keys, tokens, private keys) are handled.
#[derive(Debug, Clone)]
pub struct Secrets {
    /// Replace secrets in what servers send with `[REDACTED: kind]`.
    pub redact_responses: bool,
    /// Block tool calls whose arguments carry a secret (unless the tool's
    /// rule sets `allow_secrets`).
    pub block_in_arguments: bool,
    /// Extra patterns, as (name, compiled regex), on top of the built-in ones.
    pub patterns: Vec<(String, regex::Regex)>,
}

/// What taints a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Taint {
    /// Reading a server's resources (`resources/read`) taints the session.
    pub resources_are_untrusted: bool,
    /// Fetching a prompt (`prompts/get`) taints the session: what a prompt
    /// returns isn't pinned, only its listing.
    pub prompts_are_untrusted: bool,
}

impl Default for Taint {
    fn default() -> Self {
        Self {
            resources_are_untrusted: true,
            prompts_are_untrusted: true,
        }
    }
}

/// The `[audit]` table.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct AuditFile {
    path: Option<PathBuf>,
}

/// The audit log a policy file writes when it doesn't name one: next to
/// it, named after it (`policy.toml` → `policy.audit.jsonl`).
pub fn default_audit_log(policy: &Path) -> PathBuf {
    policy.with_extension("audit.jsonl")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolRuleFile {
    #[serde(rename = "match")]
    pattern: String,
    action: Option<Action>,
    max_argument_bytes: Option<usize>,
    #[serde(default)]
    no_shell_metacharacters: Vec<String>,
    reads_untrusted: Option<bool>,
    sends_out: Option<bool>,
    allow_secrets: Option<bool>,
}

#[derive(Clone)]
struct ToolRule {
    pattern: String,
    /// The glob, as a regex on the name's bytes.
    matcher: regex::bytes::Regex,
    action: Option<Action>,
    max_argument_bytes: Option<usize>,
    no_shell_metacharacters: Vec<String>,
    reads_untrusted: Option<bool>,
    sends_out: Option<bool>,
    allow_secrets: Option<bool>,
}

/// A loaded, checked policy.
#[derive(Clone)]
pub struct Policy {
    pub mode: Mode,
    /// The pins file, resolved against the policy file's folder.
    pub pins: Option<PathBuf>,
    pub defaults: Defaults,
    pub server_requests: ServerRequests,
    pub unknown_requests: Action,
    pub secrets: Secrets,
    pub taint: Taint,
    /// The audit log, resolved against the policy file's folder.
    pub audit_log: PathBuf,
    rules: Vec<ToolRule>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("couldn't read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{} isn't a valid policy", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("tool pattern `{pattern}` isn't a valid glob")]
    Pattern {
        pattern: String,
        #[source]
        source: globset::Error,
    },
    #[error("tool pattern `{pattern}` is too complex")]
    PatternTooComplex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
    #[error(
        "tool pattern `{pattern}` has `**` next to `\\`, which would match other tools on Windows (where it reads `\\` as a path separator); write `*` there instead"
    )]
    PatternDependsOnPlatform { pattern: String },
    #[error("secret pattern `{name}` isn't a valid regular expression")]
    SecretPattern {
        name: String,
        #[source]
        source: regex::Error,
    },
    #[error(
        "secret pattern `{name}` can match as little as {shortest} bytes of text (it must need at least {min}), so it would match ordinary text everywhere (every call blocked, every message filled with redaction markers)",
        min = MIN_SECRET_PATTERN_BYTES
    )]
    SecretPatternTooShort { name: String, shortest: usize },
}

/// What the policy says about one tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDecision {
    pub action: Action,
    pub max_argument_bytes: usize,
    /// Arguments whose string values may not contain shell metacharacters.
    pub no_shell_metacharacters: BTreeSet<String>,
    /// Taint labels; `None` when no rule says (the tool's own annotations
    /// then decide).
    pub reads_untrusted: Option<bool>,
    pub sends_out: Option<bool>,
    /// Whether calls may carry secrets in their arguments.
    pub allow_secrets: bool,
    /// The patterns of the rules that matched, for logs.
    pub matched: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArgumentProblem {
    #[error("its arguments are {size} bytes, over the {limit}-byte limit")]
    TooLarge { size: usize, limit: usize },
    #[error("argument `{argument}` contains the shell metacharacter {character:?}")]
    ShellMetacharacter { argument: String, character: char },
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse_file(&text, path)
    }

    /// Parses the text of the policy file at `path`, as [`load`](Self::load)
    /// does once it has read it: relative paths resolve against its folder,
    /// and errors name it. For callers that also hash the text: the hash
    /// then describes exactly the policy in force.
    pub fn parse_file(text: &str, path: &Path) -> Result<Self, PolicyError> {
        let base = path.parent().unwrap_or(Path::new("."));
        Self::parse_with(text, base, default_audit_log(path)).map_err(|error| match error {
            PolicyError::Parse { source, .. } => PolicyError::Parse {
                path: path.to_owned(),
                source,
            },
            other => other,
        })
    }

    /// Parses policy text; relative paths (`pins`, the audit log) are
    /// resolved against `base`. Without a file name to go by, the default
    /// audit log is `mcp-mandate.audit.jsonl` in `base`.
    pub fn parse(text: &str, base: &Path) -> Result<Self, PolicyError> {
        Self::parse_with(text, base, base.join("mcp-mandate.audit.jsonl"))
    }

    fn parse_with(text: &str, base: &Path, default_log: PathBuf) -> Result<Self, PolicyError> {
        let file: PolicyFile = toml::from_str(text).map_err(|source| PolicyError::Parse {
            path: PathBuf::new(),
            source,
        })?;
        let rules = file
            .tools
            .into_iter()
            .map(|rule| {
                Ok(ToolRule {
                    matcher: tool_matcher(&rule.pattern)?,
                    pattern: rule.pattern,
                    action: rule.action,
                    max_argument_bytes: rule.max_argument_bytes,
                    no_shell_metacharacters: rule.no_shell_metacharacters,
                    reads_untrusted: rule.reads_untrusted,
                    sends_out: rule.sends_out,
                    allow_secrets: rule.allow_secrets,
                })
            })
            .collect::<Result<_, PolicyError>>()?;
        let patterns = file
            .secrets
            .patterns
            .into_iter()
            .map(|pattern| {
                let regex = regex::Regex::new(&pattern.regex).map_err(|source| {
                    PolicyError::SecretPattern {
                        name: pattern.name.clone(),
                        source,
                    }
                })?;
                if let Some(shortest) = shortest_match(&pattern.regex)
                    && shortest < MIN_SECRET_PATTERN_BYTES
                {
                    return Err(PolicyError::SecretPatternTooShort {
                        name: pattern.name,
                        shortest,
                    });
                }
                Ok((pattern.name, regex))
            })
            .collect::<Result<_, PolicyError>>()?;
        Ok(Self {
            mode: file.mode,
            pins: file.pins.map(|pins| base.join(pins)),
            defaults: file.defaults,
            server_requests: file.server_requests,
            unknown_requests: file.unknown_requests,
            secrets: Secrets {
                redact_responses: file.secrets.redact_responses,
                block_in_arguments: file.secrets.block_in_arguments,
                patterns,
            },
            taint: file.taint,
            audit_log: file.audit.path.map_or(default_log, |log| base.join(log)),
            rules,
        })
    }

    /// The most restrictive outcome of every rule matching `tool`.
    pub fn for_tool(&self, tool: &str) -> ToolDecision {
        let mut action: Option<Action> = None;
        let mut decision = ToolDecision {
            action: self.defaults.tools,
            max_argument_bytes: self.defaults.max_argument_bytes,
            no_shell_metacharacters: BTreeSet::new(),
            reads_untrusted: None,
            sends_out: None,
            allow_secrets: false,
            matched: Vec::new(),
        };
        let mut allow_secrets: Option<bool> = None;
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.matcher.is_match(tool.as_bytes()))
        {
            decision.matched.push(rule.pattern.clone());
            if let Some(rule_action) = rule.action {
                action = Some(action.map_or(rule_action, |current| current.max(rule_action)));
            }
            if let Some(limit) = rule.max_argument_bytes {
                decision.max_argument_bytes = decision.max_argument_bytes.min(limit);
            }
            decision
                .no_shell_metacharacters
                .extend(rule.no_shell_metacharacters.iter().cloned());
            // For taint labels "yes" is the strict answer; for secrets, "no".
            decision.reads_untrusted =
                either(decision.reads_untrusted, rule.reads_untrusted, |a, b| {
                    a || b
                });
            decision.sends_out = either(decision.sends_out, rule.sends_out, |a, b| a || b);
            allow_secrets = either(allow_secrets, rule.allow_secrets, |a, b| a && b);
        }
        if let Some(action) = action {
            decision.action = action;
        }
        decision.allow_secrets = allow_secrets.unwrap_or(false);
        decision
    }
}

impl ToolDecision {
    /// Checks a call's arguments against the limits for this tool.
    pub fn check_arguments(&self, arguments: &Value) -> Result<(), ArgumentProblem> {
        let size = serde_json::to_vec(arguments).map_or(usize::MAX, |bytes| bytes.len());
        if size > self.max_argument_bytes {
            return Err(ArgumentProblem::TooLarge {
                size,
                limit: self.max_argument_bytes,
            });
        }
        for argument in &self.no_shell_metacharacters {
            if let Some(value) = arguments.get(argument)
                && let Some(character) = find_metacharacter(value)
            {
                return Err(ArgumentProblem::ShellMetacharacter {
                    argument: argument.clone(),
                    character,
                });
            }
        }
        Ok(())
    }
}

/// Compiles a rule's glob. globset's own matcher would treat the name as a
/// path, and on Windows read `\` (in the glob and in the name) as `/`; its
/// regex, run on the name's bytes, means the same everywhere.
fn tool_matcher(pattern: &str) -> Result<regex::bytes::Regex, PolicyError> {
    let glob = GlobBuilder::new(pattern)
        .backslash_escape(true)
        .literal_separator(false)
        .build()
        .map_err(|source| PolicyError::Pattern {
            pattern: pattern.to_owned(),
            source,
        })?;
    if double_star_next_to_backslash(pattern) {
        return Err(PolicyError::PatternDependsOnPlatform {
            pattern: pattern.to_owned(),
        });
    }
    // As globset compiles it: `*` and `?` match newlines too.
    regex::bytes::RegexBuilder::new(glob.regex())
        .dot_matches_new_line(true)
        .build()
        .map_err(|source| PolicyError::PatternTooComplex {
            pattern: pattern.to_owned(),
            source,
        })
}

/// Whether a glob globset accepted has a `**` right after a `\` (an escaped
/// one, `\\**`) or right before one (`**\*`). Only there does globset ask
/// the platform: it reads `\` as a path separator on Windows, so the glob
/// would mean something else there.
fn double_star_next_to_backslash(glob: &str) -> bool {
    let mut chars = glob.chars().peekable();
    // The character before the current one, as globset sees it.
    let mut previous = None;
    while let Some(c) = chars.next() {
        match c {
            // The escaped character is what comes before what follows.
            '\\' => previous = chars.next(),
            // A class: its characters are literal, `*` and `\` included,
            // and a `]` right after the opening (or `!`, `^`) is one of them.
            '[' => {
                let _ = chars.next_if(|&c| c == '!' || c == '^');
                let _ = chars.next_if_eq(&']');
                for c in chars.by_ref() {
                    if c == ']' {
                        break;
                    }
                }
                previous = Some(']');
            }
            '*' if chars.next_if_eq(&'*').is_some() => {
                if previous == Some('\\') || chars.peek() == Some(&'\\') {
                    return true;
                }
                previous = Some('*');
            }
            c => previous = Some(c),
        }
    }
    false
}

/// The length, in bytes, of the shortest text `pattern` can match (`None`
/// when it can match nothing at all). Empty text counts: `token|`, `[a-z]*`
/// and `\b` can match it.
fn shortest_match(pattern: &str) -> Option<usize> {
    match regex_syntax::parse(pattern) {
        Ok(hir) => hir.properties().minimum_len(),
        // The regex crate parses with this same parser, and accepted it.
        Err(_) => Some(0),
    }
}

/// The first shell metacharacter in any string inside `value`.
fn find_metacharacter(value: &Value) -> Option<char> {
    match value {
        Value::String(text) => text.chars().find(|c| SHELL_METACHARACTERS.contains(c)),
        Value::Array(items) => items.iter().find_map(find_metacharacter),
        Value::Object(map) => map.values().find_map(find_metacharacter),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(text: &str) -> Policy {
        Policy::parse(text, Path::new("/policies")).unwrap()
    }

    #[test]
    fn defaults_are_safe() {
        // A policy starts out only observing; blocking is asked for.
        assert_eq!(policy("mode = \"enforce\"").mode, Mode::Enforce);
        let policy = policy("");
        assert_eq!(policy.mode, Mode::Observe);
        assert_eq!(policy.for_tool("anything").action, Action::Deny);
        assert_eq!(policy.server_requests.sampling, Action::Deny);
        assert_eq!(policy.server_requests.elicitation, Action::Deny);
        assert_eq!(policy.server_requests.roots, Action::Allow);
        assert_eq!(policy.unknown_requests, Action::Deny);
        assert_eq!(policy.pins, None);
        assert!(policy.secrets.redact_responses);
        assert!(policy.secrets.block_in_arguments);
        assert!(policy.taint.resources_are_untrusted);
        let decision = policy.for_tool("anything");
        assert_eq!((decision.reads_untrusted, decision.sends_out), (None, None));
        assert!(!decision.allow_secrets);
    }

    #[test]
    fn taint_labels_and_secret_permission_take_the_strict_answer() {
        let policy = policy(
            r#"
            [[tools]]
            match = "*"
            sends_out = false
            allow_secrets = true

            [[tools]]
            match = "send_*"
            sends_out = true

            [[tools]]
            match = "deploy"
            allow_secrets = true

            [[tools]]
            match = "d*"
            allow_secrets = false
            "#,
        );
        assert_eq!(policy.for_tool("read_file").sends_out, Some(false));
        assert_eq!(policy.for_tool("send_email").sends_out, Some(true));
        assert!(policy.for_tool("read_file").allow_secrets);
        assert!(!policy.for_tool("deploy").allow_secrets);
    }

    #[test]
    fn compiles_custom_secret_patterns_and_rejects_bad_ones() {
        let policy = policy(
            r#"
            [[secrets.patterns]]
            name = "internal-token"
            regex = "itk_[a-z0-9]{16}"
            "#,
        );
        assert_eq!(policy.secrets.patterns[0].0, "internal-token");
        assert!(
            policy.secrets.patterns[0]
                .1
                .is_match("itk_0123456789abcdef")
        );

        let broken = Policy::parse(
            "[[secrets.patterns]]\nname = \"x\"\nregex = \"(\"\n",
            Path::new("."),
        );
        assert!(matches!(broken, Err(PolicyError::SecretPattern { .. })));
    }

    fn secret_pattern(regex: &str) -> Result<Policy, PolicyError> {
        let text = format!(
            "[[secrets.patterns]]\nname = \"typo\"\nregex = {}\n",
            toml::Value::String(regex.to_owned())
        );
        Policy::parse(&text, Path::new("."))
    }

    #[test]
    fn rejects_secret_patterns_that_match_empty_text() {
        for regex in [
            "token|",
            "[a-z]*",
            r"\S*",
            "[A-Z0-9]{0,40}",
            r"\b",
            r"\b[a-z]*\b",
            "(?m)^",
        ] {
            assert!(
                matches!(
                    secret_pattern(regex),
                    Err(PolicyError::SecretPatternTooShort { shortest: 0, .. })
                ),
                "accepted {regex}"
            );
        }
    }

    #[test]
    fn rejects_secret_patterns_that_match_very_short_text() {
        // A count forgotten, or a single character: a marker would replace
        // every letter of every message.
        for regex in [
            "[A-Za-z0-9]",
            "[a-z]",
            "x",
            r"\w",
            r"(?i)k",
            "ab12",
            r"\d{4}",
            r"\bpin\b",
            "é",
        ] {
            assert!(
                matches!(
                    secret_pattern(regex),
                    Err(PolicyError::SecretPatternTooShort { .. })
                ),
                "accepted {regex}"
            );
        }
        for regex in [r"\d{6}", "itk_[a-z0-9]{32}", "[A-Za-z0-9]{40}", "[^\\s\\S]"] {
            assert!(secret_pattern(regex).is_ok(), "refused {regex}");
        }
    }

    #[test]
    fn tool_globs_mean_the_same_on_every_platform() {
        let policy = policy(
            r#"
            [[tools]]
            match = 'run\*'
            action = "allow"

            [[tools]]
            match = "admin/*"
            action = "deny"

            [[tools]]
            match = "Echo"
            action = "allow"
            "#,
        );
        assert_eq!(policy.for_tool("run*").matched, [r"run\*"]);
        assert!(policy.for_tool("runx").matched.is_empty());
        assert_eq!(policy.for_tool("admin/x/y").matched, ["admin/*"]);
        assert!(policy.for_tool(r"admin\x").matched.is_empty());
        assert!(policy.for_tool("echo").matched.is_empty(), "case-sensitive");
    }

    #[test]
    fn refuses_a_double_star_next_to_a_backslash() {
        // On Windows globset reads that `\` as a path separator: `**\*`
        // would match every tool there, but only names ending in `*`
        // elsewhere.
        for pattern in [r"**\*", r"files/**\*", r"a\\**", r"**\a", r"{x,**\*}"] {
            let text = format!(
                "[[tools]]\nmatch = {}\naction = \"allow\"\n",
                toml::Value::String(pattern.to_owned())
            );
            assert!(
                matches!(
                    Policy::parse(&text, Path::new(".")),
                    Err(PolicyError::PatternDependsOnPlatform { .. })
                ),
                "accepted {pattern}"
            );
        }
        // An escaped star before a star, a class holding `\`, and `**`
        // away from any `\` mean the same everywhere.
        let policy = policy(
            r#"
            [[tools]]
            match = 'run\**'
            action = "allow"

            [[tools]]
            match = '[\]**'
            action = "allow"

            [[tools]]
            match = 'a\\*'
            action = "allow"

            [[tools]]
            match = 'x/**'
            action = "allow"
            "#,
        );
        assert_eq!(policy.for_tool("run*now").matched, [r"run\**"]);
        assert_eq!(policy.for_tool(r"\tool").matched, [r"[\]**"]);
        assert_eq!(policy.for_tool(r"a\b").matched, [r"a\\*"]);
        assert_eq!(policy.for_tool("x/y/z").matched, ["x/**"]);
    }

    #[test]
    fn resolves_pins_next_to_the_policy() {
        let policy = policy("pins = \"server.pins.toml\"");
        assert_eq!(
            policy.pins,
            Some(PathBuf::from("/policies/server.pins.toml"))
        );
    }

    #[test]
    fn the_example_policy_is_valid() {
        let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/example.toml");
        let policy = Policy::load(&example).unwrap();
        assert!(policy.audit_log.ends_with("logs/everything.audit.jsonl"));
    }

    #[test]
    fn the_audit_log_goes_next_to_the_policy_unless_it_names_one() {
        let dir = std::env::temp_dir().join(format!("mcp-mandate-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("server.policy.toml");
        std::fs::write(&file, "").unwrap();
        assert_eq!(
            Policy::load(&file).unwrap().audit_log,
            dir.join("server.policy.audit.jsonl")
        );
        std::fs::write(&file, "[audit]\npath = \"logs/audit.jsonl\"\n").unwrap();
        assert_eq!(
            Policy::load(&file).unwrap().audit_log,
            dir.join("logs/audit.jsonl")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_text_already_read_as_if_loaded_from_its_file() {
        let file = Path::new("/policies/server.policy.toml");
        let policy = Policy::parse_file("pins = \"server.pins.toml\"", file).unwrap();
        assert_eq!(
            policy.pins,
            Some(PathBuf::from("/policies/server.pins.toml"))
        );
        assert_eq!(
            policy.audit_log,
            PathBuf::from("/policies/server.policy.audit.jsonl")
        );
        let Err(error) = Policy::parse_file("mode = ", file) else {
            panic!("expected a parse error");
        };
        assert!(error.to_string().contains("server.policy.toml"), "{error}");
    }

    #[test]
    fn the_most_restrictive_matching_rule_wins_whatever_the_order() {
        let policy = policy(
            r#"
            [[tools]]
            match = "*"
            action = "allow"

            [[tools]]
            match = "delete_*"
            action = "deny"

            [[tools]]
            match = "write_*"
            action = "hold"
            "#,
        );
        assert_eq!(policy.for_tool("read_file").action, Action::Allow);
        assert_eq!(policy.for_tool("write_file").action, Action::Hold);
        assert_eq!(policy.for_tool("delete_repo").action, Action::Deny);
    }

    #[test]
    fn rejects_typos_instead_of_ignoring_them() {
        let typo = Policy::parse(
            "[[tools]]\nmatch = \"x\"\nacton = \"deny\"\n",
            Path::new("."),
        );
        assert!(matches!(typo, Err(PolicyError::Parse { .. })));
        let bad_value = Policy::parse("mode = \"enforcing\"", Path::new("."));
        assert!(matches!(bad_value, Err(PolicyError::Parse { .. })));
    }

    #[test]
    fn checks_argument_size_and_shell_metacharacters() {
        let policy = policy(
            r#"
            [[tools]]
            match = "run_command"
            action = "allow"
            max_argument_bytes = 40
            no_shell_metacharacters = ["command"]
            "#,
        );
        let decision = policy.for_tool("run_command");

        assert_eq!(
            decision.check_arguments(&json!({"command": "ls -la"})),
            Ok(())
        );
        assert_eq!(
            decision.check_arguments(&json!({"command": "ls; curl evil.example"})),
            Err(ArgumentProblem::ShellMetacharacter {
                argument: "command".to_owned(),
                character: ';'
            })
        );
        assert_eq!(
            decision.check_arguments(&json!({"command": ["ls", "$(id)"]})),
            Err(ArgumentProblem::ShellMetacharacter {
                argument: "command".to_owned(),
                character: '$'
            })
        );
        assert!(matches!(
            decision.check_arguments(&json!({"command": "x".repeat(100)})),
            Err(ArgumentProblem::TooLarge { limit: 40, .. })
        ));
    }
}

#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn any_text_parses_or_fails_without_panicking(text in r"\PC{0,256}") {
            let _ = Policy::parse(&text, Path::new("."));
        }

        #[test]
        fn any_tool_name_gets_a_decision(name in r"\PC{0,64}", pattern in r"[a-z*?_\[\]{},-]{0,16}") {
            let text = format!("[[tools]]\nmatch = {}\naction = \"allow\"\n", toml::Value::String(pattern));
            if let Ok(policy) = Policy::parse(&text, Path::new(".")) {
                let _ = policy.for_tool(&name);
            }
        }
    }
}
