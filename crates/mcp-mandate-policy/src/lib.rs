//! The policy file: what a session may do, written by people.
//!
//! ```toml
//! mode = "enforce"               # or "observe": log what would be blocked
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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobMatcher};
use serde::Deserialize;
use serde_json::Value;

/// Default cap on a tool call's arguments, as JSON.
pub const DEFAULT_MAX_ARGUMENT_BYTES: usize = 64 * 1024;

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
    #[default]
    Enforce,
    /// Log what would be blocked, but let everything through.
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
    matcher: GlobMatcher,
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
    #[error("secret pattern `{name}` isn't a valid regular expression")]
    SecretPattern {
        name: String,
        #[source]
        source: regex::Error,
    },
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
        let base = path.parent().unwrap_or(Path::new("."));
        Self::parse_with(&text, base, default_audit_log(path)).map_err(|error| match error {
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
                let matcher = Glob::new(&rule.pattern)
                    .map_err(|source| PolicyError::Pattern {
                        pattern: rule.pattern.clone(),
                        source,
                    })?
                    .compile_matcher();
                Ok(ToolRule {
                    pattern: rule.pattern,
                    matcher,
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
        for rule in self.rules.iter().filter(|rule| rule.matcher.is_match(tool)) {
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
        let policy = policy("");
        assert_eq!(policy.mode, Mode::Enforce);
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
