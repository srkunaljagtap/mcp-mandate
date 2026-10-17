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
//! [server_requests]
//! sampling = "deny"
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
}

fn deny() -> Action {
    Action::Deny
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
}

struct ToolRule {
    pattern: String,
    matcher: GlobMatcher,
    action: Option<Action>,
    max_argument_bytes: Option<usize>,
    no_shell_metacharacters: Vec<String>,
}

/// A loaded, checked policy.
pub struct Policy {
    pub mode: Mode,
    /// The pins file, resolved against the policy file's folder.
    pub pins: Option<PathBuf>,
    pub defaults: Defaults,
    pub server_requests: ServerRequests,
    pub unknown_requests: Action,
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
}

/// What the policy says about one tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDecision {
    pub action: Action,
    pub max_argument_bytes: usize,
    /// Arguments whose string values may not contain shell metacharacters.
    pub no_shell_metacharacters: BTreeSet<String>,
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
        Self::parse(&text, base).map_err(|error| match error {
            PolicyError::Parse { source, .. } => PolicyError::Parse {
                path: path.to_owned(),
                source,
            },
            other => other,
        })
    }

    /// Parses policy text; a relative `pins` path is resolved against `base`.
    pub fn parse(text: &str, base: &Path) -> Result<Self, PolicyError> {
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
                })
            })
            .collect::<Result<_, PolicyError>>()?;
        Ok(Self {
            mode: file.mode,
            pins: file.pins.map(|pins| base.join(pins)),
            defaults: file.defaults,
            server_requests: file.server_requests,
            unknown_requests: file.unknown_requests,
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
            matched: Vec::new(),
        };
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
        }
        if let Some(action) = action {
            decision.action = action;
        }
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
