//! What a tool can do, as far as taint tracking is concerned.

use serde_json::Value;

/// Whether a tool can bring untrusted content in and data out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Traits {
    /// Its output may carry outside content, and so hidden instructions.
    pub reads_untrusted: bool,
    /// It can carry data out of the session. Even a read can: a URL fetch
    /// can leak data in its query string.
    pub sends_out: bool,
}

/// What a policy says about a tool; `None` means it doesn't say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Labels {
    pub reads_untrusted: Option<bool>,
    pub sends_out: Option<bool>,
}

impl Traits {
    /// Policy labels first; otherwise the tool's own MCP annotations, which
    /// were fixed when it was pinned. A tool that "interacts with the open
    /// world" (`openWorldHint`) can both bring content in and send data
    /// out. MCP defaults that hint to true, so a tool that says nothing
    /// counts as both: the strict side wins.
    pub fn of(tool: &Value, labels: Labels) -> Self {
        let open_world = tool
            .pointer("/annotations/openWorldHint")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        Self {
            reads_untrusted: labels.reads_untrusted.unwrap_or(open_world),
            sends_out: labels.sends_out.unwrap_or(open_world),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_tool_that_says_nothing_counts_as_both() {
        let traits = Traits::of(&json!({"name": "fetch"}), Labels::default());
        assert_eq!(
            traits,
            Traits {
                reads_untrusted: true,
                sends_out: true
            }
        );
    }

    #[test]
    fn a_closed_world_tool_counts_as_neither() {
        let tool = json!({"name": "add", "annotations": {"openWorldHint": false}});
        assert_eq!(
            Traits::of(&tool, Labels::default()),
            Traits {
                reads_untrusted: false,
                sends_out: false
            }
        );
    }

    #[test]
    fn policy_labels_override_annotations() {
        let tool = json!({"name": "send_email", "annotations": {"openWorldHint": false}});
        let labels = Labels {
            reads_untrusted: None,
            sends_out: Some(true),
        };
        assert_eq!(
            Traits::of(&tool, labels),
            Traits {
                reads_untrusted: false,
                sends_out: true
            }
        );
    }
}
