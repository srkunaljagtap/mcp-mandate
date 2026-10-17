//! Scout reviews MCP servers before you trust them: a rule-based scan of
//! everything they show the model, an optional review by Claude with your
//! own API key, and a draft policy for you to approve. Scout only proposes;
//! the gate decides.
//!
//! The draft is built by risk: read-only, closed-world tools are allowed,
//! tools that can change things or reach the outside world are held, and
//! flagged tools are denied. Claude's review can only make the draft
//! stricter, never looser, because the descriptions it reads were written
//! by the server and may try to talk it into "this is safe".

mod draft;
mod report;
mod rules;
mod text;

#[cfg(feature = "llm")]
pub mod claude;
#[cfg(feature = "llm")]
mod review;

pub use draft::{Draft, ToolPlan, plan_tools};
pub use report::render;
pub use rules::{compare_with_pins, scan};
pub use text::printable;

#[cfg(feature = "llm")]
pub use review::{MODEL, Review, ReviewError, review};

use mcp_mandate_pin::Kind;

/// What a finding is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subject {
    /// The server's instructions to the model.
    Instructions,
    /// A tool, prompt, resource or resource template, by name (or URI).
    Item(Kind, String),
}

impl Subject {
    pub fn tool(name: &str) -> Self {
        Self::Item(Kind::Tool, name.to_owned())
    }
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Instructions => write!(f, "the server's instructions"),
            Self::Item(kind, name) => write!(f, "{} `{}`", kind.noun(), printable(name, 80)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Worth knowing; doesn't change the draft.
    Low,
    /// The draft holds the tool.
    Medium,
    /// The draft denies the tool.
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Something Scout noticed about a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub subject: Subject,
    pub severity: Severity,
    /// Which check found it, e.g. `hidden-instructions` or `claude-review`.
    pub check: &'static str,
    /// What was found. May quote server text, so print it with
    /// [`printable`].
    pub detail: String,
}

/// Every kind of item a server lists.
const KINDS: [Kind; 4] = [
    Kind::Tool,
    Kind::Prompt,
    Kind::Resource,
    Kind::ResourceTemplate,
];
