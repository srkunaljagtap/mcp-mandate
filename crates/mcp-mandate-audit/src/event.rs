//! What an audit entry records.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One decision, or the start or end of a session. Which fields are set
/// depends on `event`; unset ones are left out of the line.
///
/// No message content is recorded: arguments and messages appear only as
/// SHA-256 hashes, so a payload you still have can be matched to its entry,
/// but the log can't be read back for what was said. (A short, guessable
/// value can still be recovered from its hash by trying every candidate.)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Event {
    pub event: EventKind,

    // A message crossing the gate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Origin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<MessageKind>,
    /// The JSON-RPC method; for a response, its request's method when the
    /// gate tracked it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// The tool, prompt or resource the message is about (for an
    /// `initialize` response, the server's name and version).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    /// In observe mode, what enforce mode would have done instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub would: Option<Verdict>,
    /// Why the message was blocked or dropped (or would have been).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What the gate changed in the message (or would have changed).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
    /// Set when this message tainted the session: what it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint: Option<String>,
    /// The message as received, without its line ending.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The message as forwarded, when the gate changed it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarded_sha256: Option<String>,
    /// A tool call's or prompt request's arguments, as canonical JSON (keys
    /// sorted, no whitespace).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_sha256: Option<String>,

    // The start of a session.
    /// The mcp-mandate version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// The policy file, as given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Hashes of the policy file's and the pins file's bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pins_sha256: Option<String>,
    /// The server's program name. Its arguments can carry tokens, so the
    /// full command appears only as a hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    // The end of a session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventKind {
    SessionStart,
    #[default]
    Message,
    SessionEnd,
}

/// Which side sent a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageKind {
    Request,
    Response,
    Notification,
    Batch,
    /// Not a JSON-RPC message.
    Invalid,
}

/// What happened to a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Forwarded unchanged.
    Allow,
    /// Forwarded with changes (items hidden, secrets redacted).
    Modify,
    /// Answered by the gate with an error instead of being forwarded.
    Block,
    /// Not forwarded, and nothing answered.
    Drop,
}
