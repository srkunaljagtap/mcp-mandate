//! The gate: decides what crosses between an MCP client and an MCP server.
//!
//! It takes one complete JSON-RPC message at a time and says where it goes,
//! so every transport (stdio today, HTTPS later) shares exactly the same
//! checks. Its only I/O is recording each decision through the audit
//! [`Recorder`] it's given.
//!
//! - Client to server: calls and reads (`tools/call`, `prompts/get`,
//!   `resources/read`) pass only for items that are pinned, were listed and
//!   matched their pin in this session, and that the policy allows.
//! - Server to client: lists are filtered down to approved items, the
//!   server's instructions are removed unless approved, and requests the
//!   server makes (sampling, elicitation) follow the policy.
//! - Taint: once a tool that reads untrusted content (or a resource) has
//!   answered, the session is tainted and tools that can send data out are
//!   held for the rest of the session, in every session of the same agent.
//!   An answer whose taint can't be shared with those doesn't pass.
//! - Secrets: redacted from everything the server sends (keys included),
//!   and blocked in what the client sends: tool and prompt arguments and
//!   resource URIs.
//! - Protocol: a response must answer a request the client is still
//!   waiting for, and a message the gate can't read in full doesn't pass
//!   (one too large to check that is a request, or the answer to one, is
//!   answered with an error, so nobody waits for it).
//!
//! - Audit: every message gets an entry (what it was, what the gate did and
//!   why, and hashes, never content). A message whose entry can't be
//!   written doesn't pass.
//!
//! In observe mode every decision is logged but nothing is blocked, hidden
//! or redacted.

pub mod jsonrpc;
mod template;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mcp_mandate_audit::{self as audit, MessageKind, Origin, Recorder};
use mcp_mandate_pin::{Kind, Pins, Verdict, fingerprint};
use mcp_mandate_policy::{Action as Rule, Mode, Policy};
use mcp_mandate_taint::{Labels, SecretDetector, SecretPattern, Traits};
use serde_json::{Value, json};
use tracing::{debug, error, info, warn};

use crate::jsonrpc::{Message, ParseError, classify};
use crate::template::{Misfit, Template};

/// JSON-RPC error code for requests the gate blocks (from the range
/// JSON-RPC leaves to implementations).
pub const BLOCKED_ERROR_CODE: i64 = -32000;

/// Most client requests waiting for a server response that the gate tracks.
const MAX_PENDING: usize = 4096;

/// Limits on what one audit entry holds, since either side can send
/// arbitrarily long names.
const MAX_NAME: usize = 256;
const MAX_REASON: usize = 1024;
const MAX_CHANGES: usize = 50;
const MAX_ID_BYTES: usize = 128;

/// Where a message goes after the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Write these bytes to the server.
    ToServer(Vec<u8>),
    /// Write these bytes to the client.
    ToClient(Vec<u8>),
}

/// How a blocked client request is answered.
#[derive(Clone, Copy)]
enum Reply {
    /// A tool result marked as an error, so the model reads why.
    ToolError,
    /// A JSON-RPC error.
    Error,
}

/// Why a request is blocked. The `detail` goes to the client only, never to
/// the audit log, because it can quote the arguments.
struct Refusal {
    reason: String,
    detail: Option<String>,
}

impl From<String> for Refusal {
    fn from(reason: String) -> Self {
        Self {
            reason,
            detail: None,
        }
    }
}

/// Taint shared by every gate serving the same agent, so reading untrusted
/// content through one server holds sending through all of them (each
/// server normally has its own gate).
pub trait SharedTaint: Send + Sync {
    /// What tainted the agent's sessions, if anything has. It may go on
    /// reporting a taint it has seen after the record itself is gone, so
    /// holds don't lapse.
    fn get(&self) -> Option<String>;
    /// Records that `source` tainted them. Returns whether it could: if
    /// not, the gate doesn't pass the answer that tainted its session
    /// (except in observe mode), since the other sessions wouldn't hold
    /// their tools.
    fn set(&self, source: &str) -> bool;
    /// Makes sure the record is still where the other sessions read it,
    /// putting `source` back if something removed it. Returns whether it's
    /// there: if not, the gate treats its taint as unshared again. A
    /// tainted gate asks while messages pass (at most once a second).
    fn reshare(&self, source: &str) -> bool {
        self.get().is_some() || self.set(source)
    }
}

/// How often, at most, a tainted gate checks that its taint is still where
/// the agent's other gates read it.
const TAINT_CHECK: Duration = Duration::from_secs(1);

/// One session's gate.
pub struct Gate {
    policy: Policy,
    pins: Option<Pins>,
    secrets: SecretDetector,
    /// Client requests whose responses the gate inspects, by id.
    pending: HashMap<String, Pending>,
    /// Server requests passed to the client, by id, with their method.
    server_pending: HashMap<String, String>,
    session: Session,
    shared_taint: Option<Arc<dyn SharedTaint>>,
    /// Whether the agent's other sessions were told this one is tainted.
    taint_shared: bool,
    /// When this gate last checked that they still can see it.
    taint_checked: Option<Instant>,
    audit: Box<dyn Recorder>,
    /// The audit entry for the message being checked.
    event: audit::Event,
    /// Changes to it beyond [`MAX_CHANGES`], counted rather than listed.
    more_changes: usize,
}

/// A client request whose response the gate inspects.
enum Pending {
    /// `initialize` or a list, checked against the pins.
    List(String),
    /// A tool call, whose output may taint the session.
    ToolCall(String),
    /// A resource read, whose content may taint the session.
    ResourceRead,
    /// A prompt, whose messages may taint the session.
    PromptGet,
    /// Any other request: its response only needs to be expected.
    Other(String),
}

/// An approved tool.
struct ToolInfo {
    /// Its compiled input schema (`None` when it can't be compiled, e.g. it
    /// needs a remote `$ref`).
    validator: Option<jsonschema::Validator>,
    traits: Traits,
}

/// What this session has checked against the pins, and whether it's tainted.
#[derive(Default)]
struct Session {
    tools: HashMap<String, ToolInfo>,
    prompts: HashSet<String>,
    resources: HashSet<String>,
    /// Approved resource templates, ready to match URIs.
    templates: HashMap<String, Template>,
    /// Items whose content no longer matches their pin.
    changed: HashSet<(Kind, String)>,
    /// What tainted the session, once something has. It stays tainted.
    taint: Option<String>,
}

impl Session {
    fn approve(&mut self, kind: Kind, name: &str, item: &Value, labels: Labels) {
        self.changed.remove(&(kind, name.to_owned()));
        match kind {
            Kind::Tool => {
                let schema = item
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or_else(|| json!({"type": "object"}));
                let info = ToolInfo {
                    validator: validator(&schema),
                    traits: Traits::of(item, labels),
                };
                self.tools.insert(name.to_owned(), info);
            }
            Kind::Prompt => {
                self.prompts.insert(name.to_owned());
            }
            Kind::Resource => {
                self.resources.insert(name.to_owned());
            }
            Kind::ResourceTemplate => {
                self.templates
                    .insert(name.to_owned(), Template::parse(name));
            }
        }
    }

    fn quarantine(&mut self, kind: Kind, name: &str) {
        match kind {
            Kind::Tool => {
                self.tools.remove(name);
            }
            Kind::Prompt => {
                self.prompts.remove(name);
            }
            Kind::Resource => {
                self.resources.remove(name);
            }
            Kind::ResourceTemplate => {
                self.templates.remove(name);
            }
        }
        self.changed.insert((kind, name.to_owned()));
    }

    /// Whether `uri` names an approved resource or fits an approved
    /// template. If it has a template's shape but still doesn't fit, says
    /// why, so the model can write it again rather than give up.
    fn resource_allowed(&self, uri: &str) -> Result<(), Option<String>> {
        if self.resources.contains(uri) {
            return Ok(());
        }
        let mut closest: Option<(&String, Misfit)> = None;
        for (name, template) in &self.templates {
            match template.check(uri) {
                Ok(()) => return Ok(()),
                Err(Misfit::Shape) => {}
                // The first template by name, so the answer is the same
                // every time.
                Err(misfit) if closest.is_none_or(|(first, _)| name < first) => {
                    closest = Some((name, misfit));
                }
                Err(_) => {}
            }
        }
        Err(closest.map(|(name, misfit)| {
            format!(
                "resource URI `{uri}` fits template `{name}`, but {}",
                misfit.describe()
            )
        }))
    }
}

/// A tool's input schema compiled for checking, with `pattern` keywords run
/// by a linear-time regex engine (a backtracking one could be made to spin
/// by a crafted schema). `None` when it can't be compiled.
fn validator(schema: &Value) -> Option<jsonschema::Validator> {
    jsonschema::options()
        .with_pattern_options(jsonschema::PatternOptions::regex())
        .build(schema)
        .ok()
}

impl Gate {
    /// A gate enforcing `policy` and recording every decision to `audit`.
    /// Without `pins`, nothing a server offers is approved.
    pub fn new(policy: Policy, pins: Option<Pins>, audit: Box<dyn Recorder>) -> Self {
        let custom = policy
            .secrets
            .patterns
            .iter()
            .map(|(name, regex)| SecretPattern {
                name: name.clone(),
                regex: regex.clone(),
            })
            .collect();
        Self {
            secrets: SecretDetector::new(custom),
            policy,
            pins,
            pending: HashMap::new(),
            server_pending: HashMap::new(),
            session: Session::default(),
            shared_taint: None,
            taint_shared: false,
            taint_checked: None,
            audit,
            event: audit::Event::default(),
            more_changes: 0,
        }
    }

    /// Shares taint with the other gates serving the same agent.
    pub fn with_shared_taint(mut self, shared: Arc<dyn SharedTaint>) -> Self {
        self.shared_taint = Some(shared);
        self
    }

    /// Adds exact strings to treat as secrets, such as the credential the
    /// gateway itself uses for this server: redacted if the server echoes
    /// them, blocked if the client sends them. Strings shorter than 8
    /// characters are ignored (they'd match ordinary text).
    pub fn add_secret_literals<I: IntoIterator<Item = String>>(&mut self, literals: I) {
        for literal in literals {
            self.secrets.add_literal("gateway-credential", &literal);
        }
    }

    /// Like [`add_secret_literals`](Self::add_secret_literals), but
    /// replacing every exact string added or set before: for a credential
    /// that's renewed, so expired tokens don't pile up. Cheap when the
    /// strings haven't changed, so it can run before every message.
    pub fn set_secret_literals(&mut self, literals: &[String]) {
        self.secrets.set_literals("gateway-credential", literals);
    }

    /// Forgets a client request that will never be answered through the
    /// gate (its transport failed), so it doesn't stay pending forever.
    pub fn abandon(&mut self, id: &Value) {
        self.pending.remove(&id_key(id));
    }

    /// What tainted the session, if anything has: here, or through another
    /// gate serving the same agent.
    pub fn taint(&self) -> Option<String> {
        self.session
            .taint
            .clone()
            .or_else(|| self.shared_taint.as_ref().and_then(|shared| shared.get()))
    }

    pub fn mode(&self) -> Mode {
        self.policy.mode
    }

    /// Decides what happens to one message from the client, and records it.
    pub fn from_client(&mut self, frame: &[u8]) -> Vec<Action> {
        self.keep_taint_shared();
        let message = classify(frame);
        self.begin(Origin::Client, frame, &message);
        let actions = match message {
            Ok(Message::Request { id, method }) => {
                let refusal = if self.pending.contains_key(&id_key(&id)) {
                    // Reusing an id still in flight would make the gate
                    // attribute one request's answer to the other.
                    Some("a request with this id is still waiting for its answer")
                } else if self.pending.len() >= MAX_PENDING {
                    Some("too many requests are waiting for the server")
                } else {
                    None
                };
                if let Some(reason) = refusal {
                    let reply = reply_for(&method);
                    let actions = self.block_client(frame, &id, &method, reason.to_owned(), reply);
                    return self.record(Origin::Client, frame, actions);
                }
                let actions = self.client_request(frame, &id, &method);
                // Every request that reaches the server is expected to be
                // answered once; any other response is dropped.
                if forwards_to_server(&actions) {
                    self.pending
                        .entry(id_key(&id))
                        .or_insert(Pending::Other(method));
                }
                actions
            }
            Ok(Message::Notification { method }) => {
                if method == "notifications/cancelled"
                    && let Some(id) = params(frame).get("requestId")
                {
                    self.pending.remove(&id_key(id));
                }
                to_server(frame)
            }
            Ok(Message::Response { id, .. }) => self.client_response(frame, &id),
            Ok(Message::Batch { len }) => self.batch(len, Action::ToServer(frame.to_vec())),
            Err(ParseError::Empty) => return Vec::new(),
            Err(error) => self.unreadable(&error, Origin::Client, frame),
        };
        self.record(Origin::Client, frame, actions)
    }

    /// The client's answer to a server request. It must answer a request
    /// the gate passed on, and an answer to a sampling or elicitation
    /// request (the model's or the user's words) mustn't carry a secret.
    fn client_response(&mut self, frame: &[u8], id: &Value) -> Vec<Action> {
        let Some(method) = self.server_pending.remove(&id_key(id)) else {
            self.note_block(
                "an answer to no request the server is waiting for",
                audit::Verdict::Drop,
            );
            if self.observe() {
                return to_server(frame);
            }
            warn!("dropped a client answer to no request the server is waiting for");
            return Vec::new();
        };
        self.event.method = Some(self.audit_text(&method, MAX_NAME));
        let carries_words = matches!(
            method.as_str(),
            "sampling/createMessage" | "elicitation/create"
        );
        let reason = if carries_words {
            match serde_json::from_slice::<Value>(frame) {
                Ok(message) => self.secret_in(&message).map(|kind| {
                    format!(
                        "the answer to the server's `{method}` request contains what looks like a secret ({kind})"
                    )
                }),
                Err(_) => Some(format!(
                    "the answer to the server's `{method}` request can't be read in full, so it can't be checked"
                )),
            }
        } else {
            None
        };
        let Some(reason) = reason else {
            return to_server(frame);
        };
        self.note_block(&reason, audit::Verdict::Block);
        if self.observe() {
            warn!(%reason, "would block (observe mode)");
            return to_server(frame);
        }
        warn!(%reason, "blocked");
        // The gate answers the server in the client's place: recorded as a
        // block, not as a changed answer.
        self.event.verdict = Some(audit::Verdict::Block);
        let text = format!("Blocked by mcp-mandate: {reason}");
        vec![Action::ToServer(encode(&rpc_error(id, &text)))]
    }

    /// Decides what happens to one message from the server, and records it.
    pub fn from_server(&mut self, frame: &[u8]) -> Vec<Action> {
        self.keep_taint_shared();
        let message = classify(frame);
        self.begin(Origin::Server, frame, &message);
        let actions = match message {
            Ok(Message::Response { id, .. }) => match self.pending.remove(&id_key(&id)) {
                Some(pending) => self.server_response(frame, Some(pending)),
                None => self.unexpected_response(frame),
            },
            Ok(Message::Request { id, method }) => {
                let refusal = if self.server_pending.contains_key(&id_key(&id)) {
                    // Reusing an id still in flight would make the gate
                    // check the client's answer to one request as the
                    // answer to the other.
                    Some("a request with this id is still waiting for its answer")
                } else if self.server_pending.len() >= MAX_PENDING {
                    Some("too many of its requests are waiting for the client")
                } else {
                    None
                };
                if let Some(reason) = refusal {
                    // Not tracked, even when observe mode passes it on.
                    let actions = self.block_server(frame, &id, &method, reason.to_owned());
                    return self.record(Origin::Server, frame, actions);
                }
                let actions = self.server_request(frame, &id, &method);
                if matches!(actions.as_slice(), [Action::ToClient(_)]) {
                    self.server_pending.insert(id_key(&id), method);
                }
                actions
            }
            Ok(Message::Notification { method }) => {
                // The client doesn't answer a request the server cancelled.
                if method == "notifications/cancelled"
                    && let Some(id) = params(frame).get("requestId")
                {
                    self.server_pending.remove(&id_key(id));
                }
                if method.ends_with("/list_changed") {
                    info!(%method, "the server says a list changed; the new list will be checked against the pins");
                }
                self.server_response(frame, None)
            }
            Ok(Message::Batch { len }) => self.batch(len, Action::ToClient(frame.to_vec())),
            Err(ParseError::Empty) => return Vec::new(),
            Err(error) => self.unreadable(&error, Origin::Server, frame),
        };
        self.record(Origin::Server, frame, actions)
    }

    /// Records the end of the session, with the code mcp-mandate exits with
    /// when it ended normally.
    pub fn end_session(&mut self, exit_code: Option<i32>) {
        let event = audit::Event {
            event: audit::EventKind::SessionEnd,
            exit_code,
            ..audit::Event::default()
        };
        if let Err(error) = self.audit.record(&event) {
            warn!(error = %describe(&error), "couldn't record the end of the session in the audit log");
        }
    }

    fn observe(&self) -> bool {
        self.policy.mode == Mode::Observe
    }

    /// Starts the audit entry for a message.
    fn begin(&mut self, from: Origin, frame: &[u8], message: &Result<Message, ParseError>) {
        let (kind, method, id) = match message {
            Ok(Message::Request { id, method }) => (MessageKind::Request, Some(method), Some(id)),
            Ok(Message::Notification { method }) => (MessageKind::Notification, Some(method), None),
            Ok(Message::Response { id, .. }) => (MessageKind::Response, None, Some(id)),
            Ok(Message::Batch { .. }) => (MessageKind::Batch, None, None),
            Err(_) => (MessageKind::Invalid, None, None),
        };
        self.more_changes = 0;
        self.event = audit::Event {
            from: Some(from),
            kind: Some(kind),
            method: method.map(|method| self.audit_text(method, MAX_NAME)),
            id: id.map(|id| self.audit_id(id)),
            sha256: Some(audit::sha256_hex(without_line_ending(frame))),
            ..audit::Event::default()
        };
    }

    /// `text` for the audit log: secrets redacted, then cut to `max` bytes.
    /// In that order, so a cut can't leave the start of a secret too short
    /// to be recognized.
    fn audit_text(&self, text: &str, max: usize) -> String {
        match self.secrets.redact_text(text) {
            Some((redacted, _)) => clip(&redacted, max),
            None => clip(text, max),
        }
    }

    /// A request id for the audit log: a very long one is replaced by its
    /// hash, and secrets in a string one are redacted.
    fn audit_id(&self, id: &Value) -> Value {
        let text = id.to_string();
        if text.len() > MAX_ID_BYTES {
            return Value::String(format!("sha256:{}", audit::sha256_hex(text.as_bytes())));
        }
        match id.as_str().and_then(|id| self.secrets.redact_text(id)) {
            Some((redacted, _)) => Value::String(redacted),
            None => id.clone(),
        }
    }

    /// Records what happened to `frame`. A message that can't be recorded
    /// doesn't pass (in observe mode, it passes with a warning).
    fn record(&mut self, from: Origin, frame: &[u8], actions: Vec<Action>) -> Vec<Action> {
        let mut event = std::mem::take(&mut self.event);
        // Judged by where the message went, unless the gate already said
        // what it did.
        let (verdict, forwarded) = match event.verdict {
            Some(verdict) => (verdict, None),
            None => judge(from, frame, &actions),
        };
        event.verdict = Some(verdict);
        event.forwarded_sha256 =
            forwarded.map(|bytes| audit::sha256_hex(without_line_ending(bytes)));
        if self.more_changes > 0 {
            event
                .changes
                .push(format!("and {} more", self.more_changes));
        }
        // Names, URIs and reasons can quote what was blocked: a secret that
        // got a request blocked mustn't end up in the log. (They're redacted
        // when set; this catches anything set some other way.)
        for text in event
            .item
            .iter_mut()
            .chain(event.reason.iter_mut())
            .chain(event.changes.iter_mut())
        {
            if let Some((redacted, _)) = self.secrets.redact_text(text) {
                *text = redacted;
            }
        }
        let Err(failure) = self.audit.record(&event) else {
            return actions;
        };
        let failure = describe(&failure);
        if self.observe() {
            warn!(error = %failure, "couldn't record a decision in the audit log; letting it through (observe mode)");
            return actions;
        }
        error!(error = %failure, "couldn't record a decision in the audit log, so the message doesn't pass; nothing will until the log can be written");
        let forwarded = matches!(
            (from, actions.as_slice()),
            (Origin::Client, [Action::ToServer(_)]) | (Origin::Server, [Action::ToClient(_)])
        );
        self.unrecorded(from, frame, event.method.as_deref(), forwarded)
    }

    /// Fails closed for a message the audit log couldn't take: answers a
    /// request with an error, so nobody waits for it, and drops anything
    /// else. A request that was to be `forwarded` stops waiting for its
    /// answer; one that wasn't never started (its id may be another
    /// request's, which still waits).
    fn unrecorded(
        &mut self,
        from: Origin,
        frame: &[u8],
        method: Option<&str>,
        forwarded: bool,
    ) -> Vec<Action> {
        let text = "Blocked by mcp-mandate: the audit log can't be written, so nothing passes until it can";
        match (from, classify(frame)) {
            (Origin::Client, Ok(Message::Request { id, method })) => {
                if forwarded {
                    self.pending.remove(&id_key(&id));
                }
                vec![Action::ToClient(encode(&blocked_reply(
                    &id,
                    text,
                    reply_for(&method),
                )))]
            }
            (Origin::Server, Ok(Message::Response { id, .. })) => {
                let reply = reply_for(method.unwrap_or_default());
                vec![Action::ToClient(encode(&blocked_reply(&id, text, reply)))]
            }
            (Origin::Server, Ok(Message::Request { id, .. })) => {
                // The client never sees it, so it will never answer.
                if forwarded {
                    self.server_pending.remove(&id_key(&id));
                }
                vec![Action::ToServer(encode(&rpc_error(&id, text)))]
            }
            _ => Vec::new(),
        }
    }

    /// Notes why the current message is blocked (or, in observe mode,
    /// would be).
    fn note_block(&mut self, reason: &str, would: audit::Verdict) {
        self.event.reason = Some(self.audit_text(reason, MAX_REASON));
        if self.observe() {
            self.event.would = Some(would);
        }
    }

    /// Notes a change to the current message (in observe mode, one that
    /// would have been made, unless it would have been blocked or dropped
    /// instead).
    fn note_change(&mut self, change: String) {
        if self.observe() && self.event.would.is_none() {
            self.event.would = Some(audit::Verdict::Modify);
        }
        if self.event.changes.len() < MAX_CHANGES {
            let change = self.audit_text(&change, MAX_REASON);
            self.event.changes.push(change);
        } else {
            self.more_changes += 1;
        }
    }

    /// A message the gate can't read reliably. It's dropped, except that a
    /// request too large to check, or an answer to one, is answered with an
    /// error so nobody waits for it. In observe mode, it's passed on
    /// unchanged.
    fn unreadable(&mut self, error: &ParseError, from: Origin, frame: &[u8]) -> Vec<Action> {
        let answer = match error {
            ParseError::TooManyValues => self.too_large(from, frame),
            _ => Vec::new(),
        };
        let would = if answer.is_empty() {
            audit::Verdict::Drop
        } else {
            audit::Verdict::Block
        };
        self.note_block(&error.to_string(), would);
        let direction = match from {
            Origin::Client => "client→server",
            Origin::Server => "server→client",
        };
        if self.observe() {
            warn!(direction, reason = %error, bytes = frame.len(), "would drop a line that isn't JSON-RPC (observe mode)");
            return match from {
                Origin::Client => to_server(frame),
                Origin::Server => to_client(frame),
            };
        }
        if answer.is_empty() {
            warn!(direction, reason = %error, bytes = frame.len(), "dropped a line that isn't JSON-RPC");
        } else {
            warn!(direction, reason = %error, bytes = frame.len(), "answered a message too large to check with an error");
            // Answered in the sender's place: recorded as a block, not as
            // a changed message.
            self.event.verdict = Some(audit::Verdict::Block);
        }
        answer
    }

    /// The error that answers a message too large to check, if it's a
    /// request or the answer to one, as its top-level members say (read
    /// alone, they cost next to nothing). Such an answer stops being
    /// waited for.
    fn too_large(&mut self, from: Origin, frame: &[u8]) -> Vec<Action> {
        let Some(head) = jsonrpc::head(frame) else {
            return Vec::new();
        };
        let (id, method) = match &head {
            Message::Request { id, method } => (id, Some(method)),
            Message::Response { id, .. } => (id, None),
            _ => return Vec::new(),
        };
        self.event.id = Some(self.audit_id(id));
        if let Some(method) = method {
            self.event.method = Some(self.audit_text(method, MAX_NAME));
        }
        let text = "Blocked by mcp-mandate: the message is too large for mcp-mandate to check";
        match (from, method) {
            (Origin::Client, Some(method)) => {
                vec![Action::ToClient(encode(&blocked_reply(
                    id,
                    text,
                    reply_for(method),
                )))]
            }
            (Origin::Server, Some(_)) => vec![Action::ToServer(encode(&rpc_error(id, text)))],
            (Origin::Server, None) => match self.pending.remove(&id_key(id)) {
                Some(pending) => {
                    let reply = match pending {
                        Pending::ToolCall(_) => Reply::ToolError,
                        _ => Reply::Error,
                    };
                    let text = "Blocked by mcp-mandate: the server's answer is too large for mcp-mandate to check";
                    vec![Action::ToClient(encode(&blocked_reply(id, text, reply)))]
                }
                None => Vec::new(),
            },
            (Origin::Client, None) => match self.server_pending.remove(&id_key(id)) {
                Some(_) => vec![Action::ToServer(encode(&rpc_error(id, text)))],
                None => Vec::new(),
            },
        }
    }

    fn client_request(&mut self, frame: &[u8], id: &Value, method: &str) -> Vec<Action> {
        match method {
            "initialize"
            | "tools/list"
            | "prompts/list"
            | "resources/list"
            | "resources/templates/list" => {
                if self.pending.len() >= MAX_PENDING {
                    let reason = "too many requests are waiting for the server".to_owned();
                    return self.block_client(frame, id, method, reason, Reply::Error);
                }
                self.pending
                    .insert(id_key(id), Pending::List(method.to_owned()));
                to_server(frame)
            }
            "tools/call" => self.tool_call(frame, id),
            "prompts/get" => self.prompt_get(frame, id),
            "resources/read" | "resources/subscribe" | "resources/unsubscribe" => {
                self.resource_request(frame, id, method)
            }
            "ping" | "logging/setLevel" => to_server(frame),
            "completion/complete" => {
                let reason = match read_params(frame) {
                    Some(params) => self.secret_in(&params).map(|kind| {
                        format!("the completion request contains what looks like a secret ({kind})")
                    }),
                    None => Some(
                        "the completion request can't be read in full, so it can't be checked"
                            .to_owned(),
                    ),
                };
                match reason {
                    Some(reason) => self.block_client(frame, id, method, reason, Reply::Error),
                    None => to_server(frame),
                }
            }
            _ if self.policy.unknown_requests == Rule::Allow => to_server(frame),
            _ => {
                let reason = format!("`{method}` isn't a request mcp-mandate knows how to check");
                self.block_client(frame, id, method, reason, Reply::Error)
            }
        }
    }

    fn tool_call(&mut self, frame: &[u8], id: &Value) -> Vec<Action> {
        let mut params = params(frame);
        let Some(name) = params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            let reason = "the call doesn't name a tool".to_owned();
            return self.block_client(frame, id, "tools/call", reason, Reply::ToolError);
        };
        // Taken out, not copied: the arguments can be most of the message.
        let arguments = params
            .as_object_mut()
            .and_then(|params| params.remove("arguments"))
            .unwrap_or_else(|| json!({}));
        self.event.item = Some(self.audit_text(&name, MAX_NAME));
        self.event.args_sha256 = Some(fingerprint(&arguments));
        let verdict = if self.pending.len() >= MAX_PENDING {
            Err(Refusal::from(
                "too many requests are waiting for the server".to_owned(),
            ))
        } else {
            self.check_tool_call(&name, &arguments)
        };
        let actions = match verdict {
            Ok(()) => {
                debug!(tool = %name, "allowed a tool call");
                to_server(frame)
            }
            Err(refusal) => self.block_client(frame, id, "tools/call", refusal, Reply::ToolError),
        };
        // Whatever reaches the server (in observe mode, even a call that
        // would be blocked) is tracked, so its output can taint the session.
        if forwards_to_server(&actions) {
            self.pending.insert(id_key(id), Pending::ToolCall(name));
        }
        actions
    }

    fn check_tool_call(&self, name: &str, arguments: &Value) -> Result<(), Refusal> {
        let Some(info) = self.session.tools.get(name) else {
            return Err(self.not_verified(Kind::Tool, name).into());
        };
        let decision = self.policy.for_tool(name);
        match decision.action {
            Rule::Allow => {}
            Rule::Hold => {
                return Err(format!(
                    "tool `{name}` needs your approval (the policy holds it), and approvals aren't supported yet"
                )
                .into());
            }
            Rule::Deny => return Err(format!("tool `{name}` is denied by policy").into()),
        }
        if info.traits.sends_out
            && let Some(source) = self.taint()
        {
            return Err(format!(
                "this session has read untrusted content ({source}) and tool `{name}` can send data out, so it needs your approval, and approvals aren't supported yet"
            )
            .into());
        }
        decision
            .check_arguments(arguments)
            .map_err(|problem| Refusal::from(format!("tool `{name}`: {problem}")))?;
        if self.policy.secrets.block_in_arguments
            && !decision.allow_secrets
            && let Some(kind) = self.secrets.find_in_json(arguments)
        {
            return Err(format!(
                "tool `{name}`: its arguments contain what looks like a secret ({kind})"
            )
            .into());
        }
        let Some(validator) = &info.validator else {
            return Err(
                format!("tool `{name}` has an input schema mcp-mandate can't check").into(),
            );
        };
        validator.validate(arguments).map_err(|error| {
            // Where and which rule failed, but not the value: the error's
            // own text quotes the arguments.
            let at = error.instance_path().to_string();
            let at = if at.is_empty() {
                "the top level".to_owned()
            } else {
                at
            };
            Refusal {
                reason: format!(
                    "tool `{name}`: its arguments don't match its schema (`{}` at {at})",
                    error.kind().keyword()
                ),
                detail: Some(error.to_string()),
            }
        })
    }

    fn prompt_get(&mut self, frame: &[u8], id: &Value) -> Vec<Action> {
        let params = params(frame);
        self.event.args_sha256 = params.get("arguments").map(fingerprint);
        let reason = match params.get("name").and_then(Value::as_str) {
            Some(name) => {
                self.event.item = Some(self.audit_text(name, MAX_NAME));
                if !self.session.prompts.contains(name) {
                    self.not_verified(Kind::Prompt, name)
                } else if let Some(kind) = params
                    .get("arguments")
                    .and_then(|arguments| self.secret_in(arguments))
                {
                    format!(
                        "prompt `{name}`: its arguments contain what looks like a secret ({kind})"
                    )
                } else {
                    // Its messages are checked when they come back: what
                    // a prompt returns isn't pinned, only its listing.
                    self.pending.insert(id_key(id), Pending::PromptGet);
                    return to_server(frame);
                }
            }
            None => "the request doesn't name a prompt".to_owned(),
        };
        self.block_client(frame, id, "prompts/get", reason, Reply::Error)
    }

    /// A secret in what the client sends, when the policy blocks those.
    fn secret_in(&self, value: &Value) -> Option<String> {
        if !self.policy.secrets.block_in_arguments {
            return None;
        }
        self.secrets
            .find_in_json(value)
            .map(|kind| kind.to_string())
    }

    fn resource_request(&mut self, frame: &[u8], id: &Value, method: &str) -> Vec<Action> {
        let params = params(frame);
        if let Some(uri) = params.get("uri").and_then(Value::as_str) {
            self.event.item = Some(self.audit_text(uri, MAX_NAME));
        }
        let uri = params.get("uri").and_then(Value::as_str);
        // A template accepts any suffix, so a URI can carry data out.
        let secret = uri.and_then(|uri| self.secret_in(&json!(uri)));
        let actions = match (uri, secret) {
            (Some(_), Some(kind)) => {
                let reason = format!("the resource URI contains what looks like a secret ({kind})");
                self.block_client(frame, id, method, reason, Reply::Error)
            }
            (Some(uri), None) => match self.session.resource_allowed(uri) {
                Ok(()) => to_server(frame),
                Err(misfit) => {
                    let reason = misfit.unwrap_or_else(|| self.not_verified(Kind::Resource, uri));
                    self.block_client(frame, id, method, reason, Reply::Error)
                }
            },
            (None, _) => {
                let reason = "the request doesn't name a resource".to_owned();
                self.block_client(frame, id, method, reason, Reply::Error)
            }
        };
        if method == "resources/read"
            && forwards_to_server(&actions)
            && self.pending.len() < MAX_PENDING
        {
            self.pending.insert(id_key(id), Pending::ResourceRead);
        }
        actions
    }

    /// A response to no request the client is waiting for: a server
    /// answering twice, or making one up. Dropped (in observe mode, passed
    /// on after the usual checks).
    fn unexpected_response(&mut self, frame: &[u8]) -> Vec<Action> {
        let reason = "a response to no request the client is waiting for";
        self.note_block(reason, audit::Verdict::Drop);
        if self.observe() {
            warn!("would drop {reason} (observe mode)");
            return self.server_response(frame, None);
        }
        warn!("dropped {reason}");
        Vec::new()
    }

    /// Why an item can't be used: never pinned, changed, or not yet listed.
    fn not_verified(&self, kind: Kind, name: &str) -> String {
        let noun = kind.noun();
        let Some(pins) = &self.pins else {
            return format!(
                "this server hasn't been pinned, so no {noun} is approved (run `mcp-mandate pin` and review the result)"
            );
        };
        if self.session.changed.contains(&(kind, name.to_owned())) {
            format!("{noun} `{name}` changed since it was approved")
        } else if pins.contains(kind, name) {
            format!("{noun} `{name}` hasn't been listed and checked in this session")
        } else {
            format!("{noun} `{name}` isn't approved")
        }
    }

    /// Checks a response (or notification) from the server: filters lists,
    /// records taint, and redacts secrets.
    fn server_response(&mut self, frame: &[u8], pending: Option<Pending>) -> Vec<Action> {
        match &pending {
            Some(Pending::List(method)) => self.event.method = Some(method.clone()),
            Some(Pending::ToolCall(tool)) => {
                self.event.method = Some("tools/call".to_owned());
                self.event.item = Some(self.audit_text(tool, MAX_NAME));
            }
            Some(Pending::ResourceRead) => self.event.method = Some("resources/read".to_owned()),
            Some(Pending::PromptGet) => self.event.method = Some("prompts/get".to_owned()),
            Some(Pending::Other(method)) => {
                self.event.method = Some(self.audit_text(method, MAX_NAME));
            }
            None => {}
        }
        let redact = self.policy.secrets.redact_responses;
        if pending.is_none() && !redact {
            return to_client(frame);
        }
        let Ok(mut message) = serde_json::from_slice::<Value>(frame) else {
            // Its envelope parsed but the whole message doesn't (nested too
            // deeply, say): it can't be checked, so it doesn't pass.
            let reason = "the message can't be read in full (it's nested too deeply), so it can't be checked";
            self.note_block(reason, audit::Verdict::Drop);
            if self.observe() {
                warn!("would drop a server message: {reason} (observe mode)");
                return to_client(frame);
            }
            warn!("dropped a server message: {reason}");
            return Vec::new();
        };
        // (An `error` member is always an object here: classifying refuses
        // any other, and one next to a `result`.)
        if let Some(Pending::List(method)) = &pending
            && message.get("error").is_none()
            && !expected_shape(method, &message)
        {
            // A lenient client could show what a malformed answer holds.
            let reason = format!(
                "the server's answer to `{method}` isn't shaped as MCP requires, so it can't be checked"
            );
            self.note_block(&reason, audit::Verdict::Drop);
            if self.observe() {
                warn!("would drop: {reason} (observe mode)");
                return to_client(frame);
            }
            warn!("dropped: {reason}");
            return Vec::new();
        }
        let reply = match &pending {
            Some(Pending::ToolCall(_)) => Reply::ToolError,
            _ => Reply::Error,
        };
        let taint = match &pending {
            Some(Pending::ToolCall(tool)) => {
                // A tool that's no longer approved counts as untrusted.
                let reads_untrusted = self
                    .session
                    .tools
                    .get(tool)
                    .is_none_or(|info| info.traits.reads_untrusted);
                reads_untrusted.then(|| format!("the output of tool `{tool}`"))
            }
            Some(Pending::ResourceRead) => self
                .policy
                .taint
                .resources_are_untrusted
                .then(|| "a resource from the server".to_owned()),
            Some(Pending::PromptGet) => self
                .policy
                .taint
                .prompts_are_untrusted
                .then(|| "a prompt from the server".to_owned()),
            _ => None,
        };
        if let Some(source) = taint
            && !self.mark_tainted(source.clone())
            && let Some(reason) = self.unshared_taint(&source)
        {
            // The client is answered in the server's place: recorded as a
            // block, not as a changed answer.
            self.event.verdict = Some(audit::Verdict::Block);
            let id = message.get("id").cloned().unwrap_or(Value::Null);
            let text = format!("Blocked by mcp-mandate: {reason}, so the answer is withheld");
            return vec![Action::ToClient(encode(&blocked_reply(&id, &text, reply)))];
        }
        let mut modified = match pending {
            Some(Pending::List(method)) => match method.as_str() {
                "initialize" => self.check_initialize(&mut message),
                "tools/list" => self.filter_list(&mut message, Kind::Tool),
                "prompts/list" => self.filter_list(&mut message, Kind::Prompt),
                "resources/list" => self.filter_list(&mut message, Kind::Resource),
                "resources/templates/list" => {
                    self.filter_list(&mut message, Kind::ResourceTemplate)
                }
                _ => false,
            },
            _ => false,
        };
        if redact {
            modified |= self.redact(&mut message);
        }
        // The only places the gate rewrites a message: everything else is
        // forwarded byte for byte.
        if modified {
            vec![Action::ToClient(encode(&message))]
        } else {
            to_client(frame)
        }
    }

    /// Puts this session's taint back where the agent's other gates read
    /// it, if something removed it meanwhile (a cleaner of temporary files,
    /// say): they read only that, and this session stays tainted. If it
    /// can't be put back, the taint counts as unshared again, as if it
    /// couldn't be shared at first (see [`mark_tainted`](Self::mark_tainted)).
    /// Checked at most once every [`TAINT_CHECK`], since reading it can
    /// mean reading a file.
    fn keep_taint_shared(&mut self) {
        let (Some(source), Some(shared)) = (&self.session.taint, &self.shared_taint) else {
            return;
        };
        let now = Instant::now();
        if self
            .taint_checked
            .is_some_and(|checked| now.duration_since(checked) < TAINT_CHECK)
        {
            return;
        }
        self.taint_checked = Some(now);
        let present = shared.reshare(source);
        if self.taint_shared && !present {
            warn!("couldn't put this session's taint back where the agent's other servers read it");
        }
        self.taint_shared = present;
    }

    /// Taints the session (once; it stays tainted), and every other session
    /// of the same agent. Returns false when those couldn't be told (until
    /// they are, an answer that taints the session doesn't pass).
    fn mark_tainted(&mut self, source: String) -> bool {
        if self.session.taint.is_none() {
            warn!(%source, "the session read untrusted content: tools that can send data out are now held");
            self.event.taint = Some(self.audit_text(&source, MAX_REASON));
            self.session.taint = Some(source);
        }
        match (&self.session.taint, &self.shared_taint) {
            (Some(source), Some(shared)) if !self.taint_shared => {
                self.taint_shared = shared.set(source);
                self.taint_shared
            }
            _ => true,
        }
    }

    /// For a server message whose taint couldn't be shared with the agent's
    /// other sessions: those wouldn't hold their tools, so it doesn't pass.
    /// Returns why, or `None` in observe mode, where it passes with a
    /// warning.
    fn unshared_taint(&mut self, source: &str) -> Option<String> {
        let reason = format!(
            "{source} tainted this session, but the taint couldn't be shared with the agent's other servers"
        );
        self.note_block(&reason, audit::Verdict::Block);
        if self.observe() {
            warn!(%reason, "would withhold the server's message (observe mode)");
            return None;
        }
        error!(%reason, "withheld the server's message");
        Some(reason)
    }

    /// Redacts secrets anywhere in `message` (in observe mode, only logs
    /// them). Returns whether the message changed.
    fn redact(&mut self, message: &mut Value) -> bool {
        if self.observe() {
            if let Some(kind) = self.secrets.find_in_response(message) {
                warn!(%kind, "would redact a secret from a server message (observe mode)");
                self.note_change(format!("secrets redacted: {kind}"));
            }
            return false;
        }
        let kinds = self.secrets.redact_json(message);
        if kinds.is_empty() {
            return false;
        }
        warn!(?kinds, "redacted secrets from a server message");
        self.note_change(format!("secrets redacted: {}", kinds.join(", ")));
        true
    }

    /// Logs the negotiated protocol and removes unapproved instructions.
    fn check_initialize(&mut self, message: &mut Value) -> bool {
        let Some(result) = message.get_mut("result").and_then(Value::as_object_mut) else {
            return false;
        };
        let version = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let server = result
            .get("serverInfo")
            .and_then(|info| info.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        info!(
            protocol_version = version,
            server, "MCP session initialized"
        );
        let server_version = result
            .get("serverInfo")
            .and_then(|info| info.get("version"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        self.event.item = Some(self.audit_text(&format!("{server} {server_version}"), MAX_NAME));

        let text = match result.get("instructions") {
            None => return false,
            Some(Value::String(text)) => text.clone(),
            Some(_) => {
                // Instructions that aren't text can't be checked against a pin.
                self.note_change("the server's instructions removed: they aren't text".to_owned());
                if self.observe() {
                    return false;
                }
                result.remove("instructions");
                return true;
            }
        };
        let text = text.as_str();
        let verdict = self
            .pins
            .as_ref()
            .map_or(Verdict::Unknown, |pins| pins.check_instructions(text));
        let reason = match verdict {
            Verdict::Approved => return false,
            Verdict::Changed => "they changed since they were approved",
            Verdict::Unknown => "they aren't approved",
        };
        self.note_change(format!("the server's instructions removed: {reason}"));
        if self.observe() {
            warn!("would remove the server's instructions: {reason} (observe mode)");
            return false;
        }
        warn!("removed the server's instructions: {reason}");
        result.remove("instructions");
        true
    }

    /// Keeps only approved items in a list result. Returns whether it
    /// removed any.
    fn filter_list(&mut self, message: &mut Value, kind: Kind) -> bool {
        let observe = self.observe();
        let pointer = format!("/result/{}", kind.list_field());
        let Some(items) = message.pointer_mut(&pointer).and_then(Value::as_array_mut) else {
            return false;
        };
        let before = items.len();
        let mut kept = Vec::with_capacity(before);
        for item in std::mem::take(items) {
            if self.check_item(kind, &item, observe) || observe {
                kept.push(item);
            }
        }
        *items = kept;
        items.len() != before
    }

    /// Checks one listed item against the pins and records the outcome.
    /// Returns whether the item may be shown.
    fn check_item(&mut self, kind: Kind, item: &Value, observe: bool) -> bool {
        let noun = kind.noun();
        let hide = if observe { "would hide" } else { "hiding" };
        let Some(name) = Pins::item_name(kind, item) else {
            warn!(kind = noun, "{hide} an item with no name");
            self.note_change(format!("a {noun} with no name hidden"));
            return false;
        };
        let verdict = self
            .pins
            .as_ref()
            .map_or(Verdict::Unknown, |pins| pins.check(kind, name, item));
        match verdict {
            Verdict::Approved => {
                let decision = self.policy.for_tool(name);
                let labels = Labels {
                    reads_untrusted: decision.reads_untrusted,
                    sends_out: decision.sends_out,
                };
                self.session.approve(kind, name, item, labels);
                if kind == Kind::Tool && decision.action == Rule::Deny {
                    debug!(item = name, "{hide} a tool the policy denies");
                    self.note_change(format!("tool `{name}` hidden: the policy denies it"));
                    return false;
                }
                true
            }
            Verdict::Changed => {
                warn!(
                    kind = noun,
                    item = name,
                    "{hide} it: it changed since it was approved"
                );
                self.session.quarantine(kind, name);
                self.note_change(format!(
                    "{noun} `{name}` hidden: it changed since it was approved"
                ));
                false
            }
            Verdict::Unknown => {
                info!(kind = noun, item = name, "{hide} it: it isn't approved");
                self.note_change(format!("{noun} `{name}` hidden: it isn't approved"));
                false
            }
        }
    }

    fn server_request(&mut self, frame: &[u8], id: &Value, method: &str) -> Vec<Action> {
        let rule = match method {
            "sampling/createMessage" => self.policy.server_requests.sampling,
            "elicitation/create" => self.policy.server_requests.elicitation,
            "roots/list" => self.policy.server_requests.roots,
            "ping" => Rule::Allow,
            _ => self.policy.unknown_requests,
        };
        match rule {
            Rule::Allow => {
                // A sampling request puts the server's text in front of the
                // model, like a tool's output does.
                let source = "the server's `sampling/createMessage` request";
                if method == "sampling/createMessage"
                    && !self.mark_tainted(source.to_owned())
                    && let Some(reason) = self.unshared_taint(source)
                {
                    let text = format!("Blocked by mcp-mandate: {reason}");
                    return vec![Action::ToServer(encode(&rpc_error(id, &text)))];
                }
                // Checked like a response: secrets are redacted.
                self.server_response(frame, None)
            }
            Rule::Hold => {
                let reason = format!(
                    "the server's `{method}` request needs your approval, and approvals aren't supported yet"
                );
                self.block_server(frame, id, method, reason)
            }
            Rule::Deny => {
                let reason = format!("the server's `{method}` request is denied by policy");
                self.block_server(frame, id, method, reason)
            }
        }
    }

    /// Answers a blocked client request (or, in observe mode, forwards it).
    fn block_client(
        &mut self,
        frame: &[u8],
        id: &Value,
        method: &str,
        refusal: impl Into<Refusal>,
        reply: Reply,
    ) -> Vec<Action> {
        let Refusal { reason, detail } = refusal.into();
        self.note_block(&reason, audit::Verdict::Block);
        if self.observe() {
            warn!(%method, %reason, "would block (observe mode)");
            return to_server(frame);
        }
        warn!(%method, %reason, "blocked");
        let text = match detail {
            Some(detail) => format!("Blocked by mcp-mandate: {reason}: {detail}"),
            None => format!("Blocked by mcp-mandate: {reason}"),
        };
        vec![Action::ToClient(encode(&blocked_reply(id, &text, reply)))]
    }

    /// Answers a blocked server request (or, in observe mode, forwards it).
    fn block_server(
        &mut self,
        frame: &[u8],
        id: &Value,
        method: &str,
        reason: String,
    ) -> Vec<Action> {
        self.note_block(&reason, audit::Verdict::Block);
        if self.observe() {
            warn!(%method, %reason, "would block (observe mode)");
            return to_client(frame);
        }
        warn!(%method, %reason, "blocked");
        let text = format!("Blocked by mcp-mandate: {reason}");
        vec![Action::ToServer(encode(&rpc_error(id, &text)))]
    }

    fn batch(&mut self, len: usize, forward: Action) -> Vec<Action> {
        self.note_block(
            "batches can't be checked one message at a time",
            audit::Verdict::Drop,
        );
        if self.observe() {
            warn!(len, "would drop a JSON-RPC batch (observe mode)");
            return vec![forward];
        }
        warn!(
            len,
            "dropped a JSON-RPC batch: batches can't be checked one message at a time"
        );
        Vec::new()
    }
}

/// What the gate did with a message, judged by where it sent it: back to
/// its sender means answered instead of forwarded. Also returns the
/// forwarded bytes when they differ from what arrived.
fn judge<'a>(
    from: Origin,
    frame: &[u8],
    actions: &'a [Action],
) -> (audit::Verdict, Option<&'a [u8]>) {
    let forwarded = match (from, actions) {
        (_, []) => return (audit::Verdict::Drop, None),
        (Origin::Client, [Action::ToServer(bytes)])
        | (Origin::Server, [Action::ToClient(bytes)]) => bytes,
        _ => return (audit::Verdict::Block, None),
    };
    if forwarded == frame {
        (audit::Verdict::Allow, None)
    } else {
        (audit::Verdict::Modify, Some(forwarded))
    }
}

/// A blocked request's answer: a tool error for a tool call, so the model
/// reads why; a JSON-RPC error otherwise.
fn blocked_reply(id: &Value, text: &str, reply: Reply) -> Value {
    match reply {
        Reply::ToolError => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"content": [{"type": "text", "text": text}], "isError": true}
        }),
        Reply::Error => rpc_error(id, text),
    }
}

fn reply_for(method: &str) -> Reply {
    if method == "tools/call" {
        Reply::ToolError
    } else {
        Reply::Error
    }
}

/// A message's bytes without its line ending, for hashing.
fn without_line_ending(frame: &[u8]) -> &[u8] {
    let frame = frame.strip_suffix(b"\n").unwrap_or(frame);
    frame.strip_suffix(b"\r").unwrap_or(frame)
}

/// `text`, cut to at most `max` bytes (at a character boundary), with "…"
/// added when cut.
fn clip(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// An error and its causes on one line.
fn describe(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

fn to_server(frame: &[u8]) -> Vec<Action> {
    vec![Action::ToServer(frame.to_vec())]
}

/// Whether a successful answer to a list (or to `initialize`) has the shape
/// MCP requires.
fn expected_shape(method: &str, message: &Value) -> bool {
    let result = &message["result"];
    match method {
        "initialize" => result.is_object(),
        "tools/list" => result["tools"].is_array(),
        "prompts/list" => result["prompts"].is_array(),
        "resources/list" => result["resources"].is_array(),
        "resources/templates/list" => result["resourceTemplates"].is_array(),
        _ => true,
    }
}

fn forwards_to_server(actions: &[Action]) -> bool {
    matches!(actions, [Action::ToServer(_)])
}

fn to_client(frame: &[u8]) -> Vec<Action> {
    vec![Action::ToClient(frame.to_vec())]
}

/// A message's `params`, or `null`.
fn params(frame: &[u8]) -> Value {
    read_params(frame).unwrap_or(Value::Null)
}

/// A message's `params` (`null` when it has none), or `None` when the
/// message can't be read in full.
fn read_params(frame: &[u8]) -> Option<Value> {
    let mut message = serde_json::from_slice::<Value>(frame).ok()?;
    Some(message.get_mut("params").map_or(Value::Null, Value::take))
}

fn id_key(id: &Value) -> String {
    id.to_string()
}

fn rpc_error(id: &Value, text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": BLOCKED_ERROR_CODE, "message": text}
    })
}

fn encode(message: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(message).expect("JSON values always serialize");
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
mod tests;
