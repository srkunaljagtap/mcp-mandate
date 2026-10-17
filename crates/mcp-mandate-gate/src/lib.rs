//! The gate: decides what crosses between an MCP client and an MCP server.
//!
//! It takes one complete JSON-RPC message at a time and says where it goes,
//! never doing I/O itself, so every transport (stdio today, HTTPS later)
//! shares exactly the same checks.
//!
//! - Client to server: calls and reads (`tools/call`, `prompts/get`,
//!   `resources/read`) pass only for items that are pinned, were listed and
//!   matched their pin in this session, and that the policy allows.
//! - Server to client: lists are filtered down to approved items, the
//!   server's instructions are removed unless approved, and requests the
//!   server makes (sampling, elicitation) follow the policy.
//! - Taint: once a tool that reads untrusted content (or a resource) has
//!   answered, the session is tainted and tools that can send data out are
//!   held for the rest of the session.
//! - Secrets: redacted from everything the server sends, and blocked in
//!   tool-call arguments.
//!
//! In observe mode every decision is logged but nothing is blocked, hidden
//! or redacted.

pub mod jsonrpc;

use std::collections::{HashMap, HashSet};

use mcp_mandate_pin::{Kind, Pins, Verdict};
use mcp_mandate_policy::{Action as Rule, Mode, Policy};
use mcp_mandate_taint::{Labels, SecretDetector, SecretPattern, Traits};
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::jsonrpc::{Message, ParseError, classify};

/// JSON-RPC error code for requests the gate blocks (from the range
/// JSON-RPC leaves to implementations).
pub const BLOCKED_ERROR_CODE: i64 = -32000;

/// Most client requests waiting for a server response that the gate tracks.
const MAX_PENDING: usize = 4096;

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

/// One session's gate.
pub struct Gate {
    policy: Policy,
    pins: Option<Pins>,
    secrets: SecretDetector,
    /// Client requests whose responses the gate inspects, by id.
    pending: HashMap<String, Pending>,
    session: Session,
}

/// A client request whose response the gate inspects.
enum Pending {
    /// `initialize` or a list, checked against the pins.
    List(String),
    /// A tool call, whose output may taint the session.
    ToolCall(String),
    /// A resource read, whose content may taint the session.
    ResourceRead,
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
    /// Approved resource templates and the fixed URI prefix before their
    /// first `{`.
    templates: HashMap<String, String>,
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
                    validator: jsonschema::validator_for(&schema).ok(),
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
                let prefix = name.split('{').next().unwrap_or_default().to_owned();
                self.templates.insert(name.to_owned(), prefix);
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

    fn resource_allowed(&self, uri: &str) -> bool {
        self.resources.contains(uri)
            || self
                .templates
                .values()
                .any(|prefix| !prefix.is_empty() && uri.starts_with(prefix.as_str()))
    }
}

impl Gate {
    /// A gate enforcing `policy`. Without `pins`, nothing a server offers is
    /// approved.
    pub fn new(policy: Policy, pins: Option<Pins>) -> Self {
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
            session: Session::default(),
        }
    }

    /// What tainted the session, if anything has.
    pub fn taint(&self) -> Option<&str> {
        self.session.taint.as_deref()
    }

    pub fn mode(&self) -> Mode {
        self.policy.mode
    }

    /// Decides what happens to one message from the client.
    pub fn from_client(&mut self, frame: &[u8]) -> Vec<Action> {
        match classify(frame) {
            Ok(Message::Request { id, method }) => self.client_request(frame, &id, &method),
            Ok(Message::Notification { .. } | Message::Response { .. }) => to_server(frame),
            Ok(Message::Batch { len }) => self.batch(len, Action::ToServer(frame.to_vec())),
            Err(error) => drop_line(&error, "client→server", frame),
        }
    }

    /// Decides what happens to one message from the server.
    pub fn from_server(&mut self, frame: &[u8]) -> Vec<Action> {
        match classify(frame) {
            Ok(Message::Response { id, .. }) => {
                let pending = self.pending.remove(&id_key(&id));
                self.server_response(frame, pending)
            }
            Ok(Message::Request { id, method }) => self.server_request(frame, &id, &method),
            Ok(Message::Notification { method }) => {
                if method.ends_with("/list_changed") {
                    info!(%method, "the server says a list changed; the new list will be checked against the pins");
                }
                self.server_response(frame, None)
            }
            Ok(Message::Batch { len }) => self.batch(len, Action::ToClient(frame.to_vec())),
            Err(error) => drop_line(&error, "server→client", frame),
        }
    }

    fn observe(&self) -> bool {
        self.policy.mode == Mode::Observe
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
            "ping" | "completion/complete" | "logging/setLevel" => to_server(frame),
            _ if self.policy.unknown_requests == Rule::Allow => to_server(frame),
            _ => {
                let reason = format!("`{method}` isn't a request mcp-mandate knows how to check");
                self.block_client(frame, id, method, reason, Reply::Error)
            }
        }
    }

    fn tool_call(&mut self, frame: &[u8], id: &Value) -> Vec<Action> {
        let params = params(frame);
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            let reason = "the call doesn't name a tool".to_owned();
            return self.block_client(frame, id, "tools/call", reason, Reply::ToolError);
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let verdict = if self.pending.len() >= MAX_PENDING {
            Err("too many requests are waiting for the server".to_owned())
        } else {
            self.check_tool_call(name, &arguments)
        };
        let actions = match verdict {
            Ok(()) => {
                debug!(tool = name, "allowed a tool call");
                to_server(frame)
            }
            Err(reason) => self.block_client(frame, id, "tools/call", reason, Reply::ToolError),
        };
        // Whatever reaches the server (in observe mode, even a call that
        // would be blocked) is tracked, so its output can taint the session.
        if forwards_to_server(&actions) {
            self.pending
                .insert(id_key(id), Pending::ToolCall(name.to_owned()));
        }
        actions
    }

    fn check_tool_call(&self, name: &str, arguments: &Value) -> Result<(), String> {
        let Some(info) = self.session.tools.get(name) else {
            return Err(self.not_verified(Kind::Tool, name));
        };
        let decision = self.policy.for_tool(name);
        match decision.action {
            Rule::Allow => {}
            Rule::Hold => {
                return Err(format!(
                    "tool `{name}` needs your approval (the policy holds it), and approvals aren't supported yet"
                ));
            }
            Rule::Deny => return Err(format!("tool `{name}` is denied by policy")),
        }
        if let Some(source) = &self.session.taint
            && info.traits.sends_out
        {
            return Err(format!(
                "this session has read untrusted content ({source}) and tool `{name}` can send data out, so it needs your approval, and approvals aren't supported yet"
            ));
        }
        decision
            .check_arguments(arguments)
            .map_err(|problem| format!("tool `{name}`: {problem}"))?;
        if self.policy.secrets.block_in_arguments
            && !decision.allow_secrets
            && let Some(kind) = self.secrets.find_in_json(arguments)
        {
            return Err(format!(
                "tool `{name}`: its arguments contain what looks like a secret ({kind})"
            ));
        }
        match &info.validator {
            Some(validator) => validator.validate(arguments).map_err(|error| {
                format!("tool `{name}`: its arguments don't match its schema: {error}")
            }),
            None => Err(format!(
                "tool `{name}` has an input schema mcp-mandate can't check"
            )),
        }
    }

    fn prompt_get(&mut self, frame: &[u8], id: &Value) -> Vec<Action> {
        let params = params(frame);
        let reason = match params.get("name").and_then(Value::as_str) {
            Some(name) if self.session.prompts.contains(name) => return to_server(frame),
            Some(name) => self.not_verified(Kind::Prompt, name),
            None => "the request doesn't name a prompt".to_owned(),
        };
        self.block_client(frame, id, "prompts/get", reason, Reply::Error)
    }

    fn resource_request(&mut self, frame: &[u8], id: &Value, method: &str) -> Vec<Action> {
        let params = params(frame);
        let actions = match params.get("uri").and_then(Value::as_str) {
            Some(uri) if self.session.resource_allowed(uri) => to_server(frame),
            Some(uri) => {
                let reason = self.not_verified(Kind::Resource, uri);
                self.block_client(frame, id, method, reason, Reply::Error)
            }
            None => {
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
        let redact = self.policy.secrets.redact_responses;
        if pending.is_none() && !redact {
            return to_client(frame);
        }
        let Ok(mut message) = serde_json::from_slice::<Value>(frame) else {
            return to_client(frame);
        };
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
            Some(Pending::ToolCall(tool)) => {
                // A tool that's no longer approved counts as untrusted.
                let reads_untrusted = self
                    .session
                    .tools
                    .get(&tool)
                    .is_none_or(|info| info.traits.reads_untrusted);
                if reads_untrusted {
                    self.mark_tainted(format!("the output of tool `{tool}`"));
                }
                false
            }
            Some(Pending::ResourceRead) => {
                if self.policy.taint.resources_are_untrusted {
                    self.mark_tainted("a resource from the server".to_owned());
                }
                false
            }
            None => false,
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

    /// Taints the session (once; it stays tainted).
    fn mark_tainted(&mut self, source: String) {
        if self.session.taint.is_none() {
            warn!(%source, "the session read untrusted content: tools that can send data out are now held");
            self.session.taint = Some(source);
        }
    }

    /// Redacts secrets anywhere in `message` (in observe mode, only logs
    /// them). Returns whether the message changed.
    fn redact(&self, message: &mut Value) -> bool {
        if self.observe() {
            if let Some(kind) = self.secrets.find_in_json(message) {
                warn!(%kind, "would redact a secret from a server message (observe mode)");
            }
            return false;
        }
        let kinds = self.secrets.redact_json(message);
        if kinds.is_empty() {
            return false;
        }
        warn!(?kinds, "redacted secrets from a server message");
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

        let Some(text) = result.get("instructions").and_then(Value::as_str) else {
            return false;
        };
        let verdict = self
            .pins
            .as_ref()
            .map_or(Verdict::Unknown, |pins| pins.check_instructions(text));
        let reason = match verdict {
            Verdict::Approved => return false,
            Verdict::Changed => "they changed since they were approved",
            Verdict::Unknown => "they aren't approved",
        };
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
                false
            }
            Verdict::Unknown => {
                info!(kind = noun, item = name, "{hide} it: it isn't approved");
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
            Rule::Allow => to_client(frame),
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
        &self,
        frame: &[u8],
        id: &Value,
        method: &str,
        reason: String,
        reply: Reply,
    ) -> Vec<Action> {
        if self.observe() {
            warn!(%method, %reason, "would block (observe mode)");
            return to_server(frame);
        }
        warn!(%method, %reason, "blocked");
        let text = format!("Blocked by mcp-mandate: {reason}");
        let response = match reply {
            Reply::ToolError => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"content": [{"type": "text", "text": text}], "isError": true}
            }),
            Reply::Error => rpc_error(id, &text),
        };
        vec![Action::ToClient(encode(&response))]
    }

    /// Answers a blocked server request (or, in observe mode, forwards it).
    fn block_server(&self, frame: &[u8], id: &Value, method: &str, reason: String) -> Vec<Action> {
        if self.observe() {
            warn!(%method, %reason, "would block (observe mode)");
            return to_client(frame);
        }
        warn!(%method, %reason, "blocked");
        let text = format!("Blocked by mcp-mandate: {reason}");
        vec![Action::ToServer(encode(&rpc_error(id, &text)))]
    }

    fn batch(&self, len: usize, forward: Action) -> Vec<Action> {
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

fn drop_line(error: &ParseError, direction: &str, frame: &[u8]) -> Vec<Action> {
    if !matches!(error, ParseError::Empty) {
        warn!(direction, reason = %error, bytes = frame.len(), "dropped a line that isn't JSON-RPC");
    }
    Vec::new()
}

fn to_server(frame: &[u8]) -> Vec<Action> {
    vec![Action::ToServer(frame.to_vec())]
}

fn forwards_to_server(actions: &[Action]) -> bool {
    matches!(actions, [Action::ToServer(_)])
}

fn to_client(frame: &[u8]) -> Vec<Action> {
    vec![Action::ToClient(frame.to_vec())]
}

/// A message's `params`, or `null`.
fn params(frame: &[u8]) -> Value {
    serde_json::from_slice::<Value>(frame)
        .ok()
        .and_then(|mut message| message.get_mut("params").map(Value::take))
        .unwrap_or(Value::Null)
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
