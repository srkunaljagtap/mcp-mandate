//! Properties that must hold for any input, checked with random inputs:
//! the gate never panics, answers each message at most once, and never lets
//! a planted secret through from the server.

use std::path::Path;

use mcp_mandate_audit::{AuditError, Event, Recorder};
use mcp_mandate_gate::jsonrpc::classify;
use mcp_mandate_gate::{Action, Gate};
use mcp_mandate_pin::{Inventory, Pins};
use mcp_mandate_policy::Policy;
use proptest::prelude::*;
use serde_json::{Map, Value, json};

const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

struct Discard;

impl Recorder for Discard {
    fn record(&mut self, _: &Event) -> Result<(), AuditError> {
        Ok(())
    }
}

fn gate(observe: bool) -> Gate {
    let mode = if observe { "mode = \"observe\"\n" } else { "" };
    let policy = Policy::parse(
        &format!("{mode}[[tools]]\nmatch = \"*\"\naction = \"allow\"\n"),
        Path::new("."),
    )
    .unwrap();
    let pins = Pins::from_inventory(
        "properties",
        &Inventory {
            tools: vec![json!({"name": "echo", "inputSchema": {"type": "object"}})],
            ..Inventory::default()
        },
    );
    Gate::new(policy, Some(pins), Box::new(Discard))
}

/// Random JSON, with object keys from a small alphabet so method names,
/// ids and params line up with real ones often enough to matter.
fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        "[a-z/ _.-]{0,12}".prop_map(Value::String),
        prop_oneof![
            Just("tools/call"),
            Just("tools/list"),
            Just("initialize"),
            Just("sampling/createMessage"),
            Just("notifications/cancelled"),
            Just("echo"),
            Just("2.0"),
        ]
        .prop_map(|text| Value::String(text.to_owned())),
    ];
    leaf.prop_recursive(6, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::vec((key(), inner), 0..6)
                .prop_map(|pairs| Value::Object(pairs.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

fn key() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("jsonrpc"),
        Just("id"),
        Just("method"),
        Just("params"),
        Just("result"),
        Just("error"),
        Just("name"),
        Just("arguments"),
        Just("content"),
        Just("text"),
        Just("tools"),
        Just("message"),
        Just("requestId"),
    ]
    .prop_map(str::to_owned)
}

/// A JSON-RPC-shaped message built from random parts.
fn message() -> impl Strategy<Value = Value> {
    (json_value(), json_value(), json_value(), any::<u8>()).prop_map(
        |(id, params, result, shape)| {
            let mut message = json!({"jsonrpc": "2.0"});
            match shape % 4 {
                0 => {
                    message["id"] = id;
                    message["method"] = json!("tools/call");
                    message["params"] = params;
                }
                1 => message["method"] = json!("notifications/message"),
                2 => {
                    message["id"] = json!(1);
                    message["result"] = result;
                }
                _ => {
                    message["id"] = id;
                    message["method"] = json!("sampling/createMessage");
                    message["params"] = params;
                }
            }
            message
        },
    )
}

/// Puts the secret into some string inside `value` (or makes one).
fn plant(value: &mut Value, pick: usize) -> bool {
    match value {
        Value::String(text) => {
            text.push(' ');
            text.push_str(SECRET);
            true
        }
        Value::Array(items) if !items.is_empty() => {
            let index = pick % items.len();
            plant(&mut items[index], pick / 2)
        }
        Value::Object(map) if !map.is_empty() => {
            let key = map.keys().nth(pick % map.len()).cloned().unwrap();
            plant(map.get_mut(&key).unwrap(), pick / 2)
        }
        _ => false,
    }
}

fn output(actions: &[Action]) -> String {
    actions
        .iter()
        .map(|action| match action {
            Action::ToClient(bytes) | Action::ToServer(bytes) => {
                String::from_utf8_lossy(bytes).into_owned()
            }
        })
        .collect()
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512), observe in any::<bool>()) {
        let _ = classify(&bytes);
        let mut gate = gate(observe);
        prop_assert!(gate.from_client(&bytes).len() <= 1);
        prop_assert!(gate.from_server(&bytes).len() <= 1);
    }

    #[test]
    fn arbitrary_messages_get_at_most_one_answer(messages in prop::collection::vec((message(), any::<bool>()), 1..8)) {
        let mut gate = gate(false);
        for (message, from_client) in messages {
            let mut bytes = serde_json::to_vec(&message).unwrap();
            bytes.push(b'\n');
            let actions = if from_client { gate.from_client(&bytes) } else { gate.from_server(&bytes) };
            prop_assert!(actions.len() <= 1);
        }
    }

    #[test]
    fn a_secret_from_the_server_never_reaches_the_client(mut payload in json_value(), pick in any::<usize>()) {
        if !plant(&mut payload, pick) {
            payload = json!(format!("value {SECRET}"));
        }
        let mut gate = gate(false);
        for message in [
            json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": payload.clone()}}),
            json!({"jsonrpc": "2.0", "id": "s", "method": "elicitation/create", "params": {"message": payload.clone()}}),
        ] {
            let mut bytes = serde_json::to_vec(&message).unwrap();
            bytes.push(b'\n');
            let out = output(&gate.from_server(&bytes));
            prop_assert!(!out.contains(SECRET), "leaked: {out}");
        }
        // A tool result, answering a real call.
        gate.from_client(&json_line(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})));
        gate.from_server(&json_line(&json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}})));
        gate.from_client(&json_line(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {}}})));
        let out = output(&gate.from_server(&json_line(&json!({"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "x"}], "structuredContent": payload}}))));
        prop_assert!(!out.contains(SECRET), "leaked: {out}");
    }

    #[test]
    fn a_secret_in_tool_arguments_never_reaches_the_server(mut arguments in json_value(), pick in any::<usize>()) {
        if !plant(&mut arguments, pick) {
            arguments = json!({"note": SECRET});
        }
        let mut gate = gate(false);
        gate.from_client(&json_line(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})));
        gate.from_server(&json_line(&json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}})));
        let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": arguments}});
        let actions = gate.from_client(&json_line(&call));
        prop_assert!(!actions.iter().any(|action| matches!(action, Action::ToServer(_))));
    }
}

fn json_line(message: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(message).unwrap();
    bytes.push(b'\n');
    bytes
}
