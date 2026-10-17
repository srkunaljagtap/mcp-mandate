//! Any sequence of messages, from either side, through a gate with an
//! approved tool: the gate must never panic or answer a message twice, and
//! a planted secret must never get through.
#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use mcp_mandate_audit::{AuditError, Event, Recorder};
use mcp_mandate_gate::{Action, Gate};
use mcp_mandate_pin::{Inventory, Pins};
use mcp_mandate_policy::Policy;
use serde_json::json;

const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

struct Discard;

impl Recorder for Discard {
    fn record(&mut self, _: &Event) -> Result<(), AuditError> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let policy = Policy::parse("[[tools]]\nmatch = \"*\"\naction = \"allow\"\n", Path::new(".")).unwrap();
    let pins = Pins::from_inventory(
        "fuzz",
        &Inventory {
            tools: vec![json!({"name": "echo", "inputSchema": {"type": "object"}})],
            ..Inventory::default()
        },
    );
    let mut gate = Gate::new(policy, Some(pins), Box::new(Discard));
    // Each line is a message; its first byte says who sends it.
    for line in data.split(|&byte| byte == b'\n') {
        let Some((&side, message)) = line.split_first() else {
            continue;
        };
        let mut frame = message.to_vec();
        frame.push(b'\n');
        let from_server = side % 2 == 1;
        let actions = if from_server {
            gate.from_server(&frame)
        } else {
            gate.from_client(&frame)
        };
        assert!(actions.len() <= 1);
        if from_server && String::from_utf8_lossy(message).contains(SECRET) {
            for action in &actions {
                if let Action::ToClient(out) = action {
                    // Image and audio data are left untouched by design.
                    let out = String::from_utf8_lossy(out);
                    assert!(
                        !out.contains(SECRET) || out.contains("\"data\"") || out.contains("\"blob\""),
                        "a secret got through: {out}"
                    );
                }
            }
        }
    }
});
