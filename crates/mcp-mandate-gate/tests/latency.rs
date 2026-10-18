//! The time the gate adds to each message, with every check on and a real
//! audit log being written. CI runs it in a release build:
//!
//! ```sh
//! cargo test --release -p mcp-mandate-gate --test latency -- --ignored --nocapture
//! ```
//!
//! and fails if the median goes over the 5 ms budget.

use std::path::Path;
use std::time::{Duration, Instant};

use mcp_mandate_audit::Log;
use mcp_mandate_gate::Gate;
use mcp_mandate_pin::{Inventory, Pins};
use mcp_mandate_policy::Policy;
use serde_json::{Value, json};

const BUDGET: Duration = Duration::from_millis(5);
const ROUNDS: u64 = 2000;

fn line(message: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(message).unwrap();
    bytes.push(b'\n');
    bytes
}

fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index]
}

#[test]
#[ignore = "a benchmark: run it in a release build"]
fn the_gate_adds_well_under_five_milliseconds_per_message() {
    let dir = std::env::temp_dir().join(format!("mcp-mandate-latency-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = Policy::parse(
        "mode = \"enforce\"\n[[tools]]\nmatch = \"*\"\naction = \"allow\"\nno_shell_metacharacters = [\"message\"]\n",
        &dir,
    )
    .unwrap();
    let tool = json!({"name": "search", "description": "Searches the docs",
        "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["message"]},
        "annotations": {"readOnlyHint": true, "openWorldHint": false}});
    let pins = Pins::from_inventory(
        "latency",
        &Inventory {
            tools: vec![tool.clone()],
            ..Inventory::default()
        },
    );
    let log = Log::open(&policy.audit_log).unwrap();
    let mut gate = Gate::new(policy, Some(pins), Box::new(log));
    gate.from_client(&line(
        &json!({"jsonrpc": "2.0", "id": "list", "method": "tools/list"}),
    ));
    gate.from_server(&line(
        &json!({"jsonrpc": "2.0", "id": "list", "result": {"tools": [tool]}}),
    ));

    // A typical exchange: about 1 KB of arguments, about 10 KB of results.
    let query = "how do I rotate the signing keys for the staging cluster ".repeat(18);
    let paragraph = "The gateway checks every token against the provider's keys, then forwards the call with its own credential. See https://example.com/docs/gateway for details. ";
    let result = paragraph.repeat(60);
    let mut timings = Vec::with_capacity(ROUNDS as usize * 2);
    for round in 0..ROUNDS + 100 {
        let call = line(
            &json!({"jsonrpc": "2.0", "id": round, "method": "tools/call",
            "params": {"name": "search", "arguments": {"message": query, "limit": 5}}}),
        );
        let answer = line(&json!({"jsonrpc": "2.0", "id": round,
            "result": {"content": [{"type": "text", "text": result}]}}));
        let started = Instant::now();
        let forwarded = gate.from_client(&call);
        let middle = Instant::now();
        let returned = gate.from_server(&answer);
        let finished = Instant::now();
        assert_eq!((forwarded.len(), returned.len()), (1, 1));
        if round >= 100 {
            // The first rounds warm caches up.
            timings.push(middle - started);
            timings.push(finished - middle);
        }
    }
    timings.sort();
    let (p50, p95, p99) = (
        percentile(&timings, 0.50),
        percentile(&timings, 0.95),
        percentile(&timings, 0.99),
    );
    println!(
        "gate latency per message over {} messages: p50 {p50:?}, p95 {p95:?}, p99 {p99:?}, max {:?}",
        timings.len(),
        timings.last().unwrap()
    );
    let _ = std::fs::remove_dir_all(Path::new(&dir));
    assert!(p50 < BUDGET, "p50 {p50:?} is over the {BUDGET:?} budget");
}
