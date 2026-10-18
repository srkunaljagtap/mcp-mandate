//! Soak test: tens of thousands of messages through the real binary, checking
//! that its memory stays flat once warmed up. Linux only (it reads /proc).
//! Slow, so it runs on request:
//!
//!   cargo test --release -p mcp-mandate --test soak -- --ignored --nocapture
#![cfg(target_os = "linux")]

mod common;

use common::{Session, temp_file};
use mcp_mandate_pin::{Inventory, Pins};
use serde_json::{Value, json};

/// A server that answers every request with the id it was sent: the tool
/// list, a tool result carrying a key (so every answer is redacted), or an
/// empty result.
const SERVER: &str = r#"while IFS= read -r line; do
  case $line in *'"id":'*) ;; *) continue ;; esac
  rest=${line#*\"id\":}; id=${rest%%,*}; id=${id%%\}*}
  case $line in
    *'"tools/list"'*) printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[$TOOL]}}" ;;
    *'"tools/call"'*) printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok AKIAIOSFODNN7EXAMPLE\"}]}}" ;;
    *) printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{}}" ;;
  esac
done"#;

fn echo_tool() -> Value {
    json!({
        "name": "echo",
        "description": "Echoes",
        "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": true, "openWorldHint": false}
    })
}

/// Resident memory of process `pid`, in KiB.
fn resident_kib(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmRSS in /proc/<pid>/status")
}

/// Sends `count` calls starting at id `first`, in batches, checking each
/// answer: allowed calls come back redacted, the unapproved one blocked.
fn calls(session: &mut Session, first: u64, count: u64) {
    const BATCH: u64 = 100;
    let mut id = first;
    while id < first + count {
        let end = (id + BATCH).min(first + count);
        for n in id..end {
            // Every tenth call names a tool that was never approved.
            let tool = if n % 10 == 0 { "sneaky" } else { "echo" };
            session.send(&json!({"jsonrpc": "2.0", "id": n, "method": "tools/call",
                "params": {"name": tool, "arguments": {"n": n}}}));
        }
        for _ in id..end {
            let answer = session.recv();
            let text = answer["result"]["content"][0]["text"].as_str().unwrap();
            assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "{answer}");
        }
        id = end;
    }
}

#[test]
#[ignore = "slow; run on request (see the module docs)"]
fn memory_stays_flat_over_many_messages() {
    let approved = Inventory {
        tools: vec![echo_tool()],
        ..Inventory::default()
    };
    let pins = temp_file(
        "soak.pins.toml",
        &Pins::from_inventory("soak", &approved).to_toml(),
    );
    let policy = temp_file(
        "soak.policy.toml",
        &format!(
            "pins = \"{}\"\n[[tools]]\nmatch = \"echo\"\naction = \"allow\"\n",
            pins.display()
        ),
    );
    let envs = [("TOOL".to_owned(), echo_tool().to_string())];
    let policy = policy.display().to_string();
    let mut session = Session::start(
        &["run", "--policy", &policy, "--", "sh", "-c", SERVER],
        &envs,
    );

    session.send(&json!({"jsonrpc": "2.0", "id": 0, "method": "tools/list"}));
    assert_eq!(session.recv()["result"]["tools"][0]["name"], "echo");

    calls(&mut session, 1, 2_000);
    let warmed = resident_kib(session.pid());
    calls(&mut session, 2_001, 20_000);
    let after = resident_kib(session.pid());
    println!("resident memory: {warmed} KiB after 2,000 calls, {after} KiB after 22,000");

    let (status, logs) = session.finish();
    assert!(status.success(), "{logs}");
    // Allocator noise is a few hundred KiB; a per-message leak of even 100
    // bytes would add about 2 MiB over 20,000 calls.
    assert!(
        after <= warmed + 1024,
        "memory grew from {warmed} KiB to {after} KiB"
    );
}
