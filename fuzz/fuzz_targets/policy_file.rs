//! Any text read as a policy: it parses or fails cleanly, and a parsed
//! policy decides for any tool name without panicking.
#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use mcp_mandate_policy::Policy;

fuzz_target!(|text: &str| {
    if let Ok(policy) = Policy::parse(text, Path::new(".")) {
        for name in ["echo", "", "*", "a/b", "\u{0435}cho"] {
            let _ = policy.for_tool(name);
        }
    }
});
