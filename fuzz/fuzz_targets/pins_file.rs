//! Any text read as a pins file: it parses or fails cleanly, and parsed
//! pins check items without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcp_mandate_pin::{Kind, Pins};
use serde_json::json;

fuzz_target!(|text: &str| {
    if let Ok(pins) = toml::from_str::<Pins>(text) {
        let _ = pins.check(Kind::Tool, "echo", &json!({"name": "echo"}));
        let _ = pins.check_instructions("hello");
        let _ = pins.to_toml();
    }
});
