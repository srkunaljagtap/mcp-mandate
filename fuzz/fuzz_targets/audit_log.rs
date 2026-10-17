//! Any file checked as an audit log: verification must never panic, and
//! must never call a log with unsealed lines intact.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcp_mandate_audit::verify_reader;

fuzz_target!(|data: &[u8]| {
    if let Ok(report) = verify_reader(data, None) {
        assert_eq!(report.entries as usize, data.iter().filter(|&&byte| byte == b'\n').count());
    }
});
