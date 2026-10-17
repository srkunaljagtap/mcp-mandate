//! Any server-sent event stream, split anywhere: parsing must never panic,
//! and no event may exceed the size limit.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcp_mandate_proxy::gateway::sse::Parser;

fuzz_target!(|data: &[u8]| {
    let Some((&split, stream)) = data.split_first() else {
        return;
    };
    let cut = usize::from(split) % (stream.len() + 1);
    let mut parser = Parser::new(4096);
    for chunk in [&stream[..cut], &stream[cut..]] {
        match parser.push(chunk) {
            Ok(events) => {
                for event in events {
                    assert!(event.data.len() <= 4096);
                }
            }
            Err(_) => return,
        }
    }
});
