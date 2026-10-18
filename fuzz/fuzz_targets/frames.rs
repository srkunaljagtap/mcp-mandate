//! Any byte stream read as newline-framed messages, in small chunks:
//! framing must never panic or return a frame over the limit.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcp_mandate_proxy::framing::read_frame;

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    runtime.block_on(async {
        let mut reader = tokio::io::BufReader::with_capacity(7, data);
        let mut frame = Vec::new();
        while let Ok(true) = read_frame(&mut reader, &mut frame, 1024).await {
            assert!(frame.len() <= 1024);
        }
    });
});
