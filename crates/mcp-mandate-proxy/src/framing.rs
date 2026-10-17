//! Line framing for MCP's stdio transport: one JSON-RPC message per line.

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Largest single message accepted, newline included. Tool results can carry
/// base64 images, so this is generous; anything bigger ends the session
/// instead of being buffered without limit.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("message is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Reads one newline-terminated frame into `buf`, newline included.
///
/// Returns `Ok(false)` at end of stream. A last frame without a trailing
/// newline is still returned.
pub async fn read_frame<R>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> Result<bool, FrameError>
where
    R: AsyncBufRead + Unpin,
{
    buf.clear();
    loop {
        let (used, complete) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(!buf.is_empty());
            }
            let (used, complete) = match available.iter().position(|&byte| byte == b'\n') {
                Some(newline) => (newline + 1, true),
                None => (available.len(), false),
            };
            if buf.len() + used > limit {
                return Err(FrameError::TooLarge { limit });
            }
            buf.extend_from_slice(&available[..used]);
            (used, complete)
        };
        reader.consume(used);
        if complete {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn frames(input: &[u8], limit: usize) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut reader = tokio::io::BufReader::with_capacity(4, input);
        let mut frame = Vec::new();
        let mut frames = Vec::new();
        while read_frame(&mut reader, &mut frame, limit).await? {
            frames.push(frame.clone());
        }
        Ok(frames)
    }

    #[tokio::test]
    async fn splits_lines_and_keeps_their_endings() {
        let frames = frames(b"{\"a\":1}\n{\"b\":2}\r\n{\"c\":3}", 1024)
            .await
            .unwrap();
        assert_eq!(
            frames,
            [&b"{\"a\":1}\n"[..], b"{\"b\":2}\r\n", b"{\"c\":3}"]
        );
    }

    #[tokio::test]
    async fn refuses_frames_over_the_limit() {
        let error = frames(b"0123456789\n", 8).await.unwrap_err();
        assert!(matches!(error, FrameError::TooLarge { limit: 8 }));
    }
}

#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn frames_are_the_same_whatever_the_chunk_size(lines in prop::collection::vec("[ -~]{0,40}", 1..8), capacity in 1usize..16) {
            let input: Vec<u8> = lines.iter().flat_map(|line| format!("{line}\n").into_bytes()).collect();
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let frames = runtime.block_on(async {
                let mut reader = tokio::io::BufReader::with_capacity(capacity, &input[..]);
                let mut frame = Vec::new();
                let mut frames = Vec::new();
                while read_frame(&mut reader, &mut frame, 1024).await.unwrap() {
                    frames.push(String::from_utf8(frame.clone()).unwrap());
                }
                frames
            });
            let expected: Vec<String> = lines.iter().map(|line| format!("{line}\n")).collect();
            prop_assert_eq!(frames, expected);
        }

        #[test]
        fn oversized_input_is_refused_not_buffered(length in 65usize..512) {
            let input = vec![b'x'; length];
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let result = runtime.block_on(async {
                let mut reader = tokio::io::BufReader::with_capacity(8, &input[..]);
                let mut frame = Vec::new();
                read_frame(&mut reader, &mut frame, 64).await
            });
            prop_assert!(result.is_err());
        }
    }
}
