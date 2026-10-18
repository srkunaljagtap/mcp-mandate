//! Server-sent events, the streaming half of MCP's Streamable HTTP: reading
//! a server's stream event by event, and writing events to the client.

/// Longest event id passed on; a longer one is dropped.
const MAX_ID_BYTES: usize = 256;

/// One event. Only events with no type or type `message` carry MCP
/// messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: Option<String>,
    pub kind: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
#[error("an event is larger than {0} bytes")]
pub struct TooLarge(usize);

/// Reads events from a byte stream that arrives in arbitrary chunks.
pub struct Parser {
    limit: usize,
    line: Vec<u8>,
    data: Vec<u8>,
    has_data: bool,
    /// The last byte was a CR, so an LF right after it ends nothing.
    after_cr: bool,
    id: Option<String>,
    kind: Option<String>,
}

impl Parser {
    /// A parser that refuses events (or lines) over `limit` bytes.
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            line: Vec::new(),
            data: Vec::new(),
            has_data: false,
            after_cr: false,
            id: None,
            kind: None,
        }
    }

    /// Feeds a chunk; returns the events it completed.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Event>, TooLarge> {
        let mut events = Vec::new();
        for &byte in chunk {
            // A line ends at LF, CR, or CRLF (counted once), as the spec says.
            if byte == b'\n' && self.after_cr {
                self.after_cr = false;
                continue;
            }
            self.after_cr = byte == b'\r';
            if byte != b'\n' && byte != b'\r' {
                self.line.push(byte);
                if self.line.len() > self.limit {
                    return Err(TooLarge(self.limit));
                }
                continue;
            }
            let line = std::mem::take(&mut self.line);
            if let Some(event) = self.line_done(&line)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    fn line_done(&mut self, line: &[u8]) -> Result<Option<Event>, TooLarge> {
        if line.is_empty() {
            if !self.has_data {
                self.kind = None;
                return Ok(None);
            }
            self.has_data = false;
            return Ok(Some(Event {
                id: self.id.clone(),
                kind: self.kind.take(),
                data: std::mem::take(&mut self.data),
            }));
        }
        if line.starts_with(b":") {
            return Ok(None); // a comment, often a keep-alive
        }
        let (field, value) = match line.iter().position(|&byte| byte == b':') {
            Some(colon) => {
                let value = &line[colon + 1..];
                (&line[..colon], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &b""[..]),
        };
        match field {
            b"data" => {
                if self.has_data {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(value);
                self.has_data = true;
                if self.data.len() > self.limit {
                    return Err(TooLarge(self.limit));
                }
            }
            b"id" if !value.contains(&0) && value.len() <= MAX_ID_BYTES => {
                self.id = Some(String::from_utf8_lossy(value).into_owned());
            }
            b"event" => self.kind = Some(String::from_utf8_lossy(value).into_owned()),
            _ => {} // `retry` and unknown fields
        }
        Ok(None)
    }
}

/// Writes one message as an event, keeping `id` so the client can resume.
pub fn encode(id: Option<&str>, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 32);
    if let Some(id) = id.filter(|id| id.len() <= MAX_ID_BYTES && !id.contains(['\n', '\r'])) {
        out.extend_from_slice(b"id: ");
        out.extend_from_slice(id.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(b"event: message\n");
    // Any line ending (LF, CR or CRLF) starts a new `data:` line, so a
    // client that splits on bare CRs reads the same message.
    let message = message.trim_ascii_end();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < message.len() {
        match message[index] {
            b'\r' | b'\n' => {
                lines.push(&message[start..index]);
                let crlf = message[index] == b'\r' && message.get(index + 1) == Some(&b'\n');
                index += if crlf { 2 } else { 1 };
                start = index;
            }
            _ => index += 1,
        }
    }
    lines.push(&message[start..]);
    for line in lines {
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.push(b'\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(chunks: &[&[u8]]) -> Vec<Event> {
        let mut parser = Parser::new(1024);
        chunks
            .iter()
            .flat_map(|chunk| parser.push(chunk).unwrap())
            .collect()
    }

    #[test]
    fn reads_events_split_across_chunks() {
        let events = parse(&[b"id: 7\nevent: mess", b"age\ndata: {\"a\"", b":1}\r\n\r\n"]);
        assert_eq!(
            events,
            [Event {
                id: Some("7".to_owned()),
                kind: Some("message".to_owned()),
                data: b"{\"a\":1}".to_vec(),
            }]
        );
    }

    #[test]
    fn joins_data_lines_and_skips_comments() {
        let events = parse(&[b": keep-alive\n\ndata: {\ndata: }\n\n"]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, b"{\n}");
        assert_eq!(events[0].id, None);
    }

    #[test]
    fn refuses_oversized_events() {
        let mut parser = Parser::new(8);
        assert!(parser.push(b"data: 0123456789\n").is_err());
    }

    #[test]
    fn a_bare_cr_ends_a_line_and_long_ids_are_dropped() {
        let long_id = "i".repeat(300);
        let stream = format!("id: {long_id}\rdata: {{}}\r\rdata: x\r\n\r\n");
        let events = parse(&[stream.as_bytes()]);
        assert_eq!(events.len(), 2);
        assert_eq!(
            (events[0].id.as_deref(), events[0].data.as_slice()),
            (None, &b"{}"[..])
        );
        let written = encode(Some(&long_id), b"{\r \"a\": 1\r}");
        let text = String::from_utf8(written).unwrap();
        assert!(!text.contains('\r'), "{text:?}");
        assert!(!text.contains("id:"), "{text:?}");
    }

    #[test]
    fn writes_what_it_reads() {
        let written = encode(Some("3"), b"{\n \"a\": 1\n}\n");
        let events = parse(&[&written]);
        assert_eq!(events[0].data, b"{\n \"a\": 1\n}");
        assert_eq!(events[0].id.as_deref(), Some("3"));
        let unsafe_id = encode(Some("3\ndata: x"), b"{}");
        assert!(!String::from_utf8(unsafe_id).unwrap().contains("data: x"));
    }
}

#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn any_stream_parses_without_panicking_or_overflowing(chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..16)) {
            let mut parser = Parser::new(128);
            for chunk in chunks {
                match parser.push(&chunk) {
                    Ok(events) => {
                        for event in events {
                            prop_assert!(event.data.len() <= 128);
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        #[test]
        fn what_is_written_reads_back_whatever_the_chunking(message in "[ -~]{1,200}", id in "[0-9a-z]{0,8}", split in any::<prop::sample::Index>()) {
            let written = encode(Some(&id).filter(|id| !id.is_empty()).map(String::as_str), message.as_bytes());
            let cut = split.index(written.len());
            let mut parser = Parser::new(1024);
            let mut events = parser.push(&written[..cut]).unwrap();
            events.extend(parser.push(&written[cut..]).unwrap());
            prop_assert_eq!(events.len(), 1);
            prop_assert_eq!(&events[0].data, message.trim_ascii_end().as_bytes());
        }
    }
}
