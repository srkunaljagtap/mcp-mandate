//! Server-sent events, the streaming half of MCP's Streamable HTTP: reading
//! a server's stream event by event, and writing events to the client.

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
            id: None,
            kind: None,
        }
    }

    /// Feeds a chunk; returns the events it completed.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Event>, TooLarge> {
        let mut events = Vec::new();
        for &byte in chunk {
            if byte != b'\n' {
                self.line.push(byte);
                if self.line.len() > self.limit {
                    return Err(TooLarge(self.limit));
                }
                continue;
            }
            let line = std::mem::take(&mut self.line);
            let line = line.strip_suffix(b"\r").unwrap_or(&line);
            if let Some(event) = self.line_done(line)? {
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
            b"id" if !value.contains(&0) => {
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
    if let Some(id) = id.filter(|id| !id.contains(['\n', '\r'])) {
        out.extend_from_slice(b"id: ");
        out.extend_from_slice(id.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(b"event: message\n");
    let message = message.trim_ascii_end();
    for line in message.split(|&byte| byte == b'\n') {
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(line.strip_suffix(b"\r").unwrap_or(line));
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
    fn writes_what_it_reads() {
        let written = encode(Some("3"), b"{\n \"a\": 1\n}\n");
        let events = parse(&[&written]);
        assert_eq!(events[0].data, b"{\n \"a\": 1\n}");
        assert_eq!(events[0].id.as_deref(), Some("3"));
        let unsafe_id = encode(Some("3\ndata: x"), b"{}");
        assert!(!String::from_utf8(unsafe_id).unwrap().contains("data: x"));
    }
}
