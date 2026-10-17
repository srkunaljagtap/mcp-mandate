//! Rust versions of the JSON the Messages API sends and receives.
//!
//! serde's derive macros generate the JSON conversion code from these
//! definitions, so the field names here must match the API's names exactly
//! (or be renamed with `#[serde(rename = ...)]`).

use serde::{Deserialize, Serialize};

/// Who wrote a message in the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

/// One turn of the conversation we send to Claude.
///
/// Content is plain text for now; it becomes a list of blocks once tool
/// results need to be sent back.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
}

impl Message {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: content.into(),
        }
    }
}

/// How much thinking and output Claude spends on a reply: the main
/// cost/quality dial. Claude Opus 5.5 defaults to `Medium`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OutputConfig {
    pub effort: Effort,
}

/// The body of `POST /v1/messages`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MessagesRequest {
    pub model: String,
    /// Hard cap on output tokens for this reply (thinking included).
    pub max_tokens: u32,
    // `skip_serializing_if` leaves the field out of the JSON entirely when
    // it's None, instead of sending `"system": null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_config: Option<OutputConfig>,
    /// `"default"` asks the API to retry a declined request on a fallback
    /// model server-side instead of returning the refusal. Needs a beta
    /// header, which the client adds when this is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallbacks: Option<String>,
}

impl MessagesRequest {
    /// A request with server-side refusal fallbacks switched on.
    pub fn new(model: impl Into<String>, max_tokens: u32, messages: Vec<Message>) -> Self {
        Self {
            model: model.into(),
            max_tokens,
            system: None,
            messages,
            output_config: None,
            fallbacks: Some("default".to_owned()),
        }
    }

    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    pub fn with_effort(mut self, effort: Effort) -> Self {
        self.output_config = Some(OutputConfig { effort });
        self
    }
}

/// One block of Claude's reply. A reply is a list of these.
///
/// `#[serde(tag = "type")]` reads the block's `"type"` field to pick the
/// variant: `{"type": "text", "text": "Hi"}` becomes `ContentBlock::Text`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    /// Claude's reasoning. On current models the text is empty unless you
    /// ask for a summary; the signature lets the API verify the block if
    /// it's sent back in a later turn.
    Thinking {
        #[serde(default)]
        thinking: String,
        #[serde(default)]
        signature: String,
    },
    /// Any block type this code doesn't handle yet, such as tool calls.
    /// Without this catch-all, a new block type from the API would make the
    /// whole reply fail to parse.
    #[serde(other)]
    Unknown,
}

/// Why Claude stopped writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Finished naturally.
    EndTurn,
    /// Hit `max_tokens`; the reply is cut off.
    MaxTokens,
    StopSequence,
    /// Wants to call a tool.
    ToolUse,
    /// A long server-side turn paused; send the reply back to continue.
    PauseTurn,
    /// Declined by a safety classifier. Check this before reading content.
    Refusal,
    #[serde(other)]
    Other,
}

/// Tokens billed for this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// The body of a successful `POST /v1/messages` response.
///
/// Fields the API sends that aren't listed here are ignored by serde.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct MessagesResponse {
    pub id: String,
    /// The model that actually answered (differs from the request's model
    /// if a refusal fallback kicked in).
    pub model: String,
    pub content: Vec<ContentBlock>,
    pub stop_reason: Option<StopReason>,
    pub usage: Usage,
}

impl MessagesResponse {
    /// The reply's text: every `Text` block joined in order, with nothing
    /// added between them. `Thinking` and `Unknown` blocks are skipped.
    pub fn text(&self) -> String {
        let mut result = String::new();

        // `&self.content` borrows the list, so we can read the blocks
        // without taking them away from the response.
        for block in &self.content {
            if let ContentBlock::Text { text } = block {
                result.push_str(text);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_leaves_out_unset_optional_fields() {
        let request = MessagesRequest::new("claude-opus-5-5", 1024, vec![Message::user("Hi")]);

        let body = serde_json::to_value(&request).unwrap();

        assert_eq!(
            body,
            json!({
                "model": "claude-opus-5-5",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "Hi"}],
                "fallbacks": "default"
            })
        );
    }

    #[test]
    fn request_includes_system_and_effort_when_set() {
        let request = MessagesRequest::new("claude-opus-5-5", 1024, vec![Message::user("Hi")])
            .with_system("Be brief.")
            .with_effort(Effort::Low);

        let body = serde_json::to_value(&request).unwrap();

        assert_eq!(body["system"], "Be brief.");
        assert_eq!(body["output_config"], json!({"effort": "low"}));
    }

    #[test]
    fn response_parses_known_and_unknown_blocks() {
        let body = json!({
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-5-5",
            "content": [
                {"type": "thinking", "thinking": "", "signature": "sig"},
                {"type": "text", "text": "Hello"},
                {"type": "some_future_block", "data": 42}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 0}
        });

        let response: MessagesResponse = serde_json::from_value(body).unwrap();

        assert_eq!(
            response.content,
            vec![
                ContentBlock::Thinking {
                    thinking: String::new(),
                    signature: "sig".to_owned()
                },
                ContentBlock::Text {
                    text: "Hello".to_owned()
                },
                ContentBlock::Unknown,
            ]
        );
        assert_eq!(response.stop_reason, Some(StopReason::EndTurn));
        assert_eq!(response.usage.output_tokens, 5);
    }

    #[test]
    fn unknown_stop_reason_does_not_fail_parsing() {
        let reason: StopReason = serde_json::from_value(json!("brand_new_reason")).unwrap();
        assert_eq!(reason, StopReason::Other);
    }
}

/// Tests for `MessagesResponse::text`.
#[cfg(test)]
mod text_tests {
    use super::*;

    fn response_with(content: Vec<ContentBlock>) -> MessagesResponse {
        MessagesResponse {
            id: "msg_test".to_owned(),
            model: "claude-opus-5-5".to_owned(),
            content,
            stop_reason: Some(StopReason::EndTurn),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
            },
        }
    }

    fn text(s: &str) -> ContentBlock {
        ContentBlock::Text { text: s.to_owned() }
    }

    #[test]
    fn text_joins_text_blocks_in_order() {
        let response = response_with(vec![text("Hello, "), text("world")]);
        assert_eq!(response.text(), "Hello, world");
    }

    #[test]
    fn text_skips_thinking_and_unknown_blocks() {
        let response = response_with(vec![
            ContentBlock::Thinking {
                thinking: "private reasoning".to_owned(),
                signature: "sig".to_owned(),
            },
            text("Answer"),
            ContentBlock::Unknown,
        ]);
        assert_eq!(response.text(), "Answer");
    }

    #[test]
    fn text_is_empty_when_there_are_no_text_blocks() {
        let response = response_with(vec![ContentBlock::Unknown]);
        assert_eq!(response.text(), "");
    }
}
