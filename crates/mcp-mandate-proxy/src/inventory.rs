//! Listing everything a server offers, over any transport: the MCP
//! handshake, then each list method it supports, page by page. This is
//! what `mcp-mandate pin` records and Scout reviews.

use mcp_mandate_pin::Inventory;
use serde_json::{Value, json};
use tracing::warn;

use crate::ProxyError;

/// The protocol version mcp-mandate asks for when it talks to a server
/// itself.
pub(crate) const PROTOCOL_VERSION: &str = "2025-06-18";

/// Most pages read from one list before giving up.
const MAX_PAGES: usize = 100;
/// Most items one list may hold. Far more than any honest server offers;
/// a hostile one could otherwise fill memory, and make the review that
/// follows crawl.
const MAX_ITEMS: usize = 10_000;
/// Most values (object keys included) one reply may hold, as in one message
/// the gate checks. A reply is read whole, where each value takes many
/// times its size in the text, so a reply of tiny values (`[{},{},…]`)
/// could otherwise fill memory before the limits above are checked.
const MAX_VALUES: usize = 1_000_000;

/// A way to send requests to an MCP server.
pub(crate) trait Rpc {
    /// Sends a request and returns its `result`.
    async fn request(&mut self, method: &str, params: Value) -> Result<Value, ProxyError>;
    /// Sends a notification.
    async fn notify(&mut self, method: &str) -> Result<(), ProxyError>;
}

/// Does the handshake and lists everything the server offers.
pub(crate) async fn collect(rpc: &mut impl Rpc) -> Result<Inventory, ProxyError> {
    let init = rpc
        .request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-mandate", "version": env!("CARGO_PKG_VERSION")}
            }),
        )
        .await?;
    rpc.notify("notifications/initialized").await?;

    let offers = |capability: &str| {
        init.get("capabilities")
            .and_then(|caps| caps.get(capability))
            .is_some()
    };
    let mut inventory = Inventory {
        instructions: init
            .get("instructions")
            .and_then(Value::as_str)
            .map(str::to_owned),
        ..Inventory::default()
    };
    if offers("tools") {
        inventory.tools = list_all(rpc, "tools/list", "tools").await?;
    }
    if offers("prompts") {
        inventory.prompts = list_all(rpc, "prompts/list", "prompts").await?;
    }
    if offers("resources") {
        inventory.resources = list_all(rpc, "resources/list", "resources").await?;
        // Templates are optional even for servers with resources, so a
        // server that doesn't list them is recorded as having none, with a
        // warning. A list too long to read whole is an error, as for the
        // other lists.
        inventory.resource_templates =
            match list_all(rpc, "resources/templates/list", "resourceTemplates").await {
                Ok(templates) => templates,
                Err(error @ ProxyError::TooLong { .. }) => return Err(error),
                Err(error) => {
                    warn!(
                        %error,
                        "the server didn't list its resource templates, so none are recorded"
                    );
                    Vec::new()
                }
            };
    }
    Ok(inventory)
}

/// Calls a list method, following `nextCursor` across pages. A list too
/// long to read whole is an error: a partial one would pin or review only
/// some of what the server offers.
async fn list_all(rpc: &mut impl Rpc, method: &str, field: &str) -> Result<Vec<Value>, ProxyError> {
    let too_long = |limit: String| ProxyError::TooLong {
        method: method.to_owned(),
        limit,
    };
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let params = match &cursor {
            Some(cursor) => json!({"cursor": cursor}),
            None => json!({}),
        };
        let mut result = rpc.request(method, params).await?;
        if let Some(Value::Array(page)) = result.get_mut(field).map(Value::take) {
            items.extend(page);
        }
        if items.len() > MAX_ITEMS {
            return Err(too_long(format!("{MAX_ITEMS} items")));
        }
        match result.get("nextCursor").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_owned()),
            None => return Ok(items),
        }
    }
    Err(too_long(format!("{MAX_PAGES} pages")))
}

/// Parses a message the server sent while being listed: `None` if it isn't
/// JSON. One with more than [`MAX_VALUES`] values is an error, found before
/// it's parsed.
pub(crate) fn read_reply(method: &str, bytes: &[u8]) -> Result<Option<Value>, ProxyError> {
    if most_values(bytes) > MAX_VALUES {
        return Err(ProxyError::TooLong {
            method: method.to_owned(),
            limit: format!("{MAX_VALUES} values in one reply"),
        });
    }
    Ok(serde_json::from_slice(bytes).ok())
}

/// The most values (object keys included) that JSON text can hold, counted
/// without parsing it: each one but the first follows a `[`, `{`, `,` or
/// `:` outside a string.
fn most_values(bytes: &[u8]) -> usize {
    let mut count = 1;
    let (mut in_string, mut escaped) = (false, false);
    for &byte in bytes {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'[' | b'{' | b',' | b':' => count += 1,
                _ => {}
            }
        }
    }
    count
}

/// The `result` of a JSON-RPC response, taken out of it rather than copied,
/// or the server's error as a [`ProxyError`].
pub(crate) fn result_of(method: &str, mut message: Value) -> Result<Value, ProxyError> {
    if let Some(error) = message.get("error") {
        return Err(ProxyError::Server {
            method: method.to_owned(),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("no message")
                .to_owned(),
        });
    }
    Ok(message
        .get_mut("result")
        .map(Value::take)
        .unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server whose tool list never ends: each page holds `per_page`
    /// tools and points to another.
    struct Endless {
        per_page: usize,
    }

    impl Rpc for Endless {
        async fn request(&mut self, method: &str, _: Value) -> Result<Value, ProxyError> {
            let tools: Vec<Value> = (0..self.per_page)
                .map(|n| json!({"name": format!("t{n}")}))
                .collect();
            Ok(match method {
                "initialize" => json!({"capabilities": {"tools": {}}}),
                _ => json!({"tools": tools, "nextCursor": "more"}),
            })
        }

        async fn notify(&mut self, _: &str) -> Result<(), ProxyError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_list_too_long_to_read_whole_is_an_error() {
        // Too many pages, and too many items.
        for per_page in [0, 5_000] {
            let listed = collect(&mut Endless { per_page }).await;
            assert!(
                matches!(listed, Err(ProxyError::TooLong { .. })),
                "{per_page} per page: {:?}",
                listed.map(|inventory| inventory.tools.len())
            );
        }
    }

    /// A server with one resource, whose resource templates list answers
    /// with `templates`.
    struct WithTemplates {
        templates: fn() -> Result<Value, ProxyError>,
    }

    impl Rpc for WithTemplates {
        async fn request(&mut self, method: &str, _: Value) -> Result<Value, ProxyError> {
            match method {
                "initialize" => Ok(json!({"capabilities": {"resources": {}}})),
                "resources/list" => Ok(json!({"resources": [{"name": "r", "uri": "file:///r"}]})),
                _ => (self.templates)(),
            }
        }

        async fn notify(&mut self, _: &str) -> Result<(), ProxyError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn too_many_templates_is_an_error_but_no_templates_list_is_none() {
        let too_many = || -> Result<Value, ProxyError> {
            Ok(json!({"resourceTemplates": vec![json!({"name": "t"}); MAX_ITEMS + 1]}))
        };
        let listed = collect(&mut WithTemplates {
            templates: too_many,
        })
        .await;
        assert!(
            matches!(listed, Err(ProxyError::TooLong { .. })),
            "{:?}",
            listed.map(|inventory| inventory.resource_templates.len())
        );
        let unsupported = || -> Result<Value, ProxyError> {
            Err(ProxyError::Server {
                method: "resources/templates/list".to_owned(),
                message: "Method not found".to_owned(),
            })
        };
        let listed = collect(&mut WithTemplates {
            templates: unsupported,
        })
        .await
        .unwrap();
        assert_eq!(listed.resources.len(), 1);
        assert!(listed.resource_templates.is_empty());
    }

    #[test]
    fn a_reply_of_too_many_values_is_refused_before_it_is_parsed() {
        // Each `{"a":1}` is 3 values in 8 bytes, and hundreds of bytes
        // once parsed.
        let tools = vec![r#"{"a":1}"#; MAX_VALUES / 2].join(",");
        let reply = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{tools}]}}}}"#);
        assert!(matches!(
            read_reply("tools/list", reply.as_bytes()),
            Err(ProxyError::TooLong { .. })
        ));
        // What's inside a string is one value, however it looks.
        let text = "[{,:\\\"".repeat(MAX_VALUES);
        let reply = json!({"jsonrpc": "2.0", "id": 1, "result": {"text": text}}).to_string();
        let message = read_reply("tools/list", reply.as_bytes()).unwrap().unwrap();
        assert_eq!(result_of("tools/list", message).unwrap()["text"], text);
        assert_eq!(most_values(br#"["a\"[,", {"b": [1, 2]}]"#), 7);
        assert!(read_reply("tools/list", b"not json").unwrap().is_none());
    }
}
