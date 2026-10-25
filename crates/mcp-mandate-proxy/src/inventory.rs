//! Listing everything a server offers, over any transport: the MCP
//! handshake, then each list method it supports, page by page. This is
//! what `mcp-mandate pin` records and Scout reviews.

use mcp_mandate_gate::jsonrpc::{ParseError, classify};
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
/// Most memory everything listed from one server may take, in bytes as
/// [`kept`] estimates them: four times what the gate lets one message take.
/// Each reply is held to the gate's own limit as it's read (see
/// [`read_reply`]), but a list may span [`MAX_PAGES`] pages, there are four
/// lists, and every page's items are kept until the listing ends.
const MAX_KEPT: usize = 256_000_000;

/// A way to send requests to an MCP server.
pub(crate) trait Rpc {
    /// Sends a request and returns its `result`.
    async fn request(&mut self, method: &str, params: Value) -> Result<Value, ProxyError>;
    /// Sends a notification.
    async fn notify(&mut self, method: &str) -> Result<(), ProxyError>;
}

/// Does the handshake and lists everything the server offers.
pub(crate) async fn collect(rpc: &mut impl Rpc) -> Result<Inventory, ProxyError> {
    let mut budget = Budget::new(MAX_KEPT);
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
    budget.charge("initialize", std::slice::from_ref(&init))?;
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
        inventory.tools = list_all(rpc, "tools/list", "tools", &mut budget).await?;
    }
    if offers("prompts") {
        inventory.prompts = list_all(rpc, "prompts/list", "prompts", &mut budget).await?;
    }
    if offers("resources") {
        inventory.resources = list_all(rpc, "resources/list", "resources", &mut budget).await?;
        // Templates are optional even for servers with resources, so a
        // server that doesn't list them is recorded as having none, with a
        // warning. A list too long to read whole is an error, as for the
        // other lists.
        let templates = list_all(
            rpc,
            "resources/templates/list",
            "resourceTemplates",
            &mut budget,
        )
        .await;
        inventory.resource_templates = match templates {
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
async fn list_all(
    rpc: &mut impl Rpc,
    method: &str,
    field: &str,
    budget: &mut Budget,
) -> Result<Vec<Value>, ProxyError> {
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
            budget.charge(method, &page)?;
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

/// How much memory a listing may still take with what it keeps.
struct Budget {
    total: usize,
    left: usize,
}

impl Budget {
    fn new(total: usize) -> Self {
        Self { total, left: total }
    }

    /// Takes what keeping `values` costs, or fails if the listing would
    /// then keep more than it may.
    fn charge(&mut self, method: &str, values: &[Value]) -> Result<(), ProxyError> {
        let cost = values.iter().map(kept).fold(0, usize::saturating_add);
        self.left = self
            .left
            .checked_sub(cost)
            .ok_or_else(|| ProxyError::TooLong {
                method: method.to_owned(),
                limit: format!(
                    "{} MB in memory, counting all its lists",
                    self.total / 1_000_000
                ),
            })?;
        Ok(())
    }
}

/// Roughly how many bytes `value` takes in memory: what the gate counts for
/// a message it checks (see `mcp_mandate_gate::jsonrpc`), plus the bytes of
/// its strings. The gate needn't count those, as a message's own size
/// bounds them, but over many replies they add up.
fn kept(value: &Value) -> usize {
    // The gate's weights: a slot for every value and key, and an allocation
    // of its own for every non-empty string, array and object.
    const VALUE: usize = 64;
    const STRING: usize = 32;
    const ARRAY: usize = 128;
    const OBJECT: usize = 640;
    let text = |text: &str| {
        if text.is_empty() {
            0
        } else {
            STRING + text.len()
        }
    };
    VALUE
        + match value {
            Value::String(string) => text(string),
            Value::Array(items) if !items.is_empty() => {
                ARRAY + items.iter().map(kept).sum::<usize>()
            }
            Value::Object(members) if !members.is_empty() => {
                OBJECT
                    + members
                        .iter()
                        .map(|(key, value)| VALUE + text(key) + kept(value))
                        .sum::<usize>()
            }
            _ => 0,
        }
}

/// Parses a message the server sent while being listed, refusing what the
/// gate refuses. One too large for the gate to check is an error, found
/// before it's parsed. Anything else the gate would drop (it isn't JSON,
/// isn't JSON-RPC, or repeats a key, say) is `None`, without being parsed.
pub(crate) fn read_reply(method: &str, bytes: &[u8]) -> Result<Option<Value>, ProxyError> {
    match classify(bytes) {
        Ok(_) => Ok(serde_json::from_slice(bytes).ok()),
        Err(ParseError::TooManyValues) => Err(ProxyError::TooLong {
            method: method.to_owned(),
            limit: "what the gate can check in one message".to_owned(),
        }),
        Err(_) => Ok(None),
    }
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

    /// A server whose every list has `pages` pages of one `item` each.
    struct Paged {
        item: Value,
        pages: usize,
    }

    impl Rpc for Paged {
        async fn request(&mut self, method: &str, params: Value) -> Result<Value, ProxyError> {
            let field = method.split('/').next().unwrap();
            let page: usize = params["cursor"]
                .as_str()
                .map_or(1, |cursor| cursor.parse().unwrap());
            let mut result = json!({});
            result[field] = json!([self.item.clone()]);
            if page < self.pages {
                result["nextCursor"] = json!((page + 1).to_string());
            }
            Ok(result)
        }

        async fn notify(&mut self, _: &str) -> Result<(), ProxyError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn what_a_listing_keeps_has_one_budget_across_pages_and_lists() {
        let item = json!({"name": "t", "description": "x".repeat(1_000)});
        let each = kept(&item);
        assert!(each > 1_000, "a string's bytes count: {each}");
        let mut rpc = Paged { item, pages: 3 };
        // Room for two lists of three pages, and no more.
        let mut budget = Budget::new(6 * each);
        let tools = list_all(&mut rpc, "tools/list", "tools", &mut budget).await;
        assert_eq!(tools.unwrap().len(), 3);
        let prompts = list_all(&mut rpc, "prompts/list", "prompts", &mut budget).await;
        assert_eq!(prompts.unwrap().len(), 3);
        let resources = list_all(&mut rpc, "resources/list", "resources", &mut budget).await;
        assert!(
            matches!(resources, Err(ProxyError::TooLong { .. })),
            "{resources:?}"
        );
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
    fn a_reply_the_gate_would_refuse_is_refused_before_it_is_parsed() {
        // 100,000 `{"":0}` are 300,000 values in 700 kB of text, but would
        // take over 80 MB once parsed: more than the gate reads of one
        // message.
        let tools = vec![r#"{"":0}"#; 100_000].join(",");
        let reply = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{tools}]}}}}"#);
        assert!(matches!(
            classify(reply.as_bytes()),
            Err(ParseError::TooManyValues)
        ));
        assert!(matches!(
            read_reply("tools/list", reply.as_bytes()),
            Err(ProxyError::TooLong { .. })
        ));
        // What's inside a string is one value, however it looks.
        let text = "[{,:\\\"".repeat(1_000_000);
        let reply = json!({"jsonrpc": "2.0", "id": 1, "result": {"text": text}}).to_string();
        let message = read_reply("tools/list", reply.as_bytes()).unwrap().unwrap();
        assert_eq!(result_of("tools/list", message).unwrap()["text"], text);
        // What the gate would drop is skipped like a line that isn't JSON,
        // and a repeated key is found before the rest is read.
        let repeated =
            format!(r#"{{"jsonrpc":"2.0","id":1,"id":1,"result":{{"tools":[{tools}]}}}}"#);
        assert!(
            read_reply("tools/list", repeated.as_bytes())
                .unwrap()
                .is_none()
        );
        let not_json_rpc = br#"{"id":1,"result":{"tools":[]}}"#;
        assert!(read_reply("tools/list", not_json_rpc).unwrap().is_none());
        assert!(read_reply("tools/list", b"not json").unwrap().is_none());
    }
}
