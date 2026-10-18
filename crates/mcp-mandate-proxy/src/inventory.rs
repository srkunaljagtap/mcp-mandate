//! Listing everything a server offers, over any transport: the MCP
//! handshake, then each list method it supports, page by page. This is
//! what `mcp-mandate pin` records and Scout reviews.

use mcp_mandate_pin::Inventory;
use serde_json::{Value, json};

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
        // Templates are optional even for servers with resources.
        inventory.resource_templates =
            list_all(rpc, "resources/templates/list", "resourceTemplates")
                .await
                .unwrap_or_default();
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

/// The `result` of a JSON-RPC response, or the server's error as a
/// [`ProxyError`].
pub(crate) fn result_of(method: &str, message: &Value) -> Result<Value, ProxyError> {
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
    Ok(message.get("result").cloned().unwrap_or(Value::Null))
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
}
