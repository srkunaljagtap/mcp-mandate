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

/// Calls a list method, following `nextCursor` across pages.
async fn list_all(rpc: &mut impl Rpc, method: &str, field: &str) -> Result<Vec<Value>, ProxyError> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let params = match &cursor {
            Some(cursor) => json!({"cursor": cursor}),
            None => json!({}),
        };
        let result = rpc.request(method, params).await?;
        if let Some(page) = result.get(field).and_then(Value::as_array) {
            items.extend(page.iter().cloned());
        }
        match result.get("nextCursor").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_owned()),
            None => return Ok(items),
        }
    }
    warn!(
        method,
        pages = MAX_PAGES,
        "stopped listing after too many pages"
    );
    Ok(items)
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
