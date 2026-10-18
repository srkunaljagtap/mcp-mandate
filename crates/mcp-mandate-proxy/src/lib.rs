//! Transports for mcp-mandate. Every MCP message between an agent and a
//! server passes through here on its way to and from the gate: over stdio
//! for local servers (`run`), or over HTTPS for remote ones (`gate`).

pub mod agent_taint;
mod error;
pub mod framing;
pub mod gateway;
mod inventory;
mod process;
pub mod stdio;

pub use error::ProxyError;
