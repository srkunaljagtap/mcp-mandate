//! Transports for mcp-mandate. Every MCP message between an agent and a
//! server passes through here, which is where the gate's checks will hook in.

pub mod jsonrpc;
mod process;
pub mod stdio;
