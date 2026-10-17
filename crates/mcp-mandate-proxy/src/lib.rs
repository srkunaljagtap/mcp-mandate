//! Transports for mcp-mandate. Every MCP message between an agent and a
//! server passes through here on its way to and from the gate.

pub mod framing;
mod process;
pub mod stdio;
