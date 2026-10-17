//! Scout reviews MCP servers before you trust them: a rule-based scan of
//! their tools, an optional LLM review with your own API key, and a draft
//! policy for you to approve. Scout only proposes; the gate decides.

pub mod claude;
