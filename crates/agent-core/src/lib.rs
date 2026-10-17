//! Core building blocks for the agent: the Claude API client, request and
//! response types, and errors.

mod client;
mod error;
mod types;

// Re-export so callers write `agent_core::Client`, not
// `agent_core::client::Client`. The module layout stays private and free to
// change.
pub use client::Client;
pub use error::Error;
pub use types::{
    ContentBlock, Effort, Message, MessagesRequest, MessagesResponse, OutputConfig, Role,
    StopReason, Usage,
};

/// This crate's version, baked in at compile time from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One-line name and version, shown when the CLI starts.
pub fn banner() -> String {
    format!("rust-agent v{VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_includes_name_and_version() {
        let banner = banner();
        assert!(banner.starts_with("rust-agent v"));
        assert!(banner.ends_with(VERSION));
    }
}
