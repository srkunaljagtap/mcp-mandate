//! Errors from the transports.

use std::time::Duration;

use crate::framing::FrameError;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("couldn't find `{program}` (is it installed and on PATH?)")]
    NotFound {
        program: String,
        #[source]
        source: which::Error,
    },
    #[error("couldn't start `{program}`")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("lost track of the MCP server process")]
    Wait(#[source] std::io::Error),
    #[error("the MCP server didn't answer within {} seconds", .0.as_secs())]
    Timeout(Duration),
    #[error("the MCP server closed its output before answering `{0}`")]
    Closed(String),
    #[error("the MCP server answered `{method}` with an error: {message}")]
    Server { method: String, message: String },
    #[error("couldn't read from the MCP server")]
    Frame(#[from] FrameError),
    #[error("couldn't write to the MCP server")]
    Io(#[from] std::io::Error),
    #[error("couldn't reach the MCP server")]
    Http(#[from] reqwest::Error),
    #[error("the MCP server answered `{method}` with HTTP {status}")]
    Status { method: String, status: u16 },
    #[error("the MCP server's reply to `{0}` isn't a JSON-RPC message")]
    BadReply(String),
    #[error("couldn't get a credential for the MCP server")]
    Credential(#[from] crate::gateway::CredentialError),
}
