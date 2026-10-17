//! A minimal client for the Claude Messages API, used by Scout's optional
//! LLM review. The gate never calls it.

mod client;
mod error;
mod types;

pub use client::Client;
pub use error::Error;
pub use types::{
    ContentBlock, Effort, Message, MessagesRequest, MessagesResponse, OutputConfig, Role,
    StopReason, Usage,
};
