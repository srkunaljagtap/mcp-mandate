//! Pinning: fingerprints of everything an MCP server shows the model (tool,
//! prompt and resource descriptions, and its instructions), and the pins
//! file that records the fingerprints you approved.
//!
//! An item whose fingerprint no longer matches its pin has changed since you
//! approved it (a "rug pull") and is hidden; an item with no pin was never
//! approved and is hidden too.

mod fingerprint;
mod package;
mod pins;

pub use fingerprint::fingerprint;
pub use package::unpinned_package;
pub use pins::{FORMAT, Inventory, Kind, Pinned, Pins, PinsError, Verdict, is_hidden};
