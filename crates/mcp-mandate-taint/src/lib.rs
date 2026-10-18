//! Taint tracking and secret detection.
//!
//! **Taint.** Once a session has read content nobody vouched for (a web
//! page, an email, an issue a stranger wrote), instructions hidden in it may
//! be steering the model. From then on, tools that can send data out are
//! held, so a hijacked model can't finish an exfiltration. [`Traits`] says
//! which tools read untrusted content and which can send data out.
//!
//! **Secrets.** [`SecretDetector`] spots API keys, tokens and private keys,
//! so they can be redacted from what servers return and blocked from what
//! tool calls send.

mod secrets;
mod traits;

pub use secrets::{SecretDetector, SecretPattern};
pub use traits::{Labels, Traits};
