//! The audit log: one JSON line per decision the gate makes, each carrying
//! the hash of the line before it.
//!
//! A line's `hash` is the SHA-256 of the line's exact bytes without the
//! `hash` field, and its `prev` is the hash of the line before it (the first
//! line's `prev` is [`GENESIS`]). Editing any byte breaks that line's hash;
//! removing, adding or reordering lines breaks the links. [`verify`] reports
//! the first line where either happens.
//!
//! What a chain can't show on its own: lines cut off the end, or a whole log
//! rewritten with fresh hashes. Saving the head hash somewhere else and
//! checking for it later (`verify` with an anchor) catches both.
//!
//! The log records decisions and hashes, never message content: see
//! [`Event`].

mod event;
mod log;
mod time;
mod verify;

pub use event::{Event, EventKind, MessageKind, Origin, Verdict};
pub use log::{AuditError, Log, Recorder};
pub use verify::{Problem, Report, VerifyError, verify, verify_reader};

use sha2::{Digest, Sha256};

/// The `prev` of a log's first entry.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Every line ends with `,"hash":"<64 hex digits>"}`.
const HASH_PREFIX: &[u8] = b",\"hash\":\"";
const HASH_SUFFIX_LEN: usize = HASH_PREFIX.len() + 64 + 2;

/// Adds the hash to an entry serialized without one. Returns the line
/// (newline included) and its hash.
fn seal(mut body: Vec<u8>) -> (Vec<u8>, String) {
    let hash = sha256_hex(&body);
    body.pop(); // the closing `}`
    body.extend_from_slice(HASH_PREFIX);
    body.extend_from_slice(hash.as_bytes());
    body.extend_from_slice(b"\"}\n");
    (body, hash)
}

/// An entry whose line matched its own hash.
struct Sealed {
    hash: String,
    fields: serde_json::Value,
}

/// Checks one line (without its newline) against its own hash.
fn unseal(line: &[u8]) -> Result<Sealed, Problem> {
    let Some(split) = line.len().checked_sub(HASH_SUFFIX_LEN) else {
        return Err(Problem::NotAnEntry);
    };
    let (head, suffix) = line.split_at(split);
    let hash = &suffix[HASH_PREFIX.len()..HASH_PREFIX.len() + 64];
    let well_formed = head.len() > 1
        && suffix.starts_with(HASH_PREFIX)
        && suffix.ends_with(b"\"}")
        && hash
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
    if !well_formed {
        return Err(Problem::NotAnEntry);
    }
    let mut body = head.to_vec();
    body.push(b'}');
    let hash = String::from_utf8_lossy(hash).into_owned();
    if sha256_hex(&body) != hash {
        return Err(Problem::Edited);
    }
    let fields: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| Problem::NotAnEntry)?;
    if !fields.is_object() {
        return Err(Problem::NotAnEntry);
    }
    Ok(Sealed { hash, fields })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_line_unseals_and_any_edit_breaks_it() {
        let (line, hash) = seal(br#"{"seq":1,"verdict":"block"}"#.to_vec());
        assert!(line.ends_with(b"\"}\n"));
        let line = &line[..line.len() - 1];
        let sealed = unseal(line).unwrap();
        assert_eq!(sealed.hash, hash);
        assert_eq!(sealed.fields["verdict"], "block");

        let edited = String::from_utf8(line.to_vec())
            .unwrap()
            .replace("block", "allow");
        assert!(matches!(unseal(edited.as_bytes()), Err(Problem::Edited)));
        let spaced = String::from_utf8(line.to_vec()).unwrap().replace(':', ": ");
        assert!(matches!(
            unseal(spaced.as_bytes()),
            Err(Problem::Edited | Problem::NotAnEntry)
        ));
    }

    #[test]
    fn rejects_lines_that_are_not_entries() {
        for line in [
            &b""[..],
            b"{}",
            b"not json at all, but long enough to hold a hash suffix of seventy-five bytes",
        ] {
            assert!(matches!(unseal(line), Err(Problem::NotAnEntry)), "{line:?}");
        }
        let (line, _) = seal(b"[1,2]".to_vec());
        assert!(unseal(&line[..line.len() - 1]).is_err());
    }
}
