//! Checking a log's chain.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::{GENESIS, unseal};

/// What a log that verified contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub entries: u64,
    pub sessions: usize,
    /// Sessions that started but have no end entry: still running, stopped
    /// abruptly, or cut off with the end of the log.
    pub unfinished: usize,
    /// The first and last entries' times.
    pub first: Option<String>,
    pub last: Option<String>,
    /// The last entry's hash ([`GENESIS`] for an empty log). Saved
    /// somewhere else, it lets a later check catch entries cut off the end
    /// or a rewritten log.
    pub head: String,
    /// The entry number where the anchor given to [`verify`] was found.
    pub anchor_at: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("couldn't read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("line {line}: {problem}")]
    Broken { line: u64, problem: Problem },
    #[error(
        "the saved head {anchor} isn't in the log: entries were cut off the end, or the log was rewritten, after it was saved"
    )]
    AnchorMissing { anchor: String },
}

/// What's wrong with a line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Problem {
    #[error("it isn't an audit entry")]
    NotAnEntry,
    #[error("it doesn't match its own hash: it was edited")]
    Edited,
    #[error("the log doesn't start with its first entry: entries before this one were removed")]
    MissingStart,
    #[error("it doesn't link to the line before it: entries were removed, added or reordered here")]
    Unlinked,
    #[error("it's numbered {found}, but {expected} comes next")]
    Sequence { expected: u64, found: u64 },
    #[error("it's incomplete: a write was cut short")]
    Incomplete,
}

/// Checks every line of the log at `path`: each must match its own hash,
/// link to the line before it, and be numbered in order. With an `anchor`
/// (a head hash saved earlier), also checks that the log still contains it.
pub fn verify(path: &Path, anchor: Option<&str>) -> Result<Report, VerifyError> {
    let read_error = |source| VerifyError::Read {
        path: path.to_owned(),
        source,
    };
    let file = File::open(path).map_err(read_error)?;
    // Waits out any write in progress, so the last line is whole.
    file.lock_shared().map_err(read_error)?;
    let mut reader = BufReader::new(&file);

    let mut report = Report {
        entries: 0,
        sessions: 0,
        unfinished: 0,
        first: None,
        last: None,
        head: GENESIS.to_owned(),
        anchor_at: None,
    };
    let mut sessions = HashSet::new();
    let mut open = HashSet::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).map_err(read_error)? == 0 {
            break;
        }
        let number = report.entries + 1;
        let broken = |problem| VerifyError::Broken {
            line: number,
            problem,
        };
        let Some(body) = line.strip_suffix(b"\n") else {
            return Err(broken(Problem::Incomplete));
        };
        let sealed = unseal(body).map_err(broken)?;
        let field = |name: &str| sealed.fields.get(name).and_then(Value::as_str);
        match field("prev") {
            Some(prev) if prev == report.head => {}
            _ if number == 1 => return Err(broken(Problem::MissingStart)),
            _ => return Err(broken(Problem::Unlinked)),
        }
        match sealed.fields.get("seq").and_then(Value::as_u64) {
            Some(seq) if seq == number => {}
            Some(found) => {
                return Err(broken(Problem::Sequence {
                    expected: number,
                    found,
                }));
            }
            None => return Err(broken(Problem::NotAnEntry)),
        }
        if let Some(session) = field("session") {
            sessions.insert(session.to_owned());
            match field("event") {
                Some("session-start") => {
                    open.insert(session.to_owned());
                }
                Some("session-end") => {
                    open.remove(session);
                }
                _ => {}
            }
        }
        if let Some(time) = field("time") {
            report.first.get_or_insert_with(|| time.to_owned());
            report.last = Some(time.to_owned());
        }
        if anchor == Some(sealed.hash.as_str()) {
            report.anchor_at = Some(number);
        }
        report.entries = number;
        report.head = sealed.hash;
    }
    let _ = file.unlock();

    if let Some(anchor) = anchor
        && report.anchor_at.is_none()
        && anchor != GENESIS
    {
        return Err(VerifyError::AnchorMissing {
            anchor: anchor.to_owned(),
        });
    }
    report.sessions = sessions.len();
    report.unfinished = open.len();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::log::tests::{message, temp_dir};
    use crate::{Event, EventKind, Log, Recorder, Verdict};

    /// A log of `count` entries; returns its path and lines.
    fn log_of(name: &str, count: usize) -> (PathBuf, Vec<String>) {
        let path = temp_dir(name).join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.record(&Event {
            event: EventKind::SessionStart,
            ..Event::default()
        })
        .unwrap();
        for _ in 1..count {
            log.record(&message(Verdict::Allow)).unwrap();
        }
        let lines = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        (path, lines)
    }

    fn rewrite(path: &Path, lines: &[String]) {
        let mut file = File::create(path).unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
    }

    fn broken_at(path: &Path) -> (u64, Problem) {
        match verify(path, None) {
            Err(VerifyError::Broken { line, problem }) => (line, problem),
            other => panic!("expected a broken chain, got {other:?}"),
        }
    }

    #[test]
    fn reports_an_intact_log() {
        let (path, lines) = log_of("intact", 4);
        let report = verify(&path, None).unwrap();
        assert_eq!(report.entries, 4);
        assert_eq!(report.sessions, 1);
        assert_eq!(report.unfinished, 1, "the session never ended");
        let last: Value = serde_json::from_str(&lines[3]).unwrap();
        assert_eq!(report.head, last["hash"]);
        assert!(report.first.unwrap() <= report.last.unwrap());
    }

    #[test]
    fn an_empty_log_is_intact() {
        let path = temp_dir("empty").join("audit.jsonl");
        File::create(&path).unwrap();
        let report = verify(&path, None).unwrap();
        assert_eq!((report.entries, report.head.as_str()), (0, GENESIS));
    }

    #[test]
    fn finds_an_edited_line() {
        let (path, mut lines) = log_of("edited", 4);
        lines[2] = lines[2].replace("\"allow\"", "\"block\"");
        rewrite(&path, &lines);
        assert_eq!(broken_at(&path), (3, Problem::Edited));
    }

    #[test]
    fn finds_a_removed_line() {
        let (path, mut lines) = log_of("removed", 4);
        lines.remove(1);
        rewrite(&path, &lines);
        assert_eq!(broken_at(&path), (2, Problem::Unlinked));
    }

    #[test]
    fn finds_a_removed_start() {
        let (path, mut lines) = log_of("start", 3);
        lines.remove(0);
        rewrite(&path, &lines);
        assert_eq!(broken_at(&path), (1, Problem::MissingStart));
    }

    #[test]
    fn finds_reordered_lines() {
        let (path, mut lines) = log_of("reordered", 4);
        lines.swap(1, 2);
        rewrite(&path, &lines);
        assert_eq!(broken_at(&path), (2, Problem::Unlinked));
    }

    #[test]
    fn finds_an_incomplete_last_line() {
        let (path, lines) = log_of("incomplete", 2);
        let mut file = File::create(&path).unwrap();
        writeln!(file, "{}", lines[0]).unwrap();
        write!(file, "{}", &lines[1][..20]).unwrap();
        assert_eq!(broken_at(&path), (2, Problem::Incomplete));
    }

    #[test]
    fn an_anchor_catches_entries_cut_off_the_end() {
        let (path, mut lines) = log_of("anchor", 4);
        let head = verify(&path, None).unwrap().head;
        assert_eq!(verify(&path, Some(&head)).unwrap().anchor_at, Some(4));

        lines.truncate(3);
        rewrite(&path, &lines);
        assert!(verify(&path, None).is_ok(), "a chain alone can't tell");
        assert!(matches!(
            verify(&path, Some(&head)),
            Err(VerifyError::AnchorMissing { .. })
        ));
    }
}
