//! Checking a log's chain.

use std::collections::HashSet;
use std::fs::File;
use std::hash::{BuildHasher, RandomState};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::log::MAX_LINE_BYTES;
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
    // Waits out any write in progress, so the last line is whole. Writers
    // only ever add whole lines after this length, so what's before it
    // stays put: it's checked without holding writers up meanwhile.
    file.lock_shared().map_err(read_error)?;
    let len = file.metadata().map(|metadata| metadata.len());
    let _ = file.unlock();
    let reader = SharedReads(&file).take(len.map_err(read_error)?);
    check(
        BufReader::with_capacity(64 * 1024, reader),
        anchor,
        &read_error,
    )
}

/// Reads a log holding its shared lock only for each read. On Windows,
/// where locks are enforced, a read while a writer holds its lock would
/// fail.
struct SharedReads<'a>(&'a File);

impl Read for SharedReads<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock_shared()?;
        let read = self.0.read(buf);
        let _ = self.0.unlock();
        read
    }
}

/// Like [`verify`], for a log read from anywhere (a pipe, a download).
pub fn verify_reader(reader: impl BufRead, anchor: Option<&str>) -> Result<Report, VerifyError> {
    check(reader, anchor, &|source| VerifyError::Read {
        path: PathBuf::from("(input)"),
        source,
    })
}

fn check(
    mut reader: impl BufRead,
    anchor: Option<&str>,
    read_error: &dyn Fn(std::io::Error) -> VerifyError,
) -> Result<Report, VerifyError> {
    let mut report = Report {
        entries: 0,
        sessions: 0,
        unfinished: 0,
        first: None,
        last: None,
        head: GENESIS.to_owned(),
        anchor_at: None,
    };
    // Sessions are kept as hashes, and lines read only up to the longest
    // the log writes: a file that isn't a log can't fill memory.
    let hasher = RandomState::new();
    let mut sessions = HashSet::new();
    let mut open = HashSet::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut reader)
            .take(MAX_LINE_BYTES as u64)
            .read_until(b'\n', &mut line)
            .map_err(read_error)?;
        if read == 0 {
            break;
        }
        let number = report.entries + 1;
        let broken = |problem| VerifyError::Broken {
            line: number,
            problem,
        };
        let Some(body) = line.strip_suffix(b"\n") else {
            return Err(broken(if line.len() == MAX_LINE_BYTES {
                Problem::NotAnEntry
            } else {
                Problem::Incomplete
            }));
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
            let session = hasher.hash_one(session);
            sessions.insert(session);
            match field("event") {
                Some("session-start") => {
                    open.insert(session);
                }
                Some("session-end") => {
                    open.remove(&session);
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
    use std::time::{Duration, Instant};

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

    #[test]
    fn stops_reading_a_line_longer_than_any_entry() {
        let endless = std::io::repeat(b'{').take(3 * MAX_LINE_BYTES as u64);
        assert!(matches!(
            verify_reader(BufReader::new(endless), None),
            Err(VerifyError::Broken {
                line: 1,
                problem: Problem::NotAnEntry
            })
        ));
    }

    #[test]
    fn writers_are_not_held_up_while_a_log_is_checked() {
        // A log long enough that checking it takes a while.
        let path = temp_dir("busy").join("audit.jsonl");
        let mut lines = Vec::new();
        let mut prev = GENESIS.to_owned();
        for seq in 1..=20_000 {
            let entry =
                serde_json::json!({"seq": seq, "session": "s", "event": "message", "prev": prev});
            let (line, hash) = crate::seal(serde_json::to_vec(&entry).unwrap());
            lines.extend_from_slice(&line);
            prev = hash;
        }
        std::fs::write(&path, &lines).unwrap();

        let started = Instant::now();
        let checking = {
            let path = path.clone();
            std::thread::spawn(move || {
                let from = started.elapsed();
                let report = verify(&path, None);
                (report, from, started.elapsed())
            })
        };
        // A writer takes the lock whenever it can while the check runs.
        let writer = File::open(&path).unwrap();
        let mut locked_at = Vec::new();
        while !checking.is_finished() {
            if writer.try_lock().is_ok() {
                locked_at.push(started.elapsed());
                writer.unlock().unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let (report, from, to) = checking.join().unwrap();
        assert_eq!(report.unwrap().entries, 20_000);
        let middle = from + (to - from) / 4..to - (to - from) / 4;
        assert!(
            locked_at.iter().any(|at| middle.contains(at)),
            "the writer never got the lock between {middle:?}: {locked_at:?}"
        );
    }
}

#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::*;
    use crate::{seal, unseal};

    proptest! {
        #[test]
        fn any_bytes_are_checked_without_panicking(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = unseal(&bytes);
            let _ = verify_reader(&bytes[..], None);
        }

        #[test]
        fn any_object_seals_and_unseals(fields in prop::collection::btree_map("[a-z]{1,8}", r"\PC{0,24}", 1..6)) {
            let body = serde_json::to_vec(&fields).unwrap();
            let (line, hash) = seal(body);
            let sealed = unseal(&line[..line.len() - 1]).unwrap();
            prop_assert_eq!(sealed.hash, hash);
        }

        #[test]
        fn any_single_byte_edit_is_caught(fields in prop::collection::btree_map("[a-z]{1,8}", "[ -~]{0,24}", 1..6), at in any::<prop::sample::Index>(), byte in 32u8..127) {
            let (mut line, _) = seal(serde_json::to_vec(&fields).unwrap());
            line.pop();
            let index = at.index(line.len());
            prop_assume!(line[index] != byte);
            line[index] = byte;
            prop_assert!(unseal(&line).is_err());
        }
    }
}
