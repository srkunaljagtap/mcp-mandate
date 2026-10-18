//! Appending entries to the log file.

use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, RandomState};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::time::rfc3339;
use crate::{Event, GENESIS, Problem, seal, sha256_hex, unseal};

/// Longest line the log writes or reads back as its last entry.
pub(crate) const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Somewhere decisions are recorded.
pub trait Recorder: Send {
    /// Records `event`. An error means it wasn't recorded.
    fn record(&mut self, event: &Event) -> Result<(), AuditError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("couldn't open the audit log {}", path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("couldn't write to the audit log {}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "the last line of the audit log {} can't be continued ({problem}); check it with `mcp-mandate audit verify`",
        path.display()
    )]
    Tail { path: PathBuf, problem: Problem },
    #[error("the audit log {} was moved, replaced or deleted while in use", path.display())]
    Replaced { path: PathBuf },
    #[error(
        "the audit log {} shrank from {expected} to {actual} bytes while in use: entries were removed",
        path.display()
    )]
    Shrank {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    #[error("an audit entry would be {size} bytes, over the {MAX_LINE_BYTES}-byte limit")]
    TooLarge { size: usize },
}

/// One session's view of an audit log file: its entries carry the session's
/// id.
///
/// Several processes can share one log (two agents running the same
/// server, say): each append takes an exclusive lock on the file, picks up
/// entries other processes added since, and links to the last one. Within
/// one process, sessions made with [`Log::new_session`] share one open file.
pub struct Log {
    session: String,
    file: Arc<Mutex<LogFile>>,
}

/// The open file behind one or more sessions.
struct LogFile {
    path: PathBuf,
    file: File,
    /// The last entry's number and hash, and the file's length after it.
    seq: u64,
    prev: String,
    len: u64,
    /// The file's device and inode, to notice it being replaced.
    #[cfg(unix)]
    identity: (u64, u64),
}

/// An entry as written, before its hash is added.
#[derive(Serialize)]
struct Line<'a> {
    seq: u64,
    time: String,
    session: &'a str,
    #[serde(flatten)]
    event: &'a Event,
    prev: &'a str,
}

impl Log {
    /// Opens (or creates) the log at `path` and checks that its last entry
    /// can be continued: the first session on it.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        Ok(Self {
            session: new_session_id(),
            file: Arc::new(Mutex::new(LogFile::open(path)?)),
        })
    }

    /// Another session recording to the same open file.
    pub fn new_session(&self) -> Self {
        Self {
            session: new_session_id(),
            file: Arc::clone(&self.file),
        }
    }

    pub fn path(&self) -> PathBuf {
        self.file
            .lock()
            .map(|file| file.path.clone())
            .unwrap_or_default()
    }

    /// This session's id, recorded in each of its entries.
    pub fn session(&self) -> &str {
        &self.session
    }
}

impl Recorder for Log {
    fn record(&mut self, event: &Event) -> Result<(), AuditError> {
        let Ok(mut file) = self.file.lock() else {
            return Err(AuditError::Write {
                path: PathBuf::new(),
                source: std::io::Error::other("an earlier write panicked"),
            });
        };
        file.record(&self.session, event)
    }
}

impl LogFile {
    fn open(path: &Path) -> Result<Self, AuditError> {
        let open_error = |source| AuditError::Open {
            path: path.to_owned(),
            source,
        };
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(open_error)?;
        }
        let mut options = OpenOptions::new();
        // Not append mode: a failed write is cut back off with `set_len`,
        // which append-only handles can't do on every platform. The lock
        // keeps seek-then-write safe between processes.
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The log shows which tools were used: keep it private. And
            // never follow a symlink planted where the log should be.
            options
                .mode(0o600)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
        }
        let file = options.open(path).map_err(open_error)?;
        let mut log = Self {
            path: path.to_owned(),
            #[cfg(unix)]
            identity: identity(&file.metadata().map_err(open_error)?),
            file,
            seq: 0,
            prev: GENESIS.to_owned(),
            len: 0,
        };
        log.file.lock().map_err(open_error)?;
        let caught_up = log.catch_up();
        let unlocked = log.file.unlock().map_err(open_error);
        caught_up?;
        unlocked?;
        Ok(log)
    }

    fn record(&mut self, session: &str, event: &Event) -> Result<(), AuditError> {
        self.file
            .lock()
            .map_err(|source| self.write_error(source))?;
        let appended = self.append(session, event);
        let unlocked = self
            .file
            .unlock()
            .map_err(|source| self.write_error(source));
        appended?;
        unlocked
    }

    /// Appends one entry. Call with the file locked.
    fn append(&mut self, session: &str, event: &Event) -> Result<(), AuditError> {
        self.check_identity()?;
        let len = self.file_len()?;
        if len < self.len {
            return Err(AuditError::Shrank {
                path: self.path.clone(),
                expected: self.len,
                actual: len,
            });
        }
        if len > self.len {
            // Another process appended since our last entry.
            self.catch_up()?;
        }
        let line = Line {
            seq: self.seq + 1,
            time: rfc3339(SystemTime::now()),
            session,
            event,
            prev: &self.prev,
        };
        let body = serde_json::to_vec(&line).expect("audit entries always serialize");
        let (bytes, hash) = seal(body);
        if bytes.len() > MAX_LINE_BYTES {
            return Err(AuditError::TooLarge { size: bytes.len() });
        }
        let written = (&self.file)
            .seek(SeekFrom::Start(self.len))
            .and_then(|_| (&self.file).write_all(&bytes));
        if let Err(source) = written {
            // Cut off any part of the line that made it (a full disk, say),
            // so the log still ends on a whole entry.
            let _ = self.file.set_len(self.len);
            return Err(self.write_error(source));
        }
        self.seq += 1;
        self.prev = hash;
        self.len += bytes.len() as u64;
        Ok(())
    }

    /// Reads the last entry, to continue the chain from it.
    fn catch_up(&mut self) -> Result<(), AuditError> {
        let len = self.file_len()?;
        let tail_error = |problem| AuditError::Tail {
            path: self.path.clone(),
            problem,
        };
        if len == 0 {
            (self.seq, self.prev, self.len) = (0, GENESIS.to_owned(), 0);
            return Ok(());
        }
        let window = len.min(MAX_LINE_BYTES as u64 + 1);
        let mut bytes = vec![0; usize::try_from(window).unwrap_or(MAX_LINE_BYTES)];
        (&self.file)
            .seek(SeekFrom::Start(len - window))
            .and_then(|_| (&self.file).read_exact(&mut bytes))
            .map_err(|source| self.write_error(source))?;
        let Some((b'\n', body)) = bytes.split_last() else {
            return Err(tail_error(Problem::Incomplete));
        };
        let start = match body.iter().rposition(|&byte| byte == b'\n') {
            Some(newline) => newline + 1,
            None if window < len => return Err(tail_error(Problem::NotAnEntry)),
            None => 0,
        };
        let sealed = unseal(&body[start..]).map_err(tail_error)?;
        let Some(seq) = sealed.fields.get("seq").and_then(serde_json::Value::as_u64) else {
            return Err(tail_error(Problem::NotAnEntry));
        };
        (self.seq, self.prev, self.len) = (seq, sealed.hash, len);
        Ok(())
    }

    fn file_len(&self) -> Result<u64, AuditError> {
        self.file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|source| self.write_error(source))
    }

    /// Fails if `path` no longer names the file this log has open.
    fn check_identity(&self) -> Result<(), AuditError> {
        let replaced = || AuditError::Replaced {
            path: self.path.clone(),
        };
        let on_disk = std::fs::metadata(&self.path).map_err(|_| replaced())?;
        #[cfg(unix)]
        if identity(&on_disk) != self.identity {
            return Err(replaced());
        }
        #[cfg(not(unix))]
        let _ = on_disk;
        Ok(())
    }

    fn write_error(&self, source: std::io::Error) -> AuditError {
        AuditError::Write {
            path: self.path.clone(),
            source,
        }
    }
}

#[cfg(unix)]
fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

/// 16 hex digits, unique enough to tell sessions in one log apart.
fn new_session_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // `RandomState` is seeded randomly per process.
    let random = RandomState::new().hash_one(nanos);
    let seed = format!("{}:{nanos}:{random}", std::process::id());
    sha256_hex(seed.as_bytes())[..16].to_owned()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{EventKind, Origin, Verdict, verify};

    /// A fresh, empty folder for one test.
    pub(crate) fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcp-mandate-audit-{name}-{}-{}",
            std::process::id(),
            new_session_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    pub(crate) fn message(verdict: Verdict) -> Event {
        Event {
            from: Some(Origin::Client),
            method: Some("tools/call".to_owned()),
            item: Some("echo".to_owned()),
            verdict: Some(verdict),
            ..Event::default()
        }
    }

    fn lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn writes_a_chain_of_numbered_entries() {
        let path = temp_dir("chain").join("policy.audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.record(&message(Verdict::Allow)).unwrap();
        log.record(&message(Verdict::Block)).unwrap();

        let entries = lines(&path);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["seq"], 1);
        assert_eq!(entries[0]["prev"], GENESIS);
        assert_eq!(entries[1]["seq"], 2);
        assert_eq!(entries[1]["prev"], entries[0]["hash"]);
        assert_eq!(entries[1]["verdict"], "block");
        assert_eq!(entries[1]["session"], log.session());
        assert!(entries[1]["time"].as_str().unwrap().ends_with('Z'));
        assert!(
            entries[1].get("taint").is_none(),
            "unset fields are left out"
        );
        assert_eq!(verify(&path, None).unwrap().entries, 2);
    }

    #[test]
    fn a_new_session_continues_the_chain() {
        let path = temp_dir("continue").join("audit.jsonl");
        let first = {
            let mut log = Log::open(&path).unwrap();
            log.record(&message(Verdict::Allow)).unwrap();
            log.session().to_owned()
        };
        let mut log = Log::open(&path).unwrap();
        log.record(&message(Verdict::Allow)).unwrap();

        let entries = lines(&path);
        assert_eq!(entries[1]["seq"], 2);
        assert_eq!(entries[1]["prev"], entries[0]["hash"]);
        assert_ne!(entries[1]["session"], first);
        assert_eq!(verify(&path, None).unwrap().sessions, 2);
    }

    #[test]
    fn sessions_can_share_one_open_file() {
        let path = temp_dir("one-file").join("audit.jsonl");
        let mut first = Log::open(&path).unwrap();
        let mut second = first.new_session();
        first.record(&message(Verdict::Allow)).unwrap();
        second.record(&message(Verdict::Block)).unwrap();
        first.record(&message(Verdict::Allow)).unwrap();
        assert_ne!(first.session(), second.session());
        let report = verify(&path, None).unwrap();
        assert_eq!((report.entries, report.sessions), (3, 2));
    }

    #[cfg(unix)]
    #[test]
    fn a_new_log_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_dir("private").join("audit.jsonl");
        Log::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_write_through_a_symlink() {
        let dir = temp_dir("symlink");
        let target = dir.join("elsewhere");
        let path = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(Log::open(&path).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn sessions_writing_at_once_share_one_chain() {
        let path = temp_dir("shared").join("audit.jsonl");
        let mut a = Log::open(&path).unwrap();
        let mut b = Log::open(&path).unwrap();
        a.record(&message(Verdict::Allow)).unwrap();
        b.record(&message(Verdict::Allow)).unwrap();
        a.record(&message(Verdict::Block)).unwrap();

        let report = verify(&path, None).unwrap();
        assert_eq!(report.entries, 3);
        assert_eq!(report.sessions, 2);
    }

    #[test]
    fn creates_missing_folders() {
        let path = temp_dir("folders").join("logs/today/audit.jsonl");
        Log::open(&path)
            .unwrap()
            .record(&message(Verdict::Allow))
            .unwrap();
        assert!(path.exists());
    }

    #[test]
    fn will_not_continue_after_an_incomplete_line() {
        let path = temp_dir("torn").join("audit.jsonl");
        Log::open(&path)
            .unwrap()
            .record(&message(Verdict::Allow))
            .unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"{"seq":2,"time":"#).unwrap();

        let error = Log::open(&path)
            .err()
            .expect("the torn line should stop it");
        assert!(
            matches!(
                error,
                AuditError::Tail {
                    problem: Problem::Incomplete,
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn notices_entries_removed_while_in_use() {
        let path = temp_dir("shrink").join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.record(&message(Verdict::Allow)).unwrap();
        log.record(&message(Verdict::Block)).unwrap();
        let first_line = std::fs::read_to_string(&path).unwrap().find('\n').unwrap() + 1;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(first_line as u64)
            .unwrap();

        let error = log.record(&message(Verdict::Allow)).unwrap_err();
        assert!(matches!(error, AuditError::Shrank { .. }), "{error}");
    }

    #[test]
    fn notices_the_log_being_deleted_while_in_use() {
        let path = temp_dir("deleted").join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.record(&message(Verdict::Allow)).unwrap();
        std::fs::remove_file(&path).unwrap();

        let error = log.record(&message(Verdict::Allow)).unwrap_err();
        assert!(matches!(error, AuditError::Replaced { .. }), "{error}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reports_a_failed_write() {
        let mut log = Log::open(Path::new("/dev/full")).unwrap();
        let error = log.record(&message(Verdict::Allow)).unwrap_err();
        assert!(matches!(error, AuditError::Write { .. }), "{error}");
    }

    #[test]
    fn session_start_and_end_are_entries_too() {
        let path = temp_dir("lifecycle").join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.record(&Event {
            event: EventKind::SessionStart,
            pid: Some(42),
            ..Event::default()
        })
        .unwrap();
        log.record(&Event {
            event: EventKind::SessionEnd,
            exit_code: Some(0),
            ..Event::default()
        })
        .unwrap();
        let entries = lines(&path);
        assert_eq!(entries[0]["event"], "session-start");
        assert_eq!(entries[1]["event"], "session-end");
        assert_eq!(verify(&path, None).unwrap().unfinished, 0);
    }
}
