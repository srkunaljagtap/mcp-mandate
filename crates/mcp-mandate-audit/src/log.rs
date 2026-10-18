//! Appending entries to the log file.

use std::fs::{File, OpenOptions, TryLockError};
use std::hash::{BuildHasher, RandomState};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::time::rfc3339;
use crate::{Event, GENESIS, Problem, seal, sha256_hex, unseal};

/// Longest line the log writes or reads back as its last entry.
pub(crate) const MAX_LINE_BYTES: usize = 1024 * 1024;
/// How much of the end of the log is read first to find its last entry;
/// more is read only if that entry is longer.
const TAIL_BYTES: u64 = 8 * 1024;
/// How long a write waits for another process to let go of the log's lock.
/// Writers hold it only for a moment, so a longer wait means something is
/// stuck or holding it on purpose: the write fails rather than hang, and
/// the writes after it don't wait again until one gets the lock.
const LOCK_WAIT: Duration = Duration::from_secs(2);

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
    #[error(
        "the audit log {} was moved, replaced or deleted while in use; restart mcp-mandate to use the file now at that path",
        path.display()
    )]
    Replaced { path: PathBuf },
    #[error(
        "the audit log {} shrank from {expected} to {actual} bytes while in use: entries were removed; restart mcp-mandate to carry on from what's left",
        path.display()
    )]
    Shrank {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    #[error(
        "the audit log {} was cut short or rewritten while in use: the last entry mcp-mandate saw in it is no longer where it was; restart mcp-mandate to carry on from what's there now",
        path.display()
    )]
    Rewritten { path: PathBuf },
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
    /// Which file this is, to notice another taking its place at `path`.
    identity: Identity,
    /// Set once the file is found replaced, cut short or rewritten. It then
    /// takes no more entries, even once a new file appears at the path, so
    /// entries can't vanish unnoticed; only a restart carries on.
    stopped: Option<Stop>,
    /// Set when a wait for the lock ran out. Until a write gets the lock
    /// again, writes try for it once instead of each waiting in turn.
    contended: bool,
    /// Where the end of the file is read into, kept between catch-ups.
    tail: Vec<u8>,
}

/// What tells one file from another: its device and inode on Unix, and
/// elsewhere its volume serial number and file index. Windows promises
/// those only while the file is open, so they're kept with an open handle.
#[cfg(unix)]
type Identity = (u64, u64);
#[cfg(not(unix))]
type Identity = same_file::Handle;

/// Why a log file takes no more entries.
#[derive(Clone, Copy)]
enum Stop {
    Replaced,
    Shrank { expected: u64, actual: u64 },
    Rewritten,
}

impl Stop {
    fn error(self, path: &Path) -> AuditError {
        let path = path.to_owned();
        match self {
            Self::Replaced => AuditError::Replaced { path },
            Self::Shrank { expected, actual } => AuditError::Shrank {
                path,
                expected,
                actual,
            },
            Self::Rewritten => AuditError::Rewritten { path },
        }
    }
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
            identity: identity(&file).map_err(open_error)?,
            file,
            seq: 0,
            prev: GENESIS.to_owned(),
            len: 0,
            stopped: None,
            contended: false,
            tail: Vec::new(),
        };
        lock(&log.file, LOCK_WAIT).map_err(open_error)?;
        let caught_up = log.catch_up();
        let unlocked = log.file.unlock().map_err(open_error);
        caught_up?;
        unlocked?;
        Ok(log)
    }

    fn record(&mut self, session: &str, event: &Event) -> Result<(), AuditError> {
        // Every session sharing this file queues behind this write: once
        // one has waited out the lock, the rest fail at once instead of
        // each waiting in full, until one gets it.
        let wait = if self.contended {
            Duration::ZERO
        } else {
            LOCK_WAIT
        };
        let locked = lock(&self.file, wait);
        self.contended = locked
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::TimedOut);
        locked.map_err(|source| self.write_error(source))?;
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
        if let Some(stop) = self.stopped {
            return Err(stop.error(&self.path));
        }
        let len = self.file_len()?;
        let stop = if self.replaced() {
            Some(Stop::Replaced)
        } else if len < self.len {
            Some(Stop::Shrank {
                expected: self.len,
                actual: len,
            })
        } else if len > self.len && !self.last_seen_in_place()? {
            Some(Stop::Rewritten)
        } else {
            None
        };
        if let Some(stop) = stop {
            self.stopped = Some(stop);
            return Err(stop.error(&self.path));
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
        if len == 0 {
            (self.seq, self.prev, self.len) = (0, GENESIS.to_owned(), 0);
            return Ok(());
        }
        let mut tail = std::mem::take(&mut self.tail);
        let last = self.last_entry(len, &mut tail);
        self.tail = tail;
        let (seq, prev) = last?;
        (self.seq, self.prev, self.len) = (seq, prev, len);
        Ok(())
    }

    /// Whether the entry this log last wrote or caught up to still ends
    /// where it did. Call with the file longer than that: a log cut short
    /// and then written past that point again (by another process carrying
    /// on from what was left) is longer, but no longer holds it.
    fn last_seen_in_place(&mut self) -> Result<bool, AuditError> {
        if self.len == 0 {
            return Ok(true);
        }
        let mut tail = std::mem::take(&mut self.tail);
        let last = self.last_entry(self.len, &mut tail);
        self.tail = tail;
        match last {
            Ok((_, hash)) => Ok(hash == self.prev),
            // No whole entry ends there now.
            Err(AuditError::Tail { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// The number and hash of the last entry in a file `len` bytes long,
    /// reading the end of the file into `tail`: a little first, and twice as
    /// much each time that holds no whole line, up to the longest line.
    fn last_entry(&self, len: u64, tail: &mut Vec<u8>) -> Result<(u64, String), AuditError> {
        let tail_error = |problem| AuditError::Tail {
            path: self.path.clone(),
            problem,
        };
        let longest = MAX_LINE_BYTES as u64 + 1;
        let mut window = len.min(TAIL_BYTES);
        let start = loop {
            tail.resize(usize::try_from(window).unwrap_or(MAX_LINE_BYTES), 0);
            (&self.file)
                .seek(SeekFrom::Start(len - window))
                .and_then(|_| (&self.file).read_exact(tail.as_mut_slice()))
                .map_err(|source| self.write_error(source))?;
            let Some((b'\n', body)) = tail.split_last() else {
                return Err(tail_error(Problem::Incomplete));
            };
            match body.iter().rposition(|&byte| byte == b'\n') {
                Some(newline) => break newline + 1,
                None if window == len => break 0,
                None if window >= longest => return Err(tail_error(Problem::NotAnEntry)),
                None => window = (window * 2).min(len).min(longest),
            }
        };
        let sealed = unseal(&tail[start..tail.len() - 1]).map_err(tail_error)?;
        let Some(seq) = sealed.fields.get("seq").and_then(serde_json::Value::as_u64) else {
            return Err(tail_error(Problem::NotAnEntry));
        };
        Ok((seq, sealed.hash))
    }

    fn file_len(&self) -> Result<u64, AuditError> {
        self.file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|source| self.write_error(source))
    }

    /// Whether `path` no longer names the file this log has open.
    fn replaced(&self) -> bool {
        match identity_at(&self.path) {
            Ok(on_disk) => on_disk != self.identity,
            Err(_) => true,
        }
    }

    fn write_error(&self, source: std::io::Error) -> AuditError {
        AuditError::Write {
            path: self.path.clone(),
            source,
        }
    }
}

/// Takes the exclusive lock on `file`, waiting up to `wait` for another
/// process to let go of it. Called with no wait only once a wait of
/// [`LOCK_WAIT`] has run out and no write has had the lock since.
fn lock(file: &File, wait: Duration) -> std::io::Result<()> {
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::Error(error)) => return Err(error),
            Err(TryLockError::WouldBlock) if started.elapsed() < wait => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::WouldBlock) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "another process has kept it locked for over {} seconds",
                        LOCK_WAIT.as_secs()
                    ),
                ));
            }
        }
    }
}

/// The identity of the open file `file`.
#[cfg(unix)]
fn identity(file: &File) -> std::io::Result<Identity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn identity(file: &File) -> std::io::Result<Identity> {
    same_file::Handle::from_file(file.try_clone()?)
}

/// The identity of the file at `path` now. On Unix it's read with `stat`,
/// without opening the file: opening a FIFO put at the path would wait for
/// a writer, holding the log's lock all the while.
#[cfg(unix)]
fn identity_at(path: &Path) -> std::io::Result<Identity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Windows reads a file index only through an open handle. The file is
/// opened for reading and shared, so it can still be renamed or deleted
/// meanwhile; a file that can't be opened counts as replaced.
#[cfg(not(unix))]
fn identity_at(path: &Path) -> std::io::Result<Identity> {
    same_file::Handle::from_path(path)
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
        assert!(
            log.record(&message(Verdict::Allow)).is_err(),
            "it stays stopped"
        );

        // It stays stopped once the log grows past where it was, too: it
        // would otherwise carry on as if nothing had been removed.
        let mut restarted = Log::open(&path).unwrap();
        for _ in 0..3 {
            restarted.record(&message(Verdict::Allow)).unwrap();
        }
        let error = log.record(&message(Verdict::Allow)).unwrap_err();
        assert!(matches!(error, AuditError::Shrank { .. }), "{error}");
        assert_eq!(verify(&path, None).unwrap().entries, 4);
    }

    #[test]
    fn notices_entries_removed_even_once_the_log_grows_back() {
        let path = temp_dir("regrown").join("audit.jsonl");
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
        // Another gate carries on from what's left, past where `log` was,
        // before `log` writes again.
        let mut other = Log::open(&path).unwrap();
        for _ in 0..3 {
            other.record(&message(Verdict::Allow)).unwrap();
        }

        let error = log.record(&message(Verdict::Allow)).unwrap_err();
        assert!(matches!(error, AuditError::Rewritten { .. }), "{error}");
        assert!(
            log.record(&message(Verdict::Allow)).is_err(),
            "it stays stopped"
        );
        assert_eq!(verify(&path, None).unwrap().entries, 4);
    }

    #[test]
    fn notices_the_log_being_replaced_while_in_use() {
        let dir = temp_dir("replaced");
        let path = dir.join("audit.jsonl");
        let moved = dir.join("audit.1.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.record(&message(Verdict::Allow)).unwrap();
        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, b"").unwrap();

        let error = log.record(&message(Verdict::Allow)).unwrap_err();
        assert!(matches!(error, AuditError::Replaced { .. }), "{error}");
        assert_eq!(verify(&moved, None).unwrap().entries, 1);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn notices_the_log_being_deleted_and_recreated_between_entries() {
        let path = temp_dir("recreated").join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.record(&message(Verdict::Allow)).unwrap();
        std::fs::remove_file(&path).unwrap();
        // Where a deleted file keeps its name until it's closed, no new one
        // can be made yet: the test above covers that.
        if std::fs::write(&path, b"").is_err() {
            return;
        }

        let error = log.record(&message(Verdict::Allow)).unwrap_err();
        assert!(matches!(error, AuditError::Replaced { .. }), "{error}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn notices_the_log_being_deleted_while_in_use() {
        let path = temp_dir("deleted").join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.record(&message(Verdict::Allow)).unwrap();
        std::fs::remove_file(&path).unwrap();

        let error = log.record(&message(Verdict::Allow)).unwrap_err();
        assert!(matches!(error, AuditError::Replaced { .. }), "{error}");

        // A new file at the path (a rotated log, say) isn't taken up until
        // a restart, so entries can't vanish unnoticed. (Where a deleted
        // file keeps its name until it's closed, none can be made yet.)
        if std::fs::write(&path, b"").is_ok() {
            let error = log.record(&message(Verdict::Allow)).unwrap_err();
            assert!(matches!(error, AuditError::Replaced { .. }), "{error}");
        }
        drop(log);
        let mut restarted = Log::open(&path).unwrap();
        restarted.record(&message(Verdict::Allow)).unwrap();
        assert_eq!(verify(&path, None).unwrap().entries, 1);
    }

    /// Runs `work` on another thread, failing if it takes much longer than
    /// [`LOCK_WAIT`].
    fn without_hanging<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || sender.send(work()));
        receiver
            .recv_timeout(LOCK_WAIT * 10)
            .expect("it waited for the lock instead of failing")
    }

    #[test]
    fn fails_rather_than_wait_on_a_lock_held_elsewhere() {
        let path = temp_dir("held").join("audit.jsonl");
        let log = Log::open(&path).unwrap();
        let holder = File::open(&path).unwrap();
        holder.lock().unwrap();

        let (mut log, recorded) = without_hanging(move || {
            let mut log = log;
            let recorded = log.record(&message(Verdict::Allow));
            (log, recorded)
        });
        let error = recorded.unwrap_err();
        assert!(matches!(error, AuditError::Write { .. }), "{error}");
        let opened = without_hanging({
            let path = path.clone();
            move || Log::open(&path).map(drop)
        });
        assert!(matches!(opened, Err(AuditError::Open { .. })));

        // Writing carries on once it's let go.
        holder.unlock().unwrap();
        log.record(&message(Verdict::Allow)).unwrap();
        assert_eq!(verify(&path, None).unwrap().entries, 1);
    }

    #[test]
    fn once_one_write_has_waited_out_the_lock_the_next_fail_at_once() {
        let path = temp_dir("contended").join("audit.jsonl");
        let log = Log::open(&path).unwrap();
        let mut other = log.new_session();
        let holder = File::open(&path).unwrap();
        holder.lock().unwrap();

        let (mut log, recorded) = without_hanging(move || {
            let mut log = log;
            let recorded = log.record(&message(Verdict::Allow));
            (log, recorded)
        });
        assert!(recorded.is_err());
        let started = Instant::now();
        let error = other.record(&message(Verdict::Allow)).unwrap_err();
        assert!(matches!(error, AuditError::Write { .. }), "{error}");
        let waited = started.elapsed();
        assert!(waited < LOCK_WAIT / 2, "it waited {waited:?}");

        // Once a write gets the lock, writes wait for it again.
        holder.unlock().unwrap();
        other.record(&message(Verdict::Allow)).unwrap();
        holder.lock().unwrap();
        let letting_go = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            holder.unlock().unwrap();
        });
        log.record(&message(Verdict::Allow)).unwrap();
        letting_go.join().unwrap();
        assert_eq!(verify(&path, None).unwrap().entries, 2);
    }

    #[test]
    fn catches_up_past_a_long_last_entry() {
        let path = temp_dir("long-tail").join("audit.jsonl");
        let mut a = Log::open(&path).unwrap();
        let mut b = Log::open(&path).unwrap();
        a.record(&message(Verdict::Allow)).unwrap();
        // Longer than the first read of the end of the file.
        a.record(&Event {
            reason: Some("x".repeat(100 * 1024)),
            ..message(Verdict::Block)
        })
        .unwrap();
        b.record(&message(Verdict::Allow)).unwrap();
        // `a` finds its long entry where it left it, and carries on.
        a.record(&message(Verdict::Allow)).unwrap();

        let entries = lines(&path);
        assert_eq!(entries[2]["seq"], 3);
        assert_eq!(entries[2]["prev"], entries[1]["hash"]);
        assert_eq!(entries[3]["prev"], entries[2]["hash"]);
        assert_eq!(verify(&path, None).unwrap().entries, 4);
    }

    #[test]
    fn catching_up_reads_only_the_end_of_the_log() {
        let path = temp_dir("short-tail").join("audit.jsonl");
        let mut a = Log::open(&path).unwrap();
        let mut b = Log::open(&path).unwrap();
        for _ in 0..3 {
            a.record(&message(Verdict::Allow)).unwrap();
            b.record(&message(Verdict::Allow)).unwrap();
        }
        let tail = b.file.lock().unwrap().tail.capacity();
        assert!(tail <= TAIL_BYTES as usize, "{tail}");
        assert_eq!(verify(&path, None).unwrap().entries, 6);
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
