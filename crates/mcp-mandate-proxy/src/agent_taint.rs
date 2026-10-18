//! Taint shared by every `mcp-mandate run` one agent starts.
//!
//! An agent usually has several MCP servers, each behind its own
//! mcp-mandate process. Reading untrusted content through one of them (a
//! web page, an email) must hold sending through any of the others, so the
//! processes share taint through a small file named after the agent: the
//! process that started them, by its id and start time (so a recycled id
//! doesn't inherit an old taint). `MCP_MANDATE_AGENT` names the agent
//! explicitly instead, for wrappers and tests.
//!
//! A record lasts as long as its agent. An agent process's record stays
//! while that process runs. A named agent's stays while any of its servers
//! runs: each holds a shared lock on `<record>.lock` for its life, and a
//! server that finds no other one running starts the agent afresh, clearing
//! the record an earlier session left. Every server that has seen the taint
//! keeps the record in place meanwhile: it puts it back if something
//! removes it, and touches it now and then so cleaners of old files leave
//! it alone. Each of a named agent's servers touches the lock file the same
//! way, so it isn't removed while they hold it, and makes and locks it again
//! if it's removed anyway.
//!
//! The file lives in a folder only this user can use, checked again before
//! every write, and is never written through a link. If that can't be set
//! up safely, or the agent can't be identified, each server keeps its own
//! taint, with a warning.

use std::fs::{self, File, FileTimes, OpenOptions, TryLockError};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use mcp_mandate_gate::SharedTaint;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tracing::{info, warn};

/// Records of agents that are gone are removed once untouched this long.
const STALE: Duration = Duration::from_secs(7 * 24 * 3600);
/// How often a server that has seen the taint checks that its record is
/// still there.
const CHECK: Duration = Duration::from_secs(60);
/// How long a record (or a named agent's lock file) goes untouched before
/// such a server touches it. The runtime folder's rules let a cleaner
/// remove files untouched for 6 hours.
const TOUCH: Duration = Duration::from_secs(3600);

/// Programs that suggest mcp-mandate was started through a shell rather
/// than by the agent itself.
const SHELLS: [&str; 10] = [
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "cmd.exe",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];

pub struct AgentTaint {
    path: PathBuf,
    /// The taint this process has seen. It stays for the process's life,
    /// and puts the record back if something removes it meanwhile.
    seen: Arc<OnceLock<String>>,
    /// How often the record is checked once the taint has been seen (and,
    /// for a named agent, the lock file from the start).
    check: Duration,
    /// Keeps the record in place once the taint has been seen, and a named
    /// agent's lock file in place and from looking old. Declared before
    /// `running` so it stops before this server counts as stopped.
    keeper: OnceLock<Keeper>,
    /// For a named agent: the lock file this server holds a shared lock on
    /// to show it's running. Replaced if that file is removed (see
    /// [`keep_lock`]).
    running: Option<Arc<Mutex<File>>>,
}

impl AgentTaint {
    /// The shared taint of the agent that started this process. `None`
    /// (after a warning) when it can't be set up safely.
    pub fn for_this_agent() -> Option<Self> {
        let (agent, named) = match std::env::var("MCP_MANDATE_AGENT") {
            Ok(name) if valid_name(&name) => (format!("named-{name}"), true),
            Ok(_) => {
                warn!(
                    "MCP_MANDATE_AGENT must be 1 to 64 letters, digits, `-` or `_`; taint isn't shared between servers"
                );
                return None;
            }
            Err(_) => (parent_agent()?, false),
        };
        let folder = private_folder()?;
        remove_stale(&folder);
        let path = folder.join(format!("taint-{agent}"));
        let taint = if named {
            Self::join(path, CHECK)
        } else {
            Self::at(path)
        };
        info!("taint is shared with the agent's other servers");
        Some(taint)
    }

    fn at(path: PathBuf) -> Self {
        Self {
            path,
            seen: Arc::default(),
            check: CHECK,
            keeper: OnceLock::new(),
            running: None,
        }
    }

    /// One of a named agent's servers, whose record is at `path`: marked as
    /// running for its life, and keeping that mark in place and from
    /// looking old (its lock file is checked every `check`).
    fn join(path: PathBuf, check: Duration) -> Self {
        let running = join_named(&path).map(|lock| Arc::new(Mutex::new(lock)));
        let taint = Self {
            running,
            check,
            ..Self::at(path)
        };
        if taint.running.is_some() {
            taint.keep_running();
            taint.keep();
        }
        taint
    }

    fn write(&self, source: &str) {
        if let Err(error) = write_record(&self.path, source) {
            warn!(%error, "couldn't share the taint with the agent's other servers");
        }
    }

    /// Remembers the taint for the rest of this process's life and, the
    /// first time, starts keeping its record in place.
    fn saw(&self, source: &str) {
        if self.seen.set(source.to_owned()).is_ok() {
            self.keep();
        }
    }

    /// Starts keeping the record in place (once the taint has been seen)
    /// and this server's lock file from looking old, unless that's being
    /// done already.
    fn keep(&self) {
        if self.keeper.get().is_some() {
            return;
        }
        match Keeper::start(
            self.path.clone(),
            Arc::clone(&self.seen),
            self.running.clone(),
            self.check,
        ) {
            Ok(keeper) => {
                let _ = self.keeper.set(keeper);
            }
            Err(error) => {
                warn!(%error, "couldn't start keeping the agent's taint in place; if its files are removed, the agent's other servers may not see it");
            }
        }
    }

    /// Touches this server's lock file if it looks old, and locks it again
    /// if it's been removed: done whenever the record is checked, besides
    /// by the keeper (which warns if it can't).
    fn keep_running(&self) {
        if let Some(lock) = &self.running {
            let _ = keep_lock(&self.path, lock);
        }
    }
}

impl SharedTaint for AgentTaint {
    fn get(&self) -> Option<String> {
        self.keep_running();
        let recorded = match fs::read_to_string(&self.path) {
            Ok(source) if !source.is_empty() => Some(source),
            Ok(_) => None,
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            // Fail closed: a record that exists but can't be read counts.
            Err(_) => {
                return Some("another server of this agent (its record can't be read)".to_owned());
            }
        };
        match recorded {
            Some(source) => {
                self.saw(&source);
                Some(source)
            }
            None => {
                // Removed while the agent still runs (by hand, or by a
                // cleaner of temporary files): put it back for the others.
                // Still counts here even if it can't be: `reshare` tells
                // the gate whether it's shared.
                let seen = self.seen.get()?;
                self.write(seen);
                Some(seen.clone())
            }
        }
    }

    fn set(&self, source: &str) -> bool {
        self.saw(source);
        self.keep_running();
        match write_record(&self.path, source) {
            Ok(()) => true,
            Err(error) => {
                warn!(%error, "couldn't share the taint with the agent's other servers");
                false
            }
        }
    }

    fn reshare(&self, source: &str) -> bool {
        self.saw(source);
        self.keep_running();
        match keep_record(&self.path, source) {
            Ok(()) => true,
            Err(error) => {
                warn!(%error, "couldn't put the taint back where the agent's other servers read it");
                false
            }
        }
    }
}

/// A thread that, until dropped, keeps a named agent's lock file and, once
/// the taint has been seen, its record in place: it puts either back if
/// it's gone, and touches either once it's been untouched for [`TOUCH`].
/// So a record that couldn't be written at first (a full disk, say) is
/// written as soon as it can be. The lock file is seen to first, so a
/// server started meanwhile doesn't clear the record put back.
struct Keeper {
    stop: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl Keeper {
    fn start(
        path: PathBuf,
        seen: Arc<OnceLock<String>>,
        lock: Option<Arc<Mutex<File>>>,
        check: Duration,
    ) -> std::io::Result<Self> {
        let (stop, stopped) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("taint keeper".to_owned())
            .spawn(move || {
                let (mut lock_failing, mut record_failing) = (false, false);
                while stopped.recv_timeout(check) == Err(mpsc::RecvTimeoutError::Timeout) {
                    if let Some(lock) = &lock {
                        report(
                            keep_lock(&path, lock),
                            &mut lock_failing,
                            "couldn't keep this server marked as running; a later server of the agent may clear its taint",
                        );
                    }
                    if let Some(source) = seen.get() {
                        report(
                            keep_record(&path, source),
                            &mut record_failing,
                            "couldn't keep the taint shared with the agent's other servers",
                        );
                    }
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

/// Warns about the first of a run of failures.
fn report(result: std::io::Result<()>, failing: &mut bool, problem: &str) {
    match result {
        Ok(()) => *failing = false,
        Err(error) => {
            if !*failing {
                warn!(%error, "{problem}");
            }
            *failing = true;
        }
    }
}

impl Drop for Keeper {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Puts the record back if it's gone, empty or not a plain file, and
/// touches it if it's been untouched for [`TOUCH`].
fn keep_record(path: &Path, source: &str) -> std::io::Result<()> {
    // Links aren't followed: a record is only ever a file.
    let modified = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => metadata.modified()?,
        Ok(_) => return write_record(path, source),
        Err(error) if error.kind() == ErrorKind::NotFound => return write_record(path, source),
        Err(error) => return Err(error),
    };
    if untouched(modified) {
        touch(&no_follow(File::options().write(true)).open(path)?)?;
    }
    Ok(())
}

/// Keeps the lock file next to a named agent's `record` showing this server
/// is running. It's touched, through the handle this server holds it by, if
/// it's been untouched for [`TOUCH`]: otherwise a cleaner of old files could
/// remove it while the agent runs, and the next server, finding it unlocked,
/// would clear the agent's taint. If it's removed anyway, it's made and
/// locked again (see [`follow_lock`]).
fn keep_lock(record: &Path, lock: &Mutex<File>) -> std::io::Result<()> {
    // A panic while it was held can't have left the file half replaced.
    let mut lock = lock.lock().unwrap_or_else(PoisonError::into_inner);
    follow_lock(record, &mut lock)?;
    if untouched(lock.metadata()?.modified()?) {
        touch(&lock)?;
    }
    Ok(())
}

/// Makes sure `lock` is the file a server starting now finds next to
/// `record`. A lock on a file no longer there shows no later server that
/// this one runs: if it's been removed (with its folder, say, as a runtime
/// folder is at logout) or replaced, the folder and the file are made again
/// as needed, and the file there is locked instead.
#[cfg(unix)]
fn follow_lock(record: &Path, lock: &mut File) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let held = lock.metadata()?;
    // Links aren't followed: one in the lock file's place isn't it.
    match fs::symlink_metadata(record.with_extension("lock")) {
        Ok(found) if found.dev() == held.dev() && found.ino() == held.ino() => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(folder) = record.parent() {
        make_private(folder).map_err(std::io::Error::other)?;
    }
    let found = open_lock(record)?;
    found.lock_shared()?;
    *lock = found;
    info!("the agent's lock file was removed; this server is marked as running again");
    Ok(())
}

/// On Windows the lock file's folder, under `LOCALAPPDATA`, isn't emptied
/// at logout or by a cleaner of old files, so the lock file is left as it is.
#[cfg(not(unix))]
fn follow_lock(_: &Path, _: &mut File) -> std::io::Result<()> {
    Ok(())
}

/// Whether something last modified at `modified` has gone untouched for
/// longer than [`TOUCH`].
fn untouched(modified: SystemTime) -> bool {
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age > TOUCH)
}

fn touch(file: &File) -> std::io::Result<()> {
    let now = SystemTime::now();
    file.set_times(FileTimes::new().set_accessed(now).set_modified(now))
}

/// Writes a record aside, then renames it into place, so a reader never
/// sees half of it. The folder is checked first, and made again if
/// something removed it: in a shared temporary folder, another user could
/// have made one in its place. A failed write is tried once more.
fn write_record(path: &Path, source: &str) -> std::io::Result<()> {
    // Each write gets its own temporary file: a keeper may write while
    // another thread of this process does.
    static WRITES: AtomicUsize = AtomicUsize::new(0);
    let attempt = || {
        if let Some(folder) = path.parent() {
            make_private(folder).map_err(std::io::Error::other)?;
        }
        let temporary = path.with_extension(format!(
            "{}-{}.tmp",
            std::process::id(),
            WRITES.fetch_add(1, Ordering::Relaxed)
        ));
        let written = write_private(&temporary, source).and_then(|()| fs::rename(&temporary, path));
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        written
    };
    attempt().or_else(|_| attempt())
}

/// The process that started this one, as `<pid>-<start time>`.
fn parent_agent() -> Option<String> {
    let identified = (|| {
        let me = sysinfo::get_current_pid().ok()?;
        let mut system = System::new();
        refresh(&mut system, me);
        let parent = system.process(me)?.parent()?;
        refresh(&mut system, parent);
        let process = system.process(parent)?;
        Some((
            parent.as_u32(),
            started(&system, parent)?,
            process.name().to_string_lossy().into_owned(),
        ))
    })();
    let Some((pid, start, name)) = identified else {
        warn!(
            "couldn't identify the agent that started mcp-mandate; taint isn't shared between servers"
        );
        return None;
    };
    if SHELLS.contains(&name.to_ascii_lowercase().as_str()) {
        warn!(
            parent = %name,
            "mcp-mandate was started through a shell, so taint is shared only with servers started by that same shell. Start mcp-mandate directly from the agent's MCP configuration, or set MCP_MANDATE_AGENT"
        );
    }
    Some(format!("{pid}-{start}"))
}

/// Whether the agent process named `<pid>-<start time>` is still running.
fn agent_running(agent: &str) -> bool {
    let Some((pid, start)) = agent.split_once('-') else {
        return false;
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return false;
    };
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    refresh(&mut system, pid);
    started(&system, pid).is_some_and(|started| started == start)
}

/// When `pid` started, as part of a record's name: it stays the same for
/// the process's life, and a later process given the same id gets another.
#[cfg(not(target_os = "linux"))]
fn started(system: &System, pid: Pid) -> Option<String> {
    system
        .process(pid)
        .map(|process| process.start_time().to_string())
}

/// On Linux, sysinfo's start time is the boot time plus the time since
/// boot, and the boot time it reads moves whenever the clock is set (after
/// a suspend, say), so the same process could later read as another. The
/// time since boot, in clock ticks, doesn't move; the boot's id tells it
/// from a process that started as long after a later boot.
#[cfg(target_os = "linux")]
fn started(_: &System, pid: Pid) -> Option<String> {
    let ticks = start_ticks(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
    Some(
        match fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            Ok(boot) => format!("{ticks}-{}", boot.trim()),
            Err(_) => ticks.to_string(),
        },
    )
}

/// The start time (field 22) in a `/proc/<pid>/stat` line. The program's
/// name (field 2) can hold spaces and parentheses, so fields are counted
/// from the last `)`.
#[cfg(any(target_os = "linux", test))]
fn start_ticks(stat: &str) -> Option<u64> {
    let (_, fields) = stat.rsplit_once(')')?;
    fields.split_whitespace().nth(19)?.parse().ok()
}

fn refresh(system: &mut System, pid: Pid) {
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        false,
        ProcessRefreshKind::nothing(),
    );
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Marks this process as one of a named agent's servers for as long as it
/// runs. If no other server of the agent is running, the agent is starting
/// afresh, so the record an earlier session left is removed first.
fn join_named(record: &Path) -> Option<File> {
    let lock = match open_lock(record) {
        Ok(lock) => lock,
        Err(error) => {
            warn!(%error, "couldn't tell whether the agent's other servers are running; the taint of an earlier session stays");
            return None;
        }
    };
    match lock.try_lock() {
        // Nobody else holds it, so no other server of this agent runs.
        Ok(()) => {
            match fs::remove_file(record) {
                Ok(()) => info!("cleared the taint an earlier session of this agent left"),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    warn!(%error, "couldn't clear the taint an earlier session of this agent left");
                }
            }
            let _ = lock.unlock();
        }
        Err(TryLockError::WouldBlock) => {}
        Err(TryLockError::Error(error)) => {
            warn!(%error, "couldn't tell whether the agent's other servers are running; the taint of an earlier session stays");
            return None;
        }
    }
    match lock.lock_shared() {
        Ok(()) => Some(lock),
        Err(error) => {
            warn!(%error, "couldn't mark this server as running; a later server of the agent may clear its taint");
            None
        }
    }
}

/// The lock file next to a named agent's record, made if needed.
fn open_lock(record: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    no_follow(&mut options).open(record.with_extension("lock"))
}

/// A folder only this user can read or write, made if needed.
fn private_folder() -> Option<PathBuf> {
    let refuse = |problem: String| {
        warn!("{problem}; taint isn't shared between servers");
        None
    };
    let candidates = match candidate_folders() {
        Ok(candidates) => candidates,
        Err(problem) => return refuse(problem),
    };
    let mut problems = Vec::new();
    for folder in candidates {
        match make_private(&folder) {
            Ok(()) => {
                // Servers of the agent that can use a better folder share
                // there instead, without this one.
                if !problems.is_empty() {
                    warn!(
                        folder = %folder.display(),
                        "{}; taint is shared only with the agent's servers that use this same folder",
                        problems.join("; ")
                    );
                }
                return Some(folder);
            }
            Err(problem) => problems.push(problem),
        }
    }
    refuse(problems.join("; "))
}

/// Where the records can go, best first: the user's runtime folder, then
/// one in their home folder (taken from the user database rather than the
/// environment, so every server of the agent picks the same), then the
/// temporary folder, where another user could take the name first.
#[cfg(unix)]
fn candidate_folders() -> Result<Vec<PathBuf>, String> {
    let uid = nix::unistd::getuid();
    let mut folders = Vec::new();
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
        && runtime.is_absolute()
    {
        folders.push(runtime.join("mcp-mandate"));
    }
    if let Ok(Some(user)) = nix::unistd::User::from_uid(uid)
        && user.dir.is_absolute()
    {
        folders.push(user.dir.join(".local").join("state").join("mcp-mandate"));
    }
    folders.push(std::env::temp_dir().join(format!("mcp-mandate-{}", uid.as_raw())));
    Ok(folders)
}

/// Per-user on Windows, and closed to other users by default.
#[cfg(not(unix))]
fn candidate_folders() -> Result<Vec<PathBuf>, String> {
    local_app_data(std::env::var_os("LOCALAPPDATA"))
        .map(|folder| vec![folder])
        .ok_or_else(|| "LOCALAPPDATA isn't set to a full path".to_owned())
}

/// The folder under `LOCALAPPDATA`, if that's a full path: a relative one
/// would land in the folder the server runs in, where the agent's own file
/// tools can reach it.
#[cfg(any(not(unix), test))]
fn local_app_data(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    value
        .map(PathBuf::from)
        .filter(|base| base.is_absolute())
        .map(|base| base.join("mcp-mandate").join("taint"))
}

/// Makes `folder` if needed, and checks that it's a real folder (not a
/// link) that only this user can use.
fn make_private(folder: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

        let _ = fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(folder);
        // Someone else could have made it first (in a shared /tmp): it must
        // be a real folder, ours, and closed to others.
        let metadata = fs::symlink_metadata(folder)
            .map_err(|error| format!("couldn't make {}: {error}", folder.display()))?;
        if !metadata.is_dir()
            || metadata.uid() != nix::unistd::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!(
                "{} isn't a private folder of this user",
                folder.display()
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(folder)
            .map_err(|error| format!("couldn't make {}: {error}", folder.display()))?;
        // A link or junction could lead somewhere others can reach.
        let metadata = fs::symlink_metadata(folder)
            .map_err(|error| format!("couldn't make {}: {error}", folder.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("{} is a link, not a folder", folder.display()));
        }
        Ok(())
    }
}

/// Writes `text` to a new file at `path` that only this user can read. If
/// anything is already there, even a link, nothing is written: each
/// temporary file's name is used once, so something else put it there.
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    no_follow(&mut options)
        .open(path)?
        .write_all(text.as_bytes())
}

/// Opens a file without following a link in its place, where the system
/// allows it.
fn no_follow(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
    }
    options
}

/// Removes what agents that are gone left behind, once untouched for
/// [`STALE`]: records whose agent no longer runs, and temporary files from
/// interrupted writes. Lock files stay: removing one while a server is
/// starting could let a later one clear a running agent's taint.
fn remove_stale(folder: &Path) {
    let Ok(entries) = fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(agent) = name.strip_prefix("taint-") else {
            continue;
        };
        let old = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age > STALE);
        if !old || agent.ends_with(".lock") {
            continue;
        }
        let path = entry.path();
        if agent.ends_with(".tmp") {
            let _ = fs::remove_file(&path);
        } else if agent.starts_with("named-") {
            remove_unless_running(&path);
        } else if !agent_running(agent) {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Removes a named agent's record if none of its servers is running. The
/// lock is held meanwhile, so no server can start using the record.
fn remove_unless_running(record: &Path) {
    if let Ok(lock) = open_lock(record)
        && lock.try_lock().is_ok()
    {
        let _ = fs::remove_file(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private folder for one test's records.
    fn folder(test: &str) -> PathBuf {
        let folder = std::env::temp_dir().join(format!(
            "mcp-mandate-agent-taint-{}-{test}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&folder);
        make_private(&folder).unwrap();
        folder
    }

    /// Makes `path` look untouched for longer than [`STALE`].
    fn age(path: &Path) {
        let long_ago = SystemTime::now() - STALE - Duration::from_secs(3600);
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
    }

    #[test]
    fn what_one_server_records_the_others_read() {
        let folder = folder("shared");
        let path = folder.join("taint-test");
        let first = AgentTaint::at(path.clone());
        let second = AgentTaint::at(path);
        assert_eq!(second.get(), None);
        first.set("the output of tool `fetch`");
        assert_eq!(second.get().as_deref(), Some("the output of tool `fetch`"));
        let _ = fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_record_that_cant_be_written_is_reported() {
        let folder = folder("unwritable");
        let written = AgentTaint::at(folder.join("taint-test"));
        assert!(written.set("the output of tool `fetch`"));
        drop(written);

        // A file where the record's folder should be: neither writing the
        // record nor making the folder again can work.
        let blocked = folder.join("blocked");
        fs::write(&blocked, "").unwrap();
        let taint = AgentTaint::at(blocked.join("taint-test"));
        assert!(!taint.set("the output of tool `fetch`"));
        // This server still counts as tainted.
        assert!(taint.get().is_some());
        drop(taint);
        let _ = fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_taint_once_seen_stays_and_its_record_is_put_back() {
        let folder = folder("seen");
        let path = folder.join("taint-test");
        let reader = AgentTaint::at(path.clone());
        let sender = AgentTaint::at(path.clone());
        let late = AgentTaint::at(path.clone());
        reader.set("the output of tool `fetch`");
        assert!(sender.get().is_some());

        // The record goes away: a server that saw it keeps the taint and
        // puts the record back for one that hadn't.
        fs::remove_file(&path).unwrap();
        assert_eq!(sender.get().as_deref(), Some("the output of tool `fetch`"));
        assert_eq!(late.get().as_deref(), Some("the output of tool `fetch`"));

        // The folder goes away too: the next write makes it again.
        fs::remove_dir_all(&folder).unwrap();
        reader.set("the output of tool `fetch`");
        assert_eq!(
            AgentTaint::at(path).get().as_deref(),
            Some("the output of tool `fetch`")
        );
        let _ = fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_record_that_cant_be_put_back_is_reported() {
        let folder = folder("lost");
        let records = folder.join("records");
        let path = records.join("taint-test");
        let taint = AgentTaint::at(path.clone());
        assert!(taint.set("the output of tool `fetch`"));
        assert!(taint.reshare("the output of tool `fetch`"));

        // The record's folder goes, and can't be made again (a file is in
        // its place): this server still counts as tainted, but its taint
        // isn't shared.
        fs::remove_dir_all(&records).unwrap();
        fs::write(&records, "").unwrap();
        assert!(taint.get().is_some());
        assert!(!taint.reshare("the output of tool `fetch`"));

        // Once it can be, the record is put back.
        fs::remove_file(&records).unwrap();
        assert!(taint.reshare("the output of tool `fetch`"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "the output of tool `fetch`"
        );
        drop(taint);
        let _ = fs::remove_dir_all(&folder);
    }

    /// Whether `path` was touched less than [`TOUCH`] ago.
    fn recent(path: &Path) -> bool {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| modified.elapsed().is_ok_and(|age| age < TOUCH))
    }

    /// Whether `condition` holds within 10 seconds.
    fn eventually(condition: impl Fn() -> bool) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !condition() {
            if std::time::Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    #[test]
    fn a_server_that_saw_the_taint_keeps_its_record() {
        let folder = folder("kept");
        let path = folder.join("taint-test");
        let reader = AgentTaint {
            check: Duration::from_millis(10),
            ..AgentTaint::at(path.clone())
        };
        reader.set("the output of tool `fetch`");

        // Removed: put back without waiting for a server to ask for it.
        fs::remove_file(&path).unwrap();
        assert!(eventually(|| path.exists()), "the record is put back");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "the output of tool `fetch`"
        );

        // Old: touched, so cleaners of old files leave it alone.
        age(&path);
        assert!(eventually(|| recent(&path)), "the record is touched");

        // Once the server stops, so does keeping the record.
        drop(reader);
        fs::remove_file(&path).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&folder);
    }

    /// Something else at a record's or a temporary file's name, such as a
    /// link to another of this user's files, is never written through.
    #[cfg(unix)]
    #[test]
    fn a_record_is_never_written_through_a_link() {
        let folder = folder("link");
        let target = folder.join("target");
        fs::write(&target, "keep").unwrap();
        let temporary = folder.join("taint-test.1-0.tmp");
        std::os::unix::fs::symlink(&target, &temporary).unwrap();
        assert!(write_private(&temporary, "the output of tool `fetch`").is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");

        // A record that's a link is replaced by a file.
        let record = folder.join("taint-test");
        std::os::unix::fs::symlink(&target, &record).unwrap();
        keep_record(&record, "the output of tool `fetch`").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
        assert!(fs::symlink_metadata(&record).unwrap().is_file());
        assert_eq!(
            fs::read_to_string(&record).unwrap(),
            "the output of tool `fetch`"
        );
        let _ = fs::remove_dir_all(&folder);
    }

    /// The folder is checked before every write: one another user could
    /// use isn't written to.
    #[cfg(unix)]
    #[test]
    fn a_record_is_written_only_in_a_private_folder() {
        use std::os::unix::fs::PermissionsExt;
        let folder = folder("open-write");
        let open = folder.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(write_record(&open.join("taint-test"), "the output of tool `fetch`").is_err());
        assert_eq!(fs::read_dir(&open).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&folder);
    }

    #[test]
    fn the_start_time_is_read_after_the_programs_name() {
        let stat = "1234 (my (odd) name) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 100";
        assert_eq!(start_ticks(stat), Some(98765));
        assert_eq!(start_ticks("1234 (short) S 1"), None);
    }

    /// The agent's start time can't move with the clock, or its record
    /// would later count as another agent's.
    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_start_time_counts_from_boot() {
        let me = sysinfo::get_current_pid().unwrap();
        let ticks = start_ticks(&fs::read_to_string("/proc/self/stat").unwrap()).unwrap();
        let start = started(&System::new(), me).unwrap();
        assert!(start.starts_with(&format!("{ticks}-")), "{start}");
        assert!(agent_running(&format!("{me}-{start}")));
    }

    #[test]
    fn a_running_agents_record_is_kept_however_old() {
        let folder = folder("stale");
        let me = sysinfo::get_current_pid().unwrap();
        let mut system = System::new();
        refresh(&mut system, me);
        let start = started(&system, me).unwrap();
        let running = folder.join(format!("taint-{}-{start}", me.as_u32()));
        let recycled = folder.join(format!("taint-{}-1{start}", me.as_u32()));
        let fresh_gone = folder.join(format!("taint-{}-2{start}", me.as_u32()));
        let left = folder.join("taint-1-0.123.tmp");
        for path in [&running, &recycled, &fresh_gone, &left] {
            fs::write(path, "the output of tool `fetch`").unwrap();
        }
        for path in [&running, &recycled, &left] {
            age(path);
        }

        remove_stale(&folder);
        assert!(running.exists(), "the agent still runs");
        assert!(!recycled.exists(), "that agent is gone");
        assert!(
            fresh_gone.exists(),
            "kept for a week after its agent is gone"
        );
        assert!(!left.exists(), "an interrupted write");
        let _ = fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_named_agents_taint_lasts_while_any_of_its_servers_runs() {
        let folder = folder("named");
        let path = folder.join("taint-named-test");
        let first = AgentTaint::join(path.clone(), CHECK);
        assert!(first.running.is_some());
        first.set("the output of tool `fetch`");

        // A second server joins while the first runs: the taint holds,
        // however old, and cleanup leaves it alone.
        let second = AgentTaint::join(path.clone(), CHECK);
        age(&path);
        remove_stale(&folder);
        assert!(second.get().is_some());
        drop(first);
        remove_stale(&folder);
        assert!(second.get().is_some());

        // Once none runs, the next session starts clean.
        drop(second);
        let next = AgentTaint::join(path.clone(), CHECK);
        assert_eq!(next.get(), None);
        next.set("the output of tool `fetch`");
        drop(next);

        // An old record with no server running is cleaned up.
        age(&path);
        remove_stale(&folder);
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&folder);
    }

    /// A cleaner of old files that removed the lock file while servers hold
    /// it would let the next server clear the running agent's taint.
    #[test]
    fn a_named_server_keeps_its_lock_file_from_looking_old() {
        let folder = folder("lock");
        let path = folder.join("taint-named-test");
        let lock = path.with_extension("lock");

        // Touched whenever the record is checked.
        let server = AgentTaint::join(path.clone(), CHECK);
        age(&lock);
        assert_eq!(server.get(), None);
        assert!(recent(&lock), "touched when the record is checked");
        drop(server);

        // And meanwhile, though this server hasn't seen the taint.
        let server = AgentTaint::join(path.clone(), Duration::from_millis(10));
        assert!(server.running.is_some());
        age(&lock);
        assert!(eventually(|| recent(&lock)), "touched while it runs");

        // Once the server stops, so does touching it.
        drop(server);
        age(&lock);
        std::thread::sleep(Duration::from_millis(100));
        assert!(!recent(&lock));
        let _ = fs::remove_dir_all(&folder);
    }

    /// Whether a running server holds the lock file at `path`.
    #[cfg(unix)]
    fn locked(path: &Path) -> bool {
        File::open(path).is_ok_and(|file| matches!(file.try_lock(), Err(TryLockError::WouldBlock)))
    }

    /// A lock file removed while the agent runs, alone or with its folder
    /// (as a runtime folder is at logout, made again at the next login), is
    /// made and locked again, so a server started afterwards doesn't clear
    /// the running agent's taint.
    #[cfg(unix)]
    #[test]
    fn a_named_server_locks_its_lock_file_again_once_its_removed() {
        let folder = folder("relock");
        let records = folder.join("records");
        make_private(&records).unwrap();
        let path = records.join("taint-named-test");
        let lock = path.with_extension("lock");
        // It hasn't seen the taint, so only its lock keeps the record.
        let server = AgentTaint::join(path.clone(), Duration::from_millis(10));
        let running = server.running.as_ref().unwrap();
        assert!(locked(&lock));

        fs::remove_file(&lock).unwrap();
        assert!(eventually(|| locked(&lock)), "locked again once removed");

        // The folder goes and can't be made again for a while (a file is
        // in its place). The keeper waits while it's swapped.
        let paused = running.lock().unwrap();
        fs::remove_dir_all(&records).unwrap();
        fs::write(&records, "").unwrap();
        drop(paused);
        std::thread::sleep(Duration::from_millis(100));

        // Then it's made again, and a server that saw the taint puts the
        // record back.
        let paused = running.lock().unwrap();
        fs::remove_file(&records).unwrap();
        make_private(&records).unwrap();
        write_record(&path, "the output of tool `fetch`").unwrap();
        drop(paused);
        assert!(
            eventually(|| locked(&lock)),
            "locked again once its folder is back"
        );

        // A server starting now sees the agent running.
        let next = AgentTaint::join(path.clone(), CHECK);
        assert_eq!(next.get().as_deref(), Some("the output of tool `fetch`"));

        // No lock is left behind once they stop.
        drop(server);
        drop(next);
        assert!(!locked(&lock));
        let _ = fs::remove_dir_all(&folder);
    }

    #[test]
    fn the_agent_is_identified_by_the_parent_process() {
        let agent = parent_agent().expect("the test's parent process is identified");
        assert_eq!(parent_agent().as_deref(), Some(agent.as_str()));
        assert!(!agent.ends_with("-0"), "no start time was read: {agent}");
        assert!(agent_running(&agent), "{agent}");
    }

    #[test]
    fn agent_names_are_restricted() {
        assert!(valid_name("claude-code_1"));
        assert!(!valid_name(""));
        assert!(!valid_name("../x"));
        assert!(!valid_name(&"a".repeat(65)));
    }

    #[test]
    fn local_app_data_must_be_a_full_path() {
        let full = std::env::temp_dir();
        assert_eq!(
            local_app_data(Some(full.clone().into_os_string())),
            Some(full.join("mcp-mandate").join("taint"))
        );
        assert_eq!(local_app_data(Some("".into())), None);
        assert_eq!(local_app_data(Some("relative".into())), None);
        assert_eq!(local_app_data(None), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_folder_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let folder = private_folder().unwrap();
        let mode = fs::metadata(&folder).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_someone_else_could_use_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let folder = folder("open");
        let open = folder.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(make_private(&open).is_err());
        let link = folder.join("link");
        std::os::unix::fs::symlink(folder.join("private"), &link).unwrap();
        fs::create_dir(folder.join("private")).unwrap();
        assert!(make_private(&link).is_err());
        let nested = folder.join("a").join("b");
        assert_eq!(make_private(&nested), Ok(()));
        let _ = fs::remove_dir_all(&folder);
    }
}
