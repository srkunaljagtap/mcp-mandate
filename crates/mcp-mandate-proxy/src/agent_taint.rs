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
//! the record an earlier session left.
//!
//! The file lives in a folder only this user can use. If that can't be set
//! up safely, or the agent can't be identified, each server keeps its own
//! taint, with a warning.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use mcp_mandate_gate::SharedTaint;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tracing::{info, warn};

/// Records of agents that are gone are removed once untouched this long.
const STALE: Duration = Duration::from_secs(7 * 24 * 3600);

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
    seen: OnceLock<String>,
    /// For a named agent: the shared lock that shows this server is running.
    _running: Option<File>,
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
        let running = if named { join_named(&path) } else { None };
        info!("taint is shared with the agent's other servers");
        Some(Self {
            _running: running,
            ..Self::at(path)
        })
    }

    fn at(path: PathBuf) -> Self {
        Self {
            path,
            seen: OnceLock::new(),
            _running: None,
        }
    }

    /// Writes the record aside, then renames it into place, so a reader
    /// never sees half of it. If that fails, makes the folder again
    /// (something may have removed it) and tries once more.
    fn write(&self, source: &str) {
        let attempt = || {
            let temporary = self
                .path
                .with_extension(format!("{}.tmp", std::process::id()));
            let written =
                write_private(&temporary, source).and_then(|()| fs::rename(&temporary, &self.path));
            if written.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            written
        };
        let mut written = attempt();
        if written.is_err()
            && let Some(folder) = self.path.parent()
            && make_private(folder).is_ok()
        {
            written = attempt();
        }
        if let Err(error) = written {
            warn!(%error, "couldn't share the taint with the agent's other servers");
        }
    }
}

impl SharedTaint for AgentTaint {
    fn get(&self) -> Option<String> {
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
                let _ = self.seen.set(source.clone());
                Some(source)
            }
            None => {
                // Removed while the agent still runs (by hand, or by a
                // cleaner of temporary files): put it back for the others.
                let seen = self.seen.get()?;
                self.write(seen);
                Some(seen.clone())
            }
        }
    }

    fn set(&self, source: &str) {
        let _ = self.seen.set(source.to_owned());
        self.write(source);
    }
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
            process.start_time(),
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
    let (Ok(pid), Ok(start)) = (pid.parse::<u32>(), start.parse::<u64>()) else {
        return false;
    };
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    refresh(&mut system, pid);
    system
        .process(pid)
        .is_some_and(|process| process.start_time() == start)
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
    options.open(record.with_extension("lock"))
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
            Ok(()) => return Some(folder),
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

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(text.as_bytes())
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

    /// A folder for one test's records.
    fn folder(test: &str) -> PathBuf {
        let folder = std::env::temp_dir().join(format!(
            "mcp-mandate-agent-taint-{}-{test}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&folder);
        fs::create_dir_all(&folder).unwrap();
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
    fn a_running_agents_record_is_kept_however_old() {
        let folder = folder("stale");
        let me = sysinfo::get_current_pid().unwrap();
        let mut system = System::new();
        refresh(&mut system, me);
        let start = system.process(me).unwrap().start_time();
        let running = folder.join(format!("taint-{}-{start}", me.as_u32()));
        let recycled = folder.join(format!("taint-{}-{}", me.as_u32(), start + 1));
        let fresh_gone = folder.join(format!("taint-{}-{}", me.as_u32(), start + 2));
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
        let first = AgentTaint {
            _running: join_named(&path),
            ..AgentTaint::at(path.clone())
        };
        assert!(first._running.is_some());
        first.set("the output of tool `fetch`");

        // A second server joins while the first runs: the taint holds,
        // however old, and cleanup leaves it alone.
        let second = AgentTaint {
            _running: join_named(&path),
            ..AgentTaint::at(path.clone())
        };
        age(&path);
        remove_stale(&folder);
        assert!(second.get().is_some());
        drop(first);
        remove_stale(&folder);
        assert!(second.get().is_some());

        // Once none runs, the next session starts clean.
        drop(second);
        let next = AgentTaint {
            _running: join_named(&path),
            ..AgentTaint::at(path.clone())
        };
        assert_eq!(next.get(), None);
        next.set("the output of tool `fetch`");
        drop(next);

        // An old record with no server running is cleaned up.
        age(&path);
        remove_stale(&folder);
        assert!(!path.exists());
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
