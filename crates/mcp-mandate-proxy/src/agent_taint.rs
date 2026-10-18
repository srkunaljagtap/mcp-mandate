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
//! The file lives in a folder only this user can use. If that can't be set
//! up safely, or the agent can't be identified, each server keeps its own
//! taint, with a warning.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use mcp_mandate_gate::SharedTaint;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tracing::{info, warn};

/// Records older than this are removed at startup.
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
}

impl AgentTaint {
    /// The shared taint of the agent that started this process. `None`
    /// (after a warning) when it can't be set up safely.
    pub fn for_this_agent() -> Option<Self> {
        let agent = match std::env::var("MCP_MANDATE_AGENT") {
            Ok(name) if valid_name(&name) => format!("named-{name}"),
            Ok(_) => {
                warn!(
                    "MCP_MANDATE_AGENT must be 1 to 64 letters, digits, `-` or `_`; taint isn't shared between servers"
                );
                return None;
            }
            Err(_) => parent_agent()?,
        };
        let folder = private_folder()?;
        remove_stale(&folder);
        info!("taint is shared with the agent's other servers");
        Some(Self::at(folder.join(format!("taint-{agent}"))))
    }

    fn at(path: PathBuf) -> Self {
        Self { path }
    }
}

impl SharedTaint for AgentTaint {
    fn get(&self) -> Option<String> {
        match fs::read_to_string(&self.path) {
            Ok(source) if !source.is_empty() => Some(source),
            Ok(_) => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            // Fail closed: a record that exists but can't be read counts.
            Err(_) => Some("another server of this agent (its record can't be read)".to_owned()),
        }
    }

    fn set(&self, source: &str) {
        // Written aside, then renamed, so a reader never sees half of it.
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", std::process::id()));
        let written =
            write_private(&temporary, source).and_then(|()| fs::rename(&temporary, &self.path));
        if let Err(error) = written {
            warn!(%error, "couldn't share the taint with the agent's other servers");
        }
    }
}

/// The process that started this one, as `<pid>-<start time>`.
fn parent_agent() -> Option<String> {
    let identified = (|| {
        let me = sysinfo::get_current_pid().ok()?;
        let mut system = System::new();
        let refresh = |system: &mut System, pid: Pid| {
            system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[pid]),
                false,
                ProcessRefreshKind::nothing(),
            );
        };
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

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A folder only this user can read or write, made if needed.
fn private_folder() -> Option<PathBuf> {
    let refuse = |problem: String| {
        warn!("{problem}; taint isn't shared between servers");
        None
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

        let uid = nix::unistd::getuid().as_raw();
        let folder = match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            Some(runtime) if runtime.is_absolute() => runtime.join("mcp-mandate"),
            _ => std::env::temp_dir().join(format!("mcp-mandate-{uid}")),
        };
        let _ = fs::DirBuilder::new().mode(0o700).create(&folder);
        // Someone else could have made it first (in a shared /tmp): it must
        // be a real folder, ours, and closed to others.
        let Ok(metadata) = fs::symlink_metadata(&folder) else {
            return refuse(format!("couldn't make {}", folder.display()));
        };
        if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0
        {
            return refuse(format!(
                "{} isn't a private folder of this user",
                folder.display()
            ));
        }
        Some(folder)
    }
    #[cfg(not(unix))]
    {
        // Per-user on Windows, and closed to other users by default.
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let folder = base.join("mcp-mandate").join("taint");
        match fs::create_dir_all(&folder) {
            Ok(()) => Some(folder),
            Err(error) => refuse(format!("couldn't make {}: {error}", folder.display())),
        }
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

/// Removes records nobody has touched for a week (agents long gone).
fn remove_stale(folder: &Path) {
    let Ok(entries) = fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        let old = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age > STALE);
        if old && entry.file_name().to_string_lossy().starts_with("taint-") {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_one_server_records_the_others_read() {
        let folder =
            std::env::temp_dir().join(format!("mcp-mandate-agent-taint-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        let path = folder.join("taint-test");
        let _ = fs::remove_file(&path);
        let first = AgentTaint::at(path.clone());
        let second = AgentTaint::at(path);
        assert_eq!(second.get(), None);
        first.set("the output of tool `fetch`");
        assert_eq!(second.get().as_deref(), Some("the output of tool `fetch`"));
        let _ = fs::remove_dir_all(&folder);
    }

    #[test]
    fn agent_names_are_restricted() {
        assert!(valid_name("claude-code_1"));
        assert!(!valid_name(""));
        assert!(!valid_name("../x"));
        assert!(!valid_name(&"a".repeat(65)));
    }

    #[cfg(unix)]
    #[test]
    fn the_folder_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let folder = private_folder().unwrap();
        let mode = fs::metadata(&folder).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
}
