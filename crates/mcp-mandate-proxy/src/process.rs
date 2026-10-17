//! Starting and stopping an MCP server together with everything it starts.
//!
//! Servers are often launched through wrappers (`npx` → `npm exec` → `sh` →
//! `node`), so stopping only the direct child would leave the real server
//! running. On Unix the server leads its own process group, and the whole
//! group is stopped: SIGTERM first, SIGKILL after a grace period.
//!
//! On Windows only the direct child is stopped for now; containing the whole
//! process tree there needs a Job Object.

use std::process::ExitStatus;
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::time::timeout;
use tracing::warn;

/// How long a server gets to stop after being asked before it's killed.
pub const TERM_GRACE: Duration = Duration::from_secs(2);

pub struct ServerProcess {
    child: Child,
    /// The process group id on Unix (the server's own pid).
    #[cfg_attr(not(unix), allow(dead_code))]
    group: Option<u32>,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(unix), allow(dead_code))]
enum Stop {
    Ask,
    Force,
}

impl ServerProcess {
    pub fn spawn(command: &mut Command) -> std::io::Result<Self> {
        #[cfg(unix)]
        command.process_group(0);
        let child = command.kill_on_drop(true).spawn()?;
        let group = if cfg!(unix) { child.id() } else { None };
        Ok(Self { child, group })
    }

    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    /// Waits for the server to exit, then kills anything it left running.
    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait().await?;
        self.signal_tree(Stop::Force);
        Ok(status)
    }

    /// Asks the server's process tree to stop, then kills it if it's still
    /// running after `grace`.
    pub async fn terminate(&mut self, grace: Duration) -> std::io::Result<ExitStatus> {
        self.signal_tree(Stop::Ask);
        if let Ok(status) = timeout(grace, self.wait()).await {
            return status;
        }
        warn!(
            grace_ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX),
            "MCP server ignored the stop request; killing it"
        );
        self.signal_tree(Stop::Force);
        // Covers platforms without process groups; harmless if already dead.
        let _ = self.child.start_kill();
        self.wait().await
    }

    #[cfg(unix)]
    fn signal_tree(&self, stop: Stop) {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;

        let Some(group) = self.group.and_then(|group| i32::try_from(group).ok()) else {
            return;
        };
        let signal = match stop {
            Stop::Ask => Signal::SIGTERM,
            Stop::Force => Signal::SIGKILL,
        };
        // An error here (ESRCH) only means the whole group has already exited.
        let _ = killpg(Pid::from_raw(group), signal);
    }

    #[cfg(not(unix))]
    fn signal_tree(&mut self, stop: Stop) {
        if let Stop::Ask = stop {
            // No polite stop on Windows: TerminateProcess is immediate.
            let _ = self.child.start_kill();
        }
    }
}

/// Stop signals for mcp-mandate itself, registered once at startup so that
/// none is missed at any stage of a session (including during shutdown).
pub struct Signals {
    #[cfg(unix)]
    interrupt: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    terminate: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    hangup: Option<tokio::signal::unix::Signal>,
    #[cfg(windows)]
    ctrl_c: Option<tokio::signal::windows::CtrlC>,
}

impl Signals {
    pub fn new() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Self {
                interrupt: signal(SignalKind::interrupt()).ok(),
                terminate: signal(SignalKind::terminate()).ok(),
                hangup: signal(SignalKind::hangup()).ok(),
            }
        }
        #[cfg(windows)]
        {
            Self {
                ctrl_c: tokio::signal::windows::ctrl_c().ok(),
            }
        }
    }

    /// Waits for the next stop signal and returns the exit code that reports
    /// it (128 + signal number, the shell convention).
    pub async fn recv(&mut self) -> i32 {
        #[cfg(unix)]
        {
            tokio::select! {
                Some(()) = next(&mut self.interrupt) => 130,
                Some(()) = next(&mut self.terminate) => 143,
                Some(()) = next(&mut self.hangup) => 129,
                else => std::future::pending().await,
            }
        }
        #[cfg(windows)]
        {
            if let Some(ctrl_c) = &mut self.ctrl_c
                && ctrl_c.recv().await.is_some()
            {
                return 130;
            }
            std::future::pending().await
        }
    }
}

#[cfg(unix)]
async fn next(signal: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    match signal {
        Some(signal) => signal.recv().await,
        // Registration failed: this signal never arrives.
        None => std::future::pending().await,
    }
}
