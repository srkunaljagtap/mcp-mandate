//! Starting and stopping an MCP server together with everything it starts.
//!
//! Servers are often launched through wrappers (`npx` → `npm exec` → `sh` →
//! `node`), so stopping only the direct child would leave the real server
//! running.
//!
//! - On Unix the server leads its own process group, and the whole group is
//!   stopped: SIGTERM first, SIGKILL after a grace period.
//! - On Windows the server is put in a Job Object that kills everything in
//!   it when it's closed, which happens when the server is stopped and also
//!   if mcp-mandate itself dies. (Anything the server starts in the moment
//!   before it joins the job escapes; servers take far longer than that to
//!   start their first child.)

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
    /// The Job Object holding the server and what it starts, on Windows.
    #[cfg(windows)]
    job: Option<win32job::Job>,
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
        Ok(Self {
            #[cfg(windows)]
            job: contain(&child),
            child,
            group,
        })
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

    #[cfg(windows)]
    fn signal_tree(&mut self, _stop: Stop) {
        // Windows has no polite stop: closing the job kills everything in
        // it at once, the server included.
        self.job = None;
        let _ = self.child.start_kill();
    }

    #[cfg(not(any(unix, windows)))]
    fn signal_tree(&mut self, stop: Stop) {
        if let Stop::Ask = stop {
            let _ = self.child.start_kill();
        }
    }
}

impl Drop for ServerProcess {
    /// Kills the server's whole tree if it's still running, for example
    /// after a panic. (Only while the server itself hasn't been reaped, so
    /// its group id can't belong to someone else yet.)
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            self.signal_tree(Stop::Force);
        }
    }
}

/// Puts the server in a Job Object that kills every process in it when the
/// job closes. Without one (if Windows refuses), only the server itself
/// can be stopped.
#[cfg(windows)]
fn contain(child: &Child) -> Option<win32job::Job> {
    let mut limits = win32job::ExtendedLimitInfo::new();
    limits.limit_kill_on_job_close();
    let contained = child
        .raw_handle()
        .ok_or_else(|| "the server already exited".to_owned())
        .and_then(|handle| {
            let job = win32job::Job::create_with_limit_info(&limits)
                .map_err(|error| error.to_string())?;
            job.assign_process(handle as isize)
                .map_err(|error| error.to_string())?;
            Ok(job)
        });
    match contained {
        Ok(job) => Some(job),
        Err(error) => {
            warn!(%error, "couldn't put the MCP server in a Job Object; stopping it may leave processes it started running");
            None
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

impl Default for Signals {
    fn default() -> Self {
        Self::new()
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

#[cfg(all(test, unix))]
mod unix_tests {
    use std::process::Stdio;

    use tokio::io::{AsyncBufReadExt, BufReader};

    use super::*;

    /// Whether a process with this id is running (a zombie, exited but not
    /// yet reaped, counts as gone).
    fn alive(pid: &str) -> bool {
        let output = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&output.stdout);
        let state = state.trim();
        !state.is_empty() && !state.starts_with('Z')
    }

    #[tokio::test]
    async fn dropping_a_running_server_stops_what_it_started() {
        // The "server" starts a helper and reports its id.
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 300 & echo $!; sleep 300"])
            .stdout(Stdio::piped());
        let mut server = ServerProcess::spawn(&mut command).unwrap();
        let stdout = server.child_mut().stdout.take().unwrap();
        let helper = timeout(
            Duration::from_secs(10),
            BufReader::new(stdout).lines().next_line(),
        )
        .await
        .expect("the script reported its helper")
        .unwrap()
        .unwrap();
        assert!(alive(&helper), "the helper should be running");

        drop(server);
        for _ in 0..50 {
            if !alive(&helper) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("process {helper} outlived the server it was started by");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::process::Stdio;

    use tokio::io::{AsyncBufReadExt, BufReader};

    use super::*;

    /// Whether a process with this id is running.
    fn alive(pid: u32) -> bool {
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).contains(&pid.to_string())
    }

    #[tokio::test]
    async fn stopping_the_server_stops_what_it_started() {
        // The "server" starts a long ping and reports its id.
        let script = "$p = Start-Process -FilePath ping.exe -ArgumentList '-n','120','127.0.0.1' -WindowStyle Hidden -PassThru; Write-Output $p.Id; Start-Sleep -Seconds 120";
        let mut command = Command::new("powershell");
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .stdout(Stdio::piped());
        let mut server = ServerProcess::spawn(&mut command).unwrap();
        let stdout = server.child_mut().stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let line = timeout(Duration::from_secs(60), lines.next_line())
            .await
            .expect("the script reported its child")
            .unwrap()
            .unwrap();
        let pid: u32 = line.trim().parse().unwrap();
        assert!(alive(pid), "the grandchild should be running");

        server.terminate(Duration::from_millis(200)).await.unwrap();
        for _ in 0..50 {
            if !alive(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("process {pid} outlived the server it was started by");
    }
}
