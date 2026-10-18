//! Helpers shared by the end-to-end tests: running the real `mcp-mandate`
//! binary with a scripted server, and talking to it one message at a time.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

pub struct Finished {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Writes `contents` to a file unique to this test process.
pub fn temp_file(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("mcp-mandate-{}-{name}", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

/// A policy file with no pins: protocol plumbing passes, tools don't.
pub fn empty_policy(test: &str) -> String {
    temp_file(&format!("{test}.policy.toml"), "")
        .display()
        .to_string()
}

/// A `sh` script for a server that answers each line it reads with the next
/// response (an empty response reads a line without answering), then
/// swallows the rest. Responses are passed in `MOCK_1`, `MOCK_2`, ….
pub fn scripted_server(responses: &[&str]) -> (String, Vec<(String, String)>) {
    let vars: Vec<String> = (1..=responses.len())
        .map(|n| format!("\"$MOCK_{n}\""))
        .collect();
    let script = format!(
        "for r in {}; do read -r _ || exit 0; if [ -n \"$r\" ]; then printf '%s\\n' \"$r\"; fi; done; cat > /dev/null",
        vars.join(" ")
    );
    let envs = responses
        .iter()
        .enumerate()
        .map(|(n, response)| (format!("MOCK_{}", n + 1), (*response).to_owned()))
        .collect();
    (script, envs)
}

pub fn start(args: &[&str], envs: &[(String, String)]) -> Child {
    // Every process the tests start shares this test binary as its parent:
    // each gets its own agent name, so their taint stays apart unless a
    // test gives two of them the same one.
    static NEXT_AGENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let agent = format!(
        "test-{}-{}",
        std::process::id(),
        NEXT_AGENT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    );
    spawn(command(args).env("MCP_MANDATE_AGENT", agent), envs)
}

/// Like [`start`], but the agent is identified as it is by default: by the
/// process that started mcp-mandate, which is this test binary for every
/// process started this way.
pub fn start_unnamed(args: &[&str], envs: &[(String, String)]) -> Child {
    spawn(command(args).env_remove("MCP_MANDATE_AGENT"), envs)
}

fn command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-mandate"));
    command.args(args).env("XDG_RUNTIME_DIR", runtime_dir());
    command
}

fn spawn(command: &mut Command, envs: &[(String, String)]) -> Child {
    command
        .envs(envs.iter().map(|(key, value)| (key, value)))
        .env("MCP_MANDATE_LOG", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start mcp-mandate")
}

/// A runtime folder for the processes the tests start, so the taint they
/// share stays out of the user's own.
pub fn runtime_dir() -> PathBuf {
    std::env::temp_dir().join(format!("mcp-mandate-{}-runtime", std::process::id()))
}

/// Waits for the process (failing the test after 30 s instead of hanging),
/// collecting its output.
pub fn finish(mut child: Child, stdin: Option<ChildStdin>) -> Finished {
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let stdout = thread::spawn(move || {
        let mut buf = Vec::new();
        out.read_to_end(&mut buf).unwrap();
        buf
    });
    let stderr = thread::spawn(move || {
        let mut buf = String::new();
        err.read_to_string(&mut buf).unwrap();
        buf
    });
    let status = wait(&mut child);
    drop(stdin);
    Finished {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("mcp-mandate didn't exit within 30 seconds");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Sends `input`, closes stdin like a client shutting down, and waits.
pub fn run(args: &[&str], envs: &[(String, String)], input: &[u8]) -> Finished {
    let mut child = start(args, envs);
    let mut stdin = child.stdin.take().unwrap();
    // Ignore errors: the process may legitimately exit before reading it all.
    let _ = stdin.write_all(input);
    drop(stdin);
    finish(child, None)
}

/// A client conversation with `mcp-mandate run`, one message at a time.
pub struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
    stderr: thread::JoinHandle<String>,
}

impl Session {
    pub fn start(args: &[&str], envs: &[(String, String)]) -> Self {
        Self::of(start(args, envs))
    }

    /// A session whose agent is identified by default (see [`start_unnamed`]).
    pub fn start_unnamed(args: &[&str], envs: &[(String, String)]) -> Self {
        Self::of(start_unnamed(args, envs))
    }

    fn of(mut child: Child) -> Self {
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = thread::spawn(move || {
            let mut buf = String::new();
            let _ = err.read_to_string(&mut buf);
            buf
        });
        Self {
            child,
            stdin,
            lines,
            stderr,
        }
    }

    pub fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// The next message the client receives (fails after 10 s).
    pub fn recv(&mut self) -> Value {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(10))
            .expect("no message from mcp-mandate within 10 seconds");
        serde_json::from_str(&line).unwrap()
    }

    /// The `mcp-mandate` process's id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Hangs up and waits for the process; returns its exit status and logs.
    pub fn finish(mut self) -> (ExitStatus, String) {
        drop(self.stdin.take());
        let status = wait(&mut self.child);
        (status, self.stderr.join().unwrap())
    }
}
