//! End-to-end tests for `mcp-mandate run`: the real binary relaying to a real
//! child process. `cat` stands in for an MCP server because it echoes every
//! line back, so whatever reaches the "server" comes straight back out.
#![cfg(unix)]

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PING: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
const INITIALIZED: &[u8] = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";

struct Finished {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: String,
}

fn start(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_mcp-mandate"))
        .args(args)
        .env("MCP_MANDATE_LOG", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start mcp-mandate")
}

/// Waits for the process (failing the test after 30 s instead of hanging),
/// collecting its output.
fn finish(mut child: Child, stdin: Option<ChildStdin>) -> Finished {
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
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("mcp-mandate didn't exit within 30 seconds");
        }
        thread::sleep(Duration::from_millis(20));
    };
    drop(stdin);
    Finished {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

/// Sends `input`, closes stdin like a client shutting down, and waits.
fn run(args: &[&str], input: &[u8]) -> Finished {
    let mut child = start(args);
    let mut stdin = child.stdin.take().unwrap();
    // Ignore errors: the process may legitimately exit before reading it all.
    let _ = stdin.write_all(input);
    drop(stdin);
    finish(child, None)
}

#[test]
fn relays_messages_unchanged_in_both_directions() {
    let input = [PING, INITIALIZED].concat();
    let done = run(&["run", "--", "cat"], &input);

    assert_eq!(done.stdout, input, "stderr: {}", done.stderr);
    assert!(done.status.success(), "stderr: {}", done.stderr);
    assert!(
        done.stderr.contains("started MCP server"),
        "{}",
        done.stderr
    );
}

#[test]
fn drops_lines_that_are_not_json_rpc() {
    let input = [&b"this is not json\n"[..], PING].concat();
    let done = run(&["run", "--", "cat"], &input);

    assert_eq!(done.stdout, PING);
    assert!(
        done.stderr.contains("dropped a line that isn't JSON-RPC"),
        "{}",
        done.stderr
    );
}

#[test]
fn exits_with_the_servers_exit_code() {
    let done = run(&["run", "--", "sh", "-c", "exit 3"], b"");
    assert_eq!(done.status.code(), Some(3), "stderr: {}", done.stderr);
}

#[test]
fn exits_when_the_server_does_even_if_the_client_stays_connected() {
    let mut child = start(&["run", "--", "sh", "-c", "exit 0"]);
    let stdin = child.stdin.take();
    // stdin stays open until after mcp-mandate has exited.
    let done = finish(child, stdin);
    assert!(done.status.success(), "stderr: {}", done.stderr);
}

#[test]
fn reports_a_server_that_cannot_be_found() {
    let done = run(&["run", "--", "mcp-mandate-test-no-such-server"], b"");

    assert!(!done.status.success());
    assert!(
        done.stdout.is_empty(),
        "nothing may reach the protocol stream"
    );
    assert!(done.stderr.contains("couldn't find"), "{}", done.stderr);
}

#[test]
fn refuses_a_policy_until_policies_are_enforced() {
    let done = run(&["run", "--policy", "policy.toml", "--", "cat"], PING);

    assert_eq!(done.status.code(), Some(2));
    assert!(done.stdout.is_empty());
    assert!(
        done.stderr.contains("isn't enforced yet"),
        "{}",
        done.stderr
    );
}

/// Is `pid` still running? Zombies (exited, waiting to be reaped) count as
/// gone. Uses `ps`, which works the same on Linux and macOS.
fn is_running(pid: &str) -> bool {
    let output = Command::new("ps")
        .args(["-o", "stat=", "-p", pid])
        .output()
        .expect("run ps");
    let state = String::from_utf8_lossy(&output.stdout);
    let state = state.trim();
    !state.is_empty() && !state.starts_with('Z')
}

fn wait_until_gone(pid: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !is_running(pid) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Starts a "server" that launches a background helper (a grandchild of
/// mcp-mandate) and reports its pid through a file.
fn start_server_with_helper(test: &str, server_tail: &str) -> (Child, Option<ChildStdin>, String) {
    let pid_file =
        std::env::temp_dir().join(format!("mcp-mandate-{test}-{}.pid", std::process::id()));
    let _ = std::fs::remove_file(&pid_file);
    let script = format!(
        "sleep 300 & echo $! > '{}'; {server_tail}",
        pid_file.display()
    );
    let mut child = start(&["run", "--", "sh", "-c", &script]);
    let stdin = child.stdin.take();

    let deadline = Instant::now() + Duration::from_secs(10);
    let helper = loop {
        if let Ok(pid) = std::fs::read_to_string(&pid_file)
            && !pid.trim().is_empty()
        {
            break pid.trim().to_owned();
        }
        assert!(Instant::now() < deadline, "server never started its helper");
        thread::sleep(Duration::from_millis(20));
    };
    let _ = std::fs::remove_file(&pid_file);
    (child, stdin, helper)
}

#[test]
fn sigterm_stops_the_server_and_everything_it_started() {
    let (child, stdin, helper) = start_server_with_helper("sigterm", "cat");
    assert!(is_running(&helper));

    let sent = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let done = finish(child, stdin);

    assert_eq!(done.status.code(), Some(143), "stderr: {}", done.stderr);
    assert!(
        wait_until_gone(&helper),
        "the server's helper process survived"
    );
}

#[test]
fn a_server_that_ignores_stop_requests_is_killed() {
    // The server ignores both its input closing and SIGTERM (the ignore is
    // inherited by its helper), so only SIGKILL ends it.
    let (child, stdin, helper) = start_server_with_helper("stubborn", "trap '' TERM; sleep 300");
    drop(stdin); // the client disconnects
    let done = finish(child, None);

    assert_eq!(done.status.code(), Some(137), "stderr: {}", done.stderr);
    assert!(
        done.stderr.contains("ignored the stop request"),
        "{}",
        done.stderr
    );
    assert!(
        wait_until_gone(&helper),
        "the server's helper process survived"
    );
}
