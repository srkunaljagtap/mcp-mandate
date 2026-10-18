//! End-to-end tests for `mcp-mandate run`: the real binary relaying to a real
//! child process. `cat` stands in for an MCP server because it echoes every
//! line back, so whatever reaches the "server" comes straight back out.
#![cfg(unix)]

mod common;

use std::process::{Child, ChildStdin, Command};
use std::thread;
use std::time::{Duration, Instant};

use common::{empty_policy, finish, run, start, temp_file};

const PING: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
const INITIALIZED: &[u8] = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";

#[test]
fn relays_protocol_messages_unchanged_in_both_directions() {
    let policy = empty_policy("relay");
    let input = [PING, INITIALIZED].concat();
    let done = run(&["run", "--policy", &policy, "--", "cat"], &[], &input);

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
    let policy = empty_policy("junk");
    let input = [&b"this is not json\n"[..], PING].concat();
    let done = run(&["run", "--policy", &policy, "--", "cat"], &[], &input);

    assert_eq!(done.stdout, PING);
    assert!(
        done.stderr.contains("dropped a line that isn't JSON-RPC"),
        "{}",
        done.stderr
    );
}

#[test]
fn exits_with_the_servers_exit_code() {
    let policy = empty_policy("exit-code");
    let done = run(
        &["run", "--policy", &policy, "--", "sh", "-c", "exit 3"],
        &[],
        b"",
    );
    assert_eq!(done.status.code(), Some(3), "stderr: {}", done.stderr);
}

#[test]
fn exits_when_the_server_does_even_if_the_client_stays_connected() {
    let policy = empty_policy("server-exits");
    let mut child = start(
        &["run", "--policy", &policy, "--", "sh", "-c", "exit 0"],
        &[],
    );
    let stdin = child.stdin.take();
    // stdin stays open until after mcp-mandate has exited.
    let done = finish(child, stdin);
    assert!(done.status.success(), "stderr: {}", done.stderr);
}

#[test]
fn reports_a_server_that_cannot_be_found() {
    let policy = empty_policy("not-found");
    let done = run(
        &[
            "run",
            "--policy",
            &policy,
            "--",
            "mcp-mandate-test-no-such-server",
        ],
        &[],
        b"",
    );

    assert!(!done.status.success());
    assert!(
        done.stdout.is_empty(),
        "nothing may reach the protocol stream"
    );
    assert!(done.stderr.contains("couldn't find"), "{}", done.stderr);
}

#[test]
fn never_logs_a_token_in_the_servers_package() {
    let policy = empty_policy("package-token");
    let done = run(
        &[
            "run",
            "--policy",
            &policy,
            "--",
            "mcp-mandate-test-no-such-folder/npx",
            "-y",
            "git+https://oauth2:T0ken5ecret@gitlab.example/org/server.git",
        ],
        &[],
        b"",
    );

    assert!(
        done.stderr
            .contains("git+https://***@gitlab.example/org/server.git"),
        "{}",
        done.stderr
    );
    assert!(done.stderr.contains("no pinned version"), "{}", done.stderr);
    assert!(!done.stderr.contains("T0ken5ecret"), "{}", done.stderr);
}

#[test]
fn requires_a_policy() {
    let done = run(&["run", "--", "cat"], &[], PING);

    assert_eq!(done.status.code(), Some(2));
    assert!(done.stdout.is_empty());
    assert!(done.stderr.contains("--policy"), "{}", done.stderr);
}

#[test]
fn refuses_to_start_with_a_broken_policy() {
    let policy = temp_file("typo.policy.toml", "mode = \"enforcing\"\n");
    let done = run(
        &[
            "run",
            "--policy",
            &policy.display().to_string(),
            "--",
            "cat",
        ],
        &[],
        PING,
    );

    assert_eq!(done.status.code(), Some(2));
    assert!(done.stdout.is_empty());
    assert!(
        done.stderr.contains("isn't a valid policy"),
        "{}",
        done.stderr
    );
    assert!(
        !done.stderr.contains("started MCP server"),
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

/// Starts a "server" behind `mcp-mandate run` that launches a background
/// helper (a grandchild of mcp-mandate) and reports its pid through a file.
fn start_server_with_helper(test: &str, server_tail: &str) -> (Child, Option<ChildStdin>, String) {
    let policy = empty_policy(test);
    start_with_helper(test, &["run", "--policy", &policy], server_tail)
}

/// The same for any mcp-mandate command (`args`, before `--`) that starts
/// a server.
fn start_with_helper(
    test: &str,
    args: &[&str],
    server_tail: &str,
) -> (Child, Option<ChildStdin>, String) {
    let pid_file =
        std::env::temp_dir().join(format!("mcp-mandate-{test}-{}.pid", std::process::id()));
    let _ = std::fs::remove_file(&pid_file);
    let script = format!(
        "sleep 300 & echo $! > '{}'; {server_tail}",
        pid_file.display()
    );
    let args: Vec<&str> = args
        .iter()
        .copied()
        .chain(["--", "sh", "-c", script.as_str()])
        .collect();
    let mut child = start(&args, &[]);
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
fn sigterm_while_pinning_stops_the_server_and_everything_it_started() {
    let out = std::env::temp_dir().join(format!(
        "mcp-mandate-{}-interrupted.pins.toml",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&out);
    // The server never answers, so `pin` is still waiting for it.
    let (child, stdin, helper) = start_with_helper(
        "pin-sigterm",
        &["pin", "--out", &out.display().to_string()],
        "sleep 300",
    );
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
    assert!(!out.exists(), "nothing was pinned");
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

#[test]
fn refuses_to_start_when_the_audit_log_cannot_be_opened() {
    // A file where the log's folder should be.
    let blocker = temp_file("blocker", "");
    let policy = temp_file(
        "unloggable.policy.toml",
        &format!("[audit]\npath = \"{}/audit.jsonl\"\n", blocker.display()),
    );
    let done = run(
        &[
            "run",
            "--policy",
            &policy.display().to_string(),
            "--",
            "cat",
        ],
        &[],
        PING,
    );

    assert_eq!(done.status.code(), Some(2));
    assert!(done.stdout.is_empty());
    assert!(
        done.stderr.contains("couldn't open the audit log"),
        "{}",
        done.stderr
    );
    assert!(
        !done.stderr.contains("started MCP server"),
        "{}",
        done.stderr
    );
}
