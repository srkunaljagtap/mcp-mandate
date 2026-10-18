//! Runs an MCP server as a child process and relays its stdio transport
//! through the gate.
//!
//! ```text
//! agent stdin  ─▶ client reader ─▶ gate ─▶ server queue ─▶ server writer ─▶ server stdin
//! agent stdout ◀─ client writer ◀─ client queue ◀─ gate ◀─ server reader ◀─ server stdout
//!                 (a blocked request's answer goes back the way it came)
//! server stderr ──▶ agent's stderr, untouched
//! ```
//!
//! Each output has exactly one writer task, fed by a queue, so an answer the
//! gate makes and a message it forwards can never interleave mid-line.
//! stdout carries the protocol; logs go to stderr through `tracing`.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcp_mandate_gate::{Action, Gate};
use mcp_mandate_pin::Inventory;
use mcp_mandate_taint::SecretDetector;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::framing::{FrameError, MAX_MESSAGE_BYTES, read_frame};
use crate::inventory::{self, Rpc, result_of};
use crate::process::{ServerProcess, TERM_GRACE};

/// How long a server gets to exit on its own after its input closes.
const EXIT_GRACE: Duration = Duration::from_secs(5);
/// How long to keep delivering a server's last output after it stops.
const DRAIN_GRACE: Duration = Duration::from_secs(5);
/// Messages queued per output before a reader waits for its writer. Each
/// can be up to [`MAX_MESSAGE_BYTES`], so this also bounds memory.
const QUEUE: usize = 16;
/// How long a reader waits for room in a full queue before giving up on a
/// side that has stopped reading (a hung server, or an agent that's gone).
const SEND_STALL: Duration = Duration::from_secs(300);
/// How long `inventory` waits for a server to answer everything it's asked.
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(60);

/// The MCP server to run: a program and its arguments.
///
/// It displays as a label for people, in logs and in the files they keep
/// (pins, Scout's draft). Arguments can carry passwords and tokens, so
/// anything that looks like one is masked: the user name, password, query
/// and fragment of every URL, wherever it is in an argument
/// (`name@git+https://…`), the value of a variable (`NAME=value`), of an
/// option or header named like a secret (`--api-key`, `Authorization:`),
/// and anything shaped like a known kind of key. A value can have spaces,
/// so it is masked up to its closing quote, if it opens one, or else up to
/// the next option. Split over arguments, it is followed for as many words
/// as it can have: one after `--api-key`, two (a scheme and a token) after
/// `Authorization:`.
#[derive(Debug, Clone)]
pub struct ServerCommand {
    pub program: OsString,
    pub args: Vec<OsString>,
}

/// Shown in place of a value that may be secret.
const MASK: &str = "***";

/// Parts of a name (of an option, a variable or a header) that say its
/// value is a secret.
const SECRET_NAMES: [&str; 9] = [
    "key",
    "token",
    "secret",
    "pass",
    "pwd",
    "auth",
    "credential",
    "cookie",
    "session",
];

impl fmt::Display for ServerCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secrets = SecretDetector::default();
        write!(f, "{}", self.program.to_string_lossy())?;
        // How many words of a value such as `--api-key`'s are still to come.
        let mut value = 0;
        for arg in &self.args {
            let (shown, value_next) = mask(&arg.to_string_lossy(), value, &secrets);
            write!(f, " {shown}")?;
            value = value_next;
        }
        Ok(())
    }
}

/// One argument as a [`ServerCommand`] shows it, for a part of a command
/// shown on its own, such as the package a launcher runs.
pub fn masked(arg: &str) -> String {
    mask(arg, 0, &SecretDetector::default()).0
}

/// How far a secret goes on past the word that starts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Run {
    /// It doesn't.
    No,
    /// Up to the next option: the value of `--api-key` or `Authorization:`.
    /// It goes on into the next arguments until it has this many more
    /// words, as a client may pass each word as an argument of its own.
    Value(usize),
    /// Up to the next option in this argument: the rest of `NAME=value` or
    /// `--password=value`, as a value can have spaces.
    Rest,
    /// Up to the word that closes this quote: `PASSWORD='a b c'`.
    Quote(char),
}

/// One argument with anything that may be a secret masked, and how many
/// words of a secret's value the arguments after it still hold. `value` is
/// how many this one does.
fn mask(arg: &str, value: usize, secrets: &SecretDetector) -> (String, usize) {
    // Word by word, for scripts passed to a shell (`sh -c "…"`) and values
    // with spaces (`Authorization: Bearer …`).
    let mut run = if value > 0 {
        Run::Value(value)
    } else {
        Run::No
    };
    let mut words = Vec::new();
    for raw in arg.split_whitespace() {
        let (open, word, close) = unquote(raw);
        if matches!(run, Run::Value(_) | Run::Rest) && word.starts_with('-') {
            run = Run::No;
        }
        let shown = if run == Run::No {
            let (shown, starts) = redact_word(word, secrets);
            run = match starts {
                // The quote around the value closes in this same word.
                Run::Quote(quote) if close.contains(quote) => Run::No,
                starts => starts,
            };
            shown
        } else {
            run = match run {
                Run::Quote(quote) if raw.ends_with(quote) => Run::No,
                Run::Value(left) => Run::Value(left.saturating_sub(1)),
                run => run,
            };
            MASK.to_owned()
        };
        words.push(format!("{open}{shown}{close}"));
    }
    // A value that hasn't all its words yet goes on in the next argument:
    // `--api-key` `abc123`, `Authorization:` `Bearer` `abc123`.
    let value_next = match run {
        Run::Value(left) => left,
        _ => 0,
    };
    (words.join(" "), value_next)
}

/// One word of an argument, with anything that may be a secret masked, and
/// how far past it a secret it starts goes.
fn redact_word(word: &str, secrets: &SecretDetector) -> (String, Run) {
    // A URL, wherever it is in the word (`name@git+https://…`), unless it's
    // in a value masked as such (`DATABASE_URL=postgres://…`).
    let url = find_url(word).filter(|&(start, _)| start == 0 || assignment(word).is_none());
    let (shown, run) = if let Some(url) = url {
        (without_credentials(word, url), Run::No)
    } else if let Some((name, separator, value)) = assignment(word) {
        // A variable's value may be anything; an option's or a header's
        // is a secret when its name says so.
        if (separator == '=' && !name.starts_with('-')) || secret_name(name) {
            let shown = if value.is_empty() {
                format!("{name}{separator}")
            } else {
                format!("{name}{separator}{MASK}")
            };
            (shown, secret_run(name, separator, value))
        } else {
            // `--header=Authorization: …`, `--url='https://…'`
            let (open, value, close) = unquote(value);
            let (value, run) = redact_word(value, secrets);
            (format!("{name}{separator}{open}{value}{close}"), run)
        }
    } else if word.starts_with('-') && secret_name(word) {
        (word.to_owned(), Run::Value(1))
    } else {
        (word.to_owned(), Run::No)
    };
    let shown = secrets
        .redact_text(&shown)
        .map_or(shown, |(redacted, _)| redacted);
    (shown, run)
}

/// How far the masked value of `name` goes past its first word.
fn secret_run(name: &str, separator: char, value: &str) -> Run {
    match value.chars().next() {
        // `Authorization:` with its scheme and token after a space.
        None if secret_name(name) && separator == ':' => Run::Value(2),
        // `--token=` with the value after a space.
        None if secret_name(name) => Run::Value(1),
        None => Run::No,
        Some(quote @ ('"' | '\'')) if value[1..].contains(quote) => Run::No,
        Some(quote @ ('"' | '\'')) => Run::Quote(quote),
        // `Authorization:Bearer` with the token after it.
        Some(_) if separator == ':' => Run::Value(1),
        Some(_) => Run::Rest,
    }
}

/// Where the first URL in `text` starts, and where its `://` is. A scheme
/// is a letter and then letters, digits, `+`, `-` or `.`; what comes before
/// it can be anything, such as a package's name (`name@git+https://…`).
fn find_url(text: &str) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(found) = text[from..].find("://") {
        let separator = from + found;
        // The scheme characters just before `://`, from the first letter.
        let start = text[..separator]
            .trim_end_matches(|c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            .len();
        if let Some(letter) = text[start..separator].find(|c: char| c.is_ascii_alphabetic()) {
            return Some((start + letter, separator));
        }
        from = separator + 3;
    }
    None
}

/// `word` with the user name and password, query and fragment of every URL
/// in it masked. `url` is where the first one is, as [`find_url`] gives it.
fn without_credentials(word: &str, url: (usize, usize)) -> String {
    let (start, separator) = url;
    let mut shown = word[..start].to_owned();
    let mut scheme = &word[start..separator];
    let mut rest = &word[separator + 3..];
    loop {
        // A URL ends where the next one starts: `kafka://a@h1,kafka://b@h2`.
        let next = find_url(rest);
        let url = &rest[..next.map_or(rest.len(), |(start, _)| start)];
        let (authority, tail) = url.split_at(url.find(['/', '?', '#']).unwrap_or(url.len()));
        shown.push_str(scheme);
        shown.push_str("://");
        match authority.rfind('@') {
            Some(at) => {
                shown.push_str(MASK);
                shown.push_str(&authority[at..]);
            }
            None => shown.push_str(authority),
        }
        let query = tail.find(['?', '#']);
        shown.push_str(&tail[..query.unwrap_or(tail.len())]);
        // Whatever follows a query or fragment is part of it.
        let (Some((start, separator)), None) = (next, query) else {
            return shown;
        };
        scheme = &rest[start..separator];
        rest = &rest[separator + 3..];
    }
}

/// Splits `--name=value`, `NAME=value` or `Name:value` at the separator
/// that follows the name.
fn assignment(word: &str) -> Option<(&str, char, &str)> {
    let (name, rest) = word.split_at(word.find(['=', ':'])?);
    let separator = if rest.starts_with('=') { '=' } else { ':' };
    let value = &rest[1..];
    let bare = name.trim_start_matches('-');
    let option = bare.len() < name.len();
    let valid = bare.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        // An option's value follows `=`, and `pkg==1.2` is a version.
        && !(option && separator == ':')
        && !(separator == '=' && value.starts_with('='));
    valid.then_some((name, separator, value))
}

fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_NAMES.iter().any(|part| name.contains(part))
}

/// Splits the quotes a shell script puts around a word from the word.
fn unquote(word: &str) -> (&str, &str, &str) {
    let quote = |c: char| c == '"' || c == '\'';
    let start = word.len() - word.trim_start_matches(quote).len();
    let end = start.max(word.trim_end_matches(quote).len());
    (&word[..start], &word[start..end], &word[end..])
}

pub use crate::ProxyError;
pub use crate::process::Signals;

#[derive(Debug, Clone, Copy)]
enum Side {
    Client,
    Server,
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Client => "client",
            Self::Server => "server",
        })
    }
}

/// An item in a writer's queue.
#[derive(Debug, PartialEq, Eq)]
enum Outgoing {
    Frame(Vec<u8>),
    /// Close this output (the server's input, when the client hangs up).
    Close,
}

/// Starts `command`, relays the agent's stdin/stdout to it through `gate`
/// until either side ends, and returns the exit code to finish with (the
/// server's own, where it has one).
pub async fn run(command: &ServerCommand, gate: Gate) -> Result<i32, ProxyError> {
    // Register before starting the server so no signal is missed.
    let mut signals = Signals::new();
    let (mut server, server_in, server_out) = start(command)?;
    info!(server = %command, pid = server.id(), "started MCP server");

    // Taken out when the session ends, so a reader still running then
    // (stopping isn't instant) can't check or record anything after it.
    let gate = Arc::new(Mutex::new(Some(gate)));
    let (to_client, client_queue) = mpsc::channel(QUEUE);
    let (to_server, server_queue) = mpsc::channel(QUEUE);
    let tasks = Tasks {
        client_writer: tokio::spawn(write_frames(tokio::io::stdout(), client_queue)),
        server_writer: tokio::spawn(write_frames(server_in, server_queue)),
        client_reader: tokio::spawn(read_side(
            BufReader::new(tokio::io::stdin()),
            Side::Client,
            Arc::clone(&gate),
            to_server.clone(),
            to_client.clone(),
        )),
        server_reader: tokio::spawn(read_side(
            BufReader::new(server_out),
            Side::Server,
            Arc::clone(&gate),
            to_server,
            to_client,
        )),
    };
    let result = supervise(&mut server, &mut signals, tasks).await;
    if let Ok(mut slot) = gate.lock()
        && let Some(mut gate) = slot.take()
    {
        gate.end_session(result.as_ref().ok().copied());
    }
    result
}

/// Starts the server with piped stdin and stdout.
fn start(command: &ServerCommand) -> Result<(ServerProcess, ChildStdin, ChildStdout), ProxyError> {
    start_with(command, &[])
}

/// Starts the server without the environment variables named in `withheld`.
fn start_with(
    command: &ServerCommand,
    withheld: &[&str],
) -> Result<(ServerProcess, ChildStdin, ChildStdout), ProxyError> {
    let program = resolve(&command.program)?;
    let mut builder = Command::new(&program);
    builder
        .args(&command.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for name in withheld {
        builder.env_remove(name);
    }
    let mut server = ServerProcess::spawn(&mut builder).map_err(|source| ProxyError::Spawn {
        program: command.program.to_string_lossy().into_owned(),
        source,
    })?;
    let child = server.child_mut();
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        unreachable!("stdin and stdout were set to piped");
    };
    Ok((server, stdin, stdout))
}

type Reader = JoinHandle<Result<u64, FrameError>>;
type Writer = JoinHandle<std::io::Result<u64>>;

struct Tasks {
    client_reader: Reader,
    server_reader: Reader,
    client_writer: Writer,
    server_writer: Writer,
}

impl Tasks {
    fn abort_all(&self) {
        self.client_reader.abort();
        self.server_reader.abort();
        self.client_writer.abort();
        self.server_writer.abort();
    }
}

/// Waits for the first side to finish (or a stop signal), then shuts the
/// rest down in order. Returns the exit code to finish with.
async fn supervise(
    server: &mut ServerProcess,
    signals: &mut Signals,
    mut tasks: Tasks,
) -> Result<i32, ProxyError> {
    let code = tokio::select! {
        status = server.wait() => {
            let status = status.map_err(ProxyError::Wait)?;
            info!(%status, "MCP server exited");
            deliver_remaining(&mut tasks, true).await;
            exit_code(status)
        }
        result = &mut tasks.client_reader => {
            log_reader(Side::Client, result);
            // The client hung up, so the server's input has been closed;
            // well-behaved servers exit now.
            let status = wait_or_stop(server, signals).await?;
            deliver_remaining(&mut tasks, true).await;
            exit_code(status)
        }
        result = &mut tasks.server_reader => {
            log_reader(Side::Server, result);
            let status = wait_or_stop(server, signals).await?;
            deliver_remaining(&mut tasks, false).await;
            exit_code(status)
        }
        code = signals.recv() => {
            warn!(code, "received a stop signal; stopping the MCP server");
            let status = server.terminate(TERM_GRACE).await.map_err(ProxyError::Wait)?;
            info!(%status, "MCP server exited");
            code
        }
    };
    tasks.abort_all();
    Ok(code)
}

/// After one side has closed: gives the server [`EXIT_GRACE`] to exit by
/// itself, and stops it if it doesn't, or sooner if a stop signal arrives.
async fn wait_or_stop(
    server: &mut ServerProcess,
    signals: &mut Signals,
) -> Result<ExitStatus, ProxyError> {
    let status = tokio::select! {
        status = timeout(EXIT_GRACE, server.wait()) => match status {
            Ok(status) => status,
            Err(_) => {
                warn!(grace_secs = EXIT_GRACE.as_secs(), "MCP server didn't exit after its input closed; stopping it");
                server.terminate(TERM_GRACE).await
            }
        },
        code = signals.recv() => {
            warn!(code, "received a stop signal; stopping the MCP server");
            server.terminate(TERM_GRACE).await
        }
    }
    .map_err(ProxyError::Wait)?;
    info!(%status, "MCP server exited");
    Ok(status)
}

/// Delivers what the server wrote before it stopped: finishes reading its
/// output (unless that already ended), then lets the client's writer flush
/// everything queued.
async fn deliver_remaining(tasks: &mut Tasks, server_reader_running: bool) {
    if server_reader_running {
        match timeout(DRAIN_GRACE, &mut tasks.server_reader).await {
            Ok(result) => log_reader(Side::Server, result),
            Err(_) => warn!("the server's output was still open at shutdown; abandoning it"),
        }
    }
    // Both readers hold a sender to the client's queue; once they're gone,
    // the queue closes and its writer finishes after the last message.
    tasks.client_reader.abort();
    tasks.server_reader.abort();
    match timeout(DRAIN_GRACE, &mut tasks.client_writer).await {
        Ok(Ok(Ok(written))) => debug!(written, "finished writing to the client"),
        Ok(Ok(Err(error))) => warn!(%error, "couldn't deliver the last messages to the client"),
        Ok(Err(error)) => error!(%error, "the client writer failed"),
        Err(_) => warn!("timed out delivering the last messages to the client"),
    }
}

/// Reads frames from one side, runs each through the gate and queues the
/// gate's actions for the right writer.
async fn read_side<R>(
    mut reader: R,
    side: Side,
    gate: Arc<Mutex<Option<Gate>>>,
    to_server: mpsc::Sender<Outgoing>,
    to_client: mpsc::Sender<Outgoing>,
) -> Result<u64, FrameError>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::new();
    let mut read = 0;
    while read_frame(&mut reader, &mut frame, MAX_MESSAGE_BYTES).await? {
        read += 1;
        let actions = {
            // A poisoned lock means a check panicked: stop rather than
            // carry on with a gate in an unknown state.
            let Ok(mut slot) = gate.lock() else {
                error!(%side, "the gate failed; closing the session");
                return Ok(read);
            };
            // No gate: the session has ended.
            let Some(gate) = slot.as_mut() else {
                return Ok(read);
            };
            match side {
                Side::Client => gate.from_client(&frame),
                Side::Server => gate.from_server(&frame),
            }
        };
        for action in actions {
            let (queue, peer, bytes) = match action {
                Action::ToServer(bytes) => (&to_server, "the MCP server", bytes),
                Action::ToClient(bytes) => (&to_client, "the client", bytes),
            };
            match timeout(SEND_STALL, queue.send(Outgoing::Frame(bytes))).await {
                Ok(Ok(())) => {}
                // That output is gone, so the session is ending.
                Ok(Err(_)) => return Ok(read),
                Err(_) => {
                    return Err(FrameError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "{peer} hasn't read anything for {} seconds",
                            SEND_STALL.as_secs()
                        ),
                    )));
                }
            }
        }
    }
    if let Side::Client = side {
        // The client hung up: close the server's input so it can exit. If
        // the server isn't reading (its queue is full), don't wait for it:
        // it's given a grace period and then stopped.
        let _ = to_server.try_send(Outgoing::Close);
    }
    Ok(read)
}

/// Writes queued frames until the queue closes or a `Close` arrives.
async fn write_frames<W>(mut writer: W, mut queue: mpsc::Receiver<Outgoing>) -> std::io::Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let mut written = 0;
    while let Some(Outgoing::Frame(frame)) = queue.recv().await {
        writer.write_all(&frame).await?;
        if !frame.ends_with(b"\n") {
            writer.write_all(b"\n").await?;
        }
        // Flush every message: the other side is waiting for it.
        writer.flush().await?;
        written += 1;
    }
    Ok(written)
}

fn log_reader(side: Side, result: Result<Result<u64, FrameError>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(read)) => info!(%side, read, "stopped reading: end of stream"),
        Ok(Err(error)) => error!(%side, %error, "stopped reading"),
        Err(error) => error!(%side, %error, "the reader task failed"),
    }
}

/// Starts the server, does the MCP handshake, lists everything it offers
/// (tools, prompts, resources, resource templates and its instructions),
/// then stops it. This is what `mcp-mandate pin` records.
///
/// If `stop` finishes first (a stop signal, with the exit code that reports
/// it), the server and everything it started are stopped, and the result
/// is [`ProxyError::Interrupted`].
pub async fn inventory(
    command: &ServerCommand,
    stop: impl Future<Output = i32>,
) -> Result<Inventory, ProxyError> {
    // The server is being reviewed, so not yet trusted: it doesn't get the
    // Claude API key Scout may be using.
    let (mut server, stdin, stdout) = start_with(command, &["ANTHROPIC_API_KEY"])?;
    info!(server = %command, pid = server.id(), "started MCP server to list what it offers");
    let mut client = InventoryClient {
        writer: stdin,
        reader: BufReader::new(stdout),
        frame: Vec::new(),
        next_id: 0,
    };
    let listed = tokio::select! {
        listed = timeout(INVENTORY_TIMEOUT, inventory::collect(&mut client)) => Ok(listed),
        code = stop => Err(code),
    };
    drop(client); // closes the server's input
    let listed = match listed {
        Ok(listed) => listed,
        Err(code) => {
            warn!(code, "received a stop signal; stopping the MCP server");
            let status = server
                .terminate(TERM_GRACE)
                .await
                .map_err(ProxyError::Wait)?;
            info!(%status, "MCP server exited");
            return Err(ProxyError::Interrupted(code));
        }
    };
    if timeout(EXIT_GRACE, server.wait()).await.is_err() {
        let _ = server.terminate(TERM_GRACE).await;
    }
    listed.map_err(|_| ProxyError::Timeout(INVENTORY_TIMEOUT))?
}

/// A minimal MCP client: just enough to list what a server offers.
struct InventoryClient {
    writer: ChildStdin,
    reader: BufReader<ChildStdout>,
    frame: Vec<u8>,
    next_id: u64,
}

impl Rpc for InventoryClient {
    /// Sends a request and waits for its response, answering any requests
    /// the server makes meanwhile with an error so it isn't left waiting.
    async fn request(&mut self, method: &str, params: Value) -> Result<Value, ProxyError> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await?;
        loop {
            if !read_frame(&mut self.reader, &mut self.frame, MAX_MESSAGE_BYTES).await? {
                return Err(ProxyError::Closed(method.to_owned()));
            }
            let Some(message) = inventory::read_reply(method, &self.frame)? else {
                warn!("ignored a line from the server that isn't JSON");
                continue;
            };
            if message.get("method").is_some() {
                if let Some(request_id) = message.get("id") {
                    let refusal = json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32601, "message": "mcp-mandate pin doesn't answer server requests"}
                    });
                    self.send(&refusal).await?;
                }
                continue;
            }
            if message.get("id") != Some(&json!(id)) {
                continue;
            }
            return result_of(method, message);
        }
    }

    async fn notify(&mut self, method: &str) -> Result<(), ProxyError> {
        self.send(&json!({"jsonrpc": "2.0", "method": method}))
            .await
    }
}

impl InventoryClient {
    async fn send(&mut self, message: &Value) -> Result<(), ProxyError> {
        let mut bytes = serde_json::to_vec(message).expect("JSON values always serialize");
        bytes.push(b'\n');
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

/// Finds the program on PATH. On Windows this also finds `.cmd` and `.bat`
/// launchers such as `npx.cmd`, which the OS won't start by bare name.
fn resolve(program: &OsStr) -> Result<PathBuf, ProxyError> {
    which::which(program).map_err(|source| ProxyError::NotFound {
        program: program.to_string_lossy().into_owned(),
        source,
    })
}

/// The exit code to finish with: the server's own, or 128 + signal number
/// when a signal ended it (the shell convention).
fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mcp_mandate_audit::{AuditError, Event, Recorder};
    use mcp_mandate_policy::Policy;

    use super::*;

    /// An audit log that keeps nothing.
    struct Discard;

    impl Recorder for Discard {
        fn record(&mut self, _: &Event) -> Result<(), AuditError> {
            Ok(())
        }
    }

    /// A gate for a server that was never pinned: protocol plumbing passes,
    /// every tool call is blocked.
    fn unpinned_gate() -> Arc<Mutex<Option<Gate>>> {
        let policy = Policy::parse(
            "mode = \"enforce\"
",
            Path::new("."),
        )
        .unwrap();
        Arc::new(Mutex::new(Some(Gate::new(policy, None, Box::new(Discard)))))
    }

    const PING: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";

    /// Feeds `input` to the client side; returns what was queued for the
    /// server and for the client.
    async fn from_client(input: &[u8]) -> (Vec<Outgoing>, Vec<Outgoing>) {
        let (to_server, mut server_queue) = mpsc::channel(16);
        let (to_client, mut client_queue) = mpsc::channel(16);
        read_side(
            BufReader::new(input),
            Side::Client,
            unpinned_gate(),
            to_server,
            to_client,
        )
        .await
        .unwrap();
        let mut for_server = Vec::new();
        while let Ok(item) = server_queue.try_recv() {
            for_server.push(item);
        }
        let mut for_client = Vec::new();
        while let Ok(item) = client_queue.try_recv() {
            for_client.push(item);
        }
        (for_server, for_client)
    }

    #[tokio::test]
    async fn forwards_protocol_messages_byte_for_byte_and_closes_on_hang_up() {
        let ping = b"{ \"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"ping\" }\r\n";
        let (for_server, for_client) = from_client(ping).await;

        assert_eq!(
            for_server,
            [Outgoing::Frame(ping.to_vec()), Outgoing::Close]
        );
        assert!(for_client.is_empty());
    }

    #[tokio::test]
    async fn drops_lines_that_are_not_json_rpc() {
        let (for_server, _) = from_client(b"debug: starting\n\n").await;
        assert_eq!(for_server, [Outgoing::Close]);
    }

    #[tokio::test]
    async fn answers_a_blocked_call_without_reaching_the_server() {
        let call = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"rm\"}}\n";
        let (for_server, for_client) = from_client(call).await;

        assert_eq!(for_server, [Outgoing::Close]);
        let [Outgoing::Frame(reply)] = for_client.as_slice() else {
            panic!("expected one answer to the client, got {for_client:?}");
        };
        let reply: Value = serde_json::from_slice(reply).unwrap();
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["result"]["isError"], true);
    }

    #[tokio::test]
    async fn writes_each_frame_whole_and_stops_at_close() {
        let (queue, frames) = mpsc::channel(4);
        queue
            .send(Outgoing::Frame(b"{\"a\":1}".to_vec()))
            .await
            .unwrap();
        queue.send(Outgoing::Close).await.unwrap();
        queue
            .send(Outgoing::Frame(b"{\"b\":2}\n".to_vec()))
            .await
            .unwrap();

        let mut output = Vec::new();
        let written = write_frames(&mut output, frames).await.unwrap();

        assert_eq!(written, 1);
        assert_eq!(output, b"{\"a\":1}\n");
    }

    #[tokio::test]
    async fn forwards_nothing_once_the_session_has_ended() {
        let (to_server, mut server_queue) = mpsc::channel(16);
        let (to_client, mut client_queue) = mpsc::channel(16);
        let ended = Arc::new(Mutex::new(None));
        read_side(
            BufReader::new(PING),
            Side::Client,
            ended,
            to_server,
            to_client,
        )
        .await
        .unwrap();
        assert!(server_queue.try_recv().is_err());
        assert!(client_queue.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_on_a_side_that_stopped_reading() {
        // Room for one message, and nobody taking it.
        let (to_server, _server_queue) = mpsc::channel(1);
        let (to_client, _client_queue) = mpsc::channel(1);
        let input = [
            PING,
            b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
        ]
        .concat();
        let reading = read_side(
            BufReader::new(&input[..]),
            Side::Client,
            unpinned_gate(),
            to_server,
            to_client,
        );
        let error = timeout(SEND_STALL * 2, reading)
            .await
            .expect("the reader gave up")
            .unwrap_err();
        assert!(
            matches!(&error, FrameError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut),
            "{error}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hanging_up_does_not_wait_for_a_server_that_stopped_reading() {
        let (to_server, mut server_queue) = mpsc::channel(1);
        let (to_client, _client_queue) = mpsc::channel(1);
        let reading = read_side(
            BufReader::new(PING),
            Side::Client,
            unpinned_gate(),
            to_server,
            to_client,
        );
        let read = timeout(Duration::from_secs(1), reading)
            .await
            .expect("the reader finished")
            .unwrap();
        assert_eq!(read, 1);
        assert_eq!(
            server_queue.try_recv().unwrap(),
            Outgoing::Frame(PING.to_vec())
        );
    }

    /// Whether a process with this id is running (a zombie, exited but not
    /// yet reaped, counts as gone).
    #[cfg(unix)]
    fn alive(pid: &str) -> bool {
        let output = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&output.stdout);
        let state = state.trim();
        !state.is_empty() && !state.starts_with('Z')
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_signal_while_listing_stops_the_server_and_what_it_started() {
        let pid_file =
            std::env::temp_dir().join(format!("mcp-mandate-{}-listing.pid", std::process::id()));
        let _ = std::fs::remove_file(&pid_file);
        // The server starts a helper, then never answers.
        let command = ServerCommand {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                format!("sleep 300 & echo $! > '{}'; sleep 300", pid_file.display()).into(),
            ],
        };
        let helper = || {
            std::fs::read_to_string(&pid_file)
                .ok()
                .map(|pid| pid.trim().to_owned())
                .filter(|pid| !pid.is_empty())
        };
        // The signal arrives once the helper runs.
        let stop = async {
            while helper().is_none() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            130
        };

        let listed = timeout(Duration::from_secs(30), inventory(&command, stop))
            .await
            .expect("listing stopped");
        assert!(
            matches!(listed, Err(ProxyError::Interrupted(130))),
            "{listed:?}"
        );
        let helper = helper().unwrap();
        let _ = std::fs::remove_file(&pid_file);
        for _ in 0..50 {
            if !alive(&helper) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("process {helper} outlived the server it was started by");
    }

    /// How a command shows in logs, pins files and Scout's draft.
    fn shown(program: &str, args: &[&str]) -> String {
        ServerCommand {
            program: program.into(),
            args: args.iter().map(OsString::from).collect(),
        }
        .to_string()
    }

    #[test]
    fn displays_the_server_command() {
        assert_eq!(shown("npx", &["-y", "server"]), "npx -y server");
        assert_eq!(
            shown(
                "uvx",
                &["mcp-server-git==0.6.2", "--repository", "/home/me/repo"]
            ),
            "uvx mcp-server-git==0.6.2 --repository /home/me/repo"
        );
        assert_eq!(
            shown("node", &["C:\\servers\\index.js", "localhost:8080"]),
            "node C:\\servers\\index.js localhost:8080"
        );
    }

    #[test]
    fn masks_what_looks_like_a_secret_in_the_server_command() {
        assert_eq!(
            shown(
                "npx",
                &[
                    "-y",
                    "@modelcontextprotocol/server-postgres",
                    "postgresql://app:S3cret@db/prod?sslmode=require"
                ]
            ),
            "npx -y @modelcontextprotocol/server-postgres postgresql://***@db/prod"
        );
        assert_eq!(
            shown(
                "server",
                &["--api-key", "abc123", "--port", "8080", "--token=abc123"]
            ),
            "server --api-key *** --port 8080 --token=***"
        );
        assert_eq!(
            shown(
                "npx",
                &[
                    "mcp-remote",
                    "https://example.com/sse?key=abc123#frag",
                    "--header",
                    "Authorization: Bearer abc123",
                    "--url=https://user:pw@example.com/"
                ]
            ),
            "npx mcp-remote https://example.com/sse --header Authorization: *** *** --url=https://***@example.com/"
        );
        assert_eq!(
            shown(
                "docker",
                &[
                    "run",
                    "-i",
                    "-e",
                    "GITHUB_TOKEN",
                    "-e",
                    "TEAM=T123",
                    "image"
                ]
            ),
            "docker run -i -e GITHUB_TOKEN -e TEAM=*** image"
        );
        let token = format!("ghp_{}", "a1".repeat(18));
        assert_eq!(
            shown("server", &[&token]),
            "server [REDACTED: github-token]"
        );
        // A value can have spaces: it's masked up to the next option.
        assert_eq!(
            shown(
                "sh",
                &["-c", "API_KEY=abc123 node server.js --token 'abc 123'"]
            ),
            "sh -c API_KEY=*** *** *** --token '*** ***'"
        );
        assert_eq!(
            shown(
                "server",
                &["--db-password=correct horse battery staple", "--port", "1"]
            ),
            "server --db-password=*** *** *** *** --port 1"
        );
        assert_eq!(
            shown("docker", &["run", "-e", "TEAM=a b c", "image"]),
            "docker run -e TEAM=*** *** *** image"
        );
        // Or up to its closing quote.
        assert_eq!(
            shown(
                "sh",
                &["-c", "PGPASSWORD='correct horse battery' psql -h db"]
            ),
            "sh -c PGPASSWORD=*** *** ***' psql -h db"
        );
        assert_eq!(
            shown(
                "sh",
                &[
                    "-c",
                    "node server.js --url=\"https://user:pw@example.com/\""
                ]
            ),
            "sh -c node server.js --url=\"https://***@example.com/\""
        );
    }

    #[test]
    fn masks_a_header_value_however_it_is_split() {
        let masked = "npx mcp-remote https://example.com/sse --header Authorization:*** ***";
        assert_eq!(
            shown(
                "npx",
                &[
                    "mcp-remote",
                    "https://example.com/sse",
                    "--header",
                    "Authorization:Bearer abcd1234efgh5678"
                ]
            ),
            masked
        );
        // As a client on Windows may pass it.
        assert_eq!(
            shown(
                "npx",
                &[
                    "mcp-remote",
                    "https://example.com/sse",
                    "--header",
                    "Authorization:Bearer",
                    "abcd1234efgh5678"
                ]
            ),
            masked
        );
        // As a client that doesn't quote spaces passes
        // `Authorization: Bearer <token>`: each word its own argument.
        let masked = "npx mcp-remote https://example.com/sse --header Authorization: *** ***";
        assert_eq!(
            shown(
                "npx",
                &[
                    "mcp-remote",
                    "https://example.com/sse",
                    "--header",
                    "Authorization:",
                    "Bearer",
                    "abcd1234efgh5678"
                ]
            ),
            masked
        );
        assert_eq!(
            shown(
                "npx",
                &[
                    "mcp-remote",
                    "https://example.com/sse",
                    "--header",
                    "Authorization: Bearer",
                    "abcd1234efgh5678"
                ]
            ),
            masked
        );
        assert_eq!(
            shown(
                "npx",
                &[
                    "mcp-remote",
                    "--header=Authorization: Bearer abcd1234efgh5678",
                    "https://example.com/sse"
                ]
            ),
            "npx mcp-remote --header=Authorization: *** *** https://example.com/sse"
        );
        // The value ends once it has a scheme and a token, or at an option.
        assert_eq!(
            shown(
                "npx",
                &[
                    "mcp-remote",
                    "--header=Authorization:",
                    "Bearer",
                    "abcd1234efgh5678",
                    "https://example.com/sse"
                ]
            ),
            "npx mcp-remote --header=Authorization: *** *** https://example.com/sse"
        );
        assert_eq!(
            shown("server", &["--header", "Authorization:", "--port", "1"]),
            "server --header Authorization: --port 1"
        );
        // An option's value is one argument.
        assert_eq!(
            shown("server", &["--api-key", "abc123", "/srv"]),
            "server --api-key *** /srv"
        );
        assert_eq!(
            shown("server", &["--header", "X-Api-Key:abcd1234efgh5678"]),
            "server --header X-Api-Key:***"
        );
        // Other headers are shown.
        assert_eq!(
            shown("server", &["--header", "Accept:text/plain", "/srv"]),
            "server --header Accept:text/plain /srv"
        );
    }

    #[test]
    fn masks_one_argument_on_its_own() {
        assert_eq!(
            masked("git+https://oauth2:glpat-abcd1234@gitlab.com/org/server.git"),
            "git+https://***@gitlab.com/org/server.git"
        );
        assert_eq!(masked("some-server@latest"), "some-server@latest");
        // A URL after a package's name: npm's `name@url`, PEP 508 without
        // spaces.
        assert_eq!(
            masked("srv@git+https://user:tok@host/r.git"),
            "srv@git+https://***@host/r.git"
        );
        assert_eq!(
            masked("@scope/pkg@https://u:p@host/p.tgz?sig=abc123"),
            "@scope/pkg@https://***@host/p.tgz"
        );
        assert_eq!(
            shown(
                "uvx",
                &["--from", "srv@git+https://u:Tok3n@github.com/o/r", "srv"]
            ),
            "uvx --from srv@git+https://***@github.com/o/r srv"
        );
        // Every URL in a word.
        assert_eq!(
            masked("kafka://a:S3cret@h1,kafka://b:S3cret@h2/topic"),
            "kafka://***@h1,kafka://***@h2/topic"
        );
        assert_eq!(
            masked("https://host/go/https://u:S3cret@h2/x"),
            "https://host/go/https://***@h2/x"
        );
        // One in a query is part of the query.
        assert_eq!(
            masked("https://host/login?next=https://u:S3cret@h2/"),
            "https://host/login"
        );
        // A variable's value is masked whole, URL or not.
        assert_eq!(
            masked("DATABASE_URL=postgres://u:S3cret@db/prod"),
            "DATABASE_URL=***"
        );
        // Not a URL: `://` with no scheme before it.
        assert_eq!(masked("a@://b"), "a@://b");
    }
}
