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
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::framing::{FrameError, MAX_MESSAGE_BYTES, read_frame};
use crate::process::{ServerProcess, Signals, TERM_GRACE};

/// How long a server gets to exit on its own after its input closes.
const EXIT_GRACE: Duration = Duration::from_secs(5);
/// How long to keep delivering a server's last output after it stops.
const DRAIN_GRACE: Duration = Duration::from_secs(5);
/// Messages queued per output before a reader waits for its writer.
const QUEUE: usize = 256;
/// How long `inventory` waits for a server to answer everything it's asked.
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(60);
/// Most pages of one list `inventory` follows.
const MAX_PAGES: usize = 100;
/// The MCP protocol version `inventory` asks for.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// The MCP server to run: a program and its arguments.
#[derive(Debug, Clone)]
pub struct ServerCommand {
    pub program: OsString,
    pub args: Vec<OsString>,
}

impl fmt::Display for ServerCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program.to_string_lossy())?;
        for arg in &self.args {
            write!(f, " {}", arg.to_string_lossy())?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("couldn't find `{program}` (is it installed and on PATH?)")]
    NotFound {
        program: String,
        #[source]
        source: which::Error,
    },
    #[error("couldn't start `{program}`")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("lost track of the MCP server process")]
    Wait(#[source] std::io::Error),
    #[error("the MCP server didn't answer within {} seconds", .0.as_secs())]
    Timeout(Duration),
    #[error("the MCP server closed its output before answering `{0}`")]
    Closed(String),
    #[error("the MCP server answered `{method}` with an error: {message}")]
    Server { method: String, message: String },
    #[error("couldn't read from the MCP server")]
    Frame(#[from] FrameError),
    #[error("couldn't write to the MCP server")]
    Io(#[from] std::io::Error),
}

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

    let gate = Arc::new(Mutex::new(gate));
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
            gate,
            to_server,
            to_client,
        )),
    };
    supervise(&mut server, &mut signals, tasks).await
}

/// Starts the server with piped stdin and stdout.
fn start(command: &ServerCommand) -> Result<(ServerProcess, ChildStdin, ChildStdout), ProxyError> {
    let program = resolve(&command.program)?;
    let mut server = ServerProcess::spawn(
        Command::new(&program)
            .args(&command.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    )
    .map_err(|source| ProxyError::Spawn {
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
    gate: Arc<Mutex<Gate>>,
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
            let Ok(mut gate) = gate.lock() else {
                error!(%side, "the gate failed; closing the session");
                return Ok(read);
            };
            match side {
                Side::Client => gate.from_client(&frame),
                Side::Server => gate.from_server(&frame),
            }
        };
        for action in actions {
            let (queue, bytes) = match action {
                Action::ToServer(bytes) => (&to_server, bytes),
                Action::ToClient(bytes) => (&to_client, bytes),
            };
            if queue.send(Outgoing::Frame(bytes)).await.is_err() {
                // That output is gone, so the session is ending.
                return Ok(read);
            }
        }
    }
    if let Side::Client = side {
        // The client hung up: close the server's input so it can exit.
        let _ = to_server.send(Outgoing::Close).await;
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
pub async fn inventory(command: &ServerCommand) -> Result<Inventory, ProxyError> {
    let (mut server, stdin, stdout) = start(command)?;
    info!(server = %command, pid = server.id(), "started MCP server to list what it offers");
    let mut client = InventoryClient {
        writer: stdin,
        reader: BufReader::new(stdout),
        frame: Vec::new(),
        next_id: 0,
    };
    let listed = timeout(INVENTORY_TIMEOUT, client.inventory()).await;
    drop(client); // closes the server's input
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

impl InventoryClient {
    async fn inventory(&mut self) -> Result<Inventory, ProxyError> {
        let init = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-mandate", "version": env!("CARGO_PKG_VERSION")}
                }),
            )
            .await?;
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await?;

        let offers = |capability: &str| {
            init.get("capabilities")
                .and_then(|caps| caps.get(capability))
                .is_some()
        };
        let mut inventory = Inventory {
            instructions: init
                .get("instructions")
                .and_then(Value::as_str)
                .map(str::to_owned),
            ..Inventory::default()
        };
        if offers("tools") {
            inventory.tools = self.list_all("tools/list", "tools").await?;
        }
        if offers("prompts") {
            inventory.prompts = self.list_all("prompts/list", "prompts").await?;
        }
        if offers("resources") {
            inventory.resources = self.list_all("resources/list", "resources").await?;
            // Templates are optional even for servers with resources.
            inventory.resource_templates = self
                .list_all("resources/templates/list", "resourceTemplates")
                .await
                .unwrap_or_default();
        }
        Ok(inventory)
    }

    /// Calls a list method, following `nextCursor` across pages.
    async fn list_all(&mut self, method: &str, field: &str) -> Result<Vec<Value>, ProxyError> {
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(cursor) => json!({"cursor": cursor}),
                None => json!({}),
            };
            let result = self.request(method, params).await?;
            if let Some(page) = result.get(field).and_then(Value::as_array) {
                items.extend(page.iter().cloned());
            }
            match result.get("nextCursor").and_then(Value::as_str) {
                Some(next) => cursor = Some(next.to_owned()),
                None => return Ok(items),
            }
        }
        warn!(
            method,
            pages = MAX_PAGES,
            "stopped listing after too many pages"
        );
        Ok(items)
    }

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
            let Ok(message) = serde_json::from_slice::<Value>(&self.frame) else {
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
            if let Some(error) = message.get("error") {
                return Err(ProxyError::Server {
                    method: method.to_owned(),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("no message")
                        .to_owned(),
                });
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
    }

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

    use mcp_mandate_policy::Policy;

    use super::*;

    /// A gate for a server that was never pinned: protocol plumbing passes,
    /// every tool call is blocked.
    fn unpinned_gate() -> Arc<Mutex<Gate>> {
        let policy = Policy::parse("", Path::new(".")).unwrap();
        Arc::new(Mutex::new(Gate::new(policy, None)))
    }

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

    #[test]
    fn displays_the_server_command() {
        let command = ServerCommand {
            program: "npx".into(),
            args: vec!["-y".into(), "server".into()],
        };
        assert_eq!(command.to_string(), "npx -y server");
    }
}
