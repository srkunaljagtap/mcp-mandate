//! Runs an MCP server as a child process and relays its stdio transport.
//!
//! ```text
//! agent ──stdin──▶ relay ──▶ server stdin       (client to server)
//! agent ◀─stdout── relay ◀── server stdout      (server to client)
//!                  server stderr ──▶ agent's stderr, untouched
//! ```
//!
//! stdout carries the protocol, so this module never prints to it except to
//! forward messages. Logs go to stderr through `tracing`.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::jsonrpc::{self, FrameError, MAX_MESSAGE_BYTES};
use crate::process::{ServerProcess, Signals, TERM_GRACE};

/// How long a server gets to exit on its own after its input closes.
const EXIT_GRACE: Duration = Duration::from_secs(5);
/// How long to keep delivering a server's last output after it exits.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

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
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ClientToServer => "client→server",
            Self::ServerToClient => "server→client",
        })
    }
}

/// Counts from one direction of the relay.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RelayStats {
    pub forwarded: u64,
    pub dropped: u64,
}

/// Starts `command`, relays the agent's stdin/stdout to it until either side
/// ends, and returns the exit code to finish with (the server's own, where
/// it has one).
pub async fn run(command: &ServerCommand) -> Result<i32, ProxyError> {
    let program = resolve(&command.program)?;
    // Register before starting the server so no signal is missed.
    let mut signals = Signals::new();
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
    info!(server = %command, pid = server.id(), "started MCP server");

    let child = server.child_mut();
    let (Some(server_in), Some(server_out)) = (child.stdin.take(), child.stdout.take()) else {
        unreachable!("stdin and stdout were set to piped");
    };
    let to_server = tokio::spawn(relay(
        BufReader::new(tokio::io::stdin()),
        server_in,
        Direction::ClientToServer,
    ));
    let to_client = tokio::spawn(relay(
        BufReader::new(server_out),
        tokio::io::stdout(),
        Direction::ServerToClient,
    ));

    supervise(&mut server, &mut signals, to_server, to_client).await
}

type Relay = JoinHandle<Result<RelayStats, FrameError>>;

/// Waits for the first side to finish (or a stop signal), then shuts the
/// rest down in order. Returns the exit code to finish with.
async fn supervise(
    server: &mut ServerProcess,
    signals: &mut Signals,
    mut to_server: Relay,
    mut to_client: Relay,
) -> Result<i32, ProxyError> {
    let code = tokio::select! {
        status = server.wait() => {
            let status = status.map_err(ProxyError::Wait)?;
            info!(%status, "MCP server exited");
            drain(&mut to_client).await;
            exit_code(status)
        }
        result = &mut to_server => {
            log_relay(Direction::ClientToServer, Some(result));
            // The client closed its side, so the server's stdin is closed
            // too; well-behaved servers exit now.
            let status = wait_or_stop(server, signals).await?;
            drain(&mut to_client).await;
            exit_code(status)
        }
        result = &mut to_client => {
            log_relay(Direction::ServerToClient, Some(result));
            exit_code(wait_or_stop(server, signals).await?)
        }
        code = signals.recv() => {
            warn!(code, "received a stop signal; stopping the MCP server");
            let status = server.terminate(TERM_GRACE).await.map_err(ProxyError::Wait)?;
            info!(%status, "MCP server exited");
            code
        }
    };
    to_server.abort();
    to_client.abort();
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

/// Delivers whatever the server wrote just before it exited.
async fn drain(to_client: &mut Relay) {
    log_relay(
        Direction::ServerToClient,
        timeout(DRAIN_GRACE, to_client).await.ok(),
    );
}

/// Copies frames from `reader` to `writer` until end of stream, dropping any
/// frame that isn't JSON-RPC.
async fn relay<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
) -> Result<RelayStats, FrameError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut stats = RelayStats::default();
    let mut frame = Vec::new();
    while jsonrpc::read_frame(&mut reader, &mut frame, MAX_MESSAGE_BYTES).await? {
        match jsonrpc::classify(&frame) {
            Ok(message) => {
                debug!(%direction, %message, bytes = frame.len(), "forwarded");
                writer.write_all(&frame).await?;
                if !frame.ends_with(b"\n") {
                    writer.write_all(b"\n").await?;
                }
                // Flush every message: the other side is waiting for it.
                writer.flush().await?;
                stats.forwarded += 1;
            }
            Err(jsonrpc::ParseError::Empty) => {}
            Err(reason) => {
                warn!(%direction, %reason, bytes = frame.len(), "dropped a line that isn't JSON-RPC");
                stats.dropped += 1;
            }
        }
    }
    Ok(stats)
}

fn log_relay(
    direction: Direction,
    result: Option<Result<Result<RelayStats, FrameError>, tokio::task::JoinError>>,
) {
    match result {
        Some(Ok(Ok(stats))) => info!(
            %direction,
            forwarded = stats.forwarded,
            dropped = stats.dropped,
            "relay finished"
        ),
        Some(Ok(Err(error))) => error!(%direction, %error, "relay stopped"),
        Some(Err(error)) => error!(%direction, %error, "relay task failed"),
        None => warn!(%direction, "relay still busy at shutdown; abandoning it"),
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
    use super::*;

    async fn relay_bytes(input: &[u8]) -> (Vec<u8>, RelayStats) {
        let mut output = Vec::new();
        let stats = relay(
            BufReader::new(input),
            &mut output,
            Direction::ClientToServer,
        )
        .await
        .unwrap();
        (output, stats)
    }

    #[tokio::test]
    async fn forwards_messages_byte_for_byte() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{ \"jsonrpc\": \"2.0\", \"id\": 1, \"result\": {} }\r\n";
        let (output, stats) = relay_bytes(input).await;
        assert_eq!(output, input);
        assert_eq!(
            stats,
            RelayStats {
                forwarded: 2,
                dropped: 0
            }
        );
    }

    #[tokio::test]
    async fn drops_lines_that_are_not_json_rpc_and_skips_blank_ones() {
        let valid = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
        let input = [&b"debug: server starting\n"[..], b"\n", valid].concat();
        let (output, stats) = relay_bytes(&input).await;
        assert_eq!(output, valid);
        assert_eq!(
            stats,
            RelayStats {
                forwarded: 1,
                dropped: 1
            }
        );
    }

    #[tokio::test]
    async fn terminates_a_last_message_that_has_no_newline() {
        let (output, _) = relay_bytes(b"{\"jsonrpc\":\"2.0\",\"method\":\"x\"}").await;
        assert_eq!(output, b"{\"jsonrpc\":\"2.0\",\"method\":\"x\"}\n");
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
