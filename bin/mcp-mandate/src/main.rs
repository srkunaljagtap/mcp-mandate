//! The `mcp-mandate` command: one binary for the gate, Scout and the audit log.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mcp_mandate_proxy::stdio::{self, ServerCommand};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "mcp-mandate",
    version,
    about = "A security gate between AI agents and their MCP tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a local (stdio) MCP server behind the gate.
    Run {
        /// Policy file (TOML) with allow, deny and hold rules.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// The server command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        server: Vec<OsString>,
    },
    /// Serve the gate over Streamable HTTP for remote MCP servers.
    Gate {
        /// Gateway configuration file (TOML).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Review an MCP server's tools and draft a policy for it.
    Scout {
        /// The server command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        server: Vec<OsString>,
    },
    /// Work with the audit log.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Check that no entry in the audit log was changed or removed.
    Verify {
        /// Audit log file (JSONL).
        #[arg(long)]
        log: Option<PathBuf>,
    },
}

impl Command {
    /// What the command will do once implemented.
    fn describe(&self) -> String {
        match self {
            Self::Run { policy, server } => {
                format!("run `{}` behind the gate{}", join(server), with(policy))
            }
            Self::Gate { config } => format!("serve the HTTP gateway{}", with(config)),
            Self::Scout { server } => format!("review `{}`", join(server)),
            Self::Audit {
                command: AuditCommand::Verify { log },
            } => format!("verify the audit log{}", with(log)),
        }
    }
}

fn join(args: &[OsString]) -> String {
    args.iter()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

fn with(path: &Option<PathBuf>) -> String {
    path.as_deref()
        .map(Path::display)
        .map(|path| format!(" using {path}"))
        .unwrap_or_default()
}

// stdout is reserved for protocol traffic (stdio MCP), so every message the
// program prints goes to stderr.
fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        // Running without enforcing a policy the user asked for would look
        // protected while not being so; refuse instead.
        Command::Run {
            policy: Some(_), ..
        } => {
            eprintln!(
                "mcp-mandate: --policy isn't enforced yet, so mcp-mandate won't run as if it were"
            );
            ExitCode::from(2)
        }
        Command::Run {
            policy: None,
            server,
        } => run(server),
        other => {
            eprintln!("mcp-mandate: not implemented yet: {}", other.describe());
            ExitCode::from(2)
        }
    }
}

/// `mcp-mandate run`: relays a stdio MCP server until either side ends.
fn run(server: Vec<OsString>) -> ExitCode {
    init_logging();
    let mut parts = server.into_iter();
    let Some(program) = parts.next() else {
        unreachable!("clap requires a server command");
    };
    let command = ServerCommand {
        program,
        args: parts.collect(),
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "couldn't start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    let code = match runtime.block_on(stdio::run(&command)) {
        Ok(code) => code,
        Err(error) => {
            tracing::error!(error = %report(&error), "mcp-mandate run failed");
            1
        }
    };
    // Exit now rather than dropping the runtime: a read of our own stdin may
    // still be blocked inside it, and the client may never close stdin.
    std::process::exit(code)
}

/// Logs go to stderr. `MCP_MANDATE_LOG` sets the level (`debug` shows every
/// message); the default `info` logs only start, stop and dropped lines.
fn init_logging() {
    let filter =
        EnvFilter::try_from_env("MCP_MANDATE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .init();
}

/// An error and its causes on one line: "couldn't start `x`: permission denied".
fn report(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_takes_the_server_command_after_double_dash() {
        let cli = Cli::try_parse_from([
            "mcp-mandate",
            "run",
            "--policy",
            "p.toml",
            "--",
            "npx",
            "-y",
            "server",
        ])
        .unwrap();

        let Command::Run { policy, server } = cli.command else {
            panic!("expected the run command");
        };
        assert_eq!(policy, Some(PathBuf::from("p.toml")));
        assert_eq!(server, ["npx", "-y", "server"].map(OsString::from));
    }

    #[test]
    fn run_requires_a_server_command() {
        assert!(Cli::try_parse_from(["mcp-mandate", "run"]).is_err());
    }

    #[test]
    fn audit_verify_parses() {
        let cli =
            Cli::try_parse_from(["mcp-mandate", "audit", "verify", "--log", "a.jsonl"]).unwrap();
        assert_eq!(cli.command.describe(), "verify the audit log using a.jsonl");
    }
}
