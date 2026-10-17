//! The `mcp-mandate` command: one binary for the gate, Scout and the audit log.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

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

fn main() -> ExitCode {
    let cli = Cli::parse();
    // stdout is reserved for protocol traffic (stdio MCP), so messages go to
    // stderr.
    eprintln!(
        "mcp-mandate: not implemented yet: {}",
        cli.command.describe()
    );
    ExitCode::from(2)
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
