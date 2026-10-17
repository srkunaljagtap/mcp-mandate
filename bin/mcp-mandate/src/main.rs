//! The `mcp-mandate` command: one binary for the gate, Scout and the audit log.

use std::error::Error;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mcp_mandate_audit::{self as audit, Log, Recorder, VerifyError};
use mcp_mandate_gate::Gate;
use mcp_mandate_pin::{Kind, Pins, unpinned_package};
use mcp_mandate_policy::{Mode, Policy};
use mcp_mandate_proxy::stdio::{self, ServerCommand};
use tracing::{error, info, warn};
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
        /// Policy file (TOML): mode, pins file, and allow, deny and hold rules.
        #[arg(long)]
        policy: PathBuf,
        /// The server command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        server: Vec<OsString>,
    },
    /// Record what an MCP server offers, so you can review and approve it.
    Pin {
        /// Where to write the pins file.
        #[arg(long, default_value = "mcp-mandate.pins.toml")]
        out: PathBuf,
        /// Replace an existing pins file (this re-trusts whatever the server
        /// shows now).
        #[arg(long)]
        force: bool,
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
    /// Check that no entry in the audit log was edited, removed, added or
    /// reordered.
    Verify {
        /// The audit log (JSONL).
        #[arg(required_unless_present = "policy")]
        log: Option<PathBuf>,
        /// Check the audit log this policy writes, instead of naming it.
        #[arg(long, conflicts_with = "log")]
        policy: Option<PathBuf>,
        /// A head hash saved from an earlier check. Also fails unless the
        /// log still contains it, which catches entries cut off the end and
        /// rewritten logs.
        #[arg(long)]
        anchor: Option<String>,
    },
}

// While `run` relays a server, stdout carries the protocol traffic, so every
// message the program prints goes to stderr. Only `audit verify`, which
// relays nothing, prints its report to stdout.
fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { policy, server } => run(&policy, server_command(server)),
        Command::Pin { out, force, server } => pin(&out, force, &server_command(server)),
        Command::Gate { config } => not_yet(&format!("serve the HTTP gateway{}", with(&config))),
        Command::Scout { server } => not_yet(&format!("review `{}`", join(&server))),
        Command::Audit {
            command:
                AuditCommand::Verify {
                    log,
                    policy,
                    anchor,
                },
        } => verify(log, policy, anchor.as_deref()),
    }
}

fn not_yet(what: &str) -> ExitCode {
    eprintln!("mcp-mandate: not implemented yet: {what}");
    ExitCode::from(2)
}

/// `mcp-mandate run`: relays a stdio MCP server through the gate until
/// either side ends.
fn run(policy: &Path, command: ServerCommand) -> ExitCode {
    init_logging();
    let gate = match load_gate(policy, &command) {
        Ok(gate) => gate,
        Err(error) => {
            error!(error = %report(error.as_ref()), "couldn't start the gate");
            return ExitCode::from(2);
        }
    };
    warn_if_unpinned(&command);
    let Some(runtime) = runtime() else {
        return ExitCode::FAILURE;
    };
    let code = match runtime.block_on(stdio::run(&command, gate)) {
        Ok(code) => code,
        Err(error) => {
            error!(error = %report(&error), "mcp-mandate run failed");
            1
        }
    };
    // Exit now rather than dropping the runtime: a read of our own stdin may
    // still be blocked inside it, and the client may never close stdin.
    std::process::exit(code)
}

/// Loads the policy and pins, and opens the audit log with this session's
/// start recorded.
fn load_gate(path: &Path, command: &ServerCommand) -> Result<Gate, Box<dyn Error>> {
    let policy = Policy::load(path)?;
    let pins = match &policy.pins {
        Some(pins_path) => {
            let pins = Pins::load(pins_path)?;
            info!(
                pins = %pins_path.display(),
                tools = pins.count(Kind::Tool),
                prompts = pins.count(Kind::Prompt),
                resources = pins.count(Kind::Resource),
                resource_templates = pins.count(Kind::ResourceTemplate),
                "loaded pins"
            );
            Some(pins)
        }
        None => {
            warn!(
                "the policy names no pins file, so nothing the server offers is approved (see `mcp-mandate pin`)"
            );
            None
        }
    };
    info!(policy = %path.display(), mode = mode_name(policy.mode), "loaded policy");
    if policy.mode == Mode::Observe {
        warn!("observe mode: decisions are logged, but nothing is blocked or hidden");
    }
    let mut log = Log::open(&policy.audit_log)?;
    log.record(&session_start(path, &policy, command)?)?;
    info!(
        audit_log = %log.path().display(),
        session = log.session(),
        "recording every decision to the audit log"
    );
    Ok(Gate::new(policy, pins, Box::new(log)))
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Enforce => "enforce",
        Mode::Observe => "observe",
    }
}

/// The audit entry that opens a session: what ran, under which policy.
fn session_start(
    path: &Path,
    policy: &Policy,
    command: &ServerCommand,
) -> Result<audit::Event, Box<dyn Error>> {
    let hash_file = |file: &Path| std::fs::read(file).map(|bytes| audit::sha256_hex(&bytes));
    // The server's arguments can carry tokens, so the command is recorded
    // only as a hash: each part's bytes, each followed by a NUL.
    let mut argv = Vec::new();
    for part in std::iter::once(&command.program).chain(&command.args) {
        argv.extend_from_slice(part.as_encoded_bytes());
        argv.push(0);
    }
    let program = Path::new(&command.program)
        .file_name()
        .unwrap_or(command.program.as_os_str());
    Ok(audit::Event {
        event: audit::EventKind::SessionStart,
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        mode: Some(mode_name(policy.mode).to_owned()),
        policy: Some(path.display().to_string()),
        policy_sha256: Some(hash_file(path)?),
        pins_sha256: policy.pins.as_deref().map(hash_file).transpose()?,
        server: Some(program.to_string_lossy().into_owned()),
        command_sha256: Some(audit::sha256_hex(&argv)),
        pid: Some(std::process::id()),
        ..audit::Event::default()
    })
}

/// `mcp-mandate audit verify`: checks the log's hash chain and prints what
/// it holds.
fn verify(log: Option<PathBuf>, policy: Option<PathBuf>, anchor: Option<&str>) -> ExitCode {
    let path = match (log, policy) {
        (Some(log), _) => log,
        (None, Some(policy)) => match Policy::load(&policy) {
            Ok(policy) => policy.audit_log,
            Err(error) => {
                eprintln!("mcp-mandate: {}", report(&error));
                return ExitCode::from(2);
            }
        },
        (None, None) => unreachable!("clap requires a log or a policy"),
    };
    let (text, code) = match audit::verify(&path, anchor) {
        Ok(found) => (intact(&path, &found), ExitCode::SUCCESS),
        Err(error @ VerifyError::Read { .. }) => {
            eprintln!("mcp-mandate: {}", report(&error));
            return ExitCode::from(2);
        }
        Err(error) => (
            format!("{}: NOT INTACT: {error}\n", path.display()),
            ExitCode::FAILURE,
        ),
    };
    // A reader that stops early (`| head`) closes the pipe; the exit code
    // still tells the result, so a failed write isn't an error.
    let _ = std::io::stdout().write_all(text.as_bytes());
    code
}

/// The report on a log that verified.
fn intact(path: &Path, found: &audit::Report) -> String {
    let mut text = format!("{}: intact\n", path.display());
    let entries = count(found.entries, "entry", "entries");
    let sessions = count(found.sessions as u64, "session", "sessions");
    match (&found.first, &found.last) {
        (Some(first), Some(last)) => {
            text += &format!("  {entries} in {sessions}, {first} to {last}\n");
        }
        _ => text += &format!("  {entries}\n"),
    }
    if found.unfinished > 0 {
        text += &format!(
            "  {} without an end entry (still running, stopped abruptly, or cut off with the end of the log)\n",
            count(found.unfinished as u64, "session", "sessions")
        );
    }
    if let Some(at) = found.anchor_at {
        text += &format!("  The anchor is entry {at} of {}.\n", found.entries);
    }
    text += &format!("  Head: {}\n", found.head);
    text += "  Save the head somewhere else and check it later with --anchor: that also catches entries cut off the end, or a rewritten log.\n";
    text
}

/// "1 entry", "3 entries".
fn count(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `mcp-mandate pin`: records what the server offers into a pins file.
fn pin(out: &Path, force: bool, command: &ServerCommand) -> ExitCode {
    init_logging();
    if out.exists() && !force {
        error!(
            out = %out.display(),
            "the pins file already exists; pass --force to replace it (re-pinning trusts whatever the server shows now)"
        );
        return ExitCode::from(2);
    }
    warn_if_unpinned(command);
    let Some(runtime) = runtime() else {
        return ExitCode::FAILURE;
    };
    let inventory = match runtime.block_on(stdio::inventory(command)) {
        Ok(inventory) => inventory,
        Err(error) => {
            error!(error = %report(&error), "couldn't list what the server offers");
            return ExitCode::FAILURE;
        }
    };
    let pins = Pins::from_inventory(command.to_string(), &inventory);
    if let Err(error) = pins.save(out) {
        error!(error = %report(&error), "couldn't write the pins file");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "Pinned {} to {}.\nReview it before use: everything in it will be trusted.",
        summary(&pins),
        out.display()
    );
    ExitCode::SUCCESS
}

/// "15 tools, 3 prompts and the server's instructions".
fn summary(pins: &Pins) -> String {
    let mut parts: Vec<String> = [
        (Kind::Tool, "tool"),
        (Kind::Prompt, "prompt"),
        (Kind::Resource, "resource"),
        (Kind::ResourceTemplate, "resource template"),
    ]
    .into_iter()
    .filter(|(kind, _)| pins.count(*kind) > 0)
    .map(|(kind, noun)| {
        let count = pins.count(kind);
        format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
    })
    .collect();
    if pins.instructions.is_some() {
        parts.push("the server's instructions".to_owned());
    }
    match parts.len() {
        0 => "nothing (the server offers no tools, prompts or resources)".to_owned(),
        1 => parts.remove(0),
        _ => {
            let last = parts.pop().unwrap_or_default();
            format!("{} and {last}", parts.join(", "))
        }
    }
}

fn warn_if_unpinned(command: &ServerCommand) {
    let program = command.program.to_string_lossy();
    let args: Vec<String> = command
        .args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if let Some(package) = unpinned_package(&program, &args) {
        warn!(
            %package,
            "the server's package has no pinned version: its launcher fetches the newest release on every run, so its code can change while its tool descriptions don't. Pin a version, e.g. `{package}@1.2.3`"
        );
    }
}

fn server_command(server: Vec<OsString>) -> ServerCommand {
    let mut parts = server.into_iter();
    let Some(program) = parts.next() else {
        unreachable!("clap requires a server command");
    };
    ServerCommand {
        program,
        args: parts.collect(),
    }
}

fn runtime() -> Option<tokio::runtime::Runtime> {
    match tokio::runtime::Runtime::new() {
        Ok(runtime) => Some(runtime),
        Err(error) => {
            error!(%error, "couldn't start the async runtime");
            None
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

/// Logs go to stderr. `MCP_MANDATE_LOG` sets the level (`debug` shows every
/// decision); the default `info` logs start, stop, and what was hidden or
/// blocked.
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
fn report(error: &dyn Error) -> String {
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
    use mcp_mandate_pin::Inventory;
    use serde_json::json;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_takes_a_policy_and_the_server_command_after_double_dash() {
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
        assert_eq!(policy, PathBuf::from("p.toml"));
        assert_eq!(server, ["npx", "-y", "server"].map(OsString::from));
    }

    #[test]
    fn run_requires_a_policy_and_a_server_command() {
        assert!(Cli::try_parse_from(["mcp-mandate", "run", "--", "cat"]).is_err());
        assert!(Cli::try_parse_from(["mcp-mandate", "run", "--policy", "p.toml"]).is_err());
    }

    #[test]
    fn audit_verify_takes_a_log_or_a_policy_but_not_both() {
        let parse = |args: &[&str]| {
            Cli::try_parse_from(["mcp-mandate", "audit", "verify"].iter().chain(args))
        };
        assert!(parse(&["x.audit.jsonl"]).is_ok());
        assert!(parse(&["--policy", "p.toml", "--anchor", "abc"]).is_ok());
        assert!(parse(&[]).is_err());
        assert!(parse(&["x.audit.jsonl", "--policy", "p.toml"]).is_err());
    }

    #[test]
    fn pin_writes_to_a_default_file_and_needs_force_to_replace_it() {
        let cli = Cli::try_parse_from(["mcp-mandate", "pin", "--", "server"]).unwrap();
        let Command::Pin { out, force, .. } = cli.command else {
            panic!("expected the pin command");
        };
        assert_eq!(out, PathBuf::from("mcp-mandate.pins.toml"));
        assert!(!force);
    }

    #[test]
    fn summarizes_what_was_pinned() {
        let inventory = Inventory {
            instructions: Some("Be careful.".to_owned()),
            tools: vec![json!({"name": "a"}), json!({"name": "b"})],
            prompts: vec![json!({"name": "p"})],
            ..Inventory::default()
        };
        let pins = Pins::from_inventory("server", &inventory);
        assert_eq!(
            summary(&pins),
            "2 tools, 1 prompt and the server's instructions"
        );
        assert_eq!(
            summary(&Pins::new("server")),
            "nothing (the server offers no tools, prompts or resources)"
        );
    }
}
