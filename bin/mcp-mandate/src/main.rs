//! The `mcp-mandate` command: one binary for the gate, Scout and the audit log.

use std::error::Error;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mcp_mandate_audit::{self as audit, Log, Recorder, VerifyError};
use mcp_mandate_gate::Gate;
use mcp_mandate_pin::{Inventory, Kind, Pins, PinsError, unpinned_package};
use mcp_mandate_policy::{Mode, Policy, PolicyError};
use mcp_mandate_proxy::ProxyError;
use mcp_mandate_proxy::agent_taint::AgentTaint;
use mcp_mandate_proxy::gateway::{self, GatewayConfig};
use mcp_mandate_proxy::stdio::{self, ServerCommand};
use mcp_mandate_scout as scout;
use tracing::field::{Field, Visit};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::field::{MakeVisitor, VisitFmt, VisitOutput};
use tracing_subscriber::fmt::format::Writer;

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
        #[command(flatten)]
        target: Target,
    },
    /// Serve the gate over HTTPS for remote MCP servers.
    Gate {
        /// Gateway configuration file (TOML).
        #[arg(long)]
        config: PathBuf,
    },
    /// Review an MCP server's tools and draft a policy for it. Starts the
    /// server once to list what it offers.
    Scout {
        /// Where to write the draft policy.
        #[arg(long, default_value = "mcp-mandate.draft.toml")]
        out: PathBuf,
        /// Replace an existing draft.
        #[arg(long)]
        force: bool,
        /// A pins file to check the server against and to name in the draft.
        #[arg(long)]
        pins: Option<PathBuf>,
        /// Also have Claude review the server. Sends its tool, prompt and
        /// resource definitions to the Claude API; needs ANTHROPIC_API_KEY.
        #[arg(long)]
        llm: bool,
        #[command(flatten)]
        target: Target,
    },
    /// Work with the audit log.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

/// The server to list: a local command after `--`, or a remote server
/// from a gateway configuration.
#[derive(Debug, clap::Args)]
struct Target {
    /// A gateway configuration, to use one of its remote servers (with
    /// `--server`) and the gateway's credential for it.
    #[arg(long, requires = "remote")]
    gateway: Option<PathBuf>,
    /// The remote server's name in the gateway configuration.
    #[arg(
        long = "server",
        id = "remote",
        value_name = "NAME",
        requires = "gateway"
    )]
    remote: Option<String>,
    /// A local server's command and its arguments, after `--`.
    #[arg(
        last = true,
        required_unless_present = "gateway",
        conflicts_with = "gateway"
    )]
    server: Vec<OsString>,
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
        Command::Pin { out, force, target } => pin(&out, force, target),
        Command::Gate { config } => gate(&config),
        Command::Scout {
            out,
            force,
            pins,
            llm,
            target,
        } => scout(&out, force, pins.as_deref(), llm, target),
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
    // Each file is read once, and what's parsed is what's hashed for the
    // audit log, so the hashes describe exactly what the gate enforces.
    let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
        path: path.to_owned(),
        source,
    })?;
    let policy = Policy::parse_file(&text, path)?;
    let policy_sha256 = audit::sha256_hex(text.as_bytes());
    warn_if_exposed("policy", path);
    let (pins, pins_sha256) = match &policy.pins {
        Some(pins_path) => {
            warn_if_exposed("pins file", pins_path);
            let text = std::fs::read_to_string(pins_path).map_err(|source| PinsError::Read {
                path: pins_path.clone(),
                source,
            })?;
            let pins = Pins::parse(&text, pins_path)?;
            info!(
                pins = %pins_path.display(),
                tools = pins.count(Kind::Tool),
                prompts = pins.count(Kind::Prompt),
                resources = pins.count(Kind::Resource),
                resource_templates = pins.count(Kind::ResourceTemplate),
                "loaded pins"
            );
            (Some(pins), Some(audit::sha256_hex(text.as_bytes())))
        }
        None => {
            warn!(
                "the policy names no pins file, so nothing the server offers is approved (see `mcp-mandate pin`)"
            );
            (None, None)
        }
    };
    info!(policy = %path.display(), mode = mode_name(policy.mode), "loaded policy");
    if policy.mode == Mode::Observe {
        warn!("observe mode: decisions are logged, but nothing is blocked or hidden");
    }
    let mut log = Log::open(&policy.audit_log)?;
    log.record(&session_start(
        path,
        &policy,
        command,
        policy_sha256,
        pins_sha256,
    ))?;
    info!(
        audit_log = %log.path().display(),
        session = log.session(),
        "recording every decision to the audit log"
    );
    let gate = Gate::new(policy, pins, Box::new(log));
    // Reading untrusted content through this server holds sending through
    // the agent's other servers too.
    Ok(match AgentTaint::for_this_agent() {
        Some(shared) => gate.with_shared_taint(Arc::new(shared)),
        None => gate,
    })
}

/// Warns when a file that configures the gate sits where the agent or a
/// server could rewrite it: inside the folder the server runs in (the
/// agent's own file tools reach it without passing the gate), or writable by
/// other users, or in a folder they can write to. Whoever can edit these
/// files decides what the gate allows.
fn warn_if_exposed(what: &str, path: &Path) {
    let Ok(full) = std::fs::canonicalize(path) else {
        return; // loading it reports the problem
    };
    let home = std::env::home_dir().and_then(|home| std::fs::canonicalize(home).ok());
    if let Ok(here) = std::env::current_dir().and_then(std::fs::canonicalize)
        && in_server_folder(&full, &here, home.as_deref())
    {
        warn!(
            file = %path.display(),
            "the {what} is inside the folder the server runs in, where the agent's file tools can rewrite it; keep it in a folder they can't write to, such as ~/.config/mcp-mandate"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |path: &Path| std::fs::metadata(path).map(|metadata| metadata.permissions().mode());
        if mode(&full).is_ok_and(|mode| mode & 0o022 != 0) {
            warn!(file = %path.display(), "the {what} is writable by other users");
        }
        // Whoever can write to a folder can replace the files in it, unless
        // it has the sticky bit (as /tmp does).
        if let Some(folder) = full.parent()
            && mode(folder).is_ok_and(|mode| mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            warn!(
                file = %path.display(),
                "the {what}'s folder is writable by other users, who can replace the file"
            );
        }
    }
}

/// Whether `file` is inside `here`, the folder the server runs in. Not when
/// that's a filesystem root or the home folder: clients start servers there
/// by default, and they hold every file you have, the folders this warning
/// recommends included.
fn in_server_folder(file: &Path, here: &Path, home: Option<&Path>) -> bool {
    file.starts_with(here) && here.parent().is_some() && home != Some(here)
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Enforce => "enforce",
        Mode::Observe => "observe",
    }
}

/// The audit entry that opens a session: what ran, under which policy. The
/// hashes are of the policy and pins files' text as the gate loaded it.
fn session_start(
    path: &Path,
    policy: &Policy,
    command: &ServerCommand,
    policy_sha256: String,
    pins_sha256: Option<String>,
) -> audit::Event {
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
    audit::Event {
        event: audit::EventKind::SessionStart,
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        mode: Some(mode_name(policy.mode).to_owned()),
        policy: Some(path.display().to_string()),
        policy_sha256: Some(policy_sha256),
        pins_sha256,
        server: Some(program.to_string_lossy().into_owned()),
        command_sha256: Some(audit::sha256_hex(&argv)),
        pid: Some(std::process::id()),
        ..audit::Event::default()
    }
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
            // The times are whatever the log says, and anything that can
            // write the log can seal an entry: a raw escape sequence or line
            // break here could rewrite the rest of this report.
            text += &format!(
                "  {entries} in {sessions}, {} to {}\n",
                scout::printable(first, 64),
                scout::printable(last, 64)
            );
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

/// `mcp-mandate scout`: lists what the server offers, scans it (and with
/// `--llm` has Claude review it), writes a draft policy and prints a report.
/// Exits 0 whatever it finds; the findings are in the report.
fn scout(out: &Path, force: bool, pins: Option<&Path>, llm: bool, target: Target) -> ExitCode {
    init_logging();
    if taken(out) && !force {
        error!(out = %out.display(), "the draft already exists; pass --force to replace it");
        return ExitCode::from(2);
    }
    let source = match Source::from(target) {
        Ok(source) => source,
        Err(problem) => {
            error!("{problem}");
            return ExitCode::from(2);
        }
    };
    let pinned = match pins.map(Pins::load).transpose() {
        Ok(pinned) => pinned,
        Err(error) => {
            error!(error = %report(&error), "couldn't read the pins file");
            return ExitCode::from(2);
        }
    };
    // Checked before the server starts, so a missing key fails fast.
    let reviewer = match reviewer(llm) {
        Ok(reviewer) => reviewer,
        Err(problem) => {
            error!("{problem}");
            return ExitCode::from(2);
        }
    };
    let Some(runtime) = runtime() else {
        return ExitCode::FAILURE;
    };
    let inventory = match source.list(&runtime) {
        Ok(inventory) => inventory,
        Err(error) => {
            error!(error = %report(&error), "couldn't list what the server offers");
            return ExitCode::FAILURE;
        }
    };
    let mut findings = scout::scan(&inventory);
    if let Some(pinned) = &pinned {
        findings.extend(scout::compare_with_pins(&inventory, pinned));
    }
    let review = review(&runtime, reviewer, &inventory, &mut findings);

    let server = source.label();
    let pins = pins.map(|pins| pins_reference(out, pins));
    let draft = scout::Draft::new(&inventory, &findings, &server, pins.as_deref());
    if let Err(error) = write_output(out, &draft.text, force) {
        error!(out = %out.display(), %error, "couldn't write the draft policy");
        return ExitCode::FAILURE;
    }
    let text = scout::render(
        &server,
        &inventory,
        &findings,
        &draft,
        &out.display().to_string(),
        &review,
    );
    let _ = std::io::stdout().write_all(text.as_bytes());
    ExitCode::SUCCESS
}

/// Whether anything is at `path`, a dangling symlink included.
fn taken(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Writes an output file. Without `--force` it must be new: whatever is at
/// the path, even a dangling symlink, is left alone. With `--force` the text
/// goes to a temporary file first, which then takes the path's place, so a
/// symlink there is replaced rather than written through.
fn write_output(out: &Path, text: &str, force: bool) -> std::io::Result<()> {
    let create = |path: &Path| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Readable and writable only by you, like the audit log, whatever
        // the umask: whoever can edit a pins file approves what's in it.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()
    };
    if !force {
        return create(out);
    }
    let name = out
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a file name"))?;
    let temporary = out.with_file_name(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let written = create(&temporary).and_then(|()| std::fs::rename(&temporary, out));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// How the draft names the pins file: as given when the draft is written in
/// the current folder (both paths then start from the same place), and
/// otherwise as an absolute path.
fn pins_reference(out: &Path, pins: &Path) -> String {
    let here = out
        .parent()
        .is_none_or(|parent| parent.as_os_str().is_empty());
    if here || pins.is_absolute() {
        return pins.display().to_string();
    }
    std::path::absolute(pins)
        .unwrap_or_else(|_| pins.to_owned())
        .display()
        .to_string()
}

/// The Claude client for `--llm`.
#[cfg(feature = "llm")]
fn reviewer(llm: bool) -> Result<Option<scout::claude::Client>, String> {
    if !llm {
        return Ok(None);
    }
    let key = std::env::var("ANTHROPIC_API_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty())
        .or_else(key_from_dotenv)
        .ok_or_else(|| report(&scout::claude::Error::MissingApiKey))?;
    scout::claude::Client::new(key)
        .map(Some)
        .map_err(|error| report(&error))
}

/// `ANTHROPIC_API_KEY` from the `.env` file in the current folder (never a
/// parent folder's), read without putting it in this process's environment.
/// The server Scout starts never gets the key either way: it's removed from
/// the environment the server inherits.
#[cfg(feature = "llm")]
fn key_from_dotenv() -> Option<String> {
    key_from_dotenv_in(Path::new("."))
}

#[cfg(feature = "llm")]
fn key_from_dotenv_in(folder: &Path) -> Option<String> {
    dotenvy::from_path_iter(folder.join(".env"))
        .ok()?
        .filter_map(Result::ok)
        .find(|(name, _)| name == "ANTHROPIC_API_KEY")
        .map(|(_, key)| key)
        .filter(|key| !key.trim().is_empty())
}

/// Runs Claude's review when asked, adding its findings; returns a line for
/// the report. A failed review adds nothing: Scout fails safe.
#[cfg(feature = "llm")]
fn review(
    runtime: &tokio::runtime::Runtime,
    reviewer: Option<scout::claude::Client>,
    inventory: &mcp_mandate_pin::Inventory,
    findings: &mut Vec<scout::Finding>,
) -> String {
    let Some(client) = reviewer else {
        return "not run (add --llm to include it)".to_owned();
    };
    info!(
        model = scout::MODEL,
        "sending the server's definitions to the Claude API for review"
    );
    match runtime.block_on(scout::review(&client, inventory)) {
        Ok(review) => {
            let count = review.findings.len();
            findings.extend(review.findings);
            let mut line = format!(
                "{count} finding{} from {}",
                if count == 1 { "" } else { "s" },
                review.model
            );
            if review.ignored > 0 {
                line.push_str(&format!(
                    " ({} more dropped: they named nothing the server offers, or had no valid severity)",
                    review.ignored
                ));
            }
            line
        }
        Err(error) => {
            let error = report(&error);
            warn!(%error, "Claude's review failed; the draft holds every tool");
            findings.extend(scout::review_failed(inventory));
            format!("failed ({error}); the draft holds every tool")
        }
    }
}

#[cfg(not(feature = "llm"))]
fn reviewer(llm: bool) -> Result<Option<std::convert::Infallible>, String> {
    if llm {
        Err("this build has no Claude review (it was built without the `llm` feature)".to_owned())
    } else {
        Ok(None)
    }
}

#[cfg(not(feature = "llm"))]
fn review(
    _: &tokio::runtime::Runtime,
    _: Option<std::convert::Infallible>,
    _: &mcp_mandate_pin::Inventory,
    _: &mut Vec<scout::Finding>,
) -> String {
    "not available in this build".to_owned()
}

/// `mcp-mandate pin`: records what the server offers into a pins file.
fn pin(out: &Path, force: bool, target: Target) -> ExitCode {
    init_logging();
    if taken(out) && !force {
        error!(
            out = %out.display(),
            "the pins file already exists; pass --force to replace it (re-pinning trusts whatever the server shows now)"
        );
        return ExitCode::from(2);
    }
    let source = match Source::from(target) {
        Ok(source) => source,
        Err(problem) => {
            error!("{problem}");
            return ExitCode::from(2);
        }
    };
    let Some(runtime) = runtime() else {
        return ExitCode::FAILURE;
    };
    let inventory = match source.list(&runtime) {
        Ok(inventory) => inventory,
        Err(error) => {
            error!(error = %report(&error), "couldn't list what the server offers");
            return ExitCode::FAILURE;
        }
    };
    let pins = Pins::from_inventory(source.label(), &inventory);
    if let Err(error) = write_output(out, &pins.to_toml(), force) {
        error!(out = %out.display(), %error, "couldn't write the pins file");
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

/// Where `pin` and `scout` list a server: a local command, or a remote
/// server from a gateway configuration (signing in as the gateway does).
enum Source {
    Local(ServerCommand),
    Remote(Box<gateway::ServerConfig>),
}

impl Source {
    fn from(target: Target) -> Result<Self, String> {
        let (Some(config), Some(name)) = (target.gateway, target.remote) else {
            let command = server_command(target.server);
            warn_if_unpinned(&command);
            return Ok(Self::Local(command));
        };
        // Pins aren't loaded: the server may not be pinned yet.
        let gateway = GatewayConfig::load_without_pins(&config).map_err(|error| report(&error))?;
        let server = gateway
            .servers
            .get(&name)
            .cloned()
            .ok_or_else(|| format!("{} has no server named `{name}`", config.display()))?;
        Ok(Self::Remote(Box::new(server)))
    }

    /// What the server is, for people: its command with anything that looks
    /// like a secret masked, or its URL without a user name, password,
    /// query or fragment (any of which could hold one).
    fn label(&self) -> String {
        match self {
            Self::Local(command) => command.to_string(),
            Self::Remote(server) => {
                let mut url = server.url.clone();
                let _ = url.set_username("");
                let _ = url.set_password(None);
                url.set_query(None);
                url.set_fragment(None);
                url.to_string()
            }
        }
    }

    /// Lists what the server offers. A stop signal while a local server is
    /// being listed stops it and everything it started, then ends the
    /// program; a later one ends the program at once.
    fn list(&self, runtime: &tokio::runtime::Runtime) -> Result<Inventory, ProxyError> {
        match self {
            Self::Local(command) => runtime.block_on(async {
                let mut signals = stdio::Signals::new();
                let listed = stdio::inventory(command, signals.recv()).await;
                if let Err(ProxyError::Interrupted(code)) = listed {
                    std::process::exit(code);
                }
                // The signals stay caught from here on, so they need acting on.
                tokio::spawn(async move { std::process::exit(signals.recv().await) });
                listed
            }),
            Self::Remote(server) => runtime.block_on(gateway::inventory(server)),
        }
    }
}

/// `mcp-mandate gate`: serves the HTTPS gateway until stopped.
fn gate(config: &Path) -> ExitCode {
    init_logging();
    let config = match GatewayConfig::load(config) {
        Ok(config) => config,
        Err(error) => {
            error!(error = %report(&error), "couldn't load the gateway configuration");
            return ExitCode::from(2);
        }
    };
    let Some(runtime) = runtime() else {
        return ExitCode::FAILURE;
    };
    let code = match runtime.block_on(gateway::run(config)) {
        Ok(code) => code,
        Err(error) => {
            error!(error = %report(&error), "the gateway failed");
            1
        }
    };
    // As in `run`: exit without waiting for the runtime's other tasks.
    std::process::exit(code)
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
        .fmt_fields(EscapedFields)
        .init();
}

/// Writes log fields as the default format does, but with control and
/// invisible characters escaped in every value, not only the message.
/// Fields carry text a server or client chose (a method name, a server's
/// error message), which must not move the cursor or forge a log line.
#[derive(Clone, Copy)]
struct EscapedFields;

struct EscapedVisitor<'a> {
    writer: Writer<'a>,
    first: bool,
    result: std::fmt::Result,
}

impl<'a> MakeVisitor<Writer<'a>> for EscapedFields {
    type Visitor = EscapedVisitor<'a>;

    fn make_visitor(&self, writer: Writer<'a>) -> Self::Visitor {
        EscapedVisitor {
            writer,
            first: true,
            result: Ok(()),
        }
    }
}

impl Visit for EscapedVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.record_debug(field, &format_args!("{value}"));
        } else {
            self.record_debug(field, &value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // `log.*` fields are metadata of events from the `log` crate, which
        // the format has already written.
        if self.result.is_err() || field.name().starts_with("log.") {
            return;
        }
        let separator = if std::mem::take(&mut self.first) {
            ""
        } else {
            " "
        };
        // Nothing is cut: `usize::MAX` characters is no limit.
        let value = scout::printable(&format!("{value:?}"), usize::MAX);
        self.result = match field.name() {
            "message" => write!(self.writer, "{separator}{value}"),
            name => write!(
                self.writer,
                "{separator}{}={value}",
                name.trim_start_matches("r#")
            ),
        };
    }
}

impl VisitOutput<std::fmt::Result> for EscapedVisitor<'_> {
    fn finish(self) -> std::fmt::Result {
        self.result
    }
}

impl VisitFmt for EscapedVisitor<'_> {
    fn writer(&mut self) -> &mut dyn std::fmt::Write {
        &mut self.writer
    }
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
    fn scout_writes_a_draft_and_needs_llm_to_call_claude() {
        let cli = Cli::try_parse_from(["mcp-mandate", "scout", "--", "server"]).unwrap();
        let Command::Scout { out, llm, pins, .. } = cli.command else {
            panic!("expected the scout command");
        };
        assert_eq!(out, PathBuf::from("mcp-mandate.draft.toml"));
        assert!(!llm, "the Claude review is opt-in");
        assert_eq!(pins, None);
    }

    #[test]
    fn the_draft_names_the_pins_file_so_it_resolves_from_the_draft() {
        let here = pins_reference(Path::new("draft.toml"), Path::new("x.pins.toml"));
        assert_eq!(here, "x.pins.toml");
        let elsewhere = pins_reference(Path::new("drafts/d.toml"), Path::new("x.pins.toml"));
        assert!(Path::new(&elsewhere).is_absolute(), "{elsewhere}");
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
    fn the_verify_report_escapes_what_the_log_says() {
        // Sealing has no key, so anything that can write the log can add a
        // valid entry whose time is an escape sequence and a forged line.
        let body = format!(
            r#"{{"seq":1,"prev":"{}","time":"\u001b[2K\n  Head: forged"}}"#,
            audit::GENESIS
        );
        let line = format!(
            "{},\"hash\":\"{}\"}}\n",
            &body[..body.len() - 1],
            audit::sha256_hex(body.as_bytes())
        );
        let found = audit::verify_reader(line.as_bytes(), None).unwrap();
        let text = intact(Path::new("x.audit.jsonl"), &found);
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(!text.contains("\n  Head: forged"), "{text}");
        assert!(text.contains("\\u{1b}[2K\\u{a}  Head: forged"), "{text}");
    }

    #[test]
    fn warns_about_the_server_folder_but_not_a_root_or_the_home_folder() {
        let root = std::env::temp_dir().ancestors().last().unwrap().to_owned();
        let home = root.join("home").join("me");
        let project = home.join("project");
        let policy = project.join("policy.toml");
        let inside = |here: &Path, file: &Path| in_server_folder(file, here, Some(home.as_path()));
        assert!(inside(&project, &policy));
        assert!(!inside(&home, &policy));
        assert!(!inside(&root, &policy));
        assert!(!inside(&project, &home.join(".config").join("policy.toml")));
    }

    #[test]
    fn log_fields_cant_move_the_cursor_or_forge_a_line() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_target(false)
            .fmt_fields(EscapedFields)
            .finish();
        // A method name from a client, and a server's error message.
        let method = "x\u{1b}[1A\u{1b}[2K\nWARN allowed";
        let error = "\u{1b}]52;c;Zm9v\u{7}";
        tracing::subscriber::with_default(subscriber, || {
            warn!(%method, %error, note = "a\rb", "blocked\u{1b}[8m");
        });
        let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert_eq!(logged.matches('\n').count(), 1, "{logged}");
        assert!(!logged.contains(['\u{1b}', '\u{7}', '\r']), "{logged}");
        assert!(
            logged.contains(
                "blocked\\u{1b}[8m method=x\\u{1b}[1A\\u{1b}[2K\\u{a}WARN allowed error=\\u{1b}]52;c;Zm9v\\u{7} note=\"a\\rb\""
            ),
            "{logged}"
        );
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

    #[cfg(feature = "llm")]
    #[test]
    fn the_api_key_is_read_only_from_the_current_folders_env_file() {
        let parent = std::env::temp_dir().join(format!("mcp-mandate-env-{}", std::process::id()));
        let project = parent.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(parent.join(".env"), "ANTHROPIC_API_KEY=from-the-parent\n").unwrap();
        assert_eq!(key_from_dotenv_in(&project), None);
        std::fs::write(project.join(".env"), "ANTHROPIC_API_KEY=from-here\n").unwrap();
        assert_eq!(key_from_dotenv_in(&project).as_deref(), Some("from-here"));
        std::fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn output_files_are_new_unless_forced_and_never_written_through_a_link() {
        let dir = std::env::temp_dir().join(format!("mcp-mandate-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("draft.toml");
        write_output(&out, "one", false).unwrap();
        assert!(write_output(&out, "two", false).is_err());
        write_output(&out, "two", true).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Private whatever the umask, a replaced file included.
            let mode = std::fs::metadata(&out).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");
            write_output(&dir.join("new.toml"), "one", false).unwrap();
            let mode = std::fs::metadata(dir.join("new.toml"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");

            let target = dir.join("elsewhere");
            let link = dir.join("link.toml");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(taken(&link));
            assert!(write_output(&link, "x", false).is_err());
            assert!(!target.exists());
            write_output(&link, "x", true).unwrap();
            assert!(!target.exists());
            assert_eq!(std::fs::read_to_string(&link).unwrap(), "x");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
