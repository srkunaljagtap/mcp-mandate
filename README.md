# mcp-mandate

**Pin what you trust. Permit what you allow. Prove what happened.**

mcp-mandate is an open-source security gate between AI agents (Claude Code,
Cursor, your own) and the MCP servers they call. Every tool call passes a
deterministic check before it reaches a server, so an agent that was tricked
by something it read can't act with your keys.

> **Status: under construction.** v0.1.0 isn't released. Pinning, policy,
> taint tracking, secret redaction, the audit log, Scout and the HTTPS
> gateway work, but haven't been through the hardening and review planned
> before release. Don't rely on it for protection yet.

## How it works

Two parts, two speeds:

| | Gate | Scout |
|---|---|---|
| Runs on | Every MCP call, in line | New or changed servers, offline |
| Uses an LLM | Never | Optional, with your own API key |
| Can decide | Allow, block, hold | Only propose rules |
| When it fails | Closed (blocks) | Safe (no new rules) |

For each tool call the gate will:

1. **Identify** the caller (OIDC token on the HTTP gateway).
2. **Pin**: check the tool's name, description and schema against the hash you
   approved, and quarantine tools that changed.
3. **Authorize** against your policy (default deny).
4. **Validate** arguments: schema, size limits, no shell metacharacters in
   command fields.
5. **Flow check**: hold calls that write or send data out once the session has
   read untrusted content.
6. **Broker** a credential scoped to that one server; never forward yours.
7. **Call** the server over stdio or HTTP.
8. **Redact and label** the response: scrub secrets, mark untrusted output.
9. **Record** a hash-chained audit entry for every decision.

All nine steps work today: step 1 on the [HTTPS gateway](#the-https-gateway)
(local servers run as you), and step 6 as a credential of the gateway's own
for each server (not yet one per user). Step 8 redacts secrets, not yet
other personal data.

## Quick start

**0. Review the server (optional).** [Scout](#scout) looks for poisoned
descriptions and drafts a policy:

```sh
mcp-mandate scout -- npx -y @modelcontextprotocol/server-everything@1.0.0
```

**1. Pin the server.** This starts it once, records what it offers (tools,
prompts, resources and its instructions) and stops it:

```sh
mcp-mandate pin --out everything.pins.toml -- npx -y @modelcontextprotocol/server-everything@1.0.0
```

Read the pins file before going further: everything pinned in it is trusted.
Pin a package *version* (`@1.0.0` above); without one, `npx` fetches the
newest release on every run, so the code can change while its descriptions
don't, and mcp-mandate warns about it.

**2. Write a policy.** Start from [policies/example.toml](policies/example.toml):

```toml
pins = "everything.pins.toml"

[[tools]]
match = "echo"
action = "allow"
```

**3. Run the server behind the gate:**

```sh
mcp-mandate run --policy policy.toml -- npx -y @modelcontextprotocol/server-everything@1.0.0
```

In your MCP client's config, put `mcp-mandate run --policy <file> --` in
front of the server command it already runs:

```json
{
  "mcpServers": {
    "everything": {
      "command": "mcp-mandate",
      "args": ["run", "--policy", "/path/to/policy.toml", "--",
               "npx", "-y", "@modelcontextprotocol/server-everything@1.0.0"]
    }
  }
}
```

Logs go to stderr, never stdout (stdout carries the MCP traffic). Set
`MCP_MANDATE_LOG=debug` to log every decision; the default `info` logs what
was hidden or blocked.

**4. Check the record.** Every decision is also written to an audit log
next to the policy (`policy.toml` → `policy.audit.jsonl`):

```sh
mcp-mandate audit verify policy.audit.jsonl
```

## What's checked today

- **Pinning.** Tools, prompts, resources, resource templates and the server's
  instructions are compared with their pins. Anything changed since approval
  (a "rug pull") or never approved is hidden from lists, and calls to it are
  blocked. A server with no pins file gets nothing through.
- **Policy.** Each tool is allowed, held or denied (default: denied). When
  several rules match, the most restrictive wins. Denied tools are hidden
  from the model.
- **Arguments.** Size limits, shell metacharacters in the arguments you
  name, and the tool's own JSON Schema.
- **Requests from the server.** `sampling/createMessage` (the server asks the
  client's model to write) and `elicitation/create` (the server asks you a
  question) are denied unless the policy allows them.
- **Unknown requests** are denied, so a new protocol feature can't slip
  through unchecked.
- **Taint.** Once a tool that reads untrusted content answers (a web
  fetch, an inbox, anything a stranger could have written), or a resource is
  read, the session is tainted for the rest of its life. Tools that can send
  data out are then held, so a model hijacked by what it read can't complete
  an exfiltration. Which tools are which comes from your policy's
  `reads_untrusted` and `sends_out` labels, or else the tool's pinned
  `openWorldHint`; a tool that says nothing counts as both.
- **Secrets.** API keys, tokens, private keys and password assignments are
  replaced with `[REDACTED: kind]` in everything the server sends (except
  image and audio data), and a tool call whose arguments carry one is
  blocked unless its rule sets `allow_secrets = true`. Add your own patterns
  under `[[secrets.patterns]]`. Personal data such as emails isn't redacted
  yet.
- **Audit log.** Every message that crosses the gate is recorded with what
  the gate did and why, in a hash chain that shows any later edit. See
  [The audit log](#the-audit-log).
- **Modes.** `enforce` (the default) blocks; `observe` logs what would be
  blocked, hidden or redacted and lets everything through, for trying a
  policy on real traffic.

A blocked tool call comes back to the agent as a tool error that says why
(for example, "Blocked by mcp-mandate: tool `x` changed since it was
approved"). "Hold" needs a person's approval, which isn't supported yet, so a
held call is blocked with a reason saying so.

## The HTTPS gateway

For remote MCP servers (a URL rather than a program on your machine),
`mcp-mandate gate` runs as a service that agents connect to over HTTPS:

```
agent ──HTTPS + your OIDC token──▶ mcp-mandate gate ──HTTPS + the gateway's own credential──▶ MCP server
```

```sh
mcp-mandate pin --gateway gateway.toml --server github --out github.pins.toml
mcp-mandate gate --config gateway.toml
```

Agents connect to `https://<gateway>/servers/<name>/mcp`. Start from
[policies/gateway.example.toml](policies/gateway.example.toml).

- **Who's calling.** Every request needs a bearer token from your OIDC
  identity provider. The gateway checks:
  - the signature, against the provider's published keys (asymmetric
    algorithms only, never shared-secret `HS*`, and the key's type must
    match the token's algorithm);
  - the issuer;
  - the audience (the gateway, or the server being used);
  - the subject, the expiry and the not-before time.

  Any token that passes may use every configured server, so decide who can
  get one in your identity provider. A missing or bad token gets `401` with
  a link to the gateway's OAuth metadata (RFC 9728), which MCP clients use
  to find your provider and sign in.
- **The server never sees your token.** The gateway removes it and signs in
  with its own credential for that one server: a secret from an environment
  variable or file (never the config file itself), or short-lived OAuth
  client-credential tokens. Only the headers MCP needs are passed on, and
  redirects aren't followed, so a server can't bounce the credential
  elsewhere.
- **Sessions** belong to the caller who opened them, and each has its own
  gate: its own taint, its own audit session. The server's session id is
  never shown to the client. Idle sessions close after 30 minutes.
- **Every message**, including streamed (SSE) ones, goes through the gate
  exactly as with `mcp-mandate run`. Each session's audit log entries name
  the caller (`sub`) and their OAuth client.
- **HTTPS:** mcp-mandate serves TLS itself with your certificate, or plain
  HTTP behind a proxy that handles TLS (`terminated_by_proxy = true`). Plain
  HTTP is otherwise allowed only on localhost. Servers must use `https://`
  unless they're on localhost.

## Scout

Scout reviews a server before you trust it. It starts the server once,
reads everything the server shows the model (instructions, tools and their
parameter descriptions, prompts, resources), prints a report and writes a
draft policy. It only proposes; nothing changes until you use the draft.

```sh
mcp-mandate scout --pins everything.pins.toml --out everything.draft.toml \
  -- npx -y @modelcontextprotocol/server-everything@1.0.0
```

- **The scan** looks for:
  - text aimed at the model ("do not tell the user", `<IMPORTANT>` blocks,
    orders such as "always call this tool first");
  - credential files (`~/.ssh`, `.env`, cloud credentials), and secrets
    such as environment variables or API keys;
  - requests to send data to an address;
  - invisible or direction-changing characters, and encoded blobs;
  - arguments that take a command line.
- **The draft** is built by risk:
  - tools whose annotations say read-only and closed-world are allowed;
  - tools that can change things or reach the outside world are held, with
    taint labels set from their annotations;
  - a medium finding holds a tool, and a high finding denies it.

  Every rule names a tool exactly (never a pattern), and its comments say
  why. With `--pins`, the draft names the pins file and the report flags
  anything that isn't pinned or has changed.
- **Claude's review** (`--llm`) is a second opinion on what patterns can't
  judge, such as a description that doesn't match the tool's schema.
  - It's off unless you pass `--llm`, and it sends the server's definitions
    to the Claude API with your own key (`ANTHROPIC_API_KEY`, or a `.env`
    file; see `.env.example`).
  - The key is never put in the environment the reviewed server inherits.
  - It can only make the draft stricter, never looser: the descriptions it
    reads were written by the server and may try to talk it into "safe".
  - If it fails or declines, the draft uses the scan alone.
  - Building with `cargo build --no-default-features` leaves it out.

Scout exits 0 whenever it ran; the findings are in the report.

## The audit log

Each message that crosses the gate gets one JSON line: when, which session,
which side sent it, the method and tool, what the gate did (`allow`,
`modify`, `block` or `drop`) and why, and SHA-256 hashes of the message
and of a tool call's arguments. Message content is never written, so the
log doesn't become a second copy of everything your agent read. With a
payload in hand, you can still find its entry by its hash. (A hash of a
short, guessable value, such as a 6-digit code, can be reversed by trying
every candidate.) Each session's first entry records the mcp-mandate
version, the mode, and hashes of the policy, the pins file and the server
command.

```sh
# What was blocked, and why
jq -c 'select(.verdict == "block") | {time, item, reason}' policy.audit.jsonl
```

- **Where:** next to the policy, named after it (`policy.toml` →
  `policy.audit.jsonl`), or wherever `[audit] path` says. Several sessions
  can share one log. On Linux and macOS it's created readable only by you.
  If your policies are in git, add `*.audit.jsonl` to `.gitignore`.
- **If it can't be written** (full disk, deleted file), nothing passes:
  requests are answered with an error saying the audit log can't be
  written, until it can be again. A log that can't be opened stops
  `mcp-mandate run` from starting. Observe mode only warns.
- **Tamper evidence.** Each line holds the hash of its own bytes and of the
  line before it, so editing, removing, adding or reordering lines breaks
  the chain, and `mcp-mandate audit verify` names the first broken line.

A chain can't show entries cut off its end, or a log rewritten from
scratch with fresh hashes. To catch those, save the head hash that
`verify` prints somewhere your agent's account can't write, and check
against it later:

```sh
mcp-mandate audit verify policy.audit.jsonl --anchor <saved head>
```

## What it doesn't do

- **It only sees MCP traffic routed through it.** Your agent's built-in tools
  (shell commands, file edits, web fetches) and any MCP server configured
  directly in the client bypass the gate entirely. Use your agent's own
  permission settings for those, and route every MCP server through
  mcp-mandate.
- **It guards MCP messages, not the server process.** A local server runs
  with your operating-system permissions and could read files directly
  without making an MCP call. Use OS sandboxing to contain that.
- **It doesn't replace** your identity provider or the servers' own
  authentication.
- **Behind the gateway, a server sees the gateway, not you.** Every caller
  acts with the gateway's credential for that server. Per-user credentials
  (token exchange) come later.
- **The gateway keeps sessions in memory.** Run one instance, or send each
  client to the same one (sticky sessions). A restart ends every session.
- **No AI decides what to block.** The gate is plain rules; Scout's LLM
  review is optional and only drafts rules for you to approve.
- **On Windows, stopping a server stops only the process mcp-mandate
  started.** On Linux and macOS the server's whole process group is stopped,
  including anything it launched (such as the `node` process behind `npx`).

## Build from source

Requires [rustup](https://rustup.rs). The Rust version is pinned in
`rust-toolchain.toml` and installed on first build. On Windows you also need
the Visual Studio C++ build tools.

```sh
cargo build --release
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check        # licenses, advisories, sources (cargo install cargo-deny)
```

## Layout

| Path | What it is |
|---|---|
| `bin/mcp-mandate` | The `mcp-mandate` command: `run`, `pin`, `gate`, `scout`, `audit` |
| `crates/mcp-mandate-audit` | The hash-chained audit log and its verification |
| `crates/mcp-mandate-gate` | The checks: decides what crosses between client and server, for any transport |
| `crates/mcp-mandate-pin` | Fingerprints and the pins file |
| `crates/mcp-mandate-policy` | The policy file and argument checks |
| `crates/mcp-mandate-proxy` | Transports: the stdio relay (running the server process) and the HTTPS gateway (identity, sessions, upstream credentials) |
| `crates/mcp-mandate-taint` | Which tools read untrusted content or send data out; secret detection and redaction |
| `crates/mcp-mandate-scout` | Scout: the rule scan, draft policies and the optional Claude review |
| `policies/` | Example policies and gateway configuration |

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
