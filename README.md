# mcp-mandate

**Pin what you trust. Permit what you allow. Prove what happened.**

mcp-mandate is an open-source security gate between AI agents (Claude Code,
Cursor, your own) and the MCP servers they call. Every tool call passes a
deterministic check before it reaches a server, so an agent that was tricked
by something it read can't act with your keys.

> **Status: under construction.** v0.1.0 isn't released. Pinning, policy,
> taint tracking and secret redaction work for local (stdio) servers; the
> HTTP gateway and the audit log don't exist yet. Don't rely on it for
> protection.

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

Steps 2, 3, 4, 5, 7 and 8 work today for stdio servers (step 8 redacts
secrets, not yet other personal data).

## Quick start

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
- **Modes.** `enforce` (the default) blocks; `observe` logs what would be
  blocked, hidden or redacted and lets everything through, for trying a
  policy on real traffic.

A blocked tool call comes back to the agent as a tool error that says why
(for example, "Blocked by mcp-mandate: tool `x` changed since it was
approved"). "Hold" needs a person's approval, which isn't supported yet, so a
held call is blocked with a reason saying so.

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
| `crates/mcp-mandate-gate` | The checks: decides what crosses between client and server, for any transport |
| `crates/mcp-mandate-pin` | Fingerprints and the pins file |
| `crates/mcp-mandate-policy` | The policy file and argument checks |
| `crates/mcp-mandate-proxy` | Transports: relays stdio traffic through the gate and runs the server process |
| `crates/mcp-mandate-taint` | Which tools read untrusted content or send data out; secret detection and redaction |
| `crates/mcp-mandate-scout` | Server review and the optional Claude API client |
| `policies/` | Example and shared policies |

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
