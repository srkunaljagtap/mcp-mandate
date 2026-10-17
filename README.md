# mcp-mandate

**Pin what you trust. Permit what you allow. Prove what happened.**

mcp-mandate is an open-source security gate between AI agents (Claude Code,
Cursor, your own) and the MCP servers they call. Every tool call passes a
deterministic check before it reaches a server, so an agent that was tricked
by something it read can't act with your keys.

> **Status: under construction.** v0.1.0 isn't released. `mcp-mandate run`
> relays a stdio MCP server, but no checks are enforced yet. Don't rely on it
> for protection.

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

## Usage

Working today: relay a local (stdio) MCP server. Messages pass through
unchanged; lines that aren't JSON-RPC are dropped and logged.

```sh
mcp-mandate run -- npx -y <mcp-server>
```

Logs go to stderr, never stdout (stdout carries the MCP traffic). Set
`MCP_MANDATE_LOG=debug` to log every message, or `warn` for quieter output;
the default is `info`.

Planned:

```sh
# review a server and draft a policy for it
mcp-mandate scout -- npx -y <mcp-server>

# run it behind the gate (refused until policies are enforced)
mcp-mandate run --policy policies/default.toml -- npx -y <mcp-server>

# check that the audit log wasn't tampered with
mcp-mandate audit verify
```

In your MCP client's config, put `mcp-mandate run --` in front of the server
command it already runs:

```json
{
  "mcpServers": {
    "github": {
      "command": "mcp-mandate",
      "args": ["run", "--", "npx", "-y", "<mcp-server>"]
    }
  }
}
```

## What it doesn't do

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
| `bin/mcp-mandate` | The `mcp-mandate` command: `run`, `gate`, `scout`, `audit` |
| `crates/mcp-mandate-proxy` | Transports: relays MCP traffic (stdio today) and runs the server process |
| `crates/mcp-mandate-scout` | Server review and the optional Claude API client |

More crates (pinning, policy, taint, audit, identity) arrive as the
features do.

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
