# mcp-mandate

**Pin what you trust. Permit what you allow. Prove what happened.**

mcp-mandate is an open-source toolkit for the MCP servers your AI agents
(Claude Code, Cursor, your own) call:

- **Scout** reviews a server before you trust it and drafts its policy.
- A hash-chained **audit log** records every decision, so you can prove
  what happened.
- The **gate** checks every tool call deterministically before it reaches a
  server, so an agent tricked by something it read can't act with your keys.

> **Status: experimental.** Interfaces may change, and it hasn't been
> audited. Don't rely on it for protection yet.

## How it works

| | Gate | Scout |
|---|---|---|
| Runs on | Every MCP call, in line | New or changed servers, offline |
| Uses an LLM | Never | Optional, with your own API key |
| Can decide | Allow, block, hold | Only propose rules |
| When it fails | Closed (blocks), in `enforce` mode | Safe (no new rules) |

For each call, the gate identifies the caller (on the HTTPS gateway), checks
the tool against what you pinned, applies your policy, validates the arguments, holds tools that
send data out once the session has read untrusted content, redacts secrets
from the answer, and records the decision.

**Policies start in `observe` mode:** the gate logs what it would block,
hide or redact, and lets everything through. It blocks only once the policy
says `mode = "enforce"`.

## Install

- **Prebuilt binaries** for Linux, macOS and Windows are on the
  [releases page](https://github.com/srkunaljagtap/mcp-mandate/releases),
  each with SHA-256 checksums and a signed build attestation.
- **From source**, with [rustup](https://rustup.rs):
  `cargo install --locked --git https://github.com/srkunaljagtap/mcp-mandate --tag v0.2.0 mcp-mandate`
- **Container image** for the HTTPS gateway:
  `ghcr.io/srkunaljagtap/mcp-mandate:0.2.0` (non-root, no shell).

The Windows binary isn't code-signed yet; with Smart App Control on, use
WSL. [Install](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/install.md)
shows how to verify a download and run the container.

## Quick start

**1. Review and pin the server.** Scout flags poisoned descriptions and
drafts a policy; `pin` records what the server offers. Read the pins file:
everything in it is trusted. Pin an exact package version (`@1.0.0`).

```sh
mcp-mandate scout -- npx -y @modelcontextprotocol/server-everything@1.0.0
mcp-mandate pin --out everything.pins.toml -- npx -y @modelcontextprotocol/server-everything@1.0.0
```

**2. Write a policy**, starting from
[policies/example.toml](https://github.com/srkunaljagtap/mcp-mandate/blob/main/policies/example.toml).
Keep it and the pins file where neither the agent nor a server can write.

```toml
mode = "observe"   # logs only; change to "enforce" once the log looks right
pins = "everything.pins.toml"

[[tools]]
match = "echo"
action = "allow"
```

**3. Run the server behind the gate** by putting
`mcp-mandate run --policy <file> --` in front of its command in your MCP
client's config:

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

**4. Check the record.** Every decision goes to an audit log next to the
policy (`policy.toml` → `policy.audit.jsonl`), unless its `[audit] path`
names another place. This checks the log a policy writes, wherever it is:

```sh
mcp-mandate audit verify --policy /path/to/policy.toml
```

The full [quick start](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/quick-start.md)
covers re-pinning, how secrets in server commands are masked, and logging.

## What's checked

In `enforce` mode (`observe` mode only logs these):

- **Pinning:** tools, prompts, resources, resource templates and the
  server's instructions must match what you pinned; anything changed or
  never approved is hidden and blocked. A resource read must name a pinned
  resource or fit a pinned template, with strict rules on what a template
  variable may hold.
- **Policy:** each tool is allowed, held or denied (default: denied); the
  most restrictive matching rule wins. Approving a held call isn't
  supported yet, so a held call is blocked with a reason saying so.
- **Arguments:** size limits, the tool's JSON Schema, and shell
  metacharacters in the arguments you name.
- **Requests:** sampling and elicitation from the server are denied unless
  the policy allows them, and so is any request, from either side, that the
  gate doesn't know.
- **Taint:** once a session reads untrusted content, tools that can send
  data out are held, across all of an agent's servers.
- **Secrets:** API keys, tokens and passwords are redacted from what
  servers send, and requests carrying them are blocked.
- **Messages the gate can't check reliably** (batches, repeated keys,
  oversized messages) are dropped, or answered with an error.

[What's checked](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/checks.md)
has every rule and limit, and what observe mode still does.

## HTTPS gateway

For remote MCP servers, `mcp-mandate gate` runs as an HTTPS service.
Callers sign in with OIDC tokens; the gateway calls each server with its own
credential, so the server never sees yours, and redacts it if the server
echoes it back. Each session gets its own gate and audit trail. See
[The HTTPS gateway](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/gateway.md).

## Scout

`mcp-mandate scout` starts a server once, scans everything it shows the
model (text aimed at the model, credential files, send-to-address requests,
hidden characters, tool arguments that take a command line), prints a
report and writes a
draft policy. An optional Claude review (`--llm`, with your own API key) can
only make the draft stricter. See
[Scout](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/scout.md).

## Audit log

Every message gets one JSON line: what the gate did and why, with hashes of
the message, never its content. Lines are hash-chained, so
`mcp-mandate audit verify` finds any edit; save the head hash it prints to
catch a log cut short or rewritten. In `enforce` mode nothing passes while
the log can't be written. See
[The audit log](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/audit-log.md).

## How it's tested

An attack corpus of 82 attacks, 19 benign cases and 5 known gaps runs on
every pull request, along with property tests and a 5 ms latency budget;
coverage-guided fuzzing runs weekly. See
[How it's tested](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/testing.md),
including the known gaps.

## What it doesn't do

- It sees only MCP traffic routed through it: your agent's built-in tools,
  and servers configured directly in the client, bypass it.
- It guards MCP messages, not the server process: a local server runs with
  your permissions, so sandbox it too.
- Anything that can write its policy, pins file or audit log can loosen or
  cut them: keep those files out of reach of the agent and its servers.
- Behind the gateway, every caller acts with the gateway's credential for
  each server; per-user credentials come later.
- The gateway keeps sessions in memory: run one instance, or send each
  client to the same one (sticky sessions). A restart ends every session.

## Documentation

- [Install](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/install.md):
  verifying downloads, Windows, the container image
- [Quick start](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/quick-start.md):
  the full walkthrough
- [What's checked](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/checks.md):
  every rule, modes, and what it doesn't do
- [The HTTPS gateway](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/gateway.md),
  [Scout](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/scout.md),
  [The audit log](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/audit-log.md)
- [How it's tested](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/testing.md)
  and its known gaps
- [Development](https://github.com/srkunaljagtap/mcp-mandate/blob/main/docs/development.md):
  building from source and the code layout

## Contributing and security

See [CONTRIBUTING.md](https://github.com/srkunaljagtap/mcp-mandate/blob/main/CONTRIBUTING.md). Please report vulnerabilities
privately as described in [SECURITY.md](https://github.com/srkunaljagtap/mcp-mandate/blob/main/SECURITY.md), never in a public issue.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/srkunaljagtap/mcp-mandate/blob/main/LICENSE-APACHE) or
[MIT license](https://github.com/srkunaljagtap/mcp-mandate/blob/main/LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
