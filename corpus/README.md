# Attack corpus

Attacks on MCP sessions as data, so any MCP security tool can replay them.
mcp-mandate runs every case in CI (`crates/mcp-mandate-gate/tests/corpus.rs`):

- every **attack** must be stopped (blocked, hidden, redacted or dropped);
- every **benign** case must pass untouched (no false blocks);
- every **known gap** must still behave as described, so a fix is noticed
  and the case can become an attack that's stopped.

Each file is one class of attack:

| File | What it covers |
|---|---|
| `tool-poisoning.json` | Unapproved, changed ("rug pull") and look-alike tools, prompts, templates and instructions |
| `exfiltration.json` | Reading untrusted content, then sending data out |
| `secrets.json` | Secrets in what servers send, and in what clients send |
| `arguments.json` | Shell injection, oversized and malformed arguments, denied and held tools |
| `protocol.json` | Batches, junk, unknown methods, server requests, made-up and repeated responses |

## Format

```json
{
  "class": "secrets",
  "cases": [{
    "id": "aws-key-in-tool-result",
    "kind": "attack",
    "about": "What the attacker tries, and why it matters.",
    "policy": "TOML policy text (default: allow every tool)",
    "pinned": {"tools": [], "prompts": [], "resources": [], "resource_templates": [], "instructions": "..."},
    "skip_listing": false,
    "steps": [
      {"from": "client", "send": {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}, "expect": "forward"},
      {"from": "server", "send": {"jsonrpc": "2.0", "id": 1, "result": {}}, "expect": "modify",
       "absent": ["AKIAIOSFODNN7EXAMPLE"], "present": ["[REDACTED"]}
    ]
  }]
}
```

- `kind`: `attack`, `benign` or `known-gap`.
- `pinned`: what was approved. Unless `skip_listing` is true, the session
  first lists each pinned kind and the server answers with exactly what was
  pinned, so the case starts with everything approved and checked.
- `send` is a JSON-RPC message, or `raw` is text sent as is.
- `expect` is what the gate does with the message:
  - `forward`: passed on unchanged;
  - `modify`: passed on changed;
  - `block`: answered with an error instead;
  - `drop`: discarded.
- `absent` and `present` are text that must not or must appear in what
  comes out. `seen` is the names a list response shows after the gate.
- `gate` (default `a`) names which of the agent's servers a step goes
  through. Each server gets its own gate with the same policy and pins, and
  the gates share taint, as an agent's servers do.
- `credentials` are values the gate treats as secrets, as the HTTPS gateway
  does with the credentials it signs in to remote servers with.

The secrets in these files are made up, or are documented examples such as
AWS's `AKIAIOSFODNN7EXAMPLE`.
