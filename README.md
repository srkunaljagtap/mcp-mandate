# mcp-mandate

**Pin what you trust. Permit what you allow. Prove what happened.**

mcp-mandate is an open-source toolkit for the MCP servers your AI agents
(Claude Code, Cursor, your own) call. **Scout** reviews a server before you
trust it and drafts its policy. A hash-chained **audit log** records every
decision, so you can prove what happened. And the **gate** checks every tool
call deterministically before it reaches a server, so an agent that was
tricked by something it read can't act with your keys.

> **Status: experimental.** Interfaces may change, and it hasn't been
> audited. Don't rely on it for protection yet.

## How it works

Three parts. Scout reviews a server before you trust it, the gate checks
every call, and the audit log records what the gate decided. Scout and the
gate run at two speeds:

| | Gate | Scout |
|---|---|---|
| Runs on | Every MCP call, in line | New or changed servers, offline |
| Uses an LLM | Never | Optional, with your own API key |
| Can decide | Allow, block, hold | Only propose rules |
| When it fails | Closed (blocks), in `enforce` mode | Safe (no new rules) |

A policy starts in `observe` mode: the gate logs what it would block, hide
or redact and lets everything through. It blocks only once the policy says
`mode = "enforce"` (see [Modes](#whats-checked-today)).

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

## Install

**Prebuilt binaries** for Linux (x86_64 and arm64, glibc 2.35 or newer),
macOS (Intel and Apple silicon) and Windows (x86_64) are on the
[releases page](https://github.com/srkunaljagtap/mcp-mandate/releases).
Each release lists SHA-256 checksums in `SHA256SUMS`, and each archive has
a signed build attestation. Checked as below, the attestation proves the
archive was built by this repository's release workflow
(`.github/workflows/release.yml`) from that version's tag, on a
GitHub-hosted runner; with `--repo` alone, any workflow in the repository,
on any branch, would pass.

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify mcp-mandate-v0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo srkunaljagtap/mcp-mandate \
  --signer-workflow srkunaljagtap/mcp-mandate/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 --deny-self-hosted-runners
```

The Windows binary isn't code-signed yet. SmartScreen may say "Windows
protected your PC"; once you've checked the checksum and attestation,
choose **More info → Run anyway**. With Smart App Control on, Windows
blocks unsigned programs outright, including ones you build yourself, so
use mcp-mandate under WSL instead.

**From source**, with [rustup](https://rustup.rs):

```sh
cargo install --locked --git https://github.com/srkunaljagtap/mcp-mandate --tag v0.1.0 mcp-mandate
```

**Container image** (linux/amd64), for the [HTTPS gateway](#the-https-gateway):

```sh
docker run --rm -p 8443:8443 \
  -v "$PWD/config:/config:ro" -v mcp-mandate-audit:/audit \
  ghcr.io/srkunaljagtap/mcp-mandate:0.1.0 gate --config /config/gateway.toml
gh attestation verify oci://ghcr.io/srkunaljagtap/mcp-mandate:0.1.0 \
  --repo srkunaljagtap/mcp-mandate \
  --signer-workflow srkunaljagtap/mcp-mandate/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 --deny-self-hosted-runners
```

The image runs as a non-root user, with no shell. Mount the configuration
read-only, and point each policy's `[audit] path` into `/audit`, the one
folder that user can write. Inside the container, `listen` on
`0.0.0.0:8443`; the `-p` mapping decides who can reach it (behind a proxy
on the same host, `-p 127.0.0.1:8443:8443`). The image has no Node.js or
Python, so it isn't meant for `mcp-mandate run`.

`mcp-mandate pin` and `scout` write their files readable only by you (see
[Scout](#scout)). The image's user (uid 65532) isn't you, so on a Linux
host it can't read a pins file you mount as it is. You can either:

- let it read the pins files once you've checked they hold no secret
  (`chmod a+r config/*.pins.toml`, or `setfacl -m u:65532:r` for that user
  alone); or
- run the container as yourself: add `--user "$(id -u):$(id -g)"` and mount
  a folder you own at `/audit` instead of the volume
  (`-v "$PWD/audit:/audit"`), because the volume's folder belongs to the
  image's user.

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
Each entry shows the item's description (`text`) and everything else it
showed (`details`: title, parameters, annotations). Characters that show
as nothing or change how the text around them shows (Unicode's
default-ignorable and format characters, such as zero-width characters,
direction overrides, variation selectors and "tag" characters), and
control characters other than line breaks and tabs, are written as
escapes: `\u{…}` in `text` and `details`, and TOML's own `\uXXXX` in item
names and URIs, which still read back as the names the server sent. Pin an exact package *version* (`@1.0.0` above).
Without one, or with a tag or range such as `@latest` or `@^1.0.0`, `npx`
fetches the newest matching release on every run, so the code can change
while its descriptions don't, and mcp-mandate warns about it.

The pins file and Scout's draft name the server by its command. Anything in
the command that looks like a password or token is masked, and so is the
same text in mcp-mandate's logs, including the package named in the warning
about an unpinned version: the user name, password, query and fragment of
every URL, wherever it is in an argument (also in a package spec such as
`name@git+https://user:token@host/repo.git`), the value of `NAME=value`,
the values of options and headers such as `--api-key` or `Authorization:`,
and keys of known shapes. A value can have spaces, so it's masked up to its
closing quote if it opens one, or else up to the next option:
`--db-password=correct horse` and `Authorization: Bearer <token>` are
masked whole. When a client passes a value's words as separate arguments,
the masking follows the value into the next arguments, stopping at an
option, until it has one word for an option such as `--api-key` and two for
a header such as `Authorization:` (a scheme and a token), so
`Authorization:` `Bearer` `<token>` is masked however it's split. In a
script passed to a shell (`sh -c "API_KEY=… node server.js"`), that masks
the words after an unquoted value too. A secret with no recognizable shape in a plain argument
isn't caught, so pass secrets to servers through environment variables
instead. A remote server is named by its URL without its user name,
password, query or fragment, so a key in the URL's path is kept.

**If the pins file already exists**, `pin` stops with "the pins file already
exists; pass --force to replace it". That's on purpose: re-pinning trusts
whatever the server shows now, so it would quietly accept a tool that has
changed since you pinned it (a "rug pull").

- Already pinned it? Skip this step and carry on.
- Want to know whether the server has changed? Compare it with the existing
  pins without overwriting anything. Scout's report flags whatever isn't
  pinned or has changed:

  ```sh
  mcp-mandate scout --pins everything.pins.toml --out check.draft.toml -- npx -y @modelcontextprotocol/server-everything@1.0.0
  ```

  Scout won't overwrite an existing `check.draft.toml` either: pick a new
  name, or delete the old one first.
- Pass `--force` to `pin` only once you've read what changed and decided to
  trust it.

**2. Write a policy.** Start from [policies/example.toml](https://github.com/srkunaljagtap/mcp-mandate/blob/main/policies/example.toml).
Keep the policy and pins files where neither the agent nor a server can
write to them: whoever can edit them decides what the gate allows. A
folder such as `~/.config/mcp-mandate/` works, as long as your agent's own
file tools aren't allowed there. mcp-mandate warns when either file is
inside the folder the server runs in (unless that's your home folder or
`/`, where clients often start servers), or when other users can write to
the file or its folder. Group write access counts unless the group's id is
the owner's user id: on systems such as Fedora and Ubuntu, which give each
user a private group and make new files group-writable, that's a group only
you are in.

```toml
pins = "everything.pins.toml"

[[tools]]
match = "echo"
action = "allow"
```

This policy is in `observe` mode, the default: the gate lets everything
through and logs (with a warning each time it starts) what it would have
blocked, hidden or redacted. Try it on real traffic, read the log, and
once it blocks only what you expect, set `mode = "enforce"` at the top
(the example policy and Scout's drafts already have a `mode` line to
change). Until then nothing is protected.

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
was hidden or blocked. Control characters in what mcp-mandate logs (a tool
name, a server's error) are escaped, so they can't rewrite your terminal or
fake a log line. A local server's own stderr goes to the same place
unchanged, so what it writes there can still do both.

**4. Check the record.** Every decision is also written to an audit log
next to the policy (`policy.toml` → `policy.audit.jsonl`):

```sh
mcp-mandate audit verify policy.audit.jsonl
```

## What's checked today

- **Pinning.** Tools, prompts, resources, resource templates and the server's
  instructions are compared with their pins. Anything changed since approval
  (a "rug pull") or never approved is hidden from lists, and calls to it are
  blocked. A server with no pins file gets nothing through. A resource read
  must name a pinned resource or fit a pinned template: `{name}` fills one
  path segment and `{+path}` several. No variable (alone, next to another,
  next to a dot, or after literal text such as `?path=`) can make a `.` or
  `..` segment, plain or percent-encoded, that the template's own text
  doesn't have, and no variable can hold a `.` or `..` between query
  delimiters (`&`, `;`, `=`): `?path=&path=../secret.txt` is refused,
  because a query parser reads it as a second `path`. No variable can hold
  a space or another whitespace or control character unencoded, ASCII or
  not (a tab, a no-break space, NEL), because URL parsers drop or trim
  some of those (`.<tab>.` would be read as `..`), and so do servers that
  trim text; percent-encode them (`%20`). A read refused for one of these
  reasons says so and names the template it otherwise fits. Other template
  operators match nothing.
- **Policy.** Each tool is allowed, held or denied (default: denied). When
  several rules match, the most restrictive wins. Denied tools are hidden
  from the model. A rule's `match` is a glob on the whole tool name (`*`,
  `?`, `[abc]`, `{a,b}`). Matching is case-sensitive and works the same on
  every platform: `\` makes the next character literal (`run\*` matches
  only `run*`). A `**` right before or after a `\` (as in `**\*`) is
  refused when the policy loads, because the glob library would read that
  `\` as a path separator on Windows; write `*` there instead.
- **Arguments.** Size limits, the tool's own JSON Schema, and shell
  metacharacters in the arguments you name (`no_shell_metacharacters`).
  That last check refuses `;`, `&`, `|`, `$`, `` ` ``, `<`, `>`, `(`, `)`,
  `{`, `}`, newlines and NUL in the string values of those arguments,
  strings nested inside them (in arrays or objects) included, which stops
  command chaining and substitution in POSIX shells. Only arguments named
  at the top level are checked: an argument of the same name nested inside
  another one isn't. It doesn't stop option injection (`--upload-pack=…`,
  `-o ProxyCommand=…`) or Windows `cmd.exe` metacharacters (`%`, `^`, `!`).
- **Requests from the server.** `sampling/createMessage` (the server asks the
  client's model to write) and `elicitation/create` (the server asks you a
  question) are denied unless the policy allows them.
- **Unknown requests** are denied, so a new protocol feature can't slip
  through unchecked.
- **Messages the gate can't check reliably are dropped:** batches, repeated
  keys, a request without a real id, a message that is both a request and a
  response, a method name over 256 bytes, and a message that would take
  more memory to check than 1,000,000 numbers do (about 64 MB). Objects
  cost far more than numbers, so the limit comes sooner the more objects a
  message holds: at about 75,000 objects of one member, 40,000 of five, or
  20,000 of fifteen. A long text or a base64 image counts as one value. A
  message too large to check that is a request, or the answer to a request
  that's waiting, is answered with an error saying so instead (a tool call
  as a tool error the model can read), so nobody waits for an answer that
  won't come.
- **Taint.** Once a tool that reads untrusted content answers (a web
  fetch, an inbox, anything a stranger could have written), a resource is
  read, or a prompt is fetched (only a prompt's listing is pinned, not the
  messages it returns), the session is tainted for the rest of its life.
  Tools that can send data out are then held, so a model hijacked by what
  it read can't complete an exfiltration. Which tools are which comes from
  your policy's `reads_untrusted` and `sends_out` labels, or else the
  tool's pinned `openWorldHint`; a tool that says nothing counts as both.
  (`[taint] resources_are_untrusted` and `prompts_are_untrusted` turn off
  the other two.) Only tools are held. Once the session is tainted, reads
  through an approved resource template, and prompt and completion
  arguments, still reach the server. A template that makes the server
  fetch an address the model chooses (such as `https://{+url}`) can carry
  data out in its URI, so approve one only for a server you'd let fetch
  anything.
- **Taint is shared across an agent's servers.** Reading a web page through
  one server holds sending email through another. Every `mcp-mandate run`
  started by the same agent process shares one taint for as long as that
  process runs. After upgrading from 0.1.0, restart the agent (your MCP
  client): on Linux, 0.1.0 named an agent's taint file differently (unless
  `MCP_MANDATE_AGENT` names the agent), so a server still running 0.1.0
  and one started after the upgrade don't share taint. The taint is kept in
  a file only you can read: in `$XDG_RUNTIME_DIR/mcp-mandate` or
  `~/.local/state/mcp-mandate` on Linux and macOS (failing both, a folder
  in the temporary folder), and in `%LOCALAPPDATA%\mcp-mandate\taint` on
  Windows. Before every write, mcp-mandate checks again that the folder is
  yours and closed to others (making it again if something removed it),
  and it never writes through a link, so another user can't redirect the
  file, even in the temporary folder. Each server takes the first of these
  folders it can use, so all of an agent's servers must see the same
  `XDG_RUNTIME_DIR`; mcp-mandate warns when it has to fall back to a later
  folder, because servers using another folder don't share with it. While
  a server that has seen the taint runs, it checks the file every minute,
  and at most once a second while messages pass through it: it puts the
  file back if something removed it (a cleaner of temporary files, say)
  and touches it so it doesn't look old. If the file can't be written when
  an answer taints a server's session (a full disk, say), that answer
  doesn't reach the client: the request gets an error saying the taint
  couldn't be shared with the agent's other servers, and the audit log
  records it. A sampling request from the server is refused the same way.
  Observe mode only warns. The server itself stays tainted and keeps
  retrying, with warnings; once a write succeeds, answers that taint it
  pass again. If the folder itself is removed while the agent runs and
  can't be made again (`$XDG_RUNTIME_DIR` is removed when you log out,
  even if the agent goes on running in `tmux` or `screen`), the agent's
  servers that haven't seen the taint yet are no longer held. When
  mcp-mandate is started through a shell or wrapper, set
  `MCP_MANDATE_AGENT` to the same name in each server's configuration so
  they're still counted as one agent. A named agent's taint lasts while any
  server with that name is running; once they have all stopped, the next
  one starts clean. If no private folder can be set up, or the agent can't
  be identified, each server keeps its own taint and logs a warning. On the
  HTTPS gateway, taint is shared across every session of the same caller.
- **Secrets.** API keys, tokens, private keys, and password or secret
  assignments (`DB_PASSWORD=…`, `"password": "…"`,
  `AWS_SECRET_ACCESS_KEY=…`) are replaced with `[REDACTED: kind]` in
  everything the server sends. Values in quotes are redacted whole, spaces
  included, and so are quoted values inside JSON printed as text
  (`\"password\":\"…\"`). Prose in quotes counts too: a request that writes
  `PASSWORD_PROMPT = "Enter your password"` into a file is blocked unless
  the tool's rule sets `allow_secrets = true`, and the same text from a
  server is redacted. Under a field named like a secret (`api_keys`,
  `password`), every string of 8 or more characters is redacted, including
  each one in a list. A resource's base64 `blob` is decoded and checked
  whatever its size, including base64 broken into lines, without padding or
  URL-safe; base64 image and audio data isn't. A request whose tool or prompt
  arguments, resource URI or completion text carries a secret is blocked
  (unless the tool's rule sets `allow_secrets = true`), and so is a sampling
  or elicitation answer. Secrets encoded some other way (base64 in text,
  hex, split across messages) pass. Add your own patterns under
  `[[secrets.patterns]]`. A pattern that can match empty or very short
  text (under 5 bytes, such as `token|`, `[a-z]*`, or `[A-Za-z0-9]` without
  its count) is refused when the policy loads, because it would match
  ordinary text everywhere. Personal data such as emails isn't redacted yet.
- **Audit log.** Every message that crosses the gate is recorded with what
  the gate did and why, in a hash chain that shows any later edit. See
  [The audit log](#the-audit-log).
- **Modes.** `observe` (the default) logs what would be blocked, hidden or
  redacted and lets it through, for trying a policy on real traffic;
  mcp-mandate warns every time it starts a server in `observe` mode.
  `enforce` blocks, and a policy must say `mode = "enforce"` to get it.
  What the gate blocks, hides, holds, redacts or drops (all of the above)
  it does only in `enforce` mode; the HTTPS gateway's token checks and
  limits, and its redaction of its own credential, apply in both. In `observe` mode, messages the gate can't read
  reliably pass through unchanged too, each with a "would drop" warning
  and an audit entry saying what `enforce` mode would have done: anything
  that isn't JSON-RPC 2.0, batches, and the repeated keys, requests
  without a real id, messages that are both a request and a response, long
  method names and oversized messages listed above. In `enforce` mode
  they're dropped, and a request dropped this way gets no answer (unless
  it's too large to check: see above).

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
[policies/gateway.example.toml](https://github.com/srkunaljagtap/mcp-mandate/blob/main/policies/gateway.example.toml).

- **Who's calling.** Every request needs a bearer token from your OIDC
  identity provider. The gateway checks:
  - the signature, against the provider's published keys (asymmetric
    algorithms only, never shared-secret `HS*`, and the key's type must
    match the token's algorithm);
  - the issuer;
  - the audience (the gateway, or the server being used);
  - the subject, the expiry and the not-before time.

  Set `audience` to an API or resource identifier, never to a client id:
  the token's type isn't checked, so with a client id an ID token would
  pass as an access token. If the provider can't be reached, its keys are
  used for at most 24 hours after they were fetched.

  Any token that passes may use every configured server, so decide who can
  get one in your identity provider. A missing or bad token gets `401` with
  a link to the gateway's OAuth metadata (RFC 9728), which MCP clients use
  to find your provider and sign in.
- **The server never sees your token.** The gateway removes it and signs in
  with its own credential for that one server: a secret from an environment
  variable or file (never the config file itself), or short-lived OAuth
  client-credential tokens. A credential sent in a header must be ASCII.
  Only the headers MCP needs are passed on, and redirects aren't followed,
  so a server can't bounce the credential elsewhere. A server that echoes
  the credential back gets it redacted, in either mode, in replies and
  event streams alike (a message the gate can't read that holds it is
  dropped): the whole header value, the token after its scheme, the client
  secret, and every client-credential token that may still be valid: until
  the expiry the token endpoint gave (`expires_in`), or for a day when it
  gave none, the 16 newest at most. An event's id isn't a message, so the gate
  doesn't check it: an id holding the credential, or anything else the
  policy takes for a secret, is dropped.
- **Sessions** belong to the caller who opened them, and each has its own
  gate: its own taint, its own audit session. The server's session id is
  never shown to the client. Sessions unused for 30 minutes close, unless
  a request is still in flight. Closing a session also ends its event
  streams and the server's session.
- **Every message**, including streamed (SSE) ones, goes through the gate
  exactly as with `mcp-mandate run`. Each session's audit log entries name
  the caller (`sub`) and their OAuth client.
- **HTTPS:** mcp-mandate serves TLS itself with your certificate, or plain
  HTTP behind a proxy that handles TLS (`terminated_by_proxy = true`). Plain
  HTTP is otherwise allowed only on localhost. Behind a proxy, `listen` on
  the address the proxy connects to, not `0.0.0.0`: anything that can reach
  the port directly skips the proxy, and tokens cross that hop unencrypted.
  Servers must use `https://` unless they're on localhost.
- **Limits:** at most 1024 connections at once; 30 seconds to send a
  request's headers, then 30 seconds to send its body (at most 4 MB), which
  is read only once the token checks out; 32 open sessions per caller; and
  per session, 16 requests in flight (an answer streamed back counts until
  its stream ends), 16 messages being read or, for the client's answers and
  notifications, passed on (these never count as requests, so a client can
  always answer or cancel what's in flight), 4 event streams, and 8 of the
  gate's refusals of the server's own requests being sent at once (a server
  sending more requests waits until one is taken). Across all callers,
  messages are read and checked as many at a time as the machine has CPUs;
  the rest wait their turn. Nothing outlives the token it came with: an
  event stream ends when the token it was opened with expires, and a
  request still waiting for its answer when the token it was sent with
  expires is given up on (its event stream ends, or the client gets
  `504`); clients carry on with a fresh token. A reply or event stream
  from the server that sends nothing for 5 minutes is ended too, so a call
  that runs longer needs the server to send progress notifications or
  keep-alive comments meanwhile. The connection cap is shared by everyone
  who can reach the port, so put a public gateway behind a proxy that
  limits connections and requests per client.

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
  - invisible or direction-changing characters, terminal control
    characters (escape sequences, or a carriage return that overwrites a
    line), and encoded blobs;
  - arguments that take a command line.
- **The draft** is built by risk:
  - tools whose annotations say read-only and closed-world are allowed;
  - tools that can change things or reach the outside world are held, with
    taint labels set from their annotations;
  - a medium finding holds a tool, and a high finding denies it;
  - two tools listed under one name are both denied, and so are a tool
    with a `\` in its name and any tool whose name differs from another's
    only in `/` and `\`, out of caution: such names are easy to confuse.

  The annotations are the server's own claims. Where they say closed-world,
  the draft leaves the taint labels out and says so in a comment, rather
  than writing `false` as if it were checked.

  Every rule names a tool exactly (never a pattern; a `\` in a name is
  escaped), and its comments say why. With `--pins`, the draft names the
  pins file and the report flags anything that isn't pinned or has changed.
- **Claude's review** (`--llm`) is a second opinion on what patterns can't
  judge, such as a description that doesn't match the tool's schema.
  - It's off unless you pass `--llm`, and it sends the server's definitions
    to the Claude API with your own key (`ANTHROPIC_API_KEY`, or a `.env`
    file in the current folder; see `.env.example`).
  - The key is removed from the environment the reviewed server inherits,
    wherever it came from.
  - It can only make the draft stricter, never looser: the descriptions it
    reads were written by the server and may try to talk it into "safe".
  - If it fails or declines (a server can cause that on purpose), the draft
    holds every tool.
  - Building with `cargo build --no-default-features` leaves it out.

Scout exits 0 whenever it ran; the findings are in the report.

`scout` and `pin` start the server to see what it offers, so it runs with
your permissions. For a server you don't trust yet, run them in a container
or sandbox. Neither replaces an existing file unless you pass `--force`.
On Linux and macOS, only you can read or write the files they write. Both
name the server by its command, so a secret in it that masking misses (see
[Quick start](#quick-start)) stays private. To use them with the container
image, see [Install](#install). The listing is an error rather than
recorded in part if a server:

- lists more than 10,000 tools, prompts, resources or resource templates;
- spreads a list over more than 100 pages;
- sends a reply too large for the gate to check (see [What's checked
  today](#whats-checked-today)); or
- has lists that together would take more than about 256 MB of memory.

A reply the gate would drop for another reason (it isn't JSON-RPC 2.0, or
it repeats a key) doesn't count as an answer. A server that doesn't list
its resource templates is recorded as having none, with a warning, and the
gate hides any it has.

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
command. For a local server the command is recorded only as its program
name and a hash. For a remote server, the session's first entry records
its URL without its user name, password, query or fragment; a key in the
URL's path is recorded with it.

```sh
# What was blocked, and why
jq -c 'select(.verdict == "block") | {time, item, reason}' policy.audit.jsonl
```

- **Where:** next to the policy, named after it (`policy.toml` →
  `policy.audit.jsonl`), or wherever `[audit] path` says. Several sessions
  can share one log. On Linux and macOS it's created readable only by you,
  and never opened through a symlink. If your policies are in git, add
  `*.audit.jsonl` to `.gitignore`.
- **If it can't be written** (a full disk, say, or another process holding
  its lock for more than 2 seconds), nothing passes: requests are answered
  with an error saying the audit log can't be written, until it can be
  again. Once one write has waited 2 seconds for the lock, the ones after
  it fail at once until a write gets it, so sessions sharing the log don't
  each wait in turn. A gate stops writing to its log until it's restarted
  if it finds the log deleted, replaced by another file (it compares the
  file's device and inode, or on Windows its volume serial number and file
  index), or cut short before the last entry the gate wrote or read, even
  if the log has grown back past that point since. It stays stopped even
  once a new file appears at the path, so entries can't disappear
  unnoticed. In `observe` mode, all of this only warns. A log that can't be
  opened, or whose last line is damaged, stops `mcp-mandate run` from
  starting, in either mode.
- **Rotating it:** stop everything that writes to the log, run
  `mcp-mandate audit verify` on it and save the head hash it prints, move
  it away, then start again. A new log begins at the same path. Logs
  aren't rotated automatically and grow until you do this.
- **Tamper evidence.** Each line holds the hash of its own bytes and of the
  line before it, so editing, removing, adding or reordering lines breaks
  the chain, and `mcp-mandate audit verify` names the first broken line.
- **A damaged log stops the gate.** If the last line is cut off (a crash, or
  another process appending to the file), every gate sharing the log stops
  passing messages until it's repaired (in `observe` mode, it warns), and
  none can start. That's the fail-closed design, but it also means anything
  that can write the log can stop your servers.
  Each session's first entry records the hash of the policy exactly as
  the gate read it (`policy_sha256`), so a policy changed behind your back
  shows up there.

A chain can't show entries cut off its end, or a log rewritten from
scratch with fresh hashes. To catch those, save the head hash that
`verify` prints somewhere your agent's account can't write, and check
against it later:

```sh
mcp-mandate audit verify policy.audit.jsonl --anchor <saved head>
```

## How it's tested

- **Attack corpus.** [corpus/](https://github.com/srkunaljagtap/mcp-mandate/tree/main/corpus) holds attacks as plain JSON that
  any MCP security tool can replay: poisoned and changed tools, exfiltration
  after untrusted reads, secrets in both directions, shell injection, and
  protocol abuse. Every pull request runs all of them through the gate.
  - Every attack must be stopped: blocked, hidden, redacted or dropped (82
    today).
  - Every benign case must pass untouched, so normal use isn't blocked (19
    today).
  - Every known gap must still behave as documented (below), so a fix gets
    noticed.
- **Fuzzing.** Property tests feed random input to every parser (messages,
  framing, event streams, policy, pins and audit log files) on every pull
  request. They also check that a secret planted anywhere in a server's
  message never reaches the client. Coverage-guided fuzzing
  ([fuzz/](https://github.com/srkunaljagtap/mcp-mandate/tree/main/fuzz), cargo-fuzz) runs each parser weekly.
- **Latency.** CI fails if the gate adds more than 5 ms per message at the
  median, measured with every check on and the audit log being written.
  Typically it adds about 30 µs.
- **Real processes and servers.** End-to-end tests run the binary against
  scripted servers, a fake identity provider and fake remote servers. On
  Linux, macOS and Windows, stopping a server also stops everything it
  started: its process group, or a Windows Job Object. A server that tries
  to escape can: a process that leaves its group (`setsid`, daemonizing),
  or that it has started outside the Job Object (through WMI or the Task
  Scheduler), keeps running. If mcp-mandate itself is killed with `SIGKILL`,
  the server's group is left running.

**Known gaps** (each proven by a corpus case):

- A tool whose annotations falsely claim it's closed-world doesn't taint the
  session unless the policy labels it `reads_untrusted = true`. Scout's
  `secret-access` and `send-to-address` checks help find such tools.
- A secret with no recognizable shape passes. Add your own shapes under
  `[[secrets.patterns]]`.
- A secret encoded in base64 image or audio data from a server passes (as
  would a picture of one); only text and resource blobs are checked.
- An unquoted value with spaces (`password: my long passphrase` in YAML) is
  redacted only up to its first space, and missed when its first word is
  shorter than 8 characters. Quoted values are redacted whole. Matching to
  the end of the line would also redact prose such as `Password: must be
  12 characters`.
- Once the session is tainted, reads through an approved resource template,
  and prompt and completion arguments, still reach the server; only tools
  are held. A template that makes the server fetch an address the model
  chooses can carry data out in its URI.

## What it doesn't do

- **It only sees MCP traffic routed through it.** Your agent's built-in tools
  (shell commands, file edits, web fetches) and any MCP server configured
  directly in the client bypass the gate entirely. Use your agent's own
  permission settings for those, and route every MCP server through
  mcp-mandate.
- **It guards MCP messages, not the server process.** A local server runs
  with your operating-system permissions and could read files directly
  without making an MCP call. Use OS sandboxing to contain that.
- **Its own files are part of what you have to protect.** The policy, pins
  file and audit log *are* the gate's configuration and record. Anything
  that can write them (a local server, or your agent's file tools) can loosen
  the policy, approve a new tool, or cut the log. Keep them where neither
  can write (see the [quick start](#quick-start)).
- **It doesn't replace** your identity provider or the servers' own
  authentication.
- **Behind the gateway, a server sees the gateway, not you.** Every caller
  acts with the gateway's credential for that server. Per-user credentials
  (token exchange) come later.
- **The gateway keeps sessions in memory.** Run one instance, or send each
  client to the same one (sticky sessions). A restart ends every session.
- **No AI decides what to block.** The gate is plain rules; Scout's LLM
  review is optional and only drafts rules for you to approve.
- **Known gaps** found by the attack corpus are listed in
  [How it's tested](#how-its-tested).

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
| `corpus/` | The attack corpus: attacks, benign cases and known gaps, as JSON |
| `fuzz/` | Coverage-guided fuzz targets (cargo-fuzz, nightly) |
| `Dockerfile` | The container image, built from source |
| `.github/workflows/` | CI on every pull request, weekly fuzzing, and releases on version tags |

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
