# What's checked

## For each tool call

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

All nine steps work today: step 1 on the [HTTPS gateway](gateway.md)
(local servers run as you), and step 6 as a credential of the gateway's own
for each server (not yet one per user). Step 8 redacts secrets, not yet
other personal data.

## The checks

- **Pinning.** Tools, prompts, resources, resource templates and the server's
  instructions are compared with their pins. Anything changed since approval
  (a "rug pull") or never approved is hidden from lists, and calls to it are
  blocked. A server with no pins file gets nothing through. A resource read
  must name a pinned resource or fit a pinned template: `{name}` fills one
  path segment and `{+path}` several. No variable (alone, next to another,
  next to a dot, or after literal text such as `?path=`) can make a `.` or
  `..` segment that the template's own text doesn't have, and no variable
  can hold a `.` or `..` between query delimiters (`&`, `;`, `=`):
  `?path=&path=../secret.txt` is refused, because a query parser reads it
  as a second `path`. No variable can start with `/` or `\`, at its start
  or after a query delimiter (`?path=x&path=/etc/passwd`), and no segment
  of a variable can start with a drive such as `C:` (`docs/C:/Windows`),
  because a server that joins it to a folder would read that path instead.
  Nor can the variables make an empty segment (`//`) in the path, or a
  segment that starts with a drive, that the template's own text doesn't
  have. Right after `file://` a variable names the whole location and may
  start anywhere (`file:///etc/passwd`), and where a file URI's path
  starts (`file:///{+path}`, `file://localhost/{+path}`) it may start with
  a drive (`file:///C:/Users/u/notes.txt`). Only `http`, `https`, `ws`,
  `wss` and `file` URIs have a host, and no variable can change the host a
  template names. Right after the host (`https://api.example.com{+path}`)
  a variable must be empty or start with the path's own `/`, after which
  the rules above apply (a file URI may have a drive there), so
  `@evil.example/x` and `.evil.example/x` are refused. Inside a host, with
  more of it after (`https://{tenant}.example.com`), a variable can hold
  only letters and digits (`münchen` too), `-`, `.` and `_`, because URL
  parsers differ on what else ends a host (Node's legacy `url.parse` ends
  it at `;`, `|` or `%`), so percent-encoded host text is refused there,
  and the host must keep to DNS's lengths (253 characters in all, 63 to a
  label). After the host's `:` a variable must be a port number. A
  variable that is the whole host, alone or with only a port after it
  (`https://{host}/api`, `http://{host}:{port}/mcp`), lets the model
  choose it, an IPv6 address such as `[::1]` too. Other schemes have no
  host: `docs://page-{+p}` refuses `docs://page-/etc/passwd`. All of these
  rules also apply to percent-encoded text, with spaces and invisible
  characters taken off each segment's ends (`%20..` counts as `..`), and
  `\` separates segments just as `/` does. No variable can hold
  whitespace, a control character or U+FEFF unencoded, ASCII or not (a
  tab, a no-break space, NEL), because URL parsers drop or trim some of
  those (`.<tab>.` would be read as `..`), and so do servers that trim
  text; percent-encode them (`%20`). Other invisible characters, such as
  those inside emoji or the zero-width non-joiner in Persian, are fine in
  names. A read refused for one of these reasons says so and names the
  template it otherwise fits. Other template operators match nothing.
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
  an answer taints a server's session (a full disk, say), or it was removed
  and can't be put back, that answer doesn't reach the client: the request
  gets an error saying the taint
  couldn't be shared with the agent's other servers, and the audit log
  records it. A sampling request from the server is refused the same way.
  Observe mode only warns. The server itself stays tainted and keeps
  retrying, with warnings; once a write succeeds, answers that taint it
  pass again. If the folder itself is removed while the agent runs and
  can't be made again (`$XDG_RUNTIME_DIR` is removed when you log out,
  even if the agent goes on running in `tmux` or `screen`), the agent's
  servers that haven't seen the taint yet are no longer held, and a
  tainted server withholds every answer that would taint it until the file
  can be written again. When mcp-mandate is started through a shell or
  wrapper, set `MCP_MANDATE_AGENT` to the same name in each server's
  configuration so they're still counted as one agent. A named agent's
  taint lasts while any server with that name is running; once they have
  all stopped, the next one starts clean. Each running server holds a lock
  on a file next to the taint file (`taint-named-<name>.lock`) and touches
  it so it doesn't look old, so a cleaner doesn't make a running agent look
  stopped. On Windows that file can't be removed while a server holds it.
  On Linux and macOS each running server checks it every minute, and
  whenever it checks the taint file; if it was removed or replaced (with
  its folder when you log out, say), the server makes it again if needed
  and locks it as soon as the folder can be made again. A server started
  before then still clears the taint, and the servers that have seen it
  put it back. If no private folder can be set up, or the agent can't
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
  [The audit log](audit-log.md).
- **Modes.** `observe` (the default) logs what would be blocked, hidden or
  redacted and lets it through, for trying a policy on real traffic;
  mcp-mandate warns every time it starts a server in `observe` mode.
  `enforce` blocks, and a policy must say `mode = "enforce"` to get it.
  What the gate blocks, hides, holds, redacts or drops (all of the above)
  it does only in `enforce` mode; the HTTPS gateway's token checks and
  limits, and its redaction of its own credential, apply in both. In
  `observe` mode, messages the gate can't read reliably pass through
  unchanged too, each with a "would drop" warning and an audit entry
  saying what `enforce` mode would have done: anything that isn't JSON-RPC
  2.0, batches, and the repeated keys, requests without a real id,
  messages that are both a request and a response, long method names and
  oversized messages listed above. In `enforce` mode they're dropped, and
  a request dropped this way gets no answer (unless it's too large to
  check: see above). `observe` mode still keeps track of taint, so servers
  of the same agent that enforce are still held: whatever it passes that
  could taint the session does (an answer it can't read or can't match to
  its request, a batch, a request it would have blocked and its answer, a
  server's sampling request, even one it can't read that a lenient client
  would still take for one), and a tool call whose tool can't be read
  counts as one that reads untrusted content. A server message that can't
  be parsed as JSON at all taints the session if its text names
  `sampling/createMessage` anywhere.

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
- **Its own files are part of what you have to protect.** The policy, pins
  file and audit log *are* the gate's configuration and record. Anything
  that can write them (a local server, or your agent's file tools) can loosen
  the policy, approve a new tool, or cut the log. Keep them where neither
  can write (see the [quick start](quick-start.md)).
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
  [How it's tested](testing.md).
