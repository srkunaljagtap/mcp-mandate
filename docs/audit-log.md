# The audit log

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
  its lock for more than 2 seconds), nothing passes: requests, and answers
  the other side is waiting for, are answered with an error saying the
  audit log can't be written (messages too large to check included), until
  it can be again. Once one write has waited 2 seconds for the lock, the ones after
  it fail at once until a write gets it, so sessions sharing the log don't
  each wait in turn. A gate stops writing to its log until it's restarted
  if it finds the log deleted, replaced by another file (it compares the
  file's device and inode, or on Windows its volume serial number and file
  index), or cut short before the last entry the gate wrote or read, or
  that entry changed, even if the log has since grown back to the same
  length or past it. It stays stopped even
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
