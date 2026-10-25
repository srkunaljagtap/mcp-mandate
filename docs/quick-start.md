# Quick start

**0. Review the server (optional).** [Scout](scout.md) looks for poisoned
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
the values of options and headers such as `--api-key`, `--token:…`,
`/token …`, `/p:Password=…`, npm's `--//host/:_authToken=…` or
`Authorization:`, the whole value of an option that sets a property named
like a secret (MSBuild's `/p:Configuration=Release;Password=…`), and keys
of known shapes. A value can have spaces, so it's masked up to its
closing quote if it opens one, or else up to the next option:
`--db-password=correct horse` and `Authorization: Bearer <token>` are
masked whole. When a client passes a value's words as separate arguments,
the masking follows the value into the next arguments, stopping at an
option, until it has one word for an option such as `--api-key` and two for
a header such as `Authorization:` (a scheme and a token), so
`Authorization:` `Bearer` `<token>` is masked however it's split. In a
script passed to a shell (`sh -c "API_KEY=… node server.js"`), that masks
the words after an unquoted value too. A secret with no recognizable shape
in a plain argument isn't caught, so pass secrets to servers through
environment variables instead. A remote server is named by its URL without
its user name, password, query or fragment, so a key in the URL's path is
kept.

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
`/`, where clients often start servers). On Linux and macOS it also warns
when the file or its folder belongs to another user (anyone but you and
root), or when other users can write to the file or its folder. Group
write access counts unless the group is your own private group (named
after you, with the same id as your user id, and no other members): on
systems such as Fedora and Ubuntu, which give each user a private group and
make new files group-writable, that's a group only you are in. It isn't
counted as yours if another user has it as their primary group, or another
group has the same id; to check that, mcp-mandate reads the local user and
group lists (`/etc/passwd` and `/etc/group`), so users and groups that
only a directory service such as LDAP lists aren't checked for this. Only
the permission bits are read, not ACLs, and Windows permissions aren't
checked.

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
