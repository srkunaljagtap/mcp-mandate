# Scout

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
[Quick start](quick-start.md)) stays private. To use them with the container
image, see [Install](install.md). The listing is an error rather than
recorded in part if a server:

- lists more than 10,000 tools, prompts, resources or resource templates;
- spreads a list over more than 100 pages;
- sends a reply too large for the gate to check (see
  [What's checked](checks.md)); or
- has lists that together would take more than about 256 MB of memory.

A reply the gate would drop for another reason (it isn't JSON-RPC 2.0, or
it repeats a key) doesn't count as an answer. A server that doesn't list
its resource templates is recorded as having none, with a warning, and the
gate hides any it has.
