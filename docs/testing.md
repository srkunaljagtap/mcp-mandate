# How it's tested

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
