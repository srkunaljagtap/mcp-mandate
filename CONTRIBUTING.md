# Contributing to mcp-mandate

Thanks for helping. Security tools earn trust by being easy to inspect, so
small, well-explained changes are the most welcome kind.

## Ways to help without writing Rust

- **Policies:** policy packs (TOML) for popular MCP servers will live in
  `policies/`.
- **Attacks:** add a malicious tool description or call sequence to
  `corpus/`. CI fails until a rule stops it, and every release is tested
  against the whole corpus.

Both directories arrive with the features that use them.

## Development

1. Install [rustup](https://rustup.rs). The pinned toolchain in
   `rust-toolchain.toml` installs itself on the first build.
2. Before opening a pull request, run:

   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo deny check
   ```

3. Keep one change per pull request and explain why it's needed. Pull
   requests are squash-merged once CI passes.

Never print to stdout outside the protocol path: in stdio mode, stdout
carries MCP traffic and a stray line breaks the client. Log to stderr.

## Security issues

Don't open public issues for vulnerabilities. Follow
[SECURITY.md](SECURITY.md) instead.

## License

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the Apache-2.0
license, shall be dual licensed under MIT OR Apache-2.0, without any
additional terms or conditions.
