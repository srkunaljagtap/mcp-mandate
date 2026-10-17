# rust-agent

A command-line coding assistant written in Rust and powered by Claude. It can
read and write files and run commands inside a project folder.

## Status

Early development: the workspace builds and prints its version. Nothing talks to
Claude yet.

## Build and run

Requires [rustup](https://rustup.rs). The exact Rust version is pinned in
`rust-toolchain.toml` and installed automatically on first build.

```sh
cargo run -p agent-cli                        # build and run the CLI
cargo test                                    # run all tests
cargo fmt --check                             # check formatting
cargo clippy --all-targets -- -D warnings     # lint, treating warnings as errors
```

## Layout

| Path | What it is |
|---|---|
| `crates/agent-core` | Library: Claude API client, message types, agent loop |
| `crates/agent-cli` | Binary: the `rust-agent` command you run |
