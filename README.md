# rust-agent

A command-line coding assistant written in Rust and powered by Claude. It can
read and write files and run commands inside a project folder.

## Status

Early development: sends one prompt to Claude and prints the reply. Tool use
and multi-turn conversations aren't implemented yet.

## Build and run

Requires [rustup](https://rustup.rs). The exact Rust version is pinned in
`rust-toolchain.toml` and installed automatically on first build. On Windows
you also need the Visual Studio C++ build tools for the linker.

Put your Anthropic API key in a `.env` file (it's gitignored):

```sh
cp .env.example .env    # then paste your key after ANTHROPIC_API_KEY=
```

```sh
cargo run -q -p agent-cli -- "Explain Rust ownership in two sentences"
cargo test                                    # run all tests (no API key needed)
cargo fmt --check                             # check formatting
cargo clippy --all-targets -- -D warnings     # lint, treating warnings as errors
```

## Layout

| Path | What it is |
|---|---|
| `crates/agent-core` | Library: Claude API client, message types, agent loop |
| `crates/agent-cli` | Binary: the `rust-agent` command you run |
