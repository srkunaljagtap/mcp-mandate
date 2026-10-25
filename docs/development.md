# Development

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
| `docs/` | The documentation: install, quick start, what's checked, the HTTPS gateway, Scout, the audit log, testing and development |
| `Dockerfile` | The container image, built from source |
| `.github/workflows/` | CI on every pull request, weekly fuzzing, and releases on version tags |
