# Install

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
gh attestation verify mcp-mandate-v0.2.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo srkunaljagtap/mcp-mandate \
  --signer-workflow srkunaljagtap/mcp-mandate/.github/workflows/release.yml \
  --source-ref refs/tags/v0.2.0 --deny-self-hosted-runners
```

The Windows binary isn't code-signed yet. SmartScreen may say "Windows
protected your PC"; once you've checked the checksum and attestation,
choose **More info → Run anyway**. With Smart App Control on, Windows
blocks unsigned programs outright, including ones you build yourself, so
use mcp-mandate under WSL instead.

**From source**, with [rustup](https://rustup.rs):

```sh
cargo install --locked --git https://github.com/srkunaljagtap/mcp-mandate --tag v0.2.0 mcp-mandate
```

**Container image** (linux/amd64), for the [HTTPS gateway](gateway.md):

```sh
docker run --rm -p 8443:8443 \
  -v "$PWD/config:/config:ro" -v mcp-mandate-audit:/audit \
  ghcr.io/srkunaljagtap/mcp-mandate:0.2.0 gate --config /config/gateway.toml
gh attestation verify oci://ghcr.io/srkunaljagtap/mcp-mandate:0.2.0 \
  --repo srkunaljagtap/mcp-mandate \
  --signer-workflow srkunaljagtap/mcp-mandate/.github/workflows/release.yml \
  --source-ref refs/tags/v0.2.0 --deny-self-hosted-runners
```

The image runs as a non-root user, with no shell. Mount the configuration
read-only, and point each policy's `[audit] path` into `/audit`, the one
folder that user can write. Inside the container, `listen` on
`0.0.0.0:8443`; the `-p` mapping decides who can reach it (behind a proxy
on the same host, `-p 127.0.0.1:8443:8443`). The image has no Node.js or
Python, so it isn't meant for `mcp-mandate run`.

`mcp-mandate pin` and `scout` write their files readable only by you (see
[Scout](scout.md)). The image's user (uid 65532) isn't you, so on a Linux
host it can't read a pins file you mount as it is. You can either:

- let it read the pins files once you've checked they hold no secret
  (`chmod a+r config/*.pins.toml`, or `setfacl -m u:65532:r` for that user
  alone); or
- run the container as yourself: add `--user "$(id -u):$(id -g)"` and mount
  a folder you own at `/audit` instead of the volume
  (`-v "$PWD/audit:/audit"`), because the volume's folder belongs to the
  image's user.
