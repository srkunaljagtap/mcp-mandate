# The mcp-mandate container image, mainly for the HTTPS gateway
# (`mcp-mandate gate`). Built from source; the runtime image has no shell or
# package manager and runs as a non-root user.
#
#   docker build -t mcp-mandate .
#   docker run --rm mcp-mandate --version

# Base images are pinned by digest, so a rebuild uses exactly the same ones.
FROM rust:1.99.1-trixie@sha256:09027f873d45b8ecd1dc86f1fa13b7a62b875c961f017a0e331267b350430137 AS build
# The image's own toolchain is the one rust-toolchain.toml pins, so rustup
# has nothing to download.
ENV RUSTUP_TOOLCHAIN=1.99.1 CARGO_TERM_COLOR=never
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin mcp-mandate \
 && cp target/release/mcp-mandate /mcp-mandate \
 && mkdir /audit

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2
# The release workflow adds labels for the source repository, the version
# and the commit, and uses the repository's About text as the description.
LABEL org.opencontainers.image.description="Scout reviews MCP servers before you trust them, a hash-chained audit log records every decision, and a security gate checks every call between AI agents and their MCP tools" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=build /mcp-mandate /usr/local/bin/mcp-mandate
# A folder the non-root user can write, for audit logs; mount a volume here
# and keep the configuration itself read-only.
COPY --from=build --chown=65532:65532 /audit /audit
USER nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/mcp-mandate"]
CMD ["--help"]
