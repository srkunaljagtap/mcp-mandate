# Security policy

## Reporting a vulnerability

Please don't report vulnerabilities in public issues, discussions or pull
requests. Use GitHub's private vulnerability reporting instead: open the
repository's **Security** tab and choose **Report a vulnerability**.

Include what you can of:

- the version or commit you tested;
- steps to reproduce, or a proof of concept;
- what an attacker gains (for example, a call that bypasses a policy).

We'll acknowledge the report, confirm the issue, release a fix, and then
publish an advisory crediting you if you'd like.

## Supported versions

Before 1.0, only the latest release receives security fixes.

## Scope

In scope: anything that lets a tool call bypass the gate's checks, tampers
with or forges the audit log, leaks credentials or secrets through
mcp-mandate, or makes the gate fail open.

Out of scope: vulnerabilities in MCP servers, AI agents or identity providers
themselves, and attacks that need control of the machine mcp-mandate runs on.
