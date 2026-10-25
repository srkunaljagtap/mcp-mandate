# The HTTPS gateway

For remote MCP servers (a URL rather than a program on your machine),
`mcp-mandate gate` runs as a service that agents connect to over HTTPS:

```
agent ──HTTPS + your OIDC token──▶ mcp-mandate gate ──HTTPS + the gateway's own credential──▶ MCP server
```

```sh
mcp-mandate pin --gateway gateway.toml --server github --out github.pins.toml
mcp-mandate gate --config gateway.toml
```

Agents connect to `https://<gateway>/servers/<name>/mcp`. Start from
[policies/gateway.example.toml](https://github.com/srkunaljagtap/mcp-mandate/blob/main/policies/gateway.example.toml).

- **Who's calling.** Every request needs a bearer token from your OIDC
  identity provider. The gateway checks:
  - the signature, against the provider's published keys (asymmetric
    algorithms only, never shared-secret `HS*`, and the key's type must
    match the token's algorithm);
  - the issuer;
  - the audience (the gateway, or the server being used);
  - the subject, the expiry and the not-before time. Clocks may differ by
    up to a minute for the not-before time, but not for the expiry: a
    token past its expiry by the gateway's clock gets `401`, so the client
    renews it.

  Set `audience` to an API or resource identifier, never to a client id:
  the token's type isn't checked, so with a client id an ID token would
  pass as an access token. If the provider can't be reached, its keys are
  used for at most 24 hours after they were fetched.

  Any token that passes may use every configured server, so decide who can
  get one in your identity provider. A missing or bad token gets `401` with
  a link to the gateway's OAuth metadata (RFC 9728), which MCP clients use
  to find your provider and sign in.
- **The server never sees your token.** The gateway removes it and signs in
  with its own credential for that one server: a secret from an environment
  variable or file (never the config file itself), without the spaces or
  line breaks around it, or short-lived OAuth client-credential tokens. A
  credential sent in a header must be ASCII. Only the headers MCP needs are
  passed on, and redirects aren't followed, so a server can't bounce the
  credential elsewhere. A server that echoes the credential back gets it
  redacted, in either mode and whatever `[secrets] redact_responses` says,
  in replies and event streams alike, inside a resource's base64 `blob`
  too. A message the gate can't check that holds it, or has a `blob`
  member that could hold it encoded, is read as JSON and, if a key repeats
  or the credential has to come out, written out again with one copy of
  each key. One that can't be read in full that way, or would take too
  much memory to, doesn't pass: the request it answers gets an error
  saying why, a request from the server is answered with an error, and
  anything else is dropped. What's redacted: the whole header value, the
  token after its scheme, the client secret, and every
  client-credential token that may still be valid: until the expiry the
  token endpoint gave (`expires_in`), or for a day when it gave none, the
  16 newest at most. An event's id isn't a message, so the gate doesn't
  check it: an id holding the credential, or anything else the policy
  takes for a secret, is dropped.
- **Sessions** belong to the caller who opened them, and each has its own
  gate and its own audit session; taint is shared across all of a caller's
  sessions. The gateway keeps sessions in memory, so run one instance, or
  send each client to the same one (sticky sessions); a restart ends every
  session. The server's session id is
  never shown to the client. Sessions unused for 30 minutes close, unless
  a request is still in flight. Closing a session also ends its event
  streams and the server's session. A request whose reply hasn't started
  when its session closes gets `404`, as for any unknown session, so the
  client starts a new one, whatever the server then does with it (fails
  it, drops the connection or answers it); so does every request in flight
  and every event stream opened when the server forgets the session (it
  restarted, say). A reply stream already under way just ends. Nothing
  more is sent on a closed session.
- **Every message**, including streamed (SSE) ones, goes through the gate
  exactly as with `mcp-mandate run`. Each session's audit log entries name
  the caller (`sub`) and their OAuth client.
- **HTTPS:** mcp-mandate serves TLS itself with your certificate, or plain
  HTTP behind a proxy that handles TLS (`terminated_by_proxy = true`). Plain
  HTTP is otherwise allowed only on localhost. Behind a proxy, `listen` on
  the address the proxy connects to, not `0.0.0.0`: anything that can reach
  the port directly skips the proxy, and tokens cross that hop unencrypted.
  Servers must use `https://` unless they're on localhost.
- **Limits:** at most 1024 connections at once; 30 seconds to send a
  request's headers, then 30 seconds to send its body (at most 4 MB), which
  is read only once the token checks out; 32 open sessions per caller; and
  per session, 16 requests in flight (an answer streamed back counts until
  its stream ends), 16 messages being read or, for the client's answers and
  notifications, passed on (these never count as requests, so a client can
  always answer or cancel what's in flight), 4 event streams, and 8 of the
  gate's refusals of the server's own requests being sent at once (a server
  sending more requests waits until one is taken). Across all callers,
  messages are read and checked as many at a time as the machine has CPUs;
  the rest wait their turn. Nothing outlives the token it came with: a
  request whose token expires before the request is checked or sent gets
  `401`, an event stream ends when the token it was opened with expires,
  and a request still waiting for its answer when the token it was sent
  with expires is given up on (its event stream ends, or the client gets
  `504`); clients carry on with a fresh token. The client's answers to the
  server and its notifications are sent on once they pass the gate, even
  if their token expires meanwhile, and the server gets at least 30
  seconds to take one (in `enforce` mode, that includes an answer too
  large to check, which the gate replaces with an error). A reply or event
  stream
  from the server that sends nothing for 5 minutes is ended too, so a call
  that runs longer needs the server to send progress notifications or
  keep-alive comments meanwhile. The connection cap is shared by everyone
  who can reach the port, so put a public gateway behind a proxy that
  limits connections and requests per client.
