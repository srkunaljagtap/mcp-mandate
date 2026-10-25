//! `mcp-mandate gate`: the HTTPS gateway in front of remote MCP servers.
//!
//! ```text
//! agent ──HTTPS + caller's token──▶ gateway ──HTTPS + the gateway's own credential──▶ MCP server
//!                                     │ 1. checks the token (issuer, audience, signature, expiry)
//!                                     │ 2. finds the caller's session (each has its own gate)
//!                                     │ 3. runs every message both ways through the gate
//!                                     └ 4. records it all in the server's audit log
//! ```
//!
//! Agents reach each configured server at `/servers/<name>/mcp` (MCP's
//! Streamable HTTP transport). A missing or invalid token gets `401` with a
//! pointer to the gateway's OAuth protected-resource metadata, so MCP
//! clients can find the identity provider and sign in.

mod config;
mod identity;
mod session;
pub mod sse;
mod tls;
mod upstream;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::StreamExt;
use mcp_mandate_audit::{self as audit, Log, Recorder};
use mcp_mandate_gate::jsonrpc::{self, Message, ParseError, classify};
use mcp_mandate_gate::{Action, Gate};
use mcp_mandate_pin::Inventory;
use mcp_mandate_policy::{Mode, Policy};
use mcp_mandate_taint::{SecretDetector, SecretPattern};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

pub use config::{Auth, ConfigError, GatewayConfig, IdentityConfig, ServerConfig, Tls};
pub use identity::{Caller, IdentityError, TokenError};
pub use upstream::CredentialError;

use crate::ProxyError;
use crate::framing::MAX_MESSAGE_BYTES;
use crate::inventory::{self, PROTOCOL_VERSION, Rpc, result_of};
use crate::process::Signals;
use identity::Identity;
use session::{CallerTaints, Session, Sessions};
use upstream::{PROTOCOL_HEADER, SESSION_HEADER, Upstream};

/// Largest request body accepted from a client, and how long it may take
/// to arrive. It's read only once the client's token checks out.
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Sessions unused for this long are closed.
const IDLE_SESSION: Duration = Duration::from_secs(30 * 60);
/// How long listing a server's inventory may take.
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a server gets to take the gate's answer to one of its
/// requests (and at least as long for a client's answer or notification),
/// and to end a session.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(30);
const DELETE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often an event stream to a client gets a keep-alive comment: writing
/// is how a client that vanished is noticed.
const KEEP_ALIVE: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("couldn't listen on {address}")]
    Bind {
        address: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("couldn't load the identity provider's signing keys")]
    Identity(#[from] IdentityError),
    #[error("couldn't set up TLS: {0}")]
    Tls(String),
    #[error("couldn't open an audit log")]
    Audit(#[from] mcp_mandate_audit::AuditError),
    #[error("the gateway stopped serving")]
    Serve(#[source] std::io::Error),
}

struct App {
    config: GatewayConfig,
    identity: Identity,
    upstreams: BTreeMap<String, Upstream>,
    /// Each server's audit log, opened once.
    logs: BTreeMap<String, Log>,
    /// What each server's policy takes for a secret, for what the gate
    /// doesn't see (an event's id).
    secrets: BTreeMap<String, Mutex<SecretDetector>>,
    sessions: Sessions,
    taints: Arc<CallerTaints>,
}

/// Runs the gateway until SIGINT or SIGTERM (Ctrl-C on Windows). Returns
/// the exit code for the signal.
pub async fn run(config: GatewayConfig) -> Result<i32, GatewayError> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|source| GatewayError::Bind {
            address: config.listen,
            source,
        })?;
    let mut signals = Signals::new();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let code = signals.recv().await;
        let _ = stop.send(code);
    });
    let (code_in, code_out) = tokio::sync::oneshot::channel();
    serve(config, listener, async move {
        let code = stopped.await.unwrap_or(0);
        warn!(code, "received a stop signal; stopping the gateway");
        let _ = code_in.send(code);
    })
    .await?;
    Ok(code_out.await.unwrap_or(0))
}

/// Serves on `listener` until `shutdown` completes. Then every open
/// session's end is recorded, and its server told.
pub async fn serve(
    config: GatewayConfig,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), GatewayError> {
    let identity_http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("the HTTP client's settings are valid");
    let identity = Identity::connect(config.identity.clone(), identity_http).await?;
    let http = upstream::client();
    let upstreams = config
        .servers
        .values()
        .map(|server| (server.name.clone(), Upstream::new(server, http.clone())))
        .collect();
    let tls = match &config.tls {
        Tls::Serve { cert, key } => Some(tls::server_config(cert, key)?),
        Tls::TerminatedByProxy | Tls::Loopback => None,
    };
    // Opened now, so an unwritable log stops the start rather than every
    // session.
    let mut logs = BTreeMap::new();
    for server in config.servers.values() {
        logs.insert(server.name.clone(), Log::open(&server.policy.audit_log)?);
    }
    let secrets = config
        .servers
        .values()
        .map(|server| {
            (
                server.name.clone(),
                Mutex::new(secret_detector(&server.policy)),
            )
        })
        .collect();
    let app = Arc::new(App {
        config,
        identity,
        upstreams,
        logs,
        secrets,
        sessions: Sessions::default(),
        taints: Arc::default(),
    });
    let sweeper = tokio::spawn(sweep(Arc::clone(&app)));
    let address = listener.local_addr().map_err(GatewayError::Serve)?;
    info!(
        %address,
        public_url = %app.config.public_url,
        tls = tls.is_some(),
        servers = app.config.servers.len(),
        "the gateway is serving"
    );
    for (name, server) in &app.config.servers {
        if server.policy.mode == Mode::Observe {
            warn!(
                server = name.as_str(),
                "observe mode: decisions are logged, but nothing is blocked or hidden; add mode = \"enforce\" to the server's policy to enforce it"
            );
        }
    }
    let router = router(Arc::clone(&app));
    tls::serve(listener, tls, router, shutdown).await;
    sweeper.abort();
    let closing: Vec<_> = app
        .sessions
        .drain()
        .iter()
        .filter_map(|session| close_session(&app, session))
        .collect();
    // Ends are recorded right away; a server slow to end its session
    // doesn't hold the stop up for long.
    let _ = tokio::time::timeout(DELETE_TIMEOUT, futures_util::future::join_all(closing)).await;
    Ok(())
}

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource/servers/{name}/mcp",
            get(resource_metadata),
        )
        .route(
            "/servers/{name}/mcp",
            get(open_stream).post(post_message).delete(end_session),
        )
        .with_state(app)
}

/// Closes idle sessions once a minute.
async fn sweep(app: Arc<App>) {
    let mut every = tokio::time::interval(Duration::from_secs(60));
    loop {
        every.tick().await;
        for session in app.sessions.sweep(IDLE_SESSION) {
            info!(server = %session.server, caller = %session.caller.subject, "closed an idle session");
            close_session(&app, &session);
        }
        app.taints.keep_only(&app.sessions.callers());
    }
}

/// OAuth protected-resource metadata (RFC 9728): where to get a token for
/// a server behind the gateway.
async fn resource_metadata(State(app): State<Arc<App>>, Path(name): Path<String>) -> Response {
    if !app.config.servers.contains_key(&name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    axum::Json(json!({
        "resource": app.config.server_url(&name),
        "authorization_servers": [app.identity.issuer()],
        "bearer_methods_supported": ["header"],
    }))
    .into_response()
}

/// Lets a request in: the server must exist, the origin (if any) must be
/// allowed, and the bearer token must check out.
// The error is the HTTP response to send back; one is built per refused request.
#[allow(clippy::result_large_err)]
async fn admit(app: &App, name: &str, headers: &HeaderMap) -> Result<Caller, Response> {
    if !app.config.servers.contains_key(name) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    if let Some(origin) = headers.get(ORIGIN) {
        let allowed = origin.to_str().is_ok_and(|origin| {
            app.config
                .allowed_origins
                .iter()
                .any(|allowed| allowed == origin)
        });
        if !allowed {
            return Err((StatusCode::FORBIDDEN, "this origin isn't allowed").into_response());
        }
    }
    let metadata = metadata_url(app, name);
    let Some(token) = bearer(headers) else {
        return Err(unauthorized(&metadata, false));
    };
    match app
        .identity
        .check(token, &app.config.server_url(name))
        .await
    {
        Ok(caller) => Ok(caller),
        Err(error) => {
            info!(server = name, reason = %error, "refused a token");
            Err(unauthorized(&metadata, true))
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// Where the OAuth protected-resource metadata for server `name` is.
fn metadata_url(app: &App, name: &str) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource/servers/{name}/mcp",
        app.config.public_url
    )
}

/// The answer to a request whose token expired before the request was
/// checked or sent: the same as to a token expired on arrival, so the
/// client gets a fresh one.
fn expired_token(app: &App, name: &str) -> Response {
    info!(
        server = name,
        "refused a request: its token expired before it was sent"
    );
    unauthorized(&metadata_url(app, name), true)
}

fn unauthorized(metadata: &str, invalid: bool) -> Response {
    let challenge = if invalid {
        format!("Bearer error=\"invalid_token\", resource_metadata=\"{metadata}\"")
    } else {
        format!("Bearer resource_metadata=\"{metadata}\"")
    };
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, challenge)],
        "a valid bearer token is required",
    )
        .into_response()
}

/// The caller's open session, from the `Mcp-Session-Id` header. A missing,
/// unknown, or someone else's session is `404`, so the client starts over.
// The error is the HTTP response to send back; one is built per refused request.
#[allow(clippy::result_large_err)]
fn find_session(
    app: &App,
    name: &str,
    caller: &Caller,
    headers: &HeaderMap,
) -> Result<Arc<Session>, Response> {
    let session = headers
        .get(SESSION_HEADER)
        .and_then(|id| id.to_str().ok())
        .and_then(|id| app.sessions.get(id, name, caller));
    match session {
        Some(session) => {
            session.touch();
            Ok(session)
        }
        None => Err((
            StatusCode::NOT_FOUND,
            "no such session; send initialize first",
        )
            .into_response()),
    }
}

/// Opens a session for `caller` on server `name`: its own gate, recording
/// to the server's audit log. If the log can't be written, nothing opens.
/// The session closes again unless it's [kept](Opening::keep).
///
/// Run it as a task of its own: once the session's start is recorded, the
/// session must be built, so that its end is recorded too, even if the
/// client leaves meanwhile.
// The error is the HTTP response to send back; one is built per refused request.
#[allow(clippy::result_large_err)]
async fn open_session(app: Arc<App>, name: String, caller: Caller) -> Result<Opening, Response> {
    let server = &app.config.servers[&name];
    let unavailable =
        |problem: &str| (StatusCode::SERVICE_UNAVAILABLE, problem.to_owned()).into_response();
    // All of a server's sessions record through one open file, which may
    // have to wait for its lock: not on a thread that serves requests.
    let mut log = app.logs[&name].new_session();
    let start = session_start(&app, server, &caller);
    let recorded = tokio::task::spawn_blocking(move || log.record(&start).map(|()| log)).await;
    let log = match recorded {
        Ok(Ok(log)) => log,
        Ok(Err(failure)) => {
            error!(server = name.as_str(), error = %describe(&failure), "couldn't open a session: the audit log can't be written");
            return Err(unavailable(
                "the audit log can't be written, so no session can open",
            ));
        }
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    };
    let mut gate = Gate::new(server.policy.clone(), server.pins.clone(), Box::new(log))
        .with_shared_taint(Arc::new(app.taints.for_caller(&caller.subject)));
    // If the server ever echoes the gateway's own credential, the caller
    // mustn't get it. Kept current before every check, as tokens renew.
    gate.set_secret_literals(&app.upstreams[&name].credential_strings());
    let opening = Opening {
        session: Arc::new(Session::new(&name, caller.clone(), gate)),
        app: Arc::clone(&app),
        kept: false,
    };
    if app.sessions.insert(Arc::clone(&opening.session)).is_err() {
        return Err(unavailable("too many open sessions"));
    }
    info!(server = name.as_str(), caller = %caller.subject, "opened a session");
    Ok(opening)
}

fn session_start(app: &App, server: &ServerConfig, caller: &Caller) -> audit::Event {
    audit::Event {
        event: audit::EventKind::SessionStart,
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        mode: Some(format!("{:?}", server.policy.mode).to_lowercase()),
        policy: Some(server.policy_path.display().to_string()),
        policy_sha256: server.policy_sha256.clone(),
        pins_sha256: server.pins_sha256.clone(),
        server: Some(server.name.clone()),
        url: Some(app.upstreams[&server.name].display_url()),
        caller: Some(caller.subject.clone()),
        caller_client: caller.client.clone(),
        pid: Some(std::process::id()),
        ..audit::Event::default()
    }
}

/// Closes a session: it's forgotten, nothing more passes through it, and
/// its streams stop. Then its end is recorded, once, and the server's
/// session is ended too, by the returned task: await it, or let it run.
/// `None` if the session was closed already.
fn close_session(app: &Arc<App>, session: &Arc<Session>) -> Option<JoinHandle<()>> {
    app.sessions.remove(&session.id);
    if !session.close() {
        return None;
    }
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    let app = Arc::clone(app);
    let session = Arc::clone(session);
    Some(runtime.spawn(async move {
        session.record_end().await;
        if let Some(upstream_id) = session.upstream_id() {
            let ended = app.upstreams[&session.server].delete(&upstream_id);
            if tokio::time::timeout(DELETE_TIMEOUT, ended).await.is_err() {
                debug!(server = %session.server, "the MCP server didn't end its session in time");
            }
        }
    }))
}

/// Closes a session that `initialize` opened unless its reply goes back to
/// the client: a client that never got the session's id can't use it or
/// end it. That includes a client that left while waiting, or while the
/// session was opening.
struct Opening {
    app: Arc<App>,
    session: Arc<Session>,
    kept: bool,
}

impl Opening {
    fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for Opening {
    fn drop(&mut self) {
        if !self.kept {
            close_session(&self.app, &self.session);
        }
    }
}

/// A client's JSON-RPC message (`POST`).
async fn post_message(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Nothing of the body is read until the token checks out.
    let caller = match admit(&app, &name, &headers).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let existing = if headers.contains_key(SESSION_HEADER) {
        match find_session(&app, &name, &caller, &headers) {
            Ok(session) => Some(session),
            Err(response) => return response,
        }
    } else {
        None
    };
    // Counted before the body is read, so a session can't have any number
    // of bodies arriving at once.
    let arriving = match existing.as_ref().map(|session| session.start_message()) {
        Some(None) => return too_many("this session already has its most messages arriving"),
        Some(permit) => permit,
        None => None,
    };
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    // The client's answers to the server and its notifications aren't
    // requests: they get through however many requests are in flight, so
    // the client can always answer or cancel those.
    let Some((message, request)) = read_message(body.clone()).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let (initialize, request_id) = match message {
        Ok(Message::Request { id, method }) => (method == "initialize", Some(id)),
        _ => (false, None),
    };
    let (session, in_flight, opening) = match existing {
        Some(session) if request => {
            drop(arriving);
            match session.start_request() {
                Some(in_flight) => (session, Some(in_flight), None),
                None => {
                    return too_many("this session already has its most requests in flight");
                }
            }
        }
        Some(session) => (session, arriving, None),
        None if initialize => {
            // A task of its own, which the client leaving can't stop
            // halfway.
            let opened =
                tokio::spawn(open_session(Arc::clone(&app), name.clone(), caller.clone())).await;
            let opening = match opened {
                Ok(Ok(opening)) => opening,
                Ok(Err(response)) => return response,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let session = Arc::clone(&opening.session);
            let in_flight = session.start_request();
            (session, in_flight, Some(opening))
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "no Mcp-Session-Id: start with an initialize request",
            )
                .into_response();
        }
    };

    // Nothing outlives the token it came with: a request whose token
    // expired while its body arrived or it waited its turn isn't checked...
    let deadline = token_deadline(&caller);
    if passed(deadline) {
        return expired_token(&app, &name);
    }
    let Some(actions) = gate_check(&app, &session, move |gate| gate.from_client(&body)).await
    else {
        return check_failed(&app, &session);
    };
    let (answers, forward) = split(actions);
    let Some(forward) = forward.into_iter().next() else {
        // The gate answered (blocked) or dropped it. A session it was
        // opening closes, so its id isn't handed out.
        let id = opening.is_none().then_some(session.id.as_str());
        return match answers.into_iter().next() {
            Some(answer) => json_reply(answer, id),
            None => accepted(id),
        };
    };
    // ...one whose token expired while it was checked isn't sent, and one
    // still waiting for its answer when the token expires is given up on.
    // The client's answers and notifications aren't requests: nothing waits
    // on them, and the gate has taken them in (an answer it passed, or
    // answered in the client's place as too large to check, is no longer
    // awaited, so a retry would be dropped). Once passed, they're sent, and
    // the server gets at least as long to take one as the gate's own
    // answers.
    let deadline = if request {
        if passed(deadline) {
            abandon(&session, request_id.as_ref()).await;
            return expired_token(&app, &name);
        }
        deadline
    } else {
        deadline.map(|deadline| deadline.max(Instant::now() + ANSWER_TIMEOUT))
    };

    let protocol = protocol_version(&headers);
    let upstream = &app.upstreams[&name];
    // Nothing more passes through a session that closed while this was
    // checked. Its id is read first: a session the server forgot is closed
    // before its id is cleared, so a message that finds no id here finds
    // the session closed too, rather than going to the server without one.
    let upstream_id = session.upstream_id();
    if session.is_closed() {
        return session_ended();
    }
    let sent = upstream.post(forward, upstream_id.as_deref(), protocol.as_ref());
    let response = match within(deadline, sent).await {
        Some(Ok(response)) => response,
        Some(Err(failure)) => {
            // The client ended the session, or the gateway is stopping:
            // the server may have dropped the message with it.
            if session.is_closed() {
                return session_ended();
            }
            warn!(server = name, error = %describe(&failure), "couldn't reach the MCP server");
            abandon(&session, request_id.as_ref()).await;
            return (StatusCode::BAD_GATEWAY, "couldn't reach the MCP server").into_response();
        }
        None => {
            abandon(&session, request_id.as_ref()).await;
            return token_expired();
        }
    };
    if response.status() == reqwest::StatusCode::NOT_FOUND && upstream_id.is_some() {
        // The server forgot the session: the client must start over. That
        // goes for every message sent with the session's id, not only the
        // first to hear of it. Closed before its id is cleared (see above);
        // the id goes so the server isn't asked to end a session it no
        // longer has.
        close_session(&app, &session);
        session.set_upstream_id(None);
        return (StatusCode::NOT_FOUND, "the MCP server ended the session").into_response();
    }
    if opening.is_some() {
        let upstream_id = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|id| id.to_str().ok())
            .map(str::to_owned);
        session.set_upstream_id(upstream_id);
    }
    let reply = relay(
        Arc::clone(&app),
        session,
        response,
        protocol,
        request_id,
        in_flight,
        deadline,
    )
    .await;
    if let Some(opening) = opening
        && reply.status().is_success()
    {
        opening.keep();
    }
    reply
}

/// Works out what kind of message a client sent, and whether it's a
/// request (anything but an answer to the server or a notification), on a
/// thread where blocking is fine, once it's its [turn](session::turn): a
/// body may be large. A message the gate can't read in full is taken for
/// what its top-level members say, as the gate takes it: an answer too
/// large to check still answers the server's request. `None` if that went
/// wrong.
async fn read_message(body: Bytes) -> Option<(Result<Message, ParseError>, bool)> {
    let turn = session::turn().await;
    tokio::task::spawn_blocking(move || {
        let _turn = turn;
        let message = classify(&body);
        let request = match &message {
            Ok(message) => is_request(message),
            Err(_) => jsonrpc::head(&body).is_none_or(|head| is_request(&head)),
        };
        (message, request)
    })
    .await
    .ok()
}

fn is_request(message: &Message) -> bool {
    !matches!(
        message,
        Message::Response { .. } | Message::Notification { .. }
    )
}

/// Runs `work` until `deadline`, if there is one: `None` if the deadline
/// comes first. Work whose deadline has passed already isn't started: a
/// timeout runs its work once before it looks at the time, which could
/// send a request that's then given up on.
async fn within<T>(deadline: Option<Instant>, work: impl Future<Output = T>) -> Option<T> {
    if passed(deadline) {
        return None;
    }
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, work).await.ok(),
        None => Some(work.await),
    }
}

/// Whether `deadline`, if there is one, has passed.
fn passed(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| deadline <= Instant::now())
}

/// The answer to a message, or to a request for the server's stream, whose
/// session closed while it waited (the server forgot the session, the
/// client ended it, or the gateway is stopping): `404`, as for any session
/// that's gone, so the client starts over.
fn session_ended() -> Response {
    (
        StatusCode::NOT_FOUND,
        "the session ended; send initialize first",
    )
        .into_response()
}

fn token_expired() -> Response {
    (
        StatusCode::GATEWAY_TIMEOUT,
        "the token this request was sent with expired before the MCP server answered",
    )
        .into_response()
}

/// Runs `check` with the session's gate, after making sure the gate knows
/// every form of the gateway's credential for this server in use right
/// now: tokens are renewed, and the server may echo any of them.
async fn gate_check<T: Send + 'static>(
    app: &App,
    session: &Session,
    check: impl FnOnce(&mut Gate) -> T + Send + 'static,
) -> Option<T> {
    let credentials = app.upstreams[&session.server].credential_strings();
    session
        .check(move |gate| {
            gate.set_secret_literals(&credentials);
            check(gate)
        })
        .await
}

/// The answer to a request whose check didn't run: its session
/// [ended](session_ended) while it waited, or a check panicked, and the
/// session, now unusable, closes.
fn check_failed(app: &Arc<App>, session: &Arc<Session>) -> Response {
    if session.is_closed() {
        return session_ended();
    }
    close_session(app, session);
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// Whether `text`, which the gate doesn't see, holds a secret: any form of
/// the gateway's credential for `server`, or anything its policy takes for
/// a secret.
fn holds_secret(app: &App, server: &str, text: &str) -> bool {
    let credentials = app.upstreams[server].credential_strings();
    match app.secrets[server].lock() {
        Ok(mut detector) => {
            detector.set_literals("gateway-credential", &credentials);
            detector.find(text).is_some()
        }
        // Fail closed.
        Err(_) => true,
    }
}

/// The built-in secret patterns, and `policy`'s own.
fn secret_detector(policy: &Policy) -> SecretDetector {
    let custom = policy
        .secrets
        .patterns
        .iter()
        .map(|(name, regex)| SecretPattern {
            name: name.clone(),
            regex: regex.clone(),
        })
        .collect();
    SecretDetector::new(custom)
}

/// Forgets a request that won't be answered through the gate, so it doesn't
/// stay pending (and in memory) forever.
async fn abandon(session: &Session, request_id: Option<&Value>) {
    if let Some(id) = request_id.cloned() {
        session.check(move |gate| gate.abandon(&id)).await;
    }
}

/// Sends the server's reply back to the client, every message through the
/// gate: a single JSON message, or an event stream. The client's message
/// stays counted by `in_flight` until its reply is done, or `deadline`.
async fn relay(
    app: Arc<App>,
    session: Arc<Session>,
    response: reqwest::Response,
    protocol: Option<HeaderValue>,
    request_id: Option<Value>,
    in_flight: Option<OwnedSemaphorePermit>,
    deadline: Option<Instant>,
) -> Response {
    // Whatever the server's reply, nothing more passes through a session
    // that closed while it waited for it.
    if session.is_closed() {
        return session_ended();
    }
    let status = response.status();
    if status == reqwest::StatusCode::ACCEPTED {
        // An answer to a request may still come, on the server's stream.
        return accepted(Some(&session.id));
    }
    if !status.is_success() {
        warn!(server = %session.server, %status, "the MCP server answered with an error status");
        abandon(&session, request_id.as_ref()).await;
        return (
            StatusCode::BAD_GATEWAY,
            format!("the MCP server answered with HTTP {}", status.as_u16()),
        )
            .into_response();
    }
    if is_event_stream(response.headers()) {
        return stream(
            app, session, response, protocol, request_id, in_flight, deadline,
        );
    }
    let body = match within(deadline, read_limited(response)).await {
        Some(Ok(body)) => body,
        Some(Err(problem)) => {
            // Or one that closed while the reply arrived.
            if session.is_closed() {
                return session_ended();
            }
            warn!(server = %session.server, %problem, "couldn't read the MCP server's reply");
            abandon(&session, request_id.as_ref()).await;
            return (
                StatusCode::BAD_GATEWAY,
                "couldn't read the MCP server's reply",
            )
                .into_response();
        }
        None => {
            abandon(&session, request_id.as_ref()).await;
            return token_expired();
        }
    };
    let Some(actions) = gate_check(&app, &session, move |gate| gate.from_server(&body)).await
    else {
        return check_failed(&app, &session);
    };
    let (answers, to_server) = split(actions);
    for message in to_server {
        answer_server(&app, &session, message, protocol.clone()).await;
    }
    match answers.into_iter().next() {
        Some(answer) => json_reply(answer, Some(&session.id)),
        None => {
            abandon(&session, request_id.as_ref()).await;
            (
                StatusCode::BAD_GATEWAY,
                "the MCP server's reply didn't pass the gate",
            )
                .into_response()
        }
    }
}

/// Relays an event stream: each event's message goes through the gate, and
/// what passes is written to the client as it arrives. The stream stays
/// counted by `slot` while it's open, and ends when the client leaves, the
/// session closes, or at `deadline`.
fn stream(
    app: Arc<App>,
    session: Arc<Session>,
    response: reqwest::Response,
    protocol: Option<HeaderValue>,
    request_id: Option<Value>,
    slot: Option<OwnedSemaphorePermit>,
    deadline: Option<Instant>,
) -> Response {
    let (sender, receiver) = mpsc::channel::<Bytes>(64);
    let id = session.id.clone();
    tokio::spawn(async move {
        let _slot = slot;
        let mut answered = false;
        let expired = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        // Whichever ends first; dropping the server's stream closes it.
        tokio::select! {
            () = relay_events(&app, &session, response, protocol.as_ref(), request_id.as_ref(), &sender, &mut answered) => {}
            () = sender.closed() => {}
            () = session.closed() => {}
            () = expired => {}
        }
        // If the stream never carried the answer, forget the request.
        if !answered {
            abandon(&session, request_id.as_ref()).await;
        }
    });
    let body = Body::from_stream(futures_util::stream::unfold(
        receiver,
        |mut receiver| async move {
            receiver
                .recv()
                .await
                .map(|event| (Ok::<_, Infallible>(event), receiver))
        },
    ));
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(id) = HeaderValue::from_str(&id) {
        headers.insert(SESSION_HEADER, id);
    }
    response
}

/// Relays the server's events until its stream ends. Sets `answered` once
/// the answer to `request_id` has gone through the gate.
async fn relay_events(
    app: &Arc<App>,
    session: &Arc<Session>,
    response: reqwest::Response,
    protocol: Option<&HeaderValue>,
    request_id: Option<&Value>,
    sender: &mpsc::Sender<Bytes>,
    answered: &mut bool,
) {
    let mut parser = sse::Parser::new(MAX_MESSAGE_BYTES);
    let mut chunks = response.bytes_stream();
    let mut keep_alive = tokio::time::interval_at(Instant::now() + KEEP_ALIVE, KEEP_ALIVE);
    loop {
        let chunk = tokio::select! {
            chunk = chunks.next() => chunk,
            _ = keep_alive.tick() => {
                // A client too far behind to take it is busy anyway.
                let _ = sender.try_send(Bytes::from_static(b":\n\n"));
                continue;
            }
        };
        let Some(Ok(chunk)) = chunk else { return };
        let events = match parser.push(&chunk) {
            Ok(events) => events,
            Err(problem) => {
                warn!(server = %session.server, %problem, "stopped relaying the MCP server's stream");
                return;
            }
        };
        for event in events {
            if event.data.is_empty() || event.kind.as_deref().is_some_and(|kind| kind != "message")
            {
                continue;
            }
            // A session with a live stream isn't idle.
            session.touch();
            // The gate never sees the id, which goes to the client as it
            // is: one holding a secret is dropped.
            let id = event
                .id
                .filter(|id| !holds_secret(app, &session.server, id));
            let data = event.data;
            // Whether it's the answer is worked out with the check, where
            // reading a large message holds no thread that serves requests.
            let wanted = request_id.filter(|_| !*answered).cloned();
            let checked = gate_check(app, session, move |gate| {
                let answer = wanted.is_some_and(|wanted| {
                    matches!(classify(&data), Ok(Message::Response { id, .. }) if id == wanted)
                });
                (answer, gate.from_server(&data))
            });
            let Some((answer, actions)) = checked.await else {
                return;
            };
            *answered |= answer;
            for action in actions {
                match action {
                    Action::ToClient(message) => {
                        let event = sse::encode(id.as_deref(), &message);
                        if sender.send(Bytes::from(event)).await.is_err() {
                            return; // the client left; dropping the stream closes the server's too
                        }
                    }
                    Action::ToServer(message) => {
                        answer_server(app, session, message, protocol.cloned()).await;
                    }
                }
            }
        }
    }
}

/// Sends the gate's answer to a server request back to the server. Only a
/// few are sent at once per session; until one is done, this waits, and so
/// does the stream that brought the request: a server flooding requests
/// slows only itself, and a burst of them is still answered in full.
async fn answer_server(
    app: &Arc<App>,
    session: &Arc<Session>,
    message: Vec<u8>,
    protocol: Option<HeaderValue>,
) {
    let slot = session.start_answer().await;
    let app = Arc::clone(app);
    let session = Arc::clone(session);
    tokio::spawn(async move {
        let _slot = slot;
        let upstream = &app.upstreams[&session.server];
        let upstream_id = session.upstream_id();
        let sent = upstream.post(message, upstream_id.as_deref(), protocol.as_ref());
        match tokio::time::timeout(ANSWER_TIMEOUT, sent).await {
            Ok(Ok(_)) => {}
            Ok(Err(failure)) => {
                debug!(server = %session.server, error = %describe(&failure), "couldn't send an answer to the MCP server");
            }
            Err(_) => {
                debug!(server = %session.server, "the MCP server didn't take an answer in time");
            }
        }
    });
}

/// The server's stream for messages it sends on its own (`GET`).
async fn open_stream(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let caller = match admit(&app, &name, &headers).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let session = match find_session(&app, &name, &caller, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(slot) = session.open_stream() else {
        return too_many("this session already has its most server streams open");
    };
    // It lasts no longer than the token it was opened with: a caller whose
    // token has expired, or who was disabled, stops getting messages. Nor
    // is it opened at the server once that token has expired.
    let deadline = token_deadline(&caller);
    if passed(deadline) {
        return expired_token(&app, &name);
    }
    let protocol = protocol_version(&headers);
    let upstream = &app.upstreams[&name];
    // Its id is read before the session is checked, as for a message: a
    // session the server forgot is closed before its id is cleared, so its
    // stream isn't asked for without the id (see `post_message`).
    let upstream_id = session.upstream_id();
    let request = upstream.request(
        reqwest::Method::GET,
        "text/event-stream",
        upstream_id.as_deref(),
        protocol.as_ref(),
    );
    let request = match within(deadline, request).await {
        Some(Ok(request)) => request,
        Some(Err(failure)) => {
            warn!(server = name, error = %describe(&failure), "couldn't get a credential for the MCP server");
            return StatusCode::BAD_GATEWAY.into_response();
        }
        None => return token_expired(),
    };
    let request = match headers.get("last-event-id").filter(|id| id.len() <= 256) {
        Some(id) => request.header("last-event-id", id.clone()),
        None => request,
    };
    // Nothing is asked of the server for a session that closed meanwhile.
    if session.is_closed() {
        return session_ended();
    }
    let response = match within(deadline, request.send()).await {
        Some(Ok(response)) => response,
        Some(Err(failure)) => {
            // The client ended the session, or the gateway is stopping:
            // the server may have dropped the stream with it.
            if session.is_closed() {
                return session_ended();
            }
            warn!(server = name, error = %failure.without_url(), "couldn't reach the MCP server");
            return StatusCode::BAD_GATEWAY.into_response();
        }
        None => return token_expired(),
    };
    // Whatever the server's answer, no stream opens for a session that
    // closed while it was asked (a server refuses one for the session the
    // gateway just ended there).
    if session.is_closed() {
        return session_ended();
    }
    if response.status() == reqwest::StatusCode::NOT_FOUND && upstream_id.is_some() {
        if !session.has_streamed() {
            // A server that never opened a stream may serve no `GET` at
            // all, and many answer one with `404` rather than `405`
            // (Express's default): the session goes on over `POST`, which
            // finds out if the server forgot it.
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        // The server forgot the session (see `post_message`): a client that
        // only listens learns here that it must start over.
        close_session(&app, &session);
        session.set_upstream_id(None);
        return (StatusCode::NOT_FOUND, "the MCP server ended the session").into_response();
    }
    if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !response.status().is_success() || !is_event_stream(response.headers()) {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    session.note_streamed();
    stream(app, session, response, protocol, None, Some(slot), deadline)
}

/// When `caller`'s token expires, as an instant; `None` if it's too far
/// off to represent.
fn token_deadline(caller: &Caller) -> Option<Instant> {
    Instant::now().checked_add(caller.time_left()?)
}

/// Ends a session (`DELETE`).
async fn end_session(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let caller = match admit(&app, &name, &headers).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let session = match find_session(&app, &name, &caller, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    // Its end is recorded, and the server's session ended, before the
    // client hears back.
    if let Some(closing) = close_session(&app, &session) {
        let _ = closing.await;
    }
    StatusCode::NO_CONTENT.into_response()
}

fn too_many(problem: &'static str) -> Response {
    (StatusCode::TOO_MANY_REQUESTS, problem).into_response()
}

/// Reads a client's request body: at most [`MAX_REQUEST_BYTES`], arriving
/// within [`BODY_TIMEOUT`].
// The error is the HTTP response to send back; one is built per refused request.
#[allow(clippy::result_large_err)]
async fn read_body(headers: &HeaderMap, body: Body) -> Result<Bytes, Response> {
    let too_large = || {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("a request may be at most {MAX_REQUEST_BYTES} bytes"),
        )
            .into_response()
    };
    let declared = headers
        .get(CONTENT_LENGTH)
        .and_then(|length| length.to_str().ok())
        .and_then(|length| length.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_REQUEST_BYTES as u64) {
        return Err(too_large());
    }
    let read = async {
        let mut bytes = Vec::new();
        let mut chunks = body.into_data_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
            if bytes.len() + chunk.len() > MAX_REQUEST_BYTES {
                return Err(too_large());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(bytes))
    };
    tokio::time::timeout(BODY_TIMEOUT, read)
        .await
        .unwrap_or_else(|_| {
            Err((
                StatusCode::REQUEST_TIMEOUT,
                "the request's body took too long to arrive",
            )
                .into_response())
        })
}

fn split(actions: Vec<Action>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut to_client = Vec::new();
    let mut to_server = Vec::new();
    for action in actions {
        match action {
            Action::ToClient(message) => to_client.push(message),
            Action::ToServer(message) => to_server.push(message),
        }
    }
    (to_client, to_server)
}

fn json_reply(message: Vec<u8>, session: Option<&str>) -> Response {
    let mut response = Response::new(Body::from(message));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    with_session(response, session)
}

fn accepted(session: Option<&str>) -> Response {
    with_session(StatusCode::ACCEPTED.into_response(), session)
}

fn with_session(mut response: Response, session: Option<&str>) -> Response {
    if let Some(Ok(id)) = session.map(HeaderValue::from_str) {
        response.headers_mut().insert(SESSION_HEADER, id);
    }
    response
}

/// The client's `MCP-Protocol-Version`, passed on only if it looks like
/// one (a date such as `2025-06-18`).
fn protocol_version(headers: &HeaderMap) -> Option<HeaderValue> {
    headers
        .get(PROTOCOL_HEADER)
        .filter(|value| {
            value.len() <= 32
                && value
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'.')
        })
        .cloned()
}

fn is_event_stream(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim_start().starts_with("text/event-stream"))
}

/// Reads a reply body, refusing one over [`MAX_MESSAGE_BYTES`].
async fn read_limited(response: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|error| error.to_string())?;
        if body.len() + chunk.len() > MAX_MESSAGE_BYTES {
            return Err(format!("it's larger than {MAX_MESSAGE_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// An error and its causes on one line.
fn describe(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

// --- Listing a remote server's inventory (`pin` and `scout`) ------------------

/// Lists everything `server` offers, signing in with the gateway's
/// credential for it, then ends the session.
pub async fn inventory(server: &ServerConfig) -> Result<Inventory, ProxyError> {
    let upstream = Upstream::new(server, upstream::client());
    let mut rpc = HttpRpc {
        upstream: &upstream,
        session: None,
        protocol: None,
        next_id: 0,
    };
    let listed = tokio::time::timeout(INVENTORY_TIMEOUT, inventory::collect(&mut rpc)).await;
    if let Some(session) = rpc.session.take() {
        // Bounded too: a server under review can't hold the listing up.
        let _ = tokio::time::timeout(DELETE_TIMEOUT, upstream.delete(&session)).await;
    }
    listed.map_err(|_| ProxyError::Timeout(INVENTORY_TIMEOUT))?
}

/// A minimal Streamable HTTP client.
struct HttpRpc<'a> {
    upstream: &'a Upstream,
    session: Option<String>,
    protocol: Option<HeaderValue>,
    next_id: u64,
}

impl Rpc for HttpRpc<'_> {
    async fn request(&mut self, method: &str, params: Value) -> Result<Value, ProxyError> {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let response = self
            .upstream
            .post(
                body.to_string().into_bytes(),
                self.session.as_deref(),
                self.protocol.as_ref(),
            )
            .await?;
        if !response.status().is_success() {
            return Err(ProxyError::Status {
                method: method.to_owned(),
                status: response.status().as_u16(),
            });
        }
        if method == "initialize" {
            self.session = response
                .headers()
                .get(SESSION_HEADER)
                .and_then(|id| id.to_str().ok())
                .map(str::to_owned);
        }
        let bad_reply = || ProxyError::BadReply(method.to_owned());
        let message = if is_event_stream(response.headers()) {
            self.find_in_stream(response, method, id)
                .await?
                .ok_or_else(bad_reply)?
        } else {
            let body = read_limited(response).await.map_err(|_| bad_reply())?;
            inventory::read_reply(method, &body)?.ok_or_else(bad_reply)?
        };
        if message.get("id") != Some(&json!(id)) {
            return Err(bad_reply());
        }
        let result = result_of(method, message)?;
        if method == "initialize" {
            let version = result
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(PROTOCOL_VERSION);
            self.protocol = HeaderValue::from_str(version).ok();
        }
        Ok(result)
    }

    async fn notify(&mut self, method: &str) -> Result<(), ProxyError> {
        let body = json!({"jsonrpc": "2.0", "method": method});
        let response = self
            .upstream
            .post(
                body.to_string().into_bytes(),
                self.session.as_deref(),
                self.protocol.as_ref(),
            )
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ProxyError::Status {
                method: method.to_owned(),
                status: response.status().as_u16(),
            })
        }
    }
}

impl HttpRpc<'_> {
    /// Reads an event stream until the response with `id`, refusing any
    /// request the server makes meanwhile.
    async fn find_in_stream(
        &self,
        response: reqwest::Response,
        method: &str,
        id: u64,
    ) -> Result<Option<Value>, ProxyError> {
        let mut parser = sse::Parser::new(MAX_MESSAGE_BYTES);
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let events = parser
                .push(&chunk?)
                .map_err(|_| ProxyError::BadReply("a streamed reply".to_owned()))?;
            for event in events {
                let Some(message) = inventory::read_reply(method, &event.data)? else {
                    continue;
                };
                if message.get("method").is_some() {
                    if let Some(request_id) = message.get("id") {
                        let refusal = json!({"jsonrpc": "2.0", "id": request_id,
                            "error": {"code": -32601, "message": "mcp-mandate doesn't answer server requests while listing"}});
                        let _ = self
                            .upstream
                            .post(
                                refusal.to_string().into_bytes(),
                                self.session.as_deref(),
                                self.protocol.as_ref(),
                            )
                            .await;
                    }
                    continue;
                }
                if message.get("id") == Some(&json!(id)) {
                    return Ok(Some(message));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_body_that_never_finishes_arriving_is_given_up_on() {
        let trickle =
            Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
        let refused = read_body(&HeaderMap::new(), trickle).await.unwrap_err();
        assert_eq!(refused.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused_declared_or_not() {
        let mut declared = HeaderMap::new();
        declared.insert(CONTENT_LENGTH, HeaderValue::from(MAX_REQUEST_BYTES + 1));
        let refused = read_body(&declared, Body::empty()).await.unwrap_err();
        assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let chunks = vec![
            Ok::<_, std::io::Error>(Bytes::from(vec![b' '; MAX_REQUEST_BYTES])),
            Ok(Bytes::from_static(b" ")),
        ];
        let undeclared = Body::from_stream(futures_util::stream::iter(chunks));
        let refused = read_body(&HeaderMap::new(), undeclared).await.unwrap_err();
        assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let fits = Body::from(vec![b' '; MAX_REQUEST_BYTES]);
        assert_eq!(
            read_body(&HeaderMap::new(), fits).await.unwrap().len(),
            MAX_REQUEST_BYTES
        );
    }

    #[tokio::test]
    async fn a_clients_message_is_read_only_in_its_turn() {
        let ping = Bytes::from_static(br#"{"jsonrpc": "2.0", "id": 1, "method": "ping"}"#);
        // Every turn is taken (as by checks in sessions of any caller)...
        let all = session::all_turns().await;
        let waiting = tokio::time::timeout(Duration::from_millis(200), read_message(ping.clone()));
        assert!(waiting.await.is_err(), "it was read out of turn");
        // ...and once one is free, it's read.
        drop(all);
        let read = tokio::time::timeout(Duration::from_secs(5), read_message(ping))
            .await
            .expect("read once a turn is free");
        assert!(
            matches!(read, Some((Ok(Message::Request { .. }), true))),
            "{read:?}"
        );
    }

    #[tokio::test]
    async fn an_answer_too_large_to_check_is_still_an_answer() {
        // Each small object costs as much memory as hundreds of numbers.
        let objects = vec![r#"{"a":0}"#; 100_000].join(",");
        let answer = format!(r#"{{"jsonrpc":"2.0","id":"r1","result":{{"roots":[{objects}]}}}}"#);
        let notification = format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/progress","params":{{"x":[{objects}]}}}}"#
        );
        let call = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"x":[{objects}]}}}}"#
        );
        for (text, request) in [(answer, false), (notification, false), (call, true)] {
            let read = read_message(Bytes::from(text)).await;
            assert!(
                matches!(read, Some((Err(ParseError::TooManyValues), read_as)) if read_as == request),
                "{read:?}"
            );
        }
        // One that doesn't say what it is counts as a request.
        let read = read_message(Bytes::from_static(b"[1, 2]")).await;
        assert!(matches!(read, Some((Err(_), true))), "{read:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn work_past_its_deadline_is_given_up_on() {
        let soon = Some(Instant::now() + Duration::from_secs(1));
        assert_eq!(within(soon, async { 7 }).await, Some(7));
        assert_eq!(within(soon, std::future::pending::<()>()).await, None);
        assert_eq!(within(None, async { 7 }).await, Some(7));
    }

    #[tokio::test(start_paused = true)]
    async fn work_whose_deadline_has_passed_isnt_started() {
        let started = Arc::new(AtomicBool::new(false));
        let work = {
            let started = Arc::clone(&started);
            async move {
                started.store(true, Ordering::SeqCst);
                7
            }
        };
        assert_eq!(within(Some(Instant::now()), work).await, None);
        assert!(!started.load(Ordering::SeqCst), "it was started");
        assert!(passed(Some(Instant::now())));
        assert!(!passed(Some(Instant::now() + Duration::from_secs(1))));
        assert!(!passed(None));
    }
}
