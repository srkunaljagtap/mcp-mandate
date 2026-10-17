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
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::StreamExt;
use mcp_mandate_audit::{self as audit, Log, Recorder};
use mcp_mandate_gate::jsonrpc::{Message, classify};
use mcp_mandate_gate::{Action, Gate};
use mcp_mandate_pin::Inventory;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub use config::{Auth, ConfigError, GatewayConfig, IdentityConfig, ServerConfig, Tls};
pub use identity::{Caller, IdentityError, TokenError};
pub use upstream::CredentialError;

use crate::ProxyError;
use crate::framing::MAX_MESSAGE_BYTES;
use crate::inventory::{self, PROTOCOL_VERSION, Rpc, result_of};
use crate::process::Signals;
use identity::Identity;
use session::{Session, Sessions};
use upstream::{PROTOCOL_HEADER, SESSION_HEADER, Upstream};

/// Largest request body accepted from a client.
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
/// Sessions unused for this long are closed.
const IDLE_SESSION: Duration = Duration::from_secs(30 * 60);
/// How long listing a server's inventory may take.
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(60);

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
    #[error("the gateway stopped serving")]
    Serve(#[source] std::io::Error),
}

struct App {
    config: GatewayConfig,
    identity: Identity,
    upstreams: BTreeMap<String, Upstream>,
    sessions: Sessions,
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
/// session's end is recorded.
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
    let app = Arc::new(App {
        config,
        identity,
        upstreams,
        sessions: Sessions::default(),
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
    let router = router(Arc::clone(&app));
    let served = match tls {
        Some(tls) => {
            tls::serve(listener, tls, router, shutdown).await;
            Ok(())
        }
        None => tokio::select! {
            served = axum::serve(listener, router) => served.map_err(GatewayError::Serve),
            () = shutdown => Ok(()),
        },
    };
    sweeper.abort();
    for session in app.sessions.drain() {
        session.end();
    }
    served
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
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(app)
}

/// Closes idle sessions once a minute.
async fn sweep(app: Arc<App>) {
    let mut every = tokio::time::interval(Duration::from_secs(60));
    loop {
        every.tick().await;
        for session in app.sessions.sweep(IDLE_SESSION) {
            info!(server = %session.server, caller = %session.caller.subject, "closed an idle session");
            session.end();
        }
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
    let metadata = format!(
        "{}/.well-known/oauth-protected-resource/servers/{name}/mcp",
        app.config.public_url
    );
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
// The error is the HTTP response to send back; one is built per refused request.
#[allow(clippy::result_large_err)]
fn open_session(app: &App, name: &str, caller: &Caller) -> Result<Arc<Session>, Response> {
    let server = &app.config.servers[name];
    let unavailable =
        |problem: &str| (StatusCode::SERVICE_UNAVAILABLE, problem.to_owned()).into_response();
    let started = Log::open(&server.policy.audit_log).and_then(|mut log| {
        log.record(&session_start(app, server, caller))?;
        Ok(log)
    });
    let log = match started {
        Ok(log) => log,
        Err(failure) => {
            error!(server = name, error = %describe(&failure), "couldn't open a session: the audit log can't be written");
            return Err(unavailable(
                "the audit log can't be written, so no session can open",
            ));
        }
    };
    let gate = Gate::new(server.policy.clone(), server.pins.clone(), Box::new(log));
    let session = Arc::new(Session::new(name, caller.clone(), gate));
    if app.sessions.insert(Arc::clone(&session)).is_err() {
        session.end();
        return Err(unavailable("too many open sessions"));
    }
    info!(server = name, caller = %caller.subject, "opened a session");
    Ok(session)
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

fn close_session(app: &App, session: &Session) {
    app.sessions.remove(&session.id);
    session.end();
}

/// A client's JSON-RPC message (`POST`).
async fn post_message(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match admit(&app, &name, &headers).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let initialize = matches!(
        classify(&body),
        Ok(Message::Request { ref method, .. }) if method == "initialize"
    );
    let (session, created) = if headers.contains_key(SESSION_HEADER) {
        match find_session(&app, &name, &caller, &headers) {
            Ok(session) => (session, false),
            Err(response) => return response,
        }
    } else if initialize {
        match open_session(&app, &name, &caller) {
            Ok(session) => (session, true),
            Err(response) => return response,
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            "no Mcp-Session-Id: start with an initialize request",
        )
            .into_response();
    };

    let Some(actions) = session.with_gate(|gate| gate.from_client(&body)) else {
        close_session(&app, &session);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let (answers, forward) = split(actions);
    let Some(forward) = forward.into_iter().next() else {
        // The gate answered (blocked) or dropped it.
        if created {
            close_session(&app, &session);
        }
        return match answers.into_iter().next() {
            Some(answer) => json_reply(answer, &session.id),
            None => accepted(&session.id),
        };
    };

    let protocol = protocol_version(&headers);
    let upstream = &app.upstreams[&name];
    let response = match upstream
        .post(forward, session.upstream_id().as_deref(), protocol.as_ref())
        .await
    {
        Ok(response) => response,
        Err(failure) => {
            warn!(server = name, error = %describe(&failure), "couldn't reach the MCP server");
            if created {
                close_session(&app, &session);
            }
            return (StatusCode::BAD_GATEWAY, "couldn't reach the MCP server").into_response();
        }
    };
    if created {
        let upstream_id = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|id| id.to_str().ok())
            .map(str::to_owned);
        session.set_upstream_id(upstream_id);
    }
    relay(app, session, response, protocol, created).await
}

/// Sends the server's reply back to the client, every message through the
/// gate: a single JSON message, or an event stream.
async fn relay(
    app: Arc<App>,
    session: Arc<Session>,
    response: reqwest::Response,
    protocol: Option<HeaderValue>,
    created: bool,
) -> Response {
    let status = response.status();
    if status == reqwest::StatusCode::ACCEPTED {
        return accepted(&session.id);
    }
    if status == reqwest::StatusCode::NOT_FOUND && session.upstream_id().is_some() {
        // The server forgot the session: the client must start over.
        close_session(&app, &session);
        return (StatusCode::NOT_FOUND, "the MCP server ended the session").into_response();
    }
    if !status.is_success() {
        warn!(server = %session.server, %status, "the MCP server answered with an error status");
        if created {
            close_session(&app, &session);
        }
        return (
            StatusCode::BAD_GATEWAY,
            format!("the MCP server answered with HTTP {}", status.as_u16()),
        )
            .into_response();
    }
    if is_event_stream(response.headers()) {
        return stream(app, session, response, protocol);
    }
    let body = match read_limited(response).await {
        Ok(body) => body,
        Err(problem) => {
            warn!(server = %session.server, %problem, "couldn't read the MCP server's reply");
            return (
                StatusCode::BAD_GATEWAY,
                "couldn't read the MCP server's reply",
            )
                .into_response();
        }
    };
    let Some(actions) = session.with_gate(|gate| gate.from_server(&body)) else {
        close_session(&app, &session);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let (answers, to_server) = split(actions);
    for message in to_server {
        answer_server(&app, &session, message, protocol.clone());
    }
    match answers.into_iter().next() {
        Some(answer) => json_reply(answer, &session.id),
        None => (
            StatusCode::BAD_GATEWAY,
            "the MCP server's reply didn't pass the gate",
        )
            .into_response(),
    }
}

/// Relays an event stream: each event's message goes through the gate, and
/// what passes is written to the client as it arrives.
fn stream(
    app: Arc<App>,
    session: Arc<Session>,
    response: reqwest::Response,
    protocol: Option<HeaderValue>,
) -> Response {
    let (sender, receiver) = mpsc::channel::<Bytes>(64);
    let id = session.id.clone();
    tokio::spawn(async move {
        let mut parser = sse::Parser::new(MAX_MESSAGE_BYTES);
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let Ok(chunk) = chunk else { break };
            let events = match parser.push(&chunk) {
                Ok(events) => events,
                Err(problem) => {
                    warn!(server = %session.server, %problem, "stopped relaying the MCP server's stream");
                    break;
                }
            };
            for event in events {
                if event.data.is_empty()
                    || event.kind.as_deref().is_some_and(|kind| kind != "message")
                {
                    continue;
                }
                let Some(actions) = session.with_gate(|gate| gate.from_server(&event.data)) else {
                    return;
                };
                for action in actions {
                    match action {
                        Action::ToClient(message) => {
                            let event = sse::encode(event.id.as_deref(), &message);
                            if sender.send(Bytes::from(event)).await.is_err() {
                                return; // the client left; dropping the stream closes the server's too
                            }
                        }
                        Action::ToServer(message) => {
                            answer_server(&app, &session, message, protocol.clone());
                        }
                    }
                }
            }
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

/// Sends the gate's answer to a server request back to the server.
fn answer_server(
    app: &Arc<App>,
    session: &Arc<Session>,
    message: Vec<u8>,
    protocol: Option<HeaderValue>,
) {
    let app = Arc::clone(app);
    let session = Arc::clone(session);
    tokio::spawn(async move {
        let upstream = &app.upstreams[&session.server];
        if let Err(failure) = upstream
            .post(message, session.upstream_id().as_deref(), protocol.as_ref())
            .await
        {
            debug!(server = %session.server, error = %describe(&failure), "couldn't send an answer to the MCP server");
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
    let protocol = protocol_version(&headers);
    let upstream = &app.upstreams[&name];
    let request = match upstream
        .request(
            reqwest::Method::GET,
            "text/event-stream",
            session.upstream_id().as_deref(),
            protocol.as_ref(),
        )
        .await
    {
        Ok(request) => request,
        Err(failure) => {
            warn!(server = name, error = %describe(&failure), "couldn't get a credential for the MCP server");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let request = match headers.get("last-event-id").filter(|id| id.len() <= 256) {
        Some(id) => request.header("last-event-id", id.clone()),
        None => request,
    };
    let response = match request.send().await {
        Ok(response) => response,
        Err(failure) => {
            warn!(server = name, error = %failure, "couldn't reach the MCP server");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !response.status().is_success() || !is_event_stream(response.headers()) {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    stream(app, session, response, protocol)
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
    close_session(&app, &session);
    if let Some(upstream_id) = session.upstream_id() {
        let _ = app.upstreams[&name].delete(&upstream_id).await;
    }
    StatusCode::NO_CONTENT.into_response()
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

fn json_reply(message: Vec<u8>, session: &str) -> Response {
    let mut response = Response::new(Body::from(message));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    with_session(response, session)
}

fn accepted(session: &str) -> Response {
    with_session(StatusCode::ACCEPTED.into_response(), session)
}

fn with_session(mut response: Response, session: &str) -> Response {
    if let Ok(id) = HeaderValue::from_str(session) {
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
        let _ = upstream.delete(&session).await;
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
            self.find_in_stream(response, id)
                .await?
                .ok_or_else(bad_reply)?
        } else {
            let body = read_limited(response).await.map_err(|_| bad_reply())?;
            serde_json::from_slice::<Value>(&body).map_err(|_| bad_reply())?
        };
        if message.get("id") != Some(&json!(id)) {
            return Err(bad_reply());
        }
        let result = result_of(method, &message)?;
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
        id: u64,
    ) -> Result<Option<Value>, ProxyError> {
        let mut parser = sse::Parser::new(MAX_MESSAGE_BYTES);
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let events = parser
                .push(&chunk?)
                .map_err(|_| ProxyError::BadReply("a streamed reply".to_owned()))?;
            for event in events {
                let Ok(message) = serde_json::from_slice::<Value>(&event.data) else {
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
