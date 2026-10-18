//! Serving connections: HTTPS through rustls, or plain HTTP, through the same
//! router, with the same timeouts and connection cap.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tracing::{debug, warn};

use super::GatewayError;

/// How long a client gets to finish the TLS handshake, and to send a
/// request's headers.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Most connections served at once.
const MAX_CONNECTIONS: usize = 1024;

/// Loads the certificate chain and private key (PEM files).
pub(super) fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, GatewayError> {
    let problem = |what: &str, path: &Path, error: &dyn std::fmt::Display| {
        GatewayError::Tls(format!("{what} {}: {error}", path.display()))
    };
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|error| problem("couldn't read the certificate", cert, &error))?
        .collect::<Result<_, _>>()
        .map_err(|error| problem("couldn't parse the certificate", cert, &error))?;
    if certs.is_empty() {
        return Err(problem("no certificate in", cert, &"empty"));
    }
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|error| problem("couldn't read the private key", key, &error))?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| GatewayError::Tls(error.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Accepts connections until `shutdown` completes: HTTPS when `tls` is
/// given, plain HTTP otherwise. Both get the same header timeout, and at
/// most [`MAX_CONNECTIONS`] are served at once (beyond that, new ones wait).
pub(super) async fn serve(
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
    router: Router,
    shutdown: impl Future<Output = ()>,
) {
    serve_at_most(MAX_CONNECTIONS, listener, tls, router, shutdown).await;
}

async fn serve_at_most(
    connections: usize,
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
    router: Router,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = tls.map(TlsAcceptor::from);
    let slots = Arc::new(Semaphore::new(connections));
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let slot = tokio::select! {
            slot = Arc::clone(&slots).acquire_owned() => match slot {
                Ok(slot) => slot,
                Err(_) => return,
            },
            () = &mut shutdown => return,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(%error, "couldn't accept a connection");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => return,
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _slot = slot;
            match acceptor {
                Some(acceptor) => connection_tls(acceptor, router, stream, peer).await,
                None => http(TokioIo::new(stream), router, peer).await,
            }
        });
    }
}

async fn connection_tls(
    acceptor: TlsAcceptor,
    router: Router,
    stream: TcpStream,
    peer: SocketAddr,
) {
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(error)) => {
            debug!(%peer, %error, "TLS handshake failed");
            return;
        }
        Err(_) => {
            debug!(%peer, "TLS handshake timed out");
            return;
        }
    };
    http(TokioIo::new(tls), router, peer).await;
}

async fn http<I>(io: TokioIo<I>, router: Router, peer: SocketAddr)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let served = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(io, TowerToHyperService::new(router))
        .await;
    if let Err(error) = served {
        debug!(%peer, %error, "connection ended with an error");
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn router() -> Router {
        Router::new().route("/", axum::routing::get(|| async { "ok" }))
    }

    async fn listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    #[tokio::test]
    async fn serves_https_with_the_given_certificate_and_nothing_else() {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let dir = std::env::temp_dir().join(format!("mcp-mandate-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert, certified.cert.pem()).unwrap();
        std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
        let config = server_config(&cert, &key).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        let (listener, address) = listener().await;
        tokio::spawn(serve(
            listener,
            Some(config),
            router(),
            std::future::pending(),
        ));
        let trusted = reqwest::Certificate::from_pem(certified.cert.pem().as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(trusted)
            .resolve("localhost", address)
            .build()
            .unwrap();
        let url = format!("https://localhost:{}/", address.port());
        let answer = client.get(&url).send().await.unwrap();
        assert_eq!(answer.text().await.unwrap(), "ok");
        // Plain HTTP on the same port gets no answer.
        let plain = reqwest::get(format!("http://127.0.0.1:{}/", address.port())).await;
        assert!(plain.is_err(), "{plain:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_finishes_its_headers_is_cut_off() {
        let (listener, address) = listener().await;
        tokio::spawn(serve(listener, None, router(), std::future::pending()));
        let mut client = TcpStream::connect(address).await.unwrap();
        let started = tokio::time::Instant::now();
        let _ = client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await;
        let mut answer = Vec::new();
        let closed =
            tokio::time::timeout(HEADER_TIMEOUT * 2, client.read_to_end(&mut answer)).await;
        assert!(closed.is_ok(), "the connection was still open");
        assert!(started.elapsed() >= HEADER_TIMEOUT);
    }

    #[tokio::test]
    async fn connections_beyond_the_cap_wait_for_a_free_slot() {
        let (listener, address) = listener().await;
        tokio::spawn(serve_at_most(
            1,
            listener,
            None,
            router(),
            std::future::pending(),
        ));
        // Takes the only slot, and sends nothing.
        let first = TcpStream::connect(address).await.unwrap();
        let mut second = TcpStream::connect(address).await.unwrap();
        second
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = [0u8; 64];
        let early =
            tokio::time::timeout(Duration::from_millis(300), second.read(&mut answer)).await;
        assert!(early.is_err(), "served beyond the cap");
        drop(first);
        let read = tokio::time::timeout(Duration::from_secs(10), second.read(&mut answer))
            .await
            .expect("served once a slot was free")
            .unwrap();
        assert!(
            answer[..read].starts_with(b"HTTP/1.1 200"),
            "{:?}",
            &answer[..read]
        );
    }
}
