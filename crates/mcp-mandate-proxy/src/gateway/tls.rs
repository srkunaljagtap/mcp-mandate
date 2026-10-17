//! Serving HTTPS: rustls in front of the same router plain HTTP uses.

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
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tracing::{debug, warn};

use super::GatewayError;

/// How long a client gets to finish the TLS handshake, and to send a
/// request's headers.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Accepts TLS connections until `shutdown` completes.
pub(super) async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    router: Router,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(config);
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
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
        tokio::spawn(connection(acceptor.clone(), router.clone(), stream, peer));
    }
}

async fn connection(acceptor: TlsAcceptor, router: Router, stream: TcpStream, peer: SocketAddr) {
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
    let served = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(TokioIo::new(tls), TowerToHyperService::new(router))
        .await;
    if let Err(error) = served {
        debug!(%peer, %error, "connection ended with an error");
    }
}
