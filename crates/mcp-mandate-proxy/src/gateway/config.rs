//! The gateway's configuration file, checked when it loads: anything unsafe
//! or ambiguous stops the gateway from starting.
//!
//! ```toml
//! listen = "0.0.0.0:8443"
//! public_url = "https://gate.example.com"   # what agents connect to
//!
//! [tls]
//! cert = "/etc/mcp-mandate/tls.crt"
//! key = "/etc/mcp-mandate/tls.key"
//! # or: terminated_by_proxy = true          (a proxy in front handles HTTPS)
//!
//! [identity]
//! issuer = "https://example.okta.com/oauth2/default"
//!
//! [servers.github]                          # served at /servers/github/mcp
//! url = "https://api.githubcopilot.com/mcp/"
//! policy = "github.policy.toml"
//! auth = { type = "bearer", token_env = "GITHUB_MCP_TOKEN" }
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use jsonwebtoken::Algorithm;
use mcp_mandate_pin::{Pins, PinsError};
use mcp_mandate_policy::{Policy, PolicyError};
use reqwest::Url;
use serde::Deserialize;

/// A secret read from the environment or a file. Its `Debug` output never
/// shows it.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    pub(super) fn new(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// A loaded, checked gateway configuration.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen: SocketAddr,
    /// What agents connect to, without a trailing slash.
    pub public_url: String,
    pub tls: Tls,
    pub identity: IdentityConfig,
    /// `Origin` headers allowed on requests. Browsers send one; agents
    /// usually don't. Any other origin is rejected (DNS rebinding).
    pub allowed_origins: Vec<String>,
    pub servers: BTreeMap<String, ServerConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tls {
    /// mcp-mandate serves HTTPS with this certificate and key.
    Serve { cert: PathBuf, key: PathBuf },
    /// Plain HTTP: a proxy in front terminates TLS.
    TerminatedByProxy,
    /// Plain HTTP on a loopback address, for local use and tests.
    Loopback,
}

#[derive(Debug, Clone)]
pub struct IdentityConfig {
    pub issuer: String,
    /// Where the issuer's signing keys are; found by OIDC discovery when
    /// not set.
    pub jwks_uri: Option<String>,
    /// The audience tokens must be for (besides each server's own URL).
    pub audience: String,
    pub algorithms: Vec<Algorithm>,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub name: String,
    pub url: Url,
    pub policy_path: PathBuf,
    pub policy: Policy,
    pub pins: Option<Pins>,
    /// Hashes of the policy and pins files as loaded, for the audit log.
    pub policy_sha256: Option<String>,
    pub pins_sha256: Option<String>,
    pub auth: Auth,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("name", &self.name)
            .field("url", &self.url.as_str())
            .field("policy", &self.policy_path)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

/// How the gateway signs in to a server. Never with the caller's token.
#[derive(Debug, Clone)]
pub enum Auth {
    /// The server needs no credential.
    None,
    /// A static secret sent in a header (`Authorization: Bearer …` for
    /// `type = "bearer"`).
    Header { name: String, value: Secret },
    /// OAuth client credentials: short-lived tokens from `token_url`.
    ClientCredentials {
        token_url: Url,
        client_id: String,
        client_secret: Secret,
        scope: Option<String>,
        /// The `resource` asked for (RFC 8707); the server's URL by default.
        resource: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("couldn't read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{} isn't a valid gateway configuration", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("{0}")]
    Invalid(String),
    #[error("server `{server}`: couldn't load its policy")]
    Policy {
        server: String,
        #[source]
        source: Box<PolicyError>,
    },
    #[error("server `{server}`: couldn't load its pins")]
    Pins {
        server: String,
        #[source]
        source: Box<PinsError>,
    },
    #[error("server `{server}`: couldn't read the secret in {}", path.display())]
    SecretFile {
        server: String,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    listen: String,
    public_url: String,
    #[serde(default)]
    tls: TlsFile,
    identity: IdentityFile,
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default)]
    servers: BTreeMap<String, ServerFile>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsFile {
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    #[serde(default)]
    terminated_by_proxy: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    issuer: String,
    jwks_uri: Option<String>,
    audience: Option<String>,
    algorithms: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerFile {
    url: String,
    policy: PathBuf,
    auth: AuthFile,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum AuthFile {
    None,
    Bearer {
        token_env: Option<String>,
        token_file: Option<PathBuf>,
    },
    Header {
        name: String,
        value_env: Option<String>,
        value_file: Option<PathBuf>,
    },
    ClientCredentials {
        token_url: String,
        client_id: String,
        client_secret_env: Option<String>,
        client_secret_file: Option<PathBuf>,
        scope: Option<String>,
        resource: Option<String>,
    },
}

/// Signature algorithms accepted when the configuration doesn't say. All
/// asymmetric: a shared-secret (HS*) token could be forged by anyone who
/// knows the secret, so those are never accepted.
const DEFAULT_ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

impl GatewayConfig {
    /// Loads the configuration at `path`, each server's policy and pins,
    /// and every secret (so a missing one stops the start, not a request).
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::load_with(path, Pinned::Load)
    }

    /// Like [`load`](Self::load), but without the pins files, which may not
    /// exist yet: for listing a server to pin or review it.
    pub fn load_without_pins(path: &Path) -> Result<Self, ConfigError> {
        Self::load_with(path, Pinned::Skip)
    }

    fn load_with(path: &Path, pinned: Pinned) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let file: ConfigFile = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::check(file, base, &|name| std::env::var(name).ok(), pinned)
    }

    fn check(
        file: ConfigFile,
        base: &Path,
        env: &dyn Fn(&str) -> Option<String>,
        pinned: Pinned,
    ) -> Result<Self, ConfigError> {
        let invalid = |message: String| ConfigError::Invalid(message);
        let listen: SocketAddr = file.listen.parse().map_err(|_| {
            invalid(format!(
                "`listen = {:?}` isn't an address and port, such as \"0.0.0.0:8443\"",
                file.listen
            ))
        })?;

        let tls = match (file.tls.cert, file.tls.key, file.tls.terminated_by_proxy) {
            (Some(cert), Some(key), false) => Tls::Serve {
                cert: base.join(cert),
                key: base.join(key),
            },
            (None, None, true) => Tls::TerminatedByProxy,
            (None, None, false) if listen.ip().is_loopback() => Tls::Loopback,
            (None, None, false) => {
                return Err(invalid(format!(
                    "listening on {listen} without TLS: set [tls] cert and key, or `terminated_by_proxy = true` if a proxy in front handles HTTPS"
                )));
            }
            (_, _, true) => {
                return Err(invalid(
                    "[tls] sets a certificate and `terminated_by_proxy`: choose one".to_owned(),
                ));
            }
            _ => return Err(invalid("[tls] needs both `cert` and `key`".to_owned())),
        };

        let public_url = safe_url("public_url", &file.public_url)?;
        let public_url = public_url.as_str().trim_end_matches('/').to_owned();

        safe_url("identity.issuer", &file.identity.issuer)?;
        // Kept exactly as written: tokens' `iss` must match it character
        // for character.
        let issuer = file.identity.issuer.trim().to_owned();
        let jwks_uri = file
            .identity
            .jwks_uri
            .map(|uri| safe_url("identity.jwks_uri", &uri).map(|_| uri))
            .transpose()?;
        let algorithms = match file.identity.algorithms {
            None => DEFAULT_ALGORITHMS.to_vec(),
            Some(names) => names
                .iter()
                .map(|name| algorithm(name))
                .collect::<Result<_, _>>()?,
        };
        let identity = IdentityConfig {
            issuer,
            jwks_uri,
            audience: file.identity.audience.unwrap_or_else(|| public_url.clone()),
            algorithms,
        };

        let mut servers = BTreeMap::new();
        for (name, server) in file.servers {
            servers.insert(
                name.clone(),
                check_server(&name, server, base, env, pinned)?,
            );
        }
        if servers.is_empty() {
            return Err(invalid("no [servers.<name>] are configured".to_owned()));
        }
        Ok(Self {
            listen,
            public_url,
            tls,
            identity,
            allowed_origins: file.allowed_origins,
            servers,
        })
    }

    /// The URL agents use for `server`, which is also an audience its
    /// tokens may carry.
    pub fn server_url(&self, server: &str) -> String {
        format!("{}/servers/{server}/mcp", self.public_url)
    }
}

/// Whether to load each server's pins file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pinned {
    Load,
    Skip,
}

fn check_server(
    name: &str,
    server: ServerFile,
    base: &Path,
    env: &dyn Fn(&str) -> Option<String>,
    pinned: Pinned,
) -> Result<ServerConfig, ConfigError> {
    let valid_name = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !valid_name {
        return Err(ConfigError::Invalid(format!(
            "server name `{name}`: use 1 to 64 lowercase letters, digits, `-` or `_` (it becomes part of a URL)"
        )));
    }
    let url = safe_url(&format!("servers.{name}.url"), &server.url)?;
    let policy_path = base.join(&server.policy);
    // Each file is read once, and what's parsed is what's hashed for the
    // audit log, so the hashes describe exactly what the gate enforces.
    let policy_error = |source: PolicyError| ConfigError::Policy {
        server: name.to_owned(),
        source: Box::new(source),
    };
    let policy_text = std::fs::read_to_string(&policy_path).map_err(|source| {
        policy_error(PolicyError::Read {
            path: policy_path.clone(),
            source,
        })
    })?;
    let policy = Policy::parse_file(&policy_text, &policy_path).map_err(policy_error)?;
    let policy_sha256 = Some(mcp_mandate_audit::sha256_hex(policy_text.as_bytes()));
    let (pins, pins_sha256) = match (pinned, policy.pins.as_deref()) {
        (Pinned::Load, Some(path)) => {
            let pins_error = |source: PinsError| ConfigError::Pins {
                server: name.to_owned(),
                source: Box::new(source),
            };
            let text = std::fs::read_to_string(path).map_err(|source| {
                pins_error(PinsError::Read {
                    path: path.to_owned(),
                    source,
                })
            })?;
            let pins = Pins::parse(&text, path).map_err(pins_error)?;
            (
                Some(pins),
                Some(mcp_mandate_audit::sha256_hex(text.as_bytes())),
            )
        }
        _ => (None, None),
    };
    let secret = |variable: Option<String>, file: Option<PathBuf>, what: &str| {
        read_secret(name, what, variable, file.map(|file| base.join(file)), env)
    };
    let auth = match server.auth {
        AuthFile::None => Auth::None,
        AuthFile::Bearer {
            token_env,
            token_file,
        } => Auth::Header {
            name: "authorization".to_owned(),
            value: Secret(format!(
                "Bearer {}",
                secret(token_env, token_file, "token")?.expose()
            )),
        },
        AuthFile::Header {
            name: header,
            value_env,
            value_file,
        } => {
            let header = header.to_ascii_lowercase();
            if reqwest::header::HeaderName::from_bytes(header.as_bytes()).is_err() {
                return Err(ConfigError::Invalid(format!(
                    "server `{name}`: `{header}` isn't a valid header name"
                )));
            }
            Auth::Header {
                name: header,
                value: secret(value_env, value_file, "value")?,
            }
        }
        AuthFile::ClientCredentials {
            token_url,
            client_id,
            client_secret_env,
            client_secret_file,
            scope,
            resource,
        } => Auth::ClientCredentials {
            token_url: safe_url(&format!("servers.{name}.auth.token_url"), &token_url)?,
            client_id,
            client_secret: secret(client_secret_env, client_secret_file, "client_secret")?,
            scope,
            resource: resource.unwrap_or_else(|| url.as_str().to_owned()),
        },
    };
    Ok(ServerConfig {
        name: name.to_owned(),
        url,
        policy_sha256,
        policy_path,
        policy,
        pins,
        pins_sha256,
        auth,
    })
}

/// Reads a secret from exactly one of an environment variable or a file.
fn read_secret(
    server: &str,
    what: &str,
    variable: Option<String>,
    file: Option<PathBuf>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Secret, ConfigError> {
    let value = match (variable, file) {
        (Some(variable), None) => env(&variable).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "server `{server}`: the environment variable {variable} (its {what}) isn't set"
            ))
        })?,
        (None, Some(path)) => std::fs::read_to_string(&path)
            .map_err(|source| ConfigError::SecretFile {
                server: server.to_owned(),
                path,
                source,
            })?
            .trim()
            .to_owned(),
        _ => {
            return Err(ConfigError::Invalid(format!(
                "server `{server}`: give its {what} as exactly one of `{what}_env` (an environment variable) or `{what}_file` (never the secret itself)"
            )));
        }
    };
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(format!(
            "server `{server}`: its {what} is empty or contains control characters"
        )));
    }
    Ok(Secret(value))
}

/// Parses a URL that must use HTTPS (plain HTTP only to this machine) and
/// must not carry credentials.
fn safe_url(field: &str, text: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(text.trim())
        .map_err(|_| ConfigError::Invalid(format!("`{field}` isn't a URL: {text:?}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::Invalid(format!(
            "`{field}` contains a user name or password; give credentials through `auth`"
        )));
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback(&url) => Ok(url),
        _ => Err(ConfigError::Invalid(format!(
            "`{field}` must use https:// (plain http:// only for localhost): {text:?}"
        ))),
    }
}

pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

fn algorithm(name: &str) -> Result<Algorithm, ConfigError> {
    DEFAULT_ALGORITHMS
        .into_iter()
        .find(|algorithm| format!("{algorithm:?}") == name)
        .ok_or_else(|| {
            ConfigError::Invalid(format!(
                "identity.algorithms: `{name}` isn't accepted; use asymmetric ones such as RS256, ES256 or EdDSA (shared-secret HS* algorithms never are)"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mcp-mandate-gwconfig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("p.toml"), "").unwrap();
        dir
    }

    fn check(text: &str) -> Result<GatewayConfig, ConfigError> {
        let file: ConfigFile = toml::from_str(text).unwrap();
        GatewayConfig::check(
            file,
            &dir(),
            &|name| (name == "TOKEN").then(|| "s3cret".to_owned()),
            Pinned::Load,
        )
    }

    const SERVER: &str = r#"
[servers.github]
url = "https://mcp.example.com/mcp"
policy = "p.toml"
auth = { type = "bearer", token_env = "TOKEN" }
"#;

    fn config(top: &str) -> String {
        format!("{top}\n[identity]\nissuer = \"https://idp.example.com\"\n{SERVER}")
    }

    fn error(text: &str) -> String {
        match check(text) {
            Ok(_) => panic!("expected an error for:\n{text}"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn loads_a_valid_configuration() {
        let config = check(&config(
            "listen = \"127.0.0.1:8080\"\npublic_url = \"http://localhost:8080/\"",
        ))
        .unwrap();
        assert_eq!(config.tls, Tls::Loopback);
        assert_eq!(config.public_url, "http://localhost:8080");
        assert_eq!(config.identity.audience, "http://localhost:8080");
        assert_eq!(
            config.server_url("github"),
            "http://localhost:8080/servers/github/mcp"
        );
        let Auth::Header { name, value } = &config.servers["github"].auth else {
            panic!("expected a header credential");
        };
        assert_eq!(name, "authorization");
        assert_eq!(value.expose(), "Bearer s3cret");
        assert!(
            !format!("{config:?}").contains("s3cret"),
            "secrets stay out of Debug"
        );
        assert!(!config.identity.algorithms.contains(&Algorithm::HS256));
    }

    #[test]
    fn records_the_hash_of_the_policy_it_parsed() {
        let top = "listen = \"127.0.0.1:8080\"\npublic_url = \"http://localhost:8080\"";
        let config = check(&config(top)).unwrap();
        let server = &config.servers["github"];
        let empty = mcp_mandate_audit::sha256_hex(b"");
        assert_eq!(server.policy_sha256.as_deref(), Some(empty.as_str()));
        assert_eq!(server.pins_sha256, None, "the policy names no pins file");
    }

    #[test]
    fn the_example_configuration_is_valid_toml_for_this_format() {
        let example = include_str!("../../../../policies/gateway.example.toml");
        let parsed = toml::from_str::<ConfigFile>(example);
        assert!(parsed.is_ok(), "{:?}", parsed.err());
    }

    #[test]
    fn refuses_plain_http_off_this_machine_unless_a_proxy_handles_tls() {
        let open = config("listen = \"0.0.0.0:8080\"\npublic_url = \"https://gate.example.com\"");
        assert!(error(&open).contains("without TLS"));
        let proxied = config(
            "listen = \"0.0.0.0:8080\"\npublic_url = \"https://gate.example.com\"\n[tls]\nterminated_by_proxy = true",
        );
        assert_eq!(check(&proxied).unwrap().tls, Tls::TerminatedByProxy);
    }

    #[test]
    fn refuses_unsafe_urls_secrets_and_algorithms() {
        let top = "listen = \"127.0.0.1:8080\"\npublic_url = \"http://localhost:8080\"";
        let http_server = config(top).replace("https://mcp.example.com", "http://mcp.example.com");
        assert!(error(&http_server).contains("must use https://"));
        let userinfo = config(top).replace("https://mcp", "https://bob:pw@mcp");
        assert!(error(&userinfo).contains("user name or password"));
        let unset = config(top).replace("token_env = \"TOKEN\"", "token_env = \"NOPE\"");
        assert!(error(&unset).contains("NOPE"));
        let inline = config(top).replace("token_env = \"TOKEN\"", "token = \"abc\"");
        assert!(
            toml::from_str::<ConfigFile>(&inline).is_err(),
            "inline secrets aren't a field"
        );
        let hmac = config(top).replace(
            "issuer = \"https://idp.example.com\"",
            "issuer = \"https://idp.example.com\"\nalgorithms = [\"HS256\"]",
        );
        assert!(error(&hmac).contains("never are"));
        let bad_name = config(top).replace("[servers.github]", "[servers.\"Git Hub\"]");
        assert!(error(&bad_name).contains("server name"));
    }
}
