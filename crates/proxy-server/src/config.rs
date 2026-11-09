//! Server configuration loaded from TOML.

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub policy: PolicyConfig,
    pub limits: LimitsConfig,
    pub trust: TrustConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    #[serde(default = "default_health_addr")]
    pub health_addr: String,
    pub upstream_url: String,
    #[serde(default)]
    pub allow_insecure_upstream: bool,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    #[serde(default)]
    pub upstream_ca: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyConfig {
    pub policy_file: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    pub max_body_bytes: usize,
    pub request_timeout_secs: u64,
    pub max_concurrency: usize,
    pub rate_limit_rps: u64,
    pub rate_limit_burst: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

#[derive(Debug, Deserialize)]
pub struct TrustConfig {
    pub ca_bundle_path: PathBuf,
}

fn default_max_connections() -> usize {
    4096
}

fn default_health_addr() -> String {
    "127.0.0.1:9090".to_string()
}

impl ProxyConfig {
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: ProxyConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let listen_addr: std::net::SocketAddr = self
            .server
            .listen_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|error| anyhow::anyhow!("invalid server.listen_addr: {error}"))?;
        let health_addr: std::net::SocketAddr = self
            .server
            .health_addr
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid server.health_addr: {error}"))?;
        if !health_addr.ip().is_loopback() {
            anyhow::bail!("server.health_addr must bind to a loopback address");
        }
        if listen_addr.port() == health_addr.port()
            && (listen_addr.ip().is_unspecified() || listen_addr.ip() == health_addr.ip())
        {
            anyhow::bail!("server.health_addr must not conflict with server.listen_addr");
        }

        let upstream: http::Uri = self
            .server
            .upstream_url
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid server.upstream_url: {error}"))?;
        if upstream.authority().is_none()
            || !matches!(upstream.scheme_str(), Some("http" | "https"))
            || upstream.query().is_some()
            || upstream.path() != "" && upstream.path() != "/"
        {
            anyhow::bail!("server.upstream_url must be an HTTP(S) origin without a path or query");
        }
        if upstream.scheme_str() == Some("http") && !self.server.allow_insecure_upstream {
            anyhow::bail!(
                "plain HTTP upstreams are disabled; use HTTPS or explicitly set \
                 server.allow_insecure_upstream = true for a trusted development network"
            );
        }

        if self.limits.max_body_bytes == 0
            || self.limits.request_timeout_secs == 0
            || self.limits.max_concurrency == 0
            || self.limits.rate_limit_rps == 0
            || self.limits.rate_limit_burst == 0
            || self.limits.max_connections == 0
        {
            anyhow::bail!("all configured request limits must be greater than zero");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(upstream_url: &str, allow_insecure_upstream: bool) -> ProxyConfig {
        ProxyConfig {
            server: ServerConfig {
                listen_addr: "127.0.0.1:8443".into(),
                health_addr: "127.0.0.1:9090".into(),
                upstream_url: upstream_url.into(),
                allow_insecure_upstream,
            },
            tls: TlsConfig {
                server_cert: "server.crt".into(),
                server_key: "server.key".into(),
                upstream_ca: None,
            },
            policy: PolicyConfig {
                policy_file: "policies.yaml".into(),
            },
            limits: LimitsConfig {
                max_body_bytes: 1024,
                request_timeout_secs: 1,
                max_concurrency: 10,
                rate_limit_rps: 10,
                rate_limit_burst: 20,
                max_connections: 20,
            },
            trust: TrustConfig {
                ca_bundle_path: "client-ca.crt".into(),
            },
        }
    }

    #[test]
    fn allows_https_upstream_without_insecure_override() {
        assert!(config("https://backend.internal", false).validate().is_ok());
    }

    #[test]
    fn rejects_plain_http_upstream_by_default() {
        assert!(config("http://127.0.0.1:8080", false).validate().is_err());
    }

    #[test]
    fn allows_explicit_http_development_upstream() {
        assert!(config("http://127.0.0.1:8080", true).validate().is_ok());
    }

    #[test]
    fn rejects_upstream_paths_and_queries() {
        assert!(config("https://backend.internal/api", false)
            .validate()
            .is_err());
        assert!(config("https://backend.internal?debug=true", false)
            .validate()
            .is_err());
    }

    #[test]
    fn rejects_zero_limits() {
        let mut config = config("https://backend.internal", false);
        config.limits.max_concurrency = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_non_loopback_health_address() {
        let mut config = config("https://backend.internal", false);
        config.server.health_addr = "0.0.0.0:9090".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_conflicting_health_address() {
        let mut config = config("https://backend.internal", false);
        config.server.listen_addr = "0.0.0.0:9090".into();
        config.server.health_addr = "127.0.0.1:9090".into();
        assert!(config.validate().is_err());
    }
}
