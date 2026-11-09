//! Unified error types for the proxy.

use thiserror::Error;

/// Top-level error type for proxy operations.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    #[error("certificate validation failed: {0}")]
    CertValidation(String),

    #[error("identity extraction failed: {0}")]
    IdentityExtraction(String),

    #[error("policy denied request: {0}")]
    PolicyDenied(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("request body too large: {size} bytes exceeds limit of {limit}")]
    BodyTooLarge { size: usize, limit: usize },

    #[error("request timeout after {0}ms")]
    Timeout(u64),

    #[error("concurrency limit reached")]
    ConcurrencyLimit,

    #[error("rate limit exceeded")]
    RateLimit,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("trust store reload failed: {0}")]
    TrustReload(String),

    #[error("internal error: {0}")]
    Internal(String),
}
