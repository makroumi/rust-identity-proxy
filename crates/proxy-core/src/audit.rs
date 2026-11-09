//! Structured audit event types.
//!
//! Every proxied request produces an [`AuditEvent`] capturing the decision,
//! identity, timing, and outcome. Sensitive data (headers, cookies, credentials)
//! is never included.

use crate::identity::Identity;
use crate::policy::PolicyDecision;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A structured audit record for a single proxied request.
///
/// Security invariant: this struct must never contain request/response headers,
/// cookies, authorization tokens, or request/response bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique request identifier (UUID v4).
    pub request_id: String,
    /// Authenticated client identity, if mTLS handshake succeeded.
    pub identity: Option<IdentitySummary>,
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Request path (query string excluded).
    pub path: String,
    /// Policy decision and reason.
    pub decision: PolicyDecision,
    /// Upstream HTTP status code, if the request was forwarded.
    pub upstream_status: Option<u16>,
    /// Total request latency in milliseconds.
    pub latency_ms: u64,
    /// Unix timestamp in seconds.
    pub timestamp: String,
}

/// A privacy-safe summary of client identity for audit logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySummary {
    /// Canonical identifier (SPIFFE ID or Subject CN).
    pub canonical_id: String,
    /// Certificate serial number.
    pub serial: String,
    /// Certificate issuer.
    pub issuer: String,
}

impl From<&Identity> for IdentitySummary {
    fn from(id: &Identity) -> Self {
        Self {
            canonical_id: id.canonical_id().to_string(),
            serial: id.serial.clone(),
            issuer: id.issuer.clone(),
        }
    }
}

impl AuditEvent {
    /// Create a new audit event with a fresh UUID and current timestamp.
    pub fn new(
        identity: Option<&Identity>,
        method: &str,
        path: &str,
        decision: PolicyDecision,
        upstream_status: Option<u16>,
        latency_ms: u64,
    ) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            identity: identity.map(IdentitySummary::from),
            method: method.to_string(),
            path: path.to_string(),
            decision,
            upstream_status,
            latency_ms,
            timestamp: unix_now(),
        }
    }
}

fn unix_now() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_has_unique_ids() {
        let e1 = AuditEvent::new(None, "GET", "/", PolicyDecision::Allow, None, 10);
        let e2 = AuditEvent::new(None, "GET", "/", PolicyDecision::Allow, None, 10);
        assert_ne!(e1.request_id, e2.request_id);
    }

    #[test]
    fn audit_event_serializes_cleanly() {
        let event = AuditEvent::new(None, "GET", "/health", PolicyDecision::Allow, Some(200), 5);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("request_id"));
        assert!(json.contains("latency_ms"));
        // Must never contain sensitive fields
        let has_cookie = json.contains("cookie");
        let has_auth = json.contains("authorization");
        assert!(!has_cookie);
        assert!(!has_auth);
    }
}
