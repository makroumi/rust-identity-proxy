//! Policy decision types and the [`PolicyEngine`] trait.
//!
//! Policy engines evaluate whether an authenticated identity is authorized
//! to perform a specific HTTP method on a specific path.

use crate::identity::Identity;
use serde::{Deserialize, Serialize};

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// The request is authorized.
    Allow,
    /// The request is denied with a human-readable reason.
    Deny(String),
}

impl PolicyDecision {
    /// Returns true if the decision is Allow.
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

/// Trait for policy evaluation engines.
///
/// Implementations must be `Send + Sync` to support concurrent request handling.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate whether the given identity may perform `method` on `path`.
    fn evaluate(&self, identity: &Identity, method: &str, path: &str) -> PolicyDecision;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_is_allowed() {
        assert!(PolicyDecision::Allow.is_allowed());
    }

    #[test]
    fn deny_is_not_allowed() {
        assert!(!PolicyDecision::Deny("no".into()).is_allowed());
    }
}
