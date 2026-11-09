//! File-based policy engine for identity-aware access control.
//!
//! Policies are defined in YAML and map identity patterns to allowed
//! method+path combinations. Path matching is segment-wise to prevent
//! traversal bypass attacks.

pub mod engine;
pub mod matcher;

pub use engine::YamlPolicyEngine;
