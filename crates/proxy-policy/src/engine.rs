//! YAML-based policy engine implementation.

use crate::matcher;
use proxy_core::identity::Identity;
use proxy_core::policy::{PolicyDecision, PolicyEngine};
use serde::Deserialize;
use std::path::Path;

/// A policy rule loaded from YAML configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    /// Identity pattern (supports `*` and `**` wildcards).
    pub identity: String,
    /// List of allowed method+path combinations.
    pub allow: Vec<AllowEntry>,
}

/// A single allowed method+path combination.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowEntry {
    /// HTTP method or `"*"` for any method.
    pub method: String,
    /// Path pattern with segment-wise wildcards.
    pub path: String,
}

/// Top-level YAML policy configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub rules: Vec<PolicyRule>,
    #[serde(default = "default_deny")]
    pub default_action: String,
}

fn default_deny() -> String {
    "deny".to_string()
}

/// A policy engine backed by YAML-defined rules.
#[derive(Debug, Clone)]
pub struct YamlPolicyEngine {
    config: PolicyConfig,
}

impl YamlPolicyEngine {
    /// Load policies from a YAML file.
    pub fn from_file(path: &Path) -> Result<Self, proxy_core::ProxyError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| proxy_core::ProxyError::Config(format!("policy file read: {e}")))?;
        Self::from_yaml(&content)
    }

    /// Parse policies from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, proxy_core::ProxyError> {
        let config: PolicyConfig = noyalib::from_str(yaml)
            .map_err(|e| proxy_core::ProxyError::Config(format!("policy YAML parse: {e}")))?;
        if config.default_action != "deny" {
            return Err(proxy_core::ProxyError::Config(
                "only default_action: deny is supported".into(),
            ));
        }
        tracing::info!(rule_count = config.rules.len(), "loaded policy rules");
        Ok(Self { config })
    }
}

impl PolicyEngine for YamlPolicyEngine {
    fn evaluate(&self, identity: &Identity, method: &str, path: &str) -> PolicyDecision {
        let canonical = identity.canonical_id();
        let method_upper = method.to_uppercase();

        for rule in &self.config.rules {
            if !matcher::identity_matches(&rule.identity, canonical) {
                continue;
            }

            for allow in &rule.allow {
                let method_ok = allow.method == "*" || allow.method.to_uppercase() == method_upper;
                let path_ok = matcher::path_matches(&allow.path, path);

                if method_ok && path_ok {
                    return PolicyDecision::Allow;
                }
            }
        }

        PolicyDecision::Deny(format!(
            "identity {canonical} not authorized for {method_upper} {path}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_core::identity::{Identity, San};

    fn spiffe_identity(spiffe: &str) -> Identity {
        Identity {
            subject: "CN=test".to_string(),
            issuer: "CN=CA".to_string(),
            sans: vec![San::Uri(spiffe.to_string())],
            serial: "01".to_string(),
            not_before: 0,
            not_after: i64::MAX,
            chain_depth: 2,
        }
    }

    fn cn_identity(cn: &str) -> Identity {
        Identity {
            subject: format!("CN={cn}"),
            issuer: "CN=CA".to_string(),
            sans: vec![],
            serial: "01".to_string(),
            not_before: 0,
            not_after: i64::MAX,
            chain_depth: 2,
        }
    }

    const TEST_YAML: &str = r#"
rules:
  - identity: "spiffe://arkion.internal/agent/*"
    allow:
      - method: GET
        path: "/api/v1/identity/**"
      - method: POST
        path: "/api/v1/credentials/short-lived"
  - identity: "CN=admin"
    allow:
      - method: "*"
        path: "/**"
default_action: deny
"#;

    #[test]
    fn agent_allowed_get_identity() {
        let engine = YamlPolicyEngine::from_yaml(TEST_YAML).unwrap();
        let id = spiffe_identity("spiffe://arkion.internal/agent/42");
        let decision = engine.evaluate(&id, "GET", "/api/v1/identity/self");
        assert!(decision.is_allowed());
    }

    #[test]
    fn agent_denied_delete() {
        let engine = YamlPolicyEngine::from_yaml(TEST_YAML).unwrap();
        let id = spiffe_identity("spiffe://arkion.internal/agent/42");
        let decision = engine.evaluate(&id, "DELETE", "/api/v1/identity/self");
        assert!(!decision.is_allowed());
    }

    #[test]
    fn agent_denied_admin_path() {
        let engine = YamlPolicyEngine::from_yaml(TEST_YAML).unwrap();
        let id = spiffe_identity("spiffe://arkion.internal/agent/42");
        let decision = engine.evaluate(&id, "GET", "/admin/users");
        assert!(!decision.is_allowed());
    }

    #[test]
    fn admin_allowed_everything() {
        let engine = YamlPolicyEngine::from_yaml(TEST_YAML).unwrap();
        let id = cn_identity("admin");
        assert!(engine
            .evaluate(&id, "DELETE", "/anything/at/all")
            .is_allowed());
    }

    #[test]
    fn unknown_identity_denied() {
        let engine = YamlPolicyEngine::from_yaml(TEST_YAML).unwrap();
        let id = cn_identity("unknown");
        assert!(!engine.evaluate(&id, "GET", "/api/v1/health").is_allowed());
    }

    #[test]
    fn traversal_bypass_denied() {
        let engine = YamlPolicyEngine::from_yaml(TEST_YAML).unwrap();
        let id = spiffe_identity("spiffe://arkion.internal/agent/42");
        let decision = engine.evaluate(&id, "GET", "/api/v1/identity/../../admin/secret");
        assert!(!decision.is_allowed());
    }

    #[test]
    fn percent_encoded_traversal_bypass_denied() {
        let engine = YamlPolicyEngine::from_yaml(TEST_YAML).unwrap();
        let id = spiffe_identity("spiffe://arkion.internal/agent/42");
        let decision = engine.evaluate(&id, "GET", "/api/v1/identity/%2e%2e/%2E%2e/admin/secret");
        assert!(!decision.is_allowed());
    }

    #[test]
    fn invalid_yaml_rejected() {
        let bad = "not: [valid: yaml";
        assert!(YamlPolicyEngine::from_yaml(bad).is_err());
    }

    #[test]
    fn unsupported_default_action_rejected() {
        let config = r#"
rules: []
default_action: allow
"#;
        assert!(YamlPolicyEngine::from_yaml(config).is_err());
    }
}
