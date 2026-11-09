//! Client certificate identity fields shared by the TLS and policy layers.

use serde::{Deserialize, Serialize};

/// A subject alternative name extracted from a client certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum San {
    Dns(String),
    Email(String),
    Uri(String),
    Ip(String),
}

/// Identity information extracted from a TLS-validated client certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<San>,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub chain_depth: usize,
}

impl Identity {
    /// Return the SPIFFE URI SAN when present.
    pub fn spiffe_id(&self) -> Option<&str> {
        self.sans.iter().find_map(|san| match san {
            San::Uri(uri) if uri.starts_with("spiffe://") => Some(uri.as_str()),
            _ => None,
        })
    }

    /// Return the SPIFFE ID when available, otherwise the subject common name.
    pub fn canonical_id(&self) -> &str {
        if let Some(spiffe_id) = self.spiffe_id() {
            return spiffe_id;
        }

        self.subject
            .split(',')
            .map(str::trim)
            .find(|attribute| attribute.starts_with("CN="))
            .unwrap_or(&self.subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(subject: &str, sans: Vec<San>) -> Identity {
        Identity {
            subject: subject.to_string(),
            issuer: "CN=CA".to_string(),
            sans,
            serial: "01".to_string(),
            not_before: 0,
            not_after: i64::MAX,
            chain_depth: 1,
        }
    }

    #[test]
    fn canonical_id_prefers_spiffe_uri() {
        let id = identity(
            "CN=agent-42,O=Arkion",
            vec![San::Uri("spiffe://arkion.internal/agent/42".to_string())],
        );
        assert_eq!(id.canonical_id(), "spiffe://arkion.internal/agent/42");
    }

    #[test]
    fn canonical_id_falls_back_to_common_name() {
        let id = identity("O=Arkion,CN=admin", Vec::new());
        assert_eq!(id.canonical_id(), "CN=admin");
    }
}
