//! X.509 certificate parsing and identity extraction.
//!
//! Uses `x509-parser` to extract identity fields from DER-encoded certificates.
//! This operates at the application layer on certificates that have already been
//! validated by the TLS layer (rustls).

use proxy_core::identity::{Identity, San};
use proxy_core::ProxyError;
use x509_parser::prelude::*;

/// Extract an [`Identity`] from a DER-encoded X.509 certificate.
///
/// The certificate must have already passed TLS-layer validation. This function
/// performs application-layer field extraction only.
pub fn extract_identity(cert_der: &[u8]) -> Result<Identity, ProxyError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| ProxyError::IdentityExtraction(format!("DER parse failed: {e}")))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let serial = hex_encode(cert.serial.to_bytes_be().as_ref());

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    let sans = extract_sans(&cert)?;

    Ok(Identity {
        subject,
        issuer,
        sans,
        serial,
        not_before,
        not_after,
        chain_depth: 1,
    })
}

fn extract_sans(cert: &X509Certificate<'_>) -> Result<Vec<San>, ProxyError> {
    let mut sans = Vec::new();

    let san_ext = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext,
        Ok(None) => return Ok(sans),
        Err(e) => {
            return Err(ProxyError::IdentityExtraction(format!(
                "SAN extension parse error: {e}"
            )));
        }
    };

    for name in &san_ext.value.general_names {
        match name {
            GeneralName::DNSName(dns) => sans.push(San::Dns(dns.to_string())),
            GeneralName::RFC822Name(email) => sans.push(San::Email(email.to_string())),
            GeneralName::URI(uri) => sans.push(San::Uri(uri.to_string())),
            GeneralName::IPAddress(ip) => {
                let ip_str = match ip.len() {
                    4 => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                    16 => format!(
                        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                        ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]
                    ),
                    _ => format!("{ip:?}"),
                };
                sans.push(San::Ip(ip_str));
            }
            _ => {}
        }
    }

    Ok(sans)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};

    fn generate_test_cert(sans: Vec<SanType>) -> Vec<u8> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test-agent");
        params.distinguished_name = dn;
        params.subject_alt_names = sans;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn extract_basic_identity() {
        let der = generate_test_cert(vec![]);
        let id = extract_identity(&der).unwrap();
        assert!(id.subject.contains("test-agent"));
        assert!(!id.serial.is_empty());
    }

    #[test]
    fn extract_spiffe_san() {
        let der = generate_test_cert(vec![SanType::URI(
            "spiffe://arkion.internal/agent/99".try_into().unwrap(),
        )]);
        let id = extract_identity(&der).unwrap();
        assert_eq!(id.spiffe_id(), Some("spiffe://arkion.internal/agent/99"));
    }

    #[test]
    fn extract_dns_san() {
        let der = generate_test_cert(vec![SanType::DnsName("agent.internal".try_into().unwrap())]);
        let id = extract_identity(&der).unwrap();
        let has_dns = id
            .sans
            .iter()
            .any(|s| matches!(s, San::Dns(d) if d == "agent.internal"));
        assert!(has_dns);
    }

    #[test]
    fn reject_garbage_der() {
        let result = extract_identity(b"not a certificate");
        assert!(result.is_err());
    }

    #[test]
    fn validity_window_extracted() {
        let der = generate_test_cert(vec![]);
        let id = extract_identity(&der).unwrap();
        assert!(id.not_before > 0);
        assert!(id.not_after > id.not_before);
    }
}
