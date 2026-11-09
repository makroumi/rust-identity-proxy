//! Rustls server configuration builder with mTLS support.

use proxy_core::ProxyError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use std::sync::Arc;

/// Build a rustls `ServerConfig` with mandatory mTLS client verification.
pub fn build_server_config(
    server_cert: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca_store: RootCertStore,
) -> Result<rustls::ServerConfig, ProxyError> {
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_ca_store))
        .build()
        .map_err(|e| ProxyError::Config(format!("client verifier build failed: {e}")))?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_cert, server_key)
        .map_err(|e| ProxyError::Config(format!("server config build failed: {e}")))?;

    Ok(config)
}

/// Load PEM-encoded certificates into a `RootCertStore`.
pub fn load_root_store(pem_data: &[u8]) -> Result<RootCertStore, ProxyError> {
    let mut store = RootCertStore::empty();
    let certs = CertificateDer::pem_slice_iter(pem_data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ProxyError::Config(format!("PEM parse failed: {e}")))?;

    if certs.is_empty() {
        return Err(ProxyError::Config(
            "no certificates found in PEM data".into(),
        ));
    }

    for cert in certs {
        store
            .add(cert)
            .map_err(|e| ProxyError::Config(format!("failed to add cert to store: {e}")))?;
    }

    Ok(store)
}

/// Load PEM-encoded server certificate chain.
pub fn load_server_certs(pem_data: &[u8]) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let certs = CertificateDer::pem_slice_iter(pem_data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ProxyError::Config(format!("server cert PEM parse failed: {e}")))?;

    if certs.is_empty() {
        return Err(ProxyError::Config("no server certificates in PEM".into()));
    }

    Ok(certs)
}

/// Load PEM-encoded private key.
pub fn load_private_key(pem_data: &[u8]) -> Result<PrivateKeyDer<'static>, ProxyError> {
    let key = PrivateKeyDer::pem_slice_iter(pem_data)
        .next()
        .transpose()
        .map_err(|e| ProxyError::Config(format!("private key PEM parse failed: {e}")))?
        .ok_or_else(|| ProxyError::Config("no private key found in PEM".into()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    fn generate_ca_and_server() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut ca_params = CertificateParams::default();
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "Test CA");
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut srv_params = CertificateParams::default();
        let mut srv_dn = DistinguishedName::new();
        srv_dn.push(DnType::CommonName, "localhost");
        srv_params.distinguished_name = srv_dn;
        srv_params.subject_alt_names =
            vec![rcgen::SanType::DnsName("localhost".try_into().unwrap())];
        let srv_key = KeyPair::generate().unwrap();
        let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

        (
            ca_cert.pem().into_bytes(),
            srv_cert.pem().into_bytes(),
            ca_key.serialize_pem().into_bytes(),
            srv_key.serialize_pem().into_bytes(),
        )
    }

    #[test]
    fn load_root_store_from_pem() {
        let (ca_pem, _, _, _) = generate_ca_and_server();
        let store = load_root_store(&ca_pem).unwrap();
        assert!(!store.is_empty());
    }

    #[test]
    fn load_server_certs_from_pem() {
        let (_, srv_pem, _, _) = generate_ca_and_server();
        let certs = load_server_certs(&srv_pem).unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn load_private_key_from_pem() {
        let (_, _, _, key_pem) = generate_ca_and_server();
        let _key = load_private_key(&key_pem).unwrap();
    }

    #[test]
    fn build_config_succeeds() {
        let (ca_pem, srv_pem, _, srv_key_pem) = generate_ca_and_server();
        let store = load_root_store(&ca_pem).unwrap();
        let certs = load_server_certs(&srv_pem).unwrap();
        let key = load_private_key(&srv_key_pem).unwrap();
        let _config = build_server_config(certs, key, store).unwrap();
    }

    #[test]
    fn reject_empty_pem() {
        assert!(load_root_store(b"").is_err());
        assert!(load_server_certs(b"").is_err());
        assert!(load_private_key(b"").is_err());
    }
}
