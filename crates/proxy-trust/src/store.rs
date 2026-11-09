//! Hot-reload trust store implementation.

use arc_swap::ArcSwap;
use proxy_core::ProxyError;
use proxy_tls::config::load_root_store;
use rustls::RootCertStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A thread-safe, hot-reloadable trust store.
///
/// Internally uses `ArcSwap` for lock-free reads on the hot path.
/// The reload path validates the new bundle before swapping.
pub struct HotReloadTrustStore {
    store: ArcSwap<RootCertStore>,
    ca_path: PathBuf,
}

impl HotReloadTrustStore {
    /// Create a new trust store by loading the CA bundle from the given path.
    pub fn new(ca_path: &Path) -> Result<Self, ProxyError> {
        let pem = std::fs::read(ca_path)
            .map_err(|e| ProxyError::TrustReload(format!("initial CA load: {e}")))?;
        let store = load_root_store(&pem)?;
        tracing::info!(path = %ca_path.display(), "trust store initialized");
        Ok(Self {
            store: ArcSwap::from_pointee(store),
            ca_path: ca_path.to_path_buf(),
        })
    }

    /// Get a snapshot of the current root cert store.
    ///
    /// This is lock-free and safe to call from the hot path.
    pub fn current_store(&self) -> Arc<RootCertStore> {
        self.store.load_full()
    }

    /// Reload the CA bundle from the configured file path.
    ///
    /// Validates the new bundle before swapping. If validation fails,
    /// the existing store is retained (automatic rollback).
    pub fn reload(&self) -> Result<(), ProxyError> {
        let pem = std::fs::read(&self.ca_path)
            .map_err(|e| ProxyError::TrustReload(format!("CA file read: {e}")))?;

        let new_store = load_root_store(&pem)?;
        let cert_count = new_store.len();

        if cert_count == 0 {
            return Err(ProxyError::TrustReload(
                "new CA bundle is empty, keeping existing store".into(),
            ));
        }

        self.store.store(Arc::new(new_store));
        tracing::info!(
            cert_count,
            path = %self.ca_path.display(),
            "trust store reloaded successfully"
        );
        Ok(())
    }

    /// Reload from arbitrary PEM data (useful for testing and API-driven rotation).
    pub fn reload_from_pem(&self, pem_data: &[u8]) -> Result<(), ProxyError> {
        let new_store = load_root_store(pem_data)?;
        if new_store.is_empty() {
            return Err(ProxyError::TrustReload(
                "provided CA bundle is empty".into(),
            ));
        }
        self.store.store(Arc::new(new_store));
        tracing::info!("trust store reloaded from PEM data");
        Ok(())
    }

    /// Get the path to the CA bundle file.
    pub fn ca_path(&self) -> &Path {
        &self.ca_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    fn generate_ca_pem(cn: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem().into_bytes()
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.crt");
        std::fs::write(&ca_path, generate_ca_pem("Test CA")).unwrap();

        let store = HotReloadTrustStore::new(&ca_path).unwrap();
        assert!(!store.current_store().is_empty());
    }

    #[test]
    fn reload_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.crt");
        std::fs::write(&ca_path, generate_ca_pem("CA v1")).unwrap();

        let store = HotReloadTrustStore::new(&ca_path).unwrap();
        let v1 = store.current_store();

        std::fs::write(&ca_path, generate_ca_pem("CA v2")).unwrap();
        store.reload().unwrap();
        let v2 = store.current_store();

        assert!(!Arc::ptr_eq(&v1, &v2));
    }

    #[test]
    fn reload_rejects_empty_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.crt");
        std::fs::write(&ca_path, generate_ca_pem("CA")).unwrap();

        let store = HotReloadTrustStore::new(&ca_path).unwrap();
        let v1 = store.current_store();

        std::fs::write(&ca_path, b"not a cert").unwrap();
        assert!(store.reload().is_err());

        // Original store retained (rollback)
        assert!(Arc::ptr_eq(&v1, &store.current_store()));
    }

    #[test]
    fn reload_from_pem_data() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.crt");
        std::fs::write(&ca_path, generate_ca_pem("CA v1")).unwrap();

        let store = HotReloadTrustStore::new(&ca_path).unwrap();
        let new_pem = generate_ca_pem("CA v2");
        store.reload_from_pem(&new_pem).unwrap();
        assert!(!store.current_store().is_empty());
    }
}
