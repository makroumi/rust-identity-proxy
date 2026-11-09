//! TLS configuration and X.509 certificate identity extraction.
//!
//! This crate handles:
//! - Building rustls server configurations with mTLS client verification
//! - Extracting [`Identity`] from DER-encoded X.509 certificates
//! - Parsing SPIFFE URI SANs, Subject, Issuer, serial, and validity

pub mod config;
pub mod extract;

pub use config::build_server_config;
pub use extract::extract_identity;
