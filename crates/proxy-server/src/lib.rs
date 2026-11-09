//! Identity-aware TLS reverse proxy server.
//!
//! Provides the main proxy server with mTLS validation, identity extraction,
//! policy enforcement, structured audit logging, upstream forwarding,
//! dynamic trust store hot-reload, and resilience middleware.

pub mod audit_layer;
pub mod config;
pub mod limits;
pub mod upstream;
