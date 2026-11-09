//! Dynamic trust store with hot-reload capability.
//!
//! Wraps a `rustls::RootCertStore` in an `arc_swap::ArcSwap` to allow
//! atomic, lock-free replacement of the CA bundle without restarting the
//! proxy or dropping existing connections.
//!
//! ## Concurrency model
//!
//! - Existing TLS connections that completed the handshake continue using
//!   the certificate chain they validated against.
//! - New connections pick up the latest store atomically.
//! - The swap is lock-free via `arc-swap`, so there is no contention
//!   between the reload path and the hot path.
//!
//! The server owns the SIGHUP handler and calls this crate's reload API after
//! receiving the signal. This crate itself performs no background watching.

pub mod store;

pub use store::HotReloadTrustStore;
