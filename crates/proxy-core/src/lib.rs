//! Shared types used by the identity-aware proxy crates.

pub mod audit;
pub mod error;
pub mod identity;
pub mod policy;

pub use error::ProxyError;
