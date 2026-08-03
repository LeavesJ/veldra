//! reservegrid-common: Shared types, error codes, and configuration primitives.
//!
//! This crate is the single source of truth for:
//! - Unified reason codes (`ReasonCode`) spanning verification and gateway
//! - Gateway-specific reason codes (`GatewayReason`)
//! - Configuration schema and validation
//! - Redacted wrapper for secret-bearing values
//! - Shared error response types
//! - Process-level rustls `CryptoProvider` installation, behind the
//!   opt-in `rustls-provider` feature (`crypto_provider`)

pub mod config;
pub mod config_io;
#[cfg(feature = "rustls-provider")]
pub mod crypto_provider;
pub mod error;
pub mod metrics;
pub mod mode;
pub mod per_ip;
pub mod rate_limit;
pub mod reason;
pub mod redacted;

// Re-export the most commonly used types at crate root for ergonomics.
pub use error::ErrorResponse;
pub use mode::DeployMode;
pub use per_ip::{PerIpConnectionTracker, PerIpPermit};
pub use rate_limit::RateLimiter;
pub use reason::{GatewayReason, ReasonCode};
