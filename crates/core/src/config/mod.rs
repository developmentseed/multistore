//! Configuration provider implementations.
//!
//! Configuration is loaded through two registry traits:
//!
//! - [`BucketRegistry`](crate::registry::BucketRegistry) — bucket lookup, authorization, and listing
//! - [`CredentialRegistry`](crate::registry::CredentialRegistry) — credential and role storage
//!
//! # Available Implementations
//!
//! | Provider | Feature Flag | Use Case |
//! |----------|-------------|----------|
//! | [`StaticProvider`](static_file::StaticProvider) | *(always available)* | TOML/JSON config files, baked-in config |

pub mod static_file;

/// Default owner name used in `ListAllMyBucketsResult` responses.
pub const DEFAULT_BUCKET_OWNER: &str = "multistore-proxy";
