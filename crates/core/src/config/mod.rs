//! Configuration provider abstraction and implementations.
//!
//! The [`ConfigProvider`] trait defines how the proxy retrieves its
//! configuration (buckets, roles, credentials) from a backend store.
//! This allows the same core logic to work with static files, databases,
//! HTTP APIs, or any other configuration source.
//!
//! # Available Implementations
//!
//! | Provider | Feature Flag | Use Case |
//! |----------|-------------|----------|
//! | [`StaticProvider`](static_file::StaticProvider) | *(always available)* | TOML/JSON config files, baked-in config |
//!
//! The [`ConfigProvider`] trait makes it straightforward to implement custom
//! backends (Redis, HTTP APIs, databases, etc.) — see the docs for examples.

pub mod static_file;

use crate::error::ProxyError;
use crate::types::{BucketConfig, BucketOwner, RoleConfig, StoredCredential};
use std::future::Future;

/// Default owner name used in `ListAllMyBucketsResult` responses.
pub const DEFAULT_BUCKET_OWNER: &str = "multistore-proxy";

/// Trait for retrieving proxy configuration from a backend store.
///
/// Implementations should be cheap to clone (wrap inner state in `Arc`).
///
/// Temporary credentials are not stored via this trait — they are encrypted
/// into self-contained session tokens using [`TokenKey`](crate::sealed_token::TokenKey).
pub trait ConfigProvider: Clone + Send + Sync + 'static {
    fn list_buckets(&self) -> impl Future<Output = Result<Vec<BucketConfig>, ProxyError>> + Send;

    fn get_bucket(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<BucketConfig>, ProxyError>> + Send;

    fn get_role(
        &self,
        role_id: &str,
    ) -> impl Future<Output = Result<Option<RoleConfig>, ProxyError>> + Send;

    /// Look up a long-lived credential by its access key ID.
    fn get_credential(
        &self,
        access_key_id: &str,
    ) -> impl Future<Output = Result<Option<StoredCredential>, ProxyError>> + Send;

    /// The owner identity returned in `ListAllMyBucketsResult` responses.
    ///
    /// Defaults to `("multistore-proxy", "multistore-proxy")`.
    fn bucket_owner(&self) -> BucketOwner {
        BucketOwner {
            id: DEFAULT_BUCKET_OWNER.to_string(),
            display_name: DEFAULT_BUCKET_OWNER.to_string(),
        }
    }
}
