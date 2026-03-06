//! Backend abstraction for proxying requests to backing object stores.
//!
//! [`ProxyBackend`] is the main trait runtimes implement. It provides three
//! capabilities:
//!
//! 1. **`create_paginated_store()`** — build a `PaginatedListStore` for LIST
//!    operations with backend-side pagination.
//! 2. **`create_signer()`** — build a `Signer` for generating presigned URLs
//!    for GET, HEAD, PUT, DELETE operations.
//! 3. **`send_raw()`** — send a pre-signed HTTP request for operations not
//!    covered by `ObjectStore` (multipart uploads).
//!
//! The [`url_signer`] submodule handles `object_store` signer construction.
//! Outbound SigV4 request signing lives in [`crate::s3::request_signer`].

pub mod url_signer;
pub use url_signer::build_signer;

use crate::error::ProxyError;
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::types::{BackendType, BucketConfig};
use bytes::Bytes;
use http::HeaderMap;
use object_store::aws::AmazonS3Builder;
use object_store::list::PaginatedListStore;
use object_store::signer::Signer;
use object_store::ObjectStore;
use std::future::Future;
use std::sync::Arc;

#[cfg(feature = "azure")]
use object_store::azure::MicrosoftAzureBuilder;
#[cfg(feature = "gcp")]
use object_store::gcp::GoogleCloudStorageBuilder;

/// Trait for runtime-specific backend operations.
///
/// Each runtime provides its own implementation:
/// - Server runtime: uses `reqwest` for raw HTTP, default `object_store` HTTP connector
/// - Worker runtime: uses `web_sys::fetch` for raw HTTP, custom `FetchConnector` for `object_store`
pub trait ProxyBackend: Clone + MaybeSend + MaybeSync + 'static {
    /// Create a [`PaginatedListStore`] for the given bucket configuration.
    ///
    /// Used for LIST operations with backend-side pagination via
    /// [`PaginatedListStore::list_paginated`], avoiding loading all results
    /// into memory.
    fn create_paginated_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Box<dyn PaginatedListStore>, ProxyError>;

    /// Create a `Signer` for generating presigned URLs.
    ///
    /// Used for GET, HEAD, PUT, DELETE operations. The handler generates
    /// a presigned URL and the runtime executes the request with its
    /// native HTTP client, enabling zero-copy streaming.
    fn create_signer(&self, config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError>;

    /// Send a raw HTTP request (used for multipart operations that
    /// `ObjectStore` doesn't expose at the right abstraction level).
    fn send_raw(
        &self,
        method: http::Method,
        url: String,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl Future<Output = Result<RawResponse, ProxyError>> + MaybeSend;
}

/// Response from a raw HTTP request to a backend.
pub struct RawResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Wrapper around provider-specific `object_store` builders.
///
/// Runtimes use [`build_object_store`] and inject their HTTP connector
/// via a closure that receives this enum.
pub enum StoreBuilder {
    S3(AmazonS3Builder),
    #[cfg(feature = "azure")]
    Azure(MicrosoftAzureBuilder),
    #[cfg(feature = "gcp")]
    Gcs(GoogleCloudStorageBuilder),
}

impl StoreBuilder {
    /// Build the final `ObjectStore`.
    pub fn build(self) -> Result<Arc<dyn ObjectStore>, ProxyError> {
        match self {
            StoreBuilder::S3(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build S3 store: {}", e))
            })?)),
            #[cfg(feature = "azure")]
            StoreBuilder::Azure(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build Azure store: {}", e))
            })?)),
            #[cfg(feature = "gcp")]
            StoreBuilder::Gcs(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build GCS store: {}", e))
            })?)),
        }
    }

    /// Build a `PaginatedListStore` for backend-side paginated listing.
    pub fn build_paginated(self) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
        match self {
            StoreBuilder::S3(b) => Ok(Box::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build S3 paginated store: {}", e))
            })?)),
            #[cfg(feature = "azure")]
            StoreBuilder::Azure(b) => Ok(Box::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build Azure paginated store: {}", e))
            })?)),
            #[cfg(feature = "gcp")]
            StoreBuilder::Gcs(b) => Ok(Box::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build GCS paginated store: {}", e))
            })?)),
        }
    }

    /// Build a `Signer` for presigned URL generation.
    pub fn build_signer(self) -> Result<Arc<dyn Signer>, ProxyError> {
        match self {
            StoreBuilder::S3(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build S3 signer: {}", e))
            })?)),
            #[cfg(feature = "azure")]
            StoreBuilder::Azure(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build Azure signer: {}", e))
            })?)),
            #[cfg(feature = "gcp")]
            StoreBuilder::Gcs(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build GCS signer: {}", e))
            })?)),
        }
    }
}

/// Create a [`StoreBuilder`] from a [`BucketConfig`], dispatching on `backend_type`.
pub(crate) fn create_builder(config: &BucketConfig) -> Result<StoreBuilder, ProxyError> {
    let backend_type = config.parsed_backend_type().ok_or_else(|| {
        ProxyError::ConfigError(format!(
            "unsupported backend_type: '{}'",
            config.backend_type
        ))
    })?;

    match backend_type {
        BackendType::S3 => {
            let mut b = AmazonS3Builder::new();
            for (k, v) in &config.backend_options {
                if let Ok(key) = k.parse() {
                    b = b.with_config(key, v);
                }
            }
            Ok(StoreBuilder::S3(b))
        }
        #[cfg(feature = "azure")]
        BackendType::Azure => {
            let mut b = MicrosoftAzureBuilder::new();
            for (k, v) in &config.backend_options {
                if let Ok(key) = k.parse() {
                    b = b.with_config(key, v);
                }
            }
            Ok(StoreBuilder::Azure(b))
        }
        #[cfg(not(feature = "azure"))]
        BackendType::Azure => Err(ProxyError::ConfigError(
            "Azure backend support not enabled (requires 'azure' feature)".into(),
        )),
        #[cfg(feature = "gcp")]
        BackendType::Gcs => {
            let mut b = GoogleCloudStorageBuilder::new();
            for (k, v) in &config.backend_options {
                if let Ok(key) = k.parse() {
                    b = b.with_config(key, v);
                }
            }
            Ok(StoreBuilder::Gcs(b))
        }
        #[cfg(not(feature = "gcp"))]
        BackendType::Gcs => Err(ProxyError::ConfigError(
            "GCS backend support not enabled (requires 'gcp' feature)".into(),
        )),
    }
}

/// Build an `ObjectStore` from a [`BucketConfig`], dispatching on `backend_type`.
///
/// The `configure` closure lets each runtime inject its HTTP connector:
/// - Server runtime passes `|b| b` (default connector)
/// - CF Workers passes `|b| match b { StoreBuilder::S3(s) => StoreBuilder::S3(s.with_http_connector(FetchConnector)), .. }`
pub fn build_object_store<F>(
    config: &BucketConfig,
    configure: F,
) -> Result<Arc<dyn ObjectStore>, ProxyError>
where
    F: FnOnce(StoreBuilder) -> StoreBuilder,
{
    configure(create_builder(config)?).build()
}

/// Build a [`PaginatedListStore`] from a [`BucketConfig`], dispatching on `backend_type`.
///
/// Like [`build_object_store`], accepts a configure closure for HTTP connector injection.
pub fn build_paginated_list_store<F>(
    config: &BucketConfig,
    configure: F,
) -> Result<Box<dyn PaginatedListStore>, ProxyError>
where
    F: FnOnce(StoreBuilder) -> StoreBuilder,
{
    configure(create_builder(config)?).build_paginated()
}
