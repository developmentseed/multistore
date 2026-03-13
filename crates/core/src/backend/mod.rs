//! Backend abstraction for building object stores from bucket configuration.
//!
//! [`StoreBuilder`] wraps provider-specific builders (S3, Azure, GCS) and
//! provides a uniform API for constructing `ObjectStore`, `PaginatedListStore`,
//! `MultipartStore`, and `Signer` instances.
//!
//! Runtimes call [`create_builder`] to get a half-built store, customize it
//! (e.g. inject an HTTP connector), then call one of the `build_*` methods.

pub mod url_signer;
pub use url_signer::build_signer;

use crate::error::ProxyError;
use crate::types::{BackendType, BucketConfig};
use object_store::aws::AmazonS3Builder;
use object_store::list::PaginatedListStore;
use object_store::multipart::MultipartStore;
use object_store::signer::Signer;
use object_store::ObjectStore;
use std::sync::Arc;

#[cfg(feature = "azure")]
use object_store::azure::MicrosoftAzureBuilder;
#[cfg(feature = "gcp")]
use object_store::gcp::GoogleCloudStorageBuilder;

/// Wrapper around provider-specific `object_store` builders.
///
/// Obtain one via [`create_builder`], customize it (e.g. inject an HTTP
/// connector), then call [`build`](Self::build) or
/// [`build_signer`](Self::build_signer).
pub enum StoreBuilder {
    S3(AmazonS3Builder),
    #[cfg(feature = "azure")]
    Azure(MicrosoftAzureBuilder),
    #[cfg(feature = "gcp")]
    Gcs(GoogleCloudStorageBuilder),
}

impl StoreBuilder {
    /// Build a `PaginatedListStore` for backend-side paginated listing.
    pub fn build(self) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
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

    /// Build an [`ObjectStore`] for GET/HEAD/PUT/DELETE operations.
    pub fn build_object_store(self) -> Result<Arc<dyn ObjectStore>, ProxyError> {
        match self {
            StoreBuilder::S3(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build S3 object store: {}", e))
            })?)),
            #[cfg(feature = "azure")]
            StoreBuilder::Azure(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build Azure object store: {}", e))
            })?)),
            #[cfg(feature = "gcp")]
            StoreBuilder::Gcs(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build GCS object store: {}", e))
            })?)),
        }
    }

    /// Build a [`MultipartStore`] for multipart upload operations.
    pub fn build_multipart_store(self) -> Result<Arc<dyn MultipartStore>, ProxyError> {
        match self {
            StoreBuilder::S3(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build S3 multipart store: {}", e))
            })?)),
            #[cfg(feature = "azure")]
            StoreBuilder::Azure(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build Azure multipart store: {}", e))
            })?)),
            #[cfg(feature = "gcp")]
            StoreBuilder::Gcs(b) => Ok(Arc::new(b.build().map_err(|e| {
                ProxyError::ConfigError(format!("failed to build GCS multipart store: {}", e))
            })?)),
        }
    }
}

/// Create a [`StoreBuilder`] from a [`BucketConfig`], dispatching on `backend_type`.
///
/// Runtimes call this to get a half-built store, customize it (e.g. inject
/// an HTTP connector), then call [`StoreBuilder::build`] or
/// [`StoreBuilder::build_signer`].
pub fn create_builder(config: &BucketConfig) -> Result<StoreBuilder, ProxyError> {
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
