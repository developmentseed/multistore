//! Object store signer construction.
//!
//! [`build_signer`] dispatches on `BucketConfig::backend_type` to build
//! an `object_store` [`Signer`]. For authenticated backends it uses
//! `object_store`'s built-in signer; for anonymous backends it returns
//! [`UnsignedUrlSigner`] which constructs plain URLs without auth parameters
//! (avoiding the `InstanceCredentialProvider` → `Instant::now()` panic on WASM).

use super::create_builder;
use crate::error::ProxyError;
use crate::types::{BackendType, BucketConfig};
use object_store::signer::Signer;
use std::sync::Arc;

/// Build a [`Signer`] from a [`BucketConfig`], dispatching on `backend_type`.
pub fn build_signer(config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError> {
    let backend_type = config.parsed_backend_type().ok_or_else(|| {
        ProxyError::ConfigError(format!(
            "unsupported backend_type: '{}'",
            config.backend_type
        ))
    })?;

    // Check for credentials — if absent, return unsigned signer to avoid
    // InstanceCredentialProvider which uses Instant::now() (panics on WASM).
    let has_creds = !config.option("access_key_id").unwrap_or("").is_empty()
        && !config.option("secret_access_key").unwrap_or("").is_empty();

    if !has_creds {
        return Ok(Arc::new(UnsignedUrlSigner::from_config(config)?));
    }

    match backend_type {
        BackendType::S3 => create_builder(config)?.build_signer(),
        #[cfg(feature = "azure")]
        BackendType::Azure => create_builder(config)?.build_signer(),
        #[cfg(not(feature = "azure"))]
        BackendType::Azure => Err(ProxyError::ConfigError(
            "Azure backend support not enabled (requires 'azure' feature)".into(),
        )),
        #[cfg(feature = "gcp")]
        BackendType::Gcs => create_builder(config)?.build_signer(),
        #[cfg(not(feature = "gcp"))]
        BackendType::Gcs => Err(ProxyError::ConfigError(
            "GCS backend support not enabled (requires 'gcp' feature)".into(),
        )),
    }
}

/// Signer for anonymous/credential-less backends.
///
/// Returns unsigned URLs — no auth query params, no time calls. This avoids
/// the `InstanceCredentialProvider` → `TokenCache` → `Instant::now()` path
/// in `object_store` which panics on `wasm32-unknown-unknown`.
#[derive(Debug)]
struct UnsignedUrlSigner {
    endpoint: String,
    bucket: String,
}

impl UnsignedUrlSigner {
    fn from_config(config: &BucketConfig) -> Result<Self, ProxyError> {
        let endpoint = config
            .option("endpoint")
            .unwrap_or("https://s3.amazonaws.com");
        let bucket = config.option("bucket_name").unwrap_or("");
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            bucket: bucket.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl Signer for UnsignedUrlSigner {
    async fn signed_url(
        &self,
        _method: http::Method,
        path: &object_store::path::Path,
        _expires_in: std::time::Duration,
    ) -> object_store::Result<url::Url> {
        let key = path.as_ref();
        let url_str = if self.bucket.is_empty() {
            if key.is_empty() {
                format!("{}/", self.endpoint)
            } else {
                format!("{}/{}", self.endpoint, key)
            }
        } else if key.is_empty() {
            format!("{}/{}", self.endpoint, self.bucket)
        } else {
            format!("{}/{}/{}", self.endpoint, self.bucket, key)
        };
        url::Url::parse(&url_str).map_err(|e| object_store::Error::Generic {
            store: "UnsignedUrlSigner",
            source: Box::new(e),
        })
    }
}
