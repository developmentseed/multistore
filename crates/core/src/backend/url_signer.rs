//! Object store signer construction.
//!
//! [`build_signer`] dispatches on `BucketConfig::backend_type` to build
//! an `object_store` [`Signer`]. For authenticated backends it uses
//! `object_store`'s built-in signer; for anonymous backends it returns
//! [`UnsignedUrlSigner`] which constructs plain URLs without auth parameters
//! (avoiding the `InstanceCredentialProvider` → `Instant::now()` panic on WASM).

use super::create_builder;
use crate::error::ProxyError;
use crate::types::BucketConfig;
use object_store::signer::Signer;
use std::sync::Arc;

/// Build a [`Signer`] from a [`BucketConfig`], dispatching on `backend_type`.
pub fn build_signer(config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError> {
    // Check for credentials — if absent, return unsigned signer to avoid
    // InstanceCredentialProvider which uses Instant::now() (panics on WASM).
    let has_creds = !config.option("access_key_id").unwrap_or("").is_empty()
        && !config.option("secret_access_key").unwrap_or("").is_empty();

    if !has_creds {
        return Ok(Arc::new(UnsignedUrlSigner::from_config(config)?));
    }

    create_builder(config)?.build_signer()
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
        use crate::types::BackendType;

        match config.parsed_backend_type() {
            Some(BackendType::Azure) => {
                let account_name = config.option("account_name").unwrap_or("");
                let container = config.option("container_name").unwrap_or("");
                Ok(Self {
                    endpoint: format!("https://{}.blob.core.windows.net", account_name),
                    bucket: container.to_string(),
                })
            }
            Some(BackendType::Gcs) => {
                let bucket = config.option("bucket_name").unwrap_or("");
                Ok(Self {
                    endpoint: "https://storage.googleapis.com".to_string(),
                    bucket: bucket.to_string(),
                })
            }
            _ => {
                // S3 or unknown — use endpoint + bucket_name
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
