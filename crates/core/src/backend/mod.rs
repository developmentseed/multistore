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
//! The [`request_signer`] submodule handles outbound SigV4 request signing.
//! The [`multipart`] submodule builds URLs and signs multipart upload requests.

pub mod multipart;
pub mod request_signer;
pub mod url_signer;
pub use url_signer::build_signer;

use crate::error::ProxyError;
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::route_handler::ForwardRequest;
use crate::types::{BackendType, BucketConfig};
use bytes::Bytes;
use http::HeaderMap;
use object_store::aws::AmazonS3Builder;
use object_store::list::PaginatedListStore;
use object_store::signer::Signer;
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
    /// The streaming body type in forwarded backend responses.
    type ResponseBody: MaybeSend + 'static;

    /// The request body type accepted by [`forward()`](Self::forward).
    type Body: MaybeSend + 'static;

    /// Execute a presigned [`ForwardRequest`] against the backend and return
    /// the response with a streaming body.
    fn forward(
        &self,
        request: ForwardRequest,
        body: Self::Body,
    ) -> impl Future<Output = Result<ForwardResponse<Self::ResponseBody>, ProxyError>> + MaybeSend;

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

/// The response returned after executing a backend request.
///
/// `S` is the streaming body type, which varies per runtime — for example,
/// a Hyper `Incoming` body on native targets or a Workers `ReadableStream`
/// on the edge.
pub struct ForwardResponse<S> {
    /// HTTP status code from the backend.
    pub status: u16,
    /// Response headers from the backend.
    pub headers: HeaderMap,
    /// The streaming response body.
    pub body: S,
    /// Content length reported by the backend, if known.
    pub content_length: Option<u64>,
}

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

/// The byte length to wrap a streamed PUT body in, or `None` to forward the raw
/// stream unsized.
///
/// Runtimes that stream a PUT body through without buffering need this: a bare
/// stream body makes the Cloudflare Workers runtime send the subrequest with
/// `Transfer-Encoding: chunked` and *drop* `Content-Length`, and an S3 origin
/// that never learns the body size can hang up without answering at all.
///
/// `Content-Length` is the correct size for both body shapes, `aws-chunked`
/// included: it counts the bytes actually placed on the wire — chunk framing and
/// trailer included — whereas `x-amz-decoded-content-length` counts only the
/// payload S3 reconstructs after de-chunking. Sizing the leg does not reframe
/// the body, so the chunk framing reaches S3 untouched.
///
/// Returns `None` only when there is no usable `Content-Length` to size with.
pub fn streamed_put_body_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn plain_put_is_sized_by_content_length() {
        assert_eq!(
            streamed_put_body_length(&headers(&[("content-length", "1024")])),
            Some(1024)
        );
    }

    /// An `aws-chunked` body must be sized too. Its `Content-Length` is the
    /// *encoded* length — the 135-byte gap here is the chunk framing plus the
    /// CRC32 trailer — which is exactly what goes on the wire.
    #[test]
    fn aws_chunked_put_is_sized_by_encoded_content_length() {
        let h = headers(&[
            ("content-encoding", "aws-chunked"),
            ("content-length", "10094598"),
            ("x-amz-decoded-content-length", "10094463"),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
        ]);
        assert_eq!(streamed_put_body_length(&h), Some(10094598));
    }

    #[test]
    fn no_content_length_forwards_raw_stream() {
        assert_eq!(streamed_put_body_length(&headers(&[])), None);
        let chunked_only = headers(&[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "10094463"),
        ]);
        assert_eq!(streamed_put_body_length(&chunked_only), None);
    }
}
