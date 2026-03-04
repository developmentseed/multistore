//! Backend client and HTTP helpers for the Cloudflare Workers runtime.
//!
//! Contains:
//! - `WorkerBackend` — implements `ProxyBackend` using the Fetch API + FetchConnector
//! - `FetchHttpExchange` — implements `HttpExchange` for OIDC token exchange

use crate::fetch_connector::FetchConnector;
use bytes::Bytes;
use http::HeaderMap;
use multistore::backend::{
    build_paginated_list_store, build_signer, ProxyBackend, RawResponse, StoreBuilder,
};
use multistore::error::ProxyError;
use multistore::types::BucketConfig;
use multistore_oidc_provider::{HttpExchange, OidcProviderError};
use object_store::list::PaginatedListStore;
use object_store::signer::Signer;
use std::sync::Arc;
use worker::Fetch;

/// Backend for the Cloudflare Workers runtime.
///
/// Uses `FetchConnector` for `object_store` HTTP requests and `web_sys::fetch`
/// for raw multipart operations.
#[derive(Clone)]
pub struct WorkerBackend;

impl ProxyBackend for WorkerBackend {
    fn create_paginated_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
        build_paginated_list_store(config, |b| match b {
            StoreBuilder::S3(s) => StoreBuilder::S3(s.with_http_connector(FetchConnector)),
        })
    }

    fn create_signer(&self, config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError> {
        build_signer(config)
    }

    async fn send_raw(
        &self,
        method: http::Method,
        url: String,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<RawResponse, ProxyError> {
        tracing::debug!(
            method = %method,
            url = %url,
            "worker: sending raw backend request via Fetch API"
        );

        // Build web_sys::Headers
        let ws_headers = web_sys::Headers::new()
            .map_err(|e| ProxyError::Internal(format!("failed to create Headers: {:?}", e)))?;

        for (key, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                let _ = ws_headers.set(key.as_str(), v);
            }
        }

        // Build web_sys::RequestInit
        let init = web_sys::RequestInit::new();
        init.set_method(method.as_str());
        init.set_headers(&ws_headers.into());

        // Set body for methods that carry one
        if !body.is_empty() {
            let uint8 = js_sys::Uint8Array::from(body.as_ref());
            init.set_body(&uint8.into());
        }

        let ws_request = web_sys::Request::new_with_str_and_init(&url, &init)
            .map_err(|e| ProxyError::BackendError(format!("failed to create request: {:?}", e)))?;

        // Fetch via worker
        let worker_req: worker::Request = ws_request.into();
        let mut worker_resp = Fetch::Request(worker_req)
            .send()
            .await
            .map_err(|e| ProxyError::BackendError(format!("fetch failed: {}", e)))?;

        let status = worker_resp.status_code();

        // Read response body as bytes (multipart responses are small)
        let resp_bytes = worker_resp
            .bytes()
            .await
            .map_err(|e| ProxyError::Internal(format!("failed to read response: {}", e)))?;

        // Convert response headers
        let ws_response: web_sys::Response = worker_resp.into();
        let resp_headers = extract_response_headers(&ws_response.headers());

        Ok(RawResponse {
            status,
            headers: resp_headers,
            body: Bytes::from(resp_bytes),
        })
    }
}

/// Headers to extract from backend responses.
pub const RESPONSE_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "content-length",
    "content-range",
    "etag",
    "last-modified",
    "accept-ranges",
    "content-encoding",
    "content-disposition",
    "cache-control",
    "x-amz-request-id",
    "x-amz-version-id",
    "location",
];

/// Extract response headers from a `web_sys::Headers` using an allowlist.
pub fn extract_response_headers(ws_headers: &web_sys::Headers) -> HeaderMap {
    let mut resp_headers = HeaderMap::new();
    for name in RESPONSE_HEADER_ALLOWLIST {
        if let Ok(Some(value)) = ws_headers.get(name) {
            if let Ok(parsed) = value.parse() {
                resp_headers.insert(*name, parsed);
            }
        }
    }
    resp_headers
}

/// [`HttpExchange`] implementation using reqwest on WASM (wraps `web_sys::fetch`).
#[derive(Clone)]
pub struct FetchHttpExchange;

impl HttpExchange for FetchHttpExchange {
    async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> Result<String, OidcProviderError> {
        let client = reqwest::Client::new();
        let resp = client
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(|e| OidcProviderError::HttpError(e.to_string()))?;

        resp.text()
            .await
            .map_err(|e| OidcProviderError::HttpError(e.to_string()))
    }
}
