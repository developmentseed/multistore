//! Backend client and HTTP helpers for the Cloudflare Workers runtime.
//!
//! Contains:
//! - `WorkerBackend` — implements `ProxyBackend` using the Fetch API + FetchConnector
//! - `FetchHttpExchange` — implements `HttpExchange` for OIDC token exchange

use crate::fetch_connector::FetchConnector;
use bytes::Bytes;
use http::HeaderMap;
use multistore::backend::{build_signer, create_builder, ProxyBackend, RawResponse, StoreBuilder};
use multistore::error::ProxyError;
use multistore::forwarder::ForwardResponse;
use multistore::route_handler::ForwardRequest;
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
    type ResponseBody = web_sys::Response;

    async fn forward<Body: 'static>(
        &self,
        request: ForwardRequest,
        body: Body,
    ) -> Result<ForwardResponse<Self::ResponseBody>, ProxyError> {
        // Downcast to the concrete JsBody type used by the Workers runtime.
        let any_body: Box<dyn std::any::Any> = Box::new(body);
        let js_body = any_body
            .downcast::<crate::JsBody>()
            .map_err(|_| ProxyError::Internal("unexpected body type".into()))?;

        // Build web_sys::Headers from the forwarding headers.
        let ws_headers = web_sys::Headers::new()
            .map_err(|e| ProxyError::Internal(format!("failed to create Headers: {:?}", e)))?;
        for (key, value) in request.headers.iter() {
            if let Ok(v) = value.to_str() {
                let _ = ws_headers.set(key.as_str(), v);
            }
        }

        // Build web_sys::RequestInit.
        let init = web_sys::RequestInit::new();
        init.set_method(request.method.as_str());
        init.set_headers(&ws_headers.into());

        // Bypass Cloudflare's subrequest cache for Range requests.
        if request.headers.contains_key(http::header::RANGE) {
            init.set_cache(web_sys::RequestCache::NoStore);
        }

        // For PUT: attach the original ReadableStream directly (zero-copy!).
        if request.method == http::Method::PUT {
            if let Some(ref stream) = js_body.0 {
                init.set_body(stream);
            }
        }

        // Build the outgoing request.
        let ws_request = web_sys::Request::new_with_str_and_init(request.url.as_str(), &init)
            .map_err(|e| ProxyError::Internal(format!("failed to create request: {:?}", e)))?;

        // Fetch via the worker crate's Fetch API.
        let worker_req: worker::Request = ws_request.into();
        let worker_resp = worker::Fetch::Request(worker_req)
            .send()
            .await
            .map_err(|e| ProxyError::BackendError(format!("fetch failed: {}", e)))?;

        // Convert to web_sys::Response to access the body stream.
        let backend_ws: web_sys::Response = worker_resp.into();
        let status = backend_ws.status();

        // Build filtered response headers using the existing allowlist.
        let headers = extract_response_headers(&backend_ws.headers());
        let content_length = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        Ok(ForwardResponse {
            status,
            headers,
            body: backend_ws,
            content_length,
        })
    }

    fn create_paginated_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
        let builder = match create_builder(config)? {
            StoreBuilder::S3(s) => StoreBuilder::S3(s.with_http_connector(FetchConnector)),
        };
        builder.build()
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

use multistore::route_handler::RESPONSE_HEADER_ALLOWLIST;

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
