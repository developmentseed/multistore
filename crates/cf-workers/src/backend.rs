//! Backend client for the Cloudflare Workers runtime.
//!
//! Contains [`WorkerBackend`], which implements [`ProxyBackend`] by forwarding
//! requests through the Workers Fetch API and reading responses as
//! `web_sys::Response` streams.

use crate::body::JsBody;
use crate::fetch_connector::FetchConnector;
use bytes::Bytes;
use http::HeaderMap;
use multistore::backend::ForwardResponse;
use multistore::backend::{build_signer, create_builder, ProxyBackend, RawResponse, StoreBuilder};
use multistore::error::ProxyError;
use multistore::route_handler::ForwardRequest;
use multistore::types::BucketConfig;

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
            .downcast::<JsBody>()
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

        let headers = convert_ws_headers(&backend_ws.headers());
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
            #[cfg(feature = "azure")]
            StoreBuilder::Azure(a) => StoreBuilder::Azure(a.with_http_connector(FetchConnector)),
            #[cfg(feature = "gcp")]
            StoreBuilder::Gcs(g) => StoreBuilder::Gcs(g.with_http_connector(FetchConnector)),
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

        let ws_response: web_sys::Response = worker_resp.into();
        let resp_headers = convert_ws_headers(&ws_response.headers());

        Ok(RawResponse {
            status,
            headers: resp_headers,
            body: Bytes::from(resp_bytes),
        })
    }
}

/// Convert `web_sys::Headers` into an `http::HeaderMap`.
fn convert_ws_headers(ws_headers: &web_sys::Headers) -> HeaderMap {
    let mut out = HeaderMap::new();
    if let Ok(iter) = js_sys::try_iter(&ws_headers.entries()) {
        if let Some(iter) = iter {
            for entry in iter.flatten() {
                let pair = js_sys::Array::from(&entry);
                if let (Some(name), Some(value)) =
                    (pair.get(0).as_string(), pair.get(1).as_string())
                {
                    if let (Ok(hn), Ok(hv)) = (
                        name.parse::<http::header::HeaderName>(),
                        value.parse::<http::header::HeaderValue>(),
                    ) {
                        out.insert(hn, hv);
                    }
                }
            }
        }
    }
    out
}
