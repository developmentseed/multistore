//! Backend client for the Cloudflare Workers runtime.
//!
//! Contains [`WorkerBackend`], which implements [`ProxyBackend`] by forwarding
//! requests through the Workers Fetch API and reading responses as
//! `web_sys::Response` streams.

use crate::body::JsBody;
use crate::fetch_connector::FetchConnector;
use crate::headers::WsHeaders;
use crate::response::headermap_from_js;
use bytes::Bytes;
use http::HeaderMap;
use multistore::backend::ForwardResponse;
use multistore::backend::{build_signer, create_builder, ProxyBackend, RawResponse, StoreBuilder};
use multistore::error::ProxyError;
use multistore::route_handler::ForwardRequest;
use multistore::types::BucketConfig;

use object_store::list::PaginatedListStore;
use object_store::signer::Signer;
use object_store::RetryConfig;
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
    type Body = JsBody;

    async fn forward(
        &self,
        request: ForwardRequest,
        body: JsBody,
    ) -> Result<ForwardResponse<Self::ResponseBody>, ProxyError> {
        let js_body = body;

        // Build web_sys::RequestInit.
        let init = web_sys::RequestInit::new();
        init.set_method(request.method.as_str());
        init.set_headers(&WsHeaders::from(&request.headers).into_inner().into());

        // Bypass Cloudflare's subrequest cache for reads where leaving it on
        // would break the request (HEAD rewritten to GET on cacheable-extension
        // URLs, or Range poisoning the full-object cache). See
        // `ForwardRequest::should_bypass_cache`.
        if request.should_bypass_cache() {
            init.set_cache(web_sys::RequestCache::NoStore);
        }

        // For PUT: attach the original ReadableStream directly (zero-copy!).
        if request.method == http::Method::PUT {
            if let Some(stream) = js_body.stream() {
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

        let headers = headermap_from_js(&backend_ws.headers());
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
        // Disable retries: object_store's retry logic uses `tokio::time::sleep`
        // which panics on WASM (`std::time::Instant::now` is unsupported).
        // See: https://github.com/apache/arrow-rs-object-store/issues/624
        let no_retry = RetryConfig {
            max_retries: 0,
            ..Default::default()
        };
        let builder = match create_builder(config)? {
            StoreBuilder::S3(s) => {
                StoreBuilder::S3(s.with_http_connector(FetchConnector).with_retry(no_retry))
            }
            #[cfg(feature = "azure")]
            StoreBuilder::Azure(a) => {
                StoreBuilder::Azure(a.with_http_connector(FetchConnector).with_retry(no_retry))
            }
            #[cfg(feature = "gcp")]
            StoreBuilder::Gcs(g) => {
                StoreBuilder::Gcs(g.with_http_connector(FetchConnector).with_retry(no_retry))
            }
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

        // Build web_sys::RequestInit
        let init = web_sys::RequestInit::new();
        init.set_method(method.as_str());
        init.set_headers(&WsHeaders::from(&headers).into_inner().into());

        // Set body for methods that carry one
        if !body.is_empty() {
            let uint8 = js_sys::Uint8Array::from(body.as_ref());
            init.set_body(&uint8.into());
        }

        let ws_request = web_sys::Request::new_with_str_and_init(&url, &init)
            .map_err(|e| ProxyError::BackendError(format!("failed to create request: {:?}", e)))?;

        // Fetch via worker
        let worker_req: worker::Request = ws_request.into();
        let worker_resp = Fetch::Request(worker_req)
            .send()
            .await
            .map_err(|e| ProxyError::BackendError(format!("fetch failed: {}", e)))?;

        let status = worker_resp.status_code();

        // Convert to `web_sys::Response` and read the headers BEFORE consuming
        // the body. The `worker::Response → web_sys::Response` conversion panics
        // once the body has been read, so reading bytes first (and converting
        // after) blew up `send_raw` on every multipart/batch-delete response.
        // `forward()` relies on the same before-body ordering.
        let ws_response: web_sys::Response = worker_resp.into();
        let resp_headers = headermap_from_js(&ws_response.headers());

        // Read the (small) response body via `arrayBuffer()`.
        let buf = wasm_bindgen_futures::JsFuture::from(
            ws_response
                .array_buffer()
                .map_err(|e| ProxyError::Internal(format!("arrayBuffer() failed: {:?}", e)))?,
        )
        .await
        .map_err(|e| ProxyError::Internal(format!("failed to read response: {:?}", e)))?;
        let resp_bytes = js_sys::Uint8Array::new(&buf).to_vec();

        Ok(RawResponse {
            status,
            headers: resp_headers,
            body: Bytes::from(resp_bytes),
        })
    }
}
