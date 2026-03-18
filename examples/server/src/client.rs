//! Server backend using reqwest for raw HTTP and default object_store connector.

use bytes::Bytes;
use futures::TryStreamExt;
use http::HeaderMap;
use http_body_util::BodyStream;
use multistore::backend::{build_signer, create_builder, ProxyBackend, RawResponse};
use multistore::error::ProxyError;
use multistore::forwarder::ForwardResponse;
use multistore::route_handler::{ForwardRequest, RESPONSE_HEADER_ALLOWLIST};
use multistore::types::BucketConfig;
use multistore_oidc_provider::{HttpExchange, OidcProviderError};
use object_store::list::PaginatedListStore;
use object_store::signer::Signer;
use std::sync::Arc;

/// Backend for the Tokio/Hyper server runtime.
///
/// Uses reqwest for raw HTTP (multipart operations) and the default
/// object_store HTTP connector for high-level operations.
#[derive(Clone)]
pub struct ServerBackend {
    client: reqwest::Client,
}

impl ServerBackend {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .pool_max_idle_per_host(20)
                .build()
                .expect("failed to build reqwest client"),
        }
    }

    /// Access the underlying reqwest client for Forward request execution.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

impl Default for ServerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyBackend for ServerBackend {
    type ResponseBody = reqwest::Response;

    async fn forward<Body: Send + 'static>(
        &self,
        request: ForwardRequest,
        body: Body,
    ) -> Result<ForwardResponse<Self::ResponseBody>, ProxyError> {
        let mut req_builder = self
            .client
            .request(request.method.clone(), request.url.as_str());

        for (k, v) in request.headers.iter() {
            req_builder = req_builder.header(k, v);
        }

        // Attach streaming body for PUT
        if request.method == http::Method::PUT {
            // Downcast to the concrete axum::body::Body type used by the server runtime.
            let any_body: Box<dyn std::any::Any> = Box::new(body);
            let axum_body = any_body
                .downcast::<axum::body::Body>()
                .map_err(|_| ProxyError::Internal("unexpected body type".into()))?;
            let body_stream = BodyStream::new(*axum_body)
                .try_filter_map(|frame| async move { Ok(frame.into_data().ok()) });
            req_builder = req_builder.body(reqwest::Body::wrap_stream(body_stream));
        }

        let backend_resp = req_builder
            .send()
            .await
            .map_err(|e| ProxyError::BackendError(e.to_string()))?;

        let status = backend_resp.status().as_u16();

        // Forward allowlisted response headers
        let mut headers = HeaderMap::new();
        for name in RESPONSE_HEADER_ALLOWLIST {
            if let Some(v) = backend_resp.headers().get(*name) {
                headers.insert(*name, v.clone());
            }
        }

        let content_length = backend_resp.content_length();

        Ok(ForwardResponse {
            status,
            headers,
            body: backend_resp,
            content_length,
        })
    }

    fn create_paginated_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
        create_builder(config)?.build()
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
            "server: sending raw backend request via reqwest"
        );

        let mut req_builder = self.client.request(method, &url);

        for (key, value) in headers.iter() {
            req_builder = req_builder.header(key, value);
        }

        if !body.is_empty() {
            req_builder = req_builder.body(body);
        }

        let response = req_builder.send().await.map_err(|e| {
            tracing::error!(error = %e, "reqwest raw request failed");
            ProxyError::BackendError(e.to_string())
        })?;

        let status = response.status().as_u16();
        let resp_headers = response.headers().clone();
        let resp_body = response.bytes().await.map_err(|e| {
            ProxyError::BackendError(format!("failed to read raw response body: {}", e))
        })?;

        Ok(RawResponse {
            status,
            headers: resp_headers,
            body: resp_body,
        })
    }
}

/// [`HttpExchange`] implementation using reqwest (native).
#[derive(Clone)]
pub struct ReqwestHttpExchange {
    client: reqwest::Client,
}

impl ReqwestHttpExchange {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl HttpExchange for ReqwestHttpExchange {
    async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> Result<String, OidcProviderError> {
        let resp = self
            .client
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
