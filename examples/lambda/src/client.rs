//! Lambda backend using reqwest for raw HTTP and default object_store connector.

use bytes::Bytes;
use http::HeaderMap;
use lambda_http::Body;
use multistore::backend::{build_signer, create_builder, ProxyBackend, RawResponse};
use multistore::error::ProxyError;
use multistore::forwarder::ForwardResponse;
use multistore::route_handler::{ForwardRequest, RESPONSE_HEADER_ALLOWLIST};
use multistore::types::BucketConfig;
use multistore_oidc_provider::{HttpExchange, OidcProviderError};
use object_store::list::PaginatedListStore;
use object_store::signer::Signer;
use std::sync::Arc;

/// Backend for the Lambda runtime.
///
/// Uses reqwest for raw HTTP (multipart operations) and the default
/// object_store HTTP connector for high-level operations.
#[derive(Clone)]
pub struct LambdaBackend {
    client: reqwest::Client,
}

impl LambdaBackend {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .pool_max_idle_per_host(5)
                .build()
                .expect("failed to build reqwest client"),
        }
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

/// Collect a Lambda body into bytes.
async fn body_to_bytes(body: Body) -> Result<Bytes, Box<dyn std::error::Error>> {
    match body {
        Body::Empty => Ok(Bytes::new()),
        Body::Text(s) => Ok(Bytes::from(s)),
        Body::Binary(b) => Ok(Bytes::from(b)),
    }
}

impl ProxyBackend for LambdaBackend {
    type ResponseBody = Body;

    async fn forward<B: Send + 'static>(
        &self,
        request: ForwardRequest,
        body: B,
    ) -> Result<ForwardResponse<Self::ResponseBody>, ProxyError> {
        let mut req_builder = self
            .client
            .request(request.method.clone(), request.url.as_str());

        for (k, v) in request.headers.iter() {
            req_builder = req_builder.header(k, v);
        }

        // Attach body for PUT requests
        if request.method == http::Method::PUT {
            // Downcast to the concrete lambda_http::Body type used by the Lambda runtime.
            let any_body: Box<dyn std::any::Any> = Box::new(body);
            let lambda_body = any_body
                .downcast::<Body>()
                .map_err(|_| ProxyError::Internal("unexpected body type".into()))?;
            let bytes = body_to_bytes(*lambda_body)
                .await
                .map_err(|e| ProxyError::Internal(format!("failed to read PUT body: {e}")))?;
            req_builder = req_builder.body(bytes);
        }

        let backend_resp = req_builder
            .send()
            .await
            .map_err(|e| ProxyError::Internal(format!("forward request failed: {e}")))?;

        let status = backend_resp.status().as_u16();

        // Forward allowlisted response headers
        let mut headers = http::HeaderMap::new();
        for name in RESPONSE_HEADER_ALLOWLIST {
            if let Some(v) = backend_resp.headers().get(*name) {
                headers.insert(*name, v.clone());
            }
        }

        let content_length = backend_resp.content_length();

        // Buffer the response body (Lambda doesn't support streaming responses)
        let body_bytes = backend_resp
            .bytes()
            .await
            .map_err(|e| ProxyError::Internal(format!("failed to read backend response: {e}")))?;

        Ok(ForwardResponse {
            status,
            headers,
            body: Body::Binary(body_bytes.to_vec()),
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
            "lambda: sending raw backend request via reqwest"
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
