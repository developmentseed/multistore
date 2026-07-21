# Custom Backend

The `ProxyBackend` trait abstracts runtime-specific I/O. Implement it when deploying to a platform that's neither a standard server nor Cloudflare Workers.

## The Trait

```rust
use multistore::backend::ProxyBackend;
use multistore::types::BucketConfig;
use multistore::error::ProxyError;
use object_store::{ObjectStore, signer::Signer};
use std::sync::Arc;

pub trait ProxyBackend: Clone + MaybeSend + MaybeSync + 'static {
    /// The streaming body type in forwarded backend responses.
    type ResponseBody: MaybeSend + 'static;

    /// The request body type accepted by `forward()`.
    type Body: MaybeSend + 'static;

    /// Execute a presigned ForwardRequest against the backend and return
    /// the response with a streaming body (GET/HEAD/PUT/DELETE)
    fn forward(
        &self,
        request: ForwardRequest,
        body: Self::Body,
    ) -> impl Future<Output = Result<ForwardResponse<Self::ResponseBody>, ProxyError>> + MaybeSend;

    /// Create a Signer for presigned URL generation (GET/HEAD/PUT/DELETE)
    fn create_signer(&self, config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError>;

    /// Send a pre-signed HTTP request (multipart, batch delete, and LIST)
    fn send_raw(
        &self,
        method: http::Method,
        url: String,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl Future<Output = Result<RawResponse, ProxyError>> + MaybeSend;
}
```

## Three Responsibilities

### `forward()`

Executes a presigned `ForwardRequest` against the backend and returns a `ForwardResponse` whose `body` is your runtime's native streaming type (`Self::ResponseBody`). The gateway calls this internally for GET/HEAD/PUT/DELETE; you supply the HTTP transport and the two associated types (`Body` for the inbound request body, `ResponseBody` for the streamed response body):

```rust
async fn forward(
    &self,
    request: ForwardRequest,
    body: Self::Body,
) -> Result<ForwardResponse<Self::ResponseBody>, ProxyError> {
    let response = self.http_client
        .request(request.method, request.url.as_str())
        .headers(request.headers)
        .body(body)
        .send()
        .await
        .map_err(|e| ProxyError::BackendError(e.to_string()))?;

    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let content_length = response.content_length();

    Ok(ForwardResponse {
        status,
        headers,
        content_length,
        body: response.into_body(), // your runtime's streaming body type
    })
}
```

## Other Responsibilities

### `create_signer()`

Returns an `Arc<dyn Signer>` for generating presigned URLs. Signing is pure computation — no HTTP connector needed:

```rust
fn create_signer(&self, config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError> {
    build_signer(config)
}
```

### `send_raw()`

Executes a pre-signed HTTP request for operations not served by a presigned URL: multipart uploads, batch delete, and LIST (whose S3 XML the gateway parses itself so keys pass through byte-faithfully). Use your platform's HTTP client:

```rust
async fn send_raw(
    &self,
    method: http::Method,
    url: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<RawResponse, ProxyError> {
    let response = self.http_client
        .request(method, &url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| ProxyError::BackendError(e.to_string()))?;

    Ok(RawResponse {
        status: response.status(),
        headers: response.headers().clone(),
        body: response.bytes().await
            .map_err(|e| ProxyError::BackendError(e.to_string()))?,
    })
}
```

## Helper Functions

The `backend` module provides shared helpers:

- **`create_builder(config)`** — Dispatches on `backend_type` ("s3", "az", "gcs"), iterates `backend_options` with `with_config()`, and returns a `StoreBuilder` that can be customized (e.g. inject an HTTP connector) before calling `.build()` or `.build_signer()`
- **`build_signer(config)`** — Returns the appropriate signer: `object_store`'s built-in signer for authenticated backends, or `UnsignedUrlSigner` for anonymous backends

These handle the multi-provider dispatch logic so your backend implementation only needs to provide the HTTP transport layer.

## Wiring Into the Gateway

```rust
use multistore::router::Router;
use multistore_sts::route_handler::StsRouterExt;

let router = Router::new()
    .with_sts("/.sts", sts_creds, jwks_cache, token_key);

let backend = MyBackend::new(http_client);
let gateway = ProxyGateway::new(backend, bucket_registry, cred_registry, domain)
    .with_router(router);

// In your request handler, use handle_request for a two-variant match.
// `path` must be the raw, percent-encoded request path (the form the client
// signed) — SigV4 verification canonicalizes over it. If you decode the path
// for routing, pass the encoded path separately via `.with_signing_path()`,
// or keys containing escaped characters (e.g. a space → `%20`) fail with
// SignatureDoesNotMatch.
let req_info = RequestInfo::new(&method, &path, query.as_deref(), &headers, None);
match gateway.handle_request(&req_info, body, |b| to_bytes(b)).await {
    GatewayResponse::Response(result) => {
        // Return the complete response (LIST, errors, STS, etc.)
    }
    GatewayResponse::Forward(response) => {
        // Forwarding already happened inside handle_request (via backend.forward);
        // stream response.body to the client (response.status, response.headers)
    }
}
```
