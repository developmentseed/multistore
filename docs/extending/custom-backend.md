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
    /// Create a PaginatedListStore for LIST operations
    fn create_paginated_store(&self, config: &BucketConfig)
        -> Result<Box<dyn PaginatedListStore>, ProxyError>;

    /// Create a Signer for presigned URL generation (GET/HEAD/PUT/DELETE)
    fn create_signer(&self, config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError>;

    /// Send a pre-signed HTTP request (multipart operations)
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

### `create_paginated_store()`

Returns a `Box<dyn PaginatedListStore>` used for LIST operations with backend-side pagination. The runtime may need to inject a custom HTTP connector:

```rust
fn create_paginated_store(&self, config: &BucketConfig)
    -> Result<Box<dyn PaginatedListStore>, ProxyError>
{
    let builder = match create_builder(config)? {
        StoreBuilder::S3(s) => StoreBuilder::S3(s.with_http_connector(MyConnector)),
        other => other,
    };
    builder.build()
}
```

### `create_signer()`

Returns an `Arc<dyn Signer>` for generating presigned URLs. Signing is pure computation — no HTTP connector needed:

```rust
fn create_signer(&self, config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError> {
    build_signer(config)
}
```

### `send_raw()`

Executes a pre-signed HTTP request for multipart operations. Use your platform's HTTP client:

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
    .with_sts(sts_creds, jwks_cache, token_key);

let backend = MyBackend::new(http_client);
let gateway = ProxyGateway::new(backend, bucket_registry, cred_registry, domain)
    .with_router(router);

// In your request handler, use handle_request for a two-variant match:
let req_info = RequestInfo::new(&method, &path, query.as_deref(), &headers, None);
match gateway.handle_request(&req_info, body, |b| to_bytes(b)).await {
    GatewayResponse::Response(result) => {
        // Return the complete response (LIST, errors, STS, etc.)
    }
    GatewayResponse::Forward(fwd, body) => {
        // Execute presigned URL with your HTTP client
        // Stream request body (PUT) or response body (GET)
    }
}
```
