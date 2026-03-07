# multistore

Runtime-agnostic core library for the S3 proxy gateway. This crate contains all business logic — S3 request parsing, SigV4 signing/verification, authorization, configuration retrieval, and the proxy handler — without depending on any async runtime.

## Why This Crate Exists Separately

The proxy needs to run on fundamentally different runtimes: Tokio/Hyper in containers and Cloudflare Workers on the edge. These runtimes have incompatible stream types, HTTP primitives, and threading models (multi-threaded vs single-threaded WASM). By keeping the core free of runtime dependencies, it compiles cleanly to both `x86_64-unknown-linux-gnu` and `wasm32-unknown-unknown`.

## Key Abstractions

The core defines four trait boundaries that runtime crates implement:

**`ProxyBackend`** — Provides three capabilities: `create_paginated_store()` returns a `PaginatedListStore` for LIST, `create_signer()` returns a `Signer` for presigned URL generation (GET/HEAD/PUT/DELETE), and `send_raw()` sends signed HTTP requests for multipart operations. Both runtimes delegate to `build_signer()` which uses `object_store`'s built-in signer for authenticated backends and `UnsignedUrlSigner` for anonymous backends (avoiding `Instant::now()` which panics on WASM). For `create_paginated_store()`, the server runtime uses default connectors + reqwest; the worker runtime uses a custom `FetchConnector`.

**`BucketRegistry`** — Identity-aware bucket resolution and listing. Given a bucket name, identity, and S3 operation, `get_bucket()` returns a `ResolvedBucket` (config + optional list rewrite) or an authorization error. `list_buckets()` returns the buckets visible to a given identity. See `multistore-static-config` for a file-based implementation.

**`CredentialRegistry`** — Credential and role lookup for authentication infrastructure. Provides `get_credential()` for SigV4 verification and `get_role()` for STS role assumption. See `multistore-static-config` for a file-based implementation.

Any provider implementing these traits can be wrapped with `CachedProvider` for in-memory TTL caching of credential/role lookups (bucket resolution is always delegated directly since it involves authorization).

**`BackendAuth`** — Resolves backend credentials via OIDC token exchange. Called at the top of `dispatch_operation()` before the config reaches `create_paginated_store()`/`create_signer()`. When a bucket's `backend_options` contains `auth_type=oidc`, the implementation mints a self-signed JWT and exchanges it for temporary cloud credentials, injecting them into the config. The default `NoAuth` passes configs through unchanged (and errors if `auth_type=oidc` is set without a provider). The `oidc-provider` crate provides `OidcAuth` as the concrete implementation.

## Module Overview

```
src/
├── api/
│   ├── request.rs       Parse incoming HTTP → S3Operation enum
│   ├── response.rs      Serialize S3 XML responses
│   └── list_rewrite.rs  Rewrite <Key>/<Prefix> values in list response XML
├── auth/
│   ├── mod.rs           Authorization (scope-based access control)
│   ├── identity.rs      SigV4 verification, identity resolution
│   └── tests.rs         Auth test helpers
├── backend/
│   ├── mod.rs           ProxyBackend trait, Signer/StoreBuilder, S3RequestSigner (multipart)
│   └── auth.rs          BackendAuth trait, NoAuth default impl
├── registry/
│   ├── mod.rs           Re-exports
│   ├── bucket.rs        BucketRegistry trait, ResolvedBucket, DEFAULT_BUCKET_OWNER
│   └── credential.rs    CredentialRegistry trait
├── error.rs             ProxyError with S3-compatible error codes
├── proxy.rs             ProxyGateway — the main request handler
├── route_handler.rs     RouteHandler trait, ProxyResponseBody
└── types.rs             BucketConfig, RoleConfig, StoredCredential, etc.
```

## Usage

This crate is not used directly. Runtime crates depend on it and provide concrete `ProxyBackend` implementations. If you're building a custom runtime integration, depend on this crate and implement `ProxyBackend`, `BucketRegistry`, and/or `CredentialRegistry`.

### Standard usage

```rust
use multistore::proxy::ProxyGateway;
use multistore_static_config::StaticProvider;

let backend = MyBackend::new();
let config = StaticProvider::from_file("config.toml")?;

let gateway = ProxyGateway::new(
    backend,
    config.clone(),       // as BucketRegistry
    config,               // as CredentialRegistry
    Some("s3.example.com".into()),
);
// Optional: enable session token verification for STS temporary credentials.
// let gateway = gateway.with_credential_resolver(token_key);
// Optional: register route handlers for STS, OIDC discovery, etc.
// let gateway = gateway.with_route_handler(sts_handler);
// Optional: enable OIDC-based backend credential resolution.
// let gateway = gateway.with_backend_auth(oidc_auth);

// In your HTTP handler, use handle_request for a two-variant match:
let req_info = RequestInfo {
    method: &method,
    path: &path,
    query: query.as_deref(),
    headers: &headers,
};
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

### Custom BucketRegistry

For non-standard bucket resolution, authorization, or multi-tenant routing, implement `BucketRegistry` directly:

```rust
use multistore::registry::{BucketRegistry, ResolvedBucket};
use multistore::error::ProxyError;

#[derive(Clone)]
struct MyBucketRegistry { /* ... */ }

impl BucketRegistry for MyBucketRegistry {
    async fn get_bucket(
        &self,
        name: &str,
        identity: &ResolvedIdentity,
        operation: &S3Operation,
    ) -> Result<ResolvedBucket, ProxyError> {
        // Your custom bucket lookup, authorization, and routing logic.
        todo!()
    }

    async fn list_buckets(
        &self,
        identity: &ResolvedIdentity,
    ) -> Result<Vec<BucketEntry>, ProxyError> {
        // Return buckets visible to this identity.
        todo!()
    }
}
```

## Temporary Credential Resolution

The core defines a `TemporaryCredentialResolver` trait for resolving session tokens (from `x-amz-security-token`) into `TemporaryCredentials`. The core proxy calls this during identity resolution without knowing the token format.

The `multistore-sts` crate provides `TokenKey`, a sealed-token implementation using AES-256-GCM. Register it via `ProxyGateway::with_credential_resolver()`. See the [sealed tokens documentation](../docs/auth/sealed-tokens.md) for details.

## Feature Flags

All optional — the default build has zero network dependencies:

- `azure` — enables Azure Blob Storage backend support
- `gcp` — enables Google Cloud Storage backend support
