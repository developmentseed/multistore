# multistore

Runtime-agnostic core library for the S3 proxy gateway. This crate contains all business logic — S3 request parsing, SigV4 signing/verification, authorization, configuration retrieval, and the proxy handler — without depending on any async runtime.

## Why This Crate Exists Separately

The proxy needs to run on fundamentally different runtimes: Tokio/Hyper in containers and Cloudflare Workers on the edge. These runtimes have incompatible stream types, HTTP primitives, and threading models (multi-threaded vs single-threaded WASM). By keeping the core free of runtime dependencies, it compiles cleanly to both `x86_64-unknown-linux-gnu` and `wasm32-unknown-unknown`.

## Key Abstractions

The core defines three trait boundaries that runtime crates implement:

**`ProxyBackend`** -- Provides three capabilities: `create_paginated_store()` returns a `PaginatedListStore` for LIST, `create_signer()` returns a `Signer` for presigned URL generation (GET/HEAD/PUT/DELETE), and `send_raw()` sends signed HTTP requests for multipart operations. Both runtimes delegate to `build_signer()` which uses `object_store`'s built-in signer for authenticated backends and `UnsignedUrlSigner` for anonymous backends (avoiding `Instant::now()` which panics on WASM). For `create_paginated_store()`, the server runtime uses default connectors + reqwest; the worker runtime uses a custom `FetchConnector`.

**`BucketRegistry`** -- Identity-aware bucket resolution and listing. Given a bucket name, identity, and S3 operation, `get_bucket()` returns a `ResolvedBucket` (config + optional list rewrite) or an authorization error. `list_buckets()` returns the buckets visible to a given identity. See `multistore-static-config` for a file-based implementation.

**`CredentialRegistry`** -- Credential and role lookup for authentication infrastructure. Provides `get_credential()` for SigV4 verification and `get_role()` for STS role assumption. See `multistore-static-config` for a file-based implementation.

Any provider implementing these traits can be wrapped with `CachedProvider` for in-memory TTL caching of credential/role lookups (bucket resolution is always delegated directly since it involves authorization).

The core also defines the **`Middleware`** trait for composable request processing. All request handling flows through a unified middleware chain. Each middleware receives a `RequestContext` and a `Next` handle to continue the chain. `RequestContext` carries request metadata and a typed `http::Extensions` map that middleware uses to share data (identity, parsed operation, resolved bucket, etc.) with downstream middleware and the dispatch function.

Built-in middleware:

- **`s3::S3OpParser`** -- parses the HTTP request into a typed `S3Operation`
- **`s3::AuthMiddleware`** -- resolves caller identity from SigV4 headers
- **`s3::BucketResolver`** -- looks up bucket configuration and authorizes access
- **`cors::CorsMiddleware`** -- per-bucket CORS handling (preflight + response headers)
- **`router::Router`** -- path-based route matching (STS, OIDC discovery, etc.)

The `oidc-provider` crate provides `AwsBackendAuth` as a middleware that resolves backend credentials via OIDC token exchange.

## Module Overview

```
src/
├── api/
│   ├── request.rs       Parse incoming HTTP -> S3Operation enum
│   ├── response.rs      Serialize S3 XML responses
│   └── list_rewrite.rs  Rewrite <Key>/<Prefix> values in list response XML
├── auth/
│   ├── mod.rs           Authorization (scope-based access control)
│   ├── identity.rs      SigV4 verification, identity resolution
│   └── tests.rs         Auth test helpers
├── backend/
│   └── mod.rs           ProxyBackend trait, Signer/StoreBuilder, S3RequestSigner (multipart)
├── cors.rs              CorsMiddleware, CorsConfig, CorsProvider
├── registry/
│   ├── mod.rs           Re-exports
│   ├── bucket.rs        BucketRegistry trait, ResolvedBucket, DEFAULT_BUCKET_OWNER
│   └── credential.rs    CredentialRegistry trait
├── s3.rs                S3OpParser, AuthMiddleware, BucketResolver
├── error.rs             ProxyError with S3-compatible error codes
├── middleware.rs         Middleware trait, RequestContext, Next
├── proxy.rs             ProxyGateway -- the main request handler
├── route_handler.rs     RouteHandler trait, ProxyResponseBody
├── router.rs            Router (path-based route matching, implements Middleware)
└── types.rs             BucketConfig, RoleConfig, StoredCredential, etc.
```

## Usage

This crate is not used directly. Runtime crates depend on it and provide concrete `ProxyBackend` implementations. If you're building a custom runtime integration, depend on this crate and implement `ProxyBackend`, `BucketRegistry`, and/or `CredentialRegistry`.

### Standard usage

```rust
use multistore::proxy::ProxyGateway;
use multistore::cors::CorsMiddleware;
use multistore_static_config::StaticProvider;

let backend = MyBackend::new();
let forwarder = MyForwarder::new();
let config = StaticProvider::from_file("config.toml")?;
let domain = Some("s3.example.com".into());

let gateway = ProxyGateway::new(backend, forwarder, domain.clone())
    // Optional: CORS support (place before S3 defaults so preflight skips auth)
    .with_middleware(CorsMiddleware::new(config.clone(), domain.clone()))
    // Register S3 request processing middleware (op parsing, auth, bucket resolution)
    .with_s3_defaults(config.clone(), config);

// Optional: register a Router for STS, OIDC discovery, etc.
// let router = Router::new().with_sts(...).with_oidc_discovery(...);
// let gateway = gateway.with_middleware(router);

// In your HTTP handler, use handle_request for a two-variant match:
let req_info = RequestInfo::new(&method, &path, query.as_deref(), &headers, None);
match gateway.handle_request(&req_info, body, |b| to_bytes(b)).await {
    GatewayResponse::Response(result) => {
        // Return the complete response (LIST, errors, STS, etc.)
    }
    GatewayResponse::Forward(fwd) => {
        // Stream the forwarded response to the client
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

The `multistore-sts` crate provides `TokenKey`, a sealed-token implementation using AES-256-GCM. Register it via `ProxyGateway::with_s3_defaults_and_resolver()`. See the [sealed tokens documentation](../docs/auth/sealed-tokens.md) for details.

## Feature Flags

All optional — the default build has zero network dependencies:

- `azure` — enables Azure Blob Storage backend support
- `gcp` — enables Google Cloud Storage backend support
