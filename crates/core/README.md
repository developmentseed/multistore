# multistore

Runtime-agnostic core library for the S3 proxy gateway. This crate provides an s3s-based S3 service implementation that maps S3 API operations to `object_store` calls, along with trait abstractions for bucket/credential management that allow the proxy to run on multiple runtimes (Tokio/Hyper, AWS Lambda, Cloudflare Workers).

## Why This Crate Exists Separately

The proxy needs to run on fundamentally different runtimes: Tokio/Hyper in containers, AWS Lambda, and Cloudflare Workers on the edge. These runtimes have incompatible stream types, HTTP primitives, and threading models (multi-threaded vs single-threaded WASM). By keeping the core free of runtime dependencies, it compiles cleanly to both native targets and `wasm32-unknown-unknown`.

## Key Abstractions

**`MultistoreService`** — Implements the `s3s::S3` trait, mapping S3 operations (GET, PUT, DELETE, LIST, multipart uploads) to `object_store` calls. Generic over `BucketRegistry` (for bucket lookup/authorization) and `StoreFactory` (for creating object stores per request).

**`MultistoreAuth`** — Implements `s3s::auth::S3Auth`, wrapping a `CredentialRegistry` to provide SigV4 verification. s3s handles signature parsing and verification; this adapter just looks up secret keys.

**`StoreFactory`** — Runtime-provided factory for creating `ObjectStore`, `PaginatedListStore`, and `MultipartStore` instances. Each runtime implements this trait with its own HTTP transport (e.g., reqwest for native, `FetchConnector` for Workers).

**`BucketRegistry`** — Identity-aware bucket resolution and listing. Given a bucket name, identity, and S3 operation, `get_bucket()` returns a `ResolvedBucket` or an authorization error.

**`CredentialRegistry`** — Credential and role lookup for authentication. Provides `get_credential()` for SigV4 verification and `get_role()` for STS role assumption.

**`StoreBuilder`** — Provider-specific `object_store` builder (S3, Azure, GCS). Runtimes call `create_builder()` to get a half-built store, customize it (e.g., inject an HTTP connector), then call one of the `build_*` methods.

## Module Overview

```
src/
├── api/
│   ├── response.rs      S3 XML response serialization
│   ├── list.rs           LIST-specific helpers (prefix building)
│   └── list_rewrite.rs   Rewrite <Key>/<Prefix> values for backend prefix mapping
├── auth/
│   ├── mod.rs            TemporaryCredentialResolver trait
│   └── authorize_impl.rs Scope-based authorization (identity × operation × bucket)
├── backend/
│   ├── mod.rs            StoreBuilder, create_builder()
│   └── url_signer.rs     build_signer() helper
├── registry/
│   ├── bucket.rs         BucketRegistry trait, ResolvedBucket
│   └── credential.rs     CredentialRegistry trait
├── error.rs              ProxyError with S3-compatible error codes
├── maybe_send.rs         MaybeSend/MaybeSync markers for WASM compatibility
├── service.rs            MultistoreService, MultistoreAuth, StoreFactory
└── types.rs              BucketConfig, RoleConfig, StoredCredential, etc.
```

## Usage

This crate is not used directly. Runtime crates depend on it and provide concrete `StoreFactory` implementations.

### Standard usage (s3s)

```rust
use multistore::service::{MultistoreService, MultistoreAuth};
use multistore_static_config::StaticProvider;
use s3s::service::S3ServiceBuilder;

let backend = MyStoreFactory::new();
let config = StaticProvider::from_file("config.toml")?;

let service = MultistoreService::new(config.clone(), backend);
let auth = MultistoreAuth::new(config);

let mut builder = S3ServiceBuilder::new(service);
builder.set_auth(auth);

// Optional: set virtual-hosted-style domain
// builder.set_host(s3s::host::SingleDomain::new("s3.example.com")?);

let s3_service = builder.build();

// Use s3_service with hyper, lambda_http, or call directly
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

## Feature Flags

All optional — the default build has zero network dependencies:

- `azure` — enables Azure Blob Storage backend support
- `gcp` — enables Google Cloud Storage backend support
