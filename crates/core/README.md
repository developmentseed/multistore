# multistore

Runtime-agnostic core library for the [`multistore`](https://github.com/developmentseed/multistore) S3 proxy gateway. Contains all business logic — S3 request parsing, SigV4 signing/verification, authorization, and the proxy handler — without depending on any async runtime.

## Why This Crate Exists Separately

The proxy runs on fundamentally different runtimes: Tokio/Hyper in containers and Cloudflare Workers on the edge. These have incompatible stream types, HTTP primitives, and threading models. Keeping the core runtime-free lets it compile to both native and `wasm32-unknown-unknown`.

## Key Abstractions

- **`ProxyBackend`** — runtime-specific HTTP client for forwarding requests, creating object stores, and signing URLs
- **`BucketRegistry`** — identity-aware bucket resolution and authorization (see `multistore-static-config` for a file-based implementation)
- **`CredentialRegistry`** — credential and role lookup for SigV4 verification and STS (see `multistore-static-config`)
- **`Middleware`** — composable post-auth request processing (see `multistore-oidc-provider`, `multistore-metering`)

## Usage

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

match gateway.handle_request(&req_info, body, |b| to_bytes(b)).await {
    GatewayResponse::Response(result) => { /* buffered response */ }
    GatewayResponse::Forward(fwd, body) => { /* streaming forward */ }
}
```

## Feature Flags

- `azure` — Azure Blob Storage backend support
- `gcp` — Google Cloud Storage backend support
