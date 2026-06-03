# Config Providers

The proxy resolves its configuration through two registry traits:

- **`BucketRegistry`** — bucket lookup, authorization, and listing (product-specific policy)
- **`CredentialRegistry`** — credential and role storage (auth infrastructure)

The built-in `StaticProvider` implements both traits, loading config from a TOML or JSON file.

## Registry Traits

The traits are bounded `Clone + MaybeSend + MaybeSync + 'static` (so the same impl works on native multi-threaded runtimes and single-threaded WASM) and use return-position `impl Future` rather than `async fn`:

```rust
use std::future::Future;

pub trait BucketRegistry: Clone + MaybeSend + MaybeSync + 'static {
    fn get_bucket(
        &self,
        name: &str,
        identity: &ResolvedIdentity,
        operation: &S3Operation,
    ) -> impl Future<Output = Result<ResolvedBucket, ProxyError>> + MaybeSend;

    fn list_buckets(
        &self,
        identity: &ResolvedIdentity,
    ) -> impl Future<Output = Result<Vec<BucketEntry>, ProxyError>> + MaybeSend;

    /// The owner identity returned in `ListAllMyBucketsResult` responses.
    /// Provided default returns `("multistore-proxy", "multistore-proxy")`.
    fn bucket_owner(&self) -> BucketOwner {
        BucketOwner {
            id: "multistore-proxy".to_string(),
            display_name: "multistore-proxy".to_string(),
        }
    }
}

pub trait CredentialRegistry: Clone + MaybeSend + MaybeSync + 'static {
    fn get_credential(
        &self,
        access_key_id: &str,
    ) -> impl Future<Output = Result<Option<StoredCredential>, ProxyError>> + MaybeSend;

    fn get_role(
        &self,
        role_id: &str,
    ) -> impl Future<Output = Result<Option<RoleConfig>, ProxyError>> + MaybeSend;
}
```

## Available Providers

| Provider | Status | Best For |
|----------|--------|----------|
| [Static File](./static-file) | Built-in (always available) | Simple deployments, single-file config |

`StaticProvider` is the only built-in config provider. Any type implementing both registry traits can be wrapped with the example [CachedProvider](./cached) for in-memory caching with TTL-based expiration, or you can implement the traits yourself for a custom backend.

## Implementing Custom Registries

Implement `BucketRegistry` for custom bucket lookup/authorization logic, and `CredentialRegistry` for custom credential storage:

```rust
use multistore::registry::{BucketRegistry, CredentialRegistry};
use multistore::error::ProxyError;
use multistore::types::*;

#[derive(Clone)]
struct MyProvider { /* ... */ }

impl CredentialRegistry for MyProvider {
    async fn get_credential(&self, access_key_id: &str)
        -> Result<Option<StoredCredential>, ProxyError> {
        todo!()
    }
    async fn get_role(&self, role_id: &str)
        -> Result<Option<RoleConfig>, ProxyError> {
        todo!()
    }
}
```

See [Custom Bucket Registry](/extending/custom-resolver) and [Custom Credential Registry](/extending/custom-provider) for full guides.
