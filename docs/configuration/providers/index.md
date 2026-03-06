# Config Providers

The proxy resolves its configuration through two registry traits:

- **`BucketRegistry`** — bucket lookup, authorization, and listing (product-specific policy)
- **`CredentialRegistry`** — credential and role storage (auth infrastructure)

The built-in `StaticProvider` implements both traits, loading config from a TOML or JSON file.

## Registry Traits

```rust
pub trait BucketRegistry: Clone + Send + Sync + 'static {
    async fn get_bucket(&self, name: &str, identity: &ResolvedIdentity, operation: &S3Operation)
        -> Result<ResolvedBucket, ProxyError>;
    async fn list_buckets(&self, identity: &ResolvedIdentity)
        -> Result<Vec<BucketEntry>, ProxyError>;
}

pub trait CredentialRegistry: Clone + Send + Sync + 'static {
    async fn get_credential(&self, access_key_id: &str)
        -> Result<Option<StoredCredential>, ProxyError>;
    async fn get_role(&self, role_id: &str)
        -> Result<Option<RoleConfig>, ProxyError>;
}
```

## Available Providers

| Provider | Feature Flag | Best For |
|----------|-------------|----------|
| [Static File](./static-file) | (always available) | Simple deployments, single-file config |
| [HTTP API](./http) | `config-http` | Centralized config service, control planes |
| [DynamoDB](./dynamodb) | `config-dynamodb` | AWS-native infrastructure |
| [PostgreSQL](./postgres) | `config-postgres` | Database-backed config |

All providers can be wrapped with [CachedProvider](./cached) for in-memory caching with TTL-based expiration.

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
