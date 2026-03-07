# Custom Bucket Registry

The `BucketRegistry` trait controls how virtual buckets are resolved and authorized. Implement it for custom namespace mapping, per-request authorization, or dynamic bucket configuration.

## The Trait

```rust
use multistore::registry::{BucketRegistry, ResolvedBucket};
use multistore::api::response::BucketEntry;
use multistore::error::ProxyError;
use multistore::types::{BucketOwner, ResolvedIdentity, S3Operation};

pub trait BucketRegistry: Clone + Send + Sync + 'static {
    fn get_bucket(
        &self,
        name: &str,
        identity: &ResolvedIdentity,
        operation: &S3Operation,
    ) -> impl Future<Output = Result<ResolvedBucket, ProxyError>> + Send;

    fn list_buckets(
        &self,
        identity: &ResolvedIdentity,
    ) -> impl Future<Output = Result<Vec<BucketEntry>, ProxyError>> + Send;

    fn bucket_owner(&self) -> BucketOwner { /* default */ }
}
```

## ResolvedBucket

The registry returns a `ResolvedBucket` containing the backend configuration:

```rust
pub struct ResolvedBucket {
    /// Backend configuration for this bucket.
    pub config: BucketConfig,
    /// Optional rewrite rule for list response XML.
    pub list_rewrite: Option<ListRewrite>,
}
```

## Example: API-Backed Registry

A registry that looks up buckets from an external API and authorizes per-request:

```rust
use multistore::registry::{BucketRegistry, ResolvedBucket};
use multistore::api::response::BucketEntry;
use multistore::error::ProxyError;
use multistore::types::{BucketOwner, ResolvedIdentity, S3Operation};

#[derive(Clone)]
struct MyRegistry {
    api_client: ApiClient,
}

impl BucketRegistry for MyRegistry {
    async fn get_bucket(
        &self,
        name: &str,
        identity: &ResolvedIdentity,
        operation: &S3Operation,
    ) -> Result<ResolvedBucket, ProxyError> {
        // Look up the backend config from an external API
        let bucket_config = self.api_client
            .get_backend(name)
            .await
            .map_err(|_| ProxyError::BucketNotFound(name.to_string()))?;

        // Authorize via external service or built-in auth::authorize
        multistore::auth::authorize(identity, operation, &bucket_config)?;

        Ok(ResolvedBucket {
            config: bucket_config,
            list_rewrite: None,
        })
    }

    async fn list_buckets(
        &self,
        _identity: &ResolvedIdentity,
    ) -> Result<Vec<BucketEntry>, ProxyError> {
        let buckets = self.api_client.list_buckets().await
            .map_err(|e| ProxyError::Internal(e.to_string()))?;

        Ok(buckets.into_iter().map(|b| BucketEntry {
            name: b.name,
            creation_date: "2024-01-01T00:00:00.000Z".to_string(),
        }).collect())
    }
}
```

## Wiring Into the Gateway

```rust
let registry = MyRegistry::new(api_client);
let cred_registry = MyCredentialRegistry::new(/* ... */);
let gateway = ProxyGateway::new(backend, registry, cred_registry, domain);

// In your request handler:
let req_info = RequestInfo {
    method: &method,
    path: &path,
    query: query.as_deref(),
    headers: &headers,
    params: Default::default(),
};
match gateway.handle_request(&req_info, body, |b| to_bytes(b)).await {
    GatewayResponse::Response(result) => { /* return response */ }
    GatewayResponse::Forward(fwd, body) => { /* execute presigned URL, stream body */ }
}
```

## ListRewrite

The `list_rewrite` field in `ResolvedBucket` allows you to transform `<Key>` and `<Prefix>` values in LIST response XML:

```rust
Ok(ResolvedBucket {
    config: bucket_config,
    list_rewrite: Some(ListRewrite {
        strip_prefix: "internal/mirror/".to_string(),
        add_prefix: "public/".to_string(),
    }),
})
```

This is useful when the backend key structure differs from what clients expect.
