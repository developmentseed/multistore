# Custom Credential Registry

The `CredentialRegistry` trait defines how the proxy looks up credentials and roles for authentication. Implement it to plug in your own credential backend.

## The Trait

```rust
use multistore::registry::CredentialRegistry;
use multistore::error::ProxyError;
use multistore::types::*;

pub trait CredentialRegistry: Clone + Send + Sync + 'static {
    async fn get_credential(&self, access_key_id: &str)
        -> Result<Option<StoredCredential>, ProxyError>;
    async fn get_role(&self, role_id: &str)
        -> Result<Option<RoleConfig>, ProxyError>;
}
```

## Example: Redis Provider

```rust
use multistore::registry::CredentialRegistry;
use multistore::error::ProxyError;
use multistore::types::*;

#[derive(Clone)]
struct RedisCredentialRegistry {
    client: redis::Client,
}

impl CredentialRegistry for RedisCredentialRegistry {
    async fn get_credential(&self, access_key_id: &str)
        -> Result<Option<StoredCredential>, ProxyError>
    {
        let mut conn = self.client.get_async_connection().await
            .map_err(|e| ProxyError::Internal(e.to_string()))?;

        let json: Option<String> = redis::cmd("GET")
            .arg(format!("credential:{}", access_key_id))
            .query_async(&mut conn)
            .await
            .map_err(|e| ProxyError::Internal(e.to_string()))?;

        match json {
            Some(j) => Ok(Some(serde_json::from_str(&j)
                .map_err(|e| ProxyError::ConfigError(e.to_string()))?)),
            None => Ok(None),
        }
    }

    async fn get_role(&self, role_id: &str) -> Result<Option<RoleConfig>, ProxyError> {
        // Similar Redis GET with key "role:{role_id}"
        todo!()
    }
}
```

## Using with the Gateway

Pass your credential registry directly to `ProxyGateway`. The gateway handles S3 request parsing and identity resolution internally:

```rust
let bucket_registry = MyBucketRegistry::new(/* ... */);
let cred_registry = RedisCredentialRegistry::new(redis_client);

let gateway = ProxyGateway::new(backend, forwarder, virtual_host_domain)
    .with_s3_defaults(bucket_registry, cred_registry);
```
