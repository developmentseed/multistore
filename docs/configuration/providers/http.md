# HTTP API Provider

::: warning Planned — not yet implemented
This config provider is a planned feature and does not exist in the current release. The API shown here is a design sketch and is subject to change. The only built-in config provider today is the [static file provider](./static-file.md).
:::

The HTTP provider would fetch configuration from a centralized REST API — useful when you have a control plane service that manages proxy configuration. The sketch below illustrates the intended shape of the API.

## Usage (design sketch)

The intended constructor would look like:

```rust
use multistore::config::http::HttpProvider;

let provider = HttpProvider::new(
    "https://config-api.internal:8080".to_string(),
    Some("Bearer my-api-token".to_string()),
);
```

## Expected API Endpoints

As designed, the HTTP provider would expect a REST API with these endpoints:

| Endpoint | Method | Returns |
|----------|--------|---------|
| `/buckets` | GET | `Vec<BucketConfig>` |
| `/buckets/{name}` | GET | `Option<BucketConfig>` |
| `/roles/{id}` | GET | `Option<RoleConfig>` |
| `/credentials/{access_key_id}` | GET | `Option<StoredCredential>` |

All responses should be JSON-encoded. Missing resources should return `null` or a 404 status.

## When to Use

- Centralized config management across multiple proxy instances
- Dynamic configuration that changes without proxy restarts (when combined with [caching](./cached))
- Integration with a custom control plane or admin dashboard
