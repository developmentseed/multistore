# Caching

Wrap any provider with `CachedProvider` to add in-memory TTL-based caching. This is recommended for all network-backed providers (HTTP, DynamoDB, PostgreSQL).

`CachedProvider` implements both `BucketRegistry` and `CredentialRegistry` when the inner provider does. Credential and role lookups are cached; bucket resolution and listing are delegated directly (since they involve identity-aware authorization).

## Usage

```rust
use multistore_server::cached::CachedProvider;
use std::time::Duration;

let base = HttpProvider::new("https://config-api.internal".into(), None);
let provider = CachedProvider::new(base, Duration::from_secs(300));
```

The first call hits the underlying provider; subsequent calls within the TTL return cached data.

## Cache Behavior

- **Thread-safe**: Uses `RwLock` internally, safe for concurrent access
- **Lazy eviction**: Expired entries are evicted on access, not proactively
- **Per-entity caching**: Each role and credential is cached independently
- **BucketRegistry pass-through**: `get_bucket` and `list_buckets` are always delegated to the inner provider (authorization must not be cached)

## Manual Invalidation

```rust
// Invalidate everything
provider.invalidate_all();

// Invalidate a specific bucket
provider.invalidate_bucket("my-bucket");
```

## Recommended TTLs

| Provider | Suggested TTL | Rationale |
|----------|--------------|-----------|
| HTTP API | 60–300s | Balance between freshness and API load |
| DynamoDB | 60–300s | Reduce read capacity costs |
| PostgreSQL | 30–120s | Reduce query load |

The server example binary uses a 60-second TTL by default when wrapping the static file provider.
