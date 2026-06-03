# Caching

`CachedProvider` wraps any inner provider implementing `BucketRegistry` and/or `CredentialRegistry` to add in-memory TTL-based caching. It is useful for network-backed providers where repeated credential/role lookups would otherwise hit the backend.

> [!NOTE]
> `CachedProvider` is **example code**, not part of the published library. It is defined in the server example at `examples/server/src/cached.rs` and used within that example's own binary (`multistore_server::cached::CachedProvider`). The `multistore_server` example crate is `publish = false`, so this type is not an importable library API — copy or adapt it for your own deployment.

`CachedProvider` implements `BucketRegistry` when the inner provider does and `CredentialRegistry` when the inner provider does. Credential and role lookups are cached; bucket resolution and listing are delegated directly (since they involve identity-aware authorization).

## Usage

```rust
use multistore_server::cached::CachedProvider;
use multistore_static_config::StaticProvider;
use std::time::Duration;

let base = StaticProvider::from_file("config.toml")?;
let provider = CachedProvider::new(base, Duration::from_secs(300));
```

The first call hits the underlying provider; subsequent calls within the TTL return cached data.

## Cache Behavior

- **Thread-safe**: Uses `RwLock` internally, safe for concurrent access
- **Lazy eviction**: Expired entries are evicted on access, not proactively
- **Per-entity caching**: Each role and credential is cached independently
- **BucketRegistry pass-through**: `get_bucket` and `list_buckets` are always delegated to the inner provider (authorization must not be cached)

## Eviction

Eviction is entirely lazy and TTL-based. Each cached credential or role carries an insertion timestamp; on the next lookup after the TTL elapses, the stale entry is ignored and the value is re-fetched from the inner provider (and the cache refreshed). There is no manual-invalidation API — the type implements only `CachedProvider::new(inner, ttl)` plus the two registry traits. To pick up config changes sooner, use a shorter TTL.

## Recommended TTLs

A shorter TTL means fresher data at the cost of more lookups against the inner provider; a longer TTL reduces backend load at the cost of staleness. Values in the 30–300s range are typical, depending on how quickly config changes need to propagate.

The server example binary uses a 60-second TTL by default when wrapping the static file provider.
