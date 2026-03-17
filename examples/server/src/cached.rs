//! Caching wrapper for any [`BucketRegistry`] + [`CredentialRegistry`].
//!
//! Adds in-memory TTL-based caching over a delegate provider. This is
//! recommended for network-backed providers to reduce latency and load
//! on the config backend.

use multistore::api::response::BucketEntry;
use multistore::error::ProxyError;
use multistore::registry::{BucketRegistry, CredentialRegistry, ResolvedBucket};
use multistore::types::{BucketOwner, ResolvedIdentity, RoleConfig, S3Operation, StoredCredential};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// A cache entry with a value and expiration time.
#[derive(Clone)]
struct CacheEntry<T> {
    value: T,
    inserted_at: Instant,
}

impl<T: Clone> CacheEntry<T> {
    fn is_expired(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() > ttl
    }
}

/// Wraps a provider with in-memory TTL-based caching.
///
/// Thread-safe via `RwLock`. Cache entries are evicted lazily on access.
///
/// Caching is applied to the [`CredentialRegistry`] methods (credential
/// and role lookups). [`BucketRegistry`] methods are delegated directly
/// since they involve identity-aware authorization that should not be cached.
#[derive(Clone)]
pub struct CachedProvider<P> {
    inner: P,
    cache: Arc<CacheState>,
    ttl: Duration,
}

struct CacheState {
    roles: RwLock<HashMap<String, CacheEntry<Option<RoleConfig>>>>,
    credentials: RwLock<HashMap<String, CacheEntry<Option<StoredCredential>>>>,
}

impl<P> CachedProvider<P> {
    /// Create a new caching wrapper with the given TTL.
    pub fn new(inner: P, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Arc::new(CacheState {
                roles: RwLock::new(HashMap::new()),
                credentials: RwLock::new(HashMap::new()),
            }),
            ttl,
        }
    }
}

impl<P: BucketRegistry> BucketRegistry for CachedProvider<P> {
    fn bucket_owner(&self) -> BucketOwner {
        self.inner.bucket_owner()
    }

    async fn get_bucket(
        &self,
        name: &str,
        identity: &ResolvedIdentity,
        operation: &S3Operation,
    ) -> Result<ResolvedBucket, ProxyError> {
        self.inner.get_bucket(name, identity, operation).await
    }

    async fn list_buckets(
        &self,
        identity: &ResolvedIdentity,
    ) -> Result<Vec<BucketEntry>, ProxyError> {
        self.inner.list_buckets(identity).await
    }
}

impl<P: multistore::cors::CorsProvider> multistore::cors::CorsProvider for CachedProvider<P> {
    async fn get_cors_config(&self, bucket_name: &str) -> Option<multistore::cors::CorsConfig> {
        self.inner.get_cors_config(bucket_name).await
    }
}

impl<P: CredentialRegistry> CredentialRegistry for CachedProvider<P> {
    async fn get_role(&self, role_id: &str) -> Result<Option<RoleConfig>, ProxyError> {
        if let Ok(lock) = self.cache.roles.read() {
            if let Some(entry) = lock.get(role_id) {
                if !entry.is_expired(self.ttl) {
                    return Ok(entry.value.clone());
                }
            }
        }

        let result = self.inner.get_role(role_id).await?;

        if let Ok(mut lock) = self.cache.roles.write() {
            lock.insert(
                role_id.to_string(),
                CacheEntry {
                    value: result.clone(),
                    inserted_at: Instant::now(),
                },
            );
        }

        Ok(result)
    }

    async fn get_credential(
        &self,
        access_key_id: &str,
    ) -> Result<Option<StoredCredential>, ProxyError> {
        if let Ok(lock) = self.cache.credentials.read() {
            if let Some(entry) = lock.get(access_key_id) {
                if !entry.is_expired(self.ttl) {
                    return Ok(entry.value.clone());
                }
            }
        }

        let result = self.inner.get_credential(access_key_id).await?;

        if let Ok(mut lock) = self.cache.credentials.write() {
            lock.insert(
                access_key_id.to_string(),
                CacheEntry {
                    value: result.clone(),
                    inserted_at: Instant::now(),
                },
            );
        }

        Ok(result)
    }
}
