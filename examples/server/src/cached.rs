//! Caching wrapper for any [`ConfigProvider`].
//!
//! Adds in-memory TTL-based caching over a delegate provider. This is
//! recommended for network-backed providers to reduce latency and load
//! on the config backend.

use multistore::config::ConfigProvider;
use multistore::error::ProxyError;
use multistore::s3::response::BucketOwner;
use multistore::types::{BucketConfig, RoleConfig, StoredCredential};
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

/// Wraps a [`ConfigProvider`] with in-memory TTL-based caching.
///
/// Thread-safe via `RwLock`. Cache entries are evicted lazily on access.
#[derive(Clone)]
pub struct CachedProvider<P> {
    inner: P,
    cache: Arc<CacheState>,
    ttl: Duration,
}

struct CacheState {
    buckets_list: RwLock<Option<CacheEntry<Vec<BucketConfig>>>>,
    buckets: RwLock<HashMap<String, CacheEntry<Option<BucketConfig>>>>,
    roles: RwLock<HashMap<String, CacheEntry<Option<RoleConfig>>>>,
    credentials: RwLock<HashMap<String, CacheEntry<Option<StoredCredential>>>>,
}

impl<P: ConfigProvider> CachedProvider<P> {
    /// Create a new caching wrapper with the given TTL.
    pub fn new(inner: P, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Arc::new(CacheState {
                buckets_list: RwLock::new(None),
                buckets: RwLock::new(HashMap::new()),
                roles: RwLock::new(HashMap::new()),
                credentials: RwLock::new(HashMap::new()),
            }),
            ttl,
        }
    }
}

impl<P: ConfigProvider> ConfigProvider for CachedProvider<P> {
    fn bucket_owner(&self) -> BucketOwner {
        self.inner.bucket_owner()
    }

    async fn list_buckets(&self) -> Result<Vec<BucketConfig>, ProxyError> {
        // Check cache
        if let Ok(lock) = self.cache.buckets_list.read() {
            if let Some(entry) = &*lock {
                if !entry.is_expired(self.ttl) {
                    return Ok(entry.value.clone());
                }
            }
        }

        // Cache miss — fetch from inner
        let result = self.inner.list_buckets().await?;

        if let Ok(mut lock) = self.cache.buckets_list.write() {
            *lock = Some(CacheEntry {
                value: result.clone(),
                inserted_at: Instant::now(),
            });
        }

        Ok(result)
    }

    async fn get_bucket(&self, name: &str) -> Result<Option<BucketConfig>, ProxyError> {
        // Check cache
        if let Ok(lock) = self.cache.buckets.read() {
            if let Some(entry) = lock.get(name) {
                if !entry.is_expired(self.ttl) {
                    return Ok(entry.value.clone());
                }
            }
        }

        let result = self.inner.get_bucket(name).await?;

        if let Ok(mut lock) = self.cache.buckets.write() {
            lock.insert(
                name.to_string(),
                CacheEntry {
                    value: result.clone(),
                    inserted_at: Instant::now(),
                },
            );
        }

        Ok(result)
    }

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
