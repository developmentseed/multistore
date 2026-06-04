//! A small credential cache with single-flight refresh.
//!
//! Short-lived credentials (backend STS sessions, cloud bearer tokens) are
//! expensive to mint: a proxy that re-minted them on every request would hammer
//! the issuing STS and add latency to every read. This cache holds the current
//! value per **credential identity** (an opaque key the caller chooses — e.g. a
//! role ARN, or the rendered OIDC subject) and:
//!
//! - serves a cached value while it's still comfortably valid,
//! - **proactively refreshes** once it's within `refresh_lead` of expiry (so a
//!   credential never expires mid-use), and
//! - **single-flights** refreshes: concurrent callers for the same key await one
//!   in-flight fetch rather than each launching their own.
//!
//! The cache is generic over any value that knows when it expires (implements
//! [`Expiring`]) and over the error its fetch closure returns, so it is shared
//! by every crate that mints short-lived credentials rather than each rolling
//! its own.
//!
//! The cache is runtime-agnostic. It takes the current time as a parameter
//! rather than reading a clock (multistore targets both native and
//! `wasm32-unknown-unknown`) and uses [`futures::lock::Mutex`] so it needs no
//! async runtime.
//!
//! ```
//! use chrono::{DateTime, Duration, Utc};
//! use multistore_credential_cache::{CredentialCache, Expiring};
//!
//! #[derive(Clone)]
//! struct Creds {
//!     token: String,
//!     expiration: DateTime<Utc>,
//! }
//! impl Expiring for Creds {
//!     fn expiration(&self) -> DateTime<Utc> {
//!         self.expiration
//!     }
//! }
//!
//! # async fn run() -> Result<(), ()> {
//! let cache = CredentialCache::new(Duration::minutes(5));
//! let creds = cache
//!     .get_or_fetch("arn:aws:iam::123:role/r", Utc::now(), || async {
//!         Ok::<_, ()>(Creds { token: "t".into(), expiration: Utc::now() + Duration::hours(1) })
//!     })
//!     .await?;
//! # let _ = creds; Ok(())
//! # }
//! ```

use chrono::{DateTime, Duration, Utc};
use futures::lock::Mutex as AsyncMutex;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

/// A cached value that knows when it expires.
///
/// The cache uses this to decide when a value is due for proactive refresh.
/// Implement it for any credential type you want to cache.
pub trait Expiring {
    /// When this value expires.
    fn expiration(&self) -> DateTime<Utc>;
}

/// Caching a shared value (`Arc<T>`) is as cacheable as caching `T` itself.
impl<T: Expiring> Expiring for Arc<T> {
    fn expiration(&self) -> DateTime<Utc> {
        (**self).expiration()
    }
}

type Slot<T> = Arc<AsyncMutex<Option<T>>>;

/// Caches short-lived [`Expiring`] credentials per credential identity, with
/// proactive refresh and single-flight.
///
/// Cheap to share behind an `Arc`; all methods take `&self`.
pub struct CredentialCache<T> {
    /// How long before expiry a cached credential is considered due for refresh.
    refresh_lead: Duration,
    /// One async-locked slot per key. The outer `Mutex` only guards insertion
    /// into the map and is never held across an `.await`; the per-key
    /// [`AsyncMutex`] is what serializes (single-flights) refreshes.
    slots: Mutex<HashMap<String, Slot<T>>>,
}

impl<T: Expiring + Clone> CredentialCache<T> {
    /// Create a cache that refreshes credentials once they're within
    /// `refresh_lead` of their expiry.
    pub fn new(refresh_lead: Duration) -> Self {
        Self {
            refresh_lead,
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Return cached credentials for `key` if still fresh, otherwise run `fetch`
    /// (single-flighted) to obtain and cache new ones.
    ///
    /// `now` is the current time, supplied by the caller. A cached value is
    /// considered fresh while `now < expiration - refresh_lead`.
    ///
    /// Single-flight: while one caller is running `fetch` for a key, concurrent
    /// callers for that same key block on the per-key lock; when it releases
    /// they observe the freshly-cached value and return it without calling their
    /// own `fetch`.
    pub async fn get_or_fetch<F, Fut, E>(
        &self,
        key: &str,
        now: DateTime<Utc>,
        fetch: F,
    ) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let slot = self.slot(key);
        let mut guard = slot.lock().await;

        if let Some(creds) = guard.as_ref() {
            if self.is_fresh(creds, now) {
                return Ok(creds.clone());
            }
        }

        let fresh = fetch().await?;
        *guard = Some(fresh.clone());
        Ok(fresh)
    }

    /// Drop any cached credentials for `key`, forcing the next
    /// [`get_or_fetch`](Self::get_or_fetch) to fetch.
    ///
    /// Useful when the backend rejects a still-"fresh" credential (e.g. a 403
    /// after an out-of-band revocation) and the caller wants to re-mint.
    pub fn invalidate(&self, key: &str) {
        self.slots
            .lock()
            .expect("credential cache mutex poisoned")
            .remove(key);
    }

    fn is_fresh(&self, creds: &T, now: DateTime<Utc>) -> bool {
        now < creds.expiration() - self.refresh_lead
    }

    fn slot(&self, key: &str) -> Slot<T> {
        self.slots
            .lock()
            .expect("credential cache mutex poisoned")
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(None)))
            .clone()
    }
}

impl<T: Expiring + Clone> Default for CredentialCache<T> {
    /// A cache that refreshes 5 minutes before expiry.
    fn default() -> Self {
        Self::new(Duration::minutes(5))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct Creds {
        id: String,
        expiration: DateTime<Utc>,
    }

    impl Expiring for Creds {
        fn expiration(&self) -> DateTime<Utc> {
            self.expiration
        }
    }

    fn at(hour: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 3, hour, min, 0).unwrap()
    }

    fn creds(expiration: DateTime<Utc>) -> Creds {
        Creds {
            id: "ASIA".into(),
            expiration,
        }
    }

    #[tokio::test]
    async fn fetches_on_miss() {
        let cache = CredentialCache::new(Duration::minutes(5));
        let got = cache
            .get_or_fetch("k", at(10, 0), || async { Ok::<_, ()>(creds(at(11, 0))) })
            .await
            .unwrap();
        assert_eq!(got.id, "ASIA");
    }

    #[tokio::test]
    async fn reuses_while_fresh() {
        let cache = CredentialCache::new(Duration::minutes(5));
        cache
            .get_or_fetch("k", at(10, 0), || async { Ok::<_, ()>(creds(at(11, 0))) })
            .await
            .unwrap();
        // Well before the lead window (expiry 11:00, lead 5m → refresh at 10:55).
        let got = cache
            .get_or_fetch::<_, _, ()>("k", at(10, 30), || async {
                panic!("must not fetch while cached creds are fresh")
            })
            .await
            .unwrap();
        assert_eq!(got.expiration, at(11, 0));
    }

    #[tokio::test]
    async fn refreshes_within_lead_window() {
        let cache = CredentialCache::new(Duration::minutes(5));
        cache
            .get_or_fetch("k", at(10, 0), || async { Ok::<_, ()>(creds(at(11, 0))) })
            .await
            .unwrap();
        // 10:56 is inside the 5-minute lead before the 11:00 expiry → refetch.
        let got = cache
            .get_or_fetch("k", at(10, 56), || async { Ok::<_, ()>(creds(at(12, 0))) })
            .await
            .unwrap();
        assert_eq!(got.expiration, at(12, 0));
    }

    #[tokio::test]
    async fn invalidate_forces_refetch() {
        let cache = CredentialCache::new(Duration::minutes(5));
        cache
            .get_or_fetch("k", at(10, 0), || async { Ok::<_, ()>(creds(at(11, 0))) })
            .await
            .unwrap();
        cache.invalidate("k");
        let got = cache
            .get_or_fetch("k", at(10, 1), || async { Ok::<_, ()>(creds(at(13, 0))) })
            .await
            .unwrap();
        assert_eq!(got.expiration, at(13, 0));
    }

    #[tokio::test]
    async fn keys_are_isolated() {
        let cache = CredentialCache::new(Duration::minutes(5));
        cache
            .get_or_fetch("a", at(10, 0), || async { Ok::<_, ()>(creds(at(11, 0))) })
            .await
            .unwrap();
        let got = cache
            .get_or_fetch("b", at(10, 0), || async { Ok::<_, ()>(creds(at(12, 0))) })
            .await
            .unwrap();
        assert_eq!(got.expiration, at(12, 0));
    }

    #[tokio::test]
    async fn single_flights_concurrent_fetches() {
        let cache = Arc::new(CredentialCache::new(Duration::minutes(5)));
        let calls = Arc::new(AtomicUsize::new(0));
        let now = at(10, 0);

        let one = {
            let cache = cache.clone();
            let calls = calls.clone();
            async move {
                cache
                    .get_or_fetch("k", now, || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        // Yield while holding the per-key lock so the sibling
                        // future contends for it — exercising single-flight.
                        tokio::task::yield_now().await;
                        Ok::<_, ()>(creds(at(11, 0)))
                    })
                    .await
            }
        };
        let two = {
            let cache = cache.clone();
            let calls = calls.clone();
            async move {
                cache
                    .get_or_fetch("k", now, || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, ()>(creds(at(11, 0)))
                    })
                    .await
            }
        };

        let (a, b) = tokio::join!(one, two);
        a.unwrap();
        b.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "fetch should run once");
    }
}
