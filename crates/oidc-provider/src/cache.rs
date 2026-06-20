//! Credential cache with single-flight refresh.
//!
//! Caches [`BackendCredentials`] by key so the proxy doesn't re-mint and
//! re-exchange on every request. Beyond a plain TTL cache it:
//!
//! - **serves while fresh** — returns a cached value directly while it is
//!   comfortably valid,
//! - **proactively refreshes** — once a value is within [`REFRESH_LEAD_SECS`]
//!   of expiry, the next access re-mints it, so a credential is never handed
//!   out about to expire mid-request, and
//! - **single-flights** — while one caller is minting for a key, concurrent
//!   callers for that *same* key await the in-flight result instead of each
//!   launching their own exchange. A cold-cache burst collapses to one STS call.
//!
//! The fetch happens through a caller-supplied closure ([`get_or_fetch`]), so
//! the cache never needs to know how credentials are minted, and a runtime can
//! layer an additional cache tier (e.g. the Cloudflare Cache API) inside the
//! closure. See `docs/architecture/caching.md`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use futures::lock::Mutex as AsyncMutex;

use crate::BackendCredentials;

/// Refresh a cached credential once it is within this many seconds of expiry,
/// so it is never handed out about to expire mid-request.
const REFRESH_LEAD_SECS: i64 = 60;

/// One async-locked slot per key. The per-key [`AsyncMutex`] is what serializes
/// (single-flights) refreshes; the value is shared via `Arc`.
type Slot = Arc<AsyncMutex<Option<Arc<BackendCredentials>>>>;

/// Thread-safe credential cache with proactive refresh and single-flight.
///
/// `Clone` shares the same underlying store (the slot map is behind an `Arc`),
/// so a cloned [`OidcCredentialProvider`](crate::OidcCredentialProvider) keeps
/// hitting the same cache — letting a runtime hold the provider in a
/// shared/`static` slot and reuse it across requests instead of re-minting and
/// re-exchanging every time.
#[derive(Clone, Default)]
pub struct CredentialCache {
    /// One slot per key. The outer `Mutex` only guards insertion into the map
    /// and is never held across an `.await`; the per-key [`AsyncMutex`] inside
    /// each [`Slot`] is what single-flights refreshes.
    slots: Arc<Mutex<HashMap<String, Slot>>>,
}

impl CredentialCache {
    /// Create an empty credential cache.
    pub fn new() -> Self {
        Self {
            slots: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Return cached credentials for `key` if still fresh, otherwise run `fetch`
    /// (single-flighted) to obtain and cache new ones.
    ///
    /// A cached value is fresh while `now < expiration - REFRESH_LEAD_SECS`.
    ///
    /// Single-flight: while one caller is running `fetch` for a key, concurrent
    /// callers for that same key block on the per-key lock; when it releases
    /// they observe the freshly-cached value and return it without calling their
    /// own `fetch`.
    pub async fn get_or_fetch<F, Fut, E>(
        &self,
        key: &str,
        fetch: F,
    ) -> Result<Arc<BackendCredentials>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Arc<BackendCredentials>, E>>,
    {
        let slot = self.slot(key);
        let mut guard = slot.lock().await;

        if let Some(creds) = guard.as_ref() {
            if is_fresh(creds) {
                return Ok(creds.clone());
            }
        }

        let fresh = fetch().await?;
        *guard = Some(fresh.clone());
        Ok(fresh)
    }

    fn slot(&self, key: &str) -> Slot {
        self.slots
            .lock()
            .expect("credential cache mutex poisoned")
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(None)))
            .clone()
    }
}

/// A credential is fresh while it is more than [`REFRESH_LEAD_SECS`] from expiry.
fn is_fresh(creds: &BackendCredentials) -> bool {
    creds.expiration > Utc::now() + Duration::seconds(REFRESH_LEAD_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn creds(expires_in_secs: i64) -> Arc<BackendCredentials> {
        Arc::new(BackendCredentials {
            access_key_id: "AKID".into(),
            secret_access_key: "secret".into(),
            session_token: "token".into(),
            expiration: Utc::now() + Duration::seconds(expires_in_secs),
        })
    }

    #[tokio::test]
    async fn fetches_on_miss() {
        let cache = CredentialCache::new();
        let got = cache
            .get_or_fetch("k", || async { Ok::<_, ()>(creds(600)) })
            .await
            .unwrap();
        assert_eq!(got.access_key_id, "AKID");
    }

    #[tokio::test]
    async fn reuses_while_fresh() {
        let cache = CredentialCache::new();
        cache
            .get_or_fetch("k", || async { Ok::<_, ()>(creds(600)) })
            .await
            .unwrap();
        // Well outside the 60s refresh lead → must not re-fetch.
        let got = cache
            .get_or_fetch::<_, _, ()>("k", || async {
                panic!("must not fetch while cached creds are fresh")
            })
            .await
            .unwrap();
        assert_eq!(got.access_key_id, "AKID");
    }

    #[tokio::test]
    async fn refreshes_within_lead_window() {
        let cache = CredentialCache::new();
        // Expires in 30s — inside the 60s refresh lead → due for refresh.
        cache
            .get_or_fetch("k", || async { Ok::<_, ()>(creds(30)) })
            .await
            .unwrap();
        let got = cache
            .get_or_fetch("k", || async {
                Ok::<_, ()>(Arc::new(BackendCredentials {
                    access_key_id: "REFRESHED".into(),
                    secret_access_key: "secret".into(),
                    session_token: "token".into(),
                    expiration: Utc::now() + Duration::hours(1),
                }))
            })
            .await
            .unwrap();
        assert_eq!(got.access_key_id, "REFRESHED");
    }

    #[tokio::test]
    async fn keys_are_isolated() {
        let cache = CredentialCache::new();
        cache
            .get_or_fetch("a", || async { Ok::<_, ()>(creds(600)) })
            .await
            .unwrap();
        // A different key is a miss → fetches.
        let mut fetched = false;
        cache
            .get_or_fetch("b", || async {
                fetched = true;
                Ok::<_, ()>(creds(600))
            })
            .await
            .unwrap();
        assert!(fetched);
    }

    #[tokio::test]
    async fn single_flights_concurrent_fetches() {
        let cache = Arc::new(CredentialCache::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let one = {
            let cache = cache.clone();
            let calls = calls.clone();
            async move {
                cache
                    .get_or_fetch("k", || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        // Yield while holding the per-key lock so the sibling
                        // future contends for it — exercising single-flight.
                        tokio::task::yield_now().await;
                        Ok::<_, ()>(creds(600))
                    })
                    .await
            }
        };
        let two = {
            let cache = cache.clone();
            let calls = calls.clone();
            async move {
                cache
                    .get_or_fetch("k", || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, ()>(creds(600))
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
