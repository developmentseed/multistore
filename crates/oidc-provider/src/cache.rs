//! Credential cache with non-blocking single-flight refresh.
//!
//! Caches [`BackendCredentials`] by key so the proxy doesn't re-mint and
//! re-exchange on every request. Beyond a plain TTL cache it:
//!
//! - **serves while fresh** — returns a cached value directly while it is
//!   comfortably valid,
//! - **proactively refreshes** — once a value is within [`REFRESH_LEAD_SECS`]
//!   of expiry, the next access re-mints it, so a credential is never handed
//!   out about to expire mid-request, and
//! - **single-flights renewals** — one caller claims the renewal and the rest
//!   keep serving the credential they already have, which has not expired.
//!
//! # Why no lock
//!
//! Renewal is single-flighted *without any caller ever waiting on another*. The
//! map sits behind a `std::sync::Mutex` that is only ever held for a get or an
//! insert and never across an `.await`.
//!
//! This is a hard requirement, not a preference. On Cloudflare Workers — which
//! `multistore-cf-workers` exists to serve — a request parked on an in-memory
//! waker has no pending I/O of its own, and the runtime cancels it with *"your
//! Worker's code had hung and would never generate a response"* rather than
//! waiting for whoever holds the lock. An earlier revision of this cache took a
//! per-key `futures::lock::Mutex` on *both* the hit and miss paths, so a single
//! isolate renewing one key killed every concurrent request touching that key.
//!
//! Serving stale-but-valid credentials is what makes the lock unnecessary:
//! latecomers never need the claimant's result, so there is nothing to wait for.
//!
//! # What is deliberately not single-flighted
//!
//! A **cold** key — absent or already expired — has nothing usable to serve, so
//! concurrent callers each run their own `fetch`, with no cap beyond how many
//! arrive before the first one stores. Collapsing those would mean waiting, and
//! the only way to wait on Workers without being cancelled is to poll a real
//! timer — which costs about as long as the exchange it avoids, while adding a
//! spin loop and a dependency on the claimant surviving. The recurring event,
//! renewal, *is* single-flighted.
//!
//! Size that burst before relying on it. A single cold start mints once per
//! concurrent caller on that one process or isolate, which is small. A **deploy
//! or mass eviction is different**: it cools every isolate at once, so the
//! bursts coincide across the whole fleet and land on the token endpoint
//! together. If yours is rate-limited (AWS STS throttling surfaces here as
//! `StsError` → a 502 for every caller in the burst), layer an L2 tier inside
//! the `fetch` closure so the second and later isolates read a mint instead of
//! performing one. See `docs/architecture/caching.md`.
//!
//! The fetch happens through a caller-supplied closure ([`get_or_fetch`]), so
//! the cache never needs to know how credentials are minted, and a runtime can
//! layer an additional cache tier (e.g. the Cloudflare Cache API) inside the
//! closure. See `docs/architecture/caching.md`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Duration, Utc};

use crate::BackendCredentials;

/// Refresh a cached credential once it is within this many seconds of expiry,
/// so it is never handed out about to expire mid-request.
const REFRESH_LEAD_SECS: i64 = 60;

/// Never serve a credential with less than this much life left, even while a
/// renewal is in flight: the backend request it signs still has to reach the
/// store and complete. Below this the caller mints its own rather than sign
/// with something that may expire in transit — an expired credential comes back
/// from the store as `ExpiredToken`, which surfaces to the client as a
/// misleading `AccessDenied` instead of a retryable server-side error.
const MIN_SERVE_SECS: i64 = 5;

/// Treat a renewal claim older than this as abandoned and let another caller
/// take it. Without this, a claimant that never completes — a cancelled or
/// evicted request — leaves the key marked as renewing until the credential
/// expires, at which point every caller stampedes at once.
const CLAIM_TIMEOUT_SECS: i64 = 30;

/// Compose the cache key for a credential minted for `subject` against `scope`
/// (e.g. an IAM role ARN).
///
/// The subject is part of a credential's identity, not merely a label on it: an
/// AWS role's trust policy conditions on the assertion's `sub`, so two subjects
/// assuming the same role are **not** interchangeable. Keying on the scope alone
/// let a subject the trust policy would reject be served a credential minted for
/// one it accepts — succeeding where the token endpoint would have refused.
pub(crate) fn scoped_key(scope: &str, subject: &str) -> String {
    // U+001F (unit separator) cannot occur in a role ARN or an OIDC subject, so
    // the join is unambiguous without escaping either half.
    format!("{scope}\u{1f}{subject}")
}

/// A cached credential and the renewal claim on it, if any.
struct Entry {
    creds: Arc<BackendCredentials>,
    /// When a caller claimed the renewal of `creds`. `None` when no renewal is
    /// in flight; see [`CLAIM_TIMEOUT_SECS`] for how a stuck claim is reaped.
    renewing_since: Option<DateTime<Utc>>,
}

/// What a caller should do for a key, decided under the map lock.
enum Action {
    /// Use this credential as-is; no `fetch` needed.
    Serve(Arc<BackendCredentials>),
    /// Nothing usable, or this caller took the renewal claim: run `fetch`.
    Fetch,
}

/// Thread-safe credential cache with proactive, non-blocking refresh.
///
/// `Clone` shares the same underlying store (the entry map is behind an `Arc`),
/// so a cloned [`OidcCredentialProvider`](crate::OidcCredentialProvider) keeps
/// hitting the same cache — letting a runtime hold the provider in a
/// shared/`static` slot and reuse it across requests instead of re-minting and
/// re-exchanging every time.
#[derive(Clone, Default)]
pub struct CredentialCache {
    /// The `Mutex` guards map reads and writes only, and is never held across
    /// an `.await` — see the module docs for why that matters.
    entries: Arc<Mutex<HashMap<String, Entry>>>,
}

impl CredentialCache {
    /// Create an empty credential cache.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Return cached credentials for `key`, running `fetch` only when this
    /// caller is the one that must.
    ///
    /// A cached value is served outright while fresh (`now < expiration -
    /// REFRESH_LEAD_SECS`). Inside the refresh lead the first caller claims the
    /// renewal and runs `fetch`; concurrent callers keep receiving the cached
    /// value — which has not expired — instead of waiting on that claim. No
    /// caller ever blocks on another.
    pub async fn get_or_fetch<F, Fut, E>(
        &self,
        key: &str,
        fetch: F,
    ) -> Result<Arc<BackendCredentials>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Arc<BackendCredentials>, E>>,
    {
        if let Action::Serve(creds) = self.claim(key) {
            return Ok(creds);
        }
        match fetch().await {
            Ok(creds) => {
                self.entries().insert(
                    key.to_string(),
                    Entry {
                        creds: creds.clone(),
                        renewing_since: None,
                    },
                );
                Ok(creds)
            }
            Err(e) => {
                // Drop the claim so the next caller retries rather than serving
                // a credential nobody is renewing until it expires.
                if let Some(entry) = self.entries().get_mut(key) {
                    entry.renewing_since = None;
                }
                Err(e)
            }
        }
    }

    /// Decide what a caller should do for `key`, taking the renewal claim when
    /// this caller is the one that will run `fetch`.
    ///
    /// Not a lock: the returned [`Action`] never depends on another caller
    /// making progress.
    fn claim(&self, key: &str) -> Action {
        let now = Utc::now();
        let mut entries = self.entries();
        let Some(entry) = entries.get_mut(key) else {
            return Action::Fetch;
        };

        if entry.creds.expiration > now + Duration::seconds(REFRESH_LEAD_SECS) {
            return Action::Serve(entry.creds.clone());
        }

        let claimed = entry
            .renewing_since
            .is_some_and(|at| now < at + Duration::seconds(CLAIM_TIMEOUT_SECS));
        if claimed && entry.creds.expiration > now + Duration::seconds(MIN_SERVE_SECS) {
            return Action::Serve(entry.creds.clone());
        }

        // Either we are first into the refresh lead, the previous claim went
        // stale, or the credential is now inside `MIN_SERVE_SECS` and too close
        // to expiry to hand out.
        //
        // That last case deliberately ignores a live claim, so in the final
        // `MIN_SERVE_SECS` a claimant can be overtaken and several fetches run
        // at once, each overwriting `renewing_since`. That is the intended
        // trade: there is nothing safe left to serve, so the alternatives are
        // making callers wait (which the module docs rule out) or failing a
        // request that could have succeeded. Duplication is bounded to the
        // callers arriving inside that window.
        entry.renewing_since = Some(now);
        Action::Fetch
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .expect("credential cache mutex poisoned")
    }
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

    /// A caller must never wait on another caller's in-flight renewal while the
    /// cached credential is still usable.
    ///
    /// Waiting is not merely slow. On Cloudflare Workers a request parked on an
    /// in-memory waker has no pending I/O of its own, and the runtime cancels it
    /// outright ("your Worker's code had hung and would never generate a
    /// response"), so this ordering is a correctness requirement there.
    #[tokio::test]
    async fn serves_a_usable_credential_without_waiting_for_a_renewal() {
        let cache = CredentialCache::new();
        // Seed a credential inside the refresh lead: due for renewal, still valid.
        cache
            .get_or_fetch("k", || async { Ok::<_, ()>(creds(30)) })
            .await
            .unwrap();

        let order = Mutex::new(Vec::new());

        let renewing = async {
            cache
                .get_or_fetch("k", || async {
                    // Stay in flight long enough for the sibling to arrive.
                    for _ in 0..8 {
                        tokio::task::yield_now().await;
                    }
                    Ok::<_, ()>(creds(3600))
                })
                .await
                .unwrap();
            order.lock().unwrap().push("renewal");
        };
        let serving = async {
            cache
                .get_or_fetch::<_, _, ()>("k", || async {
                    panic!("must not mint while a usable credential is cached")
                })
                .await
                .unwrap();
            order.lock().unwrap().push("served");
        };

        tokio::join!(renewing, serving);

        assert_eq!(
            order.lock().unwrap().first().copied(),
            Some("served"),
            "the cached credential should be served immediately, not after the renewal completes"
        );
    }

    /// Renewal — the recurring event — collapses to a single exchange no matter
    /// how many callers arrive during it.
    #[tokio::test]
    async fn single_flights_a_renewal() {
        let cache = CredentialCache::new();
        cache
            .get_or_fetch("k", || async { Ok::<_, ()>(creds(30)) })
            .await
            .unwrap();

        let calls = AtomicUsize::new(0);
        let renewing = async {
            cache
                .get_or_fetch("k", || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    for _ in 0..8 {
                        tokio::task::yield_now().await;
                    }
                    Ok::<_, ()>(creds(3600))
                })
                .await
                .unwrap();
        };
        let others = async {
            for _ in 0..10 {
                cache
                    .get_or_fetch("k", || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, ()>(creds(3600))
                    })
                    .await
                    .unwrap();
                tokio::task::yield_now().await;
            }
        };

        tokio::join!(renewing, others);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only the claimant should mint during a renewal"
        );
    }

    /// A credential too close to expiry is never served, even while a renewal is
    /// claimed: signing with it risks the backend rejecting an expired token
    /// mid-flight, which reaches the client as a misleading `AccessDenied`.
    #[tokio::test]
    async fn does_not_serve_a_credential_about_to_expire() {
        let cache = CredentialCache::new();
        cache
            .get_or_fetch("k", || async { Ok::<_, ()>(creds(MIN_SERVE_SECS - 1)) })
            .await
            .unwrap();
        // Claims the renewal, and leaves the near-expired credential cached.
        cache
            .get_or_fetch("k", || async {
                Err::<Arc<BackendCredentials>, _>("STS is throttling")
            })
            .await
            .unwrap_err();

        let mut fetched = false;
        cache
            .get_or_fetch("k", || async {
                fetched = true;
                Ok::<_, ()>(creds(3600))
            })
            .await
            .unwrap();
        assert!(
            fetched,
            "must mint rather than serve a credential about to expire"
        );
    }

    /// Inside `MIN_SERVE_SECS` a live claim is deliberately overtaken: the
    /// cached credential is too close to expiry to hand out, so a caller
    /// arriving during the renewal mints its own rather than being served
    /// something that may die in transit. Bounded duplication, chosen over
    /// making the caller wait or failing a request that could have succeeded.
    #[tokio::test]
    async fn overtakes_a_claim_when_the_credential_is_about_to_expire() {
        let cache = CredentialCache::new();
        cache
            .get_or_fetch("k", || async { Ok::<_, ()>(creds(MIN_SERVE_SECS - 1)) })
            .await
            .unwrap();

        let calls = AtomicUsize::new(0);
        let claimant = async {
            cache
                .get_or_fetch("k", || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    for _ in 0..8 {
                        tokio::task::yield_now().await;
                    }
                    Ok::<_, ()>(creds(3600))
                })
                .await
                .unwrap();
        };
        let overtaker = async {
            cache
                .get_or_fetch("k", || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(creds(3600))
                })
                .await
                .unwrap();
        };

        tokio::join!(claimant, overtaker);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a credential inside the serve floor must not be handed to a caller \
             arriving during a live renewal"
        );
    }

    /// A claimant that never completes (a cancelled or evicted request) must not
    /// keep the key marked as renewing forever.
    #[tokio::test]
    async fn reclaims_an_abandoned_renewal() {
        let cache = CredentialCache::new();
        cache
            .get_or_fetch("k", || async { Ok::<_, ()>(creds(30)) })
            .await
            .unwrap();

        // Simulate a claim taken by a request that then disappeared.
        cache.entries().get_mut("k").unwrap().renewing_since =
            Some(Utc::now() - Duration::seconds(CLAIM_TIMEOUT_SECS + 1));

        let mut fetched = false;
        cache
            .get_or_fetch("k", || async {
                fetched = true;
                Ok::<_, ()>(creds(3600))
            })
            .await
            .unwrap();
        assert!(fetched, "a stale claim should be re-takeable");
    }

    /// A failed exchange releases the claim, so the next caller retries instead
    /// of serving an unrenewed credential until it expires.
    #[tokio::test]
    async fn a_failed_renewal_releases_the_claim() {
        let cache = CredentialCache::new();
        cache
            .get_or_fetch("k", || async { Ok::<_, ()>(creds(30)) })
            .await
            .unwrap();
        cache
            .get_or_fetch("k", || async { Err::<Arc<BackendCredentials>, _>("boom") })
            .await
            .unwrap_err();

        let mut fetched = false;
        cache
            .get_or_fetch("k", || async {
                fetched = true;
                Ok::<_, ()>(creds(3600))
            })
            .await
            .unwrap();
        assert!(fetched, "the claim should have been released on failure");
    }

    /// Documented trade-off: a cold key has nothing usable to serve, so
    /// concurrent callers each mint rather than wait on one another. See the
    /// module docs for why waiting is not an option.
    #[tokio::test]
    async fn cold_misses_are_not_single_flighted() {
        let cache = CredentialCache::new();
        let calls = AtomicUsize::new(0);

        let one = async {
            cache
                .get_or_fetch("cold", || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    Ok::<_, ()>(creds(600))
                })
                .await
                .unwrap();
        };
        let two = async {
            cache
                .get_or_fetch("cold", || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(creds(600))
                })
                .await
                .unwrap();
        };

        tokio::join!(one, two);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
