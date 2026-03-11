//! Durable Object for tracking per-(bucket, identity) bandwidth usage in a sliding window.
//!
//! Each DO instance represents one (bucket, identity) pair. The DO is named
//! by combining bucket and identity into a single string key.
//!
//! ## Endpoints
//!
//! - `GET /check?bytes={n}&limit={n}&window={secs}` — returns 200 if the request
//!   would stay within quota, 429 if adding `bytes` would exceed `limit`.
//! - `POST /record?bytes={n}&window={secs}` — records `bytes` of usage, prunes
//!   expired entries, persists to storage, and sets a cleanup alarm.
//!
//! ## Storage
//!
//! Entries are stored as a single `"entries"` key in DO storage, serialized as
//! `Vec<Entry>`. An alarm is set to prune expired entries after the window elapses.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use worker::*;

/// A single bandwidth usage record.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Entry {
    /// Timestamp in milliseconds since epoch.
    ts: u64,
    /// Number of bytes recorded.
    bytes: u64,
}

/// Internal mutable state for the bandwidth meter, behind a `RefCell` because
/// the `DurableObject` trait requires `&self` on `fetch` and `alarm`.
struct Inner {
    entries: Vec<Entry>,
    loaded: bool,
}

/// Durable Object that tracks bandwidth usage per (bucket, identity) pair.
///
/// Maintains a time-series of byte counts and supports checking against a
/// configurable quota within a sliding window. The limit and window are passed
/// as query parameters so configuration changes take effect immediately without
/// redeploying or migrating DO state.
#[durable_object]
pub struct BandwidthMeter {
    state: State,
    inner: RefCell<Inner>,
}

impl DurableObject for BandwidthMeter {
    fn new(state: State, _env: Env) -> Self {
        Self {
            state,
            inner: RefCell::new(Inner {
                entries: Vec::new(),
                loaded: false,
            }),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path().to_string();
        let method = req.method();

        match (method, path.as_str()) {
            (Method::Get, "/check") => self.handle_check(&url).await,
            (Method::Post, "/record") => self.handle_record(&url).await,
            _ => Response::error("Not Found", 404),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        // On alarm, just load, prune with a zero window (clear all), and persist.
        // The alarm is set to fire after the window expires, so all entries should
        // be expired by then. We prune with window_ms=0 which effectively keeps
        // nothing since now_ms - 0 = now_ms and all entries are older.
        self.ensure_loaded().await?;

        // Clear all entries — the alarm fires after the window expires, so all
        // entries are stale. The next real request will do a proper prune anyway.
        self.inner.borrow_mut().entries.clear();

        self.persist().await?;
        Response::ok("alarm handled")
    }
}

impl BandwidthMeter {
    /// Load entries from storage if not yet loaded.
    async fn ensure_loaded(&self) -> Result<()> {
        let needs_load = !self.inner.borrow().loaded;
        if needs_load {
            let stored: Option<Vec<Entry>> = self.state.storage().get("entries").await?;
            let mut inner = self.inner.borrow_mut();
            if let Some(entries) = stored {
                inner.entries = entries;
            }
            inner.loaded = true;
        }
        Ok(())
    }

    /// Persist current entries to storage.
    async fn persist(&self) -> Result<()> {
        let entries = self.inner.borrow().entries.clone();
        self.state.storage().put("entries", &entries).await
    }

    /// Remove entries older than `window_ms` from now.
    fn prune(&self, now_ms: u64, window_ms: u64) {
        let cutoff = now_ms.saturating_sub(window_ms);
        self.inner.borrow_mut().entries.retain(|e| e.ts >= cutoff);
    }

    /// Sum all bytes in current entries.
    fn total_bytes(&self) -> u64 {
        self.inner.borrow().entries.iter().map(|e| e.bytes).sum()
    }

    /// Handle `GET /check?bytes={n}&limit={n}&window={secs}`.
    async fn handle_check(&self, url: &url::Url) -> Result<Response> {
        let params = parse_query(url);
        let bytes = params.bytes.unwrap_or(0);
        let limit = params
            .limit
            .ok_or_else(|| worker::Error::RustError("missing 'limit' param".into()))?;
        let window_secs = params
            .window
            .ok_or_else(|| worker::Error::RustError("missing 'window' param".into()))?;
        let window_ms = window_secs * 1000;

        self.ensure_loaded().await?;

        let now_ms = now_ms();
        self.prune(now_ms, window_ms);

        let current = self.total_bytes();
        if current.saturating_add(bytes) > limit {
            Response::error("Rate limit exceeded", 429)
        } else {
            Response::ok("OK")
        }
    }

    /// Handle `POST /record?bytes={n}&window={secs}`.
    async fn handle_record(&self, url: &url::Url) -> Result<Response> {
        let params = parse_query(url);
        let bytes = params
            .bytes
            .ok_or_else(|| worker::Error::RustError("missing 'bytes' param".into()))?;
        let window_secs = params
            .window
            .ok_or_else(|| worker::Error::RustError("missing 'window' param".into()))?;
        let window_ms = window_secs * 1000;

        self.ensure_loaded().await?;

        let now_ms = now_ms();
        self.prune(now_ms, window_ms);

        // Record the new entry.
        self.inner
            .borrow_mut()
            .entries
            .push(Entry { ts: now_ms, bytes });

        self.persist().await?;

        // Set alarm to clean up after the window expires.
        self.state
            .storage()
            .set_alarm(std::time::Duration::from_millis(window_ms))
            .await?;

        Response::ok("recorded")
    }
}

/// Parsed query parameters.
struct QueryParams {
    bytes: Option<u64>,
    limit: Option<u64>,
    window: Option<u64>,
}

/// Parse query parameters from a URL.
fn parse_query(url: &url::Url) -> QueryParams {
    let mut bytes = None;
    let mut limit = None;
    let mut window = None;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "bytes" => bytes = value.parse().ok(),
            "limit" => limit = value.parse().ok(),
            "window" => window = value.parse().ok(),
            _ => {}
        }
    }

    QueryParams {
        bytes,
        limit,
        window,
    }
}

/// Get current time in milliseconds since epoch.
fn now_ms() -> u64 {
    Date::now().as_millis()
}
