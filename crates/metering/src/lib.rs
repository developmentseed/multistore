//! Usage metering and quota enforcement.
//!
//! This crate provides trait abstractions for tracking API usage and enforcing
//! quotas. Integrators bring their own storage backends by implementing
//! [`UsageRecorder`] and [`QuotaChecker`].
//!
//! ## Architecture
//!
//! - **Pre-dispatch:** [`QuotaChecker::check_quota`] runs before the request
//!   proceeds. Return [`Err(QuotaExceeded)`](QuotaExceeded) to reject with
//!   HTTP 429.
//! - **Post-dispatch:** [`UsageRecorder::record_operation`] runs after the
//!   response is available, recording actual status and byte counts.

use std::future::Future;
use std::net::IpAddr;

use multistore::maybe_send::{MaybeSend, MaybeSync};
use multistore::types::{ResolvedIdentity, S3Operation};

/// A completed operation's metadata, passed to [`UsageRecorder::record_operation`].
pub struct UsageEvent<'a> {
    /// The unique request identifier.
    pub request_id: &'a str,
    /// The resolved caller identity, if any.
    pub identity: Option<&'a ResolvedIdentity>,
    /// The parsed S3 operation, if determined.
    pub operation: Option<&'a S3Operation>,
    /// The target bucket name, if applicable.
    pub bucket: Option<&'a str>,
    /// The HTTP status code of the response.
    pub status: u16,
    /// Best-available byte count for the operation.
    pub bytes_transferred: u64,
    /// Whether the request was forwarded to a backend via presigned URL.
    pub was_forwarded: bool,
    /// The client's IP address, if known.
    pub source_ip: Option<IpAddr>,
}

/// Quota violation error returned by [`QuotaChecker::check_quota`].
///
/// The `message` is included in the HTTP 429 response body.
#[derive(Debug)]
pub struct QuotaExceeded {
    /// Human-readable explanation of the quota violation.
    pub message: String,
}

/// Records completed operations for usage tracking.
///
/// Integrators implement this trait with their storage backend (Redis,
/// DynamoDB, in-memory, etc.). The recorder is called after every
/// dispatched request, including failed ones.
pub trait UsageRecorder: MaybeSend + MaybeSync + 'static {
    /// Record a completed operation.
    ///
    /// Implementations should be fire-and-forget — recording failures
    /// must not affect the response.
    fn record_operation<'a>(
        &'a self,
        event: UsageEvent<'a>,
    ) -> impl Future<Output = ()> + MaybeSend + 'a;
}

/// Pre-dispatch quota enforcement.
///
/// Integrators implement this trait to enforce usage limits before a
/// request proceeds. The `estimated_bytes` value comes from the request's
/// `Content-Length` header (for uploads) or is 0 when unknown.
pub trait QuotaChecker: MaybeSend + MaybeSync + 'static {
    /// Check whether the caller is within their quota.
    ///
    /// Return `Ok(())` to allow the request, or `Err(QuotaExceeded)` to
    /// reject it with HTTP 429.
    fn check_quota<'a>(
        &'a self,
        identity: &'a ResolvedIdentity,
        operation: &'a S3Operation,
        bucket: Option<&'a str>,
        estimated_bytes: u64,
        source_ip: Option<IpAddr>,
    ) -> impl Future<Output = Result<(), QuotaExceeded>> + MaybeSend + 'a;
}

// ===========================================================================
// No-op implementations
// ===========================================================================

/// A [`UsageRecorder`] that does nothing. Useful when only quota checking
/// is needed, or for testing.
pub struct NoopRecorder;

impl UsageRecorder for NoopRecorder {
    async fn record_operation<'a>(&'a self, _event: UsageEvent<'a>) {}
}

/// A [`QuotaChecker`] that always allows requests. Useful when only usage
/// recording is needed, or for testing.
pub struct NoopQuotaChecker;

impl QuotaChecker for NoopQuotaChecker {
    async fn check_quota<'a>(
        &'a self,
        _identity: &'a ResolvedIdentity,
        _operation: &'a S3Operation,
        _bucket: Option<&'a str>,
        _estimated_bytes: u64,
        _source_ip: Option<IpAddr>,
    ) -> Result<(), QuotaExceeded> {
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use multistore::types::{ResolvedIdentity, S3Operation};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    // -- Test helpers ---------------------------------------------------------

    struct RecordingRecorder {
        last_bytes: Arc<AtomicU64>,
        call_count: Arc<AtomicU64>,
    }

    impl RecordingRecorder {
        fn new() -> (Self, Arc<AtomicU64>, Arc<AtomicU64>) {
            let last_bytes = Arc::new(AtomicU64::new(0));
            let call_count = Arc::new(AtomicU64::new(0));
            (
                Self {
                    last_bytes: Arc::clone(&last_bytes),
                    call_count: Arc::clone(&call_count),
                },
                last_bytes,
                call_count,
            )
        }
    }

    impl UsageRecorder for RecordingRecorder {
        async fn record_operation<'a>(&'a self, event: UsageEvent<'a>) {
            self.last_bytes
                .store(event.bytes_transferred, Ordering::SeqCst);
            self.call_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct RejectingChecker {
        message: String,
    }

    impl QuotaChecker for RejectingChecker {
        async fn check_quota<'a>(
            &'a self,
            _identity: &'a ResolvedIdentity,
            _operation: &'a S3Operation,
            _bucket: Option<&'a str>,
            _estimated_bytes: u64,
            _source_ip: Option<IpAddr>,
        ) -> Result<(), QuotaExceeded> {
            Err(QuotaExceeded {
                message: self.message.clone(),
            })
        }
    }

    struct CapturingChecker {
        last_estimated_bytes: Arc<AtomicU64>,
    }

    impl CapturingChecker {
        fn new() -> (Self, Arc<AtomicU64>) {
            let last_estimated_bytes = Arc::new(AtomicU64::new(u64::MAX));
            (
                Self {
                    last_estimated_bytes: Arc::clone(&last_estimated_bytes),
                },
                last_estimated_bytes,
            )
        }
    }

    impl QuotaChecker for CapturingChecker {
        async fn check_quota<'a>(
            &'a self,
            _identity: &'a ResolvedIdentity,
            _operation: &'a S3Operation,
            _bucket: Option<&'a str>,
            estimated_bytes: u64,
            _source_ip: Option<IpAddr>,
        ) -> Result<(), QuotaExceeded> {
            self.last_estimated_bytes
                .store(estimated_bytes, Ordering::SeqCst);
            Ok(())
        }
    }

    // -- Tests ----------------------------------------------------------------

    #[test]
    fn rejecting_checker_returns_error() {
        let checker = RejectingChecker {
            message: "over limit".into(),
        };

        let result = futures::executor::block_on(async {
            checker
                .check_quota(
                    &ResolvedIdentity::Anonymous,
                    &S3Operation::ListBuckets,
                    Some("test"),
                    0,
                    None,
                )
                .await
        });

        let err = result.unwrap_err();
        assert_eq!(err.message, "over limit");
    }

    #[test]
    fn noop_checker_allows_request() {
        let result = futures::executor::block_on(async {
            NoopQuotaChecker
                .check_quota(
                    &ResolvedIdentity::Anonymous,
                    &S3Operation::ListBuckets,
                    None,
                    1_000_000,
                    None,
                )
                .await
        });

        assert!(result.is_ok());
    }

    #[test]
    fn capturing_checker_receives_estimated_bytes() {
        let (checker, captured_bytes) = CapturingChecker::new();

        let _result = futures::executor::block_on(async {
            checker
                .check_quota(
                    &ResolvedIdentity::Anonymous,
                    &S3Operation::ListBuckets,
                    Some("test"),
                    42_000,
                    None,
                )
                .await
        });

        assert_eq!(captured_bytes.load(Ordering::SeqCst), 42_000);
    }

    #[test]
    fn recorder_captures_usage_event() {
        let (recorder, last_bytes, call_count) = RecordingRecorder::new();

        futures::executor::block_on(async {
            recorder
                .record_operation(UsageEvent {
                    request_id: "req-1",
                    identity: None,
                    operation: None,
                    bucket: Some("my-bucket"),
                    status: 200,
                    bytes_transferred: 1024,
                    was_forwarded: true,
                    source_ip: None,
                })
                .await;
        });

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(last_bytes.load(Ordering::SeqCst), 1024);
    }
}
