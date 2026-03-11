//! Usage metering and quota enforcement middleware.
//!
//! This crate provides trait abstractions for tracking API usage and enforcing
//! quotas, along with a [`MeteringMiddleware`] that wires them into the proxy's
//! middleware chain. Integrators bring their own storage backends by implementing
//! [`UsageRecorder`] and [`QuotaChecker`].
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use multistore_metering::{MeteringMiddleware, UsageRecorder, QuotaChecker};
//!
//! // Implement UsageRecorder and QuotaChecker for your storage backend,
//! // then register the middleware on the ProxyGateway builder:
//! let metering = MeteringMiddleware::new(my_quota_checker, my_usage_recorder);
//! gateway_builder.add_middleware(metering);
//! ```
//!
//! ## Architecture
//!
//! - **Pre-dispatch:** [`QuotaChecker::check_quota`] runs before the request
//!   proceeds, using `Content-Length` as a byte estimate. Return
//!   [`Err(QuotaExceeded)`](QuotaExceeded) to reject with HTTP 429.
//! - **Post-dispatch:** [`UsageRecorder::record_operation`] runs after the
//!   response is available, recording actual status and byte counts from
//!   the backend response.

use std::future::Future;

use multistore::error::ProxyError;
use multistore::maybe_send::{MaybeSend, MaybeSync};
use multistore::middleware::{CompletedRequest, DispatchContext, Middleware, Next};
use multistore::route_handler::HandlerAction;
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
    /// Best-available byte count: `content_length` from backend response
    /// for forwarded requests, response body length for direct responses,
    /// or `Content-Length` header estimate as fallback.
    pub bytes_transferred: u64,
    /// Whether the request was forwarded to a backend via presigned URL.
    pub was_forwarded: bool,
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
    /// This runs in the post-dispatch phase. Implementations should be
    /// fire-and-forget — recording failures must not affect the response.
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
    ) -> impl Future<Output = Result<(), QuotaExceeded>> + MaybeSend + 'a;
}

/// Middleware that enforces quotas pre-dispatch and records usage post-dispatch.
///
/// Generic over the quota checker `Q` and usage recorder `U`, allowing
/// integrators to bring their own storage backends.
///
/// ## Request flow
///
/// 1. Extract `Content-Length` from request headers as a byte estimate.
/// 2. Call [`QuotaChecker::check_quota`] — reject with 429 if over limit.
/// 3. Delegate to the next middleware via [`Next::run`].
/// 4. In [`after_dispatch`](Middleware::after_dispatch), call
///    [`UsageRecorder::record_operation`] with the actual response metadata.
pub struct MeteringMiddleware<Q, U> {
    quota_checker: Q,
    usage_recorder: U,
}

impl<Q, U> MeteringMiddleware<Q, U> {
    /// Create a new metering middleware with the given quota checker and
    /// usage recorder.
    pub fn new(quota_checker: Q, usage_recorder: U) -> Self {
        Self {
            quota_checker,
            usage_recorder,
        }
    }
}

impl<Q: QuotaChecker, U: UsageRecorder> Middleware for MeteringMiddleware<Q, U> {
    async fn handle<'a>(
        &'a self,
        ctx: DispatchContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        let estimated_bytes = ctx
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        let bucket_name = ctx.bucket_config.as_ref().map(|b| b.name.as_str());

        self.quota_checker
            .check_quota(ctx.identity, ctx.operation, bucket_name, estimated_bytes)
            .await
            .map_err(|e| ProxyError::InvalidRequest(e.message))?;

        next.run(ctx).await
    }

    fn after_dispatch(
        &self,
        completed: &CompletedRequest<'_>,
    ) -> impl Future<Output = ()> + MaybeSend + '_ {
        // Extract all fields synchronously to avoid capturing `completed`
        // in the returned future (the future's lifetime is tied to `&self`,
        // not `completed`).
        let request_id = completed.request_id.to_owned();
        let identity = completed.identity.cloned();
        let operation = completed.operation.cloned();
        let bucket = completed.bucket.map(str::to_owned);
        let status = completed.status;
        let bytes_transferred = completed
            .response_bytes
            .or(completed.request_bytes)
            .unwrap_or(0);
        let was_forwarded = completed.was_forwarded;

        async move {
            self.usage_recorder
                .record_operation(UsageEvent {
                    request_id: &request_id,
                    identity: identity.as_ref(),
                    operation: operation.as_ref(),
                    bucket: bucket.as_deref(),
                    status,
                    bytes_transferred,
                    was_forwarded,
                })
                .await;
        }
    }
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
    use multistore::middleware::CompletedRequest;
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
        ) -> Result<(), QuotaExceeded> {
            self.last_estimated_bytes
                .store(estimated_bytes, Ordering::SeqCst);
            Ok(())
        }
    }

    // -- Tests ----------------------------------------------------------------

    // Tests for `handle` use the ProxyGateway integration tests in core.
    // Here we test the quota checking and after_dispatch logic directly.

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
                )
                .await
        });

        assert_eq!(captured_bytes.load(Ordering::SeqCst), 42_000);
    }

    #[test]
    fn after_dispatch_records_usage() {
        let (recorder, last_bytes, call_count) = RecordingRecorder::new();
        let middleware = MeteringMiddleware::new(NoopQuotaChecker, recorder);

        futures::executor::block_on(async {
            let completed = CompletedRequest {
                request_id: "req-1",
                identity: None,
                operation: None,
                bucket: Some("my-bucket"),
                status: 200,
                response_bytes: Some(1024),
                request_bytes: None,
                was_forwarded: true,
            };
            Middleware::after_dispatch(&middleware, &completed).await;
        });

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(last_bytes.load(Ordering::SeqCst), 1024);
    }

    #[test]
    fn after_dispatch_falls_back_to_request_bytes() {
        let (recorder, last_bytes, _) = RecordingRecorder::new();
        let middleware = MeteringMiddleware::new(NoopQuotaChecker, recorder);

        futures::executor::block_on(async {
            let completed = CompletedRequest {
                request_id: "req-2",
                identity: None,
                operation: None,
                bucket: None,
                status: 200,
                response_bytes: None,
                request_bytes: Some(512),
                was_forwarded: false,
            };
            Middleware::after_dispatch(&middleware, &completed).await;
        });

        assert_eq!(last_bytes.load(Ordering::SeqCst), 512);
    }

    #[test]
    fn after_dispatch_defaults_to_zero_bytes() {
        let (recorder, last_bytes, call_count) = RecordingRecorder::new();
        let middleware = MeteringMiddleware::new(NoopQuotaChecker, recorder);

        futures::executor::block_on(async {
            let completed = CompletedRequest {
                request_id: "req-3",
                identity: None,
                operation: None,
                bucket: None,
                status: 500,
                response_bytes: None,
                request_bytes: None,
                was_forwarded: false,
            };
            Middleware::after_dispatch(&middleware, &completed).await;
        });

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(last_bytes.load(Ordering::SeqCst), 0);
    }
}
