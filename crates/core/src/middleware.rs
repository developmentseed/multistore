//! Composable post-auth middleware for dispatch.
//!
//! Middleware runs after identity resolution and authorization, wrapping
//! the backend dispatch call. Each middleware can inspect or modify the
//! [`DispatchContext`], short-circuit the request with an early response,
//! or delegate to the next middleware in the chain via [`Next::run`].
//!
//! Implement the [`Middleware`] trait for your type, then register it on
//! the `ProxyGateway` builder. Middleware executes in registration order.

use std::borrow::Cow;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use http::HeaderMap;

use crate::api::list_rewrite::ListRewrite;
use crate::error::ProxyError;
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::route_handler::HandlerAction;
use crate::types::{BucketConfig, ResolvedIdentity, S3Operation};

/// Post-dispatch context passed to [`Middleware::after_dispatch`].
pub struct CompletedRequest<'a> {
    /// The unique request identifier.
    pub request_id: &'a str,
    /// The resolved caller identity, if any.
    pub identity: Option<&'a ResolvedIdentity>,
    /// The parsed S3 operation, if determined.
    pub operation: Option<&'a S3Operation>,
    /// The target bucket name, if the operation targets a specific bucket.
    pub bucket: Option<&'a str>,
    /// The HTTP status code of the response.
    pub status: u16,
    /// The number of bytes in the response body, if known.
    pub response_bytes: Option<u64>,
    /// The number of bytes in the request body, if known.
    pub request_bytes: Option<u64>,
    /// Whether the request was forwarded to a backend via presigned URL.
    pub was_forwarded: bool,
    /// The IP address of the client, used for anonymous user identification.
    pub source_ip: Option<IpAddr>,
}

/// Context passed to each middleware in the dispatch chain.
///
/// Contains the resolved identity, parsed S3 operation, bucket configuration,
/// original request headers, and an extensions map for middleware to share
/// arbitrary typed data with downstream middleware or the dispatch function.
pub struct DispatchContext<'a> {
    /// The authenticated identity for this request.
    pub identity: &'a ResolvedIdentity,
    /// The parsed S3 operation being performed.
    pub operation: &'a S3Operation,
    /// The bucket configuration for the target bucket.
    /// `None` for operations that don't target a specific bucket (e.g. ListBuckets).
    pub bucket_config: Option<Cow<'a, BucketConfig>>,
    /// The original request headers.
    pub headers: &'a HeaderMap,
    /// The IP address of the client that originated this request.
    pub source_ip: Option<IpAddr>,
    /// A unique identifier for this request, used for tracing.
    pub request_id: &'a str,
    /// List rewrite rules for prefix-based bucket views.
    pub list_rewrite: Option<&'a ListRewrite>,
    /// Optional display name for the bucket in LIST responses.
    pub display_name: Option<&'a str>,
    /// Arbitrary typed data for middleware to share downstream.
    pub extensions: http::Extensions,
}

// ---------------------------------------------------------------------------
// DispatchFuture — the boxed future returned by dispatch functions.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type DispatchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HandlerAction, ProxyError>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub(crate) type DispatchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HandlerAction, ProxyError>> + 'a>>;

// ---------------------------------------------------------------------------
// AfterDispatchFuture — the boxed future returned by after_dispatch callbacks.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type AfterDispatchFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub(crate) type AfterDispatchFuture<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;

// ---------------------------------------------------------------------------
// Dispatch — trait for the terminal dispatch function at the end of the chain.
// ---------------------------------------------------------------------------

/// Terminal dispatch function at the end of the middleware chain.
///
/// Using a trait (instead of a closure/`dyn Fn`) allows the dispatch
/// implementation to borrow from its environment with arbitrary lifetimes —
/// avoiding the `'static` constraint that `Arc<dyn Fn>` would impose.
pub(crate) trait Dispatch: MaybeSend + MaybeSync {
    fn dispatch<'a>(&'a self, ctx: DispatchContext<'a>) -> DispatchFuture<'a>;
}

// ---------------------------------------------------------------------------
// ErasedMiddleware — type-erased trait object for the middleware chain.
// ---------------------------------------------------------------------------

pub(crate) trait ErasedMiddleware: MaybeSend + MaybeSync {
    fn handle<'a>(&'a self, ctx: DispatchContext<'a>, next: Next<'a>) -> DispatchFuture<'a>;
    fn after_dispatch<'a>(&'a self, completed: &'a CompletedRequest<'a>)
        -> AfterDispatchFuture<'a>;
}

// Blanket impl: any `Middleware` is automatically an `ErasedMiddleware`.
impl<T: Middleware> ErasedMiddleware for T {
    fn handle<'a>(&'a self, ctx: DispatchContext<'a>, next: Next<'a>) -> DispatchFuture<'a> {
        Box::pin(<Self as Middleware>::handle(self, ctx, next))
    }

    fn after_dispatch<'a>(
        &'a self,
        completed: &'a CompletedRequest<'a>,
    ) -> AfterDispatchFuture<'a> {
        Box::pin(<Self as Middleware>::after_dispatch(self, completed))
    }
}

// ---------------------------------------------------------------------------
// Next — wraps the remaining middleware chain plus the terminal dispatch fn.
// ---------------------------------------------------------------------------

/// Handle to the remaining middleware chain.
///
/// Call [`Next::run`] to pass the request to the next middleware, or to the
/// terminal dispatch function if no middleware remains. Middleware that wants
/// to short-circuit the chain can simply return a result without calling
/// `run`.
pub struct Next<'a> {
    middleware: &'a [Box<dyn ErasedMiddleware>],
    dispatch: &'a dyn Dispatch,
}

impl<'a> Next<'a> {
    pub(crate) fn new(
        middleware: &'a [Box<dyn ErasedMiddleware>],
        dispatch: &'a dyn Dispatch,
    ) -> Self {
        Self {
            middleware,
            dispatch,
        }
    }

    /// Run the next middleware in the chain, or the dispatch function if the
    /// chain is exhausted.
    pub async fn run(self, ctx: DispatchContext<'a>) -> Result<HandlerAction, ProxyError> {
        if let Some((first, rest)) = self.middleware.split_first() {
            let next = Next {
                middleware: rest,
                dispatch: self.dispatch,
            };
            first.handle(ctx, next).await
        } else {
            self.dispatch.dispatch(ctx).await
        }
    }
}

// ---------------------------------------------------------------------------
// Middleware — the public trait implementors use.
// ---------------------------------------------------------------------------

/// Composable post-auth middleware for the dispatch chain.
///
/// Implement this trait to intercept requests after identity resolution and
/// authorization but before (or instead of) backend dispatch. Each
/// middleware receives the [`DispatchContext`] and a [`Next`] handle to
/// continue the chain.
///
/// ```rust,ignore
/// struct RateLimiter;
///
/// impl Middleware for RateLimiter {
///     async fn handle<'a>(
///         &'a self,
///         ctx: DispatchContext<'a>,
///         next: Next<'a>,
///     ) -> Result<HandlerAction, ProxyError> {
///         if self.is_over_limit(&ctx) {
///             Ok(HandlerAction::Response(ProxyResult { status: 429, .. }))
///         } else {
///             next.run(ctx).await
///         }
///     }
/// }
/// ```
pub trait Middleware: MaybeSend + MaybeSync + 'static {
    /// Handle a request, optionally delegating to the next middleware via
    /// [`Next::run`].
    fn handle<'a>(
        &'a self,
        ctx: DispatchContext<'a>,
        next: Next<'a>,
    ) -> impl Future<Output = Result<HandlerAction, ProxyError>> + MaybeSend + 'a;

    /// Called after the request has been fully dispatched and the response is
    /// available. Use this for logging, metering, or other post-dispatch
    /// side effects. The default implementation is a no-op.
    fn after_dispatch(
        &self,
        _completed: &CompletedRequest<'_>,
    ) -> impl Future<Output = ()> + MaybeSend + '_ {
        async {}
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_handler::{ProxyResponseBody, ProxyResult};
    use crate::types::{BucketConfig, ResolvedIdentity, S3Operation};

    // -- Test helpers -------------------------------------------------------

    pub(crate) struct BlockingMiddleware;

    impl Middleware for BlockingMiddleware {
        async fn handle<'a>(
            &'a self,
            _ctx: DispatchContext<'a>,
            _next: Next<'a>,
        ) -> Result<HandlerAction, ProxyError> {
            Ok(HandlerAction::Response(ProxyResult {
                status: 429,
                headers: HeaderMap::new(),
                body: ProxyResponseBody::Empty,
            }))
        }
    }

    pub(crate) struct PassthroughMiddleware;

    impl Middleware for PassthroughMiddleware {
        async fn handle<'a>(
            &'a self,
            ctx: DispatchContext<'a>,
            next: Next<'a>,
        ) -> Result<HandlerAction, ProxyError> {
            next.run(ctx).await
        }
    }

    struct TestDispatch;

    impl Dispatch for TestDispatch {
        fn dispatch<'a>(&'a self, _ctx: DispatchContext<'a>) -> DispatchFuture<'a> {
            Box::pin(async {
                Ok(HandlerAction::Response(ProxyResult {
                    status: 200,
                    headers: HeaderMap::new(),
                    body: ProxyResponseBody::Empty,
                }))
            })
        }
    }

    fn test_context() -> DispatchContext<'static> {
        static IDENTITY: ResolvedIdentity = ResolvedIdentity::Anonymous;
        static OPERATION: S3Operation = S3Operation::ListBuckets;
        static HEADERS: std::sync::LazyLock<HeaderMap> = std::sync::LazyLock::new(HeaderMap::new);
        static BUCKET_CONFIG: std::sync::LazyLock<BucketConfig> =
            std::sync::LazyLock::new(|| BucketConfig {
                name: "test".to_string(),
                backend_type: "s3".to_string(),
                backend_prefix: None,
                anonymous_access: false,
                allowed_roles: Vec::new(),
                backend_options: Default::default(),
            });

        DispatchContext {
            identity: &IDENTITY,
            operation: &OPERATION,
            bucket_config: Some(Cow::Borrowed(&*BUCKET_CONFIG)),
            headers: &*HEADERS,
            source_ip: None,
            request_id: "test-request-id",
            list_rewrite: None,
            display_name: None,
            extensions: http::Extensions::new(),
        }
    }

    fn response_status(action: &HandlerAction) -> u16 {
        match action {
            HandlerAction::Response(r) => r.status,
            _ => panic!("expected Response variant"),
        }
    }

    // -- Tests --------------------------------------------------------------

    #[test]
    fn empty_chain_calls_dispatch() {
        let dispatch = TestDispatch;
        let middleware: Vec<Box<dyn ErasedMiddleware>> = vec![];
        let result = futures::executor::block_on(async {
            let next = Next::new(&middleware, &dispatch);
            next.run(test_context()).await
        });
        assert_eq!(response_status(&result.unwrap()), 200);
    }

    #[test]
    fn blocking_middleware_short_circuits() {
        let dispatch = TestDispatch;
        let middleware: Vec<Box<dyn ErasedMiddleware>> = vec![Box::new(BlockingMiddleware)];
        let result = futures::executor::block_on(async {
            let next = Next::new(&middleware, &dispatch);
            next.run(test_context()).await
        });
        assert_eq!(response_status(&result.unwrap()), 429);
    }

    #[test]
    fn passthrough_then_blocking_runs_in_order() {
        let dispatch = TestDispatch;
        let middleware: Vec<Box<dyn ErasedMiddleware>> = vec![
            Box::new(PassthroughMiddleware),
            Box::new(BlockingMiddleware),
        ];
        let result = futures::executor::block_on(async {
            let next = Next::new(&middleware, &dispatch);
            next.run(test_context()).await
        });
        // PassthroughMiddleware delegates, BlockingMiddleware returns 429
        assert_eq!(response_status(&result.unwrap()), 429);
    }

    #[test]
    fn passthrough_reaches_dispatch() {
        let dispatch = TestDispatch;
        let middleware: Vec<Box<dyn ErasedMiddleware>> = vec![Box::new(PassthroughMiddleware)];
        let result = futures::executor::block_on(async {
            let next = Next::new(&middleware, &dispatch);
            next.run(test_context()).await
        });
        assert_eq!(response_status(&result.unwrap()), 200);
    }

    #[test]
    fn after_dispatch_default_is_noop() {
        let middleware: Box<dyn ErasedMiddleware> = Box::new(PassthroughMiddleware);
        futures::executor::block_on(async {
            let completed = CompletedRequest {
                request_id: "test",
                identity: None,
                operation: None,
                bucket: None,
                status: 200,
                response_bytes: None,
                request_bytes: None,
                was_forwarded: false,
                source_ip: None,
            };
            middleware.after_dispatch(&completed).await;
        });
    }
}
