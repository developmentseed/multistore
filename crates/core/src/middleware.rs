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
    pub bucket_config: Cow<'a, BucketConfig>,
    /// The original request headers.
    pub headers: &'a HeaderMap,
    /// The IP address of the client that originated this request.
    pub source_ip: Option<IpAddr>,
    /// A unique identifier for this request, used for tracing.
    pub request_id: &'a str,
    /// List rewrite rules for prefix-based bucket views.
    pub list_rewrite: Option<&'a ListRewrite>,
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
// Dispatch — trait for the terminal dispatch function at the end of the chain.
// ---------------------------------------------------------------------------

/// Terminal dispatch function at the end of the middleware chain.
///
/// Using a trait (instead of a closure/`dyn Fn`) allows the dispatch
/// implementation to borrow from its environment with arbitrary lifetimes —
/// avoiding the `'static` constraint that `Arc<dyn Fn>` would impose.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait Dispatch: Send + Sync {
    fn dispatch<'a>(&'a self, ctx: DispatchContext<'a>) -> DispatchFuture<'a>;
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait Dispatch {
    fn dispatch<'a>(&'a self, ctx: DispatchContext<'a>) -> DispatchFuture<'a>;
}

// ---------------------------------------------------------------------------
// ErasedMiddleware — type-erased trait object for the middleware chain.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait ErasedMiddleware: Send + Sync {
    fn handle<'a>(
        &'a self,
        ctx: DispatchContext<'a>,
        next: Next<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerAction, ProxyError>> + Send + 'a>>;
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait ErasedMiddleware {
    fn handle<'a>(
        &'a self,
        ctx: DispatchContext<'a>,
        next: Next<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerAction, ProxyError>> + 'a>>;
}

// Blanket impl: any `Middleware` is automatically an `ErasedMiddleware`.
#[cfg(not(target_arch = "wasm32"))]
impl<T: Middleware> ErasedMiddleware for T {
    fn handle<'a>(
        &'a self,
        ctx: DispatchContext<'a>,
        next: Next<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerAction, ProxyError>> + Send + 'a>> {
        Box::pin(<Self as Middleware>::handle(self, ctx, next))
    }
}

#[cfg(target_arch = "wasm32")]
impl<T: Middleware> ErasedMiddleware for T {
    fn handle<'a>(
        &'a self,
        ctx: DispatchContext<'a>,
        next: Next<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<HandlerAction, ProxyError>> + 'a>> {
        Box::pin(<Self as Middleware>::handle(self, ctx, next))
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
            bucket_config: Cow::Borrowed(&*BUCKET_CONFIG),
            headers: &*HEADERS,
            source_ip: None,
            request_id: "test-request-id",
            list_rewrite: None,
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
}
