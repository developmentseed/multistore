//! Pluggable route handler trait for pre-dispatch request interception.
//!
//! Route handlers are checked in registration order before the main proxy
//! dispatch. Each handler can inspect the request and optionally return a
//! [`HandlerAction`] to short-circuit further processing. If no handler
//! matches, the request proceeds to the normal resolve/dispatch pipeline.

use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::proxy::HandlerAction;
use http::{HeaderMap, Method};
use std::future::Future;
use std::pin::Pin;

/// The future type returned by [`RouteHandler::handle`].
#[cfg(not(target_arch = "wasm32"))]
pub type RouteHandlerFuture<'a> =
    Pin<Box<dyn Future<Output = Option<HandlerAction>> + Send + 'a>>;

/// The future type returned by [`RouteHandler::handle`].
#[cfg(target_arch = "wasm32")]
pub type RouteHandlerFuture<'a> =
    Pin<Box<dyn Future<Output = Option<HandlerAction>> + 'a>>;

/// Parsed request metadata passed to route handlers.
pub struct RequestInfo<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
}

/// A pluggable handler that can intercept requests before proxy dispatch.
///
/// Implementations inspect the [`RequestInfo`] and return:
/// - `Some(action)` to handle the request (stops further handler checks)
/// - `None` to pass the request to the next handler or the proxy
pub trait RouteHandler: MaybeSend + MaybeSync {
    fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a>;
}

// Compile-time check that RouteHandler is object-safe.
fn _assert_object_safe(_: &dyn RouteHandler) {}
