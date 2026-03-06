//! Pluggable route handler trait for pre-dispatch request interception.
//!
//! Route handlers are checked in registration order before the main proxy
//! dispatch. Each handler can inspect the request and optionally return a
//! [`HandlerAction`] to short-circuit further processing. If no handler
//! matches, the request proceeds to the normal resolve/dispatch pipeline.
//!
//! This module also defines the action/result types shared between route
//! handlers and the proxy gateway.

use crate::maybe_send::{MaybeSend, MaybeSync};
use bytes::Bytes;
use http::{HeaderMap, Method};
use std::future::Future;
use std::pin::Pin;
use url::Url;

/// The body of a proxy response.
///
/// Only used for responses the handler constructs directly (errors, LIST XML,
/// multipart XML responses, HEAD metadata). Streaming GET/PUT bodies bypass this type
/// entirely via the `Forward` action.
pub enum ProxyResponseBody {
    /// Fixed bytes (error XML, list XML, multipart XML responses, etc.).
    Bytes(Bytes),
    /// Empty body (HEAD responses, etc.).
    Empty,
}

impl ProxyResponseBody {
    /// Create a response body from raw bytes.
    pub fn from_bytes(bytes: Bytes) -> Self {
        if bytes.is_empty() {
            Self::Empty
        } else {
            Self::Bytes(bytes)
        }
    }

    /// Create an empty response body.
    pub fn empty() -> Self {
        Self::Empty
    }
}

/// The action the handler wants the runtime to take.
pub enum HandlerAction {
    /// A fully formed response (LIST results, errors, synthetic responses).
    Response(ProxyResult),
    /// A presigned URL for the runtime to execute with its native HTTP client.
    /// The runtime streams request/response bodies directly — no handler involvement.
    Forward(ForwardRequest),
    /// The handler needs the request body to continue (multipart operations).
    /// The runtime should materialize the body and call `handle_with_body`.
    NeedsBody(PendingRequest),
}

/// A presigned URL request for the runtime to execute.
pub struct ForwardRequest {
    /// HTTP method for the backend request.
    pub method: Method,
    /// Presigned URL to the backend (includes auth in query params).
    pub url: Url,
    /// Headers to include in the backend request (Range, If-Match, Content-Type, etc.).
    pub headers: HeaderMap,
}

/// The result of handling a proxy request.
pub struct ProxyResult {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: ProxyResponseBody,
}

impl ProxyResult {
    /// Create a JSON response with the given status and body.
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        Self {
            status,
            headers,
            body: ProxyResponseBody::from_bytes(Bytes::from(body.into())),
        }
    }

    /// Create an XML response with the given status and body.
    pub fn xml(status: u16, body: impl Into<String>) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/xml".parse().unwrap());
        Self {
            status,
            headers,
            body: ProxyResponseBody::from_bytes(Bytes::from(body.into())),
        }
    }
}

/// Opaque state for a multipart operation that needs the request body.
pub struct PendingRequest {
    pub(crate) method: Method,
    pub(crate) operation: crate::types::S3Operation,
    pub(crate) bucket_config: crate::types::BucketConfig,
    pub(crate) original_headers: HeaderMap,
    pub(crate) request_id: String,
}

/// Headers to forward from backend responses (used by runtimes for Forward responses).
pub const RESPONSE_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "content-length",
    "content-range",
    "etag",
    "last-modified",
    "accept-ranges",
    "content-encoding",
    "content-disposition",
    "cache-control",
    "x-amz-request-id",
    "x-amz-version-id",
    "location",
];

/// The future type returned by [`RouteHandler::handle`].
#[cfg(not(target_arch = "wasm32"))]
pub type RouteHandlerFuture<'a> = Pin<Box<dyn Future<Output = Option<HandlerAction>> + Send + 'a>>;

/// The future type returned by [`RouteHandler::handle`].
#[cfg(target_arch = "wasm32")]
pub type RouteHandlerFuture<'a> = Pin<Box<dyn Future<Output = Option<HandlerAction>> + 'a>>;

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
