//! Pluggable route handler trait for pre-dispatch request interception.
//!
//! Route handlers are checked in registration order before the main proxy
//! dispatch. Each handler can inspect the request and optionally return a
//! [`ProxyResult`] to short-circuit further processing. If no handler
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
pub type RouteHandlerFuture<'a> = Pin<Box<dyn Future<Output = Option<ProxyResult>> + Send + 'a>>;

/// The future type returned by [`RouteHandler::handle`].
#[cfg(target_arch = "wasm32")]
pub type RouteHandlerFuture<'a> = Pin<Box<dyn Future<Output = Option<ProxyResult>> + 'a>>;

/// Extracted path parameters from route matching.
///
/// When a route pattern like `/api/buckets/{id}` matches a request path,
/// the router populates this with the extracted parameters (e.g. `id` → `"my-bucket"`).
/// Handlers access parameters by name via [`Params::get`].
#[derive(Debug, Clone, Default)]
pub struct Params(Vec<(String, String)>);

impl Params {
    /// Look up a parameter value by name.
    ///
    /// Returns `None` if the parameter was not captured by the route pattern.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Create `Params` from a `matchit::Params` match result.
    pub(crate) fn from_matchit(params: &matchit::Params<'_, '_>) -> Self {
        Self(
            params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }
}

/// Parsed request metadata passed to route handlers.
pub struct RequestInfo<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
    /// Path parameters extracted by the router during dispatch.
    ///
    /// Empty when the request is constructed outside the router (e.g. direct
    /// `ProxyGateway::handle` calls).
    pub params: Params,
}

/// A pluggable handler that can intercept requests before proxy dispatch.
///
/// Implementations inspect the [`RequestInfo`] and return:
/// - `Some(result)` to handle the request (stops further handler checks)
/// - `None` to pass the request to the next handler or the proxy
///
/// Override individual HTTP method handlers (`get`, `post`, etc.) for
/// method-specific behavior, or override `handle` directly for
/// method-agnostic handlers.
///
/// ```rust,ignore
/// struct HealthCheck;
///
/// impl RouteHandler for HealthCheck {
///     fn get<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
///         Box::pin(async move {
///             Some(ProxyResult::json(200, r#"{"ok":true}"#))
///         })
///     }
/// }
///
/// router.route("/health", HealthCheck);
/// ```
pub trait RouteHandler: MaybeSend + MaybeSync {
    /// Handle a GET request. Returns `None` by default.
    fn get<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async { None })
    }

    /// Handle a POST request. Returns `None` by default.
    fn post<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async { None })
    }

    /// Handle a PUT request. Returns `None` by default.
    fn put<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async { None })
    }

    /// Handle a DELETE request. Returns `None` by default.
    fn delete<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async { None })
    }

    /// Handle a HEAD request. Returns `None` by default.
    fn head<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async { None })
    }

    /// Dispatch by HTTP method. Override this for method-agnostic handlers.
    fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        match *req.method {
            Method::GET => self.get(req),
            Method::POST => self.post(req),
            Method::PUT => self.put(req),
            Method::DELETE => self.delete(req),
            Method::HEAD => self.head(req),
            _ => Box::pin(async { None }),
        }
    }
}
